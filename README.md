# xss_verify.py — Verificador de XSS reflejado (post-Nuclei)

Herramienta de **confirmación**, no de descubrimiento. Se usa después de Nuclei
para separar los hallazgos que son *ruido* (texto reflejado pero escapado/no
explotable) de los que son XSS **realmente explotables**.

⚠️ Úsala solo contra objetivos para los que tengas autorización explícita
(programas de bug bounty, contratos de pentesting, activos propios).

## 1. Instalación

```bash
pip install playwright
playwright install chromium
```

## 2. Paso 1: correr Nuclei generando salida JSONL

```bash
nuclei -list todo.txt \
  -t /home/tatsu_/xss-reflected-multi-param.yaml \
  -rl 50 -c 10 \
  -jsonl -o hits.jsonl
```

`-jsonl` es clave: el script lee ese formato para sacar las URLs con match.

## 3. Paso 2: verificar los hits

```bash
python3 xss_verify.py -i hits.jsonl -o confirmados.json --html-report reporte_xss.html
```

Opciones útiles:

| Flag | Qué hace |
|---|---|
| `-c / --concurrency` | páginas concurrentes (default: 5, súbelo con cuidado) |
| `--timeout` | timeout por página en ms (default: 12000) |
| `--headed` | abre el navegador visible, útil para debug manual |

También aceptas un `.txt` plano (una URL ya inyectada por línea) en vez del
`.jsonl` de Nuclei, si quieres verificar URLs sueltas.

## 4. Qué hace exactamente

Para cada URL:

1. Identifica el parámetro que trae el payload reflejado.
2. Reconstruye la URL con un payload **nuevo** que dispara un `alert()` real
   (`"><script>alert(...)</script>`), distinto al de detección de Nuclei —
   así evitas que un WAF que ya "aprendió" el primer patrón enmascare el resultado.
3. Carga la página en Chromium headless y escucha el evento `dialog`.
4. Si el `alert()` se dispara → **`confirmed_js_exec`**, es un XSS real y
   confirmado en ejecución, no solo texto reflejado.
5. Si no se dispara, analiza en qué **contexto HTML** cayó el marcador
   (texto plano, dentro de un atributo, dentro de `<script>`, dentro de un
   comentario) para estimar si aún así es explotable con otro payload.
6. Revisa si hay **CSP** en la respuesta que pueda estar bloqueando la
   ejecución inline.

## 5. Clasificación de resultados

| Estado | Significado |
|---|---|
| `confirmed_js_exec` | JS se ejecutó de verdad — reportar con alta confianza |
| `likely_exploitable` | Se refleja sin escapar en atributo/script, pero no disparó el dialog (posible CSP o necesita otro vector) — revisar a mano |
| `reflected_only` | El texto se refleja pero en un contexto no directamente explotable |
| `not_reflected` | No se encontró el marcador — probablemente sanitizado |
| `error` | Timeout u otro fallo al cargar la página |

## 6. Salidas

- `confirmados.json` — resultado estructurado completo, útil para integrarlo
  en otro pipeline o reporte.
- `reporte_xss.html` — reporte visual agrupado por severidad, para revisar
  rápido o adjuntar a un informe.

## 7. Siguiente paso lógico

Los que queden en `confirmed_js_exec` y `likely_exploitable` son los
candidatos a reportar. Antes de enviar cualquier reporte, confirma también:

- Que el activo esté en scope del programa
- Que no sea un duplicado ya reportado
- Captura de pantalla / video del `alert()` disparándose (para el PoC)
