# html_inject_fuzzer.py — Fuzzer + inyector + verificador de reflejo HTML

Herramienta todo-en-uno que **descubre** parámetros vulnerables a HTML
Injection/XSS reflejado por su cuenta: genera las combinaciones de
parámetro × payload, dispara las requests de forma asíncrona, y analiza
cada respuesta para saber si el payload se reflejó tal cual, escapado, o
parcialmente sanitizado.

No depende de Nuclei — es un motor propio en Python.

⚠️ Úsala solo contra objetivos con autorización explícita (programas de
bug bounty en scope, contrato de pentesting, o infraestructura propia).

## 1. Instalación

```bash
pip install aiohttp
```

## 2. Preparar el archivo de targets

Un `targets.txt` con una **URL base por línea** (sin el parámetro a
fuzzear — el script lo añade él mismo):

```
https://ejemplo.com/search
https://ejemplo.com/products
```

## 3. Uso básico

```bash
python3 html_inject_fuzzer.py -l targets.txt
```

Esto corre con los ~141 parámetros y 7 payloads incluidos por defecto,
concurrencia 15 y sin límite de rate.

## 4. Uso avanzado

```bash
python3 html_inject_fuzzer.py \
  -l targets.txt \
  --params params_extra.txt \
  --payloads payloads_extra.txt \
  -c 20 --rate 30 \
  -o hallazgos.json --html-report reporte.html
```

| Flag | Qué hace |
|---|---|
| `-l / --list` | archivo con URLs base (obligatorio) |
| `--params` | archivo .txt con parámetros extra, uno por línea (se suman a los ~141 por defecto) |
| `--payloads` | archivo .txt con payloads extra; cada línea **debe incluir el literal** `{MARKER}` |
| `-c / --concurrency` | requests concurrentes (default: 15) |
| `--rate` | límite aproximado de requests/segundo por worker (0 = sin límite) |
| `--timeout` | timeout por request en segundos (default: 10) |
| `-o / --output` | archivo JSON de salida (default: `hallazgos.json`) |
| `--html-report` | archivo HTML de salida (default: `reporte_fuzz.html`) |
| `--only-vuln` | guarda en el JSON solo `reflected_unescaped` y `reflected_sanitized` |

## 5. Cómo detecta el reflejo (y evita falsos positivos)

Para cada combinación `URL + parámetro + payload`, el script genera un
**marcador único** (`{MARKER}`) por request y compara la respuesta contra
tres versiones del payload:

1. **Payload exacto** (con `< > "` sin tocar) aparece tal cual en el body
   → `reflected_unescaped` — vulnerable de verdad.
2. **Versión HTML-escapada** del payload completo (`&lt; &gt; &quot;`
   etc.) aparece en el body → `reflected_escaped` — seguro, el servidor
   está escapando correctamente.
3. Solo el **marcador** sobrevive, pero ni coincide con el crudo ni con
   el escapado estándar → `reflected_sanitized` — sanitización parcial
   (p. ej. stripping de tags), merece revisión manual porque ahí suelen
   esconderse bypasses.
4. Nada de esto aparece → `not_reflected`.

Esta comparación usa el **payload completo**, no solo el marcador —
porque un marcador alfanumérico puede sobrevivir intacto dentro de HTML
correctamente escapado (las etiquetas se escapan, el texto entre ellas
no cambia), lo cual generaría falsos positivos si solo se buscara el
marcador.

## 6. Clasificación de contexto (solo para `reflected_unescaped`)

Cuando el payload se refleja sin escapar, el script además identifica
**dónde** cayó dentro del HTML:

| Contexto | Significado |
|---|---|
| `html_tag_injected` | tu propio tag (`<u>`, `<svg>`, etc.) quedó insertado tal cual — alta confianza de XSS |
| `html_attribute` | el reflejo rompe un atributo HTML existente (`value="..."`, etc.) |
| `script_block` | el reflejo cae dentro de un `<script>` — revisar si rompe el contexto JS |
| `html_comment` | cae dentro de un comentario HTML — generalmente no explotable directo |
| `html_text` | texto plano, sin quedar envuelto en una etiqueta reconocible |

## 7. Payloads y parámetros por defecto

- **Parámetros**: ~141 nombres comunes en apps reales (`q`, `search`,
  `redirect`, `callback`, `email`, `file`, etc.)
- **Payloads**: variantes que cubren distintos vectores — ruptura de
  atributo, `<svg onload>`, cierre de `<script>`, etc. — todos con
  `{MARKER}` para que el script inserte el token único en cada request.

Puedes sumar tus propios parámetros y payloads con `--params` y
`--payloads` sin tocar el script.

## 8. Salidas

- **JSON** (`hallazgos.json` por defecto) — resultado estructurado
  completo de cada request: URL, parámetro, payload, status, contexto,
  si había CSP, notas.
- **HTML** (`reporte_fuzz.html` por defecto) — reporte visual agrupado
  por severidad, con las URLs como enlaces clicables para revisión
  rápida.

## 9. Siguiente paso: confirmar ejecución real de JS

Este script confirma **reflejo en el HTML**, no ejecución de JavaScript.
Los hallazgos en `reflected_unescaped` (y los `reflected_sanitized` que
valgan la pena) son el input ideal para pasarlos por `xss_verify.py`
(verificador con navegador headless vía Playwright), que carga la página
de verdad y confirma si el `alert()` se dispara — ese es el paso que da
la confianza necesaria antes de reportar.

## 10. Aviso de volumen de tráfico

Con los defaults (~141 params × 7 payloads) cada target genera cerca de
**987 requests**. El script te avisa si el total supera 5000. Ajusta
`-c` (concurrencia) y `--rate` (límite de requests/segundo) según lo que
el objetivo pueda tolerar sin generar ruido excesivo o disparar
rate-limiting/WAF bans.
