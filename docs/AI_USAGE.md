# Uso de IA en el desarrollo

Según la estrategia del planteamiento, la IA se usa como apoyo al desarrollo
(generación de código, tests y documentación). El núcleo de la herramienta no
depende de IA en tiempo de ejecución.

## Registro

| Fecha | Asistente | Parte | Qué se generó / revisó |
|---|---|---|---|
| Antes del 2026-10-18 (fecha exacta sin registrar) | Claude | `net_device_scanner.py` v0 | Prototipo con ARP scan + sniffer básico, **generado por Claude a partir del PDF de planteamiento**. El autor solo aportó el PDF y lo revisó por encima; no hubo revisión línea a línea. Esa revisión se ha hecho después, hito a hito (ver `programa_codigos.md`). |
| 2026-10-18 | Claude (Claude Code) | Hitos 1–4 | Refactor en el paquete `iot_scanner/` (discovery, sniffer, heuristics, report), CLI nueva, tests con tráfico sintético, README. |
| 2026-10-21 | Claude (Claude Code) | Ampliación Hito 2 | Extractores NTP y TLS SNI, soporte IPv6, reglas Matter/Thread, tests y tráfico sintético nuevos. Revisado con el autor junto a `programa_codigos.md`. |
| 2026-10-25 | Claude (Claude Code) | Hito 3 | Pesos por especificidad de la evidencia, umbrales sobre la suma, regex con inicio de palabra, sin doble conteo servidor/cliente; 5 tests nuevos. Propuesto por la IA tras revisar fallos con el autor; el autor decidió implementarlo. |
| 2026-10-25 | Claude (Claude Code) | Interfaz gráfica | `gui.py` (tkinter) y `abrir_interfaz.bat`; 3 tests nuevos. Revisada con captura de pantalla sobre el pcap de ejemplo. |
| 2026-10-26 | Claude (Claude Code) | Seguridad y ampliación | Correcciones de `bandit`; WS-Discovery/ONVIF; escucha en vivo parable (`AsyncSniffer`, botón Detener, Ctrl+C); 8 tests nuevos. Pedido por el autor ("vamos a solucionar lo demás") tras revisar los pendientes. |
| 2026-10-26 | **Qwen** (propuestas) + Claude (Claude Code, revisión e implementación) | Mejoras de calidad y privacidad | Qwen propuso una lista de mejoras; el autor eligió 8 y Claude las implementó con ajustes: reglas en `rules.json` (JSON en vez de YAML), logging, `--anonymize` (HMAC con clave aleatoria en vez de hash con sal), `--arp-interval` (0,01 s configurable en vez de 0,05 s fijo), `requirements.lock`, CI de GitHub Actions con cobertura, cobertura de reglas 15/15 y filtro en la GUI; 13 tests nuevos. Descartadas: `mypy` y resultados en tiempo real. |

### Prompt del prototipo inicial (antes del 2026-10-18)

> Se pasó a Claude el documento de planteamiento (PDF) para que generase un primer
> script; el texto exacto del prompt no se conserva.

### Prompt principal (2026-10-18)

> "Ya vamos tarde, si me puedes ayudar a completar de hitos 1-4"
> (adjuntando el documento de planteamiento con la descripción de los hitos).

### Prompt de la ampliación (2026-10-21)

> "si me parece interesante añadir los protocolos ntp + tls(sni) + matter/thread"
> (tras repasar qué protocolos de capa 7 no miraba el sniffer).

### Prompt de los pesos del Hito 3 (2026-10-25)

> "implementalo, documentalo para agent y subelo al git"
> (tras ver casos mal clasificados y preguntar si quitar peso a los puertos típicos
> no perdía información sobre el IoT).

### Mejoras propuestas por Qwen (2026-10-26)

> El autor pegó una lista de mejoras sugeridas por **Qwen** (seguridad y privacidad,
> arquitectura, DevOps y GUI) con la indicación: "si los vas a coger documéntalas como
> de su parte".

Claude revisó cada propuesta antes de implementarla y corrigió algunos detalles:

| Propuesta de Qwen | Qué se hizo y por qué |
|---|---|
| `--anonymize` con SHA-256 y sal | HMAC-SHA256 con clave aleatoria por informe que no se guarda. Un hash con sal de una IPv4 se revierte probando las 2³² posibles; con HMAC y clave secreta no. |
| `inter=0.05` en `srp` ("mini-DoS") | Opción `--arp-interval`, 0,01 s por defecto. Como mucho se envían 254 ARPs (red recortada a /24); 0,05 s alargaría el escaneo a ~13 s. |
| Fijar versiones (`scapy==2.6.1`) | `requirements.lock` con las versiones reales probadas (scapy 2.8.0). `requirements.txt` solo con scapy para el lanzador; herramientas en `requirements-dev.txt`. |
| Reglas en `rules.yaml` o `rules.json` | JSON: sin PyYAML (no compilaba en Python 3.15) ni el riesgo de cargar YAML. Con validación al cargar y opción `--rules`. |
| `print()` → `logging` | Hecho; la tabla y el resumen siguen en stdout, el progreso va a stderr y a `--log`. |
| GitHub Actions + `pytest-cov`, "80 % de las reglas" | CI con pytest, flake8 y bandit; umbral de cobertura de líneas 85 % (actual 92 %). Cobertura de reglas: 15 de 15 con tráfico sintético nuevo. |
| Filtro en la tabla de la GUI | Hecho. |
| `mypy` | Descartada por el autor: el código casi no tiene anotaciones y Scapy no tiene tipos. |
| Resultados en tiempo real en la GUI | Descartada por el autor: mucho coste frente al Hito 6. |

### Prompt de la interfaz gráfica (2026-10-25)

> "vale, puedes hacer una interfaz grafica para no tener que usar los comandos?"

## Validación del código generado

- **Pruebas funcionales:** `pytest` con 55 casos sobre tráfico sintético (todos pasan); cobertura del paquete
  `iot_scanner` 92 % y de las reglas 15/15. Se repiten en GitHub Actions en cada push.
  Pendiente: validación en laboratorio real comparando con Wireshark (Hito 6).
- **Revisión de seguridad:** sin `eval`/`exec`/`subprocess`; el texto que llega de la
  red (hostname DHCP/mDNS, banners SSDP, SNI de TLS) se sanea y recorta; el parser
  del ClientHello comprueba límites y devuelve `None` si el mensaje está cortado; el CSV escapa
  celdas que empiezan por `=`, `+`, `-` o `@`.
- **Linting:** `flake8` sin avisos. `bandit` 1.9.4 (Python 3.14) sin avisos con
  `bandit -r programa -s B101` (B101 = `assert` de pytest). El XML de WS-Discovery no se
  procesa con un parser XML (riesgo de XXE): regex acotadas sobre 8 KB como máximo.

## Pendiente de revisión humana

- Ajustar la tabla de reglas de `heuristics.py` con los dispositivos reales del laboratorio.
- Calibrar pesos (fuerte 3 / media 2 / débil 1) y umbrales (baja 1-2, media 3-4, alta ≥5)
  con los dispositivos reales del laboratorio (Hito 6).
