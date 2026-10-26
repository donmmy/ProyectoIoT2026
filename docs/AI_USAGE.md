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

### Prompt de la interfaz gráfica (2026-10-25)

> "vale, puedes hacer una interfaz grafica para no tener que usar los comandos?"

## Validación del código generado

- **Pruebas funcionales:** `pytest` con 34 casos sobre tráfico sintético (todos pasan).
  Pendiente: validación en laboratorio real comparando con Wireshark (Hito 6).
- **Revisión de seguridad:** sin `eval`/`exec`/`subprocess`; el texto que llega de la
  red (hostname DHCP/mDNS, banners SSDP, SNI de TLS) se sanea y recorta; el parser
  del ClientHello comprueba límites y devuelve `None` si el mensaje está cortado; el CSV escapa
  celdas que empiezan por `=`, `+`, `-` o `@`.
- **Linting:** `flake8` sin avisos. `bandit` pendiente (no se pudo instalar en Python 3.15
  por PyYAML; ejecutar en Python 3.11–3.13).

## Pendiente de revisión humana

- Ajustar la tabla de reglas de `heuristics.py` con los dispositivos reales del laboratorio.
- Calibrar pesos (fuerte 3 / media 2 / débil 1) y umbrales (baja 1-2, media 3-4, alta ≥5)
  con los dispositivos reales del laboratorio (Hito 6).
