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
| 2026-11-16 | Claude (Claude Code) | Hito 2 (TXT de mDNS) | Lectura de registros TXT: modelo y versión de firmware como base para la futura búsqueda de CVE; lista blanca de claves al anonimizar; 5 tests nuevos. Pedido por el autor ("pues añadimos la lectura de registros TXT") tras analizar con Claude qué información de firmware dejan escapar los IoT. |
| 2026-11-16 | Claude (Claude Code) | Búsqueda de CVE (`--cve`) | `vulns.py`: NVD por CPE + CISA KEV con caché, ritmo de NVD y nivel de certeza (modelo / modelo+firmware); CVE aparte de las alertas en consola, JSON, CSV y GUI; 19 tests nuevos con NVD/KEV simulados. Diseño propuesto por Claude y aceptado por el autor ("si me parece mejor separarlo"); Claude cambió el plan inicial al comprobar que buscar en KEV por fabricante solo daba ruido. |
| 2026-11-16 | Claude (Claude Code) | `--cve`: nivel fabricante y ejemplos | Clave de NVD en un fichero ignorado por git; nivel "fabricante (suposición)" con CVE recientes de hardware de la marca; `ejemplos/` regenerado; 10 tests nuevos. Pedido por el autor ("añade también los del nivel 2, con suposiciones que sean vulnerabilidades recientes"); Claude lo limitó a hardware (`h:`) y 2 años tras comprobar que `o:` daba cientos de CVE de Android. |
| 2026-11-19 | **Qwen** (propuestas) + Claude (Claude Code, revisión e implementación) | SSDP y modelo de amenazas | Segunda lista de Qwen; el autor eligió 3: tipos UPnP (NT/ST) con regla y alerta IGD, versiones del banner SSDP y de DHCP (firmware frente a librería, con CVE de miniupnpd/libupnp/BusyBox) y `docs/THREAT_MODEL.md`; 18 tests nuevos. Descartadas: sal persistente para `--anonymize`, Aho-Corasick, `mypy`; hilo de la GUI y bridges Hue/HomeKit ya estaban. |
| 2026-11-19 | **Qwen** (propuestas) + Claude (Claude Code, revisión e implementación) | Huella DHCP y EUI-64 | Tercera lista de Qwen; el autor eligió 2: huella DHCP (opción 55, campo `dhcp_fp` en las reglas) y alerta por IPv6 global con la MAC dentro (EUI-64); 20 tests nuevos. La tercera propuesta (TXT de mDNS) ya estaba hecha desde el 2026-11-16. |
| 2026-11-19 | **Kiro** (propuestas) + Claude (Claude Code, revisión e implementación) | JA3, DHCPv6, riesgo y eTLD+1 | Lista de Kiro; el autor eligió 4: huella JA3 del ClientHello (campo `ja3` en las reglas), hostname y vendor class de DHCPv6, nivel de riesgo combinado por dispositivo y DNS/SNI al dominio registrable al anonimizar (con la Public Suffix List copiada en el repo); 32 tests nuevos. TXT de mDNS y opción 55 ya estaban; SNI de QUIC descartado. |
| 2026-11-19 | Claude (Claude Code) | `--save-pcap` | Guardar la captura en vivo en un `.pcap` (CLI y casilla en la GUI) para comparar con Wireshark y repetir el análisis en el Hito 6; 10 tests nuevos. Pedido por el autor ("sí, añádelo"), que creía tenerlo hecho en otro ordenador sin subir: en el repositorio no existía en ningún commit. |
| 2026-11-19 | Claude (Claude Code) | Hito 6: primera prueba real | Comparación en local de una captura de Wireshark y otra del programa con `tshark`; corrección de dos fallos encontrados (IP pública del router, falsos positivos de la regla UPnP); 19 tests nuevos que los reproducen con tráfico sintético. Pedido por el autor ("aquí están los 2 informes" + "sí, corrige ambos"). |

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

### Segunda lista de Qwen (2026-11-19)

> El autor pegó otra lista de mejoras de **Qwen** (seguridad y privacidad, rendimiento,
> reglas y documentación para la defensa). Claude comparó cada una con el código y el autor
> eligió cuáles hacer.

| Propuesta de Qwen | Qué se hizo y por qué |
|---|---|
| `--anonymize-salt fichero` para comparar informes | **No elegida** por el autor. Nota de Claude: con una clave guardada, quien tenga el fichero puede deshacer los seudónimos probando todas las IP; sería una clave HMAC en un fichero ignorado por git, no una "sal" |
| Versión de firmware en banners HTTP, SSDP y mDNS | Hecho para **SSDP** (`SERVER`) y **DHCP** (`udhcp`), separando núcleo, protocolo, librería y producto. mDNS ya estaba (TXT, 2026-11-16). HTTP **no**: leer un banner web es conectarse al dispositivo (escaneo activo) |
| Aho-Corasick en `heuristics.py` | **No elegida**: con 15 reglas no hay lentitud medida, añade una dependencia compilada y perdería el anclaje a inicio de palabra `(?<![a-z])` |
| Type hints + `mypy` en la CI | **No elegida** (ya se descartó el 2026-10-26) |
| Captura de la GUI en otro hilo | **Ya estaba**: el análisis corre en un `threading.Thread` (`gui.py`) con `stop_event` |
| Regla UPnP IGD "en WS-Discovery o SSDP" | Hecho, pero solo en **SSDP**: `InternetGatewayDevice` no viaja en WS-Discovery. Campo `upnp` en las reglas (+3) y alerta MEDIA |
| Bridges Zigbee/Matter (`_zigbee._tcp`, `_hap._tcp`) | **Ya estaba** `_hap._tcp` y `_hue._tcp` en la regla de enchufes y bombillas. `_hap._tcp` es HomeKit (no Zigbee) y `_zigbee._tcp` no es un servicio estándar |
| `docs/THREAT_MODEL.md` | Hecho, con STRIDE y citando el código de cada mitigación. Al redactarlo salió un riesgo no mitigado (sin límite de dispositivos) |

### Tercera lista de Qwen (2026-11-19)

| Propuesta de Qwen | Qué se hizo y por qué |
|---|---|
| Huella DHCP con la opción 55 ("o `requested_addr`") | Hecho con la **opción 55** (`param_req_list`); `requested_addr` es la opción 50, la IP pedida, y no sirve de huella. Campo `dhcp_fp` en las reglas (+3, coincidencia exacta). Sin reglas todavía: las huellas reales saldrán del Hito 6 (no se inventan) |
| Marcar EUI-64 en direcciones link-local o globales | Hecho **solo para globales** (`2000::/3`) y con la MAC del propio equipo: en link-local EUI-64 es lo normal y no filtra nada fuera de la red local. Alerta BAJA |
| Leer los TXT de mDNS | **Ya estaba** desde el 2026-11-16 (`_parse_txt`, `models`, `firmware`, lista blanca al anonimizar) |

### Lista de Kiro (2026-11-19)

> El autor pegó una lista de **Kiro** ("lo que sobra es profundidad de huella, no base"). Claude
> la comparó con el código y el autor eligió 4.

| Propuesta de Kiro | Qué se hizo y por qué |
|---|---|
| JA3 del ClientHello | Hecho, en el mismo parser que el SNI; sin JA3 si el ClientHello llega partido (la huella sería falsa). Campo `ja3` en las reglas, sin huellas hasta el Hito 6. JA4 no: en IoT JA3 basta (pilas TLS fijas) |
| TXT de mDNS | **Ya estaba** (2026-11-16) |
| SNI de QUIC (HTTP/3) | **Descartado**: el esfuerzo no es "medio" sino alto (descifrar el paquete Initial con HKDF y AES-GCM, dependencia `cryptography`) y los IoT casi no usan QUIC |
| DNS/SNI a eTLD+1 | Hecho **solo al anonimizar** (la identificación usa los dominios completos) y con la Public Suffix List, no con "las dos últimas etiquetas" (fallaría con `co.uk`). También en las evidencias de las etiquetas |
| Alertas de riesgo combinadas | Hecho como **nivel de riesgo** por dispositivo (ALTO/MEDIO/BAJO con motivos), sin sustituir a las alertas sueltas. Los CVE por fabricante no cuentan |
| DHCPv6 + NDP | Hecho DHCPv6 (opciones 39 y 16). NDP no hacía falta: cualquier paquete IPv6 ya crea el dispositivo por su MAC |
| Huella DHCP opción 55 | **Ya estaba** (commit `35dea87`) |

Kiro decía "92 % de cobertura": era el 95 % antes de estos cambios y sigue siéndolo.

### Prompt de la interfaz gráfica (2026-10-25)

> "vale, puedes hacer una interfaz grafica para no tener que usar los comandos?"

## Validación del código generado

- **Pruebas funcionales:** `pytest` con 188 casos sobre tráfico sintético (todos pasan); cobertura del paquete
  `iot_scanner` 94 % y de las reglas 15/15. Se repiten en GitHub Actions en cada push.
  Primera prueba real frente a Wireshark el 2026-11-19 (red compartida, ver `programa_codigos.md`);
  falta la del laboratorio propio con el portátil como punto de acceso (Hito 6).
- **Revisión de seguridad:** sin `eval`/`exec`/`subprocess`; el texto que llega de la
  red (hostname DHCP/mDNS, banners SSDP, SNI de TLS, TXT de mDNS) se sanea; lo que llega de NVD también y recorta; el parser
  del ClientHello comprueba límites y devuelve `None` si el mensaje está cortado; el CSV escapa
  celdas que empiezan por `=`, `+`, `-` o `@`.
- **Linting:** `flake8` sin avisos. `bandit` 1.9.4 (Python 3.14) sin avisos con
  `bandit -r programa -s B101` (B101 = `assert` de pytest). El XML de WS-Discovery no se
  procesa con un parser XML (riesgo de XXE): regex acotadas sobre 8 KB como máximo.

## Pendiente de revisión humana

- Ajustar la tabla de reglas de `heuristics.py` con los dispositivos reales del laboratorio.
- Calibrar pesos (fuerte 3 / media 2 / débil 1) y umbrales (baja 1-2, media 3-4, alta ≥5)
  con los dispositivos reales del laboratorio (Hito 6).
