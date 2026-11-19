# ProyectoIoT2026 — Escáner de dispositivos IoT

[![CI](https://github.com/donmmy/ProyectoIoT2026/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/donmmy/ProyectoIoT2026/actions/workflows/ci.yml)

Herramienta en Python + Scapy que descubre los dispositivos de una red local,
escucha pasivamente su tráfico, propone qué tipo de dispositivo es cada uno y
genera un informe con alertas de seguridad. Práctica de *Desarrollo de
Herramientas de Ciberseguridad*.

> **Uso legal:** solo en redes propias o con autorización explícita.

## Estado

| Hito | Contenido | Estado |
|---|---|---|
| 1 | Descubrimiento: ARP scan, red automática, fabricante por OUI | ✅ Hecho |
| 2 | Escucha pasiva: DHCP, mDNS (con TXT: modelo y firmware), DNS, SSDP (tipo UPnP y versiones), NTP, SNI de TLS, IPv6 (Matter/Thread) y WS-Discovery/ONVIF | ✅ Hecho |
| 3 | Identificación por reglas con pesos (`rules.json`) | ✅ Hecho |
| 4 | Informe: tabla, JSON/CSV (anonimizable) y alertas | ✅ Hecho |
| + | Vulnerabilidades conocidas (`--cve`): NVD por CPE y CISA KEV, con nivel de certeza | ✅ Hecho |
| 5 | Triaje asistido por IA sobre datos anonimizados | ⏳ Opcional, pendiente |
| 6 | Pruebas en laboratorio real frente a Wireshark y memoria | ⏳ Pendiente |

El detalle de decisiones, pendientes y sesiones está en [`docs/AGENT.md`](docs/AGENT.md).

## Organización

| Carpeta | Contenido |
|---|---|
| [`programa/`](programa) | El programa: paquete `iot_scanner/`, CLI `net_device_scanner.py`, interfaz gráfica `gui.py`, lanzador `abrir_interfaz.bat`, tests, reglas `iot_scanner/rules.json` y requisitos (`requirements*.txt`, `requirements.lock`) |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Modelo de amenazas: qué protege la herramienta, de quién (STRIDE), qué no ve y riesgos residuales |
| [`ejemplos/`](ejemplos) | Captura sintética `ejemplo_lab.pcap` y los informes que genera (JSON y CSV). No contienen datos de ninguna red real |
| [`docs/`](docs) | Apuntes: [uso de IA](docs/AI_USAGE.md), [teoría → código](docs/programa_codigos.md) y [contexto para agentes de IA](docs/AGENT.md) |

## Instalación

**Forma fácil (Windows):** instala [Python 3](https://www.python.org/downloads/) (marcando
*Add python.exe to PATH*) y [Npcap](https://npcap.com), y haz doble clic en
`programa/abrir_interfaz.bat`. La primera vez crea el entorno virtual `.venv` en la raíz
e instala las dependencias solo (tarda un minuto); las siguientes abre la ventana directamente.

**Forma manual**, desde la raíz del repositorio:

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r programa/requirements.txt       # solo el programa
pip install -r programa/requirements-dev.txt   # + tests, cobertura, flake8 y bandit
pip install -r programa/requirements.lock      # versiones exactas con las que se ha probado
```

- Windows: instalar [Npcap](https://npcap.com) y ejecutar la consola como administrador.
- Linux/Mac: ejecutar con `sudo`.

## Interfaz gráfica (sin comandos)

En Windows, doble clic en **`programa/abrir_interfaz.bat`**: pide permisos de administrador
(necesarios para capturar en vivo), prepara el entorno si hace falta y abre la ventana. También: `cd programa` y `python gui.py`.

En la ventana se elige el modo (ARP + escucha, solo escucha, solo ARP o analizar un
`.pcap`), la interfaz, la red y los tiempos, y se pulsa **Iniciar análisis**. Durante la
escucha en vivo, **■ Detener** la corta y se analiza lo capturado hasta ese momento. Encima
de la tabla, **Filtrar** busca por IP, MAC, fabricante, hostname o tipo. Pestañas:

- **Dispositivos**: tabla ordenable; al seleccionar uno se ven sus etiquetas candidatas
  con las evidencias y puntos, protocolos, puertos, DNS, SNI, NTP, IPv6, WS-Discovery, modelo,
  firmware, TXT de mDNS y banners.
- **Alertas**: coloreadas por severidad.
- **CVE**: vulnerabilidades conocidas si se marcó *Buscar CVE conocidos* (necesita internet);
  las que están en CISA KEV, en rojo.
- **Resumen** y **Registro** (la salida que daría la CLI).
- Botones **Exportar JSON / CSV**.

El modo `.pcap` no necesita permisos de administrador. Para probar sin red real, elige
`ejemplos/ejemplo_lab.pcap`.

## Uso por línea de comandos

Los comandos se ejecutan dentro de `programa/`:

```bash
cd programa
python net_device_scanner.py                                # autodetecta interfaz y red
python net_device_scanner.py -i eth0 -n 192.168.1.0/24 -t 60
python net_device_scanner.py --sniff-only -t 120            # solo escucha (sin ARP); Ctrl+C la corta antes
python net_device_scanner.py --no-sniff                     # solo ARP scan
python net_device_scanner.py -o informe.json --csv informe.csv
python net_device_scanner.py --pcap captura.pcap            # análisis offline, sin root
python net_device_scanner.py --list-ifaces
python net_device_scanner.py --arp-interval 0.05            # ARPs más espaciados (default 0.01 s)
python net_device_scanner.py --pcap c.pcap --anonymize -o informe.json   # sin MAC/IP/hostname reales
python net_device_scanner.py --pcap c.pcap --log scanner.log -v          # registro de depuración
python net_device_scanner.py --pcap c.pcap --rules mis_reglas.json       # reglas propias
python net_device_scanner.py --pcap c.pcap --cve                         # + CVE conocidos (internet)
python net_device_scanner.py -t 300 --save-pcap lab.pcap                 # guarda la captura (Wireshark, --pcap)
```

- **`--anonymize`**: los JSON/CSV exportados llevan seudónimos (HMAC-SHA256 con una clave
  aleatoria que no se guarda) en lugar de MAC, IP, IPv6, hostname, nombre ONVIF, interfaz y
  ruta del `.pcap`, y de los TXT de mDNS solo conservan las claves técnicas (modelo, versiones). El mismo dispositivo tiene el mismo seudónimo en todo el informe, pero no
  se puede revertir. La pantalla y el `--log` muestran los datos reales. En la GUI es la
  casilla *Anonimizar al exportar*.
- **Registro**: el progreso y los avisos salen por stderr (`[*]`, `[!]`; `[.]` con `-v`) y,
  con `--log`, a un fichero con todo el detalle. La tabla y el resumen salen por stdout.
- **`--save-pcap`**: guarda los paquetes de la escucha en vivo en un `.pcap` (en la GUI, la casilla
  *Guardar la captura*), para abrirla en Wireshark o repetir el análisis con `--pcap`. Lleva todo
  el tráfico en claro: es un dato sensible (está en `.gitignore`).
- **`--cve`**: busca vulnerabilidades conocidas en [NVD](https://nvd.nist.gov) por el modelo
  (pasado a nombre CPE) y marca las que están en el catálogo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  (explotadas activamente). Cada CVE lleva su certeza: **modelo+firmware** (la versión
  anunciada es vulnerable), **modelo** (sin versión) o **fabricante (suposición)**: si solo se
  sabe la marca, los CVE recientes (2 años) de su hardware, como mucho 5, que hablan de otros
  equipos de la marca y no de este. Los que la versión descarta no salen. Van en una sección
  aparte de las alertas; solo pasa a alerta ALTA un CVE en KEV con certeza modelo+firmware. A internet solo se envían modelos y fabricantes, nunca MAC/IP/hostname. Caché de 24 h en
  `~/.cache/iot_scanner` (`--cve-cache`). Sin clave de NVD espera 6 s entre consultas; con
  [clave](https://nvd.nist.gov/developers/request-an-api-key), 0,6 s: pégala en
  `programa/nvd_api_key.txt` (está en `.gitignore`, no se sube) o en la variable `NVD_API_KEY`.
  La clave solo se envía a NVD y no sale en el registro.
- **Reglas**: las reglas de identificación, sus pesos y umbrales están en
  `iot_scanner/rules.json`; se pueden editar o cargar otro fichero con `--rules`.

Captura de ejemplo (tráfico sintético, en `ejemplos/`):

```bash
python net_device_scanner.py --pcap ../ejemplos/ejemplo_lab.pcap
python -m tests.lab_packets          # la regenera en ../ejemplos/ejemplo_lab.pcap
```

## Estructura de `programa/` (un módulo por hito)

| Hito | Módulo | Qué hace |
|---|---|---|
| 1 | `iot_scanner/discovery.py` | Autodetección de interfaz y CIDR, ARP scan, fabricante por OUI (detecta MAC aleatorias). Si nadie responde al ARP (aislamiento de clientes) se pasa a modo solo-escucha. |
| 2 | `iot_scanner/sniffer.py` | Captura en vivo o desde `.pcap`, agrega por MAC. Extrae TCP/UDP/DNS/DHCP/mDNS/SSDP/ARP, NTP, SNI de TLS, IPv6 y WS-Discovery/ONVIF, puertos servidos (SYN-ACK) frente a puertos cliente, hostname por DHCP opción 12 o mDNS, servicios mDNS y sus registros TXT (modelo y firmware), banners SSDP y vendor class DHCP. Huella DHCP (opción 55), huella TLS JA3, nombre y vendor class de DHCPv6, y aviso si una IPv6 global lleva la MAC dentro (EUI-64). De SSDP, el tipo UPnP (`NT`/`ST`) y las versiones del `SERVER`, separando firmware del producto y librerías (miniupnpd, BusyBox). Todo texto de red se sanea. |
| 3 | `iot_scanner/heuristics.py` + `rules.json` | Reglas en JSON (RTSP, MQTT, CoAP, UPnP, Chromecast, impresoras, NAS...), validadas al cargar. Hasta 3 etiquetas por dispositivo; cada evidencia pesa según lo específica que es (fuerte 3, media 2, débil 1) y la confianza sale de la suma (baja 1-2, media 3-4, alta ≥5). |
| 4 | `iot_scanner/report.py` | Tabla por consola, JSON y CSV (protegido contra inyección de fórmulas), resumen con recuento, protocolos más comunes, tipos y alertas por puertos sensibles (Telnet, FTP, MQTT sin TLS, UPnP, RTSP...) y por UPnP IGD anunciado (el router abre puertos a quien se lo pida) o IPv6 global con la MAC dentro. Nivel de riesgo por dispositivo (ALTO/MEDIO/BAJO) que resume alertas y CVE fiables. Anonimización opcional de lo exportado. |
| + | `iot_scanner/vulns.py` | `--cve`: modelo → CPE (diccionario de NVD), librerías de los banners (miniupnpd, libupnp, BusyBox), CVE de NVD, nivel de certeza por versión, marca de CISA KEV, caché y ritmo de consultas. |

`iot_scanner/device.py` define el modelo de datos común, `iot_scanner/logsetup.py` el registro, `net_device_scanner.py` es la CLI y
`gui.py` la interfaz gráfica (tkinter, incluido en Python; reutiliza las funciones de la CLI).

## Tests

```bash
cd programa
python -m pytest -q --cov=iot_scanner --cov-report=term-missing   # cobertura del paquete: 94 %
python -m flake8 --max-line-length 120 iot_scanner net_device_scanner.py gui.py tests
python -m bandit -q -r . -s B101                                   # B101 = assert de pytest
```

En GitHub se ejecutan solos en cada push (GitHub Actions, `.github/workflows/ci.yml`): tests
con cobertura mínima del 85 %, flake8 y bandit, en Python 3.12 y 3.14.

Los tests usan tráfico sintético (`tests/lab_packets.py`): cámara Hikvision (con Hello ONVIF),
Chromecast, enchufe Tuya, sensor ESP32 con MQTT, bombilla Matter por IPv6 y un
dispositivo con hostname y SNI maliciosos para comprobar el saneado; además, un dispositivo
por cada regla restante (altavoz, CoAP, Thread, impresora, NAS, Apple, Windows y Android),
así que el tráfico sintético ejercita las 15 reglas. No hace falta root ni red: los tests de
`--cve` usan respuestas de NVD y KEV simuladas.

Varias mejoras de calidad y privacidad (reglas en JSON, logging, `--anonymize`,
`--arp-interval`, dependencias fijadas, CI con cobertura y el filtro de la GUI) fueron
propuestas por **Qwen** e implementadas con Claude; el detalle está en `docs/AI_USAGE.md`.

## Limitaciones conocidas

- La identificación es heurística: es una hipótesis para el analista, no un veredicto.
- El ARP scan es **activo** (envía paquetes); la escucha es **pasiva**. Con `--sniff-only`
  la herramienta no envía nada.
- En una red con switch o en Wi-Fi sin modo monitor solo se ve el tráfico broadcast/multicast
  y el propio; el tráfico unicast entre otros equipos (por ejemplo, cámara ↔ nube) no llega a
  la tarjeta. Para verlo hace falta port mirroring, un hub o usar el portátil como punto de acceso.
- WS-Discovery: en pasivo solo se ve el `Hello` de un dispositivo cuando se conecta a la red
  durante la escucha.
- `--anonymize` deja las consultas DNS y el SNI en el dominio registrable (`hik-connect.com`,
  con la [Public Suffix List](https://publicsuffix.org), MPL-2.0, copiada en
  `iot_scanner/public_suffix_list.dat`): el dominio base aún dice con qué servicios habla un
  móvil. No afecta a la pantalla ni al `--log`.
- Los dispositivos con MAC aleatoria no tienen fabricante OUI.
- `--cve` solo encuentra dispositivos que anuncian un modelo con nombre CPE en NVD; sin
  versión, "certeza modelo" quiere decir que ese modelo ha tenido el fallo, no que este
  equipo lo tenga (puede estar actualizado).
- La autodetección limita la red como mucho a /24 para no barrer redes enormes;
  usa `-n` para otro rango.
