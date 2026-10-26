# ProyectoIoT2026 — Escáner de dispositivos IoT

Herramienta en Python + Scapy que descubre los dispositivos de una red local,
escucha pasivamente su tráfico, propone qué tipo de dispositivo es cada uno y
genera un informe con alertas de seguridad. Práctica de *Desarrollo de
Herramientas de Ciberseguridad*.

> **Uso legal:** solo en redes propias o con autorización explícita.

## Organización

| Carpeta | Contenido |
|---|---|
| [`programa/`](programa) | El programa: paquete `iot_scanner/`, CLI `net_device_scanner.py`, interfaz gráfica `gui.py`, lanzador `abrir_interfaz.bat`, tests, reglas `iot_scanner/rules.json` y requisitos (`requirements*.txt`, `requirements.lock`) |
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
  con las evidencias y puntos, protocolos, puertos, DNS, SNI, NTP, IPv6, WS-Discovery y banners.
- **Alertas**: coloreadas por severidad.
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
```

- **`--anonymize`**: los JSON/CSV exportados llevan seudónimos (HMAC-SHA256 con una clave
  aleatoria que no se guarda) en lugar de MAC, IP, IPv6, hostname, nombre ONVIF, interfaz y
  ruta del `.pcap`. El mismo dispositivo tiene el mismo seudónimo en todo el informe, pero no
  se puede revertir. La pantalla y el `--log` muestran los datos reales. En la GUI es la
  casilla *Anonimizar al exportar*.
- **Registro**: el progreso y los avisos salen por stderr (`[*]`, `[!]`; `[.]` con `-v`) y,
  con `--log`, a un fichero con todo el detalle. La tabla y el resumen salen por stdout.
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
| 2 | `iot_scanner/sniffer.py` | Captura en vivo o desde `.pcap`, agrega por MAC. Extrae TCP/UDP/DNS/DHCP/mDNS/SSDP/ARP, NTP, SNI de TLS, IPv6 y WS-Discovery/ONVIF, puertos servidos (SYN-ACK) frente a puertos cliente, hostname por DHCP opción 12 o mDNS, servicios mDNS, banners SSDP y vendor class DHCP. Todo texto de red se sanea. |
| 3 | `iot_scanner/heuristics.py` + `rules.json` | Reglas en JSON (RTSP, MQTT, CoAP, UPnP, Chromecast, impresoras, NAS...), validadas al cargar. Hasta 3 etiquetas por dispositivo; cada evidencia pesa según lo específica que es (fuerte 3, media 2, débil 1) y la confianza sale de la suma (baja 1-2, media 3-4, alta ≥5). |
| 4 | `iot_scanner/report.py` | Tabla por consola, JSON y CSV (protegido contra inyección de fórmulas), resumen con recuento, protocolos más comunes, tipos y alertas por puertos sensibles (Telnet, FTP, MQTT sin TLS, UPnP, RTSP...). Anonimización opcional de lo exportado. |

`iot_scanner/device.py` define el modelo de datos común, `iot_scanner/logsetup.py` el registro, `net_device_scanner.py` es la CLI y
`gui.py` la interfaz gráfica (tkinter, incluido en Python; reutiliza las funciones de la CLI).

## Tests

```bash
cd programa
python -m pytest -q --cov=iot_scanner --cov-report=term-missing   # cobertura del paquete: 92 %
python -m flake8 --max-line-length 120 iot_scanner net_device_scanner.py gui.py tests
python -m bandit -q -r . -s B101                                   # B101 = assert de pytest
```

En GitHub se ejecutan solos en cada push (GitHub Actions, `.github/workflows/ci.yml`): tests
con cobertura mínima del 85 %, flake8 y bandit, en Python 3.12 y 3.14.

Los tests usan tráfico sintético (`tests/lab_packets.py`): cámara Hikvision (con Hello ONVIF),
Chromecast, enchufe Tuya, sensor ESP32 con MQTT, bombilla Matter por IPv6 y un
dispositivo con hostname y SNI maliciosos para comprobar el saneado; además, un dispositivo
por cada regla restante (altavoz, CoAP, Thread, impresora, NAS, Apple, Windows y Android),
así que el tráfico sintético ejercita las 15 reglas. No hace falta root ni red.

Varias mejoras de calidad y privacidad (reglas en JSON, logging, `--anonymize`,
`--arp-interval`, dependencias fijadas, CI con cobertura y el filtro de la GUI) fueron
propuestas por **Qwen** e implementadas con Claude; el detalle está en `docs/AI_USAGE.md`.

## Limitaciones conocidas

- La identificación es heurística: es una hipótesis para el analista, no un veredicto.
- En Wi-Fi sin modo monitor solo se ve el tráfico broadcast/multicast y el propio;
  el tráfico unicast entre otros equipos no llega a la tarjeta.
- Los dispositivos con MAC aleatoria no tienen fabricante OUI.
- La autodetección limita la red como mucho a /24 para no barrer redes enormes;
  usa `-n` para otro rango.
