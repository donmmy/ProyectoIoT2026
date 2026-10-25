# ProyectoIoT2026 — Escáner de dispositivos IoT

Herramienta en Python + Scapy que descubre los dispositivos de una red local,
escucha pasivamente su tráfico, propone qué tipo de dispositivo es cada uno y
genera un informe con alertas de seguridad. Práctica de *Desarrollo de
Herramientas de Ciberseguridad*.

> **Uso legal:** solo en redes propias o con autorización explícita.

## Organización

| Carpeta | Contenido |
|---|---|
| [`programa/`](programa) | El programa: paquete `iot_scanner/`, CLI `net_device_scanner.py`, interfaz gráfica `gui.py`, lanzador `abrir_interfaz.bat`, tests y `requirements.txt` |
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
pip install -r programa/requirements.txt
```

- Windows: instalar [Npcap](https://npcap.com) y ejecutar la consola como administrador.
- Linux/Mac: ejecutar con `sudo`.

## Interfaz gráfica (sin comandos)

En Windows, doble clic en **`programa/abrir_interfaz.bat`**: pide permisos de administrador
(necesarios para capturar en vivo), prepara el entorno si hace falta y abre la ventana. También: `cd programa` y `python gui.py`.

En la ventana se elige el modo (ARP + escucha, solo escucha, solo ARP o analizar un
`.pcap`), la interfaz, la red y los tiempos, y se pulsa **Iniciar análisis**. Pestañas:

- **Dispositivos**: tabla ordenable; al seleccionar uno se ven sus etiquetas candidatas
  con las evidencias y puntos, protocolos, puertos, DNS, SNI, NTP, IPv6 y banners.
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
python net_device_scanner.py --sniff-only -t 120            # solo escucha (sin ARP)
python net_device_scanner.py --no-sniff                     # solo ARP scan
python net_device_scanner.py -o informe.json --csv informe.csv
python net_device_scanner.py --pcap captura.pcap            # análisis offline, sin root
python net_device_scanner.py --list-ifaces
```

Captura de ejemplo (tráfico sintético, en `ejemplos/`):

```bash
python net_device_scanner.py --pcap ../ejemplos/ejemplo_lab.pcap
python -m tests.lab_packets          # la regenera en ../ejemplos/ejemplo_lab.pcap
```

## Estructura de `programa/` (un módulo por hito)

| Hito | Módulo | Qué hace |
|---|---|---|
| 1 | `iot_scanner/discovery.py` | Autodetección de interfaz y CIDR, ARP scan, fabricante por OUI (detecta MAC aleatorias). Si nadie responde al ARP (aislamiento de clientes) se pasa a modo solo-escucha. |
| 2 | `iot_scanner/sniffer.py` | Captura en vivo o desde `.pcap`, agrega por MAC. Extrae TCP/UDP/DNS/DHCP/mDNS/SSDP/ARP, puertos servidos (SYN-ACK) frente a puertos cliente, hostname por DHCP opción 12 o mDNS, servicios mDNS, banners SSDP y vendor class DHCP. Todo texto de red se sanea. |
| 3 | `iot_scanner/heuristics.py` | Tabla de reglas (RTSP, MQTT, CoAP, UPnP, Chromecast, impresoras, NAS...). Hasta 3 etiquetas por dispositivo; cada evidencia pesa según lo específica que es (fuerte 3, media 2, débil 1) y la confianza sale de la suma (baja 1-2, media 3-4, alta ≥5). |
| 4 | `iot_scanner/report.py` | Tabla por consola, JSON y CSV (protegido contra inyección de fórmulas), resumen con recuento, protocolos más comunes, tipos y alertas por puertos sensibles (Telnet, FTP, MQTT sin TLS, UPnP, RTSP...). |

`iot_scanner/device.py` define el modelo de datos común, `net_device_scanner.py` es la CLI y
`gui.py` la interfaz gráfica (tkinter, incluido en Python; reutiliza las funciones de la CLI).

## Tests

```bash
cd programa
python -m pytest -q
python -m flake8 --max-line-length 120 iot_scanner net_device_scanner.py gui.py tests
```

Los tests usan tráfico sintético (`tests/lab_packets.py`): cámara Hikvision,
Chromecast, enchufe Tuya, sensor ESP32 con MQTT, bombilla Matter por IPv6 y un
dispositivo con hostname y SNI maliciosos para comprobar el saneado. No hace falta root ni red.

## Limitaciones conocidas

- La identificación es heurística: es una hipótesis para el analista, no un veredicto.
- En Wi-Fi sin modo monitor solo se ve el tráfico broadcast/multicast y el propio;
  el tráfico unicast entre otros equipos no llega a la tarjeta.
- Los dispositivos con MAC aleatoria no tienen fabricante OUI.
- La autodetección limita la red como mucho a /24 para no barrer redes enormes;
  usa `-n` para otro rango.
