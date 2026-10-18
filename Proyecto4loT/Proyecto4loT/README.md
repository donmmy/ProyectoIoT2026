# Escáner de dispositivos IoT

Herramienta en Python + Scapy que descubre los dispositivos de una red local,
escucha pasivamente su tráfico, propone qué tipo de dispositivo es cada uno y
genera un informe con alertas de seguridad.

> **Uso legal:** solo en redes propias o con autorización explícita.

## Instalación

```bash
python -m venv .venv
.venv/Scripts/activate      # Windows  (Linux/Mac: source .venv/bin/activate)
pip install -r requirements.txt
```

- Windows: instalar [Npcap](https://npcap.com) y ejecutar la consola como administrador.
- Linux/Mac: ejecutar con `sudo`.

## Uso

```bash
python net_device_scanner.py                                # autodetecta interfaz y red
python net_device_scanner.py -i eth0 -n 192.168.1.0/24 -t 60
python net_device_scanner.py --sniff-only -t 120            # solo escucha (sin ARP)
python net_device_scanner.py --no-sniff                     # solo ARP scan
python net_device_scanner.py -o informe.json --csv informe.csv
python net_device_scanner.py --pcap captura.pcap            # análisis offline, sin root
python net_device_scanner.py --list-ifaces
```

Captura de ejemplo para probar sin red real:

```bash
python -m tests.lab_packets ejemplo_lab.pcap
python net_device_scanner.py --pcap ejemplo_lab.pcap
```

## Estructura (un módulo por hito)

| Hito | Módulo | Qué hace |
|---|---|---|
| 1 | `iot_scanner/discovery.py` | Autodetección de interfaz y CIDR, ARP scan, fabricante por OUI (detecta MAC aleatorias). Si nadie responde al ARP (aislamiento de clientes) se pasa a modo solo-escucha. |
| 2 | `iot_scanner/sniffer.py` | Captura en vivo o desde `.pcap`, agrega por MAC. Extrae TCP/UDP/DNS/DHCP/mDNS/SSDP/ARP, puertos servidos (SYN-ACK) frente a puertos cliente, hostname por DHCP opción 12 o mDNS, servicios mDNS, banners SSDP y vendor class DHCP. Todo texto de red se sanea. |
| 3 | `iot_scanner/heuristics.py` | Tabla de reglas (RTSP, MQTT, CoAP, UPnP, Chromecast, impresoras, NAS...). Hasta 3 etiquetas por dispositivo con puntuación = nº de evidencias y confianza baja/media/alta. |
| 4 | `iot_scanner/report.py` | Tabla por consola, JSON y CSV (protegido contra inyección de fórmulas), resumen con recuento, protocolos más comunes, tipos y alertas por puertos sensibles (Telnet, FTP, MQTT sin TLS, UPnP, RTSP...). |

`iot_scanner/device.py` define el modelo de datos común y `net_device_scanner.py` es la CLI.

## Tests

```bash
python -m pytest -q
python -m flake8 --max-line-length 120 iot_scanner net_device_scanner.py tests
```

Los tests usan tráfico sintético (`tests/lab_packets.py`): cámara Hikvision,
Chromecast, enchufe Tuya, sensor ESP32 con MQTT y un dispositivo con hostname
malicioso para comprobar el saneado. No hace falta root ni red.

## Limitaciones conocidas

- La identificación es heurística: es una hipótesis para el analista, no un veredicto.
- En Wi-Fi sin modo monitor solo se ve el tráfico broadcast/multicast y el propio;
  el tráfico unicast entre otros equipos no llega a la tarjeta.
- Los dispositivos con MAC aleatoria no tienen fabricante OUI.
- La autodetección limita la red como mucho a /24 para no barrer redes enormes;
  usa `-n` para otro rango.
