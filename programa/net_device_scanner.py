#!/usr/bin/env python3
"""
net_device_scanner.py

Escáner de dispositivos IoT en red local: descubrimiento ARP, fingerprinting
pasivo por tráfico, heurísticas de identificación e informe JSON/CSV.

USO LEGAL: solo contra redes propias o para las que tengas autorización
explícita (p. ej. tu laboratorio de Hacking Ético / Análisis Forense).
Escanear o esnifar redes ajenas sin permiso es ilegal en la mayoría de países.

Requisitos:
    pip install -r requirements.txt
    - Linux/Mac: ejecutar con sudo (necesita raw sockets)
    - Windows: instalar Npcap (https://npcap.com) y ejecutar como administrador

Uso:
    sudo python3 net_device_scanner.py                       # autodetecta interfaz/red
    sudo python3 net_device_scanner.py -i eth0 -n 192.168.1.0/24
    sudo python3 net_device_scanner.py --sniff-only -t 120    # solo escucha, sin ARP (Ctrl+C la corta antes)
    sudo python3 net_device_scanner.py -t 60 -o res.json --csv res.csv
    python3 net_device_scanner.py --pcap captura.pcap         # análisis offline, sin root
    python3 net_device_scanner.py --list-ifaces
    python3 net_device_scanner.py --pcap c.pcap --anonymize -o res.json   # informe sin MAC/IP reales
    python3 net_device_scanner.py --pcap c.pcap --log scanner.log -v      # registro de depuración
"""

import argparse
import logging
import sys
import time

try:
    from scapy.all import conf, get_if_hwaddr, get_if_list
except ImportError:
    print("[!] Falta scapy. Instálalo con: pip install -r requirements.txt")
    sys.exit(1)

from iot_scanner import discovery, heuristics, report, sniffer
from iot_scanner.logsetup import LOGGER_NAME, setup_logging

log = logging.getLogger(f"{LOGGER_NAME}.cli")


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Descubrimiento + fingerprinting pasivo de dispositivos IoT en red local")
    p.add_argument("-i", "--iface", help="Interfaz de red (ej. eth0, wlan0)")
    p.add_argument("-n", "--network", help="Red en CIDR, ej. 192.168.1.0/24 (se autodetecta si no se indica)")
    p.add_argument("-t", "--time", type=int, default=30, help="Segundos de escucha pasiva (default 30)")
    p.add_argument("--arp-timeout", type=int, default=3, help="Timeout del ARP scan en segundos (default 3)")
    p.add_argument("--arp-interval", type=float, default=discovery.DEFAULT_ARP_INTERVAL,
                   help="Segundos entre ARPs para no saturar la red "
                        f"(default {discovery.DEFAULT_ARP_INTERVAL}; 0 = sin pausa)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--sniff-only", action="store_true", help="Omite el ARP scan y solo escucha pasivamente")
    mode.add_argument("--no-sniff", action="store_true", help="Solo ARP scan, sin escucha pasiva")
    mode.add_argument("--pcap", help="Analiza un fichero .pcap en lugar de capturar en vivo")
    p.add_argument("-o", "--output", help="Ruta del fichero JSON de salida")
    p.add_argument("--csv", help="Ruta del fichero CSV de salida")
    p.add_argument("--anonymize", action="store_true",
                   help="Seudónimos (HMAC con clave aleatoria) para MAC, IP, hostname... en JSON/CSV")
    p.add_argument("--rules", help="Fichero de reglas JSON propio (por defecto iot_scanner/rules.json)")
    p.add_argument("--log", help="Guarda un registro detallado (DEBUG) en este fichero")
    p.add_argument("-v", "--verbose", action="store_true", help="Muestra también los mensajes de depuración")
    p.add_argument("--list-ifaces", action="store_true", help="Lista las interfaces disponibles y sale")
    args = p.parse_args(argv)
    if args.time < 0 or args.arp_timeout < 1 or not 0 <= args.arp_interval <= 1:
        p.error("los tiempos deben ser positivos (y --arp-interval entre 0 y 1 s)")
    return args


def run_live(args, stop_event=None):
    iface, network = args.iface, args.network
    if not iface or not network:
        auto_iface, auto_net = discovery.guess_network(iface)
        iface = iface or auto_iface
        network = network or auto_net
    network = discovery.validate_network(network)

    try:
        own_mac = get_if_hwaddr(iface)
    except Exception:
        own_mac = None

    devices = {}
    mode = "sniff-only" if args.sniff_only else "arp+sniff"
    if not args.sniff_only:
        devices = discovery.arp_scan(network, iface, timeout=args.arp_timeout, inter=args.arp_interval)
        if not devices:
            # Hito 1: red con aislamiento de clientes o ARP filtrado
            log.warning("Nadie respondió al ARP (¿aislamiento de clientes / AP isolation?). "
                        "Cambiando a modo solo-escucha.")
            mode = "fallback-sniff-only"
            if args.no_sniff:
                args.no_sniff = False
                args.time = args.time or 30

    listened = 0
    if not args.no_sniff and args.time > 0:
        t0 = time.monotonic()
        sniffer.sniff_live(iface, args.time, devices, ignore_macs=[own_mac], stop_event=stop_event)
        listened = round(time.monotonic() - t0)  # puede ser menor si se detuvo antes

    return devices, {"iface": str(iface), "network": network, "mode": mode,
                     "listen_seconds": listened}


def analyze(args, stop_event=None):
    """Captura (o lee el .pcap), clasifica y devuelve (devices, meta). Lo usan la CLI y la GUI."""
    if args.rules:
        heuristics.use_rules(args.rules)
    if args.pcap:
        devices = sniffer.sniff_pcap(args.pcap)
        meta = {"mode": "pcap", "pcap": args.pcap}
    else:
        devices, meta = run_live(args, stop_event)
    heuristics.classify_all(devices)
    return devices, meta


def export(devices, meta, args):
    """Guarda JSON/CSV; con --anonymize, de una copia con seudónimos."""
    if not (args.output or args.csv):
        return
    if args.anonymize:
        devices, meta = report.anonymize(devices, meta)
        log.info("Informe anonimizado: MAC, IP, hostname e interfaz sustituidos por seudónimos.")
    summary = report.build_summary(devices, meta)
    if args.output:
        report.export_json(devices, summary, args.output)
    if args.csv:
        report.export_csv(devices, args.csv)


def main(argv=None):
    args = parse_args(argv)
    setup_logging(verbose=args.verbose, log_file=args.log)

    if args.list_ifaces:
        for name in get_if_list():
            mark = " (por defecto)" if str(name) == str(conf.iface) else ""
            print(f"  {name}{mark}")
        return 0

    devices, meta = analyze(args)
    report.print_table(devices)
    report.print_summary(report.build_summary(devices, meta))
    export(devices, meta, args)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PermissionError:
        log.error("Necesitas permisos de administrador/root para capturar paquetes (usa sudo).")
        sys.exit(1)
    except (RuntimeError, ValueError, OSError) as e:
        log.error("Error: %s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        log.info("Interrumpido por el usuario.")
        sys.exit(130)
