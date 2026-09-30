#!/usr/bin/env python3
"""
net_device_scanner.py

Herramienta de descubrimiento de dispositivos en una red local + fingerprinting
pasivo mediante análisis de tráfico.

USO LEGAL: solo contra redes propias o para las que tengas autorización
explícita (p. ej. tu laboratorio de Hacking Ético / Análisis Forense).
Escanear o esnifar redes ajenas sin permiso es ilegal en la mayoría de países.

Requisitos:
    pip install scapy
    - Linux/Mac: ejecutar con sudo (necesita raw sockets)
    - Windows: instalar Npcap (https://npcap.com) y ejecutar como administrador

Uso:
    sudo python3 net_device_scanner.py                     # detecta interfaz/red automáticamente
    sudo python3 net_device_scanner.py -i eth0 -n 192.168.1.0/24
    sudo python3 net_device_scanner.py --sniff-only         # solo escucha, sin ARP scan
    sudo python3 net_device_scanner.py -t 60 -o resultado.json
"""

import argparse
import json
import sys
import time
from collections import defaultdict

try:
    from scapy.all import (
        ARP, Ether, IP, TCP, UDP, DNS, DHCP, srp, sniff, conf, get_if_addr,
        get_if_list, Dot11
    )
    from scapy.layers.dhcp import BOOTP
except ImportError:
    print("[!] Falta scapy. Instálalo con: pip install scapy")
    sys.exit(1)

try:
    import ipaddress
except ImportError:
    ipaddress = None


# ----------------------------------------------------------------------
# Utilidades
# ----------------------------------------------------------------------

def guess_network(iface=None):
    """Intenta deducir la red local (IP/24) a partir de la interfaz activa."""
    iface = iface or conf.iface
    ip = get_if_addr(iface)
    if not ip or ip == "0.0.0.0":
        raise RuntimeError(f"No se pudo obtener IP de la interfaz {iface}")
    net = ".".join(ip.split(".")[:3]) + ".0/24"
    return iface, net


def load_oui_db():
    """Usa la base de fabricantes (OUI) que trae Scapy si está disponible."""
    try:
        from scapy.data import MANUFDB
        return MANUFDB
    except Exception:
        return None


OUI_DB = load_oui_db()


def vendor_from_mac(mac):
    if not OUI_DB:
        return "desconocido"
    try:
        result = OUI_DB._get_manuf(mac)
        return result or "desconocido"
    except Exception:
        return "desconocido"


# ----------------------------------------------------------------------
# Fase 1: descubrimiento activo (ARP scan)
# ----------------------------------------------------------------------

def arp_scan(network, iface, timeout=3):
    """Envía peticiones ARP broadcast y recoge quién responde."""
    print(f"[*] Lanzando ARP scan sobre {network} (iface={iface})...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, iface=iface, verbose=False)

    devices = {}
    for _, resp in answered:
        ip = resp.psrc
        mac = resp.hwsrc.lower()
        devices[mac] = {
            "ip": ip,
            "mac": mac,
            "vendor": vendor_from_mac(mac),
            "hostname": None,
            "protocols": set(),
            "ports_dst": set(),
            "packet_count": 0,
        }
    print(f"[*] {len(devices)} dispositivos respondieron al ARP scan.")
    return devices


# ----------------------------------------------------------------------
# Fase 2: escucha pasiva para "ver qué paquetes sueltan"
# ----------------------------------------------------------------------

def build_sniffer(devices, by_mac_index):
    """Crea el callback que procesa cada paquete capturado."""

    def handle_packet(pkt):
        if not pkt.haslayer(Ether):
            return
        src_mac = pkt[Ether].src.lower()

        # Si el dispositivo no estaba en el ARP scan, lo damos de alta igual
        if src_mac not in devices:
            devices[src_mac] = {
                "ip": pkt[IP].src if pkt.haslayer(IP) else None,
                "mac": src_mac,
                "vendor": vendor_from_mac(src_mac),
                "hostname": None,
                "protocols": set(),
                "ports_dst": set(),
                "packet_count": 0,
            }

        entry = devices[src_mac]
        entry["packet_count"] += 1

        if pkt.haslayer(IP):
            entry["ip"] = entry["ip"] or pkt[IP].src

        # Protocolo de capa de transporte / aplicación
        if pkt.haslayer(TCP):
            entry["protocols"].add("TCP")
            entry["ports_dst"].add(pkt[TCP].dport)
        if pkt.haslayer(UDP):
            entry["protocols"].add("UDP")
            entry["ports_dst"].add(pkt[UDP].dport)
        if pkt.haslayer(DNS):
            entry["protocols"].add("DNS/mDNS")
        if pkt.haslayer(DHCP):
            entry["protocols"].add("DHCP")
            # Opción 12 del DHCP suele traer el hostname que anuncia el dispositivo
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "hostname":
                    entry["hostname"] = opt[1].decode(errors="ignore") if isinstance(opt[1], bytes) else opt[1]

        # Puertos típicos -> pista rápida de qué es el dispositivo
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
        hints = {
            80: "HTTP", 443: "HTTPS", 554: "RTSP (cámara IP)", 1883: "MQTT",
            5683: "CoAP", 8883: "MQTT-TLS", 53: "DNS", 67: "DHCP", 68: "DHCP",
            5353: "mDNS", 1900: "SSDP/UPnP", 8009: "Chromecast", 62078: "iTunes/iOS",
        }
        if dport in hints:
            entry["protocols"].add(hints[dport])

    return handle_packet


# ----------------------------------------------------------------------
# Salida
# ----------------------------------------------------------------------

def print_report(devices):
    print("\n" + "=" * 78)
    print(f"{'IP':<16}{'MAC':<19}{'Fabricante':<22}{'Pkts':<7}{'Protocolos / pistas'}")
    print("=" * 78)
    for d in sorted(devices.values(), key=lambda x: x.get("ip") or ""):
        proto = ", ".join(sorted(d["protocols"])) or "-"
        print(f"{str(d['ip']):<16}{d['mac']:<19}{d['vendor'][:20]:<22}{d['packet_count']:<7}{proto}")
    print("=" * 78 + f"\nTotal dispositivos: {len(devices)}\n")


def export_json(devices, path):
    serializable = []
    for d in devices.values():
        item = dict(d)
        item["protocols"] = sorted(item["protocols"])
        item["ports_dst"] = sorted(item["ports_dst"])
        serializable.append(item)
    with open(path, "w") as f:
        json.dump(serializable, f, indent=2, ensure_ascii=False)
    print(f"[*] Resultados guardados en {path}")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Descubrimiento + fingerprinting pasivo de dispositivos IoT en red local")
    parser.add_argument("-i", "--iface", help="Interfaz de red (ej. eth0, wlan0)")
    parser.add_argument("-n", "--network", help="Red en CIDR, ej. 192.168.1.0/24 (si no se indica, se autodetecta)")
    parser.add_argument("-t", "--time", type=int, default=30, help="Segundos de escucha pasiva (default 30)")
    parser.add_argument("--sniff-only", action="store_true", help="Omite el ARP scan y solo escucha tráfico pasivamente")
    parser.add_argument("-o", "--output", help="Ruta de fichero JSON de salida")
    args = parser.parse_args()

    iface = args.iface
    network = args.network
    if not network or not iface:
        auto_iface, auto_net = guess_network(iface)
        iface = iface or auto_iface
        network = network or auto_net

    devices = {}
    if not args.sniff_only:
        devices = arp_scan(network, iface)

    print(f"[*] Escuchando tráfico en {iface} durante {args.time}s para identificar qué sueltan los dispositivos...")
    handler = build_sniffer(devices, None)
    sniff(iface=iface, prn=handler, timeout=args.time, store=False)

    print_report(devices)
    if args.output:
        export_json(devices, args.output)


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("[!] Necesitas permisos de administrador/root para capturar paquetes (usa sudo).")
    except KeyboardInterrupt:
        print("\n[*] Interrumpido por el usuario.")
