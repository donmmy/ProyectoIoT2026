"""
Hito 2 — Sniffing pasivo y extracción de metadatos.

- Captura continua en la interfaz (o lectura de un .pcap), agregando por MAC origen.
- Extracción de protocolos (TCP/UDP/DNS/DHCP/mDNS/SSDP) y puertos por dispositivo.
- Hostname anunciado por DHCP (opción 12) o mDNS.

Todo lo que llega de la red es texto controlado por terceros: se sanea antes de
guardarlo (ver sanitize_text) para que no rompa la consola ni los exportes.
"""

import re

from scapy.all import ARP, DHCP, DNS, IP, TCP, UDP, Ether, Raw, rdpcap, sniff

from .device import Device
from .discovery import vendor_from_mac

PORT_MDNS = 5353
PORT_SSDP = 1900
PORT_DHCP = (67, 68)
EPHEMERAL_START = 49152
UDP_SERVER_PORTS = {PORT_SSDP, 5683, 5684}  # servicios UDP altos que delatan a un servidor

_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._\-:/()+@,=]")


def sanitize_text(value, max_len=64):
    """Deja solo caracteres imprimibles seguros y recorta la longitud."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    value = _SAFE_CHARS.sub("", str(value)).strip()
    return value[:max_len] or None


def _is_unicast(mac):
    return not (int(mac.split(":")[0], 16) & 0x01)


# ----------------------------------------------------------------------
# Extractores por protocolo
# ----------------------------------------------------------------------

def _dns_records(section):
    """Devuelve los RR de una sección DNS (lista en Scapy >= 2.5, encadenados antes)."""
    if section is None:
        return []
    out = []
    for first in (section if isinstance(section, list) else [section]):
        rr = first
        while rr is not None and rr.__class__.__name__ != "NoPayload":
            out.append(rr)
            rr = rr.payload
    return out


def _parse_dhcp(pkt, dev):
    dev.protocols.add("DHCP")
    for opt in pkt[DHCP].options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        if opt[0] == "hostname":
            dev.hostname = sanitize_text(opt[1]) or dev.hostname
        elif opt[0] == "vendor_class_id":
            dev.add("banners", "DHCP:" + (sanitize_text(opt[1]) or ""))


def _parse_mdns(pkt, dev):
    dev.protocols.add("mDNS")
    dns = pkt[DNS]
    records = _dns_records(dns.an) + _dns_records(dns.ar) + _dns_records(dns.qd)
    for rr in records:
        name = getattr(rr, "rrname", None) or getattr(rr, "qname", None)
        name = sanitize_text(name, 128)
        if not name:
            continue
        name = name.rstrip(".")
        # Servicios anunciados: _googlecast._tcp.local, _hap._tcp.local...
        m = re.search(r"(_[\w\-]+\._(?:tcp|udp))\.local$", name)
        if m:
            dev.add("mdns_services", m.group(1))
        # Respuesta A/AAAA (type 1 / 28) "mi-camara.local" -> hostname
        if dns.qr == 1 and getattr(rr, "type", None) in (1, 28) and name.endswith(".local"):
            dev.hostname = dev.hostname or sanitize_text(name[: -len(".local")])


def _parse_dns(pkt, dev):
    dev.protocols.add("DNS")
    dns = pkt[DNS]
    if dns.qr == 0:  # consulta hecha por el dispositivo
        for q in _dns_records(dns.qd):
            name = sanitize_text(getattr(q, "qname", None), 128)
            if name:
                dev.add("dns_queries", name.rstrip(".").lower())


def _parse_ssdp(pkt, dev):
    dev.protocols.add("SSDP")
    if not pkt.haslayer(Raw):
        return
    text = pkt[Raw].load.decode("utf-8", errors="ignore")
    for line in text.split("\r\n"):
        key, _, val = line.partition(":")
        if key.strip().upper() in ("SERVER", "USER-AGENT"):
            dev.add("banners", "SSDP:" + (sanitize_text(val, 96) or ""))


# ----------------------------------------------------------------------
# Callback principal
# ----------------------------------------------------------------------

class PassiveSniffer:
    """Agrega los paquetes capturados en un diccionario {mac: Device}."""

    def __init__(self, devices=None, ignore_macs=()):
        self.devices = devices if devices is not None else {}
        self.ignore = {m.lower() for m in ignore_macs if m}
        self.total_packets = 0

    def _get_device(self, mac, ip=None):
        dev = self.devices.get(mac)
        if dev is None:
            dev = Device(mac=mac, ip=ip, vendor=vendor_from_mac(mac), source="pasivo")
            self.devices[mac] = dev
        return dev

    def handle_packet(self, pkt):
        self.total_packets += 1
        if not pkt.haslayer(Ether):
            return
        src_mac = pkt[Ether].src.lower()
        if src_mac in self.ignore or not _is_unicast(src_mac):
            return

        dev = self._get_device(src_mac)
        dev.packet_count += 1

        # ARP: útil en redes con aislamiento, los equipos se anuncian igual
        if pkt.haslayer(ARP):
            dev.protocols.add("ARP")
            psrc = pkt[ARP].psrc
            if psrc and psrc != "0.0.0.0" and not dev.ip:
                dev.ip = psrc

        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            if ip_src != "0.0.0.0" and (not dev.ip or dev.ip == "0.0.0.0"):
                dev.ip = ip_src

        sport = dport = None
        if pkt.haslayer(TCP):
            dev.protocols.add("TCP")
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            # SYN+ACK => el dispositivo está sirviendo ese puerto
            if pkt[TCP].flags & 0x12 == 0x12:
                dev.add("ports_src", sport)
        elif pkt.haslayer(UDP):
            dev.protocols.add("UDP")
            sport, dport = pkt[UDP].sport, pkt[UDP].dport

        if dport is not None:
            if dport < EPHEMERAL_START:
                dev.add("ports_dst", dport)
            # Puerto origen bajo (o conocido) => probablemente servicio propio
            if pkt.haslayer(UDP) and (sport in UDP_SERVER_PORTS or
                                      (sport < 1024 and sport not in PORT_DHCP)):
                dev.add("ports_src", sport)

        if pkt.haslayer(DHCP):
            _parse_dhcp(pkt, dev)
        if pkt.haslayer(DNS):
            if PORT_MDNS in (sport, dport):
                _parse_mdns(pkt, dev)
            else:
                _parse_dns(pkt, dev)
        if PORT_SSDP in (sport, dport) and pkt.haslayer(UDP):
            _parse_ssdp(pkt, dev)


def sniff_live(iface, seconds, devices=None, ignore_macs=()):
    """Captura en vivo durante `seconds` segundos."""
    s = PassiveSniffer(devices, ignore_macs)
    print(f"[*] Escuchando tráfico en {iface} durante {seconds}s...")
    sniff(iface=iface, prn=s.handle_packet, timeout=seconds, store=False)
    print(f"[*] {s.total_packets} paquetes procesados.")
    return s.devices


def sniff_pcap(path, devices=None, ignore_macs=()):
    """Procesa un fichero .pcap (útil para pruebas reproducibles y comparar con Wireshark)."""
    s = PassiveSniffer(devices, ignore_macs)
    print(f"[*] Leyendo captura {path}...")
    for pkt in rdpcap(path):
        s.handle_packet(pkt)
    print(f"[*] {s.total_packets} paquetes procesados.")
    return s.devices
