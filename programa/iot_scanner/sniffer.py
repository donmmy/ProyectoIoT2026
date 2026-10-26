"""
Hito 2 — Sniffing pasivo y extracción de metadatos.

- Captura continua en la interfaz (o lectura de un .pcap), agregando por MAC origen.
- Extracción de protocolos (TCP/UDP/DNS/DHCP/mDNS/SSDP) y puertos por dispositivo.
- Hostname anunciado por DHCP (opción 12) o mDNS.
- Ampliación: NTP (servidores de hora consultados), TLS (SNI del ClientHello) e
  IPv6 (direcciones; Matter/Thread se anuncian por mDNS sobre IPv6).
- WS-Discovery / ONVIF (UDP 3702, multicast): tipo de dispositivo y modelo que
  anuncian las cámaras IP, impresoras y equipos Windows.

Todo lo que llega de la red es texto controlado por terceros: se sanea antes de
guardarlo (ver sanitize_text) para que no rompa la consola ni los exportes.
"""

import re
from urllib.parse import unquote

from scapy.all import ARP, DHCP, DNS, IP, NTP, TCP, UDP, Ether, IPv6, Raw, rdpcap, sniff

from .device import Device
from .discovery import is_unspecified, vendor_from_mac

PORT_MDNS = 5353
PORT_SSDP = 1900
PORT_DHCP = (67, 68)
PORT_NTP = 123
PORT_MATTER = 5540
PORT_WSD = 3702
EPHEMERAL_START = 49152
# Servicios UDP altos que delatan a un servidor: SSDP, CoAP/CoAPs y Matter
UDP_SERVER_PORTS = {PORT_SSDP, 5683, 5684, PORT_MATTER}
# Puertos bajos que también usa el lado cliente: no prueban que el dispositivo sirva nada
# (NTP se decide por el campo mode del paquete, ver _parse_ntp)
UDP_CLIENT_LOW_PORTS = {*PORT_DHCP, PORT_NTP}
NTP_CLIENT_MODE = 3
NTP_SERVER_MODES = (4, 5)  # respuesta de servidor y broadcast
# WS-Discovery: mensajes que solo envía el dispositivo descubierto (el servicio)
WSD_TARGET_ACTIONS = {"Hello", "Bye", "ProbeMatches", "ResolveMatches"}
WSD_MAX_BYTES = 8192
# Regex acotadas (sin .* ni anidamiento) sobre XML no confiable: no se usa un parser
# XML para no exponerse a entidades externas o expansión de entidades
_WSD_ACTION = re.compile(r"<(?:[\w-]+:)?Action[^>]{0,256}>([^<]{1,256})<")
_WSD_TYPES = re.compile(r"<(?:[\w-]+:)?Types[^>]{0,256}>([^<]{1,1024})<")
_WSD_SCOPES = re.compile(r"<(?:[\w-]+:)?Scopes[^>]{0,256}>([^<]{1,4096})<")
ONVIF_SCOPE_KEYS = ("name", "hardware", "mfr")

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


def _parse_ntp(pkt, dev, ip_dst):
    """mode 3 = el dispositivo pide la hora (cliente); 4/5 = la sirve."""
    dev.protocols.add("NTP")
    mode = getattr(pkt[NTP], "mode", None)
    if mode == NTP_CLIENT_MODE and ip_dst:
        dev.add("ntp_servers", ip_dst)
    elif mode in NTP_SERVER_MODES:
        dev.add("ports_src", PORT_NTP)


def _parse_wsd(pkt, dev):
    """
    WS-Discovery: SOAP/XML por UDP 3702 a 239.255.255.250 o ff02::c.

    Hello/Bye/ProbeMatches los envía el dispositivo descubierto: sus Types dicen qué
    es (dn:NetworkVideoTransmitter = cámara ONVIF) y sus Scopes, modelo y nombre.
    Probe/Resolve los envía quien busca (un NVR, una app, Windows).
    """
    dev.protocols.add("WS-Discovery")
    text = bytes(pkt[Raw].load[:WSD_MAX_BYTES]).decode("utf-8", errors="ignore")
    m = _WSD_ACTION.search(text)
    action = m.group(1).strip().rsplit("/", 1)[-1] if m else ""
    if action not in WSD_TARGET_ACTIONS:
        return
    dev.add("ports_src", PORT_WSD)
    m = _WSD_TYPES.search(text)
    for qname in (m.group(1).split() if m else []):
        dev.add("wsd_types", sanitize_text(qname.rsplit(":", 1)[-1]))
    m = _WSD_SCOPES.search(text)
    for scope in (m.group(1).split() if m else []):
        parts = scope.split("onvif://www.onvif.org/", 1)
        key, _, value = parts[-1].partition("/") if len(parts) == 2 else ("", "", "")
        if key in ONVIF_SCOPE_KEYS and value:
            dev.add("banners", f"ONVIF:{key}=" + (sanitize_text(unquote(value), 96) or ""))


def _u16(data, pos):
    return int.from_bytes(data[pos:pos + 2], "big")


def tls_sni(data):
    """
    Devuelve el SNI (nombre del servidor) de un TLS ClientHello, o None.

    El ClientHello viaja en claro aunque la conexión vaya cifrada. Solo se mira el
    primer segmento TCP: si el ClientHello es más largo y el SNI cae en otro
    segmento, no se encuentra.
    """
    try:
        # Registro TLS: tipo 0x16 (handshake), versión 0x03xx; mensaje 0x01 (ClientHello)
        if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32                 # cabecera registro + handshake, versión, random
        pos += 1 + data[pos]                 # session id
        pos += 2 + _u16(data, pos)           # cipher suites
        pos += 1 + data[pos]                 # métodos de compresión
        end = min(pos + 2 + _u16(data, pos), len(data))
        pos += 2
        while pos + 4 <= end:
            ext_type, ext_len = _u16(data, pos), _u16(data, pos + 2)
            pos += 4
            if ext_type == 0x0000:           # server_name: lista(2) tipo(1) longitud(2) nombre
                if data[pos + 2] != 0:       # 0 = host_name
                    return None
                n = _u16(data, pos + 3)
                name = data[pos + 5:pos + 5 + n]
                return name.decode("ascii", errors="ignore") if len(name) == n else None
            pos += ext_len
    except IndexError:
        pass
    return None


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
            if psrc and not is_unspecified(psrc) and not dev.ip:
                dev.ip = psrc

        ip_dst = None
        if pkt.haslayer(IP):
            ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
            if not is_unspecified(ip_src) and (not dev.ip or is_unspecified(dev.ip)):
                dev.ip = ip_src
        elif pkt.haslayer(IPv6):
            dev.protocols.add("IPv6")
            ip_dst = pkt[IPv6].dst
            if not is_unspecified(pkt[IPv6].src):
                dev.add("ipv6", pkt[IPv6].src)

        sport = dport = None
        if pkt.haslayer(TCP):
            dev.protocols.add("TCP")
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            # SYN+ACK => el dispositivo está sirviendo ese puerto
            if pkt[TCP].flags & 0x12 == 0x12:
                dev.add("ports_src", sport)
            if pkt.haslayer(Raw):
                sni = sanitize_text(tls_sni(bytes(pkt[Raw].load)), 128)
                if sni:
                    dev.protocols.add("TLS")
                    dev.add("tls_sni", sni.rstrip(".").lower())
        elif pkt.haslayer(UDP):
            dev.protocols.add("UDP")
            sport, dport = pkt[UDP].sport, pkt[UDP].dport

        if dport is not None:
            if dport < EPHEMERAL_START:
                dev.add("ports_dst", dport)
            # Puerto origen bajo (o conocido) => probablemente servicio propio
            if pkt.haslayer(UDP) and (sport in UDP_SERVER_PORTS or
                                      (sport < 1024 and sport not in UDP_CLIENT_LOW_PORTS)):
                dev.add("ports_src", sport)

        if PORT_NTP in (sport, dport) and pkt.haslayer(NTP):
            _parse_ntp(pkt, dev, ip_dst)
        if pkt.haslayer(DHCP):
            _parse_dhcp(pkt, dev)
        if pkt.haslayer(DNS):
            if PORT_MDNS in (sport, dport):
                _parse_mdns(pkt, dev)
            else:
                _parse_dns(pkt, dev)
        if PORT_SSDP in (sport, dport) and pkt.haslayer(UDP):
            _parse_ssdp(pkt, dev)
        if PORT_WSD in (sport, dport) and pkt.haslayer(UDP) and pkt.haslayer(Raw):
            _parse_wsd(pkt, dev)


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
