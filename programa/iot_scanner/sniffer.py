"""
Hito 2 — Sniffing pasivo y extracción de metadatos.

- Captura continua en la interfaz (o lectura de un .pcap), agregando por MAC origen.
- Extracción de protocolos (TCP/UDP/DNS/DHCP/mDNS/SSDP) y puertos por dispositivo.
- Hostname anunciado por DHCP (opción 12) o mDNS.
- Ampliación: NTP (servidores de hora consultados), TLS (SNI del ClientHello) e
  IPv6 (direcciones; Matter/Thread se anuncian por mDNS sobre IPv6).
- WS-Discovery / ONVIF (UDP 3702, multicast): tipo de dispositivo y modelo que
  anuncian las cámaras IP, impresoras y equipos Windows.
- Registros TXT de mDNS: pares clave=valor con los que muchos dispositivos anuncian
  modelo y versión de firmware (Shelly, ESPHome, Chromecast, impresoras, HomeKit).

Todo lo que llega de la red es texto controlado por terceros: se sanea antes de
guardarlo (ver sanitize_text) para que no rompa la consola ni los exportes.
"""

import hashlib
import ipaddress
import logging
import re
import time
from urllib.parse import unquote

from scapy.all import ARP, DHCP, DNS, IP, NTP, TCP, UDP, AsyncSniffer, Ether, IPv6, PcapWriter, Raw, rdpcap
from scapy.layers.dhcp6 import DHCP6, DHCP6OptClientFQDN, DHCP6OptVendorClass

from .device import Device
from .discovery import is_unspecified, vendor_from_mac

log = logging.getLogger(__name__)

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

# Registros TXT de mDNS (DNS-SD, RFC 6763): claves que, según el fabricante, dicen el
# modelo o la versión del firmware. Solo se interpretan estas; el resto se guarda tal cual.
# Ojo a las que parecen versión y no lo son: "txtvers" es la versión del formato del TXT
# y "ve" en Chromecast la del protocolo, no la del firmware.
TXT_TYPE = 16
TXT_MODEL_KEYS = ("md", "model", "ty", "product", "usb_mdl", "app")
TXT_FIRMWARE_KEYS = ("fw_version", "fw_ver", "fw_id", "firmware", "version", "ver", "osvers", "srcvers")
TXT_MAX_PAIRS = 32   # pares por registro que se leen (un TXT puede traer muchos)

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


# Opción 55 (Parameter Request List, RFC 2132): qué opciones pide el cliente y en qué
# orden. Depende del cliente DHCP del sistema (Android, Windows, udhcp, lwIP de un ESP32...),
# así que es una huella pasiva del SO/firmware. Se guarda como "1,3,6,15" (formato habitual
# de las bases de huellas, p. ej. Fingerbank).
DHCP_FP_MAX = 64


def dhcp_fingerprint(value):
    if isinstance(value, (bytes, bytearray)):
        value = list(value)
    if not isinstance(value, (list, tuple)):
        value = [value]
    codes = [v for v in value[:DHCP_FP_MAX] if isinstance(v, int) and 0 <= v <= 255]
    return ",".join(map(str, codes)) or None


def _parse_dhcp(pkt, dev):
    dev.protocols.add("DHCP")
    for opt in pkt[DHCP].options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        if opt[0] == "param_req_list":
            dev.add("dhcp_fingerprint", dhcp_fingerprint(opt[1] if len(opt) == 2 else list(opt[1:])))
        elif opt[0] == "hostname":
            dev.hostname = sanitize_text(opt[1]) or dev.hostname
        elif opt[0] == "vendor_class_id":
            vendor_class = sanitize_text(opt[1]) or ""
            dev.add("banners", "DHCP:" + vendor_class)
            m = _DHCP_CLIENT.match(vendor_class)
            if m:   # versión del cliente DHCP (librería), no del firmware
                dev.add("software", f"{m.group(1).lower()}/{m.group(2)}")


# DHCPv6 (RFC 8415): el cliente habla desde el puerto 546. Como en DHCPv4, puede decir su
# nombre (opción 39, Client FQDN, RFC 4704) y su "vendor class" (opción 16, con el número
# de empresa de IANA delante). Los dispositivos solo IPv6 (Matter/Thread) no usan DHCPv4.
PORT_DHCP6_CLIENT = 546


def _parse_dhcp6(pkt, dev):
    # haslayer() no reconoce subclases: los mensajes (Solicit, Request...) heredan de DHCP6
    if not any(issubclass(layer, DHCP6) for layer in pkt.layers()):
        return
    dev.protocols.add("DHCPv6")
    if pkt.haslayer(DHCP6OptClientFQDN):
        fqdn = sanitize_text(getattr(pkt[DHCP6OptClientFQDN], "fqdn", None), 128)
        host = (fqdn or "").rstrip(".").split(".")[0]
        if host and not dev.hostname:          # el de DHCPv4 o mDNS, si ya hay, se queda
            dev.hostname = host
    if pkt.haslayer(DHCP6OptVendorClass):
        opt = pkt[DHCP6OptVendorClass]
        for item in (getattr(opt, "vcdata", None) or [])[:8]:
            text = sanitize_text(getattr(item, "data", None))
            if text:
                dev.add("banners", f"DHCPv6:{text}")


# EUI-64 (RFC 4291, apéndice A): el identificador de interfaz (últimos 64 bits) se forma con
# la MAC partida en dos, ff:fe en medio y el bit U/L invertido. En una dirección link-local
# (fe80::) es lo normal y no filtra nada: no sale de la red local, donde la MAC ya se ve. En
# una dirección GLOBAL (2000::/3) sí: viaja a internet y permite seguir al dispositivo de una
# red a otra. Las direcciones temporales (RFC 4941) y estables opacas (RFC 7217) lo evitan.
GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")


def eui64_mac(addr):
    """MAC incrustada en una IPv6 con EUI-64, o None."""
    try:
        iid = ipaddress.IPv6Address(addr).packed[8:]
    except ValueError:
        return None
    if iid[3:5] != b"\xff\xfe":
        return None
    mac = bytes([iid[0] ^ 0x02]) + iid[1:3] + iid[5:8]
    return ":".join(f"{b:02x}" for b in mac)


def leaks_mac(addr, mac):
    """True si es una IPv6 global que lleva dentro la MAC real del dispositivo."""
    try:
        is_global = ipaddress.IPv6Address(addr) in GLOBAL_UNICAST
    except ValueError:
        return False
    return is_global and eui64_mac(addr) == (mac or "").lower()


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
        # Respuesta TXT (type 16): lo que el dispositivo cuenta de sí mismo
        if dns.qr == 1 and getattr(rr, "type", None) == TXT_TYPE:
            _parse_txt(rr, dev)


def _txt_pairs(rdata):
    """Normaliza el rdata de un TXT (lista de bytes en Scapy >= 2.5) a [(clave, valor)]."""
    items = rdata if isinstance(rdata, list) else [rdata]
    pairs = []
    for item in items[:TXT_MAX_PAIRS]:
        text = item.decode("utf-8", errors="ignore") if isinstance(item, bytes) else str(item)
        key, sep, value = text.partition("=")
        key = sanitize_text(key, 32)
        if key:   # las claves de DNS-SD no distinguen mayúsculas (RFC 6763, 6.4)
            pairs.append((key.lower(), sanitize_text(value, 96) if sep else None))
    return pairs


def _parse_txt(rr, dev):
    for key, value in _txt_pairs(getattr(rr, "rdata", None)):
        dev.add("mdns_txt", f"{key}={value}" if value is not None else key)
        if not value:
            continue
        if key in TXT_MODEL_KEYS:
            dev.add("models", value.strip("() "))
        elif key in TXT_FIRMWARE_KEYS:
            dev.add("firmware", value)


def _parse_dns(pkt, dev):
    dev.protocols.add("DNS")
    dns = pkt[DNS]
    if dns.qr == 0:  # consulta hecha por el dispositivo
        for q in _dns_records(dns.qd):
            name = sanitize_text(getattr(q, "qname", None), 128)
            if name:
                dev.add("dns_queries", name.rstrip(".").lower())


# Tipo UPnP en NT (NOTIFY) o ST (respuesta): urn:schemas-upnp-org:device:InternetGatewayDevice:1
_UPNP_URN = re.compile(r"urn:[\w.-]{1,64}:(?:device|service):([A-Za-z0-9_-]{1,64}):\d{1,3}")

# Banner SERVER de SSDP (UPnP 1.0, apartado 1.1.2): "SO/versión UPnP/1.0 producto/versión".
# Cada pieza "nombre/versión" se clasifica: el SO (versión del núcleo, no del firmware),
# el propio protocolo UPnP, una librería conocida (versión de la librería) o el producto
# (esa sí es la versión del firmware del fabricante).
_NAME_VERSION = re.compile(r"([A-Za-z][\w .+-]{0,40}?)/(\d[\w.+-]{0,24})")
OS_NAMES = {"linux", "windows", "microsoft-windows", "android", "darwin", "freertos", "unix", "ecos",
            "vxworks", "threadx", "zephyr", "os", "posix"}
PROTOCOL_NAMES = {"upnp", "dlnadoc", "http", "dlna"}
# Librerías: su versión no es la del firmware, pero tienen CVE propios (vulns.SOFTWARE_CPE)
LIBRARY_NAMES = {"miniupnpd", "libupnp", "portable sdk for upnp devices", "intel sdk for upnp devices",
                 "upnp-device-host", "rompager", "allegro-software-rompager", "goahead", "boa",
                 "lighttpd", "busybox", "udhcp", "dhcpcd", "platinum", "cling"}
# Vendor class de DHCP con la versión del cliente DHCP: "udhcp 1.24.1" (BusyBox), "dhcpcd-9.4.1:..."
_DHCP_CLIENT = re.compile(r"^(udhcp|dhcpcd)[ -](\d[\w.]{0,24})", re.IGNORECASE)


def parse_server_banner(banner):
    """[(tipo, nombre, versión)] con tipo "so", "protocolo", "libreria" o "producto"."""
    out = []
    for i, (name, version) in enumerate(_NAME_VERSION.findall(banner or "")):
        name = name.strip(" ,")
        low = name.lower()
        if low in PROTOCOL_NAMES:
            kind = "protocolo"
        elif low in LIBRARY_NAMES:
            kind = "libreria"
        elif i == 0 and (low in OS_NAMES or low.split("-")[0] in OS_NAMES):
            kind = "so"
        else:
            kind = "producto"
        out.append((kind, name, version))
    return out


def _add_versions(dev, banner):
    for kind, name, version in parse_server_banner(banner):
        if kind == "libreria":
            dev.add("software", f"{name.lower()}/{version}")
        elif kind == "producto":
            dev.add("firmware", version)


def _parse_ssdp(pkt, dev):
    dev.protocols.add("SSDP")
    if not pkt.haslayer(Raw):
        return
    text = pkt[Raw].load[:4096].decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    first = lines[0].strip().upper()
    # NOTIFY y la respuesta 200 OK los manda el dispositivo que se anuncia; un M-SEARCH
    # es de quien busca: su ST es lo que busca, no lo que es (como Probe en WS-Discovery)
    announces = first.startswith("NOTIFY") or first.startswith("HTTP/")
    for line in lines[1:64]:
        key, _, val = line.partition(":")
        key = key.strip().upper()
        if key in ("SERVER", "USER-AGENT"):
            banner = sanitize_text(val, 96) or ""
            dev.add("banners", "SSDP:" + banner)
            if key == "SERVER" and announces:
                _add_versions(dev, banner)
        elif key in ("NT", "ST") and announces:
            m = _UPNP_URN.search(val)
            if m:
                dev.add("upnp_types", m.group(1))


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


# GREASE (RFC 8701): valores 0x?a?a que los clientes meten al azar para que los servidores
# no se atasquen con valores desconocidos. JA3 los quita porque cambian en cada conexión
TLS_GREASE = {0x0A0A + 0x1010 * i for i in range(16)}


def _u16_list(data, start, length):
    return [_u16(data, start + i) for i in range(0, length - length % 2, 2)]


def parse_client_hello(data):
    """
    Lee un TLS ClientHello: {"sni": nombre o None, "ja3": huella o None}, o None.

    El ClientHello viaja en claro aunque la conexión vaya cifrada. Solo se mira el
    primer segmento TCP: si el ClientHello es más largo, el SNI puede no encontrarse y la
    huella JA3 no se calcula (saldría de una lista de extensiones incompleta).

    JA3 (Salesforce, 2017): "versión,cifrados,extensiones,curvas,formatos de punto" con los
    números en orden de aparición, separados por "-", y su MD5. Depende de la librería TLS
    del cliente (mbedTLS de un ESP32, OpenSSL de un Linux...), no del servidor.
    """
    try:
        # Registro TLS: tipo 0x16 (handshake), versión 0x03xx; mensaje 0x01 (ClientHello)
        if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
            return None
        version = _u16(data, 9)                     # versión del ClientHello
        pos = 5 + 4 + 2 + 32                        # cabecera registro + handshake, versión, random
        pos += 1 + data[pos]                        # session id
        n = _u16(data, pos)
        ciphers = _u16_list(data, pos + 2, n)       # cipher suites
        pos += 2 + n
        pos += 1 + data[pos]                        # métodos de compresión
        ext_total = _u16(data, pos)
        complete = pos + 2 + ext_total <= len(data)
        end = min(pos + 2 + ext_total, len(data))
        pos += 2
        sni, exts, curves, points = None, [], [], []
        while pos + 4 <= end:
            ext_type, ext_len = _u16(data, pos), _u16(data, pos + 2)
            body = data[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            exts.append(ext_type)
            if ext_type == 0x0000 and len(body) >= 5 and body[2] == 0:   # server_name, host_name
                k = _u16(body, 3)
                name = body[5:5 + k]
                if len(name) == k:
                    sni = name.decode("ascii", errors="ignore")
            elif ext_type == 0x000A and len(body) >= 2:                   # supported_groups (curvas)
                curves = _u16_list(body, 2, min(_u16(body, 0), len(body) - 2))
            elif ext_type == 0x000B and body:                             # ec_point_formats
                points = list(body[1:1 + body[0]])
    except IndexError:
        return None
    ja3 = None
    if complete and pos == end:
        def clean(values):
            return "-".join(str(v) for v in values if v not in TLS_GREASE)
        ja3 = ",".join([str(version), clean(ciphers), clean(exts), clean(curves), clean(points)])
    return {"sni": sni, "ja3": ja3}


def ja3_hash(ja3):
    # MD5 porque así se define JA3 (es un identificador, no una protección)
    return hashlib.md5(ja3.encode(), usedforsecurity=False).hexdigest()


def tls_sni(data):
    """Devuelve el SNI (nombre del servidor) de un TLS ClientHello, o None."""
    hello = parse_client_hello(data)
    return hello["sni"] if hello else None


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
            log.debug("Dispositivo nuevo por escucha pasiva: %s (%s)", mac, dev.vendor)
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
                if not dev.eui64_global and leaks_mac(pkt[IPv6].src, src_mac):
                    dev.eui64_global = True

        sport = dport = None
        if pkt.haslayer(TCP):
            dev.protocols.add("TCP")
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            # SYN+ACK => el dispositivo está sirviendo ese puerto
            if pkt[TCP].flags & 0x12 == 0x12:
                dev.add("ports_src", sport)
            if pkt.haslayer(Raw):
                hello = parse_client_hello(bytes(pkt[Raw].load))
                if hello:
                    dev.protocols.add("TLS")
                    sni = sanitize_text(hello["sni"], 128)
                    if sni:
                        dev.add("tls_sni", sni.rstrip(".").lower())
                    if hello["ja3"]:
                        dev.add("ja3", ja3_hash(hello["ja3"]))
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
        if sport == PORT_DHCP6_CLIENT and pkt.haslayer(UDP):
            _parse_dhcp6(pkt, dev)
        if pkt.haslayer(DNS):
            if PORT_MDNS in (sport, dport):
                _parse_mdns(pkt, dev)
            else:
                _parse_dns(pkt, dev)
        if PORT_SSDP in (sport, dport) and pkt.haslayer(UDP):
            _parse_ssdp(pkt, dev)
        if PORT_WSD in (sport, dport) and pkt.haslayer(UDP) and pkt.haslayer(Raw):
            _parse_wsd(pkt, dev)


def _stop_capture(capture):
    """Para el AsyncSniffer si ya está capturando. Devuelve False si aún no ha arrancado:
    Scapy ignora un stop() que llega antes de que el hilo empiece, así que hay que reintentar."""
    if capture.running and hasattr(capture, "continue_sniff"):
        capture.stop(join=False)
        return True
    return False


def sniff_live(iface, seconds, devices=None, ignore_macs=(), stop_event=None, save_path=None):
    """
    Captura en vivo durante `seconds` segundos.

    Se puede cortar antes: activando `stop_event` (botón Detener de la GUI) o con Ctrl+C
    en la consola. En los dos casos se conserva y analiza lo capturado hasta ese momento.

    Con `save_path` se guardan además todos los paquetes en un .pcap (como Wireshark,
    incluidos los del propio equipo, que el análisis descarta): sirve para abrirlo luego en
    Wireshark o repetir el análisis con --pcap. Se escribe paquete a paquete, así que
    Detener o Ctrl+C no pierden lo ya capturado.
    """
    s = PassiveSniffer(devices, ignore_macs)
    log.info("Escuchando tráfico en %s durante %ss...", iface, seconds)
    writer = None
    if save_path:
        writer = PcapWriter(str(save_path), append=False, sync=True)
        log.warning("Guardando la captura en %s: lleva todo el tráfico visible en claro "
                    "(MAC, IP, nombres, dominios). Trátala como un dato sensible.", save_path)

    def handle(pkt):
        if writer is not None:      # primero se guarda, como lo vería Wireshark
            writer.write(pkt)
        s.handle_packet(pkt)
    # AsyncSniffer no admite timeout: el plazo lo controla este bucle
    capture = AsyncSniffer(iface=iface, prn=handle, store=False)
    try:
        capture.start()
        _wait_capture(capture, seconds, stop_event)
    finally:
        if writer is not None:
            writer.close()
    if save_path:
        log.info("Captura guardada en %s (%d paquetes).", save_path, s.total_packets)
    log.info("%d paquetes procesados.", s.total_packets)
    return s.devices


def _wait_capture(capture, seconds, stop_event):
    """Espera al plazo, al stop_event o a Ctrl+C y para la captura."""
    deadline = time.monotonic() + seconds
    stopped = False
    try:
        # Esperas cortas: así el bucle atiende el stop_event y Ctrl+C también en Windows
        while capture.thread.is_alive() and time.monotonic() < deadline:
            if stop_event is not None and stop_event.is_set():
                stopped = True
                break
            capture.thread.join(0.2)
    except KeyboardInterrupt:
        stopped = True
    # Parar la captura, reintentando si el hilo aún no había empezado a capturar
    give_up = time.monotonic() + 5
    while capture.thread.is_alive() and time.monotonic() < give_up:
        _stop_capture(capture)
        capture.thread.join(0.2)
    if capture.exception is not None:   # p. ej. sin permisos de administrador
        raise capture.exception
    if stopped:
        log.info("Captura detenida antes de tiempo; se analiza lo capturado hasta ahora.")


def sniff_pcap(path, devices=None, ignore_macs=()):
    """Procesa un fichero .pcap (útil para pruebas reproducibles y comparar con Wireshark)."""
    s = PassiveSniffer(devices, ignore_macs)
    log.info("Leyendo captura %s...", path)
    for pkt in rdpcap(path):
        s.handle_packet(pkt)
    log.info("%d paquetes procesados.", s.total_packets)
    return s.devices
