"""
Tráfico sintético de un "laboratorio" IoT: cámara, Chromecast, enchufe Tuya,
sensor MQTT, bombilla Matter (IPv6) y un dispositivo con hostname malicioso.
Se usa en los tests y para generar una captura de ejemplo:

    python -m tests.lab_packets            (escribe ../ejemplos/ejemplo_lab.pcap)
    python -m tests.lab_packets otra.pcap
"""

import struct
import sys
from pathlib import Path

from scapy.all import (ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, IPv6,
                       NTPHeader, Raw, wrpcap)

CAM = "a4:14:37:00:00:01"       # OUI Hikvision
CAST = "f4:f5:d8:00:00:02"      # OUI Google
PLUG = "d8:1f:12:00:00:03"      # Tuya
SENSOR = "24:0a:c4:00:00:04"    # Espressif
EVIL = "00:11:22:00:00:05"
MATTER = "d8:a0:11:00:00:06"    # OUI WiZ (bombilla Matter sobre WiFi)
GW = "00:00:5e:00:01:01"
NTP_SERVER = "203.0.113.123"    # rango de documentación (RFC 5737)
DHCP_NO_IP = "0.0.0.0"  # nosec B104 - origen de un cliente DHCP aún sin IP, no un bind

# Carpeta ejemplos/ en la raíz del repositorio
DEFAULT_PCAP = Path(__file__).resolve().parents[2] / "ejemplos" / "ejemplo_lab.pcap"


def client_hello(sni):
    """TLS 1.2/1.3 ClientHello mínimo con una extensión antes del SNI."""
    name = sni.encode() if isinstance(sni, str) else sni
    sni_ext = struct.pack("!HHHBH", 0x0000, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0x000b, 2) + b"\x01\x00" + sni_ext   # ec_point_formats + SNI
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" +
            struct.pack("!H", len(exts)) + exts)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def wsd_message(action, types="", scopes=""):
    """Mensaje SOAP de WS-Discovery (Hello, Probe...) como lo envía una cámara ONVIF."""
    body = f"<d:Types>{types}</d:Types>" if types else ""
    body += f"<d:Scopes>{scopes}</d:Scopes>" if scopes else ""
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
            'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
            f"<s:Header><a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/{action}</a:Action>"
            f"</s:Header><s:Body><d:{action}>{body}</d:{action}></s:Body></s:Envelope>").encode()


def lab_packets():
    pkts = []
    # Cámara: anuncia ARP, responde RTSP y Telnet, consulta su nube
    pkts.append(Ether(src=CAM, dst="ff:ff:ff:ff:ff:ff") /
                ARP(op=2, psrc="192.168.1.10", hwsrc=CAM))
    pkts.append(Ether(src=CAM, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.50") /
                TCP(sport=554, dport=51000, flags="SA"))
    pkts.append(Ether(src=CAM, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.50") /
                TCP(sport=23, dport=51001, flags="SA"))
    pkts.append(Ether(src=CAM, dst=GW) / IP(src="192.168.1.10", dst="192.168.1.1") /
                UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname="dev.hik-connect.com")))
    # ... se anuncia por WS-Discovery (ONVIF Hello multicast): tipo, modelo y nombre
    pkts.append(Ether(src=CAM, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.10", dst="239.255.255.250") /
                UDP(sport=3702, dport=3702) /
                Raw(wsd_message("Hello", types="dn:NetworkVideoTransmitter tds:Device",
                                scopes="onvif://www.onvif.org/type/video_encoder "
                                       "onvif://www.onvif.org/hardware/DS-2CD2043G2-I "
                                       "onvif://www.onvif.org/name/HIKVISION%20Entrada")))
    # ... pide la hora (NTP cliente, puerto origen 123 como ntpd) y abre TLS con su nube
    pkts.append(Ether(src=CAM, dst=GW) / IP(src="192.168.1.10", dst=NTP_SERVER) /
                UDP(sport=123, dport=123) / NTPHeader(mode=3, version=3))
    pkts.append(Ether(src=CAM, dst=GW) / IP(src="192.168.1.10", dst="198.51.100.20") /
                TCP(sport=51500, dport=443, flags="PA") / Raw(client_hello("api.hik-connect.com")))

    # Chromecast: mDNS con servicio y hostname, sirve 8009
    pkts.append(Ether(src=CAST, dst="01:00:5e:00:00:fb") / IP(src="192.168.1.20", dst="224.0.0.251") /
                UDP(sport=5353, dport=5353) /
                DNS(qr=1, aa=1, an=[DNSRR(rrname="Chromecast-Salon.local.", type="A", rdata="192.168.1.20"),
                                    DNSRR(rrname="_googlecast._tcp.local.", type="PTR",
                                          rdata="Chromecast-Salon._googlecast._tcp.local.")]))
    pkts.append(Ether(src=CAST, dst=GW) / IP(src="192.168.1.20", dst="192.168.1.50") /
                TCP(sport=8009, dport=52000, flags="SA"))

    # Enchufe Tuya: DHCP con hostname (opción 12), consulta nube tuya, sirve 6668
    pkts.append(Ether(src=PLUG, dst="ff:ff:ff:ff:ff:ff") / IP(src=DHCP_NO_IP, dst="255.255.255.255") /
                UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(PLUG.replace(":", ""))) /
                DHCP(options=[("message-type", "request"), ("hostname", b"wlan0-tuya-plug"), "end"]))
    pkts.append(Ether(src=PLUG, dst=GW) / IP(src="192.168.1.30", dst="192.168.1.1") /
                UDP(sport=40000, dport=53) / DNS(rd=1, qd=DNSQR(qname="a3.tuyaeu.com")))
    pkts.append(Ether(src=PLUG, dst=GW) / IP(src="192.168.1.30", dst="192.168.1.50") /
                TCP(sport=6668, dport=53000, flags="SA"))

    # Sensor ESP32: publica en MQTT sin TLS
    pkts.append(Ether(src=SENSOR, dst=GW) / IP(src="192.168.1.40", dst="192.168.1.5") /
                TCP(sport=50123, dport=1883, flags="S"))

    # Dispositivo con hostname y banner SSDP manipulados (inyección)
    pkts.append(Ether(src=EVIL, dst="ff:ff:ff:ff:ff:ff") / IP(src=DHCP_NO_IP, dst="255.255.255.255") /
                UDP(sport=68, dport=67) / BOOTP() /
                DHCP(options=[("hostname", b"=cmd|'/c calc'!A1\x1b[31m;rm -rf /"), "end"]))
    pkts.append(Ether(src=EVIL, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.66", dst="239.255.255.250") /
                UDP(sport=1900, dport=1900) /
                Raw(b"NOTIFY * HTTP/1.1\r\nSERVER: Linux/3.x UPnP/1.0 <script>x</script>\r\n\r\n"))
    pkts.append(Ether(src=EVIL, dst=GW) / IP(src="192.168.1.66", dst="198.51.100.66") /
                TCP(sport=51666, dport=443, flags="PA") /
                Raw(client_hello(b"evil<script>.example\x1b[31m;rm")))

    # Bombilla Matter: se anuncia por mDNS sobre IPv6 (_matter._tcp) y sirve UDP 5540
    pkts.append(Ether(src=MATTER, dst="33:33:00:00:00:fb") / IPv6(src="fe80::daa0:11ff:fe00:6", dst="ff02::fb") /
                UDP(sport=5353, dport=5353) /
                DNS(qr=1, aa=1, an=[DNSRR(rrname="_matter._tcp.local.", type="PTR",
                                          rdata="0123456789ABCDEF-0000000000000006._matter._tcp.local."),
                                    DNSRR(rrname="D8A011000006.local.", type="AAAA",
                                          rdata="fe80::daa0:11ff:fe00:6")]))
    pkts.append(Ether(src=MATTER, dst=GW) / IPv6(src="fe80::daa0:11ff:fe00:6", dst="fe80::1") /
                UDP(sport=5540, dport=5540))
    return pkts


# Un dispositivo por cada regla que el laboratorio principal no ejercita, para que el
# tráfico sintético cubra todas las reglas de rules.json (propuesta de Qwen: cobertura).
# Va aparte para no cambiar los recuentos de los tests del laboratorio principal.
SPEAKER = "00:0e:58:00:00:11"   # OUI Sonos
COAP = "dc:a6:32:00:00:12"      # OUI Raspberry Pi (sensor CoAP)
THREAD_BR = "b8:27:eb:00:00:13"  # OUI Raspberry Pi (border router OpenThread)
PRINTER = "00:80:77:00:00:14"   # OUI Brother
NAS = "00:11:32:00:00:15"       # OUI Synology
APPLE = "f0:18:98:00:00:16"     # OUI Apple
WINDOWS = "00:15:5d:00:00:17"   # OUI Microsoft
ANDROID = "2c:d0:66:00:00:18"   # OUI Xiaomi

EXTRA_EXPECTED = {
    SPEAKER: "Altavoz / asistente inteligente",
    COAP: "Dispositivo CoAP (IoT restringido)",
    THREAD_BR: "Border router Thread / controlador Matter",
    PRINTER: "Impresora",
    NAS: "NAS / servidor de ficheros",
    APPLE: "Dispositivo Apple",
    WINDOWS: "Equipo Windows",
    ANDROID: "Móvil Android",
}


def _mdns(mac, src, records, v6=False):
    l3 = (IPv6(src=src, dst="ff02::fb") if v6 else IP(src=src, dst="224.0.0.251"))
    dst = "33:33:00:00:00:fb" if v6 else "01:00:5e:00:00:fb"
    return Ether(src=mac, dst=dst) / l3 / UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1, an=records)


def _dhcp(mac, options):
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=DHCP_NO_IP, dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(mac.replace(":", ""))) /
            DHCP(options=[("message-type", "request"), *options, "end"]))


def _dns_query(mac, src, name):
    return (Ether(src=mac, dst=GW) / IP(src=src, dst="192.168.1.1") /
            UDP(sport=41000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name)))


def extra_rule_packets():
    pkts = []
    # Altavoz Sonos: sirve 1400 y se anuncia como _sonos._tcp
    pkts.append(Ether(src=SPEAKER, dst=GW) / IP(src="192.168.1.111", dst="192.168.1.50") /
                TCP(sport=1400, dport=52111, flags="SA"))
    pkts.append(_mdns(SPEAKER, "192.168.1.111", [
        DNSRR(rrname="_sonos._tcp.local.", type="PTR", rdata="Salon._sonos._tcp.local.")]))
    # Sensor CoAP: responde desde el 5683 (UDP)
    pkts.append(Ether(src=COAP, dst=GW) / IP(src="192.168.1.112", dst="192.168.1.5") /
                UDP(sport=5683, dport=5683) / Raw(bytes([0x60, 0x45, 0x00, 0x01])))  # cabecera CoAP
    # Border router Thread: mDNS sobre IPv6 con _meshcop._udp
    pkts.append(_mdns(THREAD_BR, "fe80::ba27:ebff:fe00:13", [
        DNSRR(rrname="_meshcop._udp.local.", type="PTR", rdata="OpenThread BR._meshcop._udp.local."),
        DNSRR(rrname="openthread-br.local.", type="AAAA", rdata="fe80::ba27:ebff:fe00:13")], v6=True))
    # Impresora: WS-Discovery Hello (PrintDeviceType) y mDNS _ipp._tcp
    pkts.append(Ether(src=PRINTER, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.114", dst="239.255.255.250") /
                UDP(sport=3702, dport=3702) / Raw(wsd_message("Hello", types="wprt:PrintDeviceType")))
    pkts.append(_mdns(PRINTER, "192.168.1.114", [
        DNSRR(rrname="_ipp._tcp.local.", type="PTR", rdata="Brother HL._ipp._tcp.local.")]))
    # NAS Synology: hostname DiskStation, sirve 5000 y anuncia _smb._tcp
    pkts.append(_dhcp(NAS, [("hostname", b"DiskStation")]))
    pkts.append(Ether(src=NAS, dst=GW) / IP(src="192.168.1.115", dst="192.168.1.50") /
                TCP(sport=5000, dport=52115, flags="SA"))
    pkts.append(_mdns(NAS, "192.168.1.115", [
        DNSRR(rrname="_smb._tcp.local.", type="PTR", rdata="DiskStation._smb._tcp.local.")]))
    # Dispositivo Apple: _companion-link._tcp y consulta a iCloud
    pkts.append(_mdns(APPLE, "192.168.1.116", [
        DNSRR(rrname="_companion-link._tcp.local.", type="PTR", rdata="iPad._companion-link._tcp.local.")]))
    pkts.append(_dns_query(APPLE, "192.168.1.116", "gateway.icloud.com"))
    # Equipo Windows: DHCP "MSFT 5.0", hostname DESKTOP-... y WS-Discovery pub:Computer
    pkts.append(_dhcp(WINDOWS, [("hostname", b"DESKTOP-4F2K9QX"), ("vendor_class_id", b"MSFT 5.0")]))
    pkts.append(Ether(src=WINDOWS, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.117", dst="239.255.255.250") /
                UDP(sport=3702, dport=3702) / Raw(wsd_message("Hello", types="pub:Computer")))
    # Móvil Android: DHCP "android-dhcp-14" y comprobación de conectividad de Google
    pkts.append(_dhcp(ANDROID, [("hostname", b"Redmi-Note-12"), ("vendor_class_id", b"android-dhcp-14")]))
    pkts.append(_dns_query(ANDROID, "192.168.1.118", "connectivitycheck.gstatic.com"))
    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_PCAP)
    wrpcap(out, lab_packets())
    print(f"Captura de ejemplo escrita en {out}")
