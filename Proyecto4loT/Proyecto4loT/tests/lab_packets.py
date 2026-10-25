"""
Tráfico sintético de un "laboratorio" IoT: cámara, Chromecast, enchufe Tuya,
sensor MQTT, bombilla Matter (IPv6) y un dispositivo con hostname malicioso.
Se usa en los tests y para generar una captura de ejemplo:

    python tests/lab_packets.py ejemplo_lab.pcap
"""

import struct
import sys

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


def client_hello(sni):
    """TLS 1.2/1.3 ClientHello mínimo con una extensión antes del SNI."""
    name = sni.encode() if isinstance(sni, str) else sni
    sni_ext = struct.pack("!HHHBH", 0x0000, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0x000b, 2) + b"\x01\x00" + sni_ext   # ec_point_formats + SNI
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" +
            struct.pack("!H", len(exts)) + exts)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


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
    pkts.append(Ether(src=PLUG, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
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
    pkts.append(Ether(src=EVIL, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255") /
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


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ejemplo_lab.pcap"
    wrpcap(out, lab_packets())
    print(f"Captura de ejemplo escrita en {out}")
