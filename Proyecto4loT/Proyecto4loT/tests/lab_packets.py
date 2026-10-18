"""
Tráfico sintético de un "laboratorio" IoT: cámara, Chromecast, enchufe Tuya,
sensor MQTT y un dispositivo con hostname malicioso. Se usa en los tests y
para generar una captura de ejemplo:

    python tests/lab_packets.py ejemplo_lab.pcap
"""

import sys

from scapy.all import (ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw,
                       wrpcap)

CAM = "a4:14:37:00:00:01"       # OUI Hikvision
CAST = "f4:f5:d8:00:00:02"      # OUI Google
PLUG = "d8:1f:12:00:00:03"      # Tuya
SENSOR = "24:0a:c4:00:00:04"    # Espressif
EVIL = "00:11:22:00:00:05"
GW = "00:00:5e:00:01:01"


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
    return pkts


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "ejemplo_lab.pcap"
    wrpcap(out, lab_packets())
    print(f"Captura de ejemplo escrita en {out}")
