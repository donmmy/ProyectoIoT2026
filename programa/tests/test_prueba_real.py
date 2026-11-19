"""Fallos encontrados al comparar con Wireshark una captura real (2026-11-19, Hito 6).

Se reproducen con tráfico sintético: las capturas reales no se suben al repositorio.
"""

import pytest
from scapy.all import ARP, IP, TCP, UDP, Ether, Raw

from iot_scanner import heuristics
from iot_scanner.device import Device
from iot_scanner.sniffer import PassiveSniffer, is_global_ip
from tests import lab_packets as lab

ROUTER = "00:09:0f:09:00:12"     # OUI Fortinet, como en la captura
LAPTOP = "f8:3d:c6:00:00:01"


def _sniff(*pkts, devices=None):
    s = PassiveSniffer(devices)
    for pkt in pkts:
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    return s.devices


def _routed(src_ip, sport=443):
    """Respuesta de un servidor de internet: llega con la MAC del router, no la del servidor."""
    return Ether(src=ROUTER, dst=LAPTOP) / IP(src=src_ip, dst="10.1.193.226") / TCP(sport=sport, dport=51000)


def _arp(ip):
    return Ether(src=ROUTER, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=ROUTER)


# ---------------- 1. IP del router ----------------

def test_router_keeps_arp_ip_after_routed_traffic():
    dev = _sniff(_arp("10.1.192.1"), _routed("160.79.104.10"), _routed("199.232.215.52"))[ROUTER]
    assert dev.ip == "10.1.192.1"


def test_arp_replaces_public_ip_seen_first():
    # Como en la captura: el tráfico reenviado llega antes que el ARP del router
    dev = _sniff(_routed("160.79.104.10"), _arp("10.1.192.1"))[ROUTER]
    assert dev.ip == "10.1.192.1"


def test_private_ip_wins_over_public_without_arp():
    lan = Ether(src=ROUTER, dst=LAPTOP) / IP(src="10.1.192.1", dst="10.1.193.226") / UDP(sport=53, dport=50000)
    assert _sniff(_routed("160.79.104.10"), lan)[ROUTER].ip == "10.1.192.1"
    assert _sniff(lan, _routed("160.79.104.10"))[ROUTER].ip == "10.1.192.1"


def test_public_ip_if_nothing_better():
    # Hay redes (algunas universidades) con IP públicas en la LAN: sin otra cosa, se usa
    assert _sniff(_routed("160.79.104.10"))[ROUTER].ip == "160.79.104.10"


def test_first_arp_ip_is_kept():
    # Un equipo puede responder ARP por varias IP (proxy ARP): se queda la primera
    assert _sniff(_arp("10.1.192.1"), _arp("10.1.192.254"))[ROUTER].ip == "10.1.192.1"


def test_arp_scan_ip_is_authoritative():
    # Dispositivos que ya vienen del ARP scan (modo en vivo): su IP no se toca
    scanned = {ROUTER: Device(mac=ROUTER, ip="10.1.192.1", source="arp")}
    assert _sniff(_routed("160.79.104.10"), devices=scanned)[ROUTER].ip == "10.1.192.1"


@pytest.mark.parametrize("ip, expected", [
    ("160.79.104.10", True), ("8.8.8.8", True),
    ("10.1.192.1", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("169.254.1.1", False), ("100.64.0.1", False),          # link-local y CGNAT
    ("2001:4860::8888", True), ("fe80::1", False), ("basura", False),
])
def test_is_global_ip(ip, expected):
    assert is_global_ip(ip) is expected


# ---------------- 2. Quien busca por SSDP no es un aparato multimedia ----------------

def _msearch(mac, agent="Chromium/128.0 Windows"):
    msg = lab.ssdp_message("M-SEARCH * HTTP/1.1", [("MAN", '"ssdp:discover"'), ("MX", "1"),
                                                   ("ST", "urn:dial-multiscreen-org:service:dial:1"),
                                                   ("USER-AGENT", agent)])
    return (Ether(src=mac, dst="01:00:5e:7f:ff:fa") / IP(src="10.1.193.50", dst="239.255.255.250") /
            UDP(sport=50000, dport=1900) / Raw(msg))


def _labels(dev):
    return [lab_["label"] for lab_ in dev.labels]


def test_ssdp_searcher_is_not_upnp_media():
    # En la captura real, 7 portátiles salían como "Dispositivo UPnP / multimedia" solo por
    # conectar al 1900 (+1). Ahora no reciben esa etiqueta
    dev = _sniff(_msearch("08:8e:90:00:00:02", agent="Mozilla/5.0"))["08:8e:90:00:00:02"]
    assert "Dispositivo UPnP / multimedia" not in _labels(dev)


def test_real_upnp_device_still_detected():
    notify = lab.ssdp_message("NOTIFY * HTTP/1.1", [("NT", "urn:schemas-upnp-org:device:MediaRenderer:1"),
                                                    ("NTS", "ssdp:alive"), ("SERVER", "Linux/4.9 UPnP/1.0 TV/1.0")])
    pkt = (Ether(src="aa:bb:cc:00:00:09", dst="01:00:5e:7f:ff:fa") / IP(src="10.1.193.60", dst="239.255.255.250") /
           UDP(sport=1900, dport=1900) / Raw(notify))
    dev = _sniff(pkt)["aa:bb:cc:00:00:09"]
    assert _labels(dev)[0] == "Dispositivo UPnP / multimedia"


def test_chrome_on_windows_still_windows():
    # "Equipo Windows" salía del User-Agent de Chrome en el M-SEARCH: eso no cambia
    dev = _sniff(_msearch("08:8e:90:00:00:03"))["08:8e:90:00:00:03"]
    assert _labels(dev)[0] == "Equipo Windows"
