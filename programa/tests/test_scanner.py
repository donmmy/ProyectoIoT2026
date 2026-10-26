import csv
import json

import pytest

from iot_scanner import discovery, heuristics, report
from iot_scanner.device import Device
from iot_scanner.sniffer import PassiveSniffer, sanitize_text, tls_sni
from tests import lab_packets as lab


@pytest.fixture
def devices():
    s = PassiveSniffer()
    for pkt in lab.lab_packets():
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    return s.devices


# ---------------- Hito 1 ----------------

def test_validate_network():
    assert discovery.validate_network("192.168.1.77/24") == "192.168.1.0/24"
    with pytest.raises(ValueError):
        discovery.validate_network("no-es-una-red")
    with pytest.raises(ValueError):
        discovery.validate_network("fe80::/64")


def test_vendor_random_mac():
    assert discovery.vendor_from_mac("da:a1:19:00:00:01") == "MAC aleatoria/privada"


def test_vendor_unknown_never_returns_mac():
    v = discovery.vendor_from_mac("00:00:00:00:00:00")
    assert ":" not in v or v != "00:00:00:00:00:00"


# ---------------- Hito 2 ----------------

def test_multicast_source_ignored_and_devices_aggregated(devices):
    assert set(devices) == {lab.CAM, lab.CAST, lab.PLUG, lab.SENSOR, lab.EVIL, lab.MATTER}


def test_arp_gives_ip_in_passive_mode(devices):
    assert devices[lab.CAM].ip == "192.168.1.10"
    assert "ARP" in devices[lab.CAM].protocols


def test_served_vs_client_ports(devices):
    assert devices[lab.CAM].ports_src == {554, 23, 3702}  # 3702: WS-Discovery Hello
    assert 1883 in devices[lab.SENSOR].ports_dst
    assert not devices[lab.SENSOR].ports_src


def test_dhcp_hostname(devices):
    assert devices[lab.PLUG].hostname == "wlan0-tuya-plug"
    assert devices[lab.PLUG].ip == "192.168.1.30"  # 0.0.0.0 de DHCP no cuenta


def test_mdns_hostname_and_service(devices):
    cast = devices[lab.CAST]
    assert cast.hostname == "Chromecast-Salon"
    assert "_googlecast._tcp" in cast.mdns_services
    assert "mDNS" in cast.protocols


def test_dns_queries_and_ssdp(devices):
    assert "dev.hik-connect.com" in devices[lab.CAM].dns_queries
    evil = devices[lab.EVIL]
    assert "SSDP" in evil.protocols
    assert any(b.startswith("SSDP:") for b in evil.banners)


def test_sanitize_strips_injection(devices):
    host = devices[lab.EVIL].hostname
    for bad in ("|", "'", "!", "\x1b", ";", "<", ">"):
        assert bad not in host
    assert all("<" not in b for b in devices[lab.EVIL].banners)
    assert sanitize_text("x" * 500) == "x" * 64
    assert sanitize_text(b"\x00\x01") is None


# ---------------- Ampliación: NTP, TLS (SNI), Matter/Thread ----------------

def _sniff(*pkts):
    s = PassiveSniffer()
    for pkt in pkts:
        s.handle_packet(pkt)
    return s.devices


def test_ntp_client_is_not_a_server(devices):
    cam = devices[lab.CAM]
    assert "NTP" in cam.protocols
    assert lab.NTP_SERVER in cam.ntp_servers
    assert 123 not in cam.ports_src  # ntpd usa 123 también como cliente


def test_ntp_server_mode_marks_served_port():
    from scapy.all import IP, UDP, Ether, NTPHeader
    mac = "00:11:22:00:00:99"
    devs = _sniff(Ether(src=mac) / IP(src="192.168.1.1", dst="192.168.1.10") /
                  UDP(sport=123, dport=40000) / NTPHeader(mode=4))
    assert 123 in devs[mac].ports_src
    assert not devs[mac].ntp_servers


def test_tls_sni_extracted_and_used_as_evidence(devices):
    cam = devices[lab.CAM]
    assert "api.hik-connect.com" in cam.tls_sni
    assert "TLS" in cam.protocols
    assert 443 in cam.ports_dst


def test_tls_sni_parser_edge_cases():
    hello = lab.client_hello("a.example.com")
    assert tls_sni(hello) == "a.example.com"
    assert tls_sni(hello[:60]) is None         # ClientHello cortado en otro segmento
    assert tls_sni(b"GET / HTTP/1.1\r\n") is None
    assert tls_sni(b"") is None
    assert tls_sni(b"\x16\x03\x01\x00\x05\x01") is None


def test_tls_sni_is_sanitized(devices):
    sni = devices[lab.EVIL].tls_sni
    assert sni and all(c not in s for s in sni for c in "<>;\x1b[")


def test_sni_counts_as_domain_evidence():
    d = Device(mac="aa", tls_sni={"a3.tuyaeu.com"})
    assert heuristics.classify(d)[0]["evidence"] == ["TLS a a3.tuyaeu.com (+3)"]


def test_matter_over_ipv6(devices):
    bulb = devices[lab.MATTER]
    assert "IPv6" in bulb.protocols
    assert "fe80::daa0:11ff:fe00:6" in bulb.ipv6
    assert bulb.ip is None
    assert "_matter._tcp" in bulb.mdns_services
    assert 5540 in bulb.ports_src
    assert bulb.hostname == "D8A011000006"
    assert _labels(bulb)[0] == "Dispositivo Matter"


def test_wsd_onvif_hello(devices):
    cam = devices[lab.CAM]
    assert "WS-Discovery" in cam.protocols
    assert cam.wsd_types == {"NetworkVideoTransmitter", "Device"}
    assert "ONVIF:hardware=DS-2CD2043G2-I" in cam.banners
    assert "ONVIF:name=HIKVISION Entrada" in cam.banners  # %20 decodificado
    assert "WS-Discovery NetworkVideoTransmitter (+3)" in cam.labels[0]["evidence"]


def test_wsd_alone_identifies_camera():
    best = heuristics.classify(Device(mac="aa", wsd_types={"NetworkVideoTransmitter"}))[0]
    assert (best["label"], best["confidence"]) == ("Cámara IP / NVR", "media")


def test_wsd_probe_is_client_not_service():
    from scapy.all import IP, UDP, Ether, Raw
    mac = "00:11:22:00:00:77"
    probe = lab.wsd_message("Probe", types="dn:NetworkVideoTransmitter")
    devs = _sniff(Ether(src=mac) / IP(src="192.168.1.50", dst="239.255.255.250") /
                  UDP(sport=3702, dport=3702) / Raw(probe))
    assert "WS-Discovery" in devs[mac].protocols
    assert not devs[mac].wsd_types       # busca cámaras, no es una
    assert 3702 not in devs[mac].ports_src


def test_wsd_hostile_payloads():
    from scapy.all import IP, UDP, Ether, Raw
    mac = "00:11:22:00:00:78"
    evil = lab.wsd_message("Hello", types="dn:Net<x>work;rm",
                           scopes="onvif://www.onvif.org/name/%3Cscript%3E%1b[31m")
    junk = b"<" * 20000 + b"Action>" + b"x" * 20000   # sin cierre: no debe colgarse
    devs = _sniff(*(Ether(src=mac) / IP(src="192.168.1.51", dst="239.255.255.250") /
                    UDP(sport=3702, dport=3702) / Raw(p) for p in (evil, junk, bytes([0xff, 0xfe]))))
    dev = devs[mac]
    assert all(c not in t for t in dev.wsd_types | dev.banners for c in "<>;" + chr(27))
    assert any(b.startswith("ONVIF:name=") for b in dev.banners)


def test_wsd_alert(devices):
    keys = {(a["mac"], a["port"]) for a in report.build_alerts(devices)}
    assert (lab.CAM, 3702) in keys


def test_thread_border_router_rule():
    d = Device(mac="aa", mdns_services={"_meshcop._udp", "_trel._udp"})
    best = heuristics.classify(d)[0]
    assert best["label"] == "Border router Thread / controlador Matter"
    assert best["confidence"] == "alta"  # dos servicios mDNS específicos (3 + 3)


# ---------------- Hito 3 ----------------

def _labels(dev):
    return [c["label"] for c in dev.labels]


def test_camera_identified_high_confidence(devices):
    best = devices[lab.CAM].labels[0]
    assert best["label"] == "Cámara IP / NVR"
    assert best["confidence"] == "alta"
    assert best["score"] >= 3


def test_other_devices_identified(devices):
    assert _labels(devices[lab.CAST])[0] == "Chromecast / Smart TV"
    assert _labels(devices[lab.PLUG])[0] == "Enchufe / bombilla inteligente"
    assert "Dispositivo MQTT (sensor/actuador IoT)" in _labels(devices[lab.SENSOR])


def test_unknown_device_has_no_labels():
    d = Device(mac="00:11:22:33:44:55")
    assert heuristics.classify(d) == []


def test_labels_limited_and_sorted():
    d = Device(mac="aa", ports_src={554, 1883, 631, 445, 62078}, hostname="camera")
    labels = heuristics.classify(d)
    assert len(labels) <= 3
    assert [c["score"] for c in labels] == sorted((c["score"] for c in labels), reverse=True)


def _best(dev):
    labels = heuristics.classify(dev)
    return (labels[0]["label"], labels[0]["confidence"], labels[0]["score"]) if labels else None


def test_weights_specific_vs_generic_ports():
    # Un puerto propietario solo ya da confianza media; el 80 solo, baja
    assert _best(Device(mac="aa", ports_src={37777})) == ("Cámara IP / NVR", "media", 3)
    assert _best(Device(mac="aa", ports_src={80}))[1:] == ("baja", 1)


def test_vendor_alone_is_weak_evidence():
    # Fabricante ≠ tipo: un móvil Google o Samsung no pasa de "baja" como TV
    label, conf, score = _best(Device(mac="aa", vendor="Google, Inc."))
    assert (conf, score) == ("baja", 1)
    ev = heuristics.classify(Device(mac="aa", vendor="Google, Inc."))[0]["evidence"]
    assert ev == ["fabricante 'Google' (+1)"]


def test_text_regex_needs_word_start():
    assert heuristics.classify(Device(mac="aa", hostname="despacho-pc")) == []
    assert _best(Device(mac="aa", hostname="ESP_32AB12"))[0] == "Dispositivo MQTT (sensor/actuador IoT)"
    assert _best(Device(mac="aa", banners={"SSDP:Linux UPnP/1.0 IPCamera"}))[0] == "Cámara IP / NVR"


def test_same_port_served_and_client_counts_once():
    labels = heuristics.classify(Device(mac="aa", ports_src={1900}, ports_dst={1900}))
    upnp = next(c for c in labels if c["label"] == "Dispositivo UPnP / multimedia")
    assert upnp["evidence"] == ["sirve puerto 1900 (+1)"]


def test_weights_do_not_hide_alerts():
    # El 80 pesa poco para identificar, pero la alerta de seguridad sigue saliendo
    d = Device(mac="aa", ip="192.168.1.99", ports_src={80})
    assert any(a["port"] == 80 for a in report.build_alerts({"aa": d}))


# ---------------- Hito 4 ----------------

def test_alerts(devices):
    alerts = report.build_alerts(devices)
    keys = {(a["mac"], a["port"]) for a in alerts}
    assert (lab.CAM, 23) in keys and (lab.CAM, 554) in keys
    assert (lab.SENSOR, 1883) in keys
    assert (lab.EVIL, 1900) in keys
    assert alerts[0]["severity"] == "ALTA"


def test_summary(devices):
    s = report.build_summary(devices, {"mode": "test"})
    assert s["device_count"] == 6
    assert s["mode"] == "test"
    assert dict(s["top_protocols"])["UDP"] >= 3


def test_export_json_csv(devices, tmp_path, capsys):
    summary = report.build_summary(devices)
    jp, cp = tmp_path / "r.json", tmp_path / "r.csv"
    report.export_json(devices, summary, jp)
    report.export_csv(devices, cp)

    data = json.loads(jp.read_text(encoding="utf-8"))
    assert len(data["devices"]) == 6
    assert data["summary"]["alerts"]

    rows = list(csv.DictReader(cp.open(encoding="utf-8-sig"), delimiter=";"))
    assert len(rows) == 6
    # Ninguna celda debe empezar por un carácter de fórmula
    for r in rows:
        for v in r.values():
            assert not v[:1] in ("=", "+", "@")

    report.print_table(devices)
    report.print_summary(summary)
    out = capsys.readouterr().out
    assert "Cámara IP" in out and "Alertas" in out


def test_cli_pcap(tmp_path, capsys):
    from scapy.all import wrpcap
    import net_device_scanner
    pcap = tmp_path / "lab.pcap"
    wrpcap(str(pcap), lab.lab_packets())
    out_json = tmp_path / "o.json"
    assert net_device_scanner.main(["--pcap", str(pcap), "-o", str(out_json)]) == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["mode"] == "pcap"
    assert data["summary"]["device_count"] == 6
