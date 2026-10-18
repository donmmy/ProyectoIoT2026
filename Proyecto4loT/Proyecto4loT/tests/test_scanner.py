import csv
import json

import pytest

from iot_scanner import discovery, heuristics, report
from iot_scanner.device import Device
from iot_scanner.sniffer import PassiveSniffer, sanitize_text
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
    assert set(devices) == {lab.CAM, lab.CAST, lab.PLUG, lab.SENSOR, lab.EVIL}


def test_arp_gives_ip_in_passive_mode(devices):
    assert devices[lab.CAM].ip == "192.168.1.10"
    assert "ARP" in devices[lab.CAM].protocols


def test_served_vs_client_ports(devices):
    assert devices[lab.CAM].ports_src == {554, 23}
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
    assert s["device_count"] == 5
    assert s["mode"] == "test"
    assert dict(s["top_protocols"])["UDP"] >= 3


def test_export_json_csv(devices, tmp_path, capsys):
    summary = report.build_summary(devices)
    jp, cp = tmp_path / "r.json", tmp_path / "r.csv"
    report.export_json(devices, summary, jp)
    report.export_csv(devices, cp)

    data = json.loads(jp.read_text(encoding="utf-8"))
    assert len(data["devices"]) == 5
    assert data["summary"]["alerts"]

    rows = list(csv.DictReader(cp.open(encoding="utf-8-sig"), delimiter=";"))
    assert len(rows) == 5
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
    assert data["summary"]["device_count"] == 5
