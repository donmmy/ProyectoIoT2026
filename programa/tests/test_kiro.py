"""Propuestas de Kiro (2026-11-19): JA3, DHCPv6, riesgo combinado y eTLD+1 al anonimizar."""

import json
import struct

import pytest
from scapy.all import Ether, IPv6, TCP, UDP, Raw
from scapy.layers.dhcp6 import DHCP6_Reply, DHCP6_Solicit, DHCP6OptClientFQDN, DHCP6OptVendorClass, VENDOR_CLASS_DATA

from iot_scanner import heuristics, psl, report
from iot_scanner.device import Device
from iot_scanner.sniffer import PassiveSniffer, ja3_hash, parse_client_hello, tls_sni
from tests import lab_packets as lab

MAC = "02:00:00:00:00:07"   # MAC aleatoria: sin fabricante que sume puntos en las reglas


def _sniff(*pkts):
    s = PassiveSniffer()
    for pkt in pkts:
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    return s.devices


def _hello(ciphers, extensions, version=0x0303):
    """ClientHello con las extensiones dadas como [(tipo, cuerpo)]."""
    exts = b"".join(struct.pack("!HH", t, len(b)) + b for t, b in extensions)
    body = (struct.pack("!H", version) + bytes(32) + b"\x00" +
            struct.pack("!H", 2 * len(ciphers)) + b"".join(struct.pack("!H", c) for c in ciphers) +
            b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _sni_ext(name):
    n = name.encode()
    return 0x0000, struct.pack("!HBH", len(n) + 3, 0, len(n)) + n


GROUPS = (0x000A, struct.pack("!H", 6) + struct.pack("!HHH", 0x1A1A, 29, 23))   # GREASE, x25519, secp256r1
POINTS = (0x000B, b"\x01\x00")


# ---------------- JA3 ----------------

def test_ja3_string_skips_grease():
    data = _hello([0x0A0A, 4865, 49195], [(0x2A2A, b""), _sni_ext("a.example.com"), GROUPS, POINTS])
    hello = parse_client_hello(data)
    assert hello["sni"] == "a.example.com"
    # versión, cifrados, extensiones, curvas, formatos de punto (sin GREASE)
    assert hello["ja3"] == "771,4865-49195,0-10-11,29-23,0"
    assert ja3_hash(hello["ja3"]) == ja3_hash("771,4865-49195,0-10-11,29-23,0")
    assert len(ja3_hash(hello["ja3"])) == 32


def test_ja3_depends_on_order():
    a = parse_client_hello(_hello([4865, 49195], [GROUPS, POINTS]))["ja3"]
    b = parse_client_hello(_hello([49195, 4865], [GROUPS, POINTS]))["ja3"]
    assert a != b


def test_truncated_hello_keeps_sni_but_no_ja3():
    data = _hello([4865], [_sni_ext("b.example.com"), GROUPS, POINTS])
    cut = data[:-3]                          # el ClientHello sigue en otro segmento TCP
    hello = parse_client_hello(cut)
    assert hello["sni"] == "b.example.com" and hello["ja3"] is None
    assert tls_sni(cut) == "b.example.com"
    assert parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None   # no es un ClientHello


def test_ja3_reaches_device_and_rules(tmp_path):
    data = _hello([4865], [_sni_ext("c.example.com"), GROUPS, POINTS])
    pkt = Ether(src=MAC, dst=lab.GW) / IPv6(src="fe80::7", dst="2001:db8::1") / TCP(sport=40000, dport=443) / Raw(data)
    expected = ja3_hash(parse_client_hello(data)["ja3"])

    rules = json.loads(heuristics.DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
    rules["rules"] = [{"label": "Prueba JA3", "ja3": [expected]}]
    path = tmp_path / "r.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    try:
        heuristics.use_rules(path)
        dev = _sniff(pkt)[MAC]
    finally:
        heuristics.use_rules(None)
    assert dev.ja3 == {expected} and dev.tls_sni == {"c.example.com"}
    assert dev.labels[0]["label"] == "Prueba JA3" and dev.labels[0]["score"] == heuristics.WEIGHT_STRONG


def test_ja3_field_validated(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text('{"rules": [{"label": "X", "ja3": "abc"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="ja3"):
        heuristics.load_rules(bad)


# ---------------- DHCPv6 ----------------

def _dhcp6(msg, sport=546, fqdn=None, vendor=None):
    pkt = msg()
    if fqdn:
        pkt = pkt / DHCP6OptClientFQDN(fqdn=fqdn)
    if vendor:
        pkt = pkt / DHCP6OptVendorClass(enterprisenum=4413, vcdata=[VENDOR_CLASS_DATA(data=v) for v in vendor])
    return (Ether(src=MAC, dst="33:33:00:01:00:02") / IPv6(src="fe80::7", dst="ff02::1:2") /
            UDP(sport=sport, dport=547 if sport == 546 else 546) / pkt)


def test_dhcp6_hostname_and_vendor():
    dev = _sniff(_dhcp6(DHCP6_Solicit, fqdn="sensor-patio.casa.example.", vendor=[b"lwIP 2.1", b"x\x00<b>"]))[MAC]
    assert "DHCPv6" in dev.protocols
    assert dev.hostname == "sensor-patio"
    assert "DHCPv6:lwIP 2.1" in dev.banners
    assert all("<" not in b and "\x00" not in b for b in dev.banners)    # saneado


def test_dhcp6_from_server_is_ignored():
    dev = _sniff(_dhcp6(DHCP6_Reply, sport=547, fqdn="servidor.example."))[MAC]
    assert not dev.hostname and "DHCPv6" not in dev.protocols


def test_dhcp6_does_not_replace_hostname(extra):
    br = extra[lab.THREAD_BR]
    assert br.hostname == "openthread-br"                 # llegó antes por mDNS
    assert "DHCPv6:OpenThread BR 1.3" in br.banners and "DHCPv6" in br.protocols


# ---------------- Riesgo combinado ----------------

def _cve(cvss, certainty="modelo", kev=False):
    return {"id": "CVE-1999-0001", "cvss": cvss, "kev": kev, "certainty": certainty}


@pytest.mark.parametrize("alerts, cves, expected", [
    ([], [], None),
    (["BAJA"], [], "BAJO"),
    (["BAJA", "MEDIA"], [], "MEDIO"),
    (["ALTA", "BAJA"], [], "ALTO"),
    ([], [_cve(9.8, "fabricante")], None),               # suposición: no cuenta
    ([], [_cve(9.8, "modelo")], "BAJO"),                 # sin versión confirmada
    ([], [_cve(7.5, "modelo+firmware")], "MEDIO"),
    ([], [_cve(5.0, "modelo+firmware")], "BAJO"),
    ([], [_cve(4.0, "modelo", kev=True)], "MEDIO"),      # explotado activamente
    (["BAJA"], [_cve(7.5, "modelo+firmware")], "MEDIO"),
])
def test_device_risk(alerts, cves, expected):
    dev = Device(mac=MAC, cves=cves)
    alert_rows = [{"mac": MAC, "severity": s} for s in alerts] + [{"mac": "otro", "severity": "ALTA"}]
    assert report.device_risk(dev, alert_rows)["level"] == expected


def test_risk_in_summary_and_reports(extra, tmp_path, capsys):
    summary = report.build_summary(extra)
    levels = {r["mac"]: r["level"] for r in summary["risk"]}
    assert levels[lab.ROUTER] == "MEDIO"                  # alertas MEDIA de UPnP IGD
    assert [r["level"] for r in summary["risk"]] == sorted((r["level"] for r in summary["risk"]),
                                                           key=report.RISK_ORDER.get)
    assert all(r["reasons"] for r in summary["risk"])
    report.print_summary(summary)
    assert "Riesgo por dispositivo" in capsys.readouterr().out
    import csv
    path = tmp_path / "r.csv"
    report.export_csv(extra, path)
    rows = {r["mac"]: r for r in csv.DictReader(path.open(encoding="utf-8-sig"), delimiter=";")}
    assert rows[lab.ROUTER]["riesgo"] == "MEDIO"


def test_lab_camera_is_high_risk():
    s = PassiveSniffer()
    for pkt in lab.lab_packets():
        s.handle_packet(pkt)
    risk = {r["mac"]: r["level"] for r in report.build_risk(s.devices)}
    assert risk[lab.CAM] == "ALTO"                        # sirve Telnet


# ---------------- eTLD+1 ----------------

@pytest.mark.parametrize("domain, expected", [
    ("api.eu.hik-connect.com", "hik-connect.com"),
    ("news.bbc.co.uk", "bbc.co.uk"),                     # sufijo de dos niveles
    ("a.b.example.com.es", "example.com.es"),
    ("usuario.github.io", "usuario.github.io"),          # sufijo privado: cada usuario es "registrable"
    ("foo.bar.ck", "foo.bar.ck"),                         # comodín *.ck
    ("www.ck", "www.ck"),                                 # excepción !www.ck
    ("co.uk", "co.uk"),                                   # ya es un sufijo
    ("connectivitycheck.gstatic.com.", "gstatic.com"),
    ("localhost", "localhost"),
    ("", ""),
])
def test_registrable_domain(domain, expected):
    assert psl.registrable_domain(domain) == expected


def test_psl_parser_and_fallback(tmp_path, monkeypatch, caplog):
    f = tmp_path / "psl.dat"
    f.write_text("// comentario\ncom\n*.ck\n!www.ck\nco.uk\n", encoding="utf-8")
    normal, wild, exc = psl.load(f)
    assert normal == {"com", "co.uk"} and wild == {"ck"} and exc == {"www.ck"}
    # Sin fichero: aviso y regla por defecto (última etiqueta), sin romper nada
    monkeypatch.setattr(psl, "PSL_PATH", tmp_path / "no-existe.dat")
    monkeypatch.setattr(psl, "_RULES", None)
    assert psl.registrable_domain("a.b.example.co.uk") == "co.uk"
    assert "Public Suffix List" in caplog.text


def test_anonymize_reduces_sni_and_evidence():
    s = PassiveSniffer()
    for pkt in lab.lab_packets():
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    anon, _ = report.anonymize(s.devices, {})
    for d in anon.values():
        for name in d.dns_queries | d.tls_sni:
            assert name == psl.registrable_domain(name)
        for label in d.labels:
            for e in label["evidence"]:
                if e.startswith(("consulta ", "TLS a ")):
                    assert e.split()[-2] == psl.registrable_domain(e.split()[-2])
    # El original no se toca
    assert any(q.count(".") >= 2 for d in s.devices.values() for q in d.dns_queries)


@pytest.fixture
def extra():
    return _sniff(*lab.extra_rule_packets())
