"""Huella DHCP (opción 55) y fuga de la MAC en IPv6 global (EUI-64): propuestas de Qwen."""

import pytest
from scapy.all import BOOTP, DHCP, Ether, IP, IPv6, UDP

from iot_scanner import heuristics, report
from iot_scanner.sniffer import PassiveSniffer, dhcp_fingerprint, eui64_mac, leaks_mac
from tests import lab_packets as lab

MAC = "00:11:22:33:44:55"


def _sniff(*pkts):
    s = PassiveSniffer()
    for pkt in pkts:
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    return s.devices


def _dhcp(options, mac=MAC):
    return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=lab.DHCP_NO_IP, dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(chaddr=bytes.fromhex(mac.replace(":", ""))) /
            DHCP(options=[("message-type", "discover"), *options, "end"]))


def _v6(src, mac=MAC):
    return Ether(src=mac, dst=lab.GW) / IPv6(src=src, dst="2001:db8:2::1") / UDP(sport=40000, dport=443)


@pytest.fixture
def extra():
    return _sniff(*lab.extra_rule_packets())


# ---------------- Huella DHCP ----------------

@pytest.mark.parametrize("value, expected", [
    ([1, 3, 6, 15], "1,3,6,15"),
    ([6, 3, 1], "6,3,1"),                    # el orden forma parte de la huella
    (b"\x01\x03\x06", "1,3,6"),
    ([1, 999, -1, "x", 3], "1,3"),           # valores imposibles fuera
    (list(range(200)), ",".join(map(str, range(64)))),   # como mucho 64
    ([], None),
    (7, "7"),
])
def test_dhcp_fingerprint(value, expected):
    assert dhcp_fingerprint(value) == expected


def test_fingerprint_from_lab(extra):
    assert extra[lab.COAP].dhcp_fingerprint == {"1,3,6,12,15,28,42"}


def test_fingerprint_rule_is_strong_evidence(tmp_path):
    import json
    data = json.loads(heuristics.DEFAULT_RULES_PATH.read_text(encoding="utf-8"))
    data["rules"] = [{"label": "Prueba", "dhcp_fp": ["1,3,6,15"]}]
    rules = tmp_path / "r.json"
    rules.write_text(json.dumps(data), encoding="utf-8")
    mac = "02:00:00:00:00:01"     # MAC aleatoria: sin fabricante que sume puntos
    try:
        heuristics.use_rules(rules)
        dev = _sniff(_dhcp([("param_req_list", [1, 3, 6, 15])], mac))[mac]
        other = _sniff(_dhcp([("param_req_list", [3, 1, 6, 15])], mac))[mac]   # mismas opciones, otro orden
    finally:
        heuristics.use_rules(None)
    assert dev.labels[0]["label"] == "Prueba" and dev.labels[0]["score"] == heuristics.WEIGHT_STRONG
    assert not other.labels


def test_dhcp_fp_field_validated(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text('{"rules": [{"label": "X", "dhcp_fp": "1,3,6"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="dhcp_fp"):
        heuristics.load_rules(bad)


# ---------------- EUI-64 ----------------

@pytest.mark.parametrize("addr, expected", [
    ("fe80::211:22ff:fe33:4455", MAC),          # bit U/L: 02 -> 00
    ("2001:db8::ba27:ebff:fe00:13", "b8:27:eb:00:00:13"),
    ("2001:db8::1", None),
    ("2001:db8::5c1d:9a3e:71b2:4f08", None),     # identificador aleatorio (RFC 4941)
    ("no es una IPv6", None),
])
def test_eui64_mac(addr, expected):
    assert eui64_mac(addr) == expected


def test_leaks_only_global_and_own_mac():
    assert leaks_mac("2001:db8::211:22ff:fe33:4455", MAC)
    assert not leaks_mac("fe80::211:22ff:fe33:4455", MAC)       # link-local: no sale de la red
    assert not leaks_mac("fd00::211:22ff:fe33:4455", MAC)       # ULA: no es global
    assert not leaks_mac("2001:db8::211:22ff:fe33:4456", MAC)   # otra MAC (no es la suya)
    assert not leaks_mac("basura", MAC)


def test_eui64_alert(extra):
    thread_br, nas = extra[lab.THREAD_BR], extra[lab.NAS]
    assert thread_br.eui64_global and not nas.eui64_global
    alerts = [a for a in report.build_alerts(extra) if "EUI-64" in a["message"]]
    assert [(a["mac"], a["severity"], a["port"]) for a in alerts] == [(lab.THREAD_BR, "BAJA", None)]


def test_link_local_eui64_is_not_an_alert():
    dev = _sniff(_v6("fe80::211:22ff:fe33:4455"))[MAC]
    assert not dev.eui64_global
    assert not [a for a in report.build_alerts({MAC: dev}) if "EUI-64" in a["message"]]


def test_alert_survives_anonymize(extra):
    anon, _ = report.anonymize(extra, {})
    assert any("EUI-64" in a["message"] for a in report.build_alerts(anon))
    # ... pero la dirección IPv6 ya no aparece en el informe anonimizado
    assert not any("ba27:ebff:fe00:13" in a for d in anon.values() for a in d.ipv6)


def test_new_fields_in_reports(extra, tmp_path):
    import csv
    path = tmp_path / "r.csv"
    report.export_csv(extra, path)
    rows = {r["mac"]: r for r in csv.DictReader(path.open(encoding="utf-8-sig"), delimiter=";")}
    assert rows[lab.THREAD_BR]["eui64_global"] == "sí"
    assert rows[lab.COAP]["dhcp_fingerprint"] == "1,3,6,12,15,28,42"
    assert extra[lab.COAP].to_dict()["dhcp_fingerprint"] == ["1,3,6,12,15,28,42"]
