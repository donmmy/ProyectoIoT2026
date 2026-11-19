"""SSDP: tipos UPnP (NT/ST), versiones del banner SERVER y librerías (propuestas de Qwen)."""

import pytest
from scapy.all import DNS, Ether, IP, Raw, UDP

from iot_scanner import heuristics, report, vulns
from iot_scanner.sniffer import PassiveSniffer, parse_server_banner
from tests import lab_packets as lab
from tests.test_vulns import CVES, FakeInternet, _client, _cve

MAC = "aa:bb:cc:00:00:01"


def _sniff(*pkts):
    s = PassiveSniffer()
    for pkt in pkts:
        s.handle_packet(pkt)
    heuristics.classify_all(s.devices)
    return s.devices


def _notify(server, nt="upnp:rootdevice", first="NOTIFY * HTTP/1.1", sport=1900):
    msg = lab.ssdp_message(first, [("NT", nt), ("ST", nt), ("SERVER", server)])
    return (Ether(src=MAC, dst="01:00:5e:7f:ff:fa") / IP(src="192.168.1.9", dst="239.255.255.250") /
            UDP(sport=sport, dport=1900) / Raw(msg))


@pytest.fixture
def extra():
    return _sniff(*lab.extra_rule_packets())


@pytest.mark.parametrize("banner, expected", [
    ("Linux/3.10 UPnP/1.0 miniupnpd/2.1",
     [("so", "Linux", "3.10"), ("protocolo", "UPnP", "1.0"), ("libreria", "miniupnpd", "2.1")]),
    ("Linux/2.x UPnP/1.0 Shelly/1.0", [("so", "Linux", "2.x"), ("protocolo", "UPnP", "1.0"),
                                       ("producto", "Shelly", "1.0")]),
    ("Linux, UPnP/1.0, Portable SDK for UPnP devices/1.6.19",
     [("protocolo", "UPnP", "1.0"), ("libreria", "Portable SDK for UPnP devices", "1.6.19")]),
    ("FreeRTOS/10.0 UPnP/1.1 Sonos/70.3-35220", [("so", "FreeRTOS", "10.0"), ("protocolo", "UPnP", "1.1"),
                                                 ("producto", "Sonos", "70.3-35220")]),
    ("sin versiones", []),
    ("", []),
])
def test_parse_server_banner(banner, expected):
    assert parse_server_banner(banner) == expected


def test_router_announces_igd_and_library(extra):
    router = extra[lab.ROUTER]
    assert router.upnp_types == {"InternetGatewayDevice", "WANIPConnection"}
    assert router.software == {"miniupnpd/2.1"}
    assert not router.firmware            # Linux es el núcleo y miniupnpd una librería
    best = router.labels[0]
    assert best["label"] == "Router / gateway"
    # IGD y WANIPConnection son una sola pista (+3), no dos
    assert sum("UPnP" in e for e in best["evidence"]) == 1


def test_msearch_is_a_client_not_an_igd(extra):
    phone = extra[lab.ANDROID]
    assert not phone.upnp_types and not phone.software
    assert any(b.startswith("SSDP:Android/14") for b in phone.banners)   # el banner sí se guarda


def test_dhcp_client_version_is_a_library(extra):
    assert extra[lab.COAP].software == {"udhcp/1.24.1"}
    assert not extra[lab.COAP].firmware


def test_product_version_is_firmware():
    dev = _sniff(_notify("Linux/2.x UPnP/1.0 Shelly/1.0"))[MAC]
    assert dev.firmware == {"1.0"} and not dev.software


def test_response_counts_msearch_does_not():
    nt = "urn:schemas-upnp-org:device:MediaRenderer:1"
    assert _sniff(_notify("X/1 UPnP/1.0", nt, first="HTTP/1.1 200 OK"))[MAC].upnp_types == {"MediaRenderer"}
    searcher = _sniff(_notify("X/1 UPnP/1.0 miniupnpd/2.1", nt, first="M-SEARCH * HTTP/1.1", sport=50000))[MAC]
    assert not searcher.upnp_types and not searcher.software and not searcher.firmware


def test_hostile_ssdp():
    long_type = "urn:x:device:" + "A" * 500 + ":1"
    dev = _sniff(_notify("Linux/1 UPnP/1.0 " + "Z" * 300 + "/9", long_type),
                 Ether(src=MAC) / IP(src="192.168.1.9", dst="239.255.255.250") / UDP(sport=1900, dport=1900) /
                 Raw(b"NOTIFY * HTTP/1.1\r\n" + b"NT: urn:a:device:B:1\r\n" * 5000))[MAC]
    assert not any(len(t) > 64 for t in dev.upnp_types)
    assert all(len(s) < 120 for s in dev.software | dev.firmware)
    assert len(dev.upnp_types) <= 1


def test_ssdp_without_payload():
    dev = _sniff(Ether(src=MAC) / IP(src="192.168.1.9", dst="239.255.255.250") / UDP(sport=1900, dport=1900))[MAC]
    assert "SSDP" in dev.protocols and not dev.upnp_types


def test_igd_alert(extra):
    alerts = [a for a in report.build_alerts(extra) if a["mac"] == lab.ROUTER]
    assert {(a["severity"], a["port"]) for a in alerts} >= {("MEDIA", 1900)}
    assert any("IGD" in a["message"] for a in alerts)
    assert not [a for a in report.build_alerts(extra) if a["mac"] == lab.ANDROID and "IGD" in a["message"]]


def test_upnp_field_validated(tmp_path):
    bad = tmp_path / "r.json"
    bad.write_text('{"rules": [{"label": "X", "upnp": "InternetGatewayDevice"}]}', encoding="utf-8")
    with pytest.raises(ValueError, match="upnp"):
        heuristics.load_rules(bad)


def test_library_cves_use_library_version(extra, monkeypatch):
    monkeypatch.setitem(CVES, "cpe:2.3:*:miniupnp_project:miniupnpd", [
        # 2.1 dentro del rango: certeza producto+versión
        _cve_lib("CVE-1999-9301", versionEndExcluding="2.2"),
        # 2.1 fuera: descartado
        _cve_lib("CVE-1999-9302", versionEndExcluding="2.0"),
    ])
    net = FakeInternet()
    stats = vulns.lookup_all({lab.ROUTER: extra[lab.ROUTER]}, _client(net))
    cves = {c["id"]: c for c in extra[lab.ROUTER].cves}
    assert cves["CVE-1999-9301"]["certainty"] == "modelo+firmware"
    assert cves["CVE-1999-9301"]["product"] == "miniupnp_project:miniupnpd 2.1"
    assert "CVE-1999-9302" not in cves
    assert stats["by_software"] == 1 and stats["discarded_by_version"] == 1
    # La librería no dice nada del hardware: también se busca por fabricante (tp-link)
    assert any("cpe:2.3:h:tp-link" in u for u in net.urls)


def _cve_lib(cve_id, **ranges):
    return _cve(cve_id, "cpe:2.3:a:miniupnp_project:miniupnpd:*:*:*:*:*:*:*:*", 7.5, **ranges)


def test_mdns_still_works_next_to_ssdp():
    # Un mismo equipo con SSDP y mDNS: lo nuevo no rompe lo de antes
    mdns = (Ether(src=MAC, dst="01:00:5e:00:00:fb") / IP(src="192.168.1.9", dst="224.0.0.251") /
            UDP(sport=5353, dport=5353) / DNS(qr=1, aa=1))
    dev = _sniff(mdns, _notify("Linux/2.x UPnP/1.0 Shelly/1.0"))[MAC]
    assert {"mDNS", "SSDP"} <= dev.protocols
