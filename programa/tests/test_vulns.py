"""Búsqueda de CVE (--cve) con NVD y CISA KEV simulados: los tests no salen a internet.

Los identificadores CVE-1999-9xxx son inventados para estos tests.
"""

import csv
import json
import urllib.parse

import pytest

from iot_scanner import heuristics, report, vulns
from iot_scanner.device import Device
from iot_scanner.sniffer import PassiveSniffer
from tests import lab_packets as lab

PRINTER_MODEL = "Brother HL-L2350DW series"


def _cve(cve_id, criteria, score=7.5, **ranges):
    return {"id": cve_id,
            "descriptions": [{"lang": "en", "value": "Fake\x07 bug " + "x" * 300}],
            "metrics": {"cvssMetricV31": [{"type": "Primary",
                                           "cvssData": {"baseScore": score, "baseSeverity": "HIGH"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": criteria, **ranges}]}]}]}


ESPHOME = "cpe:2.3:a:esphome:esphome:*:*:*:*:*:*:*:*"
PRINTER_FW = "cpe:2.3:o:brother:hl-l2350dw_firmware:-:*:*:*:*:*:*:*"
CVES = {
    "cpe:2.3:*:esphome:esphome": [
        # 2024.6.1 (la del laboratorio) cae dentro: certeza modelo+firmware, y está en KEV
        _cve("CVE-1999-9001", ESPHOME, 9.1, versionStartIncluding="2024.6.0", versionEndExcluding="2024.7.0"),
        # 2024.6.1 queda fuera del rango: se descarta
        _cve("CVE-1999-9002", ESPHOME, 6.5, versionStartIncluding="2023.12.9", versionEndExcluding="2024.2.2"),
        # Sin rango de versiones: solo certeza modelo
        _cve("CVE-1999-9003", ESPHOME, 4.0),
    ],
    "cpe:2.3:*:brother:hl-l2350dw": [_cve("CVE-1999-9101", PRINTER_FW, 9.8)],
    "cpe:2.3:o:brother:hl-l2350dw_firmware": [_cve("CVE-1999-9101", PRINTER_FW, 9.8)],
}
CPES = {
    "brother hl-l2350dw": [
        "cpe:2.3:o:brother:hl-l2350dw_firmware:-:*:*:*:*:*:*:*",
        "cpe:2.3:h:brother:hl-l2350dw:-:*:*:*:*:*:*:*",
        "cpe:2.3:h:brother:hl-l2350:-:*:*:*:*:*:*:*",     # parecido, pero no es este modelo
        "cpe:2.3:h:brother:dcp-1610w:-:*:*:*:*:*:*:*",    # otro modelo de la misma marca
    ],
}


class FakeInternet:
    def __init__(self, fail=False):
        self.urls, self.headers, self.fail = [], [], fail

    def __call__(self, url, headers):
        self.urls.append(urllib.parse.unquote_plus(url))
        self.headers.append(headers)
        if self.fail:
            raise OSError("sin red")
        if url == vulns.KEV_URL:
            return {"vulnerabilities": [{"cveID": "CVE-1999-9001"}, {"cveID": "CVE-1999-9101x"}]}
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
        if url.startswith(vulns.NVD_CPES):
            return {"products": [{"cpe": {"cpeName": n, "deprecated": False}}
                                 for n in CPES.get(q["keywordSearch"], [])]}
        found = CVES.get(q.get("virtualMatchString"), [])
        return {"totalResults": len(found), "vulnerabilities": [{"cve": c} for c in found]}


RealClient = vulns.Client


def _client(fetch, **kw):
    kw.setdefault("cache_dir", None)
    return RealClient(fetch=fetch, sleep=lambda s: None, api_key="", **kw)


@pytest.fixture
def devices():
    s = PassiveSniffer()
    for pkt in lab.lab_packets():
        s.handle_packet(pkt)
    s.devices["printer"] = Device(mac="00:80:77:00:00:14", ip="192.168.1.114",
                                  hostname="Brother-Despacho", models={PRINTER_MODEL})
    heuristics.classify_all(s.devices)
    return s.devices


def _ids(dev):
    return [c["id"] for c in dev.cves]


def test_certainty_levels_and_version_discard(devices):
    stats = vulns.lookup_all(devices, _client(FakeInternet()))
    sensor = devices[lab.SENSOR]
    assert sensor.firmware == {"2024.6.1"}
    # El que está en KEV y en rango va primero; el de fuera de rango no aparece
    assert _ids(sensor) == ["CVE-1999-9001", "CVE-1999-9003"]
    assert [c["certainty"] for c in sensor.cves] == ["modelo+firmware", "modelo"]
    assert sensor.cves[0]["kev"] and not sensor.cves[1]["kev"]
    assert stats["discarded_by_version"] == 1

    # Impresora: sin versión, certeza modelo; el CVE sale una vez aunque llegue por hardware y firmware
    printer = devices["printer"]
    assert _ids(printer) == ["CVE-1999-9101"]
    assert printer.cves[0]["certainty"] == "modelo" and printer.cves[0]["product"] == "brother:hl-l2350dw"

    # Chromecast tiene modelo pero el diccionario simulado no lo conoce; la cámara no anuncia modelo
    assert devices[lab.CAST].models and not devices[lab.CAST].cves
    assert stats["no_cpe"] >= 1 and stats["without_model"] >= 1
    assert stats["cves"] == 3 and stats["kev"] == 1 and stats["kev_loaded"]


def test_similar_products_are_not_matched():
    client = _client(FakeInternet())
    assert vulns.find_products(PRINTER_MODEL, client) == {("brother", "hl-l2350dw"): True}
    assert vulns.find_products("abc", client) == {}       # demasiado corto para buscar


def test_only_models_leave_the_machine(devices):
    net = FakeInternet()
    vulns.lookup_all(devices, _client(net))
    sent = " ".join(net.urls).lower()
    for d in devices.values():
        for private in (d.mac, d.ip, d.hostname):
            assert not private or private.lower() not in sent
    assert "series" not in sent                  # palabra que no está en los nombres CPE
    assert all(u.startswith("https://") for u in net.urls)


def test_kev_in_range_becomes_alert_and_reaches_reports(devices, tmp_path, capsys):
    stats = vulns.lookup_all(devices, _client(FakeInternet()))
    alerts = [a for a in report.build_alerts(devices) if a["port"] is None]
    # Solo el CVE en KEV con certeza modelo+firmware; el de la impresora (modelo) no es alerta
    assert [(a["mac"], a["severity"]) for a in alerts] == [(lab.SENSOR, "ALTA")]
    assert "CVE-1999-9001" in alerts[0]["message"]

    summary = report.build_summary(devices, {"mode": "test", "cve_search": stats})
    assert [c["id"] for c in summary["cves"]][0] == "CVE-1999-9001"
    report.print_summary(summary)
    out = capsys.readouterr().out
    assert "Vulnerabilidades conocidas (3" in out and "KEV" in out and "puerto -" in out

    jp, cp = tmp_path / "r.json", tmp_path / "r.csv"
    report.export_json(devices, summary, jp)
    report.export_csv(devices, cp)
    data = json.loads(jp.read_text(encoding="utf-8"))
    assert any(d["cves"] for d in data["devices"])
    rows = list(csv.DictReader(cp.open(encoding="utf-8-sig"), delimiter=";"))
    assert any("CVE-1999-9001 (9.1, modelo+firmware, KEV)" in r["cves"] for r in rows)

    anon, _ = report.anonymize(devices, {})
    assert sorted(c["id"] for d in anon.values() for c in d.cves) == \
        sorted(c["id"] for d in devices.values() for c in d.cves)


def test_summary_is_sanitized_and_short(devices):
    vulns.lookup_all(devices, _client(FakeInternet()))
    text = devices["printer"].cves[0]["summary"]
    assert "\x07" not in text and len(text) == vulns.SUMMARY_CHARS


def test_cache_avoids_downloading_again(devices, tmp_path):
    first = _client(FakeInternet(), cache_dir=tmp_path)
    vulns.lookup_all(devices, first)
    assert first.requests > 0
    before = {m: _ids(d) for m, d in devices.items()}

    offline = _client(FakeInternet(fail=True), cache_dir=tmp_path)
    stats = vulns.lookup_all(devices, offline)
    assert stats["requests"] == 0 and stats["errors"] == 0
    assert {m: _ids(d) for m, d in devices.items()} == before

    expired = _client(FakeInternet(fail=True), cache_dir=tmp_path, ttl=-1)
    assert expired.get(vulns.KEV_URL, nvd=False) is None and expired.errors == 1


def test_without_internet_nothing_breaks(devices, capsys, caplog):
    stats = vulns.lookup_all(devices, _client(FakeInternet(fail=True)))
    assert stats["errors"] > 0 and not stats["kev_loaded"] and stats["cves"] == 0
    assert "No se pudo consultar" in caplog.text
    report.print_summary(report.build_summary(devices, {"cve_search": stats}))
    assert "consultas fallaron" in capsys.readouterr().out


@pytest.mark.parametrize("match, versions, expected", [
    ({"criteria": "cpe:2.3:o:x:y:1.2.3:*"}, {"1.2.3"}, True),
    ({"criteria": "cpe:2.3:o:x:y:1.2.3:*"}, {"1.2.4"}, False),
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionEndExcluding": "2.0"}, {"1.9.9"}, True),
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionEndExcluding": "2.0"}, {"2.0"}, False),
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionStartExcluding": "1.0",
      "versionEndIncluding": "1.5"}, {"1.5"}, True),
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionStartExcluding": "1.0"}, {"1.0"}, False),
    ({"criteria": "cpe:2.3:o:x:y:-:*"}, {"1.0"}, None),            # NVD no da versión
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionEndExcluding": "2.0"}, {"beta"}, None),
    ({"criteria": "cpe:2.3:o:x:y:*:*", "versionEndExcluding": "2.0"}, {"0.5", "3.0"}, True),
])
def test_version_in_range(match, versions, expected):
    assert vulns.version_in_range(match, versions) is expected


def test_nvd_rate_limit_and_api_key(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    waits = []
    net = FakeInternet()
    client = vulns.Client(cache_dir=None, fetch=net, sleep=waits.append)
    client.get(vulns.KEV_URL, nvd=False)
    client.get(vulns.NVD_CVES + "?a=1")
    client.get(vulns.NVD_CVES + "?a=2")
    assert len(waits) == 1 and 5 < waits[0] <= vulns.NVD_PAUSE      # KEV no cuenta para NVD
    assert net.headers == [{}, {}, {}]

    monkeypatch.setenv("NVD_API_KEY", "clave-de-prueba")
    waits.clear()
    client = vulns.Client(cache_dir=None, fetch=net, sleep=waits.append)
    client.get(vulns.NVD_CVES + "?a=1")
    client.get(vulns.NVD_CVES + "?a=2")
    assert waits and waits[0] <= vulns.NVD_PAUSE_KEY
    assert net.headers[-1] == {"apiKey": "clave-de-prueba"}


def test_only_https():
    with pytest.raises(ValueError):
        vulns._http_get_json("http://example.org/x.json", {})


def test_cli_with_and_without_cve(tmp_path, capsys, monkeypatch):
    from scapy.all import wrpcap
    import net_device_scanner
    pcap = tmp_path / "lab.pcap"
    wrpcap(str(pcap), lab.lab_packets())
    out_json = tmp_path / "o.json"

    assert net_device_scanner.main(["--pcap", str(pcap), "-o", str(out_json)]) == 0
    assert "no buscadas (usa --cve" in capsys.readouterr().out
    assert "cve_search" not in json.loads(out_json.read_text(encoding="utf-8"))["summary"]

    used = {}

    def fake_client(cache_dir):
        used["cache_dir"] = cache_dir
        return _client(FakeInternet())
    monkeypatch.setattr(net_device_scanner.vulns, "Client", fake_client)
    assert net_device_scanner.main(["--pcap", str(pcap), "--cve", "--cve-cache", str(tmp_path / "c"),
                                    "-o", str(out_json)]) == 0
    assert used["cache_dir"] == str(tmp_path / "c")
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["summary"]["cve_search"]["cves"] == 2
    sensor = next(d for d in data["devices"] if d["mac"] == lab.SENSOR)
    assert [c["id"] for c in sensor["cves"]] == ["CVE-1999-9001", "CVE-1999-9003"]
