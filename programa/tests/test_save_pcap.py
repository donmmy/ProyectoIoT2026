"""--save-pcap: guardar los paquetes de la escucha en vivo (para Wireshark o repetir con --pcap)."""

import threading

import pytest
from scapy.all import rdpcap

import gui
import net_device_scanner as cli
from iot_scanner import report, sniffer
from tests import lab_packets as lab
from tests.test_scanner import _FakeAsyncSniffer


@pytest.fixture
def fake_capture(monkeypatch):
    monkeypatch.setattr(sniffer, "AsyncSniffer", _FakeAsyncSniffer)


def test_saves_every_packet_and_reanalysis_matches(fake_capture, tmp_path, caplog):
    caplog.set_level("INFO", logger="iot_scanner")
    path = tmp_path / "captura.pcap"
    live = sniffer.sniff_live("lab0", 0.3, save_path=path)
    saved = rdpcap(str(path))
    assert len(saved) == len(lab.lab_packets())               # todos, como Wireshark
    offline = sniffer.sniff_pcap(str(path))                    # el mismo análisis desde el fichero
    assert offline.keys() == live.keys()
    assert all(offline[m].protocols == live[m].protocols for m in live)
    assert "dato sensible" in caplog.text and "Captura guardada" in caplog.text


def test_own_packets_are_saved_but_not_analysed(fake_capture, tmp_path):
    path = tmp_path / "captura.pcap"
    devs = sniffer.sniff_live("lab0", 0.3, ignore_macs=[lab.CAM], save_path=path)
    assert lab.CAM not in devs                                 # el análisis lo descarta...
    assert any(p.src == lab.CAM for p in rdpcap(str(path)))    # ...pero la captura lo guarda


def test_stop_early_keeps_the_file(fake_capture, tmp_path):
    path = tmp_path / "captura.pcap"
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    sniffer.sniff_live("lab0", 30, stop_event=stop, save_path=path)
    assert len(rdpcap(str(path))) == len(lab.lab_packets())


def test_error_closes_the_file(monkeypatch, tmp_path):
    class NoPermission(_FakeAsyncSniffer):
        fail_with = PermissionError("se necesita administrador")
    monkeypatch.setattr(sniffer, "AsyncSniffer", NoPermission)
    path = tmp_path / "captura.pcap"
    with pytest.raises(PermissionError):
        sniffer.sniff_live("lab0", 30, save_path=path)
    path.unlink()          # en Windows fallaría si el fichero hubiera quedado abierto


def test_without_save_path_nothing_is_written(fake_capture, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sniffer.sniff_live("lab0", 0.2)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("argv", [["--pcap", "x.pcap", "--save-pcap", "y.pcap"],
                                  ["--no-sniff", "--save-pcap", "y.pcap"]])
def test_cli_rejects_save_without_live_listening(argv):
    with pytest.raises(SystemExit):
        cli.parse_args(argv)


def test_cli_passes_path_and_meta(monkeypatch, tmp_path):
    seen = {}

    def fake_sniff_live(iface, seconds, devices, ignore_macs=(), stop_event=None, save_path=None):
        seen["save_path"] = save_path
        return devices
    monkeypatch.setattr(cli.sniffer, "sniff_live", fake_sniff_live)
    monkeypatch.setattr(cli, "get_if_hwaddr", lambda iface: "aa:aa:aa:aa:aa:aa")
    path = str(tmp_path / "lab.pcap")
    args = cli.parse_args(["-i", "lab0", "-n", "192.168.1.0/24", "--sniff-only", "-t", "1", "--save-pcap", path])
    _, meta = cli.run_live(args)
    assert seen["save_path"] == path and meta["saved_pcap"] == path

    args = cli.parse_args(["-i", "lab0", "-n", "192.168.1.0/24", "--sniff-only", "-t", "0", "--save-pcap", path])
    _, meta = cli.run_live(args)
    assert "saved_pcap" not in meta                            # sin escucha no hay captura


def test_anonymize_hides_the_path():
    _, meta = report.anonymize({}, {"saved_pcap": r"C:\Users\alguien\capturas\lab.pcap"})
    assert meta["saved_pcap"] == "lab.pcap"


def test_gui_argv():
    assert gui.build_argv("sniff-only", save_pcap="c.pcap")[-2:] == ["--save-pcap", "c.pcap"]
    assert "--save-pcap" in gui.build_argv("arp+sniff", save_pcap="c.pcap")
    assert "--save-pcap" not in gui.build_argv("arp-only", save_pcap="c.pcap")    # no hay escucha
    assert "--save-pcap" not in gui.build_argv("sniff-only")
