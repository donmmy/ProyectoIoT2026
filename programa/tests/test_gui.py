import gc

import pytest
from scapy.all import wrpcap

import gui
from tests import lab_packets as lab


@pytest.fixture(autouse=True)
def _free_tk_in_main_thread():
    # tkinter solo admite liberar sus variables desde el hilo principal: se recogen aquí
    # y no más tarde desde el hilo de otro test (p. ej. la captura en vivo simulada)
    yield
    gc.collect()


@pytest.fixture
def pcap(tmp_path):
    path = tmp_path / "lab.pcap"
    wrpcap(str(path), lab.lab_packets())
    return str(path)


def test_build_argv_modes():
    assert gui.build_argv("pcap", pcap="x.pcap")[-2:] == ["--pcap", "x.pcap"]
    assert "--sniff-only" in gui.build_argv("sniff-only")
    assert "--no-sniff" in gui.build_argv("arp-only")
    argv = gui.build_argv("arp+sniff", iface="Wi-Fi", network="192.168.1.0/24", seconds=60)
    assert argv[:2] == ["-t", "60"] and ["-i", "Wi-Fi"] == argv[4:6] and "-n" in argv
    with pytest.raises(ValueError):
        gui.build_argv("pcap")


def test_run_analysis_pcap(pcap):
    devices, summary = gui.run_analysis(gui.build_argv("pcap", pcap=pcap))
    assert summary["mode"] == "pcap"
    assert summary["device_count"] == len(devices) >= 5
    assert devices[lab.CAM].labels


def test_window_shows_results(pcap):
    try:
        root = gui.tk.Tk()
    except gui.tk.TclError:
        pytest.skip("sin pantalla disponible")
    root.withdraw()
    try:
        app = gui.ScannerApp(root)
        devices, summary = gui.run_analysis(gui.build_argv("pcap", pcap=pcap))
        app._finish(devices, summary)

        assert len(app.tree.get_children()) == len(devices)
        assert len(app.alerts.get_children()) == len(summary["alerts"])
        assert str(app.json_btn["state"]) == "normal"
        assert str(app.stop_btn["state"]) == "disabled"   # solo activo durante la escucha
        app._stop()
        assert app.stop_event.is_set()

        app.tree.selection_set(lab.CAM)
        app._on_select()
        detail = app.detail.get("1.0", "end")
        assert "Cámara IP" in detail and "554" in detail
        assert "Dispositivos:" in app.summary_text.get("1.0", "end")

        app.mode.set("pcap")
        app._on_mode_change()
        assert str(app.pcap["state"]) == "normal"
        assert str(app.network["state"]) == "disabled"
    finally:
        root.destroy()
