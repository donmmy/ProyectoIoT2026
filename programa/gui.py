#!/usr/bin/env python3
"""
gui.py — Interfaz gráfica (tkinter) del escáner de dispositivos IoT.

Hace lo mismo que net_device_scanner.py pero sin comandos: elegir modo,
interfaz y tiempos, lanzar el análisis y ver dispositivos, alertas y resumen.
Exporta a JSON/CSV con los mismos módulos que la CLI.

USO LEGAL: solo en redes propias o con autorización explícita.

    python gui.py          (la captura en vivo necesita administrador/root)
"""

import ctypes
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    from scapy.all import conf
except ImportError:
    # Con pythonw no hay consola: el aviso tiene que salir en una ventana
    msg = "Falta scapy. Instálalo con: pip install -r requirements.txt"
    print(f"[!] {msg}")
    try:
        _r = tk.Tk()
        _r.withdraw()
        messagebox.showerror("Escáner IoT", msg)
    except tk.TclError:
        pass
    sys.exit(1)

import net_device_scanner as cli
from iot_scanner import heuristics, report, sniffer

MODES = {
    "arp+sniff": "ARP scan + escucha pasiva",
    "sniff-only": "Solo escucha pasiva",
    "arp-only": "Solo ARP scan",
    "pcap": "Analizar un fichero .pcap",
}
AUTO_IFACE = "(automática)"
EXAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "ejemplos")
SEVERITY_COLORS = {"ALTA": "#f8d7da", "MEDIA": "#fff3cd", "BAJA": "#e2e3e5"}


# ----------------------------------------------------------------------
# Lógica sin interfaz (testeable)
# ----------------------------------------------------------------------

def is_admin():
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def npcap_ok():
    """En Windows Scapy necesita Npcap para capturar; en Linux/Mac no aplica."""
    return os.name != "nt" or bool(getattr(conf, "use_pcap", False))


def list_interfaces():
    """[(etiqueta visible, nombre para scapy)] con las interfaces que tienen IP."""
    items = []
    try:
        for i in conf.ifaces.values():
            ip = getattr(i, "ip", "") or ""
            if not ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            items.append((f"{i.name} — {i.description} ({ip})", i.name))
    except Exception:  # sin Npcap o sin permisos: solo queda la opción automática
        return items
    return items


def build_argv(mode, iface=None, network=None, seconds=30, arp_timeout=3, pcap=None):
    """Traduce las opciones de la ventana a argumentos de la CLI."""
    argv = ["-t", str(int(seconds)), "--arp-timeout", str(int(arp_timeout))]
    if mode == "pcap":
        if not pcap:
            raise ValueError("Elige un fichero .pcap")
        return argv + ["--pcap", pcap]
    if iface:
        argv += ["-i", iface]
    if network:
        argv += ["-n", network]
    if mode == "sniff-only":
        argv.append("--sniff-only")
    elif mode == "arp-only":
        argv.append("--no-sniff")
    return argv


def run_analysis(argv):
    """Ejecuta el mismo flujo que la CLI y devuelve (devices, summary)."""
    args = cli.parse_args(argv)
    if args.pcap:
        devices = sniffer.sniff_pcap(args.pcap)
        meta = {"mode": "pcap", "pcap": args.pcap}
    else:
        devices, meta = cli.run_live(args)
    heuristics.classify_all(devices)
    return devices, report.build_summary(devices, meta)


class _QueueWriter:
    """Redirige los print() del análisis al registro de la ventana."""

    def __init__(self, q):
        self.q = q

    def write(self, text):
        if text:
            self.q.put(("log", text))

    def flush(self):
        pass


# ----------------------------------------------------------------------
# Ventana
# ----------------------------------------------------------------------

class ScannerApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.master = master
        self.queue = queue.Queue()
        self.devices = {}
        self.summary = None
        self.worker = None
        self.started_at = 0
        self.expected = 0

        master.title("Escáner de dispositivos IoT")
        master.geometry("1150x720")
        master.minsize(900, 560)
        self.pack(fill="both", expand=True)

        self._build_config()
        self._build_results()
        self._build_footer()
        self._on_mode_change()
        self.after(100, self._poll_queue)

    # ---------------- construcción ----------------

    def _build_config(self):
        box = ttk.LabelFrame(self, text="Configuración", padding=8)
        box.pack(fill="x")

        self.mode = tk.StringVar(value="arp+sniff")
        modes = ttk.Frame(box)
        modes.grid(row=0, column=0, columnspan=6, sticky="w", pady=(0, 6))
        for key, text in MODES.items():
            ttk.Radiobutton(modes, text=text, value=key, variable=self.mode,
                            command=self._on_mode_change).pack(side="left", padx=(0, 14))

        ttk.Label(box, text="Interfaz:").grid(row=1, column=0, sticky="w")
        self.ifaces = list_interfaces()
        self.iface = ttk.Combobox(box, state="readonly", width=60,
                                  values=[AUTO_IFACE] + [label for label, _ in self.ifaces])
        self.iface.current(0)
        self.iface.grid(row=1, column=1, columnspan=3, sticky="we", padx=4)

        ttk.Label(box, text="Red (CIDR):").grid(row=1, column=4, sticky="e")
        self.network = ttk.Entry(box, width=20)
        self.network.grid(row=1, column=5, sticky="w", padx=4)
        ttk.Label(box, text="vacío = autodetectar", foreground="gray").grid(row=2, column=5, sticky="w", padx=4)

        ttk.Label(box, text="Escucha (s):").grid(row=2, column=0, sticky="w", pady=4)
        self.seconds = tk.IntVar(value=30)
        self.seconds_box = ttk.Spinbox(box, from_=5, to=3600, increment=5, width=8, textvariable=self.seconds)
        self.seconds_box.grid(row=2, column=1, sticky="w", padx=4)

        ttk.Label(box, text="Timeout ARP (s):").grid(row=2, column=2, sticky="e")
        self.arp_timeout = tk.IntVar(value=3)
        self.arp_box = ttk.Spinbox(box, from_=1, to=30, width=6, textvariable=self.arp_timeout)
        self.arp_box.grid(row=2, column=3, sticky="w", padx=4)

        ttk.Label(box, text="Fichero .pcap:").grid(row=3, column=0, sticky="w")
        self.pcap = ttk.Entry(box)
        self.pcap.grid(row=3, column=1, columnspan=3, sticky="we", padx=4)
        self.pcap_btn = ttk.Button(box, text="Examinar…", command=self._choose_pcap)
        self.pcap_btn.grid(row=3, column=4, sticky="w")

        self.start_btn = ttk.Button(box, text="▶ Iniciar análisis", command=self._start)
        self.start_btn.grid(row=3, column=5, sticky="e", padx=4)
        box.columnconfigure(3, weight=1)

        self.admin_note = ttk.Label(box, foreground="#a15c00")
        self.admin_note.grid(row=4, column=0, columnspan=6, sticky="w", pady=(4, 0))

    def _build_results(self):
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, pady=8)

        # Dispositivos: tabla + detalle
        dev_tab = ttk.Frame(self.tabs)
        self.tabs.add(dev_tab, text="Dispositivos")
        pane = ttk.PanedWindow(dev_tab, orient="vertical")
        pane.pack(fill="both", expand=True)

        cols = ("ip", "mac", "vendor", "hostname", "tipo", "conf", "pkts", "alertas")
        heads = ("IP", "MAC", "Fabricante", "Hostname", "Tipo probable", "Confianza", "Paquetes", "Alertas")
        widths = (110, 130, 170, 140, 250, 80, 70, 60)
        table_frame = ttk.Frame(pane)
        self.tree = self._make_tree(table_frame, cols, heads, widths)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(table_frame, weight=3)

        self.detail = tk.Text(pane, height=10, wrap="word", font=("Consolas", 9), state="disabled")
        pane.add(self.detail, weight=2)

        # Alertas
        alert_tab = ttk.Frame(self.tabs)
        self.tabs.add(alert_tab, text="Alertas")
        self.alerts = self._make_tree(alert_tab, ("sev", "dev", "mac", "port", "msg"),
                                      ("Severidad", "Dispositivo", "MAC", "Puerto", "Motivo"),
                                      (80, 130, 140, 60, 600))
        for sev, color in SEVERITY_COLORS.items():
            self.alerts.tag_configure(sev, background=color)

        # Resumen y registro
        self.summary_text = self._make_text_tab("Resumen")
        self.log = self._make_text_tab("Registro")

    def _make_tree(self, parent, cols, heads, widths):
        tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        for c, h, w in zip(cols, heads, widths):
            tree.heading(c, text=h, command=lambda c=c, t=tree: self._sort_tree(t, c, False))
            tree.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return tree

    def _make_text_tab(self, title):
        frame = ttk.Frame(self.tabs)
        self.tabs.add(frame, text=title)
        text = tk.Text(frame, wrap="word", font=("Consolas", 9), state="disabled")
        sb = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        return text

    def _build_footer(self):
        foot = ttk.Frame(self)
        foot.pack(fill="x")
        self.progress = ttk.Progressbar(foot, mode="determinate", length=260)
        self.progress.pack(side="left")
        self.status = ttk.Label(foot, text="Listo.")
        self.status.pack(side="left", padx=8)
        self.csv_btn = ttk.Button(foot, text="Exportar CSV…", command=self._export_csv, state="disabled")
        self.csv_btn.pack(side="right")
        self.json_btn = ttk.Button(foot, text="Exportar JSON…", command=self._export_json, state="disabled")
        self.json_btn.pack(side="right", padx=6)

    # ---------------- eventos ----------------

    def _on_mode_change(self):
        mode = self.mode.get()
        live = mode != "pcap"
        for w in (self.iface, self.network, self.arp_box):
            w.configure(state=("readonly" if w is self.iface else "normal") if live else "disabled")
        self.seconds_box.configure(state="normal" if mode in ("arp+sniff", "sniff-only") else "disabled")
        if mode == "arp-only":
            self.arp_box.configure(state="normal")
        if mode == "sniff-only":
            self.arp_box.configure(state="disabled")
        self.pcap.configure(state="disabled" if live else "normal")
        self.pcap_btn.configure(state="disabled" if live else "normal")

        if live and not npcap_ok():
            self.admin_note.configure(text="⚠ No se detecta Npcap: instálalo desde https://npcap.com para "
                                           "capturar en vivo. El modo .pcap funciona sin él.")
        elif live and not is_admin():
            self.admin_note.configure(text="⚠ La captura en vivo necesita ejecutar como administrador. "
                                           "El modo .pcap funciona sin permisos.")
        else:
            self.admin_note.configure(text="")

    def _choose_pcap(self):
        initial = os.path.normpath(EXAMPLES_DIR) if os.path.isdir(EXAMPLES_DIR) else None
        path = filedialog.askopenfilename(title="Elegir captura", initialdir=initial,
                                          filetypes=[("Capturas", "*.pcap *.pcapng"), ("Todos", "*.*")])
        if path:
            self.pcap.delete(0, "end")
            self.pcap.insert(0, path)

    def _selected_iface(self):
        idx = self.iface.current()
        return self.ifaces[idx - 1][1] if idx > 0 else None

    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        mode = self.mode.get()
        try:
            argv = build_argv(mode, self._selected_iface(), self.network.get().strip() or None,
                              self.seconds.get(), self.arp_timeout.get(), self.pcap.get().strip() or None)
        except (ValueError, tk.TclError) as e:
            messagebox.showerror("Opciones no válidas", str(e) or "Revisa los números introducidos.")
            return
        if mode != "pcap" and not messagebox.askokcancel(
                "Uso legal", "Vas a escanear/escuchar la red.\n\n"
                             "Hazlo solo en redes propias o con autorización explícita.\n¿Continuar?"):
            return

        self._clear_results()
        self.start_btn.configure(state="disabled")
        self.json_btn.configure(state="disabled")
        self.csv_btn.configure(state="disabled")
        self.status.configure(text="Analizando…")
        self.tabs.select(3)  # Registro
        self.started_at = time.time()
        self.expected = 0 if mode == "pcap" else (
            self.arp_timeout.get() + (0 if mode == "arp-only" else self.seconds.get()))
        if self.expected:
            self.progress.configure(mode="determinate", maximum=self.expected, value=0)
        else:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)

        self.worker = threading.Thread(target=self._work, args=(argv,), daemon=True)
        self.worker.start()

    def _work(self, argv):
        old = sys.stdout
        sys.stdout = _QueueWriter(self.queue)
        try:
            self.queue.put(("done", run_analysis(argv)))
        except PermissionError:
            self.queue.put(("error", "Necesitas permisos de administrador para capturar paquetes."))
        except SystemExit:
            self.queue.put(("error", "Opciones no válidas (revisa tiempos y red)."))
        except Exception as e:
            self.queue.put(("error", f"{type(e).__name__}: {e}"))
        finally:
            sys.stdout = old

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "log":
                    self._append(self.log, payload)
                elif kind == "done":
                    self._finish(*payload)
                elif kind == "error":
                    self._fail(payload)
        except queue.Empty:
            pass
        if self.worker and self.worker.is_alive() and self.expected:
            elapsed = time.time() - self.started_at
            self.progress.configure(value=min(elapsed, self.expected))
            self.status.configure(text=f"Analizando… {int(elapsed)}/{self.expected} s")
        self.after(100, self._poll_queue)

    def _stop_progress(self):
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.start_btn.configure(state="normal")

    def _fail(self, msg):
        self._stop_progress()
        self.status.configure(text="Error.")
        self._append(self.log, f"[!] {msg}\n")
        messagebox.showerror("Error en el análisis", msg)

    def _finish(self, devices, summary):
        self._stop_progress()
        self.devices, self.summary = devices, summary
        self.show_results(devices, summary)
        self.json_btn.configure(state="normal")
        self.csv_btn.configure(state="normal")
        self.status.configure(text=f"{summary['device_count']} dispositivos, "
                                   f"{len(summary['alerts'])} alertas.")
        self.tabs.select(0)

    # ---------------- resultados ----------------

    def _clear_results(self):
        for t in (self.tree, self.alerts):
            t.delete(*t.get_children())
        for t in (self.detail, self.summary_text, self.log):
            self._set_text(t, "")

    def show_results(self, devices, summary):
        alerts_by_mac = {}
        for a in summary["alerts"]:
            alerts_by_mac[a["mac"]] = alerts_by_mac.get(a["mac"], 0) + 1

        self.tree.delete(*self.tree.get_children())
        for d in sorted(devices.values(), key=report._sort_key):
            best = d.labels[0] if d.labels else {}
            # Dispositivos solo IPv6 (Matter/Thread): se muestra su primera IPv6
            ip = d.ip or (sorted(d.ipv6)[0] if d.ipv6 else "-")
            self.tree.insert("", "end", iid=d.mac, values=(
                ip, d.mac, d.vendor, d.hostname or "-",
                best.get("label", "Sin identificar"), best.get("confidence", "-"),
                d.packet_count, alerts_by_mac.get(d.mac, 0) or ""))

        self.alerts.delete(*self.alerts.get_children())
        for a in summary["alerts"]:
            self.alerts.insert("", "end", tags=(a["severity"],),
                               values=(a["severity"], a["device"], a["mac"], a["port"], a["message"]))
        self.tabs.tab(1, text=f"Alertas ({len(summary['alerts'])})")

        self._set_text(self.summary_text, self._summary_text(summary))

    @staticmethod
    def _summary_text(s):
        lines = [f"Generado: {s.get('generated_at', '')}",
                 f"Modo: {s.get('mode', '-')}" + (f"   Interfaz: {s['iface']}" if s.get("iface") else "")
                 + (f"   Red: {s['network']}" if s.get("network") else ""),
                 "",
                 f"Dispositivos: {s['device_count']}  (identificados: {s['identified_count']})",
                 "", "Protocolos más comunes:"]
        lines += [f"   {p:<12} {n}" for p, n in s["top_protocols"]] or ["   (ninguno)"]
        lines += ["", "Tipos de dispositivo:"]
        lines += [f"   {t:<45} {n}" for t, n in s["device_types"]] or ["   (ninguno)"]
        lines += ["", f"Alertas: {len(s['alerts'])}"]
        for sev in ("ALTA", "MEDIA", "BAJA"):
            n = sum(1 for a in s["alerts"] if a["severity"] == sev)
            if n:
                lines.append(f"   {sev:<6} {n}")
        lines += ["", "La identificación es heurística: es una hipótesis para el analista, no un veredicto."]
        return "\n".join(lines)

    def _on_select(self, _event=None):
        sel = self.tree.selection()
        dev = self.devices.get(sel[0]) if sel else None
        if not dev:
            return
        d = dev.to_dict()
        lines = [f"{d['ip'] or '-'}   {d['mac']}   {d['vendor']}   hostname: {d['hostname'] or '-'}",
                 f"origen: {d['source']}   paquetes: {d['packet_count']}", ""]
        if dev.labels:
            lines.append("Etiquetas candidatas:")
            for lab in dev.labels:
                lines.append(f"  • {lab['label']}  — confianza {lab['confidence']} (puntos {lab['score']})")
                lines += [f"      - {e}" for e in lab["evidence"]]
        else:
            lines.append("Sin etiquetas: no casa con ninguna regla.")
        lines.append("")
        for key, title in (("protocols", "Protocolos"), ("ports_src", "Puertos que sirve"),
                           ("ports_dst", "Puertos a los que conecta"), ("mdns_services", "Servicios mDNS"),
                           ("dns_queries", "Consultas DNS"), ("tls_sni", "TLS (SNI)"),
                           ("ntp_servers", "Servidores NTP"), ("ipv6", "IPv6"), ("banners", "Banners")):
            values = d.get(key)
            if values:
                lines.append(f"{title}: {', '.join(map(str, values))}")
        self._set_text(self.detail, "\n".join(lines))

    def _sort_tree(self, tree, col, reverse):
        rows = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(item):
            v = item[0]
            return (0, int(v)) if str(v).isdigit() else (1, str(v).lower())
        rows.sort(key=key, reverse=reverse)
        for i, (_, k) in enumerate(rows):
            tree.move(k, "", i)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    # ---------------- exportar ----------------

    def _export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", initialfile="informe.json",
                                            filetypes=[("JSON", "*.json")])
        if path:
            self._export(lambda: report.export_json(self.devices, self.summary, path), path)

    def _export_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="informe.csv",
                                            filetypes=[("CSV", "*.csv")])
        if path:
            self._export(lambda: report.export_csv(self.devices, path), path)

    def _export(self, fn, path):
        try:
            old, sys.stdout = sys.stdout, _QueueWriter(self.queue)
            try:
                fn()
            finally:
                sys.stdout = old
            self.status.configure(text=f"Guardado en {path}")
        except OSError as e:
            messagebox.showerror("No se pudo guardar", str(e))

    # ---------------- utilidades ----------------

    @staticmethod
    def _set_text(widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.configure(state="disabled")

    @staticmethod
    def _append(widget, text):
        widget.configure(state="normal")
        widget.insert("end", text)
        widget.see("end")
        widget.configure(state="disabled")


def main():
    root = tk.Tk()
    try:
        ttk.Style(root).theme_use("vista" if os.name == "nt" else "clam")
    except tk.TclError:
        pass
    ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
