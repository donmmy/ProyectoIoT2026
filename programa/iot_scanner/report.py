"""
Hito 4 — Exportación e informe.

- Tabla por consola y exportación a JSON/CSV.
- Resumen final: recuento de dispositivos, protocolos más comunes y alertas
  simples (puertos sensibles expuestos, protocolos en claro).
"""

import csv
import json
from collections import Counter
from datetime import datetime, timezone

# Puertos servidos por un dispositivo que merecen revisión: puerto -> (severidad, motivo)
SENSITIVE_SERVED = {
    23:   ("ALTA",  "Telnet expuesto (credenciales en claro, vector típico de Mirai)"),
    2323: ("ALTA",  "Telnet alternativo expuesto (típico de botnets IoT)"),
    21:   ("MEDIA", "FTP expuesto (credenciales en claro)"),
    5900: ("MEDIA", "VNC expuesto"),
    3389: ("MEDIA", "RDP expuesto"),
    445:  ("MEDIA", "SMB expuesto"),
    161:  ("MEDIA", "SNMP expuesto (community por defecto habitual)"),
    1883: ("MEDIA", "Broker MQTT sin TLS"),
    5683: ("BAJA",  "CoAP sin DTLS"),
    554:  ("BAJA",  "RTSP expuesto (revisar autenticación del stream)"),
    1900: ("BAJA",  "UPnP activo (puede abrir puertos en el router)"),
    3702: ("BAJA",  "WS-Discovery/ONVIF activo (anuncia modelo; revisar autenticación ONVIF)"),
    80:   ("BAJA",  "Interfaz web sin HTTPS"),
}

# Puertos a los que se conecta un dispositivo enviando datos sin cifrar
SENSITIVE_CLIENT = {
    1883: ("MEDIA", "Publica en MQTT sin TLS"),
    23:   ("MEDIA", "Usa Telnet saliente"),
    5683: ("BAJA",  "Habla CoAP sin DTLS"),
}

SEVERITY_ORDER = {"ALTA": 0, "MEDIA": 1, "BAJA": 2}


def _top_label(dev):
    if not dev.labels:
        return "-"
    best = dev.labels[0]
    return f"{best['label']} ({best['confidence']})"


def _sort_key(dev):
    try:
        return tuple(int(x) for x in (dev.ip or "999.999.999.999").split("."))
    except ValueError:
        return (999,)


# ----------------------------------------------------------------------
# Alertas y resumen
# ----------------------------------------------------------------------

def build_alerts(devices):
    alerts = []
    for dev in devices.values():
        who = dev.ip or dev.mac
        for port in sorted(dev.ports_src):
            if port in SENSITIVE_SERVED:
                sev, msg = SENSITIVE_SERVED[port]
                alerts.append({"severity": sev, "device": who, "mac": dev.mac,
                               "port": port, "message": msg})
        for port in sorted(dev.ports_dst):
            if port in SENSITIVE_CLIENT:
                sev, msg = SENSITIVE_CLIENT[port]
                alerts.append({"severity": sev, "device": who, "mac": dev.mac,
                               "port": port, "message": msg})
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a["severity"]], a["device"]))
    return alerts


def build_summary(devices, meta=None):
    protocols = Counter(p for d in devices.values() for p in d.protocols)
    types = Counter(d.labels[0]["label"] if d.labels else "Sin identificar"
                    for d in devices.values())
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **(meta or {}),
        "device_count": len(devices),
        "identified_count": sum(1 for d in devices.values() if d.labels),
        "top_protocols": protocols.most_common(10),
        "device_types": types.most_common(),
        "alerts": build_alerts(devices),
    }


# ----------------------------------------------------------------------
# Consola
# ----------------------------------------------------------------------

def print_table(devices):
    cols = f"{'IP':<16}{'MAC':<19}{'Fabricante':<22}{'Pkts':<7}{'Hostname':<20}{'Tipo probable'}"
    line = "=" * 110
    print("\n" + line + "\n" + cols + "\n" + line)
    for d in sorted(devices.values(), key=_sort_key):
        print(f"{str(d.ip or '-'):<16}{d.mac:<19}{d.vendor[:20]:<22}{d.packet_count:<7}"
              f"{(d.hostname or '-')[:18]:<20}{_top_label(d)}")
        protos = ", ".join(sorted(d.protocols))
        if protos:
            print(f"{'':<16}  protocolos: {protos}")
        if d.ports_src:
            print(f"{'':<16}  sirve:      {', '.join(map(str, sorted(d.ports_src)))}")
    print(line)


def print_summary(summary):
    print(f"\nTotal dispositivos: {summary['device_count']} "
          f"(identificados: {summary['identified_count']})")

    if summary["top_protocols"]:
        print("Protocolos más comunes: " +
              ", ".join(f"{p} ({n})" for p, n in summary["top_protocols"]))

    if summary["device_types"]:
        print("Tipos de dispositivo:")
        for t, n in summary["device_types"]:
            print(f"   - {t}: {n}")

    alerts = summary["alerts"]
    print(f"\nAlertas ({len(alerts)}):")
    if not alerts:
        print("   (ninguna)")
    for a in alerts:
        print(f"   [{a['severity']:<5}] {a['device']:<16} puerto {a['port']:<5} {a['message']}")
    print()


# ----------------------------------------------------------------------
# Ficheros
# ----------------------------------------------------------------------

def export_json(devices, summary, path):
    data = {
        "summary": summary,
        "devices": [d.to_dict() for d in sorted(devices.values(), key=_sort_key)],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[*] JSON guardado en {path}")


CSV_FIELDS = ["ip", "mac", "vendor", "hostname", "source", "packet_count",
              "tipo_probable", "confianza", "evidencias", "protocols",
              "ports_src", "ports_dst", "mdns_services", "banners",
              "ipv6", "tls_sni", "ntp_servers", "wsd_types"]


def _csv_safe(value):
    """Evita inyección de fórmulas al abrir el CSV en Excel/LibreOffice."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def export_csv(devices, path):
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, delimiter=";")
        w.writeheader()
        for d in sorted(devices.values(), key=_sort_key):
            best = d.labels[0] if d.labels else {}
            row = {
                "ip": d.ip or "", "mac": d.mac, "vendor": d.vendor,
                "hostname": d.hostname or "", "source": d.source,
                "packet_count": d.packet_count,
                "tipo_probable": best.get("label", ""),
                "confianza": best.get("confidence", ""),
                "evidencias": " | ".join(best.get("evidence", [])),
                "protocols": " ".join(sorted(d.protocols)),
                "ports_src": " ".join(map(str, sorted(d.ports_src))),
                "ports_dst": " ".join(map(str, sorted(d.ports_dst))),
                "mdns_services": " ".join(sorted(d.mdns_services)),
                "banners": " | ".join(sorted(d.banners)),
                "ipv6": " ".join(sorted(d.ipv6)),
                "tls_sni": " ".join(sorted(d.tls_sni)),
                "ntp_servers": " ".join(sorted(d.ntp_servers)),
                "wsd_types": " ".join(sorted(d.wsd_types)),
            }
            w.writerow({k: _csv_safe(v) for k, v in row.items()})
    print(f"[*] CSV guardado en {path}")
