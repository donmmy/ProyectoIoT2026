"""
Hito 4 — Exportación e informe.

- Tabla por consola y exportación a JSON/CSV.
- Resumen final: recuento de dispositivos, protocolos más comunes y alertas
  simples (puertos sensibles expuestos, protocolos en claro).
- Vulnerabilidades conocidas (--cve) en una sección aparte: una alerta es un hecho
  observado en el tráfico; un CVE depende de cuánto sabemos del modelo y su versión.
"""

import csv
import dataclasses
import hashlib
import hmac
import json
import logging
import re
import secrets
from collections import Counter
from datetime import datetime, timezone

log = logging.getLogger(__name__)

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

# Tipos UPnP anunciados por SSDP que merecen revisión: tipo -> (severidad, motivo).
# Un IGD (Internet Gateway Device) deja que cualquier equipo de la LAN abra puertos del
# router hacia internet sin autenticarse (lo usan botnets y malware para exponer servicios)
SENSITIVE_UPNP = {
    "InternetGatewayDevice": ("MEDIA", "UPnP IGD anunciado: cualquier equipo de la LAN puede abrir "
                                       "puertos del router hacia internet sin autenticación"),
    "WANIPConnection": ("MEDIA", "UPnP WANIPConnection anunciado: permite pedir redirecciones de "
                                 "puertos al router (AddPortMapping)"),
    "WANPPPConnection": ("MEDIA", "UPnP WANPPPConnection anunciado: permite pedir redirecciones de "
                                  "puertos al router (AddPortMapping)"),
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
        for t in sorted(dev.upnp_types & SENSITIVE_UPNP.keys()):
            sev, msg = SENSITIVE_UPNP[t]
            alerts.append({"severity": sev, "device": who, "mac": dev.mac, "port": 1900, "message": msg})
        if dev.eui64_global:
            alerts.append({"severity": "BAJA", "device": who, "mac": dev.mac, "port": None,
                           "message": "IPv6 global con la MAC dentro (EUI-64): se le puede seguir de una "
                                      "red a otra; usar direcciones temporales (RFC 4941/7217)"})
        # Un CVE solo pasa a alerta si es tan seguro y urgente como un Telnet abierto:
        # explotado activamente (KEV) y con la versión anunciada dentro del rango vulnerable
        for c in dev.cves:
            if c["kev"] and c["certainty"] == "modelo+firmware":
                alerts.append({"severity": "ALTA", "device": who, "mac": dev.mac, "port": None,
                               "message": f"{c['id']} explotado activamente (CISA KEV) "
                                          "y la versión anunciada es vulnerable"})
    alerts.sort(key=lambda a: (SEVERITY_ORDER[a["severity"]], a["device"]))
    return alerts


def build_cve_list(devices):
    """Todos los CVE en una lista plana (para la consola, la GUI y el resumen)."""
    rows = [{"device": dev.ip or dev.mac, "mac": dev.mac, **c}
            for dev in devices.values() for c in dev.cves]
    rank = {"modelo+firmware": 0, "modelo": 1, "fabricante": 2}
    rows.sort(key=lambda r: (rank.get(r["certainty"], 3), not r["kev"], -(r["cvss"] or 0)))
    return rows


def certainty_label(certainty):
    """El nivel fabricante se muestra siempre como lo que es: una suposición."""
    return "fabricante (suposición)" if certainty == "fabricante" else certainty


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
        "cves": build_cve_list(devices),
    }


# ----------------------------------------------------------------------
# Anonimización de informes (propuesta de Qwen: "Privacy by Design")
# ----------------------------------------------------------------------
#
# Se sustituyen por seudónimos los datos que identifican un equipo o a su dueño:
# MAC, IP, IPv6, hostname, nombre ONVIF, interfaz de captura y ruta del .pcap.
# Se conservan los datos técnicos que hacen falta para analizar (fabricante,
# puertos, protocolos, servicios, dominios, tipo y alertas).
#
# No basta con un hash, ni con sal: solo hay 2^32 IPv4 y unos pocos millones de
# MACs por fabricante, así que un SHA-256 se revierte probándolas todas. Se usa
# HMAC-SHA256 con una clave aleatoria por informe que no se guarda en ninguna
# parte: el mismo dispositivo recibe el mismo seudónimo en todo el informe (JSON,
# CSV y alertas), pero nadie, ni el propio autor, puede deshacerlo.

PSEUDONYM_HEX = 12   # 48 bits: sin colisiones prácticas en una red local


def make_pseudonymizer(key=None):
    """Devuelve pseudo(tipo, valor) -> "tipo-1a2b3c4d5e6f" (None se queda en None)."""
    key = key or secrets.token_bytes(32)

    def pseudo(kind, value):
        if not value:
            return value
        digest = hmac.new(key, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
        return f"{kind}-{digest[:PSEUDONYM_HEX]}"
    return pseudo


# Claves TXT de mDNS que se conservan al anonimizar (lista blanca: minimización). Las
# demás se quitan porque suelen identificar al equipo o a su dueño: id, deviceid, mac,
# serial... o nombres que pone el usuario, como fn=Salón de Oscar o note=Despacho.
SAFE_TXT_KEYS = {"md", "model", "ty", "product", "usb_mdl", "app", "fw_version", "fw_ver",
                 "fw_id", "firmware", "version", "ver", "osvers", "srcvers", "txtvers", "ve",
                 "ca", "st", "platform", "board", "arch", "gen", "pdl", "tls", "c#", "s#",
                 "ci", "ff", "sf"}


def _keep_txt(entry):
    return entry.partition("=")[0] in SAFE_TXT_KEYS


def _anonymize_banner(banner, pseudo):
    # El nombre ONVIF lo pone el usuario ("HIKVISION Entrada") y puede delatar dónde está
    if banner.startswith("ONVIF:name="):
        return "ONVIF:name=" + pseudo("name", banner[len("ONVIF:name="):])
    return banner


def anonymize(devices, meta=None, key=None):
    """Copia anonimizada de (devices, meta); los originales no se modifican."""
    pseudo = make_pseudonymizer(key)
    out = {}
    for d in devices.values():
        new = dataclasses.replace(
            d,
            mac=pseudo("mac", d.mac), ip=pseudo("ip", d.ip), hostname=pseudo("host", d.hostname),
            ipv6={pseudo("ip6", a) for a in d.ipv6},
            banners={_anonymize_banner(b, pseudo) for b in d.banners},
            mdns_txt={t for t in d.mdns_txt if _keep_txt(t)},
            labels=[dict(c) for c in d.labels], cves=[dict(c) for c in d.cves])
        out[new.mac] = new
    meta = dict(meta or {})
    if meta.get("iface"):
        meta["iface"] = pseudo("iface", meta["iface"])
    if meta.get("pcap"):
        # La ruta lleva el usuario del equipo. Se separa por \ y por / a mano: os.path solo
        # entiende el separador del sistema y en Linux dejaría entera una ruta de Windows
        meta["pcap"] = re.split(r"[\\/]", meta["pcap"])[-1]
    meta["anonymized"] = True
    return out, meta


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
        port = a["port"] if a["port"] is not None else "-"
        print(f"   [{a['severity']:<5}] {a['device']:<16} puerto {port:<5} {a['message']}")
    print_cves(summary)
    print()


def print_cves(summary):
    stats = summary.get("cve_search")
    if not stats:
        print("\nVulnerabilidades conocidas: no buscadas (usa --cve; necesita internet)")
        return
    cves = summary.get("cves", [])
    print(f"\nVulnerabilidades conocidas ({len(cves)}, de NVD; certeza modelo+firmware > modelo > fabricante):")
    if not cves:
        print("   (ninguna)")
    for c in cves:
        kev = "KEV" if c["kev"] else ""
        score = c["cvss"] if c["cvss"] is not None else "-"
        print(f"   {c['id']:<16} {score!s:<5} {kev:<4} {certainty_label(c['certainty']):<24} "
              f"{c['device']:<16} {c['product']}")
    print(f"   Por modelo: {stats['searched']} dispositivos; "
          f"por librería (banner): {stats.get('by_software', 0)}; "
          f"solo por fabricante: {stats['by_vendor']} "
          f"(CVE recientes de su hardware, no confirmados); sin datos: {stats['not_searched']}; "
          f"{stats['discarded_by_version']} CVE descartados por versión.")
    if stats.get("errors"):
        print(f"   [!] {stats['errors']} consultas fallaron: el resultado puede estar incompleto.")


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
    log.info("JSON guardado en %s", path)


CSV_FIELDS = ["ip", "mac", "vendor", "hostname", "source", "packet_count",
              "tipo_probable", "confianza", "evidencias", "protocols",
              "ports_src", "ports_dst", "mdns_services", "banners",
              "ipv6", "tls_sni", "ntp_servers", "wsd_types", "models", "firmware", "mdns_txt",
              "upnp_types", "software", "dhcp_fingerprint", "eui64_global", "cves"]


def _csv_safe(value):
    """Evita inyección de fórmulas al abrir el CSV en Excel/LibreOffice."""
    s = str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@") else s


def _cve_cell(c):
    return f"{c['id']} ({c['cvss']}, {certainty_label(c['certainty'])}{', KEV' if c['kev'] else ''})"


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
                "models": " | ".join(sorted(d.models)),
                "firmware": " | ".join(sorted(d.firmware)),
                "mdns_txt": " | ".join(sorted(d.mdns_txt)),
                "upnp_types": " ".join(sorted(d.upnp_types)),
                "software": " ".join(sorted(d.software)),
                "dhcp_fingerprint": " | ".join(sorted(d.dhcp_fingerprint)),
                "eui64_global": "sí" if d.eui64_global else "",
                "cves": " | ".join(_cve_cell(c) for c in d.cves),
            }
            w.writerow({k: _csv_safe(v) for k, v in row.items()})
    log.info("CSV guardado en %s", path)
