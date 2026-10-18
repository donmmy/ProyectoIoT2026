"""
Hito 3 — Motor de heurísticas de identificación.

- Tabla de reglas puerto/protocolo -> servicio / tipo de dispositivo.
- Cada dispositivo recibe una o varias etiquetas candidatas con un nivel de
  confianza básico basado en el número de evidencias que coinciden.

Es una primera hipótesis para el analista, no un veredicto.
"""

import re
from dataclasses import dataclass, field


@dataclass
class Rule:
    label: str
    served_ports: set = field(default_factory=set)   # el dispositivo ofrece el servicio
    client_ports: set = field(default_factory=set)   # el dispositivo se conecta a ese puerto
    mdns: set = field(default_factory=set)           # servicios mDNS anunciados
    text: str | None = None      # regex sobre hostname, fabricante y banners
    domains: str | None = None   # regex sobre consultas DNS


RULES = [
    Rule("Cámara IP / NVR",
         served_ports={554, 8554, 37777, 34567, 8000},
         mdns={"_rtsp._tcp"},
         text=r"hikvision|dahua|ipcam|camera|cam\b|ezviz|reolink|axis|foscam|amcrest|wyze|xiongmai",
         domains=r"hik-connect|ezvizlife|dahua|p2p|reolink|wyzecam"),
    Rule("Chromecast / Smart TV",
         served_ports={8008, 8009, 8443},
         mdns={"_googlecast._tcp", "_androidtvremote2._tcp", "_airplay._tcp"},
         text=r"chromecast|google|bravia|samsung|lg ?electronics|roku|tv\b|android ?tv|vizio|hisense",
         domains=r"googlecast|samsungcloud|lgtvsdp|roku\.com|netflix"),
    Rule("Altavoz / asistente inteligente",
         served_ports={1400, 4070, 55442},
         mdns={"_spotify-connect._tcp", "_sonos._tcp", "_raop._tcp"},
         text=r"sonos|echo|alexa|amazon|google ?home|nest|homepod",
         domains=r"device-metrics-us\.amazon|alexa|sonos|avs-alexa"),
    Rule("Dispositivo MQTT (sensor/actuador IoT)",
         served_ports={1883, 8883},
         client_ports={1883, 8883},
         mdns={"_mqtt._tcp"},
         text=r"esp|espressif|tasmota|shelly|sonoff|zigbee|bridge"),
    Rule("Dispositivo CoAP (IoT restringido)",
         served_ports={5683, 5684},
         client_ports={5683, 5684},
         mdns={"_coap._udp"}),
    Rule("Enchufe / bombilla inteligente",
         served_ports={9999, 6668, 6667, 55443, 80},
         mdns={"_hap._tcp", "_shelly._tcp", "_hue._tcp"},
         text=(r"tuya|tp-?link|kasa|tapo|shelly|sonoff|philips|signify|yeelight|meross"
               r"|smart ?plug|bulb"),
         domains=r"tuya|tplinkcloud|iot\.meross|yeelight|meethue|shelly"),
    Rule("Dispositivo UPnP / multimedia",
         served_ports={1900, 49152, 2869},
         client_ports={1900},
         mdns={"_dlna._tcp"},
         text=r"upnp|dlna|media ?server"),
    Rule("Impresora",
         served_ports={631, 9100, 515},
         mdns={"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp"},
         text=r"printer|epson|canon|brother|hp ?inc|hewlett|laserjet|kyocera|xerox"),
    Rule("Router / gateway",
         served_ports={53, 67, 1900},
         text=(r"router|gateway|fritz|mikrotik|ubiquiti|tp-?link|netgear|asus|huawei|zte"
               r"|sagemcom|arris|askey|mitrastar")),
    Rule("NAS / servidor de ficheros",
         served_ports={445, 139, 2049, 5000, 5001, 548},
         mdns={"_smb._tcp", "_afpovertcp._tcp", "_nfs._tcp"},
         text=r"synology|qnap|nas\b|diskstation|truenas"),
    Rule("Dispositivo Apple",
         served_ports={62078, 7000},
         mdns={"_companion-link._tcp", "_apple-mobdev2._tcp", "_airplay._tcp", "_homekit._tcp"},
         text=r"apple|iphone|ipad|macbook|imac",
         domains=r"apple\.com|icloud\.com"),
    Rule("Equipo Windows",
         served_ports={135, 139, 445, 3389},
         text=r"msft|microsoft|desktop-|laptop-|windows",
         domains=r"windowsupdate|msftconnecttest|microsoft\.com"),
    Rule("Móvil Android",
         text=r"android|galaxy|xiaomi|redmi|oneplus|pixel|oppo|realme",
         domains=r"connectivitycheck\.gstatic|android\.clients"),
]

CONFIDENCE_LEVELS = ((3, "alta"), (2, "media"), (1, "baja"))


def _confidence(score):
    for threshold, name in CONFIDENCE_LEVELS:
        if score >= threshold:
            return name
    return "ninguna"


def evaluate_rule(rule, dev):
    """Devuelve la lista de evidencias que casan con la regla."""
    evidence = []
    for p in sorted(rule.served_ports & dev.ports_src):
        evidence.append(f"sirve puerto {p}")
    for p in sorted(rule.client_ports & dev.ports_dst):
        evidence.append(f"conecta a puerto {p}")
    for s in sorted(rule.mdns & dev.mdns_services):
        evidence.append(f"anuncia {s}")

    if rule.text:
        haystack = " | ".join(filter(None, [dev.hostname, dev.vendor, *dev.banners]))
        m = re.search(rule.text, haystack, re.IGNORECASE)
        if m:
            evidence.append(f"texto '{m.group(0)}'")

    if rule.domains:
        for d in sorted(dev.dns_queries):
            if re.search(rule.domains, d, re.IGNORECASE):
                evidence.append(f"consulta {d}")
                break
    return evidence


def classify(dev, max_labels=3):
    """Calcula y asigna dev.labels: [{label, score, confidence, evidence}]."""
    candidates = []
    for rule in RULES:
        ev = evaluate_rule(rule, dev)
        if ev:
            candidates.append({
                "label": rule.label,
                "score": len(ev),
                "confidence": _confidence(len(ev)),
                "evidence": ev,
            })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    dev.labels = candidates[:max_labels]
    return dev.labels


def classify_all(devices):
    for dev in devices.values():
        classify(dev)
    return devices
