"""
Hito 3 — Motor de heurísticas de identificación.

- Tabla de reglas puerto/protocolo -> servicio / tipo de dispositivo.
- Cada dispositivo recibe una o varias etiquetas candidatas con un nivel de
  confianza basado en la suma de los pesos de las evidencias que coinciden.

Pesos: una pista vale más cuanto más específica es del tipo de dispositivo
(idea del cociente de verosimilitud: P(pista | tipo) / P(pista | otro tipo)).
Un puerto propietario como el 37777 casi confirma una cámara Dahua; el 80 lo
sirve casi todo y apenas distingue. El peso solo afecta a la identificación:
las alertas de seguridad (report.py) siguen tratando el 80 o el 1900 igual.

Es una primera hipótesis para el analista, no un veredicto.
"""

import re
from dataclasses import dataclass, field

WEIGHT_STRONG, WEIGHT_MEDIUM, WEIGHT_WEAK = 3, 2, 1

# Puertos propietarios o casi exclusivos de un tipo / fabricante
STRONG_PORTS = {37777, 34567, 8009, 6668, 9999, 55443, 5540, 62078, 1400, 9100}
# Puertos que sirve casi cualquier cosa: dicen poco del tipo (sí del riesgo)
WEAK_PORTS = {80, 443, 1900, 5000, 5001, 8080, 8443, 49152}
# Servicios mDNS que anuncian muchos tipos distintos; el resto se consideran específicos
MEDIUM_MDNS = {"_airplay._tcp", "_raop._tcp", "_hap._tcp", "_dlna._tcp", "_smb._tcp",
               "_spotify-connect._tcp"}


def port_weight(port):
    if port in STRONG_PORTS:
        return WEIGHT_STRONG
    if port in WEAK_PORTS:
        return WEIGHT_WEAK
    return WEIGHT_MEDIUM


def mdns_weight(service):
    return WEIGHT_MEDIUM if service in MEDIUM_MDNS else WEIGHT_STRONG


@dataclass
class Rule:
    label: str
    served_ports: set = field(default_factory=set)   # el dispositivo ofrece el servicio
    client_ports: set = field(default_factory=set)   # el dispositivo se conecta a ese puerto
    mdns: set = field(default_factory=set)           # servicios mDNS anunciados
    text: str | None = None      # regex sobre hostname, banners y fabricante
    domains: str | None = None   # regex sobre consultas DNS y SNI de TLS
    wsd: set = field(default_factory=set)            # tipos WS-Discovery anunciados
    _text_re: re.Pattern | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        # Solo se acepta la coincidencia al principio de una palabra: "esp" casa con
        # "ESP_32AB" o "esp32-sensor" pero no con "despacho-pc". Por la derecha no se
        # limita para no perder nombres compuestos como "IPCamera".
        if self.text:
            self._text_re = re.compile(rf"(?<![a-z])(?:{self.text})", re.IGNORECASE)


RULES = [
    Rule("Cámara IP / NVR",
         served_ports={554, 8554, 37777, 34567, 8000},
         mdns={"_rtsp._tcp"},
         wsd={"NetworkVideoTransmitter"},
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
    Rule("Dispositivo Matter",
         served_ports={5540},
         mdns={"_matter._tcp", "_matterc._udp"},
         text=r"matter"),
    Rule("Border router Thread / controlador Matter",
         mdns={"_meshcop._udp", "_trel._udp", "_matterd._udp"},
         text=r"openthread|border ?router"),
    Rule("Dispositivo UPnP / multimedia",
         served_ports={1900, 49152, 2869},
         client_ports={1900},
         mdns={"_dlna._tcp"},
         text=r"upnp|dlna|media ?server"),
    Rule("Impresora",
         served_ports={631, 9100, 515},
         wsd={"PrintDeviceType", "ScanDeviceType"},
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
         wsd={"Computer"},
         text=r"msft|microsoft|desktop-|laptop-|windows",
         domains=r"windowsupdate|msftconnecttest|microsoft\.com"),
    Rule("Móvil Android",
         text=r"android|galaxy|xiaomi|redmi|oneplus|pixel|oppo|realme",
         domains=r"connectivitycheck\.gstatic|android\.clients"),
]

# Umbrales sobre la suma de pesos: una pista fuerte sola ya da "media";
# hacen falta al menos dos pistas (o una fuerte y otra) para "alta".
CONFIDENCE_LEVELS = ((5, "alta"), (3, "media"), (1, "baja"))


def _confidence(score):
    for threshold, name in CONFIDENCE_LEVELS:
        if score >= threshold:
            return name
    return "ninguna"


def evaluate_rule(rule, dev):
    """Devuelve las evidencias que casan con la regla como [(descripción, peso)]."""
    evidence = []
    served = rule.served_ports & dev.ports_src
    for p in sorted(served):
        evidence.append((f"sirve puerto {p}", port_weight(p)))
    # Un mismo puerto no cuenta dos veces: un SSDP 1900 -> 1900 es una sola pista
    for p in sorted((rule.client_ports & dev.ports_dst) - served):
        evidence.append((f"conecta a puerto {p}", port_weight(p)))
    for s in sorted(rule.mdns & dev.mdns_services):
        evidence.append((f"anuncia {s}", mdns_weight(s)))
    # El tipo WS-Discovery lo declara el propio dispositivo y es muy específico
    for t in sorted(rule.wsd & dev.wsd_types):
        evidence.append((f"WS-Discovery {t}", WEIGHT_STRONG))

    if rule._text_re:
        # Lo que el dispositivo dice de sí mismo (hostname, banners) pesa más que el
        # fabricante de la tarjeta de red: el fabricante no dice el tipo de dispositivo
        own = " | ".join(filter(None, [dev.hostname, *sorted(dev.banners)]))
        m = rule._text_re.search(own)
        if m:
            evidence.append((f"texto '{m.group(0)}'", WEIGHT_MEDIUM))
        else:
            m = rule._text_re.search(dev.vendor or "")
            if m:
                evidence.append((f"fabricante '{m.group(0)}'", WEIGHT_WEAK))

    if rule.domains:
        # Un dominio cuenta como una sola evidencia, venga de DNS o del SNI de TLS
        seen = [("consulta", d) for d in sorted(dev.dns_queries)] + \
               [("TLS a", d) for d in sorted(dev.tls_sni)]
        for how, d in seen:
            if re.search(rule.domains, d, re.IGNORECASE):
                evidence.append((f"{how} {d}", WEIGHT_STRONG))
                break
    return evidence


def classify(dev, max_labels=3):
    """Calcula y asigna dev.labels: [{label, score, confidence, evidence}]."""
    candidates = []
    for rule in RULES:
        ev = evaluate_rule(rule, dev)
        if ev:
            score = sum(w for _, w in ev)
            candidates.append({
                "label": rule.label,
                "score": score,
                "confidence": _confidence(score),
                "evidence": [f"{desc} (+{w})" for desc, w in ev],
            })
    candidates.sort(key=lambda c: c["score"], reverse=True)
    dev.labels = candidates[:max_labels]
    return dev.labels


def classify_all(devices):
    for dev in devices.values():
        classify(dev)
    return devices
