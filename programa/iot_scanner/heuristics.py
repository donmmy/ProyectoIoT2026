"""
Hito 3 — Motor de heurísticas de identificación.

- Tabla de reglas puerto/protocolo -> servicio / tipo de dispositivo, en rules.json.
- Cada dispositivo recibe una o varias etiquetas candidatas con un nivel de
  confianza basado en la suma de los pesos de las evidencias que coinciden.

Pesos: una pista vale más cuanto más específica es del tipo de dispositivo
(idea del cociente de verosimilitud: P(pista | tipo) / P(pista | otro tipo)).
Un puerto propietario como el 37777 casi confirma una cámara Dahua; el 80 lo
sirve casi todo y apenas distingue. El peso solo afecta a la identificación:
las alertas de seguridad (report.py) siguen tratando el 80 o el 1900 igual.

Es una primera hipótesis para el analista, no un veredicto.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

WEIGHT_STRONG, WEIGHT_MEDIUM, WEIGHT_WEAK = 3, 2, 1

# Las reglas, los pesos y los umbrales viven en rules.json (propuesta de Qwen): se
# pueden ampliar o ajustar sin tocar el código, o cargar otro fichero con --rules.
DEFAULT_RULES_PATH = Path(__file__).with_name("rules.json")

log = logging.getLogger(__name__)

# Se rellenan al cargar el fichero de reglas (ver use_rules al final del bloque)
STRONG_PORTS: set = set()   # puertos propietarios o casi exclusivos de un tipo / fabricante
WEAK_PORTS: set = set()     # puertos que sirve casi cualquier cosa: dicen poco del tipo
MEDIUM_MDNS: set = set()    # servicios mDNS que anuncian muchos tipos distintos
CONFIDENCE_LEVELS: tuple = ()
RULES: list = []


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


# ----------------------------------------------------------------------
# Carga y validación de rules.json
# ----------------------------------------------------------------------

_PORT_FIELDS = ("served_ports", "client_ports")
_NAME_FIELDS = ("mdns", "wsd")
_REGEX_FIELDS = ("text", "domains")
_RULE_FIELDS = {"label", *_PORT_FIELDS, *_NAME_FIELDS, *_REGEX_FIELDS}


def _ports(value, where):
    if not isinstance(value, list) or not all(isinstance(p, int) and 0 < p < 65536 for p in value):
        raise ValueError(f"{where}: debe ser una lista de puertos (1-65535)")
    return set(value)


def _names(value, where):
    if not isinstance(value, list) or not all(isinstance(n, str) and n for n in value):
        raise ValueError(f"{where}: debe ser una lista de textos")
    return set(value)


def _rule_from_dict(d, i):
    where = f"regla {i + 1}"
    if not isinstance(d, dict):
        raise ValueError(f"{where}: debe ser un objeto")
    unknown = set(d) - _RULE_FIELDS
    if unknown:   # una errata ("servedports") no debe ignorarse en silencio
        raise ValueError(f"{where}: campos desconocidos {sorted(unknown)}")
    label = d.get("label")
    if not isinstance(label, str) or not label.strip():
        raise ValueError(f"{where}: falta 'label'")
    where = f"regla '{label}'"
    kwargs = {"label": label}
    for k in _PORT_FIELDS:
        if k in d:
            kwargs[k] = _ports(d[k], f"{where}, {k}")
    for k in _NAME_FIELDS:
        if k in d:
            kwargs[k] = _names(d[k], f"{where}, {k}")
    for k in _REGEX_FIELDS:
        if k in d:
            if not isinstance(d[k], str) or not d[k]:
                raise ValueError(f"{where}, {k}: debe ser una expresión regular")
            try:
                re.compile(d[k])
            except re.error as e:
                raise ValueError(f"{where}, {k}: expresión regular no válida ({e})") from None
            kwargs[k] = d[k]
    return Rule(**kwargs)


def load_rules(path=None):
    """Lee y valida un fichero de reglas. Devuelve (rules, weights, confidence_levels)."""
    path = Path(path) if path else DEFAULT_RULES_PATH
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list) or not data["rules"]:
        raise ValueError(f"{path}: falta la lista 'rules'")
    w = data.get("weights", {})
    weights = {
        "strong_ports": _ports(w.get("strong_ports", []), "weights.strong_ports"),
        "weak_ports": _ports(w.get("weak_ports", []), "weights.weak_ports"),
        "medium_mdns": _names(w.get("medium_mdns", []), "weights.medium_mdns"),
    }
    levels = data.get("confidence_levels", [])
    try:
        levels = tuple(sorted(((int(x["min_score"]), str(x["label"])) for x in levels), reverse=True))
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"{path}: confidence_levels mal formado") from None
    if not levels:
        raise ValueError(f"{path}: faltan confidence_levels")
    rules = [_rule_from_dict(d, i) for i, d in enumerate(data["rules"])]
    return rules, weights, levels


def use_rules(path=None):
    """Activa un fichero de reglas (por defecto rules.json) para classify()."""
    global RULES, STRONG_PORTS, WEAK_PORTS, MEDIUM_MDNS, CONFIDENCE_LEVELS
    rules, weights, levels = load_rules(path)
    RULES, CONFIDENCE_LEVELS = rules, levels
    STRONG_PORTS, WEAK_PORTS = weights["strong_ports"], weights["weak_ports"]
    MEDIUM_MDNS = weights["medium_mdns"]
    log.debug("%d reglas cargadas de %s", len(RULES), path or DEFAULT_RULES_PATH)
    return RULES


use_rules()


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
