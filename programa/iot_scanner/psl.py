"""
Dominio registrable (eTLD+1) con la Public Suffix List (propuesta de Kiro, 2026-11-19).

Un "sufijo público" es la parte de un dominio bajo la que cualquiera puede registrar
nombres: "com", pero también "co.uk", "com.es" o "github.io". El dominio registrable
(eTLD+1) es ese sufijo más una etiqueta: "api.eu.hik-connect.com" -> "hik-connect.com",
"news.bbc.co.uk" -> "bbc.co.uk". Quedarse con "las dos últimas etiquetas" fallaría con
"co.uk" (daría "co.uk" para todos los dominios británicos).

Se usa al anonimizar: el dominio base basta como evidencia (dice con qué nube habla el
dispositivo), y el resto del nombre puede delatar al usuario (cuentas, ciudades, IDs).

Fichero: public_suffix_list.dat de https://publicsuffix.org (Mozilla, licencia MPL-2.0),
copiado en el repositorio para funcionar sin internet. Actualizarlo de vez en cuando:
    curl -o programa/iot_scanner/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat

Reglas del formato: "com" (normal), "*.ck" (comodín: cualquier etiqueta bajo ck es un
sufijo) y "!www.ck" (excepción al comodín). Si no casa ninguna, vale la regla por defecto
"*" (la última etiqueta es el sufijo).
"""

import logging
from pathlib import Path

log = logging.getLogger(__name__)

PSL_PATH = Path(__file__).with_name("public_suffix_list.dat")

_RULES = None   # (normales, comodines, excepciones), se cargan la primera vez


def _to_ascii(rule):
    """Las reglas de dominios internacionales vienen en Unicode; el tráfico, en punycode."""
    try:
        return rule.encode("idna").decode("ascii")
    except UnicodeError:
        return rule


def load(path=None):
    normal, wildcard, exception = set(), set(), set()
    with open(path or PSL_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                exception.add(_to_ascii(rule[1:]))
            elif rule.startswith("*."):
                wildcard.add(_to_ascii(rule[2:]))
            else:
                normal.add(_to_ascii(rule))
    return normal, wildcard, exception


def _rules():
    global _RULES
    if _RULES is None:
        try:
            _RULES = load()
        except OSError as e:   # sin fichero: queda la regla por defecto (última etiqueta)
            log.warning("No se pudo leer la Public Suffix List (%s); se usa la última etiqueta", e)
            _RULES = (set(), set(), set())
    return _RULES


def registrable_domain(domain):
    """Dominio registrable (eTLD+1); el propio dominio si ya es un sufijo o no tiene puntos."""
    if not domain:
        return domain
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) < 2:
        return domain
    normal, wildcard, exception = _rules()
    start = len(labels) - 1                         # regla por defecto "*": la última etiqueta
    for i in range(len(labels)):                    # de la más larga a la más corta
        candidate = ".".join(labels[i:])
        if candidate in exception:                  # "!www.ck": el sufijo es "ck"
            start = i + 1
            break
        if candidate in normal or (i + 1 < len(labels) and ".".join(labels[i + 1:]) in wildcard):
            start = i
            break
    if start == 0:                                  # el dominio entero es un sufijo público
        return ".".join(labels)
    return ".".join(labels[start - 1:])
