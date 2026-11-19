"""
Búsqueda de vulnerabilidades conocidas (CVE) — opcional (--cve) y con internet.

Fuentes:
- NVD (NIST), API 2.0: diccionario CPE (nombres normalizados de productos) y CVE.
- CISA KEV: catálogo de CVE que se están explotando de verdad.

Por cada dispositivo:
1. Producto CPE. Se busca el modelo anunciado (TXT de mDNS) en el diccionario CPE y solo
   se aceptan productos cuyo nombre aparece tal cual en el modelo: "hl-l2350dw" casa con
   "Brother HL-L2350DW series", pero "hl-l2350" o "dcp-1610w" no. Algunos programas que
   corren en el propio dispositivo se reconocen por su servicio mDNS (ESPHome).
2. CVE de NVD que afectan a ese producto (`virtualMatchString`). En IoT lo normal es que
   NVD diga "firmware de X (vulnerable) sobre el hardware X", así que se pregunta por los dos.
3. Nivel de certeza de cada CVE:
   - "modelo+firmware": la versión anunciada cae dentro del rango vulnerable.
   - "modelo": no se sabe la versión, o NVD no da rango (afecta al modelo sin más detalle).
   - Si NVD da rango y la versión anunciada queda fuera, el CVE se descarta.
4. KEV marca los CVE explotados activamente. KEV no se usa para buscar por fabricante:
   "Google" tiene decenas de entradas de Chrome/Chromium que nada tienen que ver con un
   Chromecast.
5. Nivel "fabricante" (una suposición): si del dispositivo solo sabemos el fabricante (OUI),
   o su modelo no está en el diccionario CPE, se listan los CVE **recientes** (2 años) de
   **hardware** de ese fabricante (`cpe:2.3:h:fabricante`), como mucho 5 y los más graves
   primero. No dicen que este aparato sea vulnerable, sino "este fabricante ha tenido estos
   fallos hace poco en sus equipos". Se pide solo hardware porque `o:` mete el sistema
   operativo (Google: cientos de CVE de Android en cuatro meses). Nunca generan alertas.

Privacidad: a internet solo salen el modelo (texto que el propio dispositivo anuncia a toda
la red), el nombre del fabricante y nombres CPE; nunca MAC, IP, hostname ni nombres que
ponga el usuario.

Las respuestas se guardan en una caché local (24 h) para no repetir consultas: NVD sin
clave admite 5 peticiones cada 30 s; con clave, 50. La clave se lee de la variable
NVD_API_KEY o del fichero programa/nvd_api_key.txt (en .gitignore), solo se envía a NVD
y nunca se escribe en el registro.
"""

import hashlib
import json
import logging
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

NVD_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "iot-scanner (proyecto academico)"   # genérico: sin datos del usuario

CACHE_DIR = Path.home() / ".cache" / "iot_scanner"
NVD_KEY_FILE = Path(__file__).resolve().parent.parent / "nvd_api_key.txt"
CACHE_TTL = 24 * 3600
HTTP_TIMEOUT = 30
MAX_RESPONSE_BYTES = 32 * 1024 * 1024   # KEV ocupa ~2 MB; un tope evita respuestas enormes
NVD_PAUSE = 6.0        # sin clave: 5 peticiones / 30 s
NVD_PAUSE_KEY = 0.6    # con clave: 50 peticiones / 30 s
CVES_PER_PAGE = 200
SUMMARY_CHARS = 160

# Software reconocible por su servicio mDNS: (fabricante, producto) en CPE.
# Su versión (TXT version=) es la del software, así que sirve para el rango.
SERVICE_PRODUCTS = {
    "_esphomelib._tcp": ("esphome", "esphome"),
}

# Librerías que el sniffer saca de los banners (SSDP SERVER, vendor class de DHCP) con su
# nombre CPE. Su versión es la de la librería, así que el rango se compara con ella.
SOFTWARE_CPE = {
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "libupnp": ("libupnp_project", "libupnp"),
    "portable sdk for upnp devices": ("libupnp_project", "libupnp"),   # nombre largo de libupnp
    "busybox": ("busybox", "busybox"),
    "udhcp": ("busybox", "busybox"),       # el cliente DHCP de BusyBox lleva su versión
    "dhcpcd": ("dhcpcd_project", "dhcpcd"),
}

# Palabras del modelo que no están en los nombres CPE y harían fallar la búsqueda
MODEL_NOISE = {"series", "printer", "inc", "ltd", "co"}

CERTAINTY_ORDER = {"modelo+firmware": 0, "modelo": 1, "fabricante": 2}

# Nivel fabricante: solo lo reciente y lo más grave, para que sea una pista y no una lista
VENDOR_RECENT_DAYS = 730
VENDOR_MAX_CVES = 5

# Palabras del nombre OUI que no son la marca ("Hangzhou Hikvision Digital Technology" -> hikvision)
VENDOR_NOISE = {
    "inc", "incorporated", "co", "ltd", "llc", "corp", "corporation", "company", "limited", "gmbh",
    "ag", "sa", "srl", "bv", "plc", "the", "and", "of", "technology", "technologies", "tech",
    "digital", "electronics", "electronic", "electric", "communications", "communication",
    "network", "networks", "systems", "system", "smart", "industries", "industrial",
    "international", "group", "holdings", "trading", "hangzhou", "shenzhen", "guangzhou", "beijing",
    "shanghai", "xiamen", "zhejiang", "dongguan", "zhuhai", "suzhou", "nanjing", "wuhan", "chengdu",
    "taiwan", "china", "japan", "korea",
}
UNKNOWN_VENDORS = ("desconocido", "MAC aleatoria")


# ----------------------------------------------------------------------
# Acceso a internet con caché y ritmo de peticiones
# ----------------------------------------------------------------------

def _http_get_json(url, headers):
    if not url.startswith("https://"):
        raise ValueError("solo se admiten URL https")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    # Bandit B310 (urlopen con esquemas file:, ftp:...): aquí solo llegan URL https de este módulo
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # nosec B310
        return json.loads(resp.read(MAX_RESPONSE_BYTES))


def read_api_key(path=None):
    """Clave de NVD: la variable NVD_API_KEY o, si no está, la primera línea útil del fichero."""
    key = os.environ.get("NVD_API_KEY", "").strip()
    if key:
        return key
    try:
        lines = Path(path or NVD_KEY_FILE).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    return next((s for s in map(str.strip, lines) if s and not s.startswith("#")), None)


class Client:
    """Hace las peticiones (o las saca de la caché) respetando el límite de NVD."""

    def __init__(self, cache_dir=CACHE_DIR, api_key=None, fetch=None, sleep=time.sleep,
                 ttl=CACHE_TTL):
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.api_key = api_key if api_key is not None else read_api_key()
        self.fetch = fetch or _http_get_json
        self.sleep = sleep
        self.ttl = ttl
        self.requests = 0
        self.errors = 0
        self._last_nvd = None

    def get(self, url, nvd=True):
        data = self._cache_read(url)
        if data is not None:
            return data
        if nvd:
            self._throttle()
        headers = {"apiKey": self.api_key} if nvd and self.api_key else {}
        try:
            data = self.fetch(url, headers)
        except (OSError, ValueError) as e:   # sin red, timeout, HTTP 4xx/5xx, JSON roto
            self.errors += 1
            log.warning("No se pudo consultar %s: %s", urllib.parse.urlsplit(url).netloc, e)
            return None
        self.requests += 1
        self._cache_write(url, data)
        return data

    def _throttle(self):
        pause = NVD_PAUSE_KEY if self.api_key else NVD_PAUSE
        if self._last_nvd is not None:
            wait = pause - (time.monotonic() - self._last_nvd)
            if wait > 0:
                self.sleep(wait)
        self._last_nvd = time.monotonic()

    def _cache_path(self, url):
        return self.cache_dir / (hashlib.sha256(url.encode()).hexdigest() + ".json")

    def _cache_read(self, url):
        if not self.cache_dir:
            return None
        try:
            entry = json.loads(self._cache_path(url).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if entry.get("url") != url or time.time() - entry.get("fetched", 0) > self.ttl:
            return None
        return entry.get("data")

    def _cache_write(self, url, data):
        if not self.cache_dir:
            return
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            self._cache_path(url).write_text(
                json.dumps({"url": url, "fetched": time.time(), "data": data}), encoding="utf-8")
        except OSError as e:   # caché no disponible: se sigue sin ella
            log.debug("No se pudo escribir la caché: %s", e)


# ----------------------------------------------------------------------
# Paso 1: del modelo al producto CPE
# ----------------------------------------------------------------------

def _cpe_parts(cpe):
    """'cpe:2.3:o:brother:hl-l2350dw_firmware:1.0:...' -> ('o', 'brother', 'hl-l2350dw_firmware', '1.0')."""
    p = cpe.split(":")
    return tuple(p[2:6]) if len(p) >= 6 else (None, None, None, None)


def _norm_model(model):
    words = [w for w in re.split(r"[\s_()]+", model.lower()) if w and w not in MODEL_NOISE]
    return "_".join(words)


def _appears_in(product, norm_model):
    # Delimitado por algo que no sea letra o número: "hl-l2350" no casa con "hl-l2350dw"
    return re.search(rf"(?<![a-z0-9]){re.escape(product)}(?![a-z0-9])", norm_model) is not None


def find_products(model, client):
    """Productos CPE del modelo: {(fabricante, producto): tiene_cpe_de_firmware}."""
    norm = _norm_model(model)
    if len(norm) < 4:
        return {}
    query = urllib.parse.urlencode({"keywordSearch": norm.replace("_", " "), "resultsPerPage": 100})
    data = client.get(f"{NVD_CPES}?{query}") or {}
    found = {}
    for item in data.get("products", []):
        cpe = item.get("cpe", {})
        if cpe.get("deprecated"):
            continue
        part, vendor, product, _ = _cpe_parts(cpe.get("cpeName", ""))
        if not product:
            continue
        base = product[:-len("_firmware")] if product.endswith("_firmware") else product
        if len(base) < 4 or base == vendor or not _appears_in(base, norm):
            continue
        found[(vendor, base)] = found.get((vendor, base), False) or product != base
    if not found:
        return {}
    # Si hay varios, el más largo es el más concreto ("hl-l2350dw" mejor que "hl")
    longest = max(len(b) for _, b in found)
    return {k: v for k, v in found.items() if len(k[1]) == longest}


def device_products(dev, client):
    products = {}
    for model in sorted(dev.models):
        products.update(find_products(model, client))
    for service in dev.mdns_services:
        if service in SERVICE_PRODUCTS:
            products.setdefault(SERVICE_PRODUCTS[service], False)
    return products


def device_software(dev):
    """Librerías con versión (banner SSDP, DHCP): {(fabricante, producto): {versiones}}."""
    found = {}
    for entry in dev.software:
        name, _, version = entry.rpartition("/")
        if name in SOFTWARE_CPE and version:
            found.setdefault(SOFTWARE_CPE[name], set()).add(version)
    return found


# ----------------------------------------------------------------------
# Paso 2 y 3: CVE del producto y nivel de certeza
# ----------------------------------------------------------------------

def _vkey(version):
    nums = re.findall(r"\d+", version or "")
    return tuple(int(n) for n in nums) if nums else None


def version_in_range(match, versions):
    """True/False si alguna versión anunciada está (o no) en el rango de la entrada CPE;
    None si NVD no da versión o la nuestra no se puede comparar."""
    keys = [k for k in map(_vkey, versions) if k is not None]
    if not keys:
        return None
    exact = _cpe_parts(match.get("criteria", ""))[3]
    if exact not in (None, "*", "-"):
        target = _vkey(exact)
        return None if target is None else target in keys
    bounds = {k: _vkey(match.get(k)) for k in ("versionStartIncluding", "versionStartExcluding",
                                               "versionEndIncluding", "versionEndExcluding")}
    if not any(bounds.values()):
        return None
    checks = {"versionStartIncluding": lambda v, b: v >= b, "versionStartExcluding": lambda v, b: v > b,
              "versionEndIncluding": lambda v, b: v <= b, "versionEndExcluding": lambda v, b: v < b}
    return any(all(checks[k](v, b) for k, b in bounds.items() if b is not None) for v in keys)


def assess(cve, products, firmware):
    """Certeza del CVE para este dispositivo, o None si la versión anunciada lo descarta."""
    names = {f"{v}:{p}" for v, p in products} | {f"{v}:{p}_firmware" for v, p in products}
    entries = [m for conf in cve.get("configurations", []) for node in conf.get("nodes", [])
               for m in node.get("cpeMatch", [])
               if m.get("vulnerable") and ":".join(_cpe_parts(m.get("criteria", ""))[1:3]) in names]
    if not firmware or not entries:
        # Sin versión, o nuestro modelo solo aparece como plataforma de otra cosa vulnerable
        return "modelo"
    verdicts = [version_in_range(m, firmware) for m in entries]
    if any(v is True for v in verdicts):
        return "modelo+firmware"
    if all(v is False for v in verdicts):
        return None
    return "modelo"


def _cvss(metrics):
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            m = next((i for i in items if i.get("type") == "Primary"), items[0])
            data = m.get("cvssData", {})
            return data.get("baseScore"), data.get("baseSeverity") or m.get("baseSeverity")
    return None, None


def _summary(cve):
    text = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()
    return text if len(text) <= SUMMARY_CHARS else text[:SUMMARY_CHARS - 1] + "…"


def product_cves(vendor, product, has_firmware_cpe, client):
    """CVE de NVD de un producto: {id: cve}. Se pregunta por el hardware y por su firmware."""
    patterns = [f"cpe:2.3:*:{vendor}:{product}"]
    if has_firmware_cpe:
        patterns.append(f"cpe:2.3:o:{vendor}:{product}_firmware")
    cves = {}
    for pattern in patterns:
        query = urllib.parse.urlencode({"virtualMatchString": pattern, "resultsPerPage": CVES_PER_PAGE})
        data = client.get(f"{NVD_CVES}?{query}") or {}
        if data.get("totalResults", 0) > CVES_PER_PAGE:
            log.warning("%s tiene más de %d CVE; solo se muestran los primeros", pattern, CVES_PER_PAGE)
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            if cve.get("id"):
                cves[cve["id"]] = cve
    return cves


def cpe_vendor(oui_vendor):
    """Marca del nombre OUI en minúsculas, como en CPE; None si no hay fabricante útil."""
    if not oui_vendor or oui_vendor.startswith(UNKNOWN_VENDORS):
        return None
    # Con guiones dentro: "Tp-Link" es tp-link en CPE, no "tp" + "link"
    for word in re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", oui_vendor.lower()):
        if len(word) >= 3 and not word.isdigit() and word not in VENDOR_NOISE:
            return word
    return None


def vendor_recent_cves(vendor, client, now=None):
    """CVE recientes de hardware del fabricante, los más graves primero: [(id, cve)]."""
    query = urllib.parse.urlencode({"virtualMatchString": f"cpe:2.3:h:{vendor}",
                                    "resultsPerPage": CVES_PER_PAGE})
    data = client.get(f"{NVD_CVES}?{query}") or {}
    if data.get("totalResults", 0) > CVES_PER_PAGE:
        log.warning("%s tiene más de %d CVE de hardware; solo se miran los primeros", vendor, CVES_PER_PAGE)
    now = now or time.time()
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now - VENDOR_RECENT_DAYS * 86400))
    recent = [v.get("cve", {}) for v in data.get("vulnerabilities", [])]
    recent = [c for c in recent if c.get("id") and c.get("published", "") >= since]
    recent.sort(key=lambda c: c.get("published", ""), reverse=True)        # a igual CVSS, el más nuevo
    recent.sort(key=lambda c: -(_cvss(c.get("metrics", {}))[0] or 0))
    return [(c["id"], c) for c in recent[:VENDOR_MAX_CVES]]


def load_kev(client):
    """IDs del catálogo KEV, o un conjunto vacío si no se pudo descargar."""
    data = client.get(KEV_URL, nvd=False) or {}
    return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}


# ----------------------------------------------------------------------
# Todo junto
# ----------------------------------------------------------------------

def _entry(cve_id, cve, kev, certainty, product):
    score, severity = _cvss(cve.get("metrics", {}))
    return {"id": cve_id, "cvss": score, "severity": severity, "kev": cve_id in kev,
            "certainty": certainty, "product": product, "published": cve.get("published", "")[:10],
            "summary": _summary(cve)}


def lookup_device(dev, client, kev, memo=None, now=None):
    """Rellena dev.cves. Devuelve (niveles usados, CVE descartados por versión); los niveles
    son "modelo" (modelo o software del dispositivo), "software" (librería de un banner) y
    "fabricante" (suposición)."""
    memo = {} if memo is None else memo
    products = device_products(dev, client) if dev.models or dev.mdns_services else {}
    # Qué buscar: (fabricante, producto, ¿hay CPE de firmware?, versiones, nivel, etiqueta)
    targets = [(v, p, fw, dev.firmware, "modelo", f"{v}:{p}") for (v, p), fw in sorted(products.items())]
    targets += [(v, p, False, versions, "software", f"{v}:{p} {'/'.join(sorted(versions))}")
                for (v, p), versions in sorted(device_software(dev).items())]
    found, discarded, levels = {}, 0, set()
    for vendor, product, has_fw, versions, level, label in targets:
        levels.add(level)
        if (vendor, product) not in memo:
            memo[(vendor, product)] = product_cves(vendor, product, has_fw, client)
        for cve_id, cve in memo[(vendor, product)].items():
            certainty = assess(cve, {(vendor, product)}, versions)
            if certainty is None:
                discarded += 1
                continue
            prev = found.get(cve_id)
            if prev and CERTAINTY_ORDER[prev["certainty"]] <= CERTAINTY_ORDER[certainty]:
                continue
            found[cve_id] = _entry(cve_id, cve, kev, certainty, label)

    # Sin producto CPE del propio aparato: suposición con lo reciente del fabricante. Una
    # librería (miniupnpd) no dice nada del hardware, así que no lo impide
    vendor = cpe_vendor(dev.vendor) if not products else None
    if vendor:
        levels.add("fabricante")
        if ("vendor", vendor) not in memo:
            memo[("vendor", vendor)] = vendor_recent_cves(vendor, client, now)
        for cve_id, cve in memo[("vendor", vendor)]:
            found.setdefault(cve_id, _entry(cve_id, cve, kev, "fabricante", f"{vendor}:* (hardware)"))

    dev.cves = sorted(found.values(), key=lambda c: (not c["kev"], CERTAINTY_ORDER[c["certainty"]],
                                                     -(c["cvss"] or 0), c["id"]))
    return levels, discarded


def lookup_all(devices, client=None, now=None):
    """Busca CVE para todos los dispositivos: por modelo o software y, si no, por fabricante."""
    client = client or Client()
    log.info("Buscando CVE en NVD y CISA KEV (solo se envían modelos y fabricantes, nunca MAC/IP). %s",
             "Con clave de NVD." if client.api_key else
             f"Sin clave de NVD cada consulta espera {NVD_PAUSE:.0f} s (ver nvd_api_key.txt).")
    kev = load_kev(client)
    stats = {"searched": 0, "by_software": 0, "by_vendor": 0, "not_searched": 0, "no_cpe": 0, "cves": 0,
             "kev": 0, "discarded_by_version": 0, "requests": 0, "errors": 0, "kev_loaded": bool(kev)}
    memo = {}
    for dev in devices.values():
        has_model = bool(dev.models or (dev.mdns_services & SERVICE_PRODUCTS.keys()))
        levels, discarded = lookup_device(dev, client, kev, memo, now)
        if "modelo" in levels:
            stats["searched"] += 1
        elif "fabricante" in levels:
            stats["by_vendor"] += 1
        elif not levels:
            stats["not_searched"] += 1
        if "software" in levels:
            stats["by_software"] += 1
        if has_model and "modelo" not in levels:
            stats["no_cpe"] += 1
        stats["discarded_by_version"] += discarded
        stats["cves"] += len(dev.cves)
        stats["kev"] += sum(1 for c in dev.cves if c["kev"])
    stats["requests"], stats["errors"] = client.requests, client.errors
    log.info("CVE: %d encontrados (%d en KEV): %d dispositivos por modelo, %d solo por fabricante "
             "(suposición), %d sin datos para buscar.",
             stats["cves"], stats["kev"], stats["searched"], stats["by_vendor"], stats["not_searched"])
    return stats
