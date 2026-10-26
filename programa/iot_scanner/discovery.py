"""
Hito 1 — Descubrimiento de dispositivos.

- ARP scan sobre la red/CIDR indicada, con detección automática de interfaz.
- Resolución de fabricante por MAC contra la base OUI.
- Si el ARP no obtiene respuestas (aislamiento de clientes), el llamador
  hace fallback a modo solo-escucha.
"""

import ipaddress
import logging

from scapy.all import ARP, Ether, conf, get_if_addr, srp

from .device import Device

BROADCAST = "ff:ff:ff:ff:ff:ff"

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Interfaz y red
# ----------------------------------------------------------------------

def is_unspecified(ip):
    """0.0.0.0 / :: = "sin dirección" (cliente DHCP sin IP, ruta sin gateway)."""
    try:
        return ipaddress.ip_address(ip).is_unspecified
    except ValueError:
        return False


def _netmask_for(iface, ip):
    """Busca la máscara de la ruta directamente conectada (sin gateway) a la interfaz."""
    try:
        for net, mask, gw, r_iface, r_addr, _ in conf.route.routes:
            if str(r_iface) == str(iface) and r_addr == ip and is_unspecified(gw) and net != 0:
                return mask
    except (AttributeError, TypeError, ValueError):
        # Tabla de rutas de Scapy no disponible o con otro formato: se usará /24
        return None
    return None


def guess_network(iface=None):
    """Deduce interfaz y red local (CIDR) a partir de la interfaz activa."""
    iface = iface or conf.iface
    ip = get_if_addr(iface)
    if not ip or is_unspecified(ip):
        raise RuntimeError(f"No se pudo obtener IP de la interfaz {iface}")

    mask = _netmask_for(iface, ip)
    prefix = bin(mask).count("1") if mask else 24
    # Evitamos barrer redes enormes por accidente (/16 = 65k ARPs)
    prefix = max(prefix, 24)
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return iface, str(net)


def validate_network(network):
    """Valida el CIDR y devuelve su forma normalizada (lanza ValueError si no vale)."""
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4:
        raise ValueError("ARP solo funciona sobre IPv4")
    return str(net)


# ----------------------------------------------------------------------
# Fabricante por OUI
# ----------------------------------------------------------------------

def _load_oui_db():
    try:
        return conf.manufdb
    except Exception:
        return None


OUI_DB = _load_oui_db()


def is_locally_administered(mac):
    """Bit U/L activo -> MAC aleatoria (móviles modernos), no tiene OUI real."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor_from_mac(mac):
    if is_locally_administered(mac):
        return "MAC aleatoria/privada"
    if not OUI_DB:
        return "desconocido"
    try:
        name = OUI_DB._get_manuf(mac)
    except Exception:
        return "desconocido"
    # Scapy devuelve la propia MAC si no la encuentra
    if not name or name.lower() == mac.lower():
        return "desconocido"
    return name


# ----------------------------------------------------------------------
# ARP scan
# ----------------------------------------------------------------------

DEFAULT_ARP_INTERVAL = 0.01   # s entre ARPs: un /24 tarda ~2,5 s más en salir


def arp_scan(network, iface, timeout=3, retry=1, inter=DEFAULT_ARP_INTERVAL):
    """
    Envía ARP broadcast a toda la red y devuelve {mac: Device}.

    `inter` espacia los ARPs (rate limiting, propuesta de Qwen) para no soltar toda
    la ráfaga de golpe: más "educado" con la red y con dispositivos IoT sencillos
    que pueden perder respuestas si les llegan muchas peticiones seguidas.
    0 = sin pausa (como antes).
    """
    hosts = ipaddress.ip_network(network, strict=False).num_addresses
    log.info("Lanzando ARP scan sobre %s (iface=%s, %s s entre ARPs)...", network, iface, inter)
    log.debug("Envío estimado: %.1f s + %s s de espera de respuestas", hosts * inter, timeout)
    pkt = Ether(dst=BROADCAST) / ARP(pdst=network)
    answered, _ = srp(pkt, timeout=timeout, iface=iface, retry=retry, inter=inter, verbose=False)

    devices = {}
    for _, resp in answered:
        mac = resp[ARP].hwsrc.lower()
        devices[mac] = Device(mac=mac, ip=resp[ARP].psrc,
                              vendor=vendor_from_mac(mac), source="arp")
    log.info("%d dispositivos respondieron al ARP scan.", len(devices))
    return devices
