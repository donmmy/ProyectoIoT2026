"""Modelo de datos común: un dispositivo observado en la red."""

from dataclasses import dataclass, field

# Límite de elementos por conjunto para que un dispositivo ruidoso no infle la memoria
MAX_ITEMS = 64


@dataclass
class Device:
    mac: str
    ip: str | None = None
    vendor: str = "desconocido"
    hostname: str | None = None
    source: str = "arp"                            # "arp" o "pasivo"
    protocols: set = field(default_factory=set)
    ports_dst: set = field(default_factory=set)    # puertos a los que se conecta (cliente)
    ports_src: set = field(default_factory=set)    # puertos que sirve (servidor)
    dns_queries: set = field(default_factory=set)  # dominios que resuelve
    mdns_services: set = field(default_factory=set)  # p.ej. _googlecast._tcp
    banners: set = field(default_factory=set)      # SSDP SERVER, DHCP vendor class...
    packet_count: int = 0
    labels: list = field(default_factory=list)     # rellenado por heuristics

    def add(self, attr, value):
        """Añade a un conjunto respetando MAX_ITEMS."""
        s = getattr(self, attr)
        if value is not None and value != "" and (value in s or len(s) < MAX_ITEMS):
            s.add(value)

    def to_dict(self):
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "source": self.source,
            "packet_count": self.packet_count,
            "protocols": sorted(self.protocols),
            "ports_dst": sorted(self.ports_dst),
            "ports_src": sorted(self.ports_src),
            "dns_queries": sorted(self.dns_queries),
            "mdns_services": sorted(self.mdns_services),
            "banners": sorted(self.banners),
            "labels": self.labels,
        }
