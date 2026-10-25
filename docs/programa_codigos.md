# programa_codigos.md — Dónde se usa la teoría en el código

Mapa de cada concepto teórico a la línea de código que lo aplica, hito a hito.
Las rutas son relativas a `programa/`. Las líneas corresponden a
la rama `hitos-1-4` tras añadir NTP, TLS (SNI) y Matter/Thread; si el código cambia, revisarlas.

Fichero vivo: se completa a medida que se revisa cada hito.

---

## Hito 1 — Descubrimiento (`iot_scanner/discovery.py`)

**Idea:** ¿quién hay en la red? ARP pregunta por cada IP; la respuesta trae la MAC;
el OUI de la MAC da el fabricante.

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Red = IP + máscara (CIDR) | `_netmask_for(iface, ip)` | `discovery.py:23` | Busca en la tabla de rutas la ruta directamente conectada (sin gateway, `gw == "0.0.0.0"`, y no la ruta por defecto, `net != 0`) |
| Prefijo = bits a 1 de la máscara | `bin(mask).count("1")` | `discovery.py:42` | `255.255.255.0` → 24 |
| Seguridad operativa: no barrer redes enormes | `prefix = max(prefix, 24)` | `discovery.py:44` | Nunca escanea más de un /24 automáticamente (un /16 serían 65.534 ARPs) |
| Normalizar el CIDR | `ipaddress.ip_network(..., strict=False)` | `discovery.py:45`, `:51` | `192.168.1.77/24` → `192.168.1.0/24` |
| ARP solo existe en IPv4 (IPv6 usa NDP) | `if net.version != 4: raise` | `discovery.py:52` | Rechaza redes IPv6 |
| Bit U/L = MAC localmente administrada | `int(mac.split(":")[0], 16) & 0x02` | `discovery.py:74` | Si está a 1, la MAC es aleatoria y el OUI no vale |
| OUI = 24 primeros bits → fabricante | `OUI_DB._get_manuf(mac)` | `discovery.py:85` | Consulta la base `manuf` (Wireshark) que trae Scapy |
| Trampa de Scapy | `name.lower() == mac.lower()` | `discovery.py:89` | Si Scapy no la conoce devuelve la propia MAC → "desconocido" |
| ARP en broadcast | `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)` | `discovery.py:101` | Una pregunta "¿quién tiene X?" por cada IP de la red |
| Envío/recepción en capa 2 | `srp(pkt, timeout, iface, retry)` | `discovery.py:102` | Envía tramas crudas y empareja pregunta ↔ respuesta |
| La respuesta trae IP + MAC | `resp[ARP].hwsrc`, `resp[ARP].psrc` | `discovery.py:106-107` | No hace falta un segundo paso de búsqueda |
| La MAC identifica al dispositivo (la IP cambia por DHCP) | `devices[mac] = Device(...)` | `discovery.py:107` | Diccionario con la MAC como clave |
| Aislamiento de clientes (AP isolation) | `if not devices: mode = "fallback-sniff-only"` | `net_device_scanner.py:73-81` | Si nadie responde al ARP, pasa a escucha pasiva (mín. 30 s) |

**Puntos débiles detectados:** recorte a /24 silencioso; `_get_manuf` es API privada
de Scapy; si una IP responde con varias MACs (proxy ARP), cada respuesta pisa la
anterior.

---

## Hito 2 — Sniffing pasivo (`iot_scanner/sniffer.py`)

**Idea:** ¿qué hace cada dispositivo? Se escucha el tráfico sin enviar nada, se
agrupa cada paquete por su MAC de origen y se extraen protocolos, puertos,
hostname, servicios y banners.

### Captura y agregación por MAC

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Captura pasiva (no se envía nada) | `sniff(iface, prn=..., timeout, store=False)` | `sniffer.py:256` | Llama a `handle_packet` por cada paquete; `store=False` no guarda los paquetes en memoria |
| Análisis offline reproducible | `rdpcap(path)` | `sniffer.py:265` | Mismo procesado sobre un `.pcap` (comparable con Wireshark) |
| La MAC de origen identifica al emisor | `pkt[Ether].src` | `sniffer.py:190` | Clave para agrupar |
| Bit I/G (0x01): multicast/broadcast no son emisores reales | `_is_unicast(mac)` | `sniffer.py:48-49`, `:191` | Descarta orígenes multicast; también se ignora la MAC propia |
| Un dispositivo nuevo visto solo en pasivo | `_get_device(...)`, `source="pasivo"` | `sniffer.py:179-184` | Lo crea con fabricante por OUI (reutiliza el Hito 1) |
| ARP gratuito / respuestas ARP de otros | `pkt[ARP].psrc` | `sniffer.py:198-202` | Saca la IP aunque haya aislamiento de clientes |
| IP de origen (capa 3) | `pkt[IP].src` | `sniffer.py:204-208` | Rellena la IP si aún no se tiene (ignora `0.0.0.0` de DHCP) |

### Puertos: cliente vs. servidor (capa 4)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Handshake TCP: SYN → SYN+ACK → ACK; quien manda SYN+ACK es el servidor | `pkt[TCP].flags & 0x12 == 0x12` | `sniffer.py:220-221` | SYN (0x02) + ACK (0x10) → el puerto origen es un servicio que ofrece (`ports_src`) |
| Puerto destino = servicio al que se conecta (cliente) | `dev.add("ports_dst", dport)` | `sniffer.py:232-233` | Ej.: 1883 = se conecta a un broker MQTT |
| Puertos efímeros (IANA ≥ 49152) son del cliente, ruido | `dport < EPHEMERAL_START` | `sniffer.py:26`, `:232` | No guarda puertos efímeros |
| UDP no tiene handshake: puerto origen bajo ≈ servicio propio | `sport < 1024 and sport not in UDP_CLIENT_LOW_PORTS` | `sniffer.py:31`, `:235-237` | DHCP (67/68) y NTP (123) se excluyen porque el cliente también los usa como origen |
| Servicios UDP altos que delatan a un servidor | `UDP_SERVER_PORTS = {1900, 5683, 5684, 5540}` | `sniffer.py:28` | SSDP/UPnP, CoAP (5683) / CoAP sobre DTLS (5684) y Matter (5540) |

### Capa 7: lo que el dispositivo cuenta de sí mismo

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| DHCP opción 12 = hostname que pide el cliente | `opt[0] == "hostname"` | `sniffer.py:74-75` | Fuente preferida de hostname |
| DHCP opción 60 = vendor class (cliente DHCP / SO) | `opt[0] == "vendor_class_id"` | `sniffer.py:76-77` | Banner `DHCP:...` (ej. `udhcp`, `android-dhcp`, `MSFT 5.0`) |
| mDNS = DNS multicast en `224.0.0.251:5353`, nombres `.local` | `PORT_MDNS in (sport, dport)` | `sniffer.py:21`, `:244-245` | Separa mDNS del DNS normal por el puerto |
| DNS-SD: servicios `_servicio._tcp.local` | `re.search(r"(_[\w\-]+\._(?:tcp\|udp))\.local$", name)` | `sniffer.py:91-93` | Ej.: `_googlecast._tcp` = Chromecast, `_hap._tcp` = HomeKit |
| Registro A (1) / AAAA (28) en respuesta mDNS = "mi nombre es X.local" | `dns.qr == 1 and rr.type in (1, 28)` | `sniffer.py:95-96` | Hostname por mDNS (solo si DHCP no dio uno) |
| Secciones DNS (qd, an, ar) son listas en Scapy ≥ 2.5 | `_dns_records(section)` | `sniffer.py:56-66` | Recorre los registros en ambos formatos (lista y encadenado) |
| DNS: `qr = 0` es consulta | `if dns.qr == 0` | `sniffer.py:102-106` | Dominios que resuelve (a qué nube habla: `hik-connect.com`, `tuyaeu.com`...) |
| SSDP/UPnP: anuncios HTTP sobre UDP 1900 | `key in ("SERVER", "USER-AGENT")` | `sniffer.py:114-117` | Banner con SO y modelo (ej. `Linux/3.10 UPnP/1.0 IPCamera`) |

### Seguridad: el texto de la red es entrada no confiable

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Inyección vía campos de red (riesgo del PDF) | `_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._\-:/()+@,=]")` | `sniffer.py:35` | Lista blanca: todo lo demás se borra (secuencias ANSI, `<`, `;`, comillas, saltos de línea) |
| Limitar longitud | `value[:max_len]` | `sniffer.py:45` | 64 caracteres por defecto (128 nombres DNS, 96 banners SSDP) |
| Bytes con codificación inválida | `decode("utf-8", errors="ignore")` | `sniffer.py:43` | No revienta con bytes basura |
| Un dispositivo ruidoso no infla la memoria | `MAX_ITEMS = 64` | `device.py:6`, `:28-32` | Máximo 64 elementos por conjunto |

**Puntos débiles detectados:**
- En una red con switch o WiFi solo se ve el tráfico propio + broadcast/multicast; el
  unicast entre otros dispositivos (cámara ↔ nube) no llega salvo con port mirroring,
  hub o siendo el propio punto de acceso. Los tests lo dan por visto.
- El router reenvía el tráfico de Internet con **su** MAC: en modo solo-escucha (sin
  ARP previo) la IP del router puede quedarse con una IP pública si es lo primero que
  se ve, y siempre se le atribuyen puertos de servidores externos.
- Linux usa puertos efímeros desde 32768 (no 49152): los puertos 32768-49151 se cuelan
  como ruido en `ports_dst`.
- Un cliente UDP con puerto origen < 1024 se marcaría como servidor (raro, pero posible).

---

## Ampliación del Hito 2 — NTP, TLS (SNI) y Matter/Thread

**Idea:** tres señales más que se ven aunque el contenido vaya cifrado o el
dispositivo no use IPv4. Añadidas el 2026-10-21 (código asistido por IA).

### NTP: a qué servidor de hora pregunta

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| NTP = UDP 123; casi todo IoT sincroniza la hora y el servidor elegido delata al fabricante | `PORT_NTP in (sport, dport) and pkt.haslayer(NTP)` | `sniffer.py:239-240` | Scapy disecciona el NTP; se marca el protocolo |
| Campo `mode` del NTP: 3 = cliente, 4 = respuesta de servidor, 5 = broadcast | `_parse_ntp(pkt, dev, ip_dst)` | `sniffer.py:120-127` | Cliente → guarda la IP del servidor en `ntp_servers`; servidor → `ports_src` 123 |
| ntpd usa el 123 también como puerto origen del cliente | `UDP_CLIENT_LOW_PORTS = {67, 68, 123}` | `sniffer.py:31`, `:236` | Evita marcar como "servidor NTP" a un cliente (falso positivo que tenía el Hito 2) |

### TLS: el nombre del servidor viaja en claro (SNI)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| HTTPS va cifrado, pero el primer mensaje (ClientHello) no: lleva el SNI para que el servidor sepa qué certificado dar | `tls_sni(data)` | `sniffer.py:134-168` | Parser manual del ClientHello sin dependencias |
| Registro TLS `0x16` (handshake), versión `0x03xx`, mensaje `0x01` (ClientHello) | `data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01` | `sniffer.py:144` | Descarta todo lo que no es un ClientHello |
| Estructura: versión, random (32), session id, cipher suites, compresión, extensiones | `pos += ...` | `sniffer.py:146-150` | Salta los campos de longitud variable leyendo su longitud |
| Extensión `0x0000` = server_name; tipo 0 = host_name | `ext_type == 0x0000` | `sniffer.py:155-160` | Devuelve el nombre; si está cortado, `None` |
| Entrada no confiable | `sanitize_text(tls_sni(...), 128)` | `sniffer.py:222-226` | El SNI se sanea igual que hostname y banners |
| Un dominio es un dominio, venga de DNS o de TLS | `seen = [("consulta", d) ...] + [("TLS a", d) ...]` | `heuristics.py:166-173` | El SNI alimenta la misma regex `domains` de las reglas; cuenta como una sola evidencia |

### Matter / Thread: IPv6 y mDNS

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Matter va sobre IPv6 (link-local `fe80::`) y se anuncia por mDNS en `ff02::fb` | `elif pkt.haslayer(IPv6)` | `sniffer.py:209-213` | Guarda las direcciones IPv6 en `ipv6` (antes se perdían) |
| Matter operativo = UDP 5540 | `PORT_MATTER = 5540` en `UDP_SERVER_PORTS` | `sniffer.py:25`, `:28` | Puerto servido |
| DNS-SD de Matter: `_matter._tcp` (ya emparejado), `_matterc._udp` (por emparejar), `_matterd._udp` (controlador) | regla `Dispositivo Matter` | `heuristics.py:92-95` | La regex de servicios mDNS del Hito 2 ya los captura sin cambios |
| Thread no es IP en tu WiFi: solo se ve su border router (`_meshcop._udp`, `_trel._udp`) | regla `Border router Thread / controlador Matter` | `heuristics.py:96-98` | Identifica el puente, no los nodos Thread |

**Puntos débiles de la ampliación:**
- El SNI solo se busca en el primer segmento TCP. Los ClientHello modernos (Chrome con
  claves post-cuánticas) superan los ~1460 bytes y el SNI puede caer en el segundo.
- Con **ECH** (Encrypted Client Hello) el SNI real va cifrado; solo se vería el del
  servidor frontal.
- `ntp_servers` guarda IPs; el nombre (`time.hikvision.com`) sale de `dns_queries`.
- La tabla de consola muestra `-` como IP de un dispositivo solo IPv6 (está en el JSON/CSV).

---

## Hito 3 — Heurísticas (`iot_scanner/heuristics.py`)

**Idea:** ¿qué es probablemente cada dispositivo? Un sistema de reglas (como un
sistema experto o el *fingerprinting* de p0f/nmap): cada regla describe un tipo de
dispositivo con varias pistas; se suman los **pesos** de las pistas que casan y,
cuanto más alta la suma, más confianza. Es una hipótesis para el analista, no un
veredicto.

Revisado y mejorado el 2026-10-25 (pesos por especificidad, regex con inicio de
palabra, sin doble conteo). La versión original contaba pistas: todas pesaban 1.

### Pesos: cuánto distingue cada pista

**Teoría:** el valor de una pista para identificar es su **cociente de verosimilitud**,
`P(pista | es este tipo) / P(pista | es otro tipo)`. Si una pista aparece igual en
todos los tipos (cociente ≈ 1) no distingue nada, aunque sea muy común. Misma idea que
TF-IDF: una palabra que sale en todos los documentos no dice de qué trata uno.
Sin datos reales para calcular los cocientes (eso es el Hito 6), se usan tres niveles.

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Tres niveles de especificidad | `WEIGHT_STRONG, WEIGHT_MEDIUM, WEIGHT_WEAK = 3, 2, 1` | `heuristics.py:20` | Fuerte = casi exclusiva de un tipo; débil = la tiene casi todo |
| Puertos propietarios → fuertes | `STRONG_PORTS = {37777, 34567, 8009, 6668, ...}` | `heuristics.py:23` | 37777 Dahua, 34567 XMEye, 8009 Chromecast, 6668 Tuya, 5540 Matter, 62078 iPhone |
| Puertos genéricos → débiles | `WEAK_PORTS = {80, 443, 1900, 5000, 5001, 8080, 8443, 49152}` | `heuristics.py:25` | Web y UPnP: los sirve casi cualquier cosa |
| El resto de puertos → medio | `port_weight(port)` | `heuristics.py:31-36` | Puertos de protocolo característico: 554 RTSP, 1883 MQTT, 631 IPP |
| Servicios mDNS: específicos salvo los compartidos | `MEDIUM_MDNS`, `mdns_weight()` | `heuristics.py:27-28`, `:39-40` | `_googlecast._tcp` = 3; `_airplay._tcp` (Apple TV, Mac, altavoces) = 2 |
| Lo que el dispositivo dice de sí mismo pesa más que su fabricante | `own = hostname + banners` → +2; si no, `vendor` → +1 | `heuristics.py:154-164` | **Fabricante ≠ tipo**: un móvil Google ya no pasa de "baja" como TV |
| Dominio de la nube del fabricante → fuerte | `WEIGHT_STRONG` | `heuristics.py:166-173` | `hik-connect.com`, `tuyaeu.com` (DNS o SNI de TLS) |
| El peso solo afecta a identificar, no al riesgo | (sin cambios en `report.py`) | `report.py:15-35` | El 80 y el 1900 siguen generando sus alertas de seguridad |

### Las reglas

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Una regla = un tipo de dispositivo + sus pistas | `@dataclass class Rule` | `heuristics.py:43-58` | Campos: `served_ports`, `client_ports`, `mdns`, `text` (regex), `domains` (regex) |
| Cada pista viene de una señal del Hito 2 | campos de `Rule` ↔ campos de `Device` | `heuristics.py:46-50` | `served_ports`↔`ports_src`, `client_ports`↔`ports_dst`, `mdns`↔`mdns_services`, `text`↔hostname+banners (o fabricante), `domains`↔`dns_queries`+`tls_sni` |
| La regex de texto solo casa al **inicio de palabra** | `(?<![a-z])(?:...)` en `__post_init__` | `heuristics.py:53-58` | `esp` casa con `ESP_32AB` y `esp32-x` pero no con `despacho-pc`; por la derecha no se limita para no perder `IPCamera` |
| Base de conocimiento | `RULES = [...]` | `heuristics.py:61-128` | 15 tipos: cámara, TV, altavoz, MQTT, CoAP, enchufe, Matter, Thread, UPnP, impresora, router, NAS, Apple, Windows, Android |

### Evaluar una regla: reunir evidencias

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Coincidencia por intersección de conjuntos | `rule.served_ports & dev.ports_src` | `heuristics.py:145-147` | Cada puerto que coincide es una evidencia, con su peso |
| **Sin doble conteo**: un puerto servido no vuelve a contar como cliente | `(rule.client_ports & dev.ports_dst) - served` | `heuristics.py:148-150` | Un solo paquete SSDP 1900 → 1900 es una pista, no dos |
| Servicios mDNS | `rule.mdns & dev.mdns_services` | `heuristics.py:151-152` | Una evidencia por servicio |
| Dominios (DNS y SNI) | `seen = [...]` + `break` | `heuristics.py:166-173` | **Una** evidencia como máximo, venga de DNS o de TLS |
| Evidencias explicables **con su peso** | `f"{desc} (+{w})"` | `heuristics.py:188` | El informe muestra, p. ej., `sirve puerto 554 (+2)`: el analista ve por qué y cuánto |

### Puntuar y decidir

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Puntuación = suma de pesos | `score = sum(w for _, w in ev)` | `heuristics.py:183` | Un 37777 (3) ya no vale lo mismo que un 80 (1) |
| Umbrales sobre la suma | `CONFIDENCE_LEVELS = ((5, "alta"), (3, "media"), (1, "baja"))` | `heuristics.py:132-139` | Una pista fuerte sola = media; para alta hacen falta varias pistas |
| Varias hipótesis ordenadas | `candidates.sort(...)`; `[:max_labels]` | `heuristics.py:190-191` | Hasta 3 etiquetas; en empate gana la regla que va antes en `RULES` |
| Sin evidencias, sin etiqueta | `if ev:` | `heuristics.py:182` | Un dispositivo sin pistas queda "Sin identificar" (mejor que inventar) |
| Se ejecuta tras el sniffing | `heuristics.classify_all(devices)` | `net_device_scanner.py:106` | Rellena `dev.labels` para el informe (Hito 4) |

**Antes y después** (casos comprobados el 2026-10-21 y el 2026-10-25):

| Caso | Antes (conteo) | Ahora (pesos) |
|---|---|---|
| Móvil Pixel / Samsung (solo fabricante) | Chromecast / TV, baja | Chromecast / TV, baja, `fabricante 'Google' (+1)`: sigue saliendo, pero marcado como pista débil |
| PC `despacho-pc` | Dispositivo MQTT, baja | Sin identificar |
| Solo sirve el 80 | Enchufe / bombilla, baja (1) | Enchufe / bombilla, baja (1) + alerta del 80 intacta |
| SSDP 1900 → 1900 | UPnP, **media** (2 evidencias) | UPnP, baja (1) |
| Solo el 37777 (Dahua) | Cámara, **baja** | Cámara, **media** (3) |
| Cámara del laboratorio | Cámara, alta (3) | Cámara, alta (6) |

**Puntos débiles que quedan:**
- Los pesos son **juicio experto**, no medidos; los umbrales (1/3/5) tampoco están
  calibrados. Medir aciertos y falsos positivos en el Hito 6 (conteo frente a pesos es un
  buen experimento para la investigación).
- **Evidencias correlacionadas**: 554 + 8554 + 8000 suman 2 + 2 + 2 aunque las tres digan
  lo mismo ("sirve vídeo").
- **Sin evidencia negativa**: nada resta puntos (p. ej. "habla con apple.com" no descarta TV).
- Un solo puerto genérico sigue generando una etiqueta "baja" (el 80 → enchufe).
- `tp-?link` sigue en dos reglas (enchufe y router).

---

## Hito 4 — Informe (`iot_scanner/report.py`)

_Pendiente de revisar._
