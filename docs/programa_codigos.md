# programa_codigos.md — Dónde se usa la teoría en el código

Mapa de cada concepto teórico a la línea de código que lo aplica, hito a hito.
Las rutas son relativas a `programa/`. Las líneas corresponden a
la rama `hitos-1-4` (2026-10-26: tras las mejoras propuestas por Qwen); si el código cambia,
revisarlas. `rules.json` está en `programa/iot_scanner/`.

Fichero vivo: se completa a medida que se revisa cada hito.

---

## Hito 1 — Descubrimiento (`iot_scanner/discovery.py`)

**Idea:** ¿quién hay en la red? ARP pregunta por cada IP; la respuesta trae la MAC;
el OUI de la MAC da el fabricante.

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Red = IP + máscara (CIDR) | `_netmask_for(iface, ip)` | `discovery.py:34` | Busca en la tabla de rutas la ruta directamente conectada (sin gateway, `gw == "0.0.0.0"`, y no la ruta por defecto, `net != 0`) |
| Prefijo = bits a 1 de la máscara | `bin(mask).count("1")` | `discovery.py:54` | `255.255.255.0` → 24 |
| Seguridad operativa: no barrer redes enormes | `prefix = max(prefix, 24)` | `discovery.py:56` | Nunca escanea más de un /24 automáticamente (un /16 serían 65.534 ARPs) |
| Normalizar el CIDR | `ipaddress.ip_network(..., strict=False)` | `discovery.py:57`, `:63` | `192.168.1.77/24` → `192.168.1.0/24` |
| ARP solo existe en IPv4 (IPv6 usa NDP) | `if net.version != 4: raise` | `discovery.py:64` | Rechaza redes IPv6 |
| Bit U/L = MAC localmente administrada | `int(mac.split(":")[0], 16) & 0x02` | `discovery.py:86` | Si está a 1, la MAC es aleatoria y el OUI no vale |
| OUI = 24 primeros bits → fabricante | `OUI_DB._get_manuf(mac)` | `discovery.py:97` | Consulta la base `manuf` (Wireshark) que trae Scapy |
| Trampa de Scapy | `name.lower() == mac.lower()` | `discovery.py:101` | Si Scapy no la conoce devuelve la propia MAC → "desconocido" |
| ARP en broadcast | `Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)` | `discovery.py:125` | Una pregunta "¿quién tiene X?" por cada IP de la red |
| Envío/recepción en capa 2 | `srp(pkt, timeout, iface, retry, inter)` | `discovery.py:126` | Envía tramas crudas y empareja pregunta ↔ respuesta |
| La respuesta trae IP + MAC | `resp[ARP].hwsrc`, `resp[ARP].psrc` | `discovery.py:130-131` | No hace falta un segundo paso de búsqueda |
| La MAC identifica al dispositivo (la IP cambia por DHCP) | `devices[mac] = Device(...)` | `discovery.py:131` | Diccionario con la MAC como clave |
| Aislamiento de clientes (AP isolation) | `if not devices: mode = "fallback-sniff-only"` | `net_device_scanner.py:95-102` | Si nadie responde al ARP, pasa a escucha pasiva (mín. 30 s) |

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
| Captura pasiva (no se envía nada) | `AsyncSniffer(iface, prn=..., store=False)` | `sniffer.py:345-379` | Llama a `handle_packet` por cada paquete en un hilo aparte; `store=False` no guarda los paquetes en memoria (ver "Escucha parable") |
| Análisis offline reproducible | `rdpcap(path)` | `sniffer.py:385` | Mismo procesado sobre un `.pcap` (comparable con Wireshark) |
| La MAC de origen identifica al emisor | `pkt[Ether].src` | `sniffer.py:272` | Clave para agrupar |
| `0.0.0.0` / `::` = "sin dirección" (DHCP sin IP, ruta sin gateway) | `is_unspecified(ip)` con `ipaddress` | `discovery.py:26-31` | Sustituye las comparaciones con el literal `"0.0.0.0"` (avisos B104 de bandit) |
| Bit I/G (0x01): multicast/broadcast no son emisores reales | `_is_unicast(mac)` | `sniffer.py:76-77`, `:273` | Descarta orígenes multicast; también se ignora la MAC propia |
| Un dispositivo nuevo visto solo en pasivo | `_get_device(...)`, `source="pasivo"` | `sniffer.py:260-266` | Lo crea con fabricante por OUI (reutiliza el Hito 1) |
| ARP gratuito / respuestas ARP de otros | `pkt[ARP].psrc` | `sniffer.py:280-284` | Saca la IP aunque haya aislamiento de clientes |
| IP de origen (capa 3) | `pkt[IP].src` | `sniffer.py:286-290` | Rellena la IP si aún no se tiene (ignora `0.0.0.0` de DHCP) |

### Puertos: cliente vs. servidor (capa 4)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Handshake TCP: SYN → SYN+ACK → ACK; quien manda SYN+ACK es el servidor | `pkt[TCP].flags & 0x12 == 0x12` | `sniffer.py:302-303` | SYN (0x02) + ACK (0x10) → el puerto origen es un servicio que ofrece (`ports_src`) |
| Puerto destino = servicio al que se conecta (cliente) | `dev.add("ports_dst", dport)` | `sniffer.py:314-315` | Ej.: 1883 = se conecta a un broker MQTT |
| Puertos efímeros (IANA ≥ 49152) son del cliente, ruido | `dport < EPHEMERAL_START` | `sniffer.py:36`, `:314` | No guarda puertos efímeros |
| UDP no tiene handshake: puerto origen bajo ≈ servicio propio | `sport < 1024 and sport not in UDP_CLIENT_LOW_PORTS` | `sniffer.py:41`, `:317-319` | DHCP (67/68) y NTP (123) se excluyen porque el cliente también los usa como origen |
| Servicios UDP altos que delatan a un servidor | `UDP_SERVER_PORTS = {1900, 5683, 5684, 5540}` | `sniffer.py:38` | SSDP/UPnP, CoAP (5683) / CoAP sobre DTLS (5684) y Matter (5540) |

### Capa 7: lo que el dispositivo cuenta de sí mismo

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| DHCP opción 12 = hostname que pide el cliente | `opt[0] == "hostname"` | `sniffer.py:102-103` | Fuente preferida de hostname |
| DHCP opción 60 = vendor class (cliente DHCP / SO) | `opt[0] == "vendor_class_id"` | `sniffer.py:104-105` | Banner `DHCP:...` (ej. `udhcp`, `android-dhcp`, `MSFT 5.0`) |
| mDNS = DNS multicast en `224.0.0.251:5353`, nombres `.local` | `PORT_MDNS in (sport, dport)` | `sniffer.py:30`, `:326-327` | Separa mDNS del DNS normal por el puerto |
| DNS-SD: servicios `_servicio._tcp.local` | `re.search(r"(_[\w\-]+\._(?:tcp\|udp))\.local$", name)` | `sniffer.py:119-121` | Ej.: `_googlecast._tcp` = Chromecast, `_hap._tcp` = HomeKit |
| Registro A (1) / AAAA (28) en respuesta mDNS = "mi nombre es X.local" | `dns.qr == 1 and rr.type in (1, 28)` | `sniffer.py:123-124` | Hostname por mDNS (solo si DHCP no dio uno) |
| Secciones DNS (qd, an, ar) son listas en Scapy ≥ 2.5 | `_dns_records(section)` | `sniffer.py:84-94` | Recorre los registros en ambos formatos (lista y encadenado) |
| DNS: `qr = 0` es consulta | `if dns.qr == 0` | `sniffer.py:157-161` | Dominios que resuelve (a qué nube habla: `hik-connect.com`, `tuyaeu.com`...) |
| SSDP/UPnP: anuncios HTTP sobre UDP 1900 | `key in ("SERVER", "USER-AGENT")` | `sniffer.py:171-172` | Banner con SO y modelo (ej. `Linux/3.10 UPnP/1.0 IPCamera`) |

### Seguridad: el texto de la red es entrada no confiable

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Inyección vía campos de red (riesgo del PDF) | `_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._\-:/()+@,=]")` | `sniffer.py:63` | Lista blanca: todo lo demás se borra (secuencias ANSI, `<`, `;`, comillas, saltos de línea) |
| Limitar longitud | `value[:max_len]` | `sniffer.py:73` | 64 caracteres por defecto (128 nombres DNS, 96 banners SSDP) |
| Bytes con codificación inválida | `decode("utf-8", errors="ignore")` | `sniffer.py:71` | No revienta con bytes basura |
| Un dispositivo ruidoso no infla la memoria | `MAX_ITEMS = 64` | `device.py:6`, `:33-37` | Máximo 64 elementos por conjunto |

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
| NTP = UDP 123; casi todo IoT sincroniza la hora y el servidor elegido delata al fabricante | `PORT_NTP in (sport, dport) and pkt.haslayer(NTP)` | `sniffer.py:321-322` | Scapy disecciona el NTP; se marca el protocolo |
| Campo `mode` del NTP: 3 = cliente, 4 = respuesta de servidor, 5 = broadcast | `_parse_ntp(pkt, dev, ip_dst)` | `sniffer.py:175-182` | Cliente → guarda la IP del servidor en `ntp_servers`; servidor → `ports_src` 123 |
| ntpd usa el 123 también como puerto origen del cliente | `UDP_CLIENT_LOW_PORTS = {67, 68, 123}` | `sniffer.py:41`, `:318` | Evita marcar como "servidor NTP" a un cliente (falso positivo que tenía el Hito 2) |

### TLS: el nombre del servidor viaja en claro (SNI)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| HTTPS va cifrado, pero el primer mensaje (ClientHello) no: lleva el SNI para que el servidor sepa qué certificado dar | `tls_sni(data)` | `sniffer.py:215-245` | Parser manual del ClientHello sin dependencias |
| Registro TLS `0x16` (handshake), versión `0x03xx`, mensaje `0x01` (ClientHello) | `data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01` | `sniffer.py:225` | Descarta todo lo que no es un ClientHello |
| Estructura: versión, random (32), session id, cipher suites, compresión, extensiones | `pos += ...` | `sniffer.py:227-231` | Salta los campos de longitud variable leyendo su longitud |
| Extensión `0x0000` = server_name; tipo 0 = host_name | `ext_type == 0x0000` | `sniffer.py:236-241` | Devuelve el nombre; si está cortado, `None` |
| Entrada no confiable | `sanitize_text(tls_sni(...), 128)` | `sniffer.py:304-308` | El SNI se sanea igual que hostname y banners |
| Un dominio es un dominio, venga de DNS o de TLS | `seen = [("consulta", d) ...] + [("TLS a", d) ...]` | `heuristics.py:194-201` | El SNI alimenta la misma regex `domains` de las reglas; cuenta como una sola evidencia |

### Matter / Thread: IPv6 y mDNS

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Matter va sobre IPv6 (link-local `fe80::`) y se anuncia por mDNS en `ff02::fb` | `elif pkt.haslayer(IPv6)` | `sniffer.py:291-295` | Guarda las direcciones IPv6 en `ipv6` (antes se perdían) |
| Matter operativo = UDP 5540 | `PORT_MATTER = 5540` en `UDP_SERVER_PORTS` | `sniffer.py:34`, `:38` | Puerto servido |
| DNS-SD de Matter: `_matter._tcp` (ya emparejado), `_matterc._udp` (por emparejar), `_matterd._udp` (controlador) | regla `Dispositivo Matter` | `rules.json:57-62` | La regex de servicios mDNS del Hito 2 ya los captura sin cambios |
| Thread no es IP en tu WiFi: solo se ve su border router (`_meshcop._udp`, `_trel._udp`) | regla `Border router Thread / controlador Matter` | `rules.json:63-67` | Identifica el puente, no los nodos Thread |

### WS-Discovery / ONVIF: la cámara dice qué es (añadido el 2026-10-26)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| WS-Discovery = SOAP/XML por UDP 3702 a `239.255.255.250` / `ff02::c` (multicast: llega sin port mirroring) | `PORT_WSD in (sport, dport)` | `sniffer.py:35`, `:332-333` | Activa el extractor |
| Quién envía cada mensaje: `Hello`/`Bye`/`ProbeMatches` el dispositivo descubierto; `Probe`/`Resolve` quien busca (NVR, app, Windows) | `WSD_TARGET_ACTIONS`; `action not in ...` | `sniffer.py:45`, `:197-199` | Solo el dispositivo descubierto gana tipos y `ports_src` 3702; un `Probe` no lo convierte en cámara |
| `Types`: qué es (`dn:NetworkVideoTransmitter` = cámara ONVIF, `PrintDeviceType`, `pub:Computer`) | `_WSD_TYPES`; `dev.add("wsd_types", ...)` | `sniffer.py:50`, `:200-202` | Se guarda el nombre sin prefijo XML |
| `Scopes` ONVIF: `onvif://www.onvif.org/name/...`, `/hardware/...` (modelo) | `ONVIF_SCOPE_KEYS`; `unquote` | `sniffer.py:52`, `:203-208` | Banners `ONVIF:hardware=DS-2CD2043G2-I`, `ONVIF:name=...` (sirven a la regex de texto y, en el futuro, a buscar CVE por modelo) |
| XML no confiable: un parser XML se expone a entidades externas (XXE) o expansión de entidades | regex acotadas `{0,256}`, `[^<]`; `WSD_MAX_BYTES = 8192` | `sniffer.py:46-51` | Sin parser, sin backtracking catastrófico, tamaño limitado y texto saneado |
| El tipo lo declara el propio dispositivo y es muy específico | `rule.wsd & dev.wsd_types` → `WEIGHT_STRONG` | `heuristics.py:179-180` | +3 para cámara, impresora o Windows |
| ONVIF activo revela el modelo | `SENSITIVE_SERVED[3702]` | `report.py:37` | Alerta BAJA: revisar la autenticación ONVIF |

Límite: el `Hello` solo se envía al conectarse el dispositivo a la red, y la respuesta a un
`Probe` (`ProbeMatches`) va por unicast a quien preguntó. En pasivo se ve la cámara si
arranca durante la escucha; un `Probe` activo (opcional, futuro) la vería siempre.

**Puntos débiles de la ampliación:**
- El SNI solo se busca en el primer segmento TCP. Los ClientHello modernos (Chrome con
  claves post-cuánticas) superan los ~1460 bytes y el SNI puede caer en el segundo.
- Con **ECH** (Encrypted Client Hello) el SNI real va cifrado; solo se vería el del
  servidor frontal.
- `ntp_servers` guarda IPs; el nombre (`time.hikvision.com`) sale de `dns_queries`.
- La tabla de consola muestra `-` como IP de un dispositivo solo IPv6 (está en el JSON/CSV).

### Registros TXT de mDNS: modelo y firmware (añadido el 2026-11-16)

**Para qué:** buscar vulnerabilidades (CVE) exige saber el **modelo** y, para tener
certeza, la **versión del firmware**. Solo con el fabricante (OUI) no se puede. Casi
ningún IoT anuncia el firmware, pero muchos lo dejan en los TXT de mDNS: es la fuente
pasiva más rentable para subir de "fabricante" a "modelo" o "modelo + versión".

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| DNS-SD (RFC 6763): cada servicio mDNS puede llevar un registro TXT (tipo 16) con pares `clave=valor` | `rr.type == TXT_TYPE` | `sniffer.py:58`, `:126-127` | Solo en respuestas (`qr = 1`), que son lo que el dispositivo dice de sí mismo |
| En Scapy ≥ 2.5 el `rdata` de un TXT es una lista de bytes | `_txt_pairs(rdata)` | `sniffer.py:130-140` | Decodifica, separa por el primer `=`, sanea clave (32) y valor (96) y lee como mucho 32 pares |
| Las claves no distinguen mayúsculas (RFC 6763, 6.4); una clave sin `=` es un booleano | `key.lower()`; `value = None` | `sniffer.py:139` | `MODEL=` cuenta como `model=`; `solo_clave` se guarda tal cual |
| Cada fabricante usa sus claves para modelo y versión | `TXT_MODEL_KEYS`, `TXT_FIRMWARE_KEYS` | `sniffer.py:59-60` | Modelo: `md` (Google), `model`, `ty` y `product` (impresoras), `app` (Shelly). Firmware: `ver` (Shelly), `version` (ESPHome), `fw_id`, `osvers`… |
| No todo lo que parece versión es firmware | (excluidas a propósito) | `sniffer.py:54-57` | `txtvers` = versión del **formato** del TXT; `ve` en Chromecast = versión del **protocolo** |
| Trazabilidad: guardar todo, interpretar solo lo conocido | `mdns_txt`, `models`, `firmware` | `sniffer.py:143-151`, `device.py:26-28` | Todos los pares en `mdns_txt`; modelo y firmware en campos propios para la futura búsqueda de CVE |
| El modelo es texto que el dispositivo dice de sí mismo | `own = hostname + models + banners` | `heuristics.py:185` | Pesa +2 en las reglas (frente a +1 del fabricante por OUI) |
| Privacidad: los TXT llevan identificadores (`id`, `deviceid`, `mac`) y nombres del usuario (`fn=Salón de Oscar`, `note=Despacho`) | `SAFE_TXT_KEYS` (lista blanca), `_keep_txt()` | `report.py:151-158`, `:178` | Con `--anonymize` solo quedan las claves técnicas (modelo, versiones, plataforma…) |

Límites: el saneado solo admite ASCII (`Salón` queda como `Saln`); no todos los
fabricantes usan las mismas claves, así que habrá TXT con versión que no se reconozcan
(quedan en `mdns_txt` para revisarlos a mano); y un TXT solo llega si el dispositivo
anuncia servicios por mDNS.

### Escucha parable (2026-10-26)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Captura en un hilo aparte que se puede parar | `AsyncSniffer(...)`, `capture.start()` | `sniffer.py:355-356` | Sustituye a `sniff(timeout=...)`, que bloqueaba hasta agotar el plazo |
| En Scapy 2.8 `AsyncSniffer` no admite `timeout` | `deadline = time.monotonic() + seconds` | `sniffer.py:357-367` | El plazo lo controla el bucle, con esperas cortas de 0,2 s que atienden `stop_event` y Ctrl+C (también en Windows) |
| Carrera: un `stop()` antes de que el hilo empiece a capturar se ignora | `_stop_capture()` + reintentos | `sniffer.py:336-342`, `:369-372` | Reintenta hasta 5 s hasta que la captura para de verdad |
| Los errores del hilo no deben perderse | `raise capture.exception` | `sniffer.py:373-374` | Sin permisos o sin Npcap, el error llega a la CLI o a la GUI |
| Se analiza lo capturado hasta el corte | `listened = round(time.monotonic() - t0)` | `net_device_scanner.py` (`run_live`) | El informe guarda los segundos escuchados de verdad |
| Botón Detener solo durante la escucha | `self.stop_btn`, `self.stop_event.set()` | `gui.py` (`_start`, `_stop`) | Activo en modos con escucha en vivo; se desactiva al terminar |

### Seguridad del propio código: bandit (2026-10-26)

`bandit -r programa -s B101` sin avisos (B101 = `assert`, lo normal en pytest). Los B104 eran
falsos positivos por el literal `"0.0.0.0"` (se compara, no se hace bind); se sustituyeron
por `is_unspecified()`. Los B110 (`except: pass`) pasaron a excepciones concretas o a un
retorno explícito comentado.

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
| Tres niveles de especificidad | `WEIGHT_STRONG, WEIGHT_MEDIUM, WEIGHT_WEAK = 3, 2, 1` | `heuristics.py:23` | Fuerte = casi exclusiva de un tipo; débil = la tiene casi todo |
| Puertos propietarios → fuertes | `"strong_ports": [...]` → `STRONG_PORTS` | `rules.json:5`, `heuristics.py:32` | 37777 Dahua, 34567 XMEye, 8009 Chromecast, 6668 Tuya, 5540 Matter, 62078 iPhone |
| Puertos genéricos → débiles | `"weak_ports": [80, 443, 1900, ...]` → `WEAK_PORTS` | `rules.json:6`, `heuristics.py:33` | Web y UPnP: los sirve casi cualquier cosa |
| El resto de puertos → medio | `port_weight(port)` | `heuristics.py:39-44` | Puertos de protocolo característico: 554 RTSP, 1883 MQTT, 631 IPP |
| Servicios mDNS: específicos salvo los compartidos | `"medium_mdns"` → `MEDIUM_MDNS`, `mdns_weight()` | `rules.json:7`, `heuristics.py:47-48` | `_googlecast._tcp` = 3; `_airplay._tcp` (Apple TV, Mac, altavoces) = 2 |
| Lo que el dispositivo dice de sí mismo pesa más que su fabricante | `own = hostname + banners` → +2; si no, `vendor` → +1 | `heuristics.py:182-192` | **Fabricante ≠ tipo**: un móvil Google ya no pasa de "baja" como TV |
| Dominio de la nube del fabricante → fuerte | `WEIGHT_STRONG` | `heuristics.py:194-201` | `hik-connect.com`, `tuyaeu.com` (DNS o SNI de TLS) |
| El peso solo afecta a identificar, no al riesgo | (sin cambios en `report.py`) | `report.py:25-46` | El 80 y el 1900 siguen generando sus alertas de seguridad |

### Las reglas

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Una regla = un tipo de dispositivo + sus pistas | `@dataclass class Rule` | `heuristics.py:51-67` | Campos: `served_ports`, `client_ports`, `mdns`, `text` (regex), `domains` (regex) |
| Cada pista viene de una señal del Hito 2 | campos de `Rule` ↔ campos de `Device` | `heuristics.py:54-59` | `served_ports`↔`ports_src`, `client_ports`↔`ports_dst`, `mdns`↔`mdns_services`, `text`↔hostname+banners (o fabricante), `domains`↔`dns_queries`+`tls_sni` |
| La regex de texto solo casa al **inicio de palabra** | `(?<![a-z])(?:...)` en `__post_init__` | `heuristics.py:62-67` | `esp` casa con `ESP_32AB` y `esp32-x` pero no con `despacho-pc`; por la derecha no se limita para no perder `IPCamera` |
| Base de conocimiento | `"rules": [...]` → `RULES` | `rules.json:14-112`, `heuristics.py:146-155` | 15 tipos: cámara, TV, altavoz, MQTT, CoAP, enchufe, Matter, Thread, UPnP, impresora, router, NAS, Apple, Windows, Android |

### Evaluar una regla: reunir evidencias

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Coincidencia por intersección de conjuntos | `rule.served_ports & dev.ports_src` | `heuristics.py:170-173` | Cada puerto que coincide es una evidencia, con su peso |
| **Sin doble conteo**: un puerto servido no vuelve a contar como cliente | `(rule.client_ports & dev.ports_dst) - served` | `heuristics.py:174-175` | Un solo paquete SSDP 1900 → 1900 es una pista, no dos |
| Servicios mDNS | `rule.mdns & dev.mdns_services` | `heuristics.py:176-177` | Una evidencia por servicio |
| Dominios (DNS y SNI) | `seen = [...]` + `break` | `heuristics.py:194-201` | **Una** evidencia como máximo, venga de DNS o de TLS |
| Evidencias explicables **con su peso** | `f"{desc} (+{w})"` | `heuristics.py:216` | El informe muestra, p. ej., `sirve puerto 554 (+2)`: el analista ve por qué y cuánto |

### Puntuar y decidir

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Puntuación = suma de pesos | `score = sum(w for _, w in ev)` | `heuristics.py:211` | Un 37777 (3) ya no vale lo mismo que un 80 (1) |
| Umbrales sobre la suma | `"confidence_levels"` → `CONFIDENCE_LEVELS`; `_confidence()` | `rules.json:9-13`, `heuristics.py:160-164` | Una pista fuerte sola = media; para alta hacen falta varias pistas |
| Varias hipótesis ordenadas | `candidates.sort(...)`; `[:max_labels]` | `heuristics.py:218-219` | Hasta 3 etiquetas; en empate gana la regla que va antes en `RULES` |
| Sin evidencias, sin etiqueta | `if ev:` | `heuristics.py:210` | Un dispositivo sin pistas queda "Sin identificar" (mejor que inventar) |
| Se ejecuta tras el sniffing | `heuristics.classify_all(devices)` | `net_device_scanner.py:123` | Rellena `dev.labels` para el informe (Hito 4) |

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

## Mejoras propuestas por Qwen (2026-10-26)

Qwen (otro asistente de IA) propuso una lista de mejoras; el autor eligió estas y Claude
(Claude Code) las implementó, con los ajustes que se indican.

### Reglas en un fichero JSON: motor de reglas extensible

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Separar datos (conocimiento) de código (motor): reglas nuevas sin tocar Python | `rules.json` + `load_rules()` | `rules.json`, `heuristics.py:122-143` | Reglas, pesos y umbrales en un fichero; se cargan al importar (`use_rules()`, `heuristics.py:157`) |
| JSON y no YAML | — | — | Sin dependencia nueva (PyYAML no compilaba en Python 3.15) y sin el riesgo de cargar YAML con etiquetas de objetos |
| Validar la entrada: una errata no debe pasar en silencio | `unknown = set(d) - _RULE_FIELDS`; `re.compile(...)` | `heuristics.py:96-98`, `:115` | Campos desconocidos, puertos fuera de 1-65535 o regex mal escritas → `ValueError` con el nombre de la regla |
| Reglas propias del analista | `--rules fichero.json` → `use_rules(path)` | `net_device_scanner.py:64`, `:116-117` | Cambia las reglas sin editar el paquete. El fichero es configuración de confianza: una regex mal hecha puede ser lenta (ReDoS) |

### print() → logging

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Separar **salida** (la tabla, el resumen: stdout) de **registro** (progreso y avisos: stderr / fichero) | `setup_logging()` | `logsetup.py:29-58` | `print_table`/`print_summary` siguen con `print`; el resto pasa a `logging` |
| Niveles: DEBUG (detalle), INFO (progreso), WARNING/ERROR (avisos) | `ConsoleFormatter` | `logsetup.py:19-26` | En consola se mantiene el estilo `[*]` / `[!]`; `[.]` para depuración |
| Registro persistente para depurar | `--log scanner.log`, `-v` | `net_device_scanner.py:69-70`, `logsetup.py:50-54` | El fichero recibe todo (DEBUG) con fecha y módulo |
| Un logger por módulo bajo `iot_scanner` | `log = logging.getLogger(__name__)` | todos los módulos | La GUI cuelga su propio handler para la pestaña Registro (`gui.py:117`) |

El registro y la consola **no se anonimizan**: son para el analista. Solo los ficheros
exportados con `--anonymize` llevan seudónimos.

### --anonymize: Privacy by Design

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| **Seudonimizar** (RGPD art. 4.5): sustituir identificadores por seudónimos | `anonymize(devices, meta)` | `report.py:168-187` | MAC, IP, IPv6, hostname, nombre ONVIF, interfaz y ruta del `.pcap` |
| **Minimización**: conservar solo lo necesario para analizar | (se mantienen) | `report.py:168-187` | Fabricante, puertos, protocolos, servicios, dominios, tipo y alertas siguen en claro |
| Un hash (incluso con sal) no anonimiza: 2³² IPv4 se prueban en segundos | `hmac.new(key, ..., sha256)` | `report.py:136-145` | HMAC-SHA256 con clave aleatoria de 32 bytes por informe (`secrets`), no guardada: irreversible |
| Coherencia dentro del informe | `pseudo(kind, value)` | `report.py:136-145` | El mismo dispositivo tiene el mismo seudónimo en JSON, CSV y alertas; distinto en otro informe |
| Datos que escribe el usuario pueden delatar dónde está | `_anonymize_banner()` | `report.py:161-165` | `ONVIF:name=HIKVISION Entrada` → `ONVIF:name=name-…` |
| La ruta del `.pcap` lleva el usuario del equipo | `os.path.basename` | `report.py:185` | `C:\Users\…\lab.pcap` → `lab.pcap` |
| Solo afecta a lo exportado | `export()` | `net_device_scanner.py:129-141`; casilla en `gui.py:301` | La tabla en pantalla sigue mostrando los datos reales |

Limitación: las consultas DNS y el SNI se conservan porque son evidencia técnica, pero en
un móvil pueden revelar hábitos de navegación.

### Rate limiting del ARP scan

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Espaciar los paquetes: menos ráfaga, menos respuestas perdidas en IoT sencillos | `srp(..., inter=inter)` | `discovery.py:110-126` | 0,01 s por defecto (un /24 tarda ~2,5 s más); `--arp-interval 0` vuelve a la ráfaga |
| Matiz a la propuesta | `prefix = max(prefix, 24)` | `discovery.py` (`guess_network`) | Como mucho son 254 ARPs, no un "mini-DoS"; Qwen proponía 0,05 s (13 s por /24): se dejó configurable |

### Dependencias fijadas

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Reproducibilidad: las mismas versiones que se probaron | `requirements.lock` (`pip freeze`) | `programa/requirements.lock` | Versiones exactas (scapy 2.8.0, no la 2.6.1 que citaba la propuesta) |
| Separar lo que necesita el programa de las herramientas | `requirements.txt` / `requirements-dev.txt` | `programa/` | El lanzador solo instala scapy; bandit (y su PyYAML) solo en desarrollo |

### Integración continua y cobertura

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| CI: cada push se prueba solo, en una máquina limpia | `.github/workflows/ci.yml` | raíz del repo | pytest + flake8 + bandit en Python 3.12 y 3.14 con `requirements.lock` |
| Cobertura de líneas como umbral | `--cov=iot_scanner --cov-fail-under=85` | `ci.yml` | 92 % el 2026-10-26; la CI falla si baja del 85 % |
| Cobertura de **reglas** (lo que pedía Qwen: ≥ 80 %) | `extra_rule_packets()`, `EXTRA_EXPECTED` | `tests/lab_packets.py:134-215` | Un dispositivo sintético por cada regla que el laboratorio no ejercitaba: 15 de 15 |

### Filtro en la tabla de la GUI

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Filtrar sin perder datos: ocultar filas, no borrarlas | `tree.detach` / `tree.reattach` | `gui.py:550-563` | Busca el texto en IP, MAC, fabricante, hostname y tipo mientras se escribe; muestra "N de M" |

## Análisis de vulnerabilidades (`iot_scanner/vulns.py`, añadido el 2026-11-16)

Con el modelo y el firmware que dejan los TXT de mDNS se pueden buscar **vulnerabilidades ya
conocidas** (CVE). Es opcional (`--cve`) porque necesita internet. Va **aparte de las alertas**:
una alerta es un hecho observado ("sirve Telnet"); un CVE es una hipótesis que depende de cuánto
sabemos del dispositivo.

### Fuentes y vocabulario

- **CVE**: identificador público de una vulnerabilidad (CVE-AAAA-NNNN).
- **NVD** (NIST): base de datos que enriquece cada CVE con su gravedad (**CVSS**, 0-10) y con
  **qué productos afecta**, escritos como **CPE**.
- **CPE**: nombre normalizado de un producto,
  `cpe:2.3:parte:fabricante:producto:versión:...`, donde la parte es `h` (hardware),
  `o` (sistema operativo o firmware) o `a` (aplicación). En IoT, NVD suele escribir "el firmware
  `o:brother:hl-l2350dw_firmware` (vulnerable) sobre el hardware `h:brother:hl-l2350dw`".
- **CISA KEV**: catálogo de CVE que **se están explotando** de verdad. Sirve para priorizar.

### De la teoría al código

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Buscar el CVE por el texto del modelo no funciona: NVD empareja por CPE | `find_products()` | `vulns.py:165-188` | Busca el modelo en el diccionario CPE y se queda con los productos cuyo nombre aparece **tal cual** en el modelo (`_appears_in`, `:160-162`): `hl-l2350dw` sí casa con "Brother HL-L2350DW series"; `hl-l2350` y `dcp-1610w` no. Quita palabras que no están en CPE ("series", `MODEL_NOISE`, `:63`) |
| Software reconocible aunque no anuncie modelo | `SERVICE_PRODUCTS` | `vulns.py:58-60`, `device_products()` `:191-198` | `_esphomelib._tcp` → `esphome:esphome`; su `version=` es la del software |
| CVE de un producto en NVD | `product_cves()` | `vulns.py:262-277` | `virtualMatchString=cpe:2.3:*:fabricante:producto` (cualquier parte) y, si existe, también `..._firmware` |
| Niveles de certeza: fabricante < modelo < modelo + firmware | `assess()` | `vulns.py:229-243` | **modelo+firmware** si la versión anunciada cae en el rango vulnerable; **modelo** si no hay versión o NVD no da rango; si el rango la excluye, el CVE **se descarta** |
| Rangos de versión de NVD | `version_in_range()`, `_vkey()` | `vulns.py:205-226` | Versión exacta en el CPE, o `versionStart/EndIncluding/Excluding`; compara las versiones como números (`2024.6.1` → `(2024, 6, 1)`) |
| Gravedad | `_cvss()` | `vulns.py:246-253` | CVSS v4.0, si no v3.1, v3.0 o v2 (la "Primary", que es la de NVD) |
| KEV marca, no busca | `load_kev()` | `vulns.py:280-283` | Solo dice si un CVE encontrado por modelo está en KEV. Buscar en KEV por fabricante es ruido: "Google" tiene decenas de entradas de Chrome/Chromium que nada tienen que ver con un Chromecast. Por eso **solo con el fabricante no se busca** |
| NVD sin clave admite 5 peticiones cada 30 s | `Client._throttle()` | `vulns.py:112-118` | 6 s entre consultas (0,6 s con `NVD_API_KEY`); KEV no cuenta |
| No repetir consultas | `Client._cache_read/_cache_write` | `vulns.py:120-143` | Caché en disco de 24 h (`~/.cache/iot_scanner`, `--cve-cache`); si falla, se sigue sin caché |
| Privacidad: qué sale a internet | `lookup_all()` | `vulns.py:315-339` | Solo el modelo (lo anuncia el propio dispositivo a toda la red) y nombres CPE; nunca MAC, IP ni hostname. User-Agent genérico |
| Lo que llega de internet tampoco es de fiar | `_http_get_json()`, `_summary()` | `vulns.py:72-78`, `:256-259` | Solo `https`, timeout de 30 s, como mucho 32 MB; la descripción se limpia de caracteres de control y se recorta a 160 |
| Sin red no se rompe nada | `Client.get()` | `vulns.py:95-110` | Un error de red o un JSON roto cuenta como error y se avisa; el informe indica que puede estar incompleto |

### En el informe

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| CVE separado de las alertas | `build_cve_list()`, `print_cves()` | `report.py:94-99`, `:235-252` | Sección "Vulnerabilidades conocidas", con certeza, KEV y cuántos se descartaron por versión |
| Solo un CVE tan seguro y urgente como un Telnet abierto se convierte en alerta | bucle `for c in dev.cves` | `report.py:85-90` | Alerta ALTA si está en **KEV** y la certeza es **modelo+firmware**; sin puerto (`-`) |
| JSON/CSV | `Device.cves`, `_cve_cell()` | `device.py:29`, `report.py:280-281` | `cves` por dispositivo; en el CSV `CVE-… (CVSS, certeza, KEV)` |
| GUI | pestaña CVE, casilla | `gui.py:209-212`, `:256-263`, `:466-472` | Casilla "Buscar CVE conocidos"; pestaña aparte con las filas KEV en rojo; columna CVE en la tabla |
| CLI | `--cve`, `--cve-cache` | `net_device_scanner.py:65-68`, `:124-125` | Se busca después de clasificar |

### Ejemplo con datos reales (NVD, 2026-11-16)

| Dispositivo | Qué sabemos | Resultado |
|---|---|---|
| Brother HL-L2350DW | modelo, sin versión | 3 CVE (CVE-2019-13192/13193/13194), certeza **modelo** |
| Chromecast | modelo (`md=Chromecast`), sin versión (`ve` es el protocolo) | 6 CVE, certeza **modelo** |
| Sensor ESPHome 2024.6.1 | software + versión | 3 CVE de ESPHome, **los 3 descartados**: la versión está fuera de los rangos |
| (prueba) ESPHome 2024.1.0 | software + versión | CVE-2024-27287 (rango 2023.12.9–2024.2.2), certeza **modelo+firmware** |

El ejemplo de ESPHome muestra para qué sirve la versión: sin ella, se habrían listado 3 CVE que
no le afectan.

**Limitaciones:**
- Solo se encuentran dispositivos cuyo modelo esté en el diccionario CPE con un nombre parecido.
- La comparación de versiones solo mira los números (`1.0-beta` y `1.0` se ven iguales).
- Con más de 200 CVE por producto solo se ven los primeros (se avisa).
- "Certeza modelo" significa "este modelo ha tenido este fallo", no "este equipo lo tiene":
  puede que ya esté actualizado.

---

## Hito 4 — Informe (`iot_scanner/report.py`)

_Pendiente de revisar._
