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
| Aislamiento de clientes (AP isolation) | `if not devices: mode = "fallback-sniff-only"` | `net_device_scanner.py:100-107` | Si nadie responde al ARP, pasa a escucha pasiva (mín. 30 s) |

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
| Captura pasiva (no se envía nada) | `AsyncSniffer(iface, prn=..., store=False)` | `sniffer.py:528-563` | Llama a `handle_packet` por cada paquete en un hilo aparte; `store=False` no guarda los paquetes en memoria (ver "Escucha parable") |
| Análisis offline reproducible | `rdpcap(path)` | `sniffer.py:594` | Mismo procesado sobre un `.pcap` (comparable con Wireshark) |
| La MAC de origen identifica al emisor | `pkt[Ether].src` | `sniffer.py:447` | Clave para agrupar |
| `0.0.0.0` / `::` = "sin dirección" (DHCP sin IP, ruta sin gateway) | `is_unspecified(ip)` con `ipaddress` | `discovery.py:26-31` | Sustituye las comparaciones con el literal `"0.0.0.0"` (avisos B104 de bandit) |
| Bit I/G (0x01): multicast/broadcast no son emisores reales | `_is_unicast(mac)` | `sniffer.py:79-80`, `:448` | Descarta orígenes multicast; también se ignora la MAC propia |
| Un dispositivo nuevo visto solo en pasivo | `_get_device(...)`, `source="pasivo"` | `sniffer.py:435-441` | Lo crea con fabricante por OUI (reutiliza el Hito 1) |
| ARP gratuito / respuestas ARP de otros | `pkt[ARP].psrc` | `sniffer.py:455-459` | Saca la IP aunque haya aislamiento de clientes |
| IP de origen (capa 3) | `pkt[IP].src` | `sniffer.py:461-465` | Rellena la IP si aún no se tiene (ignora `0.0.0.0` de DHCP) |

### Puertos: cliente vs. servidor (capa 4)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Handshake TCP: SYN → SYN+ACK → ACK; quien manda SYN+ACK es el servidor | `pkt[TCP].flags & 0x12 == 0x12` | `sniffer.py:479-480` | SYN (0x02) + ACK (0x10) → el puerto origen es un servicio que ofrece (`ports_src`) |
| Puerto destino = servicio al que se conecta (cliente) | `dev.add("ports_dst", dport)` | `sniffer.py:495-496` | Ej.: 1883 = se conecta a un broker MQTT |
| Puertos efímeros (IANA ≥ 49152) son del cliente, ruido | `dport < EPHEMERAL_START` | `sniffer.py:39`, `:495` | No guarda puertos efímeros |
| UDP no tiene handshake: puerto origen bajo ≈ servicio propio | `sport < 1024 and sport not in UDP_CLIENT_LOW_PORTS` | `sniffer.py:44`, `:498-500` | DHCP (67/68) y NTP (123) se excluyen porque el cliente también los usa como origen |
| Servicios UDP altos que delatan a un servidor | `UDP_SERVER_PORTS = {1900, 5683, 5684, 5540}` | `sniffer.py:41` | SSDP/UPnP, CoAP (5683) / CoAP sobre DTLS (5684) y Matter (5540) |

### Capa 7: lo que el dispositivo cuenta de sí mismo

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| DHCP opción 12 = hostname que pide el cliente | `opt[0] == "hostname"` | `sniffer.py:123-124` | Fuente preferida de hostname |
| DHCP opción 60 = vendor class (cliente DHCP / SO) | `opt[0] == "vendor_class_id"` | `sniffer.py:125-130` | Banner `DHCP:...` (ej. `udhcp`, `android-dhcp`, `MSFT 5.0`) |
| mDNS = DNS multicast en `224.0.0.251:5353`, nombres `.local` | `PORT_MDNS in (sport, dport)` | `sniffer.py:33`, `:509-510` | Separa mDNS del DNS normal por el puerto |
| DNS-SD: servicios `_servicio._tcp.local` | `re.search(r"(_[\w\-]+\._(?:tcp\|udp))\.local$", name)` | `sniffer.py:197-199` | Ej.: `_googlecast._tcp` = Chromecast, `_hap._tcp` = HomeKit |
| Registro A (1) / AAAA (28) en respuesta mDNS = "mi nombre es X.local" | `dns.qr == 1 and rr.type in (1, 28)` | `sniffer.py:201-202` | Hostname por mDNS (solo si DHCP no dio uno) |
| Secciones DNS (qd, an, ar) son listas en Scapy ≥ 2.5 | `_dns_records(section)` | `sniffer.py:87-97` | Recorre los registros en ambos formatos (lista y encadenado) |
| DNS: `qr = 0` es consulta | `if dns.qr == 0` | `sniffer.py:235-239` | Dominios que resuelve (a qué nube habla: `hik-connect.com`, `tuyaeu.com`...) |
| SSDP/UPnP: anuncios HTTP sobre UDP 1900 | `key in ("SERVER", "USER-AGENT")` | `sniffer.py:300-304` | Banner con SO y modelo (ej. `Linux/3.10 UPnP/1.0 IPCamera`) |

### Seguridad: el texto de la red es entrada no confiable

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Inyección vía campos de red (riesgo del PDF) | `_SAFE_CHARS = re.compile(r"[^A-Za-z0-9 ._\-:/()+@,=]")` | `sniffer.py:66` | Lista blanca: todo lo demás se borra (secuencias ANSI, `<`, `;`, comillas, saltos de línea) |
| Limitar longitud | `value[:max_len]` | `sniffer.py:76` | 64 caracteres por defecto (128 nombres DNS, 96 banners SSDP) |
| Bytes con codificación inválida | `decode("utf-8", errors="ignore")` | `sniffer.py:74` | No revienta con bytes basura |
| Un dispositivo ruidoso no infla la memoria | `MAX_ITEMS = 64` | `device.py:6`, `:38-42` | Máximo 64 elementos por conjunto |

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
| NTP = UDP 123; casi todo IoT sincroniza la hora y el servidor elegido delata al fabricante | `PORT_NTP in (sport, dport) and pkt.haslayer(NTP)` | `sniffer.py:502-503` | Scapy disecciona el NTP; se marca el protocolo |
| Campo `mode` del NTP: 3 = cliente, 4 = respuesta de servidor, 5 = broadcast | `_parse_ntp(pkt, dev, ip_dst)` | `sniffer.py:311-318` | Cliente → guarda la IP del servidor en `ntp_servers`; servidor → `ports_src` 123 |
| ntpd usa el 123 también como puerto origen del cliente | `UDP_CLIENT_LOW_PORTS = {67, 68, 123}` | `sniffer.py:44`, `:499` | Evita marcar como "servidor NTP" a un cliente (falso positivo que tenía el Hito 2) |

### TLS: el nombre del servidor viaja en claro (SNI)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| HTTPS va cifrado, pero el primer mensaje (ClientHello) no: lleva el SNI para que el servidor sepa qué certificado dar | `tls_sni(data)` → `parse_client_hello(data)` | `sniffer.py:360-420` | Parser manual del ClientHello sin dependencias |
| Registro TLS `0x16` (handshake), versión `0x03xx`, mensaje `0x01` (ClientHello) | `data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01` | `sniffer.py:374` | Descarta todo lo que no es un ClientHello |
| Estructura: versión, random (32), session id, cipher suites, compresión, extensiones | `pos += ...` | `sniffer.py:376-382` | Salta los campos de longitud variable leyendo su longitud |
| Extensión `0x0000` = server_name; tipo 0 = host_name | `ext_type == 0x0000` | `sniffer.py:393-397` | Devuelve el nombre; si está cortado, `None` |
| Entrada no confiable | `sanitize_text(hello["sni"], 128)` | `sniffer.py:485-487` | El SNI se sanea igual que hostname y banners |
| Un dominio es un dominio, venga de DNS o de TLS | `seen = [("consulta", d) ...] + [("TLS a", d) ...]` | `heuristics.py:209-216` | El SNI alimenta la misma regex `domains` de las reglas; cuenta como una sola evidencia |

### Matter / Thread: IPv6 y mDNS

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Matter va sobre IPv6 (link-local `fe80::`) y se anuncia por mDNS en `ff02::fb` | `elif pkt.haslayer(IPv6)` | `sniffer.py:466-470` | Guarda las direcciones IPv6 en `ipv6` (antes se perdían) |
| Matter operativo = UDP 5540 | `PORT_MATTER = 5540` en `UDP_SERVER_PORTS` | `sniffer.py:37`, `:41` | Puerto servido |
| DNS-SD de Matter: `_matter._tcp` (ya emparejado), `_matterc._udp` (por emparejar), `_matterd._udp` (controlador) | regla `Dispositivo Matter` | `rules.json:57-62` | La regex de servicios mDNS del Hito 2 ya los captura sin cambios |
| Thread no es IP en tu WiFi: solo se ve su border router (`_meshcop._udp`, `_trel._udp`) | regla `Border router Thread / controlador Matter` | `rules.json:63-67` | Identifica el puente, no los nodos Thread |

### WS-Discovery / ONVIF: la cámara dice qué es (añadido el 2026-10-26)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| WS-Discovery = SOAP/XML por UDP 3702 a `239.255.255.250` / `ff02::c` (multicast: llega sin port mirroring) | `PORT_WSD in (sport, dport)` | `sniffer.py:38`, `:515-516` | Activa el extractor |
| Quién envía cada mensaje: `Hello`/`Bye`/`ProbeMatches` el dispositivo descubierto; `Probe`/`Resolve` quien busca (NVR, app, Windows) | `WSD_TARGET_ACTIONS`; `action not in ...` | `sniffer.py:48`, `:333-335` | Solo el dispositivo descubierto gana tipos y `ports_src` 3702; un `Probe` no lo convierte en cámara |
| `Types`: qué es (`dn:NetworkVideoTransmitter` = cámara ONVIF, `PrintDeviceType`, `pub:Computer`) | `_WSD_TYPES`; `dev.add("wsd_types", ...)` | `sniffer.py:53`, `:336-338` | Se guarda el nombre sin prefijo XML |
| `Scopes` ONVIF: `onvif://www.onvif.org/name/...`, `/hardware/...` (modelo) | `ONVIF_SCOPE_KEYS`; `unquote` | `sniffer.py:55`, `:339-344` | Banners `ONVIF:hardware=DS-2CD2043G2-I`, `ONVIF:name=...` (sirven a la regex de texto y, en el futuro, a buscar CVE por modelo) |
| XML no confiable: un parser XML se expone a entidades externas (XXE) o expansión de entidades | regex acotadas `{0,256}`, `[^<]`; `WSD_MAX_BYTES = 8192` | `sniffer.py:49-54` | Sin parser, sin backtracking catastrófico, tamaño limitado y texto saneado |
| El tipo lo declara el propio dispositivo y es muy específico | `rule.wsd & dev.wsd_types` → `WEIGHT_STRONG` | `heuristics.py:182-183` | +3 para cámara, impresora o Windows |
| ONVIF activo revela el modelo | `SENSITIVE_SERVED[3702]` | `report.py:39` | Alerta BAJA: revisar la autenticación ONVIF |

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
| DNS-SD (RFC 6763): cada servicio mDNS puede llevar un registro TXT (tipo 16) con pares `clave=valor` | `rr.type == TXT_TYPE` | `sniffer.py:61`, `:204-205` | Solo en respuestas (`qr = 1`), que son lo que el dispositivo dice de sí mismo |
| En Scapy ≥ 2.5 el `rdata` de un TXT es una lista de bytes | `_txt_pairs(rdata)` | `sniffer.py:208-218` | Decodifica, separa por el primer `=`, sanea clave (32) y valor (96) y lee como mucho 32 pares |
| Las claves no distinguen mayúsculas (RFC 6763, 6.4); una clave sin `=` es un booleano | `key.lower()`; `value = None` | `sniffer.py:217` | `MODEL=` cuenta como `model=`; `solo_clave` se guarda tal cual |
| Cada fabricante usa sus claves para modelo y versión | `TXT_MODEL_KEYS`, `TXT_FIRMWARE_KEYS` | `sniffer.py:62-63` | Modelo: `md` (Google), `model`, `ty` y `product` (impresoras), `app` (Shelly). Firmware: `ver` (Shelly), `version` (ESPHome), `fw_id`, `osvers`… |
| No todo lo que parece versión es firmware | (excluidas a propósito) | `sniffer.py:57-60` | `txtvers` = versión del **formato** del TXT; `ve` en Chromecast = versión del **protocolo** |
| Trazabilidad: guardar todo, interpretar solo lo conocido | `mdns_txt`, `models`, `firmware` | `sniffer.py:221-229`, `device.py:26-28` | Todos los pares en `mdns_txt`; modelo y firmware en campos propios para la futura búsqueda de CVE |
| El modelo es texto que el dispositivo dice de sí mismo | `own = hostname + models + banners` | `heuristics.py:200` | Pesa +2 en las reglas (frente a +1 del fabricante por OUI) |
| Privacidad: los TXT llevan identificadores (`id`, `deviceid`, `mac`) y nombres del usuario (`fn=Salón de Oscar`, `note=Despacho`) | `SAFE_TXT_KEYS` (lista blanca), `_keep_txt()` | `report.py:235-242`, `:276` | Con `--anonymize` solo quedan las claves técnicas (modelo, versiones, plataforma…) |

Límites: el saneado solo admite ASCII (`Salón` queda como `Saln`); no todos los
fabricantes usan las mismas claves, así que habrá TXT con versión que no se reconozcan
(quedan en `mdns_txt` para revisarlos a mano); y un TXT solo llega si el dispositivo
anuncia servicios por mDNS.

### Escucha parable (2026-10-26)

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Captura en un hilo aparte que se puede parar | `AsyncSniffer(...)`, `capture.start()` | `sniffer.py:553-555` | Sustituye a `sniff(timeout=...)`, que bloqueaba hasta agotar el plazo |
| En Scapy 2.8 `AsyncSniffer` no admite `timeout` | `deadline = time.monotonic() + seconds` | `sniffer.py:568-578` | El plazo lo controla el bucle, con esperas cortas de 0,2 s que atienden `stop_event` y Ctrl+C (también en Windows) |
| Carrera: un `stop()` antes de que el hilo empiece a capturar se ignora | `_stop_capture()` + reintentos | `sniffer.py:519-525`, `:580-583` | Reintenta hasta 5 s hasta que la captura para de verdad |
| Los errores del hilo no deben perderse | `raise capture.exception` | `sniffer.py:584-585` | Sin permisos o sin Npcap, el error llega a la CLI o a la GUI |
| Se analiza lo capturado hasta el corte | `listened = round(time.monotonic() - t0)` | `net_device_scanner.py` (`run_live`) | El informe guarda los segundos escuchados de verdad |
| Botón Detener solo durante la escucha | `self.stop_btn`, `self.stop_event.set()` | `gui.py` (`_start`, `_stop`) | Activo en modos con escucha en vivo; se desactiva al terminar |

### Guardar la captura: `--save-pcap` (2026-11-19)

Para el Hito 6: una sola captura que luego se abre en Wireshark y se vuelve a analizar con
`--pcap` las veces que haga falta (al cambiar una regla o un peso, mismo tráfico de entrada).

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Guardar como Wireshark: todo lo que llega, sin filtrar | `PcapWriter(..., sync=True)` + `handle(pkt)` | `sniffer.py:544-551` | Cada paquete se escribe **antes** de analizarlo, también los del propio equipo (el análisis los descarta, la captura no) |
| Detener o Ctrl+C no deben perder la captura | escritura paquete a paquete y `writer.close()` en `finally` | `sniffer.py:554-559` | El fichero queda completo y cerrado aunque se corte o falle la captura (sin permisos) |
| La espera de la captura, aparte | `_wait_capture()` | `sniffer.py:566-586` | El mismo bucle de antes (plazo, `stop_event`, Ctrl+C, reintentos), movido a una función |
| Solo tiene sentido con escucha en vivo | `p.error(...)` | `net_device_scanner.py:79` | No se combina con `--pcap` ni con `--no-sniff`; con `-t 0` avisa de que no se guarda nada |
| La captura es un dato sensible (todo el tráfico en claro) | aviso en el registro, `.gitignore` | `sniffer.py:545-546` | Excluida de git (`*.pcap`); con `--anonymize` el informe solo guarda el nombre del fichero |
| GUI | casilla y diálogo "Guardar captura" | `gui.py:217-220`, `:356-362` | Solo activa en modos con escucha; si se cancela el diálogo, no se empieza |

La fase de ARP scan no se guarda (la hace `srp` antes de escuchar): la captura empieza con la
escucha pasiva.

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
| Lo que el dispositivo dice de sí mismo pesa más que su fabricante | `own = hostname + banners` → +2; si no, `vendor` → +1 | `heuristics.py:197-207` | **Fabricante ≠ tipo**: un móvil Google ya no pasa de "baja" como TV |
| Dominio de la nube del fabricante → fuerte | `WEIGHT_STRONG` | `heuristics.py:209-216` | `hik-connect.com`, `tuyaeu.com` (DNS o SNI de TLS) |
| El peso solo afecta a identificar, no al riesgo | (sin cambios en `report.py`) | `report.py:27-48` | El 80 y el 1900 siguen generando sus alertas de seguridad |

### Las reglas

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Una regla = un tipo de dispositivo + sus pistas | `@dataclass class Rule` | `heuristics.py:51-70` | Campos: `served_ports`, `client_ports`, `mdns`, `text` (regex), `domains` (regex) |
| Cada pista viene de una señal del Hito 2 | campos de `Rule` ↔ campos de `Device` | `heuristics.py:54-59` | `served_ports`↔`ports_src`, `client_ports`↔`ports_dst`, `mdns`↔`mdns_services`, `text`↔hostname+banners (o fabricante), `domains`↔`dns_queries`+`tls_sni` |
| La regex de texto solo casa al **inicio de palabra** | `(?<![a-z])(?:...)` en `__post_init__` | `heuristics.py:65-70` | `esp` casa con `ESP_32AB` y `esp32-x` pero no con `despacho-pc`; por la derecha no se limita para no perder `IPCamera` |
| Base de conocimiento | `"rules": [...]` → `RULES` | `rules.json:14-112`, `heuristics.py:149-158` | 15 tipos: cámara, TV, altavoz, MQTT, CoAP, enchufe, Matter, Thread, UPnP, impresora, router, NAS, Apple, Windows, Android |

### Evaluar una regla: reunir evidencias

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Coincidencia por intersección de conjuntos | `rule.served_ports & dev.ports_src` | `heuristics.py:173-176` | Cada puerto que coincide es una evidencia, con su peso |
| **Sin doble conteo**: un puerto servido no vuelve a contar como cliente | `(rule.client_ports & dev.ports_dst) - served` | `heuristics.py:177-178` | Un solo paquete SSDP 1900 → 1900 es una pista, no dos |
| Servicios mDNS | `rule.mdns & dev.mdns_services` | `heuristics.py:179-180` | Una evidencia por servicio |
| Dominios (DNS y SNI) | `seen = [...]` + `break` | `heuristics.py:209-216` | **Una** evidencia como máximo, venga de DNS o de TLS |
| Evidencias explicables **con su peso** | `f"{desc} (+{w})"` | `heuristics.py:231` | El informe muestra, p. ej., `sirve puerto 554 (+2)`: el analista ve por qué y cuánto |

### Puntuar y decidir

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Puntuación = suma de pesos | `score = sum(w for _, w in ev)` | `heuristics.py:226` | Un 37777 (3) ya no vale lo mismo que un 80 (1) |
| Umbrales sobre la suma | `"confidence_levels"` → `CONFIDENCE_LEVELS`; `_confidence()` | `rules.json:9-13`, `heuristics.py:163-167` | Una pista fuerte sola = media; para alta hacen falta varias pistas |
| Varias hipótesis ordenadas | `candidates.sort(...)`; `[:max_labels]` | `heuristics.py:233-234` | Hasta 3 etiquetas; en empate gana la regla que va antes en `RULES` |
| Sin evidencias, sin etiqueta | `if ev:` | `heuristics.py:225` | Un dispositivo sin pistas queda "Sin identificar" (mejor que inventar) |
| Se ejecuta tras el sniffing | `heuristics.classify_all(devices)` | `net_device_scanner.py:135` | Rellena `dev.labels` para el informe (Hito 4) |

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
| Separar datos (conocimiento) de código (motor): reglas nuevas sin tocar Python | `rules.json` + `load_rules()` | `rules.json`, `heuristics.py:125-146` | Reglas, pesos y umbrales en un fichero; se cargan al importar (`use_rules()`, `heuristics.py:160`) |
| JSON y no YAML | — | — | Sin dependencia nueva (PyYAML no compilaba en Python 3.15) y sin el riesgo de cargar YAML con etiquetas de objetos |
| Validar la entrada: una errata no debe pasar en silencio | `unknown = set(d) - _RULE_FIELDS`; `re.compile(...)` | `heuristics.py:99-101`, `:118` | Campos desconocidos, puertos fuera de 1-65535 o regex mal escritas → `ValueError` con el nombre de la regla |
| Reglas propias del analista | `--rules fichero.json` → `use_rules(path)` | `net_device_scanner.py:67`, `:128-129` | Cambia las reglas sin editar el paquete. El fichero es configuración de confianza: una regex mal hecha puede ser lenta (ReDoS) |

### print() → logging

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Separar **salida** (la tabla, el resumen: stdout) de **registro** (progreso y avisos: stderr / fichero) | `setup_logging()` | `logsetup.py:29-58` | `print_table`/`print_summary` siguen con `print`; el resto pasa a `logging` |
| Niveles: DEBUG (detalle), INFO (progreso), WARNING/ERROR (avisos) | `ConsoleFormatter` | `logsetup.py:19-26` | En consola se mantiene el estilo `[*]` / `[!]`; `[.]` para depuración |
| Registro persistente para depurar | `--log scanner.log`, `-v` | `net_device_scanner.py:72-73`, `logsetup.py:50-54` | El fichero recibe todo (DEBUG) con fecha y módulo |
| Un logger por módulo bajo `iot_scanner` | `log = logging.getLogger(__name__)` | todos los módulos | La GUI cuelga su propio handler para la pestaña Registro (`gui.py:120`) |

El registro y la consola **no se anonimizan**: son para el analista. Solo los ficheros
exportados con `--anonymize` llevan seudónimos.

### --anonymize: Privacy by Design

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| **Seudonimizar** (RGPD art. 4.5): sustituir identificadores por seudónimos | `anonymize(devices, meta)` | `report.py:266-292` | MAC, IP, IPv6, hostname, nombre ONVIF, interfaz y ruta del `.pcap` (leído o guardado) |
| **Minimización**: conservar solo lo necesario para analizar | (se mantienen) | `report.py:266-292` | Fabricante, puertos, protocolos, servicios, dominios, tipo y alertas siguen en claro |
| Un hash (incluso con sal) no anonimiza: 2³² IPv4 se prueban en segundos | `hmac.new(key, ..., sha256)` | `report.py:220-229` | HMAC-SHA256 con clave aleatoria de 32 bytes por informe (`secrets`), no guardada: irreversible |
| Coherencia dentro del informe | `pseudo(kind, value)` | `report.py:220-229` | El mismo dispositivo tiene el mismo seudónimo en JSON, CSV y alertas; distinto en otro informe |
| Datos que escribe el usuario pueden delatar dónde está | `_anonymize_banner()` | `report.py:259-263` | `ONVIF:name=HIKVISION Entrada` → `ONVIF:name=name-…` |
| La ruta del `.pcap` lleva el usuario del equipo | `re.split(r"[\\/]", ...)` | `report.py:286-290` | `C:\Users\…\lab.pcap` → `lab.pcap`, también en Linux (`os.path.basename` solo entiende el separador del sistema: fallo de la CI del 2026-10-26) |
| Solo afecta a lo exportado | `export()` | `net_device_scanner.py:141-153`; casilla en `gui.py:310` | La tabla en pantalla sigue mostrando los datos reales |

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
| Cobertura de **reglas** (lo que pedía Qwen: ≥ 80 %) | `extra_rule_packets()`, `EXTRA_EXPECTED` | `tests/lab_packets.py:135-258` | Un dispositivo sintético por cada regla que el laboratorio no ejercitaba: 15 de 15 |

### Filtro en la tabla de la GUI

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Filtrar sin perder datos: ocultar filas, no borrarlas | `tree.detach` / `tree.reattach` | `gui.py:577-590` | Busca el texto en IP, MAC, fabricante, hostname y tipo mientras se escribe; muestra "N de M" |

## Mejoras propuestas por Kiro (2026-11-19): JA3, DHCPv6, riesgo y eTLD+1

El autor eligió 4 de la lista de **Kiro**; de las otras, TXT de mDNS y la opción 55 de DHCP ya
estaban y el SNI de QUIC se descartó (detalle en `AI_USAGE.md`).

### Huella TLS: JA3

JA3 (Salesforce, 2017) resume el ClientHello en
`versión,cifrados,extensiones,curvas,formatos de punto`: cada lista son los números en el
orden en que llegan, separados por `-`, y la huella es su MD5. Depende de la **librería TLS del
cliente** (mbedTLS de un ESP32, OpenSSL de un Linux), no del servidor ni del dominio. En IoT es
muy estable porque el firmware no cambia de librería. En navegadores ya no sirve: Chrome desordena
las extensiones desde 2023, y para eso existe JA4.

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Un único parser para SNI y JA3 | `parse_client_hello()` | `sniffer.py:360-409` | Devuelve `{"sni", "ja3"}`; `tls_sni()` (`:417-420`) sigue igual para lo que ya lo usaba |
| GREASE (RFC 8701): valores `0x?a?a` al azar que cambian en cada conexión | `TLS_GREASE` | `sniffer.py:353` | JA3 los quita; si no, la huella cambiaría en cada conexión |
| Curvas (extensión 10) y formatos de punto (11) | `ext_type == 0x000A / 0x000B` | `sniffer.py:399-402` | Se leen en el mismo recorrido de las extensiones |
| ClientHello partido en varios segmentos TCP | `complete` | `sniffer.py:384`, `:405-408` | Si la lista de extensiones no está entera, **no** hay JA3 (saldría una huella falsa); el SNI sí, si llegó |
| MD5 como identificador, no como protección | `ja3_hash()` | `sniffer.py:412-414` | `usedforsecurity=False` (bandit lo acepta) |
| Pista fuerte en las reglas | campo `ja3` | `heuristics.py:62`, `:194-195` | Coincidencia exacta del MD5 (+3). Sin reglas todavía: las huellas reales saldrán del Hito 6 |

### DHCPv6: nombre y vendor class

Los dispositivos solo IPv6 (Matter, Thread) no usan DHCPv4, así que su nombre no llegaba por la
opción 12. En DHCPv6 (RFC 8415) el cliente habla desde el puerto **546** y puede mandar:

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Solo cuenta lo que manda el cliente | `sport == PORT_DHCP6_CLIENT` | `sniffer.py:136`, `:507` | Las respuestas del servidor (547) no describen al dispositivo |
| En Scapy los mensajes (Solicit, Request…) son subclases de `DHCP6`, y `haslayer()` no las reconoce | `issubclass(layer, DHCP6)` | `sniffer.py:141` | Comprueba las capas a mano |
| Opción 39, Client FQDN (RFC 4704) | `DHCP6OptClientFQDN` | `sniffer.py:144-148` | Primera etiqueta como hostname, **solo si no había** (DHCPv4 y mDNS mandan) |
| Opción 16, Vendor Class (número de empresa de IANA + textos) | `DHCP6OptVendorClass` | `sniffer.py:149-154` | Banner `DHCPv6:...` saneado, como mucho 8 |

### Riesgo combinado por dispositivo

Un único nivel por dispositivo para decidir qué revisar primero. Resume sus alertas y sus CVE
**fiables**; los CVE por fabricante son una suposición y no cuentan.

| Nivel | Cuándo |
|---|---|
| ALTO | alguna alerta ALTA (Telnet abierto, CVE en KEV con la versión vulnerable…) |
| MEDIO | alguna alerta MEDIA; un CVE con la versión confirmada (modelo+firmware) y CVSS ≥ 7; o un CVE en KEV con certeza de modelo |
| BAJO | cualquier otra alerta o CVE fiable |

| Código | Dónde | Qué hace |
|---|---|---|
| `_cve_risk()` | `report.py:145-150` | Riesgo que aporta un CVE según su certeza, CVSS y KEV |
| `device_risk()` | `report.py:153-169` | El peor nivel de sus alertas y CVE, con los motivos ("3 alertas (peor: MEDIA); 4 CVE fiables (CVSS máx. 7.5)") |
| `build_risk()` | `report.py:172-181`, `:198` | Lista ordenada en el resumen; columna `riesgo` en el CSV y en la tabla de la GUI (ordena por gravedad, no por orden alfabético) |

**Decisión discutible:** un CVE con CVSS 10 pero sin versión confirmada (el Chromecast del
ejemplo) se queda en BAJO, porque no sabemos si el equipo está actualizado.

### DNS y SNI al dominio registrable (eTLD+1) al anonimizar

`--anonymize` conservaba las consultas DNS y el SNI completos (riesgo residual del modelo de
amenazas). Ahora guarda solo el **dominio registrable**: `api.eu.hik-connect.com` →
`hik-connect.com`. Eso basta como evidencia (dice con qué nube habla) y se pierde lo que
puede delatar al usuario (cuentas, IDs, ciudades en el subdominio).

No vale quedarse con "las dos últimas etiquetas": `news.bbc.co.uk` daría `co.uk`. Hace falta la
**Public Suffix List** (Mozilla), que dice qué partes son sufijos públicos (`com`, `co.uk`,
`com.es`, `github.io`…).

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Lista copiada en el repositorio (342 KB, MPL-2.0), sin internet | `public_suffix_list.dat` | `iot_scanner/` | Versión del 2026-11-17; se actualiza con un `curl` (instrucciones en `psl.py`) |
| Formato: reglas normales, comodines `*.ck` y excepciones `!www.ck` | `load()` | `psl.py:40-56` | Reglas internacionales pasadas a punycode, como llegan en el tráfico |
| Sufijo más largo que casa; si ninguno, regla por defecto `*` | `registrable_domain()` | `psl.py:68-88` | Sufijo + una etiqueta |
| También en las **evidencias** de las etiquetas | `_anonymize_labels()` | `report.py:247-256` | "consulta dev.hik-connect.com (+3)" → "consulta hik-connect.com (+3)"; si no, el dominio completo seguía en el informe |
| Al anonimizar | `anonymize()` | `report.py:279-280` | La identificación se hace antes, con los dominios completos: no cambia |

---

## Mejoras propuestas por Qwen (2026-11-19, tercera lista): huella DHCP y EUI-64

De la tercera lista de **Qwen** el autor eligió 2; la tercera (TXT de mDNS) ya estaba hecha.

### Huella DHCP: opción 55 (Parameter Request List)

Al pedir IP, el cliente DHCP dice **qué opciones quiere** (máscara = 1, router = 3, DNS = 6,
nombre de dominio = 15…) y **en qué orden**. Esa lista la fija el cliente DHCP del sistema
operativo (Android, Windows, udhcp de BusyBox, lwIP de un ESP32…), no el usuario, así que es
una huella pasiva del SO o firmware. Ojo: Qwen la confundía con `requested_addr`, que es la
**opción 50** (la IP que el cliente pide).

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| RFC 2132, opción 55: lista de códigos de opción, en orden | `opt[0] == "param_req_list"` | `sniffer.py:121-122` | Scapy la da como lista de enteros |
| Formato de las bases de huellas (Fingerbank): `"1,3,6,15"` | `dhcp_fingerprint()` | `sniffer.py:104-113` | Solo enteros 0-255 y como mucho 64; el orden se conserva porque forma parte de la huella |
| Pista fuerte en las reglas | campo `dhcp_fp` | `heuristics.py:61`, `:191-192` | Coincidencia **exacta** (+3); `"3,1,6,15"` no es `"1,3,6,15"` |

**Lo que falta:** la huella sola no identifica nada sin una tabla huella → sistema. La base de
referencia (Fingerbank) no es libre para usarla sin conexión, y las huellas no se inventan: el
campo queda listo y las reglas se rellenarán con las huellas **reales** de los dispositivos
del laboratorio (Hito 6). La lista del tráfico sintético es de ejemplo.

### Fuga de la MAC en IPv6 (EUI-64)

Una IPv6 tiene 64 bits de red y 64 de **identificador de interfaz**. Con EUI-64 (RFC 4291,
apéndice A) ese identificador sale de la MAC: se parte en dos, se mete `ff:fe` en medio y se
invierte el bit U/L. `b8:27:eb:00:00:13` → `ba27:ebff:fe00:13`.

- En una dirección **link-local** (`fe80::`) es lo normal y **no filtra nada**: no sale de la
  red local, donde la MAC ya se ve en cada trama. (Qwen proponía marcar también estas.)
- En una dirección **global** (`2000::/3`) sí: viaja a internet con la MAC dentro, y el
  dispositivo se puede seguir de una red a otra aunque cambie el prefijo. Lo evitan las
  direcciones temporales (RFC 4941) y las estables opacas (RFC 7217).

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Sacar la MAC del identificador de interfaz | `eui64_mac()` | `sniffer.py:165-174` | Comprueba `ff:fe` en los bytes 3-4 del identificador y deshace el bit U/L |
| Solo las globales filtran | `leaks_mac()`, `GLOBAL_UNICAST` | `sniffer.py:162`, `:177-183` | Global **y** con la MAC real del propio dispositivo (no la de otro) |
| Se marca al ver el paquete | `dev.eui64_global` | `sniffer.py:471-472` | Un booleano, no la dirección: así sobrevive a `--anonymize` sin revelar la IPv6 |
| Alerta de privacidad | `build_alerts` | `report.py:100-103` | BAJA, sin puerto |

---

## Mejoras propuestas por Qwen (2026-11-19): SSDP y modelo de amenazas

El autor eligió 3 de la segunda lista de **Qwen**; las demás se descartaron (detalle en
`AI_USAGE.md`).

### Tipos UPnP y versiones en SSDP

SSDP (Simple Service Discovery Protocol) es el descubrimiento de UPnP: mensajes HTTP sobre
UDP al 239.255.255.250:1900. Hay tres tipos de mensaje:

- `NOTIFY`: el dispositivo **se anuncia**; `NT` dice qué es.
- Respuesta `HTTP/1.1 200 OK`: el dispositivo **responde** a una búsqueda; `ST` dice qué es.
- `M-SEARCH`: alguien **busca**; su `ST` es lo que busca, no lo que es (como `Probe` en
  WS-Discovery). Un móvil que busca un router no es un router.

El tipo va en una URN: `urn:schemas-upnp-org:device:InternetGatewayDevice:1`. El banner
`SERVER` sigue el formato de UPnP 1.0: `SO/versión UPnP/1.0 producto/versión`.

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| Solo cuenta lo que el dispositivo dice de sí mismo | `announces = NOTIFY o HTTP/` | `sniffer.py:296` | `NT`/`ST` y versiones solo de anuncios y respuestas; el banner de un `M-SEARCH` se guarda, pero no da tipo ni versiones |
| Tipo UPnP de la URN | `_UPNP_URN` | `sniffer.py:243`, `:305-308` | Saca `InternetGatewayDevice`, `MediaRenderer`… con longitudes acotadas (64) |
| Separar SO, protocolo, librería y producto en el `SERVER` | `parse_server_banner()` | `sniffer.py:249-276` | `Linux/3.10` = núcleo (no es firmware); `UPnP/1.0` = protocolo; `miniupnpd/2.1` = librería; `Shelly/1.0` = **producto** → su versión sí es firmware |
| Firmware frente a librería | `_add_versions()`, `LIBRARY_NAMES` | `sniffer.py:254`, `:279-284` | Producto → `firmware`; librería → `software` (`miniupnpd/2.1`) |
| El cliente DHCP de BusyBox lleva su versión | `_DHCP_CLIENT` | `sniffer.py:258`, `:125-130` | `udhcp 1.24.1` → `software` = `udhcp/1.24.1` (es la versión de BusyBox, no la del firmware) |
| Pista fuerte en las reglas | campo `upnp` de las reglas | `heuristics.py:60`, `:187-189`, `rules.json:73`, `:86` | Router: `InternetGatewayDevice`, `WANIPConnection`…; multimedia: `MediaRenderer`… IGD y WANIPConnection los anuncia el mismo router: cuentan **una vez** (+3) |
| UPnP IGD: cualquier equipo de la LAN puede pedir al router que abra puertos hacia internet, sin autenticación | `SENSITIVE_UPNP` | `report.py:53-62`, `:97-99` | Alerta MEDIA por IGD, WANIPConnection o WANPPPConnection |
| Las librerías tienen CVE propios, con su versión | `SOFTWARE_CPE`, `device_software()` | `vulns.py:74-81`, `:250-257`, `:391` | `miniupnpd` → `miniupnp_project:miniupnpd`, `udhcp` → `busybox:busybox`; el rango se compara con la versión de la librería |
| Una librería no dice nada del hardware | `if not products` | `vulns.py:410` | Aunque haya CVE de librería, se hace la suposición por fabricante |

**En el ejemplo regenerado (NVD real, 2026-11-19):** el router TP-Link sale como "Router /
gateway" (alta) con 2 alertas MEDIA de UPnP y 4 CVE de miniupnpd 2.1 comprobados por versión;
el sensor con `udhcp 1.24.1` recibe 21 CVE de BusyBox 1.24.1.

**Limitación:** la versión de BusyBox no dice qué applets compiló el fabricante; un CVE de
`tar` o `ash` puede no afectar a un equipo que no los tenga. "modelo+firmware" aquí significa
"esta versión de la librería es vulnerable".

### Modelo de amenazas

`docs/THREAT_MODEL.md`: activos, adversarios, amenazas por **STRIDE** con la mitigación y el
código que la implementa, lo que la herramienta no ve y los riesgos residuales. Al redactarlo
salió uno no mitigado: no hay **límite de dispositivos**, así que una inundación de MAC falsas
hace crecer la memoria (sí hay límite de 64 elementos por dispositivo).

---

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
| Buscar el CVE por el texto del modelo no funciona: NVD empareja por CPE | `find_products()` | `vulns.py:199-222` | Busca el modelo en el diccionario CPE y se queda con los productos cuyo nombre aparece **tal cual** en el modelo (`_appears_in`, `:160-162`): `hl-l2350dw` sí casa con "Brother HL-L2350DW series"; `hl-l2350` y `dcp-1610w` no. Quita palabras que no están en CPE ("series", `MODEL_NOISE`, `:63`) |
| Software reconocible aunque no anuncie modelo | `SERVICE_PRODUCTS` | `vulns.py:65-67`, `device_products()` `:191-198` | `_esphomelib._tcp` → `esphome:esphome`; su `version=` es la del software |
| CVE de un producto en NVD | `product_cves()` | `vulns.py:306-321` | `virtualMatchString=cpe:2.3:*:fabricante:producto` (cualquier parte) y, si existe, también `..._firmware` |
| Niveles de certeza: fabricante < modelo < modelo + firmware | `assess()` | `vulns.py:273-287` | **modelo+firmware** si la versión anunciada cae en el rango vulnerable; **modelo** si no hay versión o NVD no da rango; si el rango la excluye, el CVE **se descarta** |
| Rangos de versión de NVD | `version_in_range()`, `_vkey()` | `vulns.py:239-270` | Versión exacta en el CPE, o `versionStart/EndIncluding/Excluding`; compara las versiones como números (`2024.6.1` → `(2024, 6, 1)`) |
| Nivel 3, **fabricante**: una suposición, no una certeza | `cpe_vendor()`, `vendor_recent_cves()` | `vulns.py:339-363`, `lookup_device()` `:381-387` | Si solo sabemos el fabricante (OUI), o el modelo no está en el diccionario CPE: CVE de **hardware** del fabricante (`cpe:2.3:h:hikvision`) publicados en los **últimos 2 años**, como mucho **5** y los más graves primero. Solo `h:` porque `o:` mete el sistema operativo (Google: 614 CVE de Android/ChromeOS en 120 días). Nunca genera alertas, ni estando en KEV |
| Del nombre OUI a la marca CPE | `cpe_vendor()`, `VENDOR_NOISE` | `vulns.py:93-102`, `:339-347` | "Hangzhou Hikvision Digital Technology Co.,Ltd." → `hikvision`: se quitan ciudades y palabras de empresa (inc, ltd, technology, smart…); MAC aleatoria o desconocido → no se busca |
| Gravedad | `_cvss()` | `vulns.py:290-297` | CVSS v4.0, si no v3.1, v3.0 o v2 (la "Primary", que es la de NVD) |
| KEV marca, no busca | `load_kev()` | `vulns.py:366-370` | Solo dice si un CVE encontrado por modelo está en KEV. Buscar en KEV por fabricante es ruido: "Google" tiene decenas de entradas de Chrome/Chromium que nada tienen que ver con un Chromecast. |
| NVD sin clave admite 5 peticiones cada 30 s | `Client._throttle()` | `vulns.py:146-152` | 6 s entre consultas (0,6 s con `NVD_API_KEY`); KEV no cuenta |
| No repetir consultas | `Client._cache_read/_cache_write` | `vulns.py:154-177` | Caché en disco de 24 h (`~/.cache/iot_scanner`, `--cve-cache`); si falla, se sigue sin caché |
| Privacidad: qué sale a internet | `lookup_all()` | `vulns.py:423-453` | Solo el modelo (lo anuncia el propio dispositivo a toda la red), el fabricante y nombres CPE; nunca MAC, IP ni hostname. User-Agent genérico |
| Lo que llega de internet tampoco es de fiar | `_http_get_json()`, `_summary()` | `vulns.py:106-112`, `:300-303` | Solo `https`, timeout de 30 s, como mucho 32 MB; la descripción se limpia de caracteres de control y se recorta a 160 |
| Sin red no se rompe nada | `Client.get()` | `vulns.py:129-144` | Un error de red o un JSON roto cuenta como error y se avisa; el informe indica que puede estar incompleto |

### En el informe

| Teoría | Código | Dónde | Qué hace |
|---|---|---|---|
| CVE separado de las alertas | `build_cve_list()`, `print_cves()` | `report.py:115-126`, `:343-363` | Sección "Vulnerabilidades conocidas", con certeza (`certainty_label()`: "fabricante (suposición)"), KEV y cuántos se descartaron por versión |
| Solo un CVE tan seguro y urgente como un Telnet abierto se convierte en alerta | bucle `for c in dev.cves` | `report.py:106-111` | Alerta ALTA si está en **KEV** y la certeza es **modelo+firmware**; sin puerto (`-`) |
| JSON/CSV | `Device.cves`, `_cve_cell()` | `device.py:34`, `report.py:393-394` | `cves` por dispositivo; en el CSV `CVE-… (CVSS, certeza, KEV)` |
| GUI | pestaña CVE, casilla | `gui.py:213-216`, `:264-271`, `:485-492` | Casilla "Buscar CVE conocidos"; pestaña aparte con las filas KEV en rojo; columna CVE en la tabla |
| CLI | `--cve`, `--cve-cache` | `net_device_scanner.py:68-71`, `:136-137` | Se busca después de clasificar |

### Ejemplo con datos reales (NVD, 2026-11-16)

| Dispositivo | Qué sabemos | Resultado |
|---|---|---|
| Brother HL-L2350DW | modelo, sin versión | 3 CVE (CVE-2019-13192/13193/13194), certeza **modelo** |
| Chromecast | modelo (`md=Chromecast`), sin versión (`ve` es el protocolo) | 6 CVE, certeza **modelo** |
| Sensor ESPHome 2024.6.1 | software + versión | 3 CVE de ESPHome, **los 3 descartados**: la versión está fuera de los rangos |
| (prueba) ESPHome 2024.1.0 | software + versión | CVE-2024-27287 (rango 2023.12.9–2024.2.2), certeza **modelo+firmware** |
| Cámara Hikvision (sin modelo en mDNS) | fabricante | 3 CVE recientes de hardware Hikvision (CVE-2025-66176, 8.8…), certeza **fabricante (suposición)** |
| Altavoz Sonos, NAS Synology, Apple, Windows | fabricante | 1-5 CVE recientes cada uno, **suposición** |
| Enchufe Tuya, bombilla WiZ | fabricante | ninguno: NVD no tiene CVE de hardware recientes de esas marcas |

El ejemplo de ESPHome muestra para qué sirve la versión: sin ella, se habrían listado 3 CVE que
no le afectan.

**Limitaciones:**
- El nivel fabricante habla de **otros** equipos de la marca: sirve para decidir qué mirar primero, no para afirmar nada de este. Si la marca CPE no coincide con el nombre OUI (Raspberry Pi → `raspberrypi`), no sale nada.
- Solo se encuentran dispositivos cuyo modelo esté en el diccionario CPE con un nombre parecido.
- La comparación de versiones solo mira los números (`1.0-beta` y `1.0` se ven iguales).
- Con más de 200 CVE por producto solo se ven los primeros (se avisa).
- "Certeza modelo" significa "este modelo ha tenido este fallo", no "este equipo lo tiene":
  puede que ya esté actualizado.

---

## Hito 4 — Informe (`iot_scanner/report.py`)

_Pendiente de revisar._
