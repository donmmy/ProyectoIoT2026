# Modelo de amenazas del escáner IoT

Propuesto por **Qwen** (2026-11-19) y redactado con Claude a partir del código actual.
Responde a cuatro preguntas: qué protege la herramienta, de quién, qué hace para
protegerlo y **qué no puede ver ni evitar**. Cada mitigación cita el código que la
implementa; lo que no está implementado está en "Riesgos residuales".

## 1. Qué es y dónde se usa

Un escáner **pasivo** (más un ARP scan opcional) que identifica dispositivos IoT de una red
local, genera un informe JSON/CSV y, con `--cve`, consulta vulnerabilidades conocidas en NVD y
CISA KEV. Se ejecuta en el portátil del analista, conectado a la red que se audita, con
permisos de administrador para capturar (o sin ellos, si analiza un `.pcap`).

```
 red auditada ──paquetes──▶ [ sniffer → reglas → informe ] ──▶ JSON / CSV / --log
 (no fiable)                  portátil del analista           (datos sensibles)
                                       │ --cve (opcional)
                                       ▼
                               NVD / CISA KEV (HTTPS)
```

**Fronteras de confianza:**
1. Todo lo que llega de la red es **no fiable**: lo puede fabricar cualquier equipo conectado.
2. Lo que sale en los informes y el registro **es sensible**: describe una red y a sus usuarios.
3. Lo que viene de internet (`--cve`) llega por HTTPS, pero se trata igual que la red.

## 2. Activos

| Activo | Por qué importa |
|---|---|
| Datos capturados: MAC, IP, hostnames, consultas DNS, SNI, TXT de mDNS | Identifican equipos y personas (`fn=Salón de Oscar`, `note=Despacho`) y revelan hábitos (DNS, SNI) |
| Informes JSON/CSV y `--log` | Un inventario con tipos, versiones y CVE es un mapa de ataque de la red |
| Clave de la API de NVD (`programa/nvd_api_key.txt`) | Es personal; con ella otro podría consumir la cuota del autor |
| El portátil del analista | Captura con permisos de administrador: un fallo al procesar paquetes se ejecuta con esos permisos |
| La confianza en el resultado | Una identificación o un CVE erróneos llevan a decisiones erróneas |

## 3. Adversarios

| Adversario | Qué puede hacer |
|---|---|
| **Dispositivo hostil en la red** | Enviar paquetes manipulados: hostnames con código, banners SSDP enormes, XML de WS-Discovery malicioso, ClientHello TLS cortado, TXT con miles de pares, inundación de MAC falsas |
| **Dispositivo que se hace pasar por otro** | Falsificar su MAC (fabricante OUI), su hostname o lo que anuncia por mDNS/SSDP para que se le clasifique mal |
| **Quien recibe el informe** | Ver datos personales de la red auditada si el informe no se anonimiza |
| **Atacante en el camino a internet** | Manipular las respuestas de NVD/KEV (mitigado por HTTPS) |
| **Autor de reglas** | Un `rules.json` ajeno con una regex lenta (ReDoS) |
| **Uso indebido de la propia herramienta** | Escanear o escuchar redes sin autorización |

## 4. Amenazas y mitigaciones (STRIDE)

| STRIDE | Amenaza | Mitigación | Dónde |
|---|---|---|---|
| **S**uplantación | Un equipo falsifica su MAC, hostname o anuncios para parecer otro | La identificación es una **hipótesis** con evidencias y puntos, nunca un veredicto; varias pistas independientes pesan más que una | `heuristics.py` (pesos y confianza) |
| **T**ampering (manipulación) | Texto de red con caracteres de control, HTML o fórmulas | Todo texto se sanea con una lista blanca de caracteres y se recorta | `sniffer.sanitize_text` |
| | Fórmulas en el CSV (`=HYPERLINK(...)`) | Las celdas que empiezan por `= + - @` se escapan | `report._csv_safe` |
| | XML de WS-Discovery con entidades (XXE, "billion laughs") | No se usa un parser XML: regex acotadas sobre 8 KB como máximo | `sniffer.WSD_MAX_BYTES` |
| | ClientHello TLS cortado o con longitudes falsas | El parser comprueba cada longitud y devuelve `None` | `sniffer.tls_sni` |
| | SSDP con tipos UPnP o versiones enormes | Expresiones con longitudes acotadas; 4 KB y 64 líneas por mensaje | `sniffer._parse_ssdp` |
| | Un `M-SEARCH` o `Probe` haría pasar por router o cámara a quien solo busca | Solo cuentan los anuncios (`NOTIFY`, respuesta, `Hello`) | `_parse_ssdp`, `_parse_wsd` |
| | Respuesta de NVD/KEV manipulada | Solo HTTPS, timeout de 30 s, máximo 32 MB, descripciones saneadas | `vulns._http_get_json`, `vulns._summary` |
| **R**epudio | — | No aplica: la herramienta no toma decisiones en nombre de nadie. El `--log` deja registro del análisis | `logsetup.py` |
| **I**nformation disclosure | El informe revela MAC, IP, hostnames y nombres que puso el usuario | `--anonymize`: seudónimos HMAC-SHA256 con clave aleatoria que no se guarda; de los TXT solo quedan las claves técnicas | `report.anonymize`, `SAFE_TXT_KEYS` |
| | Informes o capturas reales subidos a GitHub | `.gitignore` excluye `*.pcap`, `informe*`, `*.log` | `.gitignore` |
| | DNS y SNI completos en el informe (cuentas, IDs o ciudades en el subdominio) | Con `--anonymize` solo queda el dominio registrable (Public Suffix List), también en las evidencias | `psl.registrable_domain`, `report._anonymize_labels` |
| | `--cve` filtra datos de la red a NVD | Solo salen modelos, fabricantes y nombres CPE; nunca MAC, IP ni hostname; User-Agent genérico. Es opcional | `vulns.lookup_all` (test `test_only_models_leave_the_machine`) |
| | La clave de NVD acaba en el repositorio o en el registro | Fichero en `.gitignore`; solo se envía a NVD (no a KEV) y no se escribe en el registro | `vulns.read_api_key` (test `test_api_key_file`) |
| **D**enegación de servicio | Un equipo envía miles de servicios, dominios o TXT | Como mucho 64 elementos por conjunto y dispositivo; 32 pares por TXT | `device.MAX_ITEMS`, `TXT_MAX_PAIRS` |
| | Regex lenta en un `rules.json` ajeno | Las reglas se validan al cargar; el fichero avisa de no cargar reglas de origen desconocido | `heuristics.load_rules` |
| | El ARP scan satura la red | Pausa entre ARPs; la red autodetectada se limita a /24 (con `-n` se puede indicar otra) | `--arp-interval`, `discovery.guess_network` |
| **E**levación de privilegios | Un fallo al procesar paquetes se ejecuta con los permisos de captura | Sin `eval`, `exec` ni `subprocess`; análisis revisado con `bandit` en cada push. Alternativa: capturar con `tcpdump`/Wireshark y analizar el `.pcap` **sin** permisos | CI (`bandit`), `--pcap` |
| Uso indebido | Escanear redes ajenas | Confirmación en la GUI antes de capturar; en la CLI el aviso solo está en la cabecera del código y en el README; `--sniff-only` no envía nada | `gui.py`, `net_device_scanner.py` |

## 5. Qué no ve la herramienta

Estas limitaciones no son fallos de seguridad, pero condicionan cualquier conclusión del informe:

- **Tráfico unicast en una red con switch o Wi-Fi sin modo monitor.** Solo llega el tráfico
  propio y el broadcast/multicast (ARP, DHCP, mDNS, SSDP, WS-Discovery). La conversación
  cámara ↔ nube (puertos, DNS, SNI, NTP) no pasa por la tarjeta. Hace falta port mirroring,
  un hub o usar el portátil como punto de acceso.
- **Contenido cifrado.** De TLS solo se lee el SNI del ClientHello; no se descifra nada. Con
  **ECH** (Encrypted Client Hello) ni siquiera el SNI es visible. Las consultas por **DoH/DoT**
  tampoco se ven.
- **Radios que no son IP**: Zigbee, Z-Wave, BLE y Thread (salvo lo que su pasarela anuncia
  por IP).
- **Dispositivos callados** durante la escucha: un `Hello` de WS-Discovery solo se ve al
  conectarse; un equipo que no anuncia nada solo aparece por ARP.
- **MAC aleatorias** (móviles): sin fabricante OUI.

## 6. Límites de la búsqueda de CVE

- Las certezas son **modelo+firmware**, **modelo** y **fabricante (suposición)**. Solo la
  primera afirma algo de este equipo concreto, y aun así depende de que la versión anunciada
  sea verdad (un equipo puede mentir).
- **Falsos positivos**: un CVE de BusyBox puede estar en un applet que el fabricante no
  compiló; "certeza modelo" no sabe si el equipo ya está actualizado; el nivel fabricante
  habla de **otros** equipos de la marca.
- **Falsos negativos**: modelos que no están en el diccionario CPE, marcas cuyo nombre CPE
  no coincide con el OUI, CVE que NVD aún no ha analizado.
- Solo pasa a alerta un CVE en KEV con certeza modelo+firmware.

## 7. Riesgos residuales (no mitigados)

| Riesgo | Por qué queda | Posible mitigación |
|---|---|---|
| Inundación de MAC falsas: cada MAC nueva crea un dispositivo y **no hay límite** de dispositivos | Hay límite por dispositivo (64), no de dispositivos | Tope de dispositivos con aviso en el registro |
| Captura con permisos de administrador | Scapy necesita sockets raw | Capturar con otra herramienta y usar `--pcap` |
| La CLI no pide confirmación antes de escanear | Pensada para scripts y pruebas | Mostrar el aviso legal al arrancar una captura en vivo |
| La pantalla y el `--log` muestran los datos reales aunque se use `--anonymize` | `--anonymize` solo afecta a lo exportado | Tratar el `--log` como dato sensible (está en `.gitignore`) |
| `--anonymize` deja el dominio registrable de DNS y SNI (desde 2026-11-19 ya no el nombre completo) | El dominio base es la evidencia de con qué nube habla; en un móvil aún revela qué servicios usa | Valorar caso por caso antes de compartir el informe |
| Clave de NVD en texto plano en el disco | Es el mecanismo más simple | Usar la variable `NVD_API_KEY` desde un gestor de secretos |
| Un dispositivo puede anunciar un modelo o una versión falsos | La herramienta es pasiva: no puede comprobarlo | Contrastar con el panel del fabricante o un escaneo activo autorizado |
