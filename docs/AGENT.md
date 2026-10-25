# AGENT.md — Contexto del proyecto para agentes de IA

> Fichero vivo: actualízalo al terminar cada bloque de trabajo (qué se hizo, qué
> se decidió y qué queda). Es el punto de partida para cualquier sesión nueva.

## Qué es

**Escáner de Vulnerabilidades IoT** — práctica de *Desarrollo de Herramientas de
Ciberseguridad* (autor: Oscar Jiang Lin). Herramienta en Python + Scapy que
descubre dispositivos de una red local, los perfila de forma pasiva por su
tráfico, propone qué tipo de dispositivo es cada uno y genera un informe con
alertas de seguridad.

Documento de planteamiento: `Desarrollo de Herramientas de Ciberseguridad.pdf`
(no está en el repo; lo tiene el autor). Puntos clave del PDF:

- La IA **no** forma parte del pipeline crítico: solo apoyo al desarrollo y, en
  el Hito 5 (opcional), triaje marcado siempre como "sugerencia no verificada".
- Riesgo explícito a evitar: inyección vía campos de texto de la red
  (hostname, banners). Todo texto de la red se sanea.
- Commits separados por módulo, indicando qué partes se generaron/revisaron con IA.
- Validación: pruebas funcionales, revisión de seguridad, flake8/bandit.
- Debe existir un `AI_USAGE.md` con los prompts relevantes y qué código es asistido.

**Uso legal:** solo en redes propias o con autorización explícita.

## Estado de los hitos

| Hito | Contenido | Estado |
|------|-----------|--------|
| 1 | ARP scan, autodetección de interfaz/CIDR, fabricante por OUI, fallback a solo-escucha si no responde nadie | ✅ Hecho |
| 2 | Sniffing pasivo por MAC; TCP/UDP/DNS/DHCP/mDNS/SSDP; hostname por DHCP opt.12 y mDNS. Ampliado con NTP, TLS (SNI) e IPv6 (Matter/Thread) | ✅ Hecho |
| 3 | Tabla de reglas → etiquetas candidatas con confianza (suma de pesos de las evidencias) | ✅ Hecho |
| 4 | Tabla por consola, JSON/CSV, resumen (recuentos, protocolos top, alertas) | ✅ Hecho |
| 5 | Triaje asistido por IA (datos anonimizados y saneados) | ⏳ Pendiente (opcional) |
| 6 | Pruebas en laboratorio real vs. Wireshark, casos de prueba, memoria, `AI_USAGE.md` | ⏳ Pendiente |

Tests: **34 pasan** (`pytest`), con tráfico sintético; no requieren root ni red.

## Estructura

```
README.md               portada + manual de uso (GUI, CLI, tests, limitaciones)
.venv/                  entorno virtual (en la raíz, ignorado por git)
programa/               todo el código (ejecutar desde aquí)
  net_device_scanner.py CLI / punto de entrada (argparse)
  gui.py                interfaz gráfica tkinter; build_argv() traduce la ventana a argumentos
                        de la CLI y run_analysis() reutiliza parse_args/run_live/sniff_pcap
  abrir_interfaz.bat    lanzador Windows con doble clic: pide administrador (UAC); si no existe
                        ..\.venv lo crea (py -3 o python) e instala requirements.txt; si falta
                        scapy lo reinstala; abre gui.py con pythonw
  requirements.txt
  iot_scanner/
    device.py           dataclass Device (modelo común a todos los módulos)
    discovery.py        Hito 1: guess_network, validate_network, vendor_from_mac, arp_scan
    sniffer.py          Hito 2: PassiveSniffer, sanitize_text, tls_sni, sniff_live, sniff_pcap
    heuristics.py       Hito 3: RULES, evaluate_rule, classify, classify_all
    report.py           Hito 4: build_alerts, build_summary, print_*, export_json, export_csv
  tests/
    lab_packets.py      tráfico sintético del "laboratorio" (cámara, Chromecast, enchufe Tuya,
                        sensor ESP32 MQTT, bombilla Matter por IPv6, dispositivo con hostname
                        y SNI maliciosos); client_hello() construye un TLS ClientHello; genera .pcap
    test_scanner.py     tests por hito + test de la CLI con --pcap
    test_gui.py         tests de la interfaz (se salta si no hay pantalla)
ejemplos/               salida de demostración, solo tráfico sintético
  ejemplo_lab.pcap, ejemplo_informe.json, ejemplo_informe.csv
docs/                   apuntes .md
  AGENT.md              este fichero
  AI_USAGE.md           registro del uso de IA (lo exige el PDF)
  programa_codigos.md   teoría -> línea de código
```

`docs/programa_codigos.md` mapea cada concepto teórico a la línea
de código que lo aplica (Hitos 1-3 y ampliación; Hito 4 pendiente).

Las capturas `*.pcap` están en `.gitignore` salvo las de `ejemplos/`; la de ejemplo se
regenera desde `programa/` con `python -m tests.lab_packets` (escribe en `../ejemplos/`). No subir informes de la red real
(llevan IPs, MACs y hostnames).

Flujo: interfaz/red → ARP scan (+OUI) → [0 respuestas ⇒ solo-escucha] →
sniffing pasivo → extracción de metadatos → heurísticas → informe.

## Decisiones de diseño (y por qué)

- **`ports_src` vs `ports_dst`**: en pasivo, el puerto destino indica a qué se
  *conecta* el dispositivo (cliente) y el puerto origen de un SYN+ACK (o UDP <1024)
  indica qué *sirve*. Las alertas de "puerto sensible abierto" usan `ports_src`;
  los de cliente (p. ej. MQTT 1883 sin TLS) van aparte.
- Puertos efímeros (≥49152) no se guardan en `ports_dst` para reducir ruido.
- Origen multicast/broadcast y la MAC propia se ignoran.
- Conjuntos limitados a 64 elementos por dispositivo (`MAX_ITEMS`).
- `sanitize_text`: lista blanca de caracteres + recorte a 64 chars en todo texto
  de la red. El CSV además neutraliza fórmulas (`=`, `+`, `-`, `@`).
- MAC con bit U/L activo ⇒ "MAC aleatoria/privada" (sin OUI real).
- La red autodetectada nunca es mayor que /24 para no lanzar 65k ARPs por error.
- **Pesos de las evidencias** (2026-10-25): cada pista vale según lo específica que es del
  tipo (idea del cociente de verosimilitud): fuerte = 3 (puertos propietarios como
  37777/6668/8009, servicios mDNS específicos, dominios de la nube del fabricante),
  media = 2 (puertos de protocolo como 554/1883, texto en hostname o banner), débil = 1
  (puertos genéricos 80/443/1900, texto que solo sale del fabricante por OUI).
  Tablas `STRONG_PORTS`, `WEAK_PORTS`, `MEDIUM_MDNS` en `heuristics.py`.
- Confianza sobre la **suma de pesos**: 1-2 = baja, 3-4 = media, ≥5 = alta. Máx. 3 etiquetas.
  Cada evidencia lleva su peso en el informe (`sirve puerto 554 (+2)`).
- Los pesos solo afectan a la **identificación**; las alertas de `report.py` no cambian
  (el 80 pesa poco para saber qué es, pero sigue siendo "web sin HTTPS").
- Regex de texto solo al **inicio de palabra** (`(?<![a-z])`): `esp` no casa con
  `despacho-pc`; por la derecha no se limita para no perder `IPCamera`.
- Un puerto que el dispositivo sirve no vuelve a contar como cliente en la misma regla
  (un SSDP 1900 → 1900 es una pista, no dos).
- Pesos y umbrales son juicio experto sin calibrar: medir en el Hito 6 (conteo frente a
  pesos, aciertos y falsos positivos).
- `--pcap` permite análisis offline reproducible (comparar con Wireshark en Hito 6).
- **NTP**: el rol se decide por el campo `mode` (3 cliente, 4/5 servidor), no por el
  puerto, porque ntpd usa el 123 también como origen del cliente.
- **TLS SNI**: parser manual del ClientHello (sin cargar la capa TLS de Scapy ni
  dependencias); solo el primer segmento TCP. El SNI cuenta como dominio en las reglas
  (misma regex que DNS, una sola evidencia).
- **Matter/Thread**: se ve lo que llega por IP (mDNS sobre IPv6, UDP 5540); los nodos
  Thread no, solo su border router (`_meshcop._udp`).

## Cómo ejecutar

```bash
python -m venv .venv                                       # en la raíz del repo
.venv/Scripts/python -m pip install -r programa/requirements.txt   # Windows (Linux: .venv/bin/python)
cd programa
../.venv/Scripts/python -m pytest -q
../.venv/Scripts/python -m tests.lab_packets
../.venv/Scripts/python net_device_scanner.py --pcap ../ejemplos/ejemplo_lab.pcap -o informe.json --csv informe.csv
```

Captura en vivo: Windows necesita **Npcap** y consola de administrador; Linux/Mac `sudo`.
Opciones: `-i`, `-n`, `-t`, `--arp-timeout`, `--sniff-only`, `--no-sniff`, `--pcap`,
`-o`, `--csv`, `--list-ifaces`.

## Entorno y trampas conocidas

- Python 3.15 en el equipo del autor (2026-10-25: venv recreado en la raíz del repo, `.venv/`); Scapy 2.8.0 en `.venv` (ignorado por git).
- En Scapy ≥2.5 las secciones DNS (`an`, `qd`, `ar`) son **listas**: construir
  respuestas con `an=[DNSRR(...), DNSRR(...)]`, no encadenando con `/` (si no,
  al serializar solo se cuenta el primer registro).
- `conf.manufdb._get_manuf` devuelve la propia MAC si no la conoce; se trata como
  "desconocido".

## Pendiente / siguientes pasos

- [x] `requirements.txt` y `README.md` con uso y ejemplo.
- [x] `AI_USAGE.md` (lo exige el PDF). Falta que el autor complete la fila del prototipo inicial.
- [x] `flake8 --max-line-length 120` sin avisos.
- [ ] `bandit`: no instala en Python 3.15 (PyYAML no compila); ejecutarlo con Python 3.11–3.13.
- [x] Commits separados por hito con etiqueta `[IA]` en la rama `hitos-1-4`; PR #1 hacia `main` abierto.
- [x] Interfaz gráfica (`gui.py`). Limitación: la escucha en vivo no se puede cortar antes de
  tiempo (usa el timeout de `sniff`); si se añade, usar `stop_filter`/`AsyncSniffer`.
- [ ] Hito 6: prueba real con los 3 dispositivos IoT del laboratorio y comparación con Wireshark.
- [ ] Hito 5 (opcional): triaje con IA sobre datos anonimizados y ya saneados.
- [ ] Futuro: capturar el **tráfico unicast** de los dispositivos. Hoy, en una red con
  switch o WiFi, solo llega el tráfico propio + broadcast/multicast (ARP, DHCP, mDNS,
  SSDP); el unicast cámara ↔ nube (puertos, DNS, SNI, NTP) no pasa por el portátil y los
  tests lo dan por visto porque el tráfico es sintético. Opciones: port mirroring en un
  switch gestionable, el portátil como punto de acceso (hotspot) con el IoT conectado a él,
  o un hub. Documentar en el informe/memoria qué modo de captura se usó.

## Registro de sesiones

- **2026-10-18** — Lectura del PDF. Refactor del script único en el paquete
  `iot_scanner` e implementación de los hitos 1-4 con tests (18 OK) y una captura
  de ejemplo. Creado este `AGENT.md`. Trabajo asistido por Claude (Claude Code).
  Después: README, requirements, AI_USAGE.md, flake8 limpio, 6 commits por hito
  en la rama `hitos-1-4` subida a GitHub.
- **2026-10-21** — Revisión guiada de los hitos 1-2 con el autor (`programa_codigos.md`).
  Ampliación del sniffer: NTP (servidores y rol por `mode`), TLS SNI, IPv6 y reglas
  Matter / border router Thread. Tests 18 → 26, flake8 limpio. Asistido por Claude
  (Claude Code).
- **2026-10-25** — Revisión del Hito 3 con el autor: pesos por especificidad de la pista,
  regex con inicio de palabra y sin doble conteo servidor/cliente. Tests 26 → 31,
  flake8 limpio. Asistido por Claude (Claude Code). Subido a `hitos-1-4`.
- **2026-10-25** — Interfaz gráfica `gui.py` (tkinter, sin dependencias nuevas) y lanzador
  `abrir_interfaz.bat`. El análisis corre en un hilo y sus `print` se redirigen a la pestaña
  Registro. Tests 31 → 34 (`tests/test_gui.py`, se salta si no hay pantalla). Asistido por
  Claude (Claude Code).
- **2026-10-25** — Reorganización del repo: `programa/` (código y tests), `ejemplos/`
  (pcap sintético + informes JSON/CSV, ahora versionados) y `docs/` (apuntes .md). Se quita
  la carpeta doble `Proyecto4loT/Proyecto4loT`; el venv pasa a la raíz. El manual de uso
  queda en el `README.md` de la raíz. 34 tests OK. Asistido por Claude (Claude Code).
- **2026-10-25** — `abrir_interfaz.bat` prepara el entorno la primera vez (el `.venv` no se
  sube a git). La GUI avisa en ventana si falta scapy (con pythonw no hay consola) y si no hay
  Npcap (`conf.use_pcap`). Probado en una copia limpia sin `.venv` (salvo el paso UAC).
