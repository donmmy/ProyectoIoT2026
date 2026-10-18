# Uso de IA en el desarrollo

Según la estrategia del planteamiento, la IA se usa como apoyo al desarrollo
(generación de código, tests y documentación). El núcleo de la herramienta no
depende de IA en tiempo de ejecución.

## Registro

| Fecha | Asistente | Parte | Qué se generó / revisó |
|---|---|---|---|
| (inicial) | — | `net_device_scanner.py` v0 | Prototipo con ARP scan + sniffer básico. |
| 2026-10-18 | Claude (Claude Code) | Hitos 1–4 | Refactor en el paquete `iot_scanner/` (discovery, sniffer, heuristics, report), CLI nueva, tests con tráfico sintético, README. |

### Prompt principal (2026-10-18)

> "Ya vamos tarde, si me puedes ayudar a completar de hitos 1-4"
> (adjuntando el documento de planteamiento con la descripción de los hitos).

## Validación del código generado

- **Pruebas funcionales:** `pytest` con 18 casos sobre tráfico sintético (todos pasan).
  Pendiente: validación en laboratorio real comparando con Wireshark (Hito 6).
- **Revisión de seguridad:** sin `eval`/`exec`/`subprocess`; el texto que llega de la
  red (hostname DHCP/mDNS, banners SSDP) se sanea y recorta; el CSV escapa
  celdas que empiezan por `=`, `+`, `-` o `@`.
- **Linting:** `flake8` sin avisos. `bandit` pendiente (no se pudo instalar en Python 3.15
  por PyYAML; ejecutar en Python 3.11–3.13).

## Pendiente de revisión humana

- Ajustar la tabla de reglas de `heuristics.py` con los dispositivos reales del laboratorio.
- Revisar los umbrales de confianza (1 = baja, 2 = media, 3+ = alta).
