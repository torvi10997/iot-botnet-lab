# iot-botnet-lab

Emulador y analizador para aprender a detectar **dispositivos IoT comprometidos** (TV box Android genéricos, cámaras, etc.) que se comportan como bots de una botnet DDoS dentro de una red doméstica o de un ISP pequeño.

Nació de un caso real: un TV box genérico con ADB abierto recibía órdenes de un servidor de control y lanzaba inundaciones UDP a terceros desde la IP pública del operador. Aquí queda empaquetado lo aprendido para que otros puedan practicar y revisar sus propias redes.

> **Solo biblioteca estándar de Python 3.8+.** Para probar el emulador y el analizador no hace falta instalar paquetes ni Wireshark. Para capturar tráfico real (modo visita) sí se necesita Wireshark/TShark: ver [Instalación](#instalación).

## Qué incluye

| Pieza | Para qué sirve |
|---|---|
| **Emulador** (`emulate`) | Genera una captura `.pcap` *sintética* de un dispositivo infectado (o sano). No envía tráfico a ninguna red y solo usa IP de documentación (RFC 5737). |
| **Modo visita** (`visita`) | Asistente para técnicos: captura el tráfico de un aparato en casa del cliente y entrega un informe con semáforo en lenguaje simple. |
| **Analizador** (`analyze`) | Lee un `.pcap`/`.pcapng` real o emulado y marca los indicios, con explicación y veredicto. |
| **Guías** (`docs/`) | Cómo capturar el tráfico de un dispositivo, reglas de ejemplo para MikroTik y un plan de respuesta. |

## Instalación

Funciona en Windows, Linux y macOS. El modo visita (captura con hotspot) está pensado para **Windows**.

| Qué | Para qué | Cómo |
|---|---|---|
| **Python 3.8 o superior** | Ejecutar la herramienta (siempre) | [python.org/downloads](https://www.python.org/downloads/). En Windows, marca **"Add Python to PATH"** al instalar. Comprueba con `python --version`. |
| **Esta herramienta** | El código | En esta página pulsa el botón verde **Code**, luego **Download ZIP**, y descomprime. O con Git: `git clone https://github.com/torvi10997/iot-botnet-lab.git` |
| **Wireshark con TShark y Npcap** | Solo para capturar tráfico real (`visita`) | [wireshark.org/download](https://www.wireshark.org/download.html). Deja marcado **TShark** y acepta instalar **Npcap**. |

No hay que instalar nada más (no usa `pip`). Abre una terminal **dentro de la carpeta descomprimida** y ejecuta los comandos de abajo. Para capturar, abre la terminal **como administrador**.

Prueba rápida de que todo funciona (no necesita Wireshark):

```bash
python -m botnet_lab emulate prueba.pcap
python -m botnet_lab analyze prueba.pcap
```

Debe terminar con `Veredicto: SOSPECHOSO`.

## Inicio rápido

```bash
git clone https://github.com/torvi10997/iot-botnet-lab.git   # o descarga el ZIP (ver Instalación)
cd iot-botnet-lab

# 1) Generar una captura de un dispositivo infectado y otra de uno sano
python -m botnet_lab emulate infectado.pcap
python -m botnet_lab emulate sano.pcap --clean

# 2) Analizarlas
python -m botnet_lab analyze infectado.pcap
python -m botnet_lab analyze sano.pcap

# 3) Analizar una captura real de tu red (pcap o pcapng)
python -m botnet_lab analyze mi_captura.pcapng --device 192.168.1.50

# 4) Revisar un aparato en casa de un cliente (necesita Wireshark/TShark)
python -m botnet_lab visita --minutos 15

# 5) Probar el informe sin capturar nada
python -m botnet_lab visita --desde-captura infectado.pcap
```

Para visitas en campo lee [`docs/VISITA.md`](docs/VISITA.md).

El código de salida es `2` si el veredicto es *sospechoso*, útil para scripts.

## Qué detecta

| Código | Indicio | Por qué importa |
|---|---|---|
| `UDP_FLOOD` | Inundación UDP sostenida (por defecto ≥ 200 pps durante ≥ 5 s) con casi ninguna respuesta | Es el ataque en sí: tráfico unidireccional hacia un tercero |
| `C2_ORDER` | Un mensaje pequeño entrante justo antes (≤ 2 s) de que empiece la inundación | Delata al servidor de control que da la orden |
| `BEACON` | Mensajes del mismo tamaño a intervalos regulares hacia un mismo destino (en puertos 80/443 solo informativo) | Latido del canal de control (en el caso real: 33 bytes, en pareja, cada 30 s) |
| `DNS_RANDOM` | Consultas DNS con etiquetas largas y aleatorias (incluso binarias) directo a resolvers públicos | Sondeo de dominios del malware o ruido |
| `DNS_BYPASS` | El equipo ignora el DNS del router | Informativo; muchos aparatos lo hacen |
| `SCAN` | Muchos destinos/puertos distintos con SYN en pocos segundos | Búsqueda de nuevas víctimas |

Los umbrales se ajustan con `--min-pps`, `--min-secs` y `--local-net`. Ejemplo de resultado sobre la captura emulada:

```
[ALTA] Inundación UDP desde 192.168.137.50 hacia 203.0.113.20:19132  (UDP_FLOOD)
    8850 paquetes en ~15 s (pico 600 pps, promedio 1190 B de datos), respuestas: 0%.
[ALTA] Orden de control 198.51.100.10:6969 seguida de inundación a 203.0.113.20  (C2_ORDER)
    Llegó un mensaje de 54 bytes 0.25 s antes de que empezara la inundación. ...
[MEDIA] Latido periódico 192.168.137.50 -> 198.51.100.10:6969  (BEACON)
Veredicto: SOSPECHOSO
```

## Opciones del emulador

```
--clean          dispositivo sano (para probar falsos positivos)
--duration N     segundos de captura (120)
--pps N          paquetes por segundo de cada inundación (600)
--flood-secs N   duración de cada inundación (15)
--scan           añade un barrido SYN al puerto 22
--seed N         semilla para reproducir el mismo escenario
```

## Validación

Se contrastó con capturas reales de un TV box infectado (reposo, en ataque y tras restablecer de fábrica): las tres capturas del equipo infectado salen *sospechosas* y la del restablecido, *sin indicios*. Es un solo caso, no un estudio; los umbrales pueden necesitar ajustes con otros equipos. Si lo pruebas con otro dispositivo, abre un issue con tus resultados (anonimizados).

## Límites (léelos)

- Es una **herramienta educativa y de triage**, no un antivirus ni un IDS. Un veredicto *sin indicios* en una captura corta no prueba que el equipo esté limpio: el malware puede estar callado durante minutos. Captura al menos 10 a 15 minutos, idealmente con el equipo en uso.
- Un `BEACON` o un `DNS_BYPASS` por sí solos suelen ser falsos positivos (notificaciones, apps). Lo fuerte es la combinación: latido + orden + inundación.
- Solo IPv4, TCP/UDP. Una captura cifrada (VPN, DoH) oculta parte de lo que se busca.
- Un equipo hecho para evadir (tráfico muy bajo y lento) no será detectado.

## Uso responsable

Captura solo **redes y dispositivos propios o con autorización expresa** del dueño. Esta herramienta no ataca ni genera tráfico real; el emulador solo escribe un archivo. No publiques capturas reales sin quitar IP, MAC y datos personales.

## Documentación

- [`docs/VISITA.md`](docs/VISITA.md): guía del técnico para revisar un aparato en casa del cliente (modo visita, semáforo, consentimiento).
- [`docs/CAPTURA.md`](docs/CAPTURA.md): cómo capturar el tráfico de un TV box u otro aparato (hotspot en Windows, tshark).
- [`docs/MIKROTIK.md`](docs/MIKROTIK.md): reglas de ejemplo para detectar y bloquear en RouterOS 7.
- [`docs/RESPUESTA.md`](docs/RESPUESTA.md): qué hacer cuando encuentras uno (cliente, ISP, reporte).

## Pruebas

```bash
python -m unittest discover -s tests -v
```

## Contribuir

Ideas bienvenidas: detección de más familias, soporte IPv6, reglas para otros routers (OpenWrt, pfSense, Ubiquiti), traducciones. Abre un issue o un pull request. Las capturas reales de ejemplo deben estar anonimizadas.

## Licencia

MIT, ver [`LICENSE`](LICENSE).
