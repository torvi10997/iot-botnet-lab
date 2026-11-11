# iot-botnet-lab

Herramienta para revisar, **en tiempo real y con un dispositivo real**, si un dispositivo IoT (TV box Android genérico, cámara, etc.) se comporta como un **bot de una botnet DDoS**, dentro de una red doméstica o de un ISP pequeño.

Nació de un caso real: un TV box genérico con ADB abierto recibía órdenes de un servidor de control y lanzaba inundaciones UDP a terceros desde la IP pública del operador. Aquí queda empaquetado lo aprendido para que otros puedan revisar sus propias redes.

> **Solo biblioteca estándar de Python 3.8+**: no usa `pip`. Para capturar tráfico se necesita Wireshark/TShark: ver [Instalación](#instalación).

## Cómo se usa (resumen)

1. Instala Python y Wireshark (abajo).
2. Conecta el dispositivo sospechoso al hotspot de tu laptop Windows y ponlo en uso (por ejemplo, un video).
3. **Doble clic en `Abrir_app.bat`.** Se abre una ventana que muestra, **en vivo**, qué hace el dispositivo:
   quién es (nombre, MAC, fabricante), con quién habla, a qué ritmo, qué tipo de tráfico produce (video, web,
   mensajería, publicidad...) y un **semáforo** con el diagnóstico. Tiene botones de **Iniciar, Pausar, Continuar
   y Detener**, y genera un informe en lenguaje simple para el cliente.

4. El botón **Requisitos** comprueba que Wireshark, Npcap, los permisos y el hotspot estén bien, y te guía para arreglarlo.
5. El botón **Abrir captura…** carga una captura hecha en el **router** (por ejemplo con el sniffer de MikroTik) y muestra
   **muchos dispositivos a la vez, con los sospechosos primero**.
6. En la pestaña **Puertos abiertos**, revisa a qué servicios responde el dispositivo (ADB, Telnet, paneles web...).
   Distingue un ADB **abierto sin clave** (la puerta de entrada de BADBOX y Kimwolf) de uno que pide autorización,
   explica cada puerto y qué hacer, y el resultado se incluye en el informe. Revisión rápida en unos segundos;
   completa (puertos 1 a 10 000) en 1 a 2 minutos. Solo revisa dispositivos ya detectados en tu red local, solo TCP
   (un puerto cerrado no garantiza seguridad), y debe usarse **únicamente en dispositivos propios o con permiso**.

Guía completa, con cómo funciona por dentro y la solución de problemas: [`docs/APP.md`](docs/APP.md).

La aplicación está pensada también para **aprender**: cada tipo de tráfico y cada término se explica en palabras
simples, y hay un glosario integrado. Solo observa el tráfico del dispositivo; no lee su contenido (casi todo va cifrado).

## Instalación

Funciona en Windows, Linux y macOS. El modo visita (captura con hotspot) está pensado para **Windows**.

| Qué | Para qué | Cómo |
|---|---|---|
| **Python 3.8 o superior** | Ejecutar la herramienta (siempre) | [python.org/downloads](https://www.python.org/downloads/). En Windows, marca **"Add Python to PATH"** al instalar. Comprueba con `python --version`. |
| **Esta herramienta** | El código | En esta página pulsa el botón verde **Code**, luego **Download ZIP**, y descomprime. O con Git: `git clone https://github.com/torvi10997/iot-botnet-lab.git` |
| **Wireshark con TShark y Npcap** | Solo para capturar tráfico real (`visita`) | [wireshark.org/download](https://www.wireshark.org/download.html). Deja marcado **TShark** y acepta instalar **Npcap**. |

No hay que instalar nada más (no usa `pip`). Abre una terminal **dentro de la carpeta descomprimida** y ejecuta los comandos de abajo. Para capturar, abre la terminal **como administrador**.

Comprueba la instalación con `python -m botnet_lab --help`: debe mostrar la lista de comandos.

## Inicio rápido

**Lo más fácil (Windows):** conecta el dispositivo al hotspot de tu laptop y haz doble clic en `Abrir_app.bat`.

**Con la terminal** (como administrador, dentro de la carpeta de la herramienta):

```bash
# Abrir la aplicación con ventana (captura en vivo)
python -m botnet_lab app

# Ver en la ventana una captura que ya tengas (por ejemplo, la de un router MikroTik)
python -m botnet_lab app --abrir mi_captura.pcapng --gateway 192.168.88.1

# Revisar un dispositivo conectado a tu hotspot en consola (captura 15 minutos y genera el informe)
python -m botnet_lab visita --minutos 15

# Analizar una captura real que ya tengas (pcap o pcapng)
python -m botnet_lab analyze mi_captura.pcapng --device 192.168.1.50

# Generar el informe con semáforo de una captura existente, sin capturar
python -m botnet_lab visita --desde-captura mi_captura.pcapng
```

Para visitas en campo lee [`docs/VISITA.md`](docs/VISITA.md).

El código de salida es `2` si el veredicto es *sospechoso*, útil para scripts.

## Seguridad de la propia aplicación

La ventana es una página local que solo escucha en `127.0.0.1` y rechaza peticiones con `Host` u `Origin` ajenos
(protege contra DNS rebinding y contra otras webs abiertas en el navegador). Termina y detiene la captura al
cerrar la ventana. No envía datos a ningún servidor.

## Qué detecta

| Código | Indicio | Por qué importa |
|---|---|---|
| `UDP_FLOOD` | Inundación UDP sostenida (por defecto ≥ 200 pps durante ≥ 5 s) con casi ninguna respuesta | Es el ataque en sí: tráfico unidireccional hacia un tercero |
| `C2_ORDER` | Un mensaje pequeño entrante justo antes (≤ 2 s) de que empiece la inundación | Delata al servidor de control que da la orden |
| `BEACON` | Mensajes del mismo tamaño a intervalos regulares hacia un mismo destino (en puertos 80/443 solo informativo) | Latido del canal de control (en el caso real: 33 bytes, en pareja, cada 30 s) |
| `DNS_RANDOM` | Consultas DNS con etiquetas largas y aleatorias (incluso binarias) directo a resolvers públicos | Sondeo de dominios del malware o ruido |
| `DNS_BYPASS` | El equipo ignora el DNS del router | Informativo; muchos dispositivos lo hacen |
| `SCAN` | Muchos destinos/puertos distintos con SYN en pocos segundos | Búsqueda de nuevas víctimas |

Los umbrales se ajustan con `--min-pps`, `--min-secs` y `--local-net`. Ejemplo de resultado (direcciones de documentación, no son reales):

```
[ALTA] Inundación UDP desde 192.168.137.50 hacia 203.0.113.20:19132  (UDP_FLOOD)
    8850 paquetes en ~15 s (pico 600 pps, promedio 1190 B de datos), respuestas: 0%.
[ALTA] Orden de control 198.51.100.10:6969 seguida de inundación a 203.0.113.20  (C2_ORDER)
    Llegó un mensaje de 54 bytes 0.25 s antes de que empezara la inundación. ...
[MEDIA] Latido periódico 192.168.137.50 -> 198.51.100.10:6969  (BEACON)
Veredicto: SOSPECHOSO
```

## Validación

Se contrastó con capturas reales de un TV box infectado (reposo, en ataque y tras restablecer de fábrica): las tres capturas del equipo infectado salen *sospechosas* y la del restablecido, *sin indicios*. Es un solo caso, no un estudio; los umbrales pueden necesitar ajustes con otros equipos. Si lo pruebas con otro dispositivo, abre un issue con tus resultados (anonimizados).

## Límites (léelos)

- Es una **herramienta educativa y de triage**, no un antivirus ni un IDS. Un veredicto *sin indicios* en una captura corta no prueba que el equipo esté limpio: el malware puede estar callado durante minutos. Captura al menos 10 a 15 minutos, idealmente con el equipo en uso.
- Un `BEACON` o un `DNS_BYPASS` por sí solos suelen ser falsos positivos (notificaciones, apps). Lo fuerte es la combinación: latido + orden + inundación.
- Solo IPv4, TCP/UDP. Una captura cifrada (VPN, DoH) oculta parte de lo que se busca.
- Un equipo hecho para evadir (tráfico muy bajo y lento) no será detectado.

## Uso responsable

Captura solo **redes y dispositivos propios o con autorización expresa** del dueño. Esta herramienta solo observa: no ataca ni genera tráfico hacia terceros. No publiques capturas reales sin quitar IP, MAC y datos personales.

## Documentación

- [`docs/APP.md`](docs/APP.md): **guía completa de la aplicación**: cómo funciona, uso paso a paso, qué muestra cada parte de la pantalla, puertos abiertos, límites y solución de problemas.
- [`docs/VISITA.md`](docs/VISITA.md): guía del técnico para revisar un dispositivo en casa del cliente (modo visita, semáforo, consentimiento).
- [`docs/CAPTURA.md`](docs/CAPTURA.md): cómo capturar el tráfico de un TV box u otro dispositivo (hotspot en Windows, tshark).
- [`docs/MIKROTIK.md`](docs/MIKROTIK.md): reglas de ejemplo para detectar y bloquear en RouterOS 7.
- [`docs/RESPUESTA.md`](docs/RESPUESTA.md): qué hacer cuando encuentras uno (cliente, ISP, reporte).

## Pruebas

```bash
python -m unittest discover -s tests -v
```

Las pruebas usan una utilería interna que genera tráfico sintético (`tests/emulador_pruebas.py`); no forma parte de la herramienta.

## Contribuir

Ideas bienvenidas: detección de más familias, soporte IPv6, reglas para otros routers (OpenWrt, pfSense, Ubiquiti), traducciones. Abre un issue o un pull request. Las capturas reales de ejemplo deben estar anonimizadas.

## Licencia

MIT, ver [`LICENSE`](LICENSE).
