# La aplicación: cómo funciona y cómo se usa

El **Revisor de red** es una ventana de Windows que muestra, en vivo, qué hace un dispositivo conectado a tu red (un TV box, un teléfono, una cámara) y te dice si se comporta como un dispositivo infectado. Está pensada para **técnicos, colegas y personas curiosas** que quieren entender qué produce cada dispositivo cuando se conecta a internet.

## Cómo funciona (en palabras simples)

```
 Dispositivo  ──WiFi──►  Tu laptop (hotspot de Windows)  ──cable──►  Internet
                           │
                  tshark mira el tráfico
                           ▼
                  Revisor de red (esta app)
          agrupa por dispositivo · explica · da un semáforo
```

1. **Tu laptop hace de punto de acceso** (el hotspot de Windows). El dispositivo se conecta a él, así que *todo* su tráfico pasa por tu laptop. Por eso sirve con cualquier dispositivo, sin tocar el router del cliente.
2. **`tshark`** (parte de Wireshark) copia los paquetes que pasan. La app los lee al instante.
3. La app **agrupa el tráfico por dispositivo** (usando su MAC), lo clasifica en lenguaje simple (video, web, mensajería, publicidad...) y aprende los nombres de los servidores a partir de las consultas DNS.
4. Un **analizador** busca los indicios de un dispositivo usado como bot: inundaciones UDP sin respuesta, órdenes de un servidor de control, latidos regulares, consultas DNS con nombres sin sentido, barridos de puertos.
5. Todo se resume en un **semáforo** y, si quieres, en un **informe** para el cliente.

La app **solo observa**. No ataca, no modifica el dispositivo y no envía datos a ningún servidor. Casi todo el tráfico va cifrado, así que ve *quién habla con quién, cuándo y cuánto*, pero **no el contenido** de los mensajes.

## Qué necesitas

- Una laptop con **Windows 10 u 11**, WiFi y, de preferencia, **cable de red** (ver más abajo por qué).
- **Python 3.8 o superior** (con "Add Python to PATH").
- **Wireshark con TShark y Npcap.** Ver [Instalación en el README](../README.md#instalación).

> **Sobre Npcap:** la licencia de la edición gratuita permite un número limitado de instalaciones (cinco, con algunas excepciones). Si vas a instalarlo en muchas laptops de una empresa, revisa su [licencia](https://npcap.com/oem/). Esta herramienta no lo incluye ni lo redistribuye.

## Uso paso a paso

1. **Internet por cable.** Conecta la laptop a internet por Ethernet. Si sale por el mismo WiFi que va a compartir, Windows obliga al hotspot a usar 5 GHz y muchos dispositivos baratos solo ven 2,4 GHz.
2. **Enciende el hotspot:** Configuración, Red e Internet, *Zona con cobertura inalámbrica móvil*. Banda 2,4 GHz, nombre y clave sencillos.
3. **Conecta el dispositivo** a ese WiFi.
4. **Abre la aplicación:** doble clic en `Abrir_app.bat`. Abre la ventana sin pedir permisos especiales. Si el botón **Requisitos** avisa que Npcap está limitado a administradores, usa `Abrir_app_administrador.bat`.
5. **Pulsa "Iniciar captura"** y pon el dispositivo **en uso** (por ejemplo, reproduce un video). Los bots a veces solo atacan con el dispositivo activo.
6. **Mira la pantalla** (siguiente sección). Deja correr **10 minutos o más** para poder obtener un verde.
7. **"Generar informe"** crea un documento en lenguaje simple (carpeta `informes`) para entregar al cliente.
8. **Cierra la ventana** para terminar: la captura se detiene sola.

## Qué muestra cada parte de la pantalla

| Parte | Qué significa |
|---|---|
| **Dispositivos conectados** (izquierda) | Los dispositivos del hotspot, con nombre, MAC, IP y fabricante. Una MAC marcada "privada" es una dirección aleatoria que los teléfonos modernos cambian por red; es normal. |
| **Semáforo** | **Rojo:** señales claras de dispositivo comprometido. **Amarillo:** hay señales que revisar. **Verde:** no se vieron señales (solo con 10 minutos o más). **No concluyente:** captura corta o casi sin tráfico. |
| **Cuatro números** | Paquetes por segundo que salen y entran, y velocidad de subida y bajada. Con una etiqueta: reposo, uso normal, intenso o muy alto. |
| **Ritmo de 2 minutos** | Cuánto habla el dispositivo. Una inundación se ve como una meseta alta que sale pero casi no entra. |
| **¿Qué está haciendo?** | Pastel por tipo de tráfico: video, web, mensajería, DNS, publicidad, juegos... Pasa el cursor para ver qué es cada uno. |
| **Principales destinos** | Con quién habla, por volumen, con el nombre del servidor cuando se conoce. |
| **Tipo de conexión** | TCP contra UDP, con una explicación de qué es normal. |
| **Subida y bajada** | Un dispositivo doméstico normal baja mucho más de lo que sube. |
| **Detalle de conexiones** | Una fila por conversación. Resalta las que envían mucho y no reciben respuesta. |
| **Paquetes en vivo** | La lista de paquetes, como en Wireshark (con tope de 80 por segundo para no congelar la ventana en un ataque). |
| **Glosario** | Qué es una IP, una MAC, DNS, UDP, ADB, una botnet... |

Los botones **Pausar** y **Continuar** detienen y reanudan la captura sin perder lo ya observado. El tiempo de pausa no cuenta para los 10 minutos.

## Puertos abiertos del dispositivo

La pestaña **Puertos abiertos** revisa a qué servicios de red responde el dispositivo. Es el complemento del semáforo: el semáforo mide el *comportamiento* (¿está atacando?) y los puertos miden la *exposición* (¿qué puertas tiene abiertas?).

- **Revisión rápida** (unos segundos): 43 puertos comunes y de riesgo.
- **Revisión completa** (1 a 2 minutos): puertos 1 a 10 000 y los más explotados.
- **ADB (puerto 5555):** hace el saludo del protocolo para saber si el dispositivo acepta conexiones **sin clave** (riesgo alto: es la puerta que usan BADBOX y Kimwolf) o si exige autorización. No ejecuta ningún comando en el dispositivo.
- Cada puerto explica qué es, el riesgo y qué hacer. El resultado se incluye en el informe.

Solo revisa dispositivos ya detectados en tu red local y solo TCP: un puerto cerrado no garantiza seguridad. **Úsalo únicamente en dispositivos propios o con permiso de su dueño.**

## Requisitos: comprobar que todo está listo

El botón **Requisitos** (arriba a la derecha) revisa tu equipo y te dice qué falta y cómo arreglarlo. Se abre solo si falta algo importante. Muestra una insignia: **✔ Listo**, **⚠ avisos** o **✖ faltas**.

| Comprobación | Qué revisa | Si falla |
|---|---|---|
| Wireshark (TShark) | Que esté instalado el programa que copia los paquetes | Botón **Instalar Wireshark**: abre el instalador guiado con `winget`. Deja marcada la opción **TShark** |
| Npcap | Que esté el controlador de captura (y que no haya un WinPcap antiguo en conflicto) | Botón **Abrir descarga de Npcap**. Instálalo con las opciones por defecto |
| Interfaces de red | Que TShark vea adaptadores reales (no solo puertos USB) | Suele ser Npcap sin instalar o sin permisos |
| Permisos | Si Npcap está limitado a administradores y la app no lo es | Abrir con `Abrir_app_administrador.bat` |
| Hotspot de Windows | Si está encendido, en qué banda y cuántos dispositivos hay conectados | Botón **Abrir configuración del hotspot** |
| Internet del PC | Si tu PC sale a internet por WiFi: Windows fuerza entonces el hotspot a 5 GHz y muchos dispositivos baratos solo ven 2,4 GHz | Conecta el PC por cable de red |
| Ventana | Si hay Edge o Chrome para abrir la app como ventana | Se abre en tu navegador |
| **Prueba de captura** | Captura 4 segundos de verdad para confirmar que funciona | Muestra el error exacto de TShark |

> **Licencia de Npcap:** la edición gratuita permite un número limitado de instalaciones (cinco, con algunas excepciones). La app no lo instala ni lo redistribuye: solo abre su página oficial. Si lo usarás en muchas laptops de una empresa, revisa la [licencia](https://npcap.com/oem/).

## Abrir una captura del router

No siempre puedes poner un dispositivo en tu hotspot. Si tienes una captura hecha **en el router o en un switch** (por ejemplo, con el *sniffer* de MikroTik) o con Wireshark, el botón **Abrir captura…** la muestra en la misma ventana, con **muchos dispositivos a la vez**.

1. **Obtén la captura.** En MikroTik, un ejemplo (ajusta los nombres a tu equipo):
   ```
   /tool sniffer set filter-interface=<interfaz-LAN> filter-mac-address=<MAC-del-dispositivo> file-name=captura file-limit=50000
   /tool sniffer start
   # deja pasar 10 a 15 minutos con el dispositivo en uso
   /tool sniffer stop
   ```
   Descarga `captura.pcap` desde *Files*. Sin el filtro por MAC capturas todos los clientes de esa interfaz; pesará mucho más.
2. En la aplicación pulsa **Abrir captura…**, deja vacía la IP del router (se detecta sola) y elige el archivo. Puedes elegir varios.
3. La app lee el archivo y muestra los dispositivos con los **sospechosos primero** (rojo, luego amarillo). Si hay cientos, usa el **buscador** de la izquierda (nombre, MAC, IP o fabricante).

**El router se detecta solo:** es la dirección MAC que recibe casi todo el tráfico que va de la red local hacia internet. No se cuenta como un dispositivo. La app te lo indica arriba: *"Router detectado: IP · MAC"*. Si no lo detecta (o ves al router como un dispositivo), vuelve a abrir la captura escribiendo su IP.

Las capturas abiertas se analizan igual que las de en vivo (semáforo, pasteles, conexiones, informe). Dos diferencias: no hay botones de captura, y la revisión de **puertos abiertos** solo funciona con dispositivos que estén en tu red en ese momento. También desde la terminal: `python -m botnet_lab app --abrir captura.pcap [--gateway 10.11.0.1]`.

Para que un **verde** valga, la captura debe cubrir **10 minutos o más**; una captura corta da "No concluyente".

## Límites que debes conocer

- **No es un antivirus ni un IDS.** Un verde significa "no se vieron señales en este tiempo", no "está limpio". Un dispositivo infectado puede estar callado un buen rato.
- **Un solo caso real de calibración.** Los umbrales se ajustaron con un TV box genérico infectado y con un teléfono sano. Con otros dispositivos pueden aparecer falsos positivos o pasar algo por alto; si te pasa, abre un *issue* con tus resultados anonimizados.
- **Tráfico cifrado:** se ve el *quién y el cuánto*, no el *qué*.
- **Solo IPv4**, y la captura en vivo está pensada para **Windows**.

## Privacidad y uso responsable

- Captura **solo redes y dispositivos propios o con permiso expreso** del dueño. Avisa al cliente antes de capturar.
- Los informes y las capturas contienen IP, MAC y nombres. No los publiques sin quitar esos datos.
- La ventana es una página local que solo escucha en `127.0.0.1` y rechaza peticiones con `Host` u `Origin` ajenos (protege contra otras webs abiertas en el navegador). Al cerrar la ventana, la aplicación termina.

## Solución de problemas

| Síntoma | Causa probable | Qué hacer |
|---|---|---|
| "No detecté el hotspot de Windows" | El hotspot está apagado | Actívalo en *Zona con cobertura inalámbrica móvil*, o elige la interfaz a mano en el aviso |
| "Falta Wireshark (TShark)" | No está instalado o sin la opción TShark | Instálalo desde wireshark.org y marca **TShark** |
| El dispositivo no encuentra el WiFi | El hotspot está en 5 GHz | Conecta tu laptop a internet **por cable** y usa 2,4 GHz |
| "No se pudo capturar" | Falta permiso o Npcap | Pulsa **Requisitos**; si indica permisos, abre con `Abrir_app_administrador.bat` |
| No se abre la ventana | Edge/Chrome no pudo iniciar la ventana propia | No hace falta hacer nada: si la ventana no se conecta en 12 segundos, la app **abre sola tu navegador**. Si tampoco, copia en el navegador la dirección `http://127.0.0.1:...` que muestra la consola |
| La app se cerró sola | Se cerró la última ventana o pestaña | Con una captura en curso espera hasta 10 minutos sin señal de la ventana (los navegadores frenan las pestañas ocultas). El archivo `revisor_de_red.log` (en la carpeta temporal de Windows: escribe `%TEMP%` en el Explorador) dice a qué hora y por qué terminó |
| Aparece el dispositivo pero sin tráfico | Está inactivo | Ponlo en uso (un video) y pulsa **Iniciar captura** |
| Todo sale "No concluyente" | Captura de menos de 10 minutos | Deja correr más tiempo |
| "No se pudo abrir la captura" | El archivo no es un .pcap/.pcapng válido o no trae paquetes IPv4 | Verifica que se descargó completo; ábrelo antes en Wireshark |
| Ves al router como un dispositivo | No se detectó el router | Abre la captura de nuevo indicando su IP |
| Faltan cosas al abrir la app | Wireshark o Npcap | Pulsa **Requisitos** y sigue los pasos |
