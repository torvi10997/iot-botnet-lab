# Seguridad de la aplicación

Esta herramienta captura tráfico de red, ejecuta programas del sistema (`tshark`, PowerShell) y abre un servidor local. Por eso se revisó su seguridad. Este documento dice qué se revisó, qué se encontró, qué se corrigió y qué **no** se puede garantizar.

> **Alcance honesto.** La revisión la hizo el autor con ayuda de un asistente de IA: revisión del código, pruebas de ataque contra el servidor en marcha, pruebas con datos malformados y con un dispositivo hostil simulado. **No es una auditoría de terceros ni una prueba de penetración independiente.** Si encuentras algo, mira [cómo reportarlo](../SECURITY.md).

## Modelo de amenazas

| Quién ataca | Qué podría intentar |
|---|---|
| **Una página web maliciosa** abierta en tu navegador mientras usas la app | Hablar con el servidor local (peticiones cruzadas, DNS rebinding) para ver datos de tu red o detener la captura |
| **Otro programa o usuario de tu mismo PC** | Usar el servidor local sin permiso, sobre todo si la app corre como administrador |
| **El propio dispositivo analizado** (puede estar infectado, es decir, hostil) | Mandar paquetes malformados o inundar de datos para tumbar la app; poner texto malicioso en nombres, DNS o saludos de servicio |
| **Un archivo de captura** manipulado | Provocar fallos o consumo excesivo al abrirlo |
| **Una carpeta con archivos plantados** | Que se ejecute un programa falso (por ejemplo `powershell.exe`) en lugar del real |

## Hallazgos y estado

| # | Severidad | Hallazgo | Corrección | Verificado |
|---|---|---|---|---|
| 1 | **Alta** | **Agotamiento de memoria por un dispositivo hostil.** Suplantando direcciones MAC o barriendo destinos, un solo dispositivo podía hacer crecer la memoria sin límite (medido: ~6 GB proyectados por millón de paquetes, en un PC de 11,8 GB) | Topes por dispositivo y un **presupuesto global** de entradas compartido por todos; lo que lo supera se ignora y la ventana avisa | Medición repetida: 374 MB → 11 MB en suplantación y 166 MB → 17 MB en barrido. Pruebas automáticas |
| 2 | Media | **El servidor local no tenía autenticación.** Cualquier proceso o usuario del PC podía usarlo (con la app como administrador, sería una escalada) | **Secreto de sesión** aleatorio: se entrega en el enlace que abre la ventana, pasa a una cookie `HttpOnly` + `SameSite=Strict` y se quita de la barra de direcciones. Sin él, todo da 403 | Pruebas automáticas y ataque manual |
| 3 | Media | **Interfaz de captura arbitraria.** La API aceptaba cualquier texto como interfaz, y `tshark` entiende destinos remotos (`rpcap://…`) y archivos. Se pudo pedir una conexión a un host ajeno | **Lista permitida:** solo las interfaces que `tshark` mismo lista | Se repitió el ataque: ahora responde «Interfaz no válida» |
| 4 | Baja-media | **Conexiones a medias sin límite de tiempo** (tipo *slowloris*): 40 conexiones abiertas retenían 40 hilos para siempre | Tiempo límite de 15 s por conexión, tope de 64 conexiones simultáneas | 40 conexiones a medias → 0 hilos a los 17 s |
| 5 | Baja | **Entradas abusivas:** cuerpo POST sin tamaño máximo (un `Content-Length` de 5 GB dejaba el hilo esperando), valores no numéricos y JSON que no es objeto provocaban excepciones | Máximo 64 KB, respuestas 400/413, todos los campos se validan | Excepciones internas durante el ataque: 27 → 0 |
| 6 | Baja | **Un paquete problemático podía detener toda la captura** (una excepción terminaba el hilo lector) | Cada paquete se procesa por separado; los errores se cuentan | Prueba automática |
| 7 | Baja | **Programas buscados en el directorio actual.** En Windows, `powershell`, `tshark` o `python` sin ruta se buscan primero ahí | Rutas absolutas del sistema; el PATH se recorre sin mirar el directorio actual; los `.bat` activan `NoDefaultCurrentDirectoryInExePath` | Prueba automática |
| 8 | Baja | **Comillas frágiles** en `Abrir_app_administrador.bat` (una carpeta con apóstrofes rompía el comando) | La ruta viaja en una variable de entorno | Revisión |
| 9 | Baja | **Sin cabeceras de seguridad** | `Content-Security-Policy` (sin conexiones externas, sin incrustación, sin formularios), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store` | Pruebas automáticas |
| 10 | Info | **Flujo de pruebas de GitHub** con permisos amplios y acciones por etiqueta | Permisos de solo lectura, acciones fijadas por huella (SHA), Dependabot mensual | Revisión |
| 11 | Info | Las carpetas temporales de la ventana se acumulaban | Se borran al salir y las de más de un día, al iniciar | Revisión |
| 12 | Baja | **Instalador de Wireshark con `shell=True`** (marcado por Bandit; el comando era una constante, no explotable) | Llamada directa con lista de argumentos, sin intérprete de comandos | Prueba automática |

## Lo que ya estaba bien (y se comprobó)

- **Sin inyección de código en la interfaz.** Con datos hostiles (nombres de dominio, nombre del dispositivo, saludos de servicio y resultado de puertos con `"><img onerror=…>`, `<svg onload=…>` y `</script><script>…`) mostrados en la ventana real, **nada se ejecutó** y no se creó ningún elemento: todo se muestra como texto.
- **Defensa contra DNS rebinding y otras webs:** se rechazan `Host` y `Origin` ajenos (también `Origin: null`).
- **Sin ejecución dinámica de código:** no hay `eval`, `exec`, `pickle` ni equivalentes. Todos los `subprocess` reciben listas de argumentos fijas; el único `shell=True` usa una constante.
- **Rutas:** el servidor solo sirve una página fija; los intentos de recorrido de directorios (`../`, codificados y con `\`) dan 404.
- **Lector de paquetes robusto:** 120 000 paquetes mutados al azar, 100 000 mensajes DNS aleatorios y 300 archivos de captura corruptos, **sin un solo fallo no controlado**. Un registro que declara 4 GB no reserva memoria.
- **La revisión de puertos** solo apunta a dispositivos ya detectados en la red local, nunca a una IP cualquiera, y no ejecuta comandos en el dispositivo (en ADB, solo el saludo del protocolo).
- **Sin dependencias de terceros:** solo la biblioteca estándar de Python, así que no hay cadena de suministro de paquetes que vigilar.

## Límites conocidos (lo que queda)

- **La política `Content-Security-Policy` permite scripts en línea** (`'unsafe-inline'`), porque la interfaz usa manejadores en los elementos. Aun así, impide conexiones a otros sitios y la incrustación, pero no sustituye al escapado de texto, que es la defensa principal.
- **El secreto de sesión viaja en la línea de comandos de Edge** al abrir la ventana. Lo ven otros procesos **del mismo usuario** (que ya tienen su mismo nivel de acceso), no los de otros usuarios.
- **El dispositivo sospechoso queda en la misma red que tu laptop.** Si está infectado, puede intentar atacar al propio PC por la red del hotspot. Mantén activo el firewall de Windows, no compartas carpetas ni impresoras desde ese PC y usa el hotspot, no la red de la oficina.
- **La captura (y los informes) contienen IP, MAC y nombres** que identifican a personas. La app los deja en tu PC; protégelos igual que cualquier dato personal.
- **Un presupuesto de memoria agotado** hace que lo nuevo ya no se registre (la ventana lo avisa). Es una pérdida de detalle, no una caída.
- **No está revisada por una persona o empresa ajena.** Como complemento, cada cambio pasa **Bandit** (análisis estático de Python: 0 hallazgos de severidad media o alta; los avisos bajos son por usar `subprocess` con listas de argumentos fijas) y **CodeQL** (análisis de seguridad de GitHub), y ambos se repiten cada semana. Una prueba de penetración independiente, por ejemplo con una herramienta de IA como [Strix](https://github.com/UseStrix/strix), se consideró pero no se ejecutó (tiene costo por uso del modelo de IA).

## Recomendaciones para quien la use

1. Usa **`Abrir_app.bat`**, no la versión de administrador, salvo que **Requisitos** te lo indique.
2. No abras el enlace del servidor (`http://127.0.0.1:…`) en otro navegador ni lo compartas: lleva el secreto de la sesión.
3. Descarga solo desde el repositorio oficial y comprueba que la carpeta no traiga archivos extraños (`.exe`, `.dll`) junto a los `.bat`.
4. Borra los informes y capturas cuando termine el caso.
