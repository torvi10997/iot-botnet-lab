"""Traduce puertos y dominios a lenguaje simple: qué es cada conexión y por qué ocurre."""

CATEGORIAS = {
    "video": ("Video y música", "Reproducción de video o música: descarga mucho más de lo que envía."),
    "web": ("Páginas web y apps", "Navegación y apps que se conectan a internet de forma cifrada (HTTPS)."),
    "mensajeria": ("Mensajería y redes sociales", "WhatsApp, Instagram, Facebook, Telegram y similares."),
    "dns": ("Consulta de nombres (DNS)", "El dispositivo pregunta a qué dirección corresponde un nombre, como una agenda de teléfonos."),
    "notificaciones": ("Notificaciones y sincronización", "Conexiones que se mantienen abiertas para recibir avisos y sincronizar datos."),
    "sistema": ("Funciones de la red", "Hora, asignación de dirección (DHCP) y búsqueda de otros dispositivos. Es ruido normal."),
    "actualizaciones": ("Actualizaciones y tiendas", "Descarga de apps y del sistema."),
    "juegos": ("Juegos en línea", "Conexión con servidores de juegos y voz de partida."),
    "publicidad": ("Publicidad y seguimiento", "Redes de anuncios y analítica: miden qué haces para mostrarte publicidad. Es normal en apps gratuitas."),
    "atencion": ("Puertos que merecen atención", "Servicios que un dispositivo común rara vez usa hacia internet."),
    "desconocido": ("Sin identificar", "No reconocemos el servicio. No significa que sea malo: muchas apps usan puertos propios."),
}

# (protocolo, puerto) -> (categoría, nombre del servicio, explicación breve)
PUERTOS = {
    ("UDP", 53): ("dns", "DNS", "Pregunta a qué dirección corresponde un nombre (como buscar en una agenda)."),
    ("TCP", 53): ("dns", "DNS", "Pregunta a qué dirección corresponde un nombre (como buscar en una agenda)."),
    ("TCP", 853): ("dns", "DNS cifrado", "Consulta de nombres protegida: nadie en el camino puede leerla."),
    ("TCP", 443): ("web", "HTTPS", "Comunicación web cifrada. Es la mayoría del tráfico de un dispositivo normal."),
    ("UDP", 443): ("web", "QUIC (HTTP/3)", "Versión moderna y rápida de HTTPS. YouTube y Google la usan mucho."),
    ("TCP", 80): ("web", "HTTP", "Web sin cifrar. Cada vez menos común."),
    ("TCP", 8080): ("web", "HTTP alterno", "Web en un puerto alternativo."),
    ("TCP", 8443): ("web", "HTTPS alterno", "Web cifrada en un puerto alternativo."),
    ("UDP", 123): ("sistema", "NTP (hora)", "El dispositivo ajusta su reloj con un servidor de hora."),
    ("UDP", 67): ("sistema", "DHCP", "El dispositivo pide o renueva su dirección IP en la red."),
    ("UDP", 68): ("sistema", "DHCP", "El dispositivo pide o renueva su dirección IP en la red."),
    ("UDP", 5353): ("sistema", "mDNS", "Anuncia el dispositivo en la red local (Chromecast, AirPlay, impresoras)."),
    ("UDP", 1900): ("sistema", "SSDP/UPnP", "Busca o anuncia dispositivos en la red local."),
    ("TCP", 5228): ("notificaciones", "Google push", "Canal siempre abierto con Google para recibir notificaciones."),
    ("TCP", 5229): ("notificaciones", "Google push", "Canal siempre abierto con Google para recibir notificaciones."),
    ("TCP", 5230): ("notificaciones", "Google push", "Canal siempre abierto con Google para recibir notificaciones."),
    ("TCP", 5223): ("notificaciones", "Apple push", "Canal siempre abierto con Apple para recibir notificaciones."),
    ("UDP", 3478): ("mensajeria", "STUN (llamadas)", "Ayuda a conectar llamadas y videollamadas entre dos dispositivos."),
    ("UDP", 3479): ("mensajeria", "STUN (llamadas)", "Ayuda a conectar llamadas y videollamadas entre dos dispositivos."),
    ("TCP", 5222): ("mensajeria", "XMPP", "Mensajería instantánea."),
    ("UDP", 19132): ("juegos", "Minecraft Bedrock", "Servidor de juego de Minecraft (Bedrock)."),
    ("TCP", 25565): ("juegos", "Minecraft Java", "Servidor de juego de Minecraft (Java)."),
    ("TCP", 22): ("atencion", "SSH", "Acceso remoto por consola. Un dispositivo común no suele iniciarlo hacia internet."),
    ("TCP", 23): ("atencion", "Telnet", "Acceso remoto sin cifrar. Muy usado por malware para infectar dispositivos."),
    ("TCP", 5555): ("atencion", "ADB (Android)", "Depuración de Android por red. Abierto y sin clave es una puerta de entrada típica de botnets."),
    ("TCP", 3389): ("atencion", "Escritorio remoto", "Control remoto de un PC."),
    ("TCP", 445): ("atencion", "SMB", "Compartir archivos de Windows. No debería salir a internet."),
    ("UDP", 5060): ("atencion", "SIP", "Telefonía por internet. Los barridos de SIP buscan centrales para abusar."),
    ("TCP", 5060): ("atencion", "SIP", "Telefonía por internet. Los barridos de SIP buscan centrales para abusar."),
    ("UDP", 5061): ("atencion", "SIP", "Telefonía por internet."),
    ("TCP", 3306): ("atencion", "MySQL", "Base de datos. No debería recibir conexiones desde un dispositivo doméstico."),
}

# sufijo de dominio -> (categoría, nombre)
DOMINIOS = [
    ("googlevideo.com", "video", "YouTube"), ("youtube.com", "video", "YouTube"), ("ytimg.com", "video", "YouTube"),
    ("youtu.be", "video", "YouTube"), ("netflix.com", "video", "Netflix"), ("nflxvideo.net", "video", "Netflix"),
    ("nflximg.net", "video", "Netflix"), ("tiktokv.com", "video", "TikTok"), ("tiktok.com", "video", "TikTok"),
    ("tiktokcdn.com", "video", "TikTok"), ("spotify.com", "video", "Spotify"), ("scdn.co", "video", "Spotify"),
    ("twitch.tv", "video", "Twitch"), ("ttvnw.net", "video", "Twitch"), ("disneyplus.com", "video", "Disney+"),
    ("primevideo.com", "video", "Prime Video"), ("aiv-cdn.net", "video", "Prime Video"),
    ("whatsapp.net", "mensajeria", "WhatsApp"), ("whatsapp.com", "mensajeria", "WhatsApp"),
    ("instagram.com", "mensajeria", "Instagram"), ("cdninstagram.com", "mensajeria", "Instagram"),
    ("facebook.com", "mensajeria", "Facebook"), ("fbcdn.net", "mensajeria", "Facebook"), ("fb.com", "mensajeria", "Facebook"),
    ("telegram.org", "mensajeria", "Telegram"), ("t.me", "mensajeria", "Telegram"),
    ("twitter.com", "mensajeria", "X / Twitter"), ("twimg.com", "mensajeria", "X / Twitter"), ("x.com", "mensajeria", "X / Twitter"),
    ("snapchat.com", "mensajeria", "Snapchat"), ("discord.com", "mensajeria", "Discord"), ("discord.gg", "mensajeria", "Discord"),
    ("signal.org", "mensajeria", "Signal"),
    ("mtalk.google.com", "notificaciones", "Google push"), ("push.apple.com", "notificaciones", "Apple push"),
    ("icloud.com", "notificaciones", "iCloud"), ("apple.com", "notificaciones", "Apple"),
    ("windowsupdate.com", "actualizaciones", "Windows Update"), ("delivery.mp.microsoft.com", "actualizaciones", "Windows Update"),
    ("play.googleapis.com", "actualizaciones", "Google Play"), ("android.clients.google.com", "actualizaciones", "Google Play"),
    ("mzstatic.com", "actualizaciones", "App Store"), ("apps.apple.com", "actualizaciones", "App Store"),
    ("garena.com", "juegos", "Garena / Free Fire"), ("freefiremobile.com", "juegos", "Free Fire"),
    ("activision.com", "juegos", "Call of Duty"), ("callofduty.com", "juegos", "Call of Duty"),
    ("epicgames.com", "juegos", "Epic Games"), ("riotgames.com", "juegos", "Riot Games"),
    ("roblox.com", "juegos", "Roblox"), ("steampowered.com", "juegos", "Steam"), ("minecraft.net", "juegos", "Minecraft"),
    ("dns.google", "dns", "DNS de Google"), ("cloudflare-dns.com", "dns", "DNS de Cloudflare"),
    ("googleapis.com", "web", "Servicios de Google"), ("gstatic.com", "web", "Google"), ("google.com", "web", "Google"),
    ("googleusercontent.com", "web", "Google"), ("cloudflare.com", "web", "Cloudflare"),
    ("amazonaws.com", "web", "Amazon (nube)"), ("akamaiedge.net", "web", "Akamai (CDN)"),
    ("applovin.com", "publicidad", "AppLovin (anuncios)"), ("doubleclick.net", "publicidad", "Google Ads"),
    ("googlesyndication.com", "publicidad", "Google Ads"), ("googleadservices.com", "publicidad", "Google Ads"),
    ("appsflyer.com", "publicidad", "AppsFlyer (medición)"), ("adjust.com", "publicidad", "Adjust (medición)"),
    ("unity3d.com", "publicidad", "Unity (anuncios y servicios)"), ("unityads.unity3d.com", "publicidad", "Unity Ads"),
    ("vungle.com", "publicidad", "Vungle (anuncios)"), ("ironsrc.com", "publicidad", "ironSource (anuncios)"),
    ("facebook.net", "publicidad", "Meta (seguimiento)"), ("branch.io", "publicidad", "Branch (medición)"),
    ("licdn.com", "mensajeria", "LinkedIn"), ("linkedin.com", "mensajeria", "LinkedIn"),
    ("aaplimg.com", "actualizaciones", "Apple (apps y sistema)"), ("itunes.apple.com", "actualizaciones", "App Store"),
    ("kwcdn.com", "web", "Imágenes de tienda en línea"),
    ("microsoft.com", "web", "Microsoft"), ("msftconnecttest.com", "sistema", "Prueba de conexión de Windows"),
]


def _sufijo(dominio):
    d = dominio.lower().rstrip(".")
    for suf, cat, nombre in DOMINIOS:
        if d == suf or d.endswith("." + suf):
            return cat, nombre
    return None


def describir(proto, puerto, dominio=None):
    """Devuelve (categoría, servicio, explicación) de una conexión."""
    por_puerto = PUERTOS.get((proto, puerto))
    if dominio:
        s = _sufijo(dominio)
        if s and not (por_puerto and por_puerto[0] == "atencion"):
            cat, nombre = s
            expl = por_puerto[2] if por_puerto else CATEGORIAS[cat][1]
            return cat, nombre, expl
    if por_puerto:
        return por_puerto
    return "desconocido", "%s %d" % (proto, puerto), CATEGORIAS["desconocido"][1]


GLOSARIO = [
    ("Paquete", "Un trocito de información. Todo lo que hace un dispositivo en la red se divide en paquetes, como cartas muy pequeñas."),
    ("IP", "La dirección de un dispositivo en la red, como el número de una casa. La del servidor al que se conecta es la dirección de destino."),
    ("MAC", "El identificador de la tarjeta de red del dispositivo. Algunos teléfonos usan una MAC aleatoria por red, para que no los rastreen."),
    ("DNS", "La agenda de internet: convierte un nombre como youtube.com en una dirección IP. Casi todo empieza con una consulta DNS."),
    ("TCP", "Un tipo de conexión que confirma que todo llegó. Se usa para páginas web, correo, mensajes."),
    ("UDP", "Un tipo de conexión rápida que no espera confirmación. Se usa para video, llamadas, juegos... y también para ataques de inundación."),
    ("QUIC / HTTP/3", "Una forma moderna de hablar con la web sobre UDP. YouTube la usa; por eso verás mucho UDP al ver videos y es normal."),
    ("Paquetes por segundo (pps)", "Qué tan rápido habla el dispositivo. Reposo: casi nada. Un video: cientos. Un ataque de inundación: miles hacia un solo destino y sin respuesta."),
    ("Respuesta", "En una conversación normal, el servidor contesta. Una inundación envía y envía, pero casi nunca recibe respuesta."),
    ("Servidor de control", "Un servidor que da órdenes a dispositivos infectados. Suele dejar un 'latido' regular y mensajes cortos justo antes de un ataque."),
    ("Publicidad y seguimiento", "Muchas apps gratuitas se financian con anuncios y miden tu uso. Aparecen como conexiones a redes publicitarias; no es un ataque."),
    ("SYN", "El primer mensaje de una conexión TCP («quiero conectarme»). Una inundación SYN envía miles por segundo a un servicio para saturarlo; en una conexión normal el servidor responde (SYN-ACK)."),
    ("ICMP / ping", "Un mensaje de prueba de red: «¿estás ahí?». Un ping normal es uno por segundo; cientos por segundo hacia un mismo destino son una inundación."),
    ("Botnet", "Una red de dispositivos infectados controlados a distancia, usados sin que su dueño lo sepa para atacar a otros."),
    ("ADB", "Depuración de Android por red. Si está abierta y sin clave en un TV box, cualquiera puede controlarlo."),
]
