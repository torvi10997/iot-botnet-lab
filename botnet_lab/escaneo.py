"""Revisión de puertos abiertos de un aparato (TCP), con explicaciones en lenguaje simple.

Solo se debe usar en aparatos propios o con permiso de su dueño. No explota nada: abre una conexión TCP,
lee el saludo del servicio si lo hay y, en el puerto 5555, hace el saludo del protocolo ADB para saber si
pide clave (no ejecuta ningún comando en el aparato).
"""
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# puerto -> (servicio, riesgo, qué es, qué hacer)
# riesgo: "alto", "medio", "bajo", "info"
PUERTOS = {
    21: ("FTP", "medio", "Transferencia de archivos sin cifrar.", "Apagarlo si no se usa."),
    22: ("SSH", "medio", "Acceso remoto por consola. Si el aparato lo trae activo y con clave por defecto, es una puerta de entrada.", "Cambiar la clave por defecto o desactivarlo."),
    23: ("Telnet", "alto", "Acceso remoto SIN cifrar. Es la puerta que más usa el malware tipo Mirai.", "Desactivarlo. Un aparato doméstico no debería tenerlo."),
    25: ("SMTP", "medio", "Envío de correo. Un aparato doméstico no debería ofrecerlo.", "Desactivarlo."),
    53: ("DNS", "bajo", "El aparato responde consultas de nombres (actúa como un pequeño servidor DNS).", "Normal en routers; raro en un TV box."),
    80: ("HTTP", "bajo", "Panel web sin cifrar (configuración o administración del aparato).", "Cambiar la clave de administración; que no sea accesible desde internet."),
    81: ("HTTP alterno", "bajo", "Panel web en puerto alterno.", "Revisar quién lo usa."),
    110: ("POP3", "medio", "Correo sin cifrar.", "Desactivarlo."),
    135: ("RPC de Windows", "medio", "Servicio interno de Windows.", "No debería ser visible en la red."),
    139: ("NetBIOS", "medio", "Compartir archivos de Windows (antiguo).", "Desactivarlo si no se usa."),
    143: ("IMAP", "medio", "Correo sin cifrar.", "Desactivarlo."),
    443: ("HTTPS", "bajo", "Panel web cifrado.", "Cambiar la clave de administración."),
    445: ("SMB", "alto", "Compartir archivos de Windows. Muchos gusanos lo explotan.", "Cerrarlo si no es un PC que comparte archivos a propósito."),
    554: ("RTSP (cámara)", "medio", "Transmisión de video de una cámara.", "Ponerle clave y no exponerla a internet."),
    631: ("IPP (impresora)", "bajo", "Servicio de impresión.", "Normal en impresoras."),
    1080: ("Proxy SOCKS", "alto", "Un aparato que ofrece proxy puede estar siendo usado para esconder tráfico de otros (típico de infecciones).", "Revisar de inmediato."),
    1883: ("MQTT", "medio", "Mensajería de domótica. Sin clave permite controlar sensores.", "Ponerle usuario y clave."),
    2323: ("Telnet alterno", "alto", "Variante de Telnet que usa el malware tipo Mirai.", "Desactivarlo."),
    3128: ("Proxy HTTP", "alto", "Un aparato que ofrece proxy puede estar siendo usado para esconder tráfico de otros.", "Revisar de inmediato."),
    3306: ("MySQL", "medio", "Base de datos. No debería estar en un aparato doméstico.", "Cerrarlo."),
    3389: ("Escritorio remoto", "alto", "Control remoto de un PC Windows.", "Cerrarlo o protegerlo con clave fuerte."),
    5000: ("UPnP / panel", "bajo", "Servicio de descubrimiento o panel de un NAS.", "Revisar quién lo usa."),
    5555: ("ADB (Android)", "alto", "Depuración de Android por red. Abierto y sin clave permite controlar el aparato por completo. Es la puerta de entrada de botnets como BADBOX y Kimwolf.", "Apagar la depuración USB/inalámbrica; si no se puede, reemplazar el aparato."),
    5900: ("VNC", "alto", "Control remoto del escritorio, a menudo sin cifrar.", "Cerrarlo o ponerle clave."),
    6666: ("Puerto usado por malware", "medio", "Puerto frecuente de canales de control de botnets, aunque también lo usan algunas apps.", "Averiguar qué programa lo abre."),
    6969: ("Puerto usado por malware", "medio", "Puerto visto en canales de control de botnets, aunque también lo usan algunas apps.", "Averiguar qué programa lo abre."),
    7547: ("TR-069 (gestión de router)", "alto", "Gestión remota de routers del operador. Se ha explotado en grandes botnets.", "Verificar que solo el operador pueda alcanzarlo."),
    8000: ("Panel web alterno", "bajo", "Panel web en puerto alterno.", "Revisar quién lo usa."),
    8008: ("Chromecast (HTTP)", "info", "Control de un Chromecast o Google TV en la red local.", "Normal en Google TV."),
    8009: ("Chromecast (control)", "info", "Control de un Chromecast o Google TV.", "Normal en Google TV."),
    8060: ("Roku", "info", "Control remoto de un Roku.", "Normal en Roku."),
    8080: ("HTTP alterno", "bajo", "Panel web o servidor en puerto alterno. En TV box genéricos suele ser un servicio de la app o del malware.", "Averiguar qué lo abre."),
    8081: ("HTTP alterno", "bajo", "Panel web en puerto alterno.", "Revisar quién lo usa."),
    8443: ("HTTPS alterno", "bajo", "Panel web cifrado en puerto alterno.", "Revisar quién lo usa."),
    8554: ("RTSP alterno", "medio", "Transmisión de video en puerto alterno.", "Ponerle clave."),
    8888: ("Servidor alterno", "bajo", "Servicio en puerto alterno.", "Revisar quién lo usa."),
    9100: ("Impresión directa", "bajo", "Impresión sin autenticación.", "Normal en impresoras de red."),
    9999: ("Servicio en puerto alterno", "bajo", "Usado por algunas cámaras y apps.", "Revisar quién lo usa."),
    10001: ("Servicio en puerto alterno", "bajo", "Usado por algunas cámaras y apps.", "Revisar quién lo usa."),
    37215: ("Gestión de router Huawei", "alto", "Puerto explotado por botnets contra routers Huawei.", "Actualizar el firmware o reemplazar."),
    49152: ("UPnP", "bajo", "Descubrimiento de servicios en la red.", "Desactivar UPnP en el router si no se usa."),
    52869: ("UPnP (Realtek)", "alto", "Puerto explotado por botnets contra routers con chip Realtek.", "Actualizar el firmware."),
    62078: ("iPhone sincronización", "info", "Servicio de sincronización y gestión de un iPhone o iPad con tu computador.", "Normal en dispositivos Apple."),
}

RAPIDO = sorted(PUERTOS)
EXTRAS_COMPLETO = [37215, 52869, 49152, 49153, 50000, 55443, 60001]
RIESGO_ORDEN = {"alto": 0, "medio": 1, "bajo": 2, "info": 3}
ETIQUETA = {"alto": "Riesgo alto", "medio": "Riesgo medio", "bajo": "Riesgo bajo", "info": "Informativo"}

_CNXN = 0x4E584E43
_AUTH = 0x48545541


def sondear_adb(ip, puerto=5555, timeout=2.5):
    """Saludo del protocolo ADB. Devuelve 'sin_clave' (grave), 'pide_clave' o 'desconocido'.
    No ejecuta comandos: solo envía CNXN y mira si el aparato contesta CNXN (acepta) o AUTH (exige clave)."""
    datos = b"host::\x00"
    cab = struct.pack("<6I", _CNXN, 0x01000000, 256 * 1024, len(datos), sum(datos) & 0xFFFFFFFF, _CNXN ^ 0xFFFFFFFF)
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(cab + datos)
            r = b""
            while len(r) < 24:
                b = s.recv(24 - len(r))
                if not b:
                    break
                r += b
            if len(r) < 24:
                return "desconocido"
            cmd = struct.unpack("<I", r[:4])[0]
            return "sin_clave" if cmd == _CNXN else "pide_clave" if cmd == _AUTH else "desconocido"
    except OSError:
        return "desconocido"


def _limpio(b, n=90):
    t = b.decode("latin-1", "replace")
    t = "".join(c if 32 <= ord(c) < 127 else " " for c in t).strip()
    return " ".join(t.split())[:n]


def _banner(ip, puerto, timeout=1.2):
    """Saludo del servicio, si lo hay (SSH, FTP, Telnet) o cabecera 'Server' de un panel web."""
    try:
        with socket.create_connection((ip, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            if puerto in (80, 81, 8000, 8008, 8080, 8081, 8888, 9999, 10001, 5000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                data = s.recv(600)
                server = next((l for l in data.split(b"\r\n") if l.lower().startswith(b"server:")), b"")
                linea1 = data.split(b"\r\n", 1)[0]
                return _limpio(linea1 + (b" | " + server if server else b""))
            if puerto in (21, 22, 23, 25, 110, 143):
                return _limpio(s.recv(200))
    except OSError:
        pass
    return ""


def _conecta(ip, puerto, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, puerto)) == 0
    except OSError:
        return False
    finally:
        s.close()


def lista_puertos(modo):
    if modo == "completo":
        return sorted(set(range(1, 10001)) | set(EXTRAS_COMPLETO) | set(PUERTOS))
    return RAPIDO


def escanear(ip, puertos=None, timeout=0.7, hilos=80, progreso=None, cancelar=None):
    """Revisa los puertos TCP de `ip`. Devuelve una lista ordenada por riesgo."""
    puertos = list(puertos or RAPIDO)
    total, hecho, abiertos = len(puertos), [0], []
    lock = threading.Lock()

    def uno(p):
        if cancelar is not None and cancelar.is_set():
            return
        if _conecta(ip, p, timeout):
            with lock:
                abiertos.append(p)
        with lock:
            hecho[0] += 1
            if progreso:
                progreso(hecho[0], total)

    with ThreadPoolExecutor(max_workers=hilos) as ex:
        list(ex.map(uno, puertos))

    res = []
    for p in sorted(abiertos):
        serv, riesgo, que, hacer = PUERTOS.get(p, ("Servicio sin identificar", "info",
                                                   "Hay un programa escuchando en este puerto. No lo reconocemos.",
                                                   "Averiguar qué app o servicio lo abre."))
        item = {"puerto": p, "servicio": serv, "riesgo": riesgo, "etiqueta": ETIQUETA[riesgo], "que_es": que,
                "que_hacer": hacer, "banner": _banner(ip, p), "extra": None}
        if p == 5555:
            est = sondear_adb(ip, p)
            item["extra"] = est
            if est == "sin_clave":
                item["riesgo"], item["etiqueta"] = "alto", "Riesgo alto"
                item["que_es"] = ("ADB está abierto y ACEPTA conexiones sin pedir clave: cualquiera en la red puede "
                                  "controlar el aparato. Es exactamente la puerta que usan BADBOX y Kimwolf.")
            elif est == "pide_clave":
                item["riesgo"], item["etiqueta"] = "medio", "Riesgo medio"
                item["que_es"] = "ADB está abierto pero exige autorización en el aparato. Mejor, pero conviene apagarlo."
        res.append(item)
    res.sort(key=lambda x: (RIESGO_ORDEN[x["riesgo"]], x["puerto"]))
    return res


def resumen(res):
    n = {k: sum(1 for x in res if x["riesgo"] == k) for k in RIESGO_ORDEN}
    peor = next((k for k in ("alto", "medio", "bajo", "info") if n[k]), None)
    return {"abiertos": len(res), "alto": n["alto"], "medio": n["medio"], "bajo": n["bajo"], "info": n["info"],
            "peor": peor}


class Trabajo:
    """Un escaneo en segundo plano, para consultar su progreso desde la ventana."""

    def __init__(self, ip, modo):
        self.ip, self.modo = ip, modo
        self.estado = "corriendo"
        self.hecho = self.total = 0
        self.resultados = []
        self.error = None
        self.t0 = time.time()
        self.t1 = None
        self.cancelar = threading.Event()

    def _progreso(self, h, t):
        self.hecho, self.total = h, t

    def _correr(self):
        try:
            self.resultados = escanear(self.ip, lista_puertos(self.modo), progreso=self._progreso,
                                       cancelar=self.cancelar)
            self.estado = "cancelado" if self.cancelar.is_set() else "listo"
        except Exception as e:
            self.error, self.estado = str(e), "error"
        self.t1 = time.time()

    def iniciar(self):
        threading.Thread(target=self._correr, daemon=True).start()
        return self

    def datos(self):
        return {"ip": self.ip, "modo": self.modo, "estado": self.estado, "hecho": self.hecho, "total": self.total,
                "resultados": self.resultados, "resumen": resumen(self.resultados), "error": self.error,
                "segundos": round((self.t1 or time.time()) - self.t0)}
