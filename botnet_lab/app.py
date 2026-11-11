"""Aplicación de escritorio: servidor local + ventana propia con la captura en vivo."""
import datetime
import http.server
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import escaneo, informe, requisitos, servicios, visita, vivo
from .pcapio import read_packets

WEB = Path(__file__).parent / "web"
RUTA_LOG = os.path.join(tempfile.gettempdir(), "revisor_de_red.log")


def _log(msg):
    """Registro de eventos de la ventana (para diagnosticar si algo no abre o se cierra)."""
    try:
        with open(RUTA_LOG, "a", encoding="utf8") as f:
            f.write("%s  %s\n" % (datetime.datetime.now().strftime("%H:%M:%S"), msg))
    except OSError:
        pass
CARPETA_INFORMES = "informes"


class App:
    def __init__(self, gateway=None, interfaz=None, abrir=None):
        self.tshark = visita.buscar_tshark()
        self.estado = vivo.Estado(gateway=gateway or vivo.GATEWAY_HOTSPOT, tshark=self.tshark)
        self.captura = None
        self.interfaz_forzada = interfaz
        self.interfaces = visita.listar_interfaces(self.tshark) if self.tshark else []
        self.sugerida = interfaz or (visita.interfaz_hotspot(self.interfaces) if self.tshark else None)
        self.guardar = False
        self.abrir_informe = True
        self.escaneos = {}                    # MAC -> escaneo.Trabajo
        self.carga = {"activa": False, "archivos": [], "paquetes": 0, "error": None}
        self.origen = None                    # datos de la captura abierta (si se está viendo un archivo)
        self._req = (0.0, None)               # (momento, diagnóstico en caché)
        self.archivo_captura = None
        self.paginas = {}                     # id de página -> último aviso (momento)
        self.hubo_paginas = False
        self.ultimo_cierre = 0.0
        self.inicio = time.time()
        self.lock = threading.Lock()
        if abrir:
            self.cargar_capturas(abrir, gateway)

    def _construir(self, rutas, gateway=None, progreso=None):
        """Lee capturas y devuelve (estado, datos del origen). Detecta el router si no se indica."""
        gw_ip, gw_mac = gateway, None
        if not gateway:
            gw_ip, gw_mac = vivo.detectar_router(itertools.islice(read_packets(rutas[0]), 80000))
        est = vivo.Estado(gateway=gw_ip or self.estado.gw, tshark=self.tshark)
        est.gw_mac, est.solo_archivo = gw_mac, True
        t0 = t1 = None
        n = 0
        for f in rutas:
            for pk in read_packets(f):
                est.procesar(pk)
                t0 = pk.ts if t0 is None else t0
                t1 = pk.ts
                n += 1
                if progreso and n % 2000 == 0:
                    progreso(n)
        if t0 is not None:
            est._acum = t1 - t0
        if progreso:
            progreso(n)
        origen = {"archivos": [os.path.basename(r) for r in rutas], "router_ip": gw_ip if gw_ip else None,
                  "router_mac": gw_mac, "automatico": not gateway, "paquetes": n}
        return est, origen

    def cargar_capturas(self, archivos, gateway=None):
        """Carga capturas existentes (.pcap/.pcapng) como si se hubieran visto en vivo."""
        self.estado, self.origen = self._construir(list(archivos), gateway)

    def _cargar_hilo(self, rutas, gateway):
        c = self.carga = {"activa": True, "archivos": [os.path.basename(r) for r in rutas], "paquetes": 0, "error": None}
        try:
            est, origen = self._construir(rutas, gateway, progreso=lambda n: c.__setitem__("paquetes", n))
            if origen["paquetes"] == 0:
                raise ValueError("El archivo no contiene paquetes IPv4 legibles (¿es una captura válida?).")
            with self.lock:
                self.estado, self.origen = est, origen
                self.escaneos, self.captura = {}, None
        except Exception as e:
            c["error"] = str(e)
        c["activa"] = False

    def abrir_captura(self, gateway=None):
        """Muestra el diálogo de Windows para elegir una o varias capturas y las carga en segundo plano."""
        c = self.captura
        if c and c.estado_txt in ("capturando", "pausada"):
            return {"ok": False, "error": "Detén la captura en vivo antes de abrir un archivo."}
        if self.carga["activa"]:
            return {"ok": False, "error": "Ya se está cargando una captura."}
        if gateway and not _es_ip(gateway):
            return {"ok": False, "error": "La IP del router no es válida."}
        rutas = elegir_archivos()
        if not rutas:
            return {"ok": False, "cancelado": True}
        threading.Thread(target=self._cargar_hilo, args=(rutas, gateway or None), daemon=True).start()
        return {"ok": True, "archivos": [os.path.basename(r) for r in rutas]}

    # ---- requisitos
    def requisitos_json(self, forzar=False):
        t, cache = self._req
        if forzar or cache is None or time.time() - t > 30:
            datos = requisitos.recoger(self.tshark, self.interfaces, _buscar_edge())
            checks = requisitos.evaluar(datos)
            cache = {"checks": checks, "resumen": requisitos.resumen(checks)}
            self._req = (time.time(), cache)
        return cache

    def requisito_accion(self, accion):
        if os.name != "nt" and accion in ("instalar_wireshark", "abrir_hotspot"):
            return {"ok": False, "error": "Esta acción solo existe en Windows."}
        if accion == "instalar_wireshark":
            subprocess.Popen('start "Instalar Wireshark" cmd /k ' + requisitos.WINGET_WIRESHARK, shell=True)
            return {"ok": True, "mensaje": "Se abrió una ventana de instalación. Sigue los pasos del instalador "
                    "(deja marcado TShark y acepta instalar Npcap) y luego pulsa «Volver a comprobar»."}
        if accion == "abrir_npcap":
            webbrowser.open(requisitos.URL_NPCAP)
            return {"ok": True, "mensaje": "Se abrió la página de descarga de Npcap. Instálalo con las opciones por defecto."}
        if accion == "abrir_hotspot":
            os.startfile("ms-settings:network-mobilehotspot")
            return {"ok": True, "mensaje": "Se abrió la configuración del hotspot de Windows."}
        if accion == "probar_captura":
            iface = self.sugerida or next((i for i, n in self.interfaces if "NPF_" in i and "Loopback" not in i), None)
            return dict(requisitos.probar_captura(self.tshark, iface), ok_accion=True)
        return {"ok": False, "error": "Acción no válida"}

    # ---- ciclo de vida
    def refrescar_clientes(self):
        while True:
            try:
                nuevos = vivo.clientes_hotspot()
                with self.estado.lock:
                    if not self.estado.solo_archivo:
                        self.estado.clientes = nuevos
                if not self.sugerida and self.tshark:
                    self.sugerida = visita.interfaz_hotspot(self.interfaces)
            except Exception:
                pass
            time.sleep(8)

    def aviso_pagina(self, pid, cerrar=False, ahora=None):
        """Una página (ventana o pestaña) avisa que sigue abierta, o que se está cerrando."""
        ahora = ahora if ahora is not None else time.time()
        if cerrar:
            if self.paginas.pop(pid, None) is not None:
                self.ultimo_cierre = ahora
                _log("página cerrada: %s" % pid)
        else:
            if pid not in self.paginas:
                _log("página conectada: %s" % pid)
            self.paginas[pid] = ahora
            self.hubo_paginas = True

    def debe_salir(self, ahora=None):
        """True cuando ya no queda ninguna ventana abierta. Tolera el frenado de pestañas ocultas:
        sin avisos espera 90 s (10 min si hay una captura en curso) antes de darla por cerrada."""
        ahora = ahora if ahora is not None else time.time()
        en_vivo = bool(self.captura and self.captura.estado_txt == "capturando")
        limite = 600 if en_vivo else 90
        for pid, t in list(self.paginas.items()):
            if ahora - t > limite:
                del self.paginas[pid]
                self.ultimo_cierre = ahora
                _log("página sin avisos desde hace %d s: %s" % (limite, pid))
        return self.hubo_paginas and not self.paginas and ahora - self.ultimo_cierre > 8

    def vigilar_ventana(self):
        """Termina la aplicación (y detiene la captura) cuando se cierra la última ventana."""
        while True:
            time.sleep(2)
            if self.debe_salir():
                _log("se cerró la última ventana: la aplicación termina")
                self.salir()

    def salir(self):
        try:
            if self.captura:
                self.captura.detener()
        finally:
            os._exit(0)

    # ---- acciones
    def estado_json(self, q=None):
        c = self.captura
        lista = self.estado.lista(q)
        return {
            "captura": {"estado": c.estado_txt if c else "inactiva", "error": c.error if c else None,
                        "activo_s": round(self.estado.activo()), "interfaz": c.interfaz if c else None,
                        "paquetes": self.estado.total, "guardando": bool(self.archivo_captura)},
            "requisitos": {"tshark": self.tshark, "hotspot": bool(self.sugerida),
                           "interfaz_sugerida": self.sugerida,
                           "interfaces": [{"id": i, "nombre": n} for i, n in self.interfaces]},
            "dispositivos": lista["items"], "total_dispositivos": lista["total"], "sospechosos": lista["sospechosos"],
            "carga": self.carga, "origen": self.origen,
            "min_verde_s": informe.MIN_VERDE_S,
        }

    def control(self, cuerpo):
        accion = cuerpo.get("accion")
        with self.lock:
            if accion == "nueva":
                if self.captura:
                    self.captura.detener()
                self.estado = vivo.Estado(gateway=vivo.GATEWAY_HOTSPOT, tshark=self.tshark)
                self.origen = None
                self.escaneos = {}
                self.captura = None
                self.archivo_captura = None
                return {"ok": True}
            if accion == "iniciar":
                if not self.tshark:
                    return {"ok": False, "error": "No encuentro TShark. Instala Wireshark y marca 'TShark'."}
                iface = cuerpo.get("interfaz") or self.sugerida
                if not iface:
                    return {"ok": False, "error": "Elige la interfaz donde está conectado el dispositivo."}
                if self.captura is None:
                    self.guardar = bool(cuerpo.get("guardar"))
                    if self.guardar:
                        self.archivo_captura = os.path.join(
                            tempfile.gettempdir(), "captura_%s.pcap" % datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
                    self.captura = vivo.Captura(self.estado, self.tshark, iface, guardar_en=self.archivo_captura)
                self.captura.iniciar()
                return {"ok": True}
            if accion in ("pausar", "continuar", "detener") and self.captura:
                getattr(self.captura, "iniciar" if accion == "continuar" else accion)()
                return {"ok": True}
        return {"ok": False, "error": "Acción no válida"}

    def lanzar_escaneo(self, mac, modo):
        """Revisa los puertos abiertos de un dispositivo YA detectado en la red local (nunca de una IP cualquiera)."""
        modo = "completo" if modo == "completo" else "rapido"
        d = next((x for x in self.estado.lista(q=mac)["items"] if x["mac"] == mac), None)
        ip = d["ip"] if d else None
        if not ip or ip == "-":
            return {"ok": False, "error": "Ese dispositivo todavía no tiene una dirección IP conocida."}
        if not self.estado._loc.es_local(ip) or ip == self.estado.gw:
            return {"ok": False, "error": "Solo se revisan dispositivos de la red local."}
        previo = self.escaneos.get(mac)
        if previo and previo.estado == "corriendo":
            return {"ok": True, "ya_en_curso": True}
        self.escaneos[mac] = escaneo.Trabajo(ip, modo).iniciar()
        return {"ok": True}

    def generar_informe(self, mac, referencia="", tecnico=""):
        res = self.estado.resultado(mac)
        if res is None:
            return {"ok": False, "error": "Ese dispositivo no tiene tráfico capturado."}
        os.makedirs(CARPETA_INFORMES, exist_ok=True)
        ruta = os.path.abspath(os.path.join(
            CARPETA_INFORMES, "informe_%s.html" % datetime.datetime.now().strftime("%Y%m%d_%H%M")))
        with open(ruta, "w", encoding="utf8") as f:
            esc = self.escaneos.get(mac)
            f.write(informe.render_html(res, ref=referencia, tecnico=tecnico, capturado=not self.guardar,
                                        puertos=esc.datos() if esc and esc.estado == "listo" else None))
        if self.abrir_informe:
            try:
                os.startfile(ruta) if os.name == "nt" else webbrowser.open("file://" + ruta)
            except Exception:
                pass
        return {"ok": True, "ruta": ruta, "captura": self.archivo_captura}


def _manejador(app):
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _permitido(self):
            """Solo acepta peticiones dirigidas a nuestra dirección local y que vengan de nuestra propia
            página: frena el DNS rebinding y las peticiones desde otras webs abiertas en el navegador."""
            puerto = self.server.server_address[1]
            validos = ("127.0.0.1:%d" % puerto, "localhost:%d" % puerto)
            if self.headers.get("Host") not in validos:
                return False
            origen = self.headers.get("Origin")
            return origen is None or origen in ("http://127.0.0.1:%d" % puerto, "http://localhost:%d" % puerto)

        def _json(self, obj, code=200):
            b = json.dumps(obj, ensure_ascii=False).encode("utf8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_GET(self):
            if not self._permitido():
                return self._json({"error": "origen no permitido"}, 403)
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            if u.path == "/":
                b = (WEB / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)
            elif u.path == "/api/estado":
                self._json(app.estado_json(q.get("q")))
            elif u.path == "/api/requisitos":
                self._json(app.requisitos_json(forzar=q.get("forzar") == "1"))
            elif u.path == "/api/dispositivo":
                d = app.estado.datos(q.get("mac", ""))
                self._json(d if d else {"error": "sin datos"}, 200 if d else 404)
            elif u.path == "/api/paquetes":
                self._json(app.estado.paquetes(int(q.get("desde", 0)), q.get("mac") or None))
            elif u.path == "/api/escaneo":
                t = app.escaneos.get(q.get("mac", ""))
                self._json(t.datos() if t else {"estado": "nunca"})
            elif u.path == "/api/glosario":
                self._json({"glosario": servicios.GLOSARIO,
                            "categorias": {k: {"nombre": v[0], "descripcion": v[1]} for k, v in servicios.CATEGORIAS.items()}})
            elif u.path == "/api/ping":
                app.aviso_pagina(q.get("id", "?"))
                self._json({"ok": True})
            else:
                self._json({"error": "no existe"}, 404)

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            if not self._permitido():
                self.rfile.read(n)  # se consume el cuerpo antes de rechazar, para no cortar la conexión
                return self._json({"error": "origen no permitido"}, 403)
            try:
                cuerpo = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                cuerpo = {}
            if self.path == "/api/control":
                self._json(app.control(cuerpo))
            elif self.path == "/api/escaneo":
                if cuerpo.get("accion") == "cancelar":
                    t = app.escaneos.get(cuerpo.get("mac", ""))
                    if t:
                        t.cancelar.set()
                    self._json({"ok": True})
                else:
                    self._json(app.lanzar_escaneo(cuerpo.get("mac", ""), cuerpo.get("modo", "rapido")))
            elif self.path == "/api/abrir":
                self._json(app.abrir_captura(cuerpo.get("gateway") or None))
            elif self.path == "/api/requisitos":
                self._json(app.requisito_accion(cuerpo.get("accion", "")))
            elif self.path == "/api/informe":
                self._json(app.generar_informe(cuerpo.get("mac", ""), cuerpo.get("referencia", ""),
                                               cuerpo.get("tecnico", "")))
            elif self.path.startswith("/api/ping"):
                q = {k: v[0] for k, v in parse_qs(urlparse(self.path).query).items()}
                app.aviso_pagina(q.get("id", "?"), cerrar=q.get("cerrar") == "1")
                self._json({"ok": True})
            elif self.path == "/api/salir":
                self._json({"ok": True})
                threading.Thread(target=app.salir, daemon=True).start()
            else:
                self._json({"error": "no existe"}, 404)

    return H


def _es_ip(t):
    import ipaddress
    try:
        ipaddress.IPv4Address(t.strip())
        return True
    except ValueError:
        return False


_PS_DIALOGO = r"""
Add-Type -AssemblyName System.Windows.Forms
$f = New-Object System.Windows.Forms.Form -Property @{TopMost = $true; ShowInTaskbar = $false; Opacity = 0}
$f.Show()
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Title = 'Elige una o varias capturas (.pcap, .pcapng)'
$d.Filter = 'Capturas de red (*.pcap;*.pcapng;*.cap)|*.pcap;*.pcapng;*.cap|Todos los archivos (*.*)|*.*'
$d.Multiselect = $true
if ($d.ShowDialog($f) -eq [System.Windows.Forms.DialogResult]::OK) { $d.FileNames }
$f.Close()
"""


def elegir_archivos():
    """Diálogo nativo de Windows para elegir capturas. Devuelve la lista de rutas (vacía si se cancela)."""
    if os.name != "nt":
        return []
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-STA", "-Command", _PS_DIALOGO], capture_output=True,
                             text=True, errors="replace", timeout=600).stdout
    except Exception:
        return []
    return [l.strip() for l in out.splitlines() if l.strip() and os.path.isfile(l.strip())]


def _buscar_edge():
    for c in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"):
        if os.path.exists(c):
            return c
    return shutil.which("msedge") or shutil.which("chrome") or shutil.which("google-chrome")


def _tamano_pantalla():
    try:
        import ctypes
        u = ctypes.windll.user32
        return u.GetSystemMetrics(0), u.GetSystemMetrics(1)
    except Exception:
        return 1366, 768


def _abrir_ventana(app, url):
    """Abre la app como ventana propia (Edge/Chrome). Si no se conecta en 12 s, la abre en el navegador."""
    navegador = _buscar_edge()
    proc = None
    if navegador:
        sw, sh = _tamano_pantalla()
        ancho, alto = max(900, min(1320, int(sw * 0.94))), max(600, min(880, int(sh * 0.90)))
        perfil = tempfile.mkdtemp(prefix="revisor_")
        try:
            proc = subprocess.Popen([navegador, "--app=" + url, "--window-size=%d,%d" % (ancho, alto),
                                     "--user-data-dir=" + perfil, "--no-first-run", "--disable-extensions",
                                     "--disable-background-timer-throttling", "--disable-renderer-backgrounding",
                                     "--disable-backgrounding-occluded-windows"])
            _log("ventana lanzada con %s (%dx%d)" % (os.path.basename(navegador), ancho, alto))
        except OSError as e:
            _log("no se pudo lanzar el navegador: %s" % e)
    for _ in range(24):                       # hasta 12 s esperando que la ventana se conecte
        if app.hubo_paginas:
            return
        time.sleep(0.5)
    _log("la ventana no se conectó: se abre en el navegador")
    print("\nNo pude abrir la ventana de la aplicación. La abro en tu navegador.")
    print("Si no se abre, copia esta dirección en el navegador:  %s" % url)
    webbrowser.open(url)


def ejecutar(args):
    app = App(gateway=getattr(args, "gateway", None),
              interfaz=getattr(args, "interfaz", None), abrir=getattr(args, "abrir", None))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", getattr(args, "puerto", 0) or 0), _manejador(app))
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    threading.Thread(target=app.refrescar_clientes, daemon=True).start()
    threading.Thread(target=app.vigilar_ventana, daemon=True).start()
    print("Revisor de red en %s" % url)
    print("Registro de eventos: %s" % RUTA_LOG)
    _log("inicio en %s" % url)
    if not getattr(args, "sin_ventana", False):
        print("Abriendo la ventana... (si en unos segundos no aparece, se abrirá en tu navegador)")
        print("Para terminar, cierra la ventana de la aplicación.")
        threading.Thread(target=_abrir_ventana, args=(app, url), daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        app.salir()
    return 0
