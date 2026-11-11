"""Aplicación de escritorio: servidor local + ventana propia con la captura en vivo."""
import datetime
import http.server
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

from . import informe, servicios, visita, vivo
from .pcapio import read_packets

WEB = Path(__file__).parent / "web"
CARPETA_INFORMES = "informes"


class App:
    def __init__(self, gateway=vivo.GATEWAY_HOTSPOT, interfaz=None, abrir=None):
        self.tshark = visita.buscar_tshark()
        self.estado = vivo.Estado(gateway=gateway, tshark=self.tshark)
        self.captura = None
        self.interfaz_forzada = interfaz
        self.interfaces = visita.listar_interfaces(self.tshark) if self.tshark else []
        self.sugerida = interfaz or (visita.interfaz_hotspot(self.interfaces) if self.tshark else None)
        self.guardar = False
        self.abrir_informe = True
        self.archivo_captura = None
        self.ultimo_ping = None
        self.inicio = time.time()
        self.lock = threading.Lock()
        if abrir:
            self.cargar_capturas(abrir)

    def cargar_capturas(self, archivos):
        """Carga capturas existentes (.pcap/.pcapng) como si se hubieran visto en vivo."""
        t0 = t1 = None
        for f in archivos:
            for pk in read_packets(f):
                self.estado.procesar(pk)
                t0 = pk.ts if t0 is None else t0
                t1 = pk.ts
        if t0 is not None:
            self.estado._acum = t1 - t0

    # ---- ciclo de vida
    def refrescar_clientes(self):
        while True:
            try:
                nuevos = vivo.clientes_hotspot()
                with self.estado.lock:
                    self.estado.clientes = nuevos
                if not self.sugerida and self.tshark:
                    self.sugerida = visita.interfaz_hotspot(self.interfaces)
            except Exception:
                pass
            time.sleep(8)

    def vigilar_ventana(self):
        """Si la ventana se cierra (no hay pings), la aplicación termina y detiene la captura."""
        while True:
            time.sleep(3)
            if self.ultimo_ping and time.time() - self.ultimo_ping > 20:
                self.salir()

    def salir(self):
        try:
            if self.captura:
                self.captura.detener()
        finally:
            os._exit(0)

    # ---- acciones
    def estado_json(self):
        c = self.captura
        return {
            "captura": {"estado": c.estado_txt if c else "inactiva", "error": c.error if c else None,
                        "activo_s": round(self.estado.activo()), "interfaz": c.interfaz if c else None,
                        "paquetes": self.estado.total, "guardando": bool(self.archivo_captura)},
            "requisitos": {"tshark": self.tshark, "hotspot": bool(self.sugerida),
                           "interfaz_sugerida": self.sugerida,
                           "interfaces": [{"id": i, "nombre": n} for i, n in self.interfaces]},
            "dispositivos": self.estado.lista(),
            "min_verde_s": informe.MIN_VERDE_S,
        }

    def control(self, cuerpo):
        accion = cuerpo.get("accion")
        with self.lock:
            if accion == "nueva":
                if self.captura:
                    self.captura.detener()
                self.estado = vivo.Estado(gateway=self.estado.gw, tshark=self.tshark)
                self.captura = None
                self.archivo_captura = None
                return {"ok": True}
            if accion == "iniciar":
                if not self.tshark:
                    return {"ok": False, "error": "No encuentro TShark. Instala Wireshark y marca 'TShark'."}
                iface = cuerpo.get("interfaz") or self.sugerida
                if not iface:
                    return {"ok": False, "error": "Elige la interfaz donde está conectado el aparato."}
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

    def generar_informe(self, mac, referencia="", tecnico=""):
        res = self.estado.resultado(mac)
        if res is None:
            return {"ok": False, "error": "Ese dispositivo no tiene tráfico capturado."}
        os.makedirs(CARPETA_INFORMES, exist_ok=True)
        ruta = os.path.abspath(os.path.join(
            CARPETA_INFORMES, "informe_%s.html" % datetime.datetime.now().strftime("%Y%m%d_%H%M")))
        with open(ruta, "w", encoding="utf8") as f:
            f.write(informe.render_html(res, ref=referencia, tecnico=tecnico, capturado=not self.guardar))
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
                self._json(app.estado_json())
            elif u.path == "/api/dispositivo":
                d = app.estado.datos(q.get("mac", ""))
                self._json(d if d else {"error": "sin datos"}, 200 if d else 404)
            elif u.path == "/api/paquetes":
                self._json(app.estado.paquetes(int(q.get("desde", 0)), q.get("mac") or None))
            elif u.path == "/api/glosario":
                self._json({"glosario": servicios.GLOSARIO,
                            "categorias": {k: {"nombre": v[0], "descripcion": v[1]} for k, v in servicios.CATEGORIAS.items()}})
            elif u.path == "/api/ping":
                app.ultimo_ping = time.time()
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
            elif self.path == "/api/informe":
                self._json(app.generar_informe(cuerpo.get("mac", ""), cuerpo.get("referencia", ""),
                                               cuerpo.get("tecnico", "")))
            elif self.path == "/api/salir":
                self._json({"ok": True})
                threading.Thread(target=app.salir, daemon=True).start()
            else:
                self._json({"error": "no existe"}, 404)

    return H


def _buscar_edge():
    for c in (r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"):
        if os.path.exists(c):
            return c
    return shutil.which("msedge") or shutil.which("chrome") or shutil.which("google-chrome")


def ejecutar(args):
    app = App(gateway=getattr(args, "gateway", None) or vivo.GATEWAY_HOTSPOT,
              interfaz=getattr(args, "interfaz", None), abrir=getattr(args, "abrir", None))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", getattr(args, "puerto", 0) or 0), _manejador(app))
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    threading.Thread(target=app.refrescar_clientes, daemon=True).start()
    threading.Thread(target=app.vigilar_ventana, daemon=True).start()
    print("Revisor de red en %s  (cierra la ventana para terminar)" % url)
    if not getattr(args, "sin_ventana", False):
        navegador = _buscar_edge()
        if navegador:
            perfil = tempfile.mkdtemp(prefix="revisor_")
            subprocess.Popen([navegador, "--app=" + url, "--window-size=1320,880",
                              "--user-data-dir=" + perfil, "--no-first-run", "--disable-extensions"])
        else:
            webbrowser.open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        app.salir()
    return 0
