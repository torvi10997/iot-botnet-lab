import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botnet_lab.analyzer import Analizador, analyze  # noqa: E402
from emulador_pruebas import build, generate  # noqa: E402
from botnet_lab.pcapio import read_packets  # noqa: E402


def codes(res):
    return [f["code"] for f in res["findings"]]


class LabTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def path(self, name):
        return os.path.join(self.d.name, name)

    def test_infected_is_detected(self):
        p = self.path("inf.pcap")
        generate(p, infected=True)
        res = analyze(p)
        c = codes(res)
        self.assertEqual(c.count("UDP_FLOOD"), 3)
        self.assertEqual(c.count("C2_ORDER"), 3)
        self.assertIn("BEACON", c)
        self.assertIn("DNS_RANDOM", c)
        self.assertEqual(res["verdict"], "sospechoso")
        order = [f for f in res["findings"] if f["code"] == "C2_ORDER"][0]
        self.assertEqual(order["evidence"]["controller"], "198.51.100.10")
        self.assertLess(order["evidence"]["delay_s"], 0.5)

    def test_clean_has_no_findings(self):
        p = self.path("clean.pcap")
        generate(p, infected=False)
        res = analyze(p)
        self.assertEqual([f for f in res["findings"] if f["severity"] != "info"], [])
        self.assertEqual(res["verdict"], "sin indicios")

    def test_dns_binary_labels_and_paired_heartbeat(self):
        """Caso real: etiquetas DNS de 20 bytes binarios y latido en pareja cada ~30 s."""
        p = self.path("real.pcap")
        generate(p, infected=True, beacon_every=30, duration=240)
        res = analyze(p)
        beacon = [f for f in res["findings"] if f["code"] == "BEACON"]
        self.assertEqual(len(beacon), 1)  # solo el canal de 33 bytes, no el ruido de 38
        self.assertEqual(beacon[0]["evidence"]["bytes"], 33)
        self.assertEqual(beacon[0]["severity"], "alta")  # mismo servidor que dio las ordenes
        self.assertIn("DNS_RANDOM", codes(res))

    def test_descarga_quic_no_es_inundacion(self):
        """Regresión: YouTube por QUIC (UDP 443, el destino responde mucho) no debe marcarse."""
        p = self.path("quic.pcap")
        generate(p, infected=False, duration=700, quic=True)
        res = analyze(p)
        self.assertNotIn("UDP_FLOOD", codes(res))
        self.assertEqual(res["verdict"], "sin indicios")

    def test_scan(self):
        p = self.path("scan.pcap")
        generate(p, infected=True, scan=True)
        self.assertIn("SCAN", codes(analyze(p)))

    def test_thresholds_respected(self):
        p = self.path("low.pcap")
        generate(p, infected=True, flood_pps=100)
        self.assertNotIn("UDP_FLOOD", codes(analyze(p)))

    def test_pcapng_reader(self):
        """Convierte el escenario a pcapng mínimo y comprueba que se lee igual."""
        frames = sorted(build(infected=False, duration=10), key=lambda x: x[0])
        p = self.path("x.pcapng")

        def block(t, body):
            ln = 12 + len(body)
            return struct.pack("<II", t, ln) + body + struct.pack("<I", ln)

        with open(p, "wb") as f:
            f.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
            f.write(block(1, struct.pack("<HHI", 1, 0, 0)))
            for ts, data in frames:
                us = int(round(ts * 1e6))
                pad = (-len(data)) % 4
                body = struct.pack("<IIIII", 0, us >> 32, us & 0xFFFFFFFF, len(data), len(data))
                f.write(block(6, body + data + b"\0" * pad))
        a = list(read_packets(p))
        self.assertEqual(len(a), len(frames))
        self.assertAlmostEqual(a[0].ts, frames[0][0], places=3)


class VisitaTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def run_visita(self, pcap):
        import contextlib
        import io
        from botnet_lab.cli import main
        out = os.path.join(self.d.name, "out")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["visita", "--desde-captura", pcap, "--salida", out, "--referencia", "Casa <X>"])
        with open(os.path.join(out, os.listdir(out)[0]), encoding="utf8") as fh:
            html = fh.read()
        return rc, buf.getvalue(), html

    def test_rojo(self):
        p = os.path.join(self.d.name, "a.pcap")
        generate(p, infected=True)
        rc, out, html = self.run_visita(p)
        self.assertEqual(rc, 2)
        self.assertIn("ROJO", out)
        self.assertIn("ROJO", html)
        self.assertIn("Casa &lt;X&gt;", html)  # el texto libre se escapa

    def test_corto_no_es_verde(self):
        p = os.path.join(self.d.name, "b.pcap")
        generate(p, infected=False, duration=120)
        rc, out, _ = self.run_visita(p)
        self.assertEqual(rc, 0)
        self.assertIn("NO CONCLUYENTE", out)

    def test_verde_solo_con_captura_larga(self):
        p = os.path.join(self.d.name, "c.pcap")
        generate(p, infected=False, duration=700)
        rc, out, _ = self.run_visita(p)
        self.assertIn("VERDE", out)

    def test_sin_trafico_no_es_verde(self):
        from botnet_lab.informe import semaforo
        res = {"findings": [], "summary": {"local_hosts": {"192.168.1.5": 10}, "duration_s": 900}}
        self.assertEqual(semaforo(res), "sin_datos")


class VivoTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.pcap = os.path.join(self.d.name, "v.pcap")
        generate(self.pcap, infected=True, duration=120)

    def estado(self):
        from botnet_lab.vivo import Estado
        e = Estado()
        for p in read_packets(self.pcap):
            e.procesar(p)
        return e

    def test_agrupa_por_dispositivo_y_diagnostica(self):
        e = self.estado()
        lista = e.lista()["items"]
        self.assertEqual(len(lista), 1)
        self.assertEqual(lista[0]["semaforo"], "rojo")
        d = e.datos(lista[0]["mac"])
        # los tres destinos principales son las tres víctimas de las inundaciones
        self.assertEqual({x["ip"] for x in d["destinos"][:3]}, {"203.0.113.20", "203.0.113.30", "203.0.113.40"})
        self.assertEqual(sum(x["pct"] for x in d["destinos"]) in range(98, 103), True)
        self.assertTrue(any(c["clave"] == "juegos" for c in d["categorias"]))  # puerto 19132 = Minecraft

    def test_la_lista_en_vivo_se_muestrea_en_inundaciones(self):
        e = self.estado()
        r = e.paquetes()
        self.assertLessEqual(len(r["filas"]), 300)
        self.assertGreater(r["omitidos"], 1000)

    def test_dns_respuesta_aprende_nombres(self):
        from botnet_lab.vivo import dns_respuesta
        pregunta = b"\x07example\x03com\x00\x00\x01\x00\x01"
        msg = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + pregunta +
               b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22")
        self.assertEqual(dns_respuesta(msg), ("example.com", ["93.184.216.34"]))
        self.assertIsNone(dns_respuesta(b"\x12\x34\x01\x00" + b"\x00" * 8))  # una consulta, no respuesta

    def test_servicios_en_lenguaje_simple(self):
        from botnet_lab.servicios import describir
        self.assertEqual(describir("UDP", 443, "rr1.googlevideo.com")[:2], ("video", "YouTube"))
        self.assertEqual(describir("TCP", 5555)[0], "atencion")
        self.assertEqual(describir("TCP", 9999)[0], "desconocido")

    def test_api_http(self):
        import http.server
        import json
        import threading
        import urllib.error
        import urllib.request
        from botnet_lab.app import App, _manejador
        app = App(abrir=[self.pcap])
        app.abrir_informe = False
        app.exigir_token = False
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _manejador(app))
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = "http://127.0.0.1:%d" % srv.server_address[1]

        def get(ruta):
            return urllib.request.urlopen(base + ruta, timeout=10).read()

        self.assertIn(b"Revisor de red", get("/"))
        # seguridad: se rechaza un Host ajeno (DNS rebinding) y un Origin de otra web
        for cab in ({"Host": "evil.example:80"}, {"Origin": "http://evil.example"}):
            try:
                urllib.request.urlopen(urllib.request.Request(base + "/api/estado", headers=cab), timeout=10)
                self.fail("debía rechazar " + str(cab))
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)
        try:
            urllib.request.urlopen(urllib.request.Request(
                base + "/api/control", b'{"accion":"detener"}', {"Origin": "http://evil.example"}), timeout=10)
            self.fail("debía rechazar el POST")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
        est = json.loads(get("/api/estado"))
        self.assertEqual(est["captura"]["estado"], "inactiva")
        mac = est["dispositivos"][0]["mac"]
        self.assertEqual(est["origen"]["router_mac"], "02:aa:bb:cc:00:01")   # el router se detectó solo
        det = json.loads(get("/api/dispositivo?mac=" + mac.replace(":", "%3A")))
        self.assertEqual(det["semaforo"]["color"], "rojo")
        self.assertIn("glosario", json.loads(get("/api/glosario")))
        cwd = os.getcwd()
        os.chdir(self.d.name)
        self.addCleanup(os.chdir, cwd)
        req = urllib.request.Request(base + "/api/informe", json.dumps({"mac": mac, "referencia": "x<y"}).encode(),
                                     {"Content-Type": "application/json"})
        r = json.loads(urllib.request.urlopen(req, timeout=10).read())
        self.assertTrue(r["ok"])
        with open(r["ruta"], encoding="utf8") as fh:
            self.assertIn("ROJO", fh.read())


class EscaneoTests(unittest.TestCase):
    """Prueba el escáner contra servidores falsos locales (nunca contra otros equipos)."""

    @staticmethod
    def servidor(respuesta=None):
        import socket
        import threading
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def aceptar():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                try:
                    if respuesta is not None:
                        c.settimeout(1)
                        c.recv(100)
                        c.sendall(respuesta)
                finally:
                    c.close()

        threading.Thread(target=aceptar, daemon=True).start()
        return srv, srv.getsockname()[1]

    def test_detecta_abierto_y_cerrado(self):
        import socket
        from botnet_lab.escaneo import escanear
        srv, abierto = self.servidor()
        self.addCleanup(srv.close)
        libre = socket.socket()
        libre.bind(("127.0.0.1", 0))
        cerrado = libre.getsockname()[1]
        libre.close()
        res = escanear("127.0.0.1", [abierto, cerrado], timeout=0.5)
        self.assertEqual([r["puerto"] for r in res], [abierto])
        self.assertEqual(res[0]["servicio"], "Servicio sin identificar")

    def test_adb_sin_clave_y_con_clave(self):
        import struct
        from botnet_lab.escaneo import sondear_adb
        cabecera = lambda cmd: struct.pack("<6I", cmd, 0, 0, 0, 0, cmd ^ 0xFFFFFFFF)
        s1, p1 = self.servidor(cabecera(0x4E584E43))     # CNXN: acepta sin pedir clave
        s2, p2 = self.servidor(cabecera(0x48545541))     # AUTH: exige autorización
        s3, p3 = self.servidor(b"hola")                  # no es ADB
        for s in (s1, s2, s3):
            self.addCleanup(s.close)
        self.assertEqual(sondear_adb("127.0.0.1", p1), "sin_clave")
        self.assertEqual(sondear_adb("127.0.0.1", p2), "pide_clave")
        self.assertEqual(sondear_adb("127.0.0.1", p3), "desconocido")

    def test_resumen_y_orden_por_riesgo(self):
        from botnet_lab.escaneo import resumen
        res = [{"riesgo": "bajo"}, {"riesgo": "alto"}, {"riesgo": "info"}]
        r = resumen(res)
        self.assertEqual((r["abiertos"], r["alto"], r["peor"]), (3, 1, "alto"))

    def test_instalar_wireshark_no_usa_shell(self):
        """La acción de instalar abre una consola con argumentos fijos, sin shell=True ni texto de la petición."""
        from unittest import mock
        from botnet_lab import app as modulo
        a = modulo.App()
        with mock.patch.object(modulo.os, "name", "nt"), mock.patch.object(modulo.subprocess, "Popen") as popen,              mock.patch.object(modulo.subprocess, "CREATE_NEW_CONSOLE", 16, create=True):
            r = a.requisito_accion("instalar_wireshark")
        self.assertTrue(r["ok"])
        args, kw = popen.call_args
        self.assertIsInstance(args[0], list)
        self.assertNotIn("shell", kw)
        self.assertIn("WiresharkFoundation.Wireshark", args[0])

    def test_la_app_no_escanea_desconocidos_ni_la_puerta_de_enlace(self):
        import tempfile as tf
        from botnet_lab.app import App
        with tf.TemporaryDirectory() as d:
            pcap = os.path.join(d, "x.pcap")
            generate(pcap, infected=False, duration=20)
            app = App(abrir=[pcap])
        self.assertFalse(app.lanzar_escaneo("aa:bb:cc:dd:ee:ff", "rapido")["ok"])   # MAC no vista
        self.assertEqual(app.escaneos, {})


def _datos_ok(**cambios):
    """Datos de sistema de un equipo con todo bien; cada prueba cambia lo que quiere probar."""
    d = {"os": "nt", "python": "3.12.0", "tshark": "C:/Wireshark/tshark.exe",
         "tshark_v": "TShark (Wireshark) 4.4.6\nwith Npcap version 1.79, based on libpcap",
         "interfaces": [("\\Device\\NPF_{AAA}", "Ethernet")],
         "ps": {"admin": "True", "adminonly": "0", "tipo": "6", "estado": "On", "banda": "TwoPointFourGigahertz",
                "ssid": "TEST", "clientes": "1"},
         "edge": "C:/edge.exe"}
    ps = cambios.pop("ps", None)
    d.update(cambios)
    if ps is not None:
        d["ps"] = dict(d["ps"], **ps)
    return d


class RequisitosTests(unittest.TestCase):
    def estados(self, d):
        from botnet_lab.requisitos import evaluar
        return {c["id"]: c for c in evaluar(d)}

    def test_todo_bien(self):
        from botnet_lab.requisitos import evaluar, resumen
        r = resumen(evaluar(_datos_ok()))
        self.assertEqual((r["error"], r["aviso"], r["listo"]), (0, 0, True))

    def test_sin_tshark_ofrece_instalar_wireshark(self):
        c = self.estados(_datos_ok(tshark=None, tshark_v="", interfaces=[]))
        self.assertEqual(c["tshark"]["estado"], "error")
        self.assertEqual(c["tshark"]["accion"], "instalar_wireshark")
        self.assertEqual(c["npcap"]["estado"], "pendiente")

    def test_sin_npcap(self):
        c = self.estados(_datos_ok(tshark_v="TShark (Wireshark) 4.4.6\nwith libpcap", interfaces=[]))
        self.assertEqual(c["npcap"]["estado"], "error")
        self.assertEqual(c["npcap"]["accion"], "abrir_npcap")
        self.assertEqual(c["interfaces"]["estado"], "error")

    def test_winpcap_antiguo_es_aviso(self):
        c = self.estados(_datos_ok(tshark_v="TShark (Wireshark) 4.4.6\nwith WinPcap version 4.1.3"))
        self.assertEqual(c["npcap"]["estado"], "aviso")
        self.assertIn("WinPcap", c["npcap"]["detalle"])

    def test_solo_usb_no_son_interfaces_reales(self):
        c = self.estados(_datos_ok(interfaces=[("\\\\.\\USBPcap1", "USBPcap1"), ("ciscodump", "Cisco remote capture")]))
        self.assertEqual(c["interfaces"]["estado"], "error")

    def test_npcap_solo_administradores(self):
        c = self.estados(_datos_ok(ps={"admin": "False", "adminonly": "1"}))
        self.assertEqual(c["permisos"]["estado"], "error")
        c = self.estados(_datos_ok(ps={"admin": "False", "adminonly": "0"}))
        self.assertEqual(c["permisos"]["estado"], "ok")

    def test_hotspot_apagado_y_internet_por_wifi(self):
        c = self.estados(_datos_ok(ps={"estado": "Off", "tipo": "71"}))
        self.assertEqual(c["hotspot"]["estado"], "aviso")
        self.assertEqual(c["hotspot"]["accion"], "abrir_hotspot")
        self.assertEqual(c["cable"]["estado"], "aviso")      # internet por WiFi fuerza 5 GHz
        self.assertIn("5 GHz", c["cable"]["detalle"])

    def test_hotspot_en_5ghz_avisa(self):
        c = self.estados(_datos_ok(ps={"banda": "FiveGigahertz"}))
        self.assertEqual(c["hotspot"]["estado"], "aviso")

    def test_sin_internet_no_rompe(self):
        c = self.estados(_datos_ok(ps={"sin_internet": "1", "estado": ""}))
        self.assertEqual(c["hotspot"]["estado"], "aviso")

    def test_fuera_de_windows_no_pide_hotspot(self):
        c = self.estados(_datos_ok(os="posix", ps={}))
        self.assertNotIn("hotspot", c)
        self.assertNotIn("permisos", c)


class RouterTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def pcap_dos_dispositivos(self):
        """Un dispositivo infectado y otro sano, mezclados en una sola captura (como la de un router)."""
        import emulador_pruebas as em
        from botnet_lab.pcapio import write_pcap
        frames = list(em.build(infected=True, duration=120))
        guardado = (em.DEV_IP, em.DEV_MAC)
        try:
            em.DEV_IP, em.DEV_MAC = "192.168.137.60", bytes.fromhex("02aabbcc0060")
            frames += em.build(infected=False, duration=120, seed=3)
        finally:
            em.DEV_IP, em.DEV_MAC = guardado
        ruta = os.path.join(self.d.name, "router.pcap")
        write_pcap(ruta, frames)
        return ruta

    def test_detecta_el_router(self):
        from botnet_lab.vivo import detectar_router
        ruta = self.pcap_dos_dispositivos()
        ip, mac = detectar_router(read_packets(ruta))
        self.assertEqual((ip, mac), ("192.168.137.1", "02:aa:bb:cc:00:01"))

    def test_sin_trafico_a_internet_no_inventa_router(self):
        from botnet_lab.vivo import detectar_router
        self.assertEqual(detectar_router(iter([])), (None, None))

    def test_sospechosos_primero_y_busqueda(self):
        from botnet_lab.app import App
        app = App(abrir=[self.pcap_dos_dispositivos()])
        lista = app.estado.lista()
        self.assertEqual(lista["total"], 2)                      # el router no cuenta como dispositivo
        self.assertEqual(lista["sospechosos"], 1)
        self.assertEqual(lista["items"][0]["ip"], "192.168.137.50")   # el infectado va primero
        self.assertEqual(lista["items"][0]["semaforo"], "rojo")
        solo = app.estado.lista(q="192.168.137.60")["items"]
        self.assertEqual([x["ip"] for x in solo], ["192.168.137.60"])
        self.assertTrue(app.origen["automatico"])

    def test_gateway_indicado_manualmente(self):
        from botnet_lab.app import App
        app = App(abrir=[self.pcap_dos_dispositivos()], gateway="192.168.137.1")
        self.assertFalse(app.origen["automatico"])
        self.assertEqual(app.origen["router_ip"], "192.168.137.1")

    def test_abrir_por_la_api_con_dialogo_simulado(self):
        import http.server
        import json
        import threading
        import time
        import urllib.request
        from unittest import mock
        from botnet_lab import app as modulo
        ruta = self.pcap_dos_dispositivos()
        app = modulo.App()
        app.abrir_informe = False
        app.exigir_token = False
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), modulo._manejador(app))
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = "http://127.0.0.1:%d" % srv.server_address[1]

        def post(r, cuerpo):
            q = urllib.request.Request(base + r, json.dumps(cuerpo).encode(), {"Content-Type": "application/json"})
            return json.loads(urllib.request.urlopen(q, timeout=20).read())

        self.assertFalse(post("/api/abrir", {"gateway": "no-es-ip"})["ok"])            # IP inválida
        with mock.patch.object(modulo, "elegir_archivos", return_value=[]):
            self.assertTrue(post("/api/abrir", {})["cancelado"])                       # el usuario cancela
        with mock.patch.object(modulo, "elegir_archivos", return_value=[ruta]):
            self.assertTrue(post("/api/abrir", {})["ok"])
        for _ in range(100):                                                           # espera a que termine de cargar
            est = json.loads(urllib.request.urlopen(base + "/api/estado", timeout=10).read())
            if not est["carga"]["activa"] and est["origen"]:
                break
            time.sleep(0.2)
        self.assertEqual(est["total_dispositivos"], 2)
        self.assertEqual(est["sospechosos"], 1)
        self.assertIsNone(est["carga"]["error"])
        busq = json.loads(urllib.request.urlopen(base + "/api/estado?q=192.168.137.60", timeout=10).read())
        self.assertEqual(len(busq["dispositivos"]), 1)

    def test_archivo_que_no_es_captura(self):
        from botnet_lab.app import App
        malo = os.path.join(self.d.name, "x.pcap")
        with open(malo, "wb") as f:
            f.write(b"esto no es una captura")
        app = App()
        app._cargar_hilo([malo], None)
        self.assertTrue(app.carga["error"])
        self.assertIsNone(app.origen)


class RequisitosApiTests(unittest.TestCase):
    def test_api_requisitos_y_acciones(self):
        import http.server
        import json
        import threading
        import urllib.request
        from unittest import mock
        from botnet_lab import app as modulo, requisitos
        with mock.patch.object(requisitos, "recoger", return_value=_datos_ok(tshark=None, tshark_v="", interfaces=[])):
            app = modulo.App()
            app.exigir_token = False
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), modulo._manejador(app))
            self.addCleanup(srv.server_close)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.shutdown)
            base = "http://127.0.0.1:%d" % srv.server_address[1]
            r = json.loads(urllib.request.urlopen(base + "/api/requisitos?forzar=1", timeout=10).read())
            self.assertFalse(r["resumen"]["listo"])
            ids = {c["id"]: c for c in r["checks"]}
            self.assertEqual(ids["tshark"]["accion"], "instalar_wireshark")
            q = urllib.request.Request(base + "/api/requisitos", b'{"accion":"borrar_todo"}', {"Content-Type": "application/json"})
            self.assertFalse(json.loads(urllib.request.urlopen(q, timeout=10).read())["ok"])   # acciones desconocidas se rechazan


class VentanaTests(unittest.TestCase):
    """La app termina al cerrarse la última ventana, pero tolera pestañas ocultas (el navegador las frena)."""

    def app(self):
        from botnet_lab.app import App
        return App()

    def test_nunca_se_cierra_si_nunca_hubo_ventana(self):
        a = self.app()
        self.assertFalse(a.debe_salir(ahora=10_000))

    def test_cierre_explicito_termina_tras_una_breve_espera(self):
        a = self.app()
        a.aviso_pagina("p1", ahora=100)
        self.assertFalse(a.debe_salir(ahora=105))
        a.aviso_pagina("p1", cerrar=True, ahora=106)
        self.assertFalse(a.debe_salir(ahora=110))      # 4 s después: aún espera (por si fue una recarga)
        self.assertTrue(a.debe_salir(ahora=115))       # 9 s después: termina

    def test_recargar_la_pagina_no_termina_la_app(self):
        a = self.app()
        a.aviso_pagina("p1", ahora=100)
        a.aviso_pagina("p1", cerrar=True, ahora=101)    # pagehide al recargar
        a.aviso_pagina("p2", ahora=103)                 # la página nueva se conecta enseguida
        self.assertFalse(a.debe_salir(ahora=200 - 90))  # sigue viva

    def test_dos_pestanas_cerrar_una_no_apaga_la_app(self):
        a = self.app()
        a.aviso_pagina("ventana", ahora=100)
        a.aviso_pagina("pestana", ahora=100)
        a.aviso_pagina("pestana", cerrar=True, ahora=120)
        a.aviso_pagina("ventana", ahora=125)
        self.assertFalse(a.debe_salir(ahora=130))

    def test_pestana_oculta_se_tolera_90_segundos(self):
        a = self.app()
        a.aviso_pagina("p1", ahora=100)                 # luego el navegador la frena y deja de avisar
        self.assertFalse(a.debe_salir(ahora=100 + 60))  # un minuto sin avisos: NO se cierra
        self.assertFalse(a.debe_salir(ahora=100 + 89))
        self.assertFalse(a.debe_salir(ahora=100 + 91))  # se da por perdida, pero espera 8 s de gracia
        self.assertTrue(a.debe_salir(ahora=100 + 100))

    def test_con_captura_en_curso_espera_mucho_mas(self):
        from unittest import mock
        a = self.app()
        a.captura = mock.Mock(estado_txt="capturando")
        a.aviso_pagina("p1", ahora=100)
        self.assertFalse(a.debe_salir(ahora=100 + 300))     # 5 min sin avisos con captura: no se corta
        self.assertFalse(a.debe_salir(ahora=100 + 590))
        self.assertFalse(a.debe_salir(ahora=100 + 620))     # pasa de 10 min: se da por perdida, con 8 s de gracia
        self.assertTrue(a.debe_salir(ahora=100 + 630))

    def test_si_la_ventana_no_se_conecta_se_abre_el_navegador(self):
        from unittest import mock
        from botnet_lab import app as modulo
        a = modulo.App()
        with mock.patch.object(modulo, "_buscar_edge", return_value=None),              mock.patch.object(modulo.time, "sleep"),              mock.patch.object(modulo.webbrowser, "open") as abrir:
            modulo._abrir_ventana(a, "http://127.0.0.1:1234/")
        abrir.assert_called_once_with("http://127.0.0.1:1234/")

    def test_si_la_ventana_se_conecta_no_se_abre_otro_navegador(self):
        from unittest import mock
        from botnet_lab import app as modulo
        a = modulo.App()
        a.aviso_pagina("v1")
        with mock.patch.object(modulo, "_buscar_edge", return_value=None),              mock.patch.object(modulo.time, "sleep"),              mock.patch.object(modulo.webbrowser, "open") as abrir:
            modulo._abrir_ventana(a, "http://127.0.0.1:1234/")
        abrir.assert_not_called()

    def test_ping_por_http_get_y_post(self):
        import http.server
        import threading
        import urllib.request
        from botnet_lab import app as modulo
        a = modulo.App()
        a.exigir_token = False
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), modulo._manejador(a))
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        urllib.request.urlopen(base + "/api/ping?id=abc", timeout=10).read()
        self.assertIn("abc", a.paginas)
        urllib.request.urlopen(urllib.request.Request(base + "/api/ping?id=abc&cerrar=1", b"", method="POST"), timeout=10).read()
        self.assertNotIn("abc", a.paginas)             # sendBeacon al cerrar la ventana


class SeguridadTests(unittest.TestCase):
    """Hallazgos de la auditoría de seguridad: cada uno tiene su prueba para que no vuelva."""

    def levantar(self):
        import threading
        from botnet_lab import app as modulo
        a = modulo.App()
        a.abrir_informe = False
        srv = modulo.ServidorLocal(("127.0.0.1", 0), modulo._manejador(a))
        self.addCleanup(srv.server_close)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return a, srv, srv.server_address[1], modulo

    def pet(self, puerto, metodo, ruta, headers=None, cuerpo=None):
        import http.client
        h = {"Host": "127.0.0.1:%d" % puerto}
        h.update(headers or {})
        c = http.client.HTTPConnection("127.0.0.1", puerto, timeout=10)
        try:
            c.putrequest(metodo, ruta, skip_host=True, skip_accept_encoding=True)
            for k, v in h.items():
                c.putheader(k, v)
            if cuerpo is not None:
                c.putheader("Content-Length", str(len(cuerpo)))
            c.endheaders(cuerpo)
            r = c.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            c.close()

    def test_sin_el_secreto_de_la_sesion_todo_se_rechaza(self):
        a, srv, p, _ = self.levantar()
        for ruta in ("/", "/api/estado", "/api/dispositivo?mac=x", "/api/paquetes", "/api/escaneo", "/api/glosario",
                     "/api/requisitos", "/api/ping?id=x"):
            self.assertEqual(self.pet(p, "GET", ruta)[0], 403, ruta)
        for ruta in ("/api/control", "/api/salir", "/api/informe", "/api/abrir", "/api/escaneo", "/api/requisitos"):
            self.assertEqual(self.pet(p, "POST", ruta, cuerpo=b"{}")[0], 403, ruta)
        self.assertEqual(a.paginas, {})            # ni siquiera el latido de una página ajena se acepta

    def test_enlace_con_secreto_entrega_cookie_y_la_quita_de_la_direccion(self):
        a, srv, p, _ = self.levantar()
        self.assertEqual(self.pet(p, "GET", "/?t=adivinando")[0], 403)
        st, h, _ = self.pet(p, "GET", "/?t=" + a.token)
        self.assertEqual(st, 302)
        self.assertEqual(h["location"], "/")                                   # el secreto no queda en la barra
        self.assertIn("HttpOnly", h["set-cookie"])
        self.assertIn("SameSite=Strict", h["set-cookie"])
        cookie = {"Cookie": h["set-cookie"].split(";")[0]}
        self.assertEqual(self.pet(p, "GET", "/api/estado", cookie)[0], 200)
        self.assertEqual(self.pet(p, "GET", "/", cookie)[0], 200)

    def test_cookie_ajena_o_malformada_no_sirve(self):
        a, srv, p, _ = self.levantar()
        for c in ("rt=otro", "rt=", "basura", "rt=" + "a" * 5000, "rt=\"\x00\"; ;;="):
            self.assertEqual(self.pet(p, "GET", "/api/estado", {"Cookie": c})[0], 403, c)

    def test_cabeceras_de_seguridad(self):
        a, srv, p, _ = self.levantar()
        ck = {"Cookie": "rt=" + a.token}
        st, h, _ = self.pet(p, "GET", "/", ck)
        self.assertIn("default-src 'none'", h["content-security-policy"])
        self.assertIn("frame-ancestors 'none'", h["content-security-policy"])
        self.assertIn("connect-src 'self'", h["content-security-policy"])
        self.assertEqual(h["x-content-type-options"], "nosniff")
        self.assertEqual(h["x-frame-options"], "DENY")
        self.assertEqual(h["referrer-policy"], "no-referrer")
        self.assertEqual(self.pet(p, "GET", "/api/estado", ck)[1]["x-content-type-options"], "nosniff")

    def test_cuerpos_enormes_y_content_length_invalido(self):
        a, srv, p, _ = self.levantar()
        ck = {"Cookie": "rt=" + a.token}
        self.assertEqual(self.pet(p, "POST", "/api/control", dict(ck, **{"Content-Length": "1000000000"}))[0], 413)
        self.assertEqual(self.pet(p, "POST", "/api/control", dict(ck, **{"Content-Length": "abc"}))[0], 400)
        self.assertEqual(self.pet(p, "POST", "/api/control", dict(ck, **{"Content-Length": "-5"}))[0], 400)

    def test_cuerpos_que_no_son_objetos_json_no_rompen_nada(self):
        a, srv, p, _ = self.levantar()
        ck = {"Cookie": "rt=" + a.token}
        for cuerpo in (b"[1,2,3]", b"null", b'"texto"', b"{no es json", b'{"mac": ["x"], "accion": {"a": 1}}', b'{"accion": 5}'):
            st, _, _ = self.pet(p, "POST", "/api/control", ck, cuerpo)
            self.assertEqual(st, 200, cuerpo)
        self.assertEqual(self.pet(p, "GET", "/api/paquetes?desde=abc", ck)[0], 200)

    def test_interfaz_debe_estar_en_la_lista_de_tshark(self):
        from unittest import mock
        a, srv, p, modulo = self.levantar()
        a.tshark = "tshark-falso"
        a.interfaces = [("\\Device\\NPF_{A}", "Ethernet")]
        for malo in ("rpcap://203.0.113.9/eth0", "TCP@203.0.113.9:2002", "-w C:/x.pcap", "C:/captura.pcap", "-"):
            r = a.control({"accion": "iniciar", "interfaz": malo})
            self.assertFalse(r["ok"], malo)
            self.assertIn("no válida", r["error"])
        self.assertIsNone(a.captura)
        with mock.patch.object(modulo.vivo, "Captura") as cap:
            self.assertTrue(a.control({"accion": "iniciar", "interfaz": "\\Device\\NPF_{A}"})["ok"])
            cap.assert_called_once()

    def test_tope_de_conexiones_simultaneas(self):
        import socket
        a, srv, p, modulo = self.levantar()
        for _ in range(modulo.MAX_CONEXIONES):
            srv._cupo.acquire()
        try:
            s = socket.create_connection(("127.0.0.1", p), timeout=5)
            s.sendall(b"GET /api/estado HTTP/1.0\r\n\r\n")
            try:
                datos = s.recv(100)
            except ConnectionError:
                datos = b""
            self.assertEqual(datos, b"")                     # se cierra sin atender
            s.close()
        finally:
            for _ in range(modulo.MAX_CONEXIONES):
                srv._cupo.release()

    def test_el_secreto_de_la_sesion_nunca_se_escribe_en_el_registro(self):
        import types
        from unittest import mock
        a, srv, p, modulo = self.levantar()
        escritos = []
        with mock.patch.object(modulo, "_log", side_effect=escritos.append),              mock.patch.object(modulo, "_abrir_ventana"), mock.patch.object(modulo, "ServidorLocal", return_value=srv),              mock.patch.object(srv, "serve_forever", side_effect=KeyboardInterrupt),              mock.patch.object(modulo.App, "salir"), mock.patch.object(modulo, "App", return_value=a):
            modulo.ejecutar(types.SimpleNamespace(sin_ventana=True, puerto=0))
        self.assertTrue(escritos)
        self.assertFalse([m for m in escritos if a.token in m], "el registro contiene el secreto")

    def test_las_conexiones_a_medias_tienen_tiempo_limite(self):
        a, srv, p, modulo = self.levantar()
        self.assertEqual(modulo._manejador(a).timeout, modulo.TIEMPO_CONEXION)
        self.assertLessEqual(modulo.TIEMPO_CONEXION, 30)


class LimitesTests(unittest.TestCase):
    """Un dispositivo hostil no debe poder agotar la memoria de la aplicación."""

    @staticmethod
    def pk(ts, src, dst, proto, sport, dport, smac, dmac, flags=0, payload=b"", plen=60):
        from botnet_lab.pcapio import Packet
        return Packet(ts, src, dst, proto, sport, dport, flags, plen, payload, plen + 14, smac, dmac)

    GW = bytes.fromhex("020000000001")

    def test_suplantacion_de_mac_tiene_tope(self):
        import struct
        from unittest import mock
        from botnet_lab import vivo
        with mock.patch.object(vivo, "MAX_DISPOSITIVOS", 50):
            e = vivo.Estado()
            for i in range(500):
                mac = struct.pack(">Q", 0x020000000000 + i)[2:]
                e.procesar(self.pk(1e9 + i, "192.168.%d.%d" % (i // 250, 1 + i % 250), "8.8.8.8", 17, 4000, 53, mac, self.GW))
            self.assertEqual(len(e.dispositivos), 50)
            self.assertEqual(e.ignorados, 450)

    def test_miles_de_destinos_se_agrupan_sin_perder_la_cuenta(self):
        from unittest import mock
        from botnet_lab import vivo
        mac = bytes.fromhex("0200000000aa")
        with mock.patch.object(vivo, "MAX_CONVERSACIONES", 100):
            e = vivo.Estado()
            for i in range(1000):
                e.procesar(self.pk(1e9 + i / 100, "192.168.137.50", "10.%d.%d.1" % (i // 250, i % 250), 6, 40000, 80, mac, self.GW))
            d = next(iter(e.dispositivos.values()))
            self.assertLessEqual(len(d.conv), 101)
            self.assertEqual(sum(c["po"] for c in d.conv.values()), 1000)      # ningún paquete se pierde de la cuenta
            self.assertTrue(e.agrupadas)

    def test_nombres_dns_aprendidos_tienen_tope_y_se_renuevan(self):
        from unittest import mock
        from botnet_lab import vivo
        mac = bytes.fromhex("0200000000aa")
        nombre = b"\x04host\x07example\x03com\x00"
        with mock.patch.object(vivo, "MAX_NOMBRES", 100):
            e = vivo.Estado()
            for i in range(1000):
                resp = (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + nombre + b"\x00\x01\x00\x01" +
                        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([1, 2, i // 256, i % 256]))
                e.procesar(self.pk(1e9 + i, "9.9.9.9", "192.168.137.50", 17, 53, 40000, self.GW, mac, payload=resp))
            self.assertLessEqual(len(e.nombres_ip), 100)
            self.assertIn("1.2.3.231", e.nombres_ip)                           # lo más reciente se conserva

    def test_el_presupuesto_global_es_un_limite_duro(self):
        """Aunque haya miles de dispositivos falsos, el total de entradas guardadas no pasa del presupuesto."""
        import struct
        from botnet_lab import vivo
        e = vivo.Estado(presupuesto=2000)
        for i in range(20000):
            mac = struct.pack(">Q", 0x020000000000 + i)[2:]
            e.procesar(self.pk(1e9 + i / 100, "192.168.%d.%d" % (i // 250 % 200, 1 + i % 250),
                               "20.%d.%d.1" % (i // 250 % 250, i % 250), 17, 4000, 5000 + i % 1000, mac, self.GW))
        self.assertLessEqual(e.pres.usado, 2000)
        self.assertGreater(e.pres.rechazos, 0)
        self.assertGreater(e.ignorados, 0)
        primero = next(iter(e.dispositivos))
        self.assertIsNotNone(e.datos(primero))             # lo ya guardado sigue funcionando
        self.assertTrue(e.lista()["items"])

    def test_el_historial_por_segundo_esta_acotado(self):
        from botnet_lab import vivo
        e = vivo.Estado()
        mac = bytes.fromhex("0200000000aa")
        for s in range(5000):
            e.procesar(self.pk(1e9 + s, "192.168.137.50", "8.8.8.8", 17, 4000, 53, mac, self.GW))
        d = next(iter(e.dispositivos.values()))
        self.assertLessEqual(len(d.serie), vivo.MAX_SERIE + 400)

    def test_el_analizador_tiene_topes(self):
        from unittest import mock
        from botnet_lab import analyzer as an
        with mock.patch.object(an, "MAX_PARES", 100), mock.patch.object(an, "MAX_HOSTS", 50), \
             mock.patch.object(an, "MAX_EVENTOS", 100), mock.patch.object(an, "MAX_CLAVES", 100):
            a = an.Analizador()
            m = bytes.fromhex("0200000000aa")
            for i in range(1000):                      # un origen hacia mil destinos UDP distintos
                a.feed(self.pk(1e9 + i, "192.168.137.50", "20.%d.%d.1" % (i // 250, i % 250), 17, 4000, 9000 + i, m, self.GW))
            self.assertEqual(len(a.udp_out), 100)
            for i in range(1000):                      # mil direcciones de origen falsas
                a.feed(self.pk(2e9 + i, "10.9.%d.%d" % (i // 250, 1 + i % 250), "8.8.8.8", 17, 1, 53, m, self.GW))
            self.assertLessEqual(len(a.hosts), 50)
            for i in range(5000):                      # latidos espaciados más de 2 s
                a.feed(self.pk(3e9 + i * 3, "192.168.137.50", "30.0.0.1", 6, 5000, 6969, m, self.GW, flags=0x18, plen=33))
            self.assertLessEqual(len(next(iter(a.small_out.values()))["ev"]), 100)
            self.assertLessEqual(len(a.small_out), 100)

    def test_los_latidos_comprimidos_siguen_detectandose(self):
        """La compresión a 'eventos' no cambia el resultado: 12 latidos en pareja cada 30 s siguen siendo un BEACON."""
        from botnet_lab import analyzer as an
        a = an.Analizador()
        m = bytes.fromhex("0200000000aa")
        for k in range(12):
            for dt in (0.0, 0.6):
                a.feed(self.pk(1e9 + k * 30 + dt, "192.168.137.50", "198.51.100.10", 6, 5000, 6969, m, self.GW, flags=0x18, plen=33))
        res = a.resultado()
        beacon = [f for f in res["findings"] if f["code"] == "BEACON"]
        self.assertEqual(len(beacon), 1)
        self.assertEqual(beacon[0]["evidence"]["count"], 12)

    def test_un_paquete_problematico_no_detiene_la_captura(self):
        import io
        from unittest import mock
        from botnet_lab import vivo
        from botnet_lab.pcapio import write_pcap
        import emulador_pruebas as em
        with tempfile.TemporaryDirectory() as d:
            ruta = os.path.join(d, "x.pcap")
            write_pcap(ruta, list(em.build(infected=False, duration=60)))
            datos = open(ruta, "rb").read()
            total = sum(1 for _ in read_packets(ruta))
        estado = mock.Mock()
        estado.errores = 0
        estado.procesar.side_effect = [RuntimeError("paquete raro")] + [None] * 100000
        cap = vivo.Captura(estado, "tshark", "x")
        cap.estado_txt = "detenida"
        proc = mock.Mock(stdout=io.BytesIO(datos), poll=lambda: 0, returncode=0)
        cap._leer(proc)
        self.assertEqual(estado.errores, 1)
        self.assertGreater(total, 50)
        self.assertEqual(estado.procesar.call_count, total)                   # siguió leyendo todos los paquetes tras el error

    def test_el_directorio_actual_no_se_usa_para_buscar_programas(self):
        from botnet_lab import sistema
        with tempfile.TemporaryDirectory() as d:
            falso = os.path.join(d, "herramienta_falsa.exe")
            open(falso, "wb").write(b"MZ")
            anterior = os.getcwd()
            os.chdir(d)
            try:
                with mock_path(os.pathsep.join([".", d])):
                    self.assertIsNone(sistema.buscar_en_path("herramienta_falsa"))
            finally:
                os.chdir(anterior)


class InundacionesTests(unittest.TestCase):
    """Inundaciones TCP (SYN) e ICMP: se detectan sin marcar el uso normal."""

    GW = bytes.fromhex("020000000001")
    M = bytes.fromhex("0200000000aa")

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def analizar(self, **kw):
        p = os.path.join(self.d.name, "x.pcap")
        generate(p, **kw)
        return analyze(p)

    @staticmethod
    def hallazgos(res, codigo):
        return [f for f in res["findings"] if f["code"] == codigo]

    @staticmethod
    def pk(ts, src, dst, proto, sport, dport, flags=0, plen=60):
        from botnet_lab.pcapio import Packet
        return Packet(ts, src, dst, proto, sport, dport, flags, plen, b"", plen + 14,
                      bytes.fromhex("0200000000aa"), bytes.fromhex("020000000001"))

    # ---- SYN
    def test_syn_flood_sin_syn_ack_es_alta_y_trae_la_orden_de_control(self):
        res = self.analizar(infected=False, syn_flood=True)
        syn = self.hallazgos(res, "SYN_FLOOD")
        self.assertEqual(len(syn), 1)
        e = syn[0]["evidence"]
        self.assertEqual((e["dst"], e["dport"], syn[0]["severity"]), ("203.0.113.50", 80, "alta"))
        self.assertEqual(e["reply_ratio"], 0)
        self.assertGreater(e["packets"], 8000)
        orden = self.hallazgos(res, "C2_ORDER")
        self.assertEqual(len(orden), 1)
        self.assertEqual(orden[0]["evidence"]["controller"], "198.51.100.10")
        self.assertEqual(res["verdict"], "sospechoso")

    def test_syn_con_syn_ack_es_carga_normal_no_inundacion(self):
        res = self.analizar(infected=False, syn_flood=True, flood_replies=True)
        self.assertEqual(self.hallazgos(res, "SYN_FLOOD"), [])

    def test_barrido_de_muchos_puertos_de_un_host_es_scan_no_syn_flood(self):
        a = Analizador()
        for i in range(2000):                                  # 200 SYN/s durante 10 s, cada uno a un puerto distinto
            a.feed(self.pk(1e9 + i / 200.0, "192.168.137.50", "203.0.113.70", 6, 40000 + i, 1 + i, flags=0x02))
        codigos = [f["code"] for f in a.resultado()["findings"]]
        self.assertIn("SCAN", codigos)
        self.assertNotIn("SYN_FLOOD", codigos)

    def test_syn_a_muchos_destinos_no_es_inundacion(self):
        a = Analizador()
        for i in range(3000):                                  # 300 SYN/s a 300 destinos distintos (tipo P2P)
            a.feed(self.pk(1e9 + i / 300.0, "192.168.137.50", "20.%d.%d.1" % (i // 250, i % 250), 6, 40000 + i, 6881, flags=0x02))
        self.assertNotIn("SYN_FLOOD", [f["code"] for f in a.resultado()["findings"]])

    def test_syn_bajo_el_umbral_no_se_marca(self):
        a = Analizador()
        for i in range(600):                                   # 60 SYN/s al mismo servicio: intenso pero normal
            a.feed(self.pk(1e9 + i / 60.0, "192.168.137.50", "203.0.113.50", 6, 40000 + i, 443, flags=0x02))
        self.assertNotIn("SYN_FLOOD", [f["code"] for f in a.resultado()["findings"]])

    # ---- ICMP
    def test_icmp_flood_sin_respuesta_es_alta(self):
        res = self.analizar(infected=False, icmp_flood=True)
        icmp = self.hallazgos(res, "ICMP_FLOOD")
        self.assertEqual(len(icmp), 1)
        self.assertEqual((icmp[0]["evidence"]["dst"], icmp[0]["severity"], icmp[0]["evidence"]["reply_ratio"]),
                         ("203.0.113.60", "alta", 0))
        self.assertEqual(len(self.hallazgos(res, "C2_ORDER")), 1)
        self.assertEqual(res["verdict"], "sospechoso")

    def test_icmp_flood_con_respuestas_a_ritmo_moderado_es_media(self):
        res = self.analizar(infected=False, icmp_flood=True, flood_replies=True, icmp_pps=100)
        icmp = self.hallazgos(res, "ICMP_FLOOD")
        self.assertEqual(len(icmp), 1)
        self.assertEqual(icmp[0]["severity"], "media")             # el destino responde: se baja la gravedad, no se ignora
        self.assertGreater(icmp[0]["evidence"]["reply_ratio"], 0.9)
        self.assertEqual(res["verdict"], "sospechoso" if self.hallazgos(res, "C2_ORDER") else "revisar")

    def test_icmp_flood_con_respuestas_a_ritmo_muy_alto_sigue_siendo_alta(self):
        res = self.analizar(infected=False, icmp_flood=True, flood_replies=True, icmp_pps=600)
        self.assertEqual(self.hallazgos(res, "ICMP_FLOOD")[0]["severity"], "alta")

    def test_ping_normal_no_es_inundacion(self):
        a = Analizador()
        for i in range(300):                                   # un ping por segundo durante 5 minutos, con respuesta
            a.feed(self.pk(1e9 + i, "192.168.137.50", "8.8.8.8", 1, 0, 0, flags=8))
            a.feed(self.pk(1e9 + i + 0.02, "8.8.8.8", "192.168.137.50", 1, 0, 0, flags=0))
        self.assertEqual([f for f in a.resultado()["findings"] if f["code"] == "ICMP_FLOOD"], [])

    def test_ping_hacia_la_red_local_no_cuenta(self):
        a = Analizador()
        for i in range(3000):
            a.feed(self.pk(1e9 + i / 300.0, "192.168.137.50", "192.168.137.60", 1, 0, 0, flags=8))
        self.assertEqual([f for f in a.resultado()["findings"] if f["code"] == "ICMP_FLOOD"], [])

    # ---- lector, topes, vista en vivo e informe
    def test_el_lector_distingue_ping_y_respuesta(self):
        import emulador_pruebas as em
        from botnet_lab.pcapio import _parse, frame
        eco = frame(em.DEV_MAC, em.GW_MAC, em.DEV_IP, "203.0.113.60", 1, em.icmp_segment(8, b"x" * 56))
        resp = frame(em.GW_MAC, em.DEV_MAC, "203.0.113.60", em.DEV_IP, 1, em.icmp_segment(0, b"x" * 56))
        a, b = _parse(1.0, 1, eco, len(eco)), _parse(1.0, 1, resp, len(resp))
        self.assertEqual((a.proto, a.flags, a.plen), (1, 8, 56))
        self.assertEqual((b.proto, b.flags), (1, 0))

    def test_topes_de_memoria_de_las_inundaciones(self):
        from unittest import mock
        from botnet_lab import analyzer as an
        with mock.patch.object(an, "MAX_PARES", 50):
            a = an.Analizador()
            for i in range(500):
                a.feed(self.pk(1e9 + i, "192.168.137.50", "30.%d.%d.1" % (i // 250, i % 250), 6, 4000, 80, flags=0x02))
                a.feed(self.pk(1e9 + i, "192.168.137.50", "40.%d.%d.1" % (i // 250, i % 250), 1, 0, 0, flags=8))
            self.assertLessEqual(len(a.syn_out), 50)
            self.assertLessEqual(len(a.icmp_out), 50)

    def test_la_vista_en_vivo_pone_rojo_y_describe_el_ping(self):
        from botnet_lab.vivo import Estado
        p = os.path.join(self.d.name, "v.pcap")
        generate(p, infected=False, syn_flood=True, icmp_flood=True)
        e = Estado()
        for pk in read_packets(p):
            e.procesar(pk)
        self.assertEqual(e.lista()["items"][0]["semaforo"], "rojo")
        # el texto de los paquetes ICMP en la lista en vivo (se comprueba con un Estado propio, sin el muestreo de un ataque)
        e2 = Estado()
        e2.procesar(self.pk(1e9, "192.168.137.50", "8.8.8.8", 1, 0, 0, flags=8))
        e2.procesar(self.pk(1e9 + 0.02, "8.8.8.8", "192.168.137.50", 1, 0, 0, flags=0))
        textos = [f[10] for f in e2.paquetes()["filas"]]
        self.assertEqual(textos, ["ICMP: eco (ping)", "ICMP: respuesta de eco"])

    def test_el_informe_explica_las_inundaciones_en_lenguaje_simple(self):
        from botnet_lab.informe import frases
        res = self.analizar(infected=False, syn_flood=True, icmp_flood=True)
        txt = " ".join(t for _, t in frases(res["findings"]))
        self.assertIn("conexiones nuevas", txt)
        self.assertIn("pings", txt)
        self.assertIn("SYN", txt)

    def test_no_aparecen_inundaciones_en_el_trafico_sano(self):
        res = self.analizar(infected=False, duration=700, quic=True)
        self.assertEqual([f for f in res["findings"] if f["code"] in ("SYN_FLOOD", "ICMP_FLOOD")], [])
        self.assertEqual(res["verdict"], "sin indicios")


class SondeoLocalTests(unittest.TestCase):
    """LAN_SCAN: un dispositivo que sondea muchos equipos de su propia red (movimiento lateral)."""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)

    def analizar(self, **kw):
        p = os.path.join(self.d.name, "x.pcap")
        generate(p, **kw)
        return analyze(p)

    @staticmethod
    def lan(res):
        return [f for f in res["findings"] if f["code"] == "LAN_SCAN"]

    @staticmethod
    def pk(ts, src, dst, flags=0x02, dport=5555):
        from botnet_lab.pcapio import Packet
        return Packet(ts, src, dst, 6, 40000, dport, flags, 0, b"", 60,
                      bytes.fromhex("0200000000aa"), bytes.fromhex("020000000001"))

    def test_sondeo_de_la_red_local_se_detecta_con_puerto_y_respuestas(self):
        res = self.analizar(infected=False, lan_scan=100, lan_open=3)
        f = self.lan(res)
        self.assertEqual(len(f), 1)
        e = f[0]["evidence"]
        self.assertGreaterEqual(e["hosts_per_10s"], 20)
        self.assertEqual(e["top_ports"][0][0], 5555)
        self.assertEqual(e["responded"], 3)
        self.assertEqual(f[0]["severity"], "media")          # puede ser un escáner legítimo: se pide revisar, no se acusa
        self.assertEqual(res["verdict"], "revisar")

    def test_el_sondeo_local_no_se_confunde_con_el_barrido_a_internet(self):
        res = self.analizar(infected=False, lan_scan=100)
        self.assertEqual([f for f in res["findings"] if f["code"] == "SCAN"], [])

    def test_hablar_con_pocos_equipos_locales_no_es_sondeo(self):
        a = Analizador()
        for i in range(2000):                                  # mucho tráfico, pero solo con 10 equipos conocidos
            a.feed(self.pk(1e9 + i / 100.0, "192.168.137.50", "192.168.137.%d" % (60 + i % 10)))
        self.assertEqual(self.lan(a.resultado()), [])

    def test_justo_bajo_el_umbral_no_se_marca_y_en_el_umbral_si(self):
        for n, esperado in ((19, 0), (20, 1)):
            a = Analizador()
            for i in range(n):
                a.feed(self.pk(1e9 + i * 0.1, "192.168.137.50", "192.168.137.%d" % (100 + i)))
            self.assertEqual(len(self.lan(a.resultado())), esperado, n)

    def test_el_sondeo_lento_repartido_en_el_tiempo_no_cuenta(self):
        a = Analizador()
        for i in range(60):                                    # un equipo nuevo cada 30 s: nunca 20 en 10 s
            a.feed(self.pk(1e9 + i * 30.0, "192.168.137.50", "192.168.137.%d" % (100 + i)))
        self.assertEqual(self.lan(a.resultado()), [])

    def test_el_trafico_local_normal_y_el_de_internet_no_activan_nada(self):
        res = self.analizar(infected=False, duration=700, quic=True)
        self.assertEqual(self.lan(res), [])
        self.assertEqual(res["verdict"], "sin indicios")

    def test_un_syn_hacia_si_mismo_o_de_internet_hacia_la_red_no_cuenta(self):
        a = Analizador()
        for i in range(50):
            a.feed(self.pk(1e9 + i * 0.1, "203.0.113.9", "192.168.137.%d" % (100 + i)))  # de internet hacia dentro
        self.assertEqual(self.lan(a.resultado()), [])
        a = Analizador()
        for i in range(19):                                    # 19 vecinos + él mismo = 20 "destinos", pero solo 19 equipos ajenos
            a.feed(self.pk(1e9 + i * 0.1, "192.168.137.50", "192.168.137.%d" % (100 + i)))
        a.feed(self.pk(1e9 + 2.0, "192.168.137.50", "192.168.137.50"))
        self.assertEqual(self.lan(a.resultado()), [])

    def test_con_dispositivo_elegido_solo_se_juzga_ese(self):
        a = Analizador(device="192.168.137.77")
        for i in range(60):
            a.feed(self.pk(1e9 + i * 0.1, "192.168.137.50", "192.168.137.%d" % (100 + i)))
        self.assertEqual(self.lan(a.resultado()), [])

    def test_tope_de_memoria_del_sondeo(self):
        from unittest import mock
        from botnet_lab import analyzer as an
        with mock.patch.object(an, "MAX_HOSTS", 30):
            a = an.Analizador()
            for i in range(300):
                a.feed(self.pk(1e9 + i, "192.168.%d.%d" % (i // 250, 1 + i % 250), "192.168.137.200"))
            self.assertLessEqual(len(a.lan), 30)
        a = an.Analizador()
        for i in range(2000):                                  # miles de destinos: la ventana queda acotada
            a.feed(self.pk(1e9 + i * 0.001, "192.168.137.50", "10.%d.%d.1" % (i // 250, i % 250)))
        self.assertLessEqual(len(a.lan["192.168.137.50"]["set"]), an.MAX_VENTANA_SYN)

    def test_el_informe_lo_explica_en_lenguaje_simple(self):
        from botnet_lab.informe import frases
        txt = " ".join(t for _, t in frases(self.analizar(infected=False, lan_scan=100, lan_open=2)["findings"]))
        self.assertIn("de su propia red", txt)
        self.assertIn("2 contestaron", txt)

    def test_la_vista_en_vivo_lo_pone_amarillo(self):
        from botnet_lab.vivo import Estado
        p = os.path.join(self.d.name, "v.pcap")
        generate(p, infected=False, lan_scan=100)
        e = Estado()
        for pk in read_packets(p):
            e.procesar(pk)
        self.assertEqual(e.lista()["items"][0]["semaforo"], "amarillo")


class mock_path:
    """Cambia el PATH un momento."""

    def __init__(self, valor):
        self.valor = valor

    def __enter__(self):
        self.antes = os.environ.get("PATH", "")
        os.environ["PATH"] = self.valor

    def __exit__(self, *a):
        os.environ["PATH"] = self.antes


if __name__ == "__main__":
    unittest.main()
