import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botnet_lab.analyzer import analyze  # noqa: E402
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
        lista = e.lista()
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

    def test_la_app_no_escanea_desconocidos_ni_la_puerta_de_enlace(self):
        import tempfile as tf
        from botnet_lab.app import App
        with tf.TemporaryDirectory() as d:
            pcap = os.path.join(d, "x.pcap")
            generate(pcap, infected=False, duration=20)
            app = App(abrir=[pcap])
        self.assertFalse(app.lanzar_escaneo("aa:bb:cc:dd:ee:ff", "rapido")["ok"])   # MAC no vista
        self.assertEqual(app.escaneos, {})


if __name__ == "__main__":
    unittest.main()
