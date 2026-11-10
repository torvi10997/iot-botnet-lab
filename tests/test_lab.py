import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from botnet_lab.analyzer import analyze  # noqa: E402
from botnet_lab.emulator import build, generate  # noqa: E402
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
        html = open(os.path.join(out, os.listdir(out)[0]), encoding="utf8").read()
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


if __name__ == "__main__":
    unittest.main()
