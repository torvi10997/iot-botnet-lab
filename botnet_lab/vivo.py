"""Captura en vivo: agrupa el tráfico por dispositivo para mostrarlo y diagnosticarlo mientras ocurre."""
import collections
import json
import os
import re
import subprocess
import tempfile
import threading
import time

from . import informe, oui, servicios, sistema
from .analyzer import Analizador, Presupuesto, _qname
from .pcapio import mac_str, read_stream

GATEWAY_HOTSPOT = "192.168.137.1"
# Topes de memoria: el dispositivo observado puede ser hostil (suplantar miles de MAC, barrer miles de destinos...)
MAX_DISPOSITIVOS = 1000           # en vivo; al abrir un archivo (una captura de router) se permiten más
MAX_ENTRADAS_VIVO = 400000       # presupuesto global de entradas en memoria en una captura en vivo (~150 MB)
MAX_ENTRADAS_ARCHIVO = 3000000   # al abrir un archivo elegido por el usuario
MAX_CONVERSACIONES = 5000     # por dispositivo; el resto se agrupa en "(otros destinos)"
MAX_NOMBRES = 100000          # IP -> dominio aprendidos de respuestas DNS (se descartan los más antiguos)
MAX_SERIE = 300               # segundos de historial por dispositivo (la gráfica solo muestra 2 minutos)
OTROS = "(otros destinos)"
_IP_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


# ------------------------------------------------------------ utilidades de DNS
def _leer_nombre(b, i):
    labels, saltos, fin = [], 0, None
    while True:
        if i >= len(b):
            return None, None
        ln = b[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0 == 0xC0:
            if i + 1 >= len(b):
                return None, None
            if fin is None:
                fin = i + 2
            i = ((ln & 0x3F) << 8) | b[i + 1]
            saltos += 1
            if saltos > 10:
                return None, None
            continue
        labels.append(b[i + 1:i + 1 + ln].decode("ascii", "replace"))
        i += 1 + ln
    return ".".join(labels), (fin if fin is not None else i)


def dns_respuesta(b):
    """Devuelve (nombre consultado, [IPv4 de la respuesta]) o None si no es una respuesta DNS."""
    if len(b) < 12 or not (b[2] & 0x80):
        return None
    qd, an = (b[4] << 8) | b[5], (b[6] << 8) | b[7]
    i, q = 12, None
    for _ in range(qd):
        nombre, i = _leer_nombre(b, i)
        if nombre is None:
            return None
        q = q or nombre
        i += 4
    ips = []
    for _ in range(an):
        nombre, i = _leer_nombre(b, i)
        if nombre is None or i + 10 > len(b):
            break
        tipo, rdlen = (b[i] << 8) | b[i + 1], (b[i + 8] << 8) | b[i + 9]
        i += 10
        if tipo == 1 and rdlen == 4 and i + 4 <= len(b):
            ips.append(".".join(str(x) for x in b[i:i + 4]))
        i += rdlen
    return (q, ips) if q else None


def _flags(f):
    if f & 0x04:
        return "RST"
    if f & 0x02:
        return "SYN" if not f & 0x10 else "SYN-ACK"
    if f & 0x01:
        return "FIN"
    return "datos" if f & 0x08 else "ACK"


# ---------------------------------------------------------------- router
def detectar_router(paquetes, muestra=80000):
    """Adivina el router de una captura: la MAC que recibe casi todo lo que va de la red local hacia internet.
    Devuelve (IP del router o None, MAC del router o None). Si no hay una candidata clara, (None, None)."""
    loc = Analizador().es_local
    destinos, ips = collections.Counter(), collections.defaultdict(collections.Counter)
    for i, p in enumerate(paquetes):
        if i >= muestra:
            break
        if p.src_mac is None or not loc(p.src):
            continue
        ips[p.src_mac][p.src] += 1
        if not loc(p.dst):
            destinos[p.dst_mac] += 1
    total = sum(destinos.values())
    if not total:
        return None, None
    mac, n = destinos.most_common(1)[0]
    if n < 0.5 * total or mac is None:
        return None, None
    ip = ips[mac].most_common(1)[0][0] if ips.get(mac) else None
    return ip, mac_str(mac)


# ---------------------------------------------------------------- dispositivo
class Dispositivo:
    def __init__(self, mac, ip=None, nombre=None, presupuesto=None):
        self.mac, self.ip, self.nombre = mac, ip, nombre
        self.t0 = self.t1 = None
        self.po = self.pi = self.bo = self.bi = 0
        self.serie = {}                       # segundo -> [pkts salientes, pkts entrantes, bytes sal, bytes ent]
        self.conv = {}                        # (remoto, proto, puerto) -> dict
        self.an = Analizador(presupuesto=presupuesto)
        self._cache = (0, None)


class Estado:
    def __init__(self, gateway=GATEWAY_HOTSPOT, tshark=None, presupuesto=MAX_ENTRADAS_VIVO, max_dispositivos=None):
        self.lock = threading.RLock()
        self.pres = Presupuesto(presupuesto)
        self.max_dispositivos = max_dispositivos
        self.gw, self.tshark = gateway, tshark
        self.dispositivos = {}
        self.nombres_ip = {}                  # IP -> dominio (aprendido de las respuestas DNS)
        self.ignorados = 0                    # dispositivos nuevos descartados por superar el tope
        self.agrupadas = 0                    # conversaciones agrupadas en "(otros destinos)"
        self.errores = 0                      # paquetes que no se pudieron procesar
        self._cache_lista = {}
        self.anillo = collections.deque(maxlen=800)
        self.pid = 0
        self._fila_seg, self._fila_n = 0, 0
        self.omitidos = 0
        self.total = 0
        self.t_ultimo = 0.0
        self._acum = 0.0
        self._t_run = None
        self._loc = Analizador()
        self.clientes = {}                    # MAC -> (nombre, ip) según Windows
        self.gw_mac = None                    # MAC del router (no se cuenta como dispositivo)
        self.solo_archivo = False             # True si se está viendo una captura abierta, no una en vivo

    # ---- tiempo activo (sin contar las pausas)
    def activo(self):
        return self._acum + ((time.time() - self._t_run) if self._t_run else 0.0)

    def marcha(self, on):
        with self.lock:
            if on and self._t_run is None:
                self._t_run = time.time()
            elif not on and self._t_run is not None:
                self._acum += time.time() - self._t_run
                self._t_run = None

    # ---- entrada de paquetes
    def procesar(self, p):
        if p.src_mac is None:
            return
        es = self._loc.es_local
        if es(p.src) and p.src != self.gw:
            mac, ip, sale, remoto, rport = mac_str(p.src_mac), p.src, True, p.dst, p.dport
        elif es(p.dst) and p.dst != self.gw:
            mac, ip, sale, remoto, rport = mac_str(p.dst_mac), p.dst, False, p.src, p.sport
        else:
            return
        if mac == "ff:ff:ff:ff:ff:ff" or mac == self.gw_mac:
            return
        with self.lock:
            self.total += 1
            self.t_ultimo = max(self.t_ultimo, p.ts)
            d = self.dispositivos.get(mac)
            if d is None:
                if len(self.dispositivos) >= (self.max_dispositivos or MAX_DISPOSITIVOS) or not self.pres.pedir(20):
                    self.ignorados += 1
                    return
                d = self.dispositivos[mac] = Dispositivo(mac, presupuesto=self.pres)
            d.ip = ip
            if d.t0 is None:
                d.t0 = p.ts
            d.t1 = p.ts
            ln = p.wire_len
            if len(d.serie) > MAX_SERIE + 400:
                for k in sorted(d.serie)[:-MAX_SERIE]:
                    del d.serie[k]
            b = d.serie.setdefault(int(p.ts), [0, 0, 0, 0])
            if sale:
                d.po += 1
                d.bo += ln
                b[0] += 1
                b[2] += ln
            else:
                d.pi += 1
                d.bi += ln
                b[1] += 1
                b[3] += ln
            proto = "TCP" if p.proto == 6 else "UDP" if p.proto == 17 else {1: "ICMP", 2: "IGMP", 58: "ICMPv6"}.get(p.proto, "IP%d" % p.proto)
            clave = (remoto, proto, rport)
            if clave not in d.conv and (len(d.conv) >= MAX_CONVERSACIONES or not self.pres.pedir()):
                clave = (OTROS, proto, 0)
                if clave not in d.conv:
                    self.agrupadas += 1
            c = d.conv.get(clave)
            if c is None:
                c = d.conv[clave] = {"po": 0, "pi": 0, "bo": 0, "bi": 0, "t0": p.ts, "t1": p.ts, "w": {}}
            c["t1"] = p.ts
            s = int(p.ts)
            if sale:
                c["po"] += 1
                c["bo"] += ln
                c["w"][s] = c["w"].get(s, 0) + 1
                if len(c["w"]) > 12:
                    for k in sorted(c["w"])[:-8]:
                        del c["w"][k]
            else:
                c["pi"] += 1
                c["bi"] += ln
            d.an.feed(p)
            info = ""
            if p.proto == 17:
                if p.sport == 53 and not sale:
                    r = dns_respuesta(p.payload)
                    if r:
                        for x in r[1]:
                            if x not in self.nombres_ip and len(self.nombres_ip) >= MAX_NOMBRES:
                                del self.nombres_ip[next(iter(self.nombres_ip))]
                            self.nombres_ip[x] = r[0]
                        info = "Respuesta DNS: %s -> %s" % (r[0], ", ".join(r[1][:3]) or "sin dirección")
                elif p.dport == 53 and sale:
                    q = _qname(p.payload)
                    info = "Consulta DNS: %s" % (q.decode("ascii", "replace") if q and all(32 <= x < 127 for x in q)
                                                  else "(nombre binario de %d bytes)" % len(q or b""))
            elif p.proto == 6:
                info = _flags(p.flags)
            elif p.proto == 1:
                info = {8: "ICMP: eco (ping)", 0: "ICMP: respuesta de eco", 3: "ICMP: destino inalcanzable",
                        11: "ICMP: tiempo excedido"}.get(p.flags, "ICMP tipo %d" % p.flags)
            # fila para la lista en vivo (con tope por segundo; si hay más, se muestrea)
            if s != self._fila_seg:
                self._fila_seg, self._fila_n = s, 0
            if self._fila_n < 80:
                self._fila_n += 1
                self.pid += 1
                self.anillo.append((self.pid, p.ts, mac, "sale" if sale else "entra", p.src, p.dst, proto,
                                    p.sport, p.dport, p.wire_len, info))
            else:
                self.omitidos += 1

    # ---- consultas para la interfaz
    def _ritmo(self, d, ref):
        v = [d.serie.get(t, [0, 0, 0, 0]) for t in (ref - 3, ref - 2, ref - 1)]
        return {"pps_sale": round(sum(x[0] for x in v) / 3), "pps_entra": round(sum(x[1] for x in v) / 3),
                "kbps_sale": round(sum(x[2] for x in v) * 8 / 3000), "kbps_entra": round(sum(x[3] for x in v) * 8 / 3000)}

    def _semaforo(self, d, ref):
        t, res = d._cache
        if res is None or time.time() - t > 2:
            res = d.an.resultado(nombre=d.mac, activo_s=self.activo())
            d._cache = (time.time(), res)
        color = informe.semaforo(res)
        etiqueta, titulo, _, _ = informe.SEMAFORO[color]
        fr = [{"nivel": sv, "texto": tx} for sv, tx in informe.frases(res["findings"])]
        return {"color": color, "etiqueta": etiqueta, "titulo": titulo, "frases": fr,
                "acciones": informe.ACCIONES[color], "duracion_s": res["summary"]["duration_s"],
                "faltan_s": max(0, int(informe.MIN_VERDE_S - self.activo())),
                "hallazgos": res["findings"]}

    def lista(self, q=None, limite=200):
        """Dispositivos, con los sospechosos primero. `q` filtra por nombre, MAC, IP o fabricante."""
        with self.lock:
            ahora = time.time()
            hit = self._cache_lista.get((q, limite))
            if hit and ahora - hit[0] < 1.5:
                return hit[1]
            out = []
            macs = set(self.dispositivos) | (set() if self.solo_archivo else set(self.clientes))
            for m in macs:
                d = self.dispositivos.get(m)
                cli = self.clientes.get(m, (None, None)) if not self.solo_archivo else (None, None)
                nombre = (d.nombre if d and d.nombre else None) or cli[0]
                ip = (d.ip if d and d.ip else None) or cli[1]
                ref = int(self.t_ultimo) if self.t_ultimo else int(time.time())
                item = {"mac": m, "nombre": nombre or "Dispositivo sin nombre", "ip": ip or "-",
                        "fabricante": oui.fabricante(m, self.tshark),
                        "paquetes": (d.po + d.pi) if d else 0, "visto": d is not None}
                if q:
                    t = q.lower()
                    if not any(t in str(item[k]).lower() for k in ("nombre", "mac", "ip", "fabricante")):
                        continue
                if d:
                    item["semaforo"] = self._semaforo(d, ref)["color"]
                    item["ritmo"] = self._ritmo(d, ref)
                out.append(item)
            orden = {"rojo": 0, "amarillo": 1}
            out.sort(key=lambda x: (orden.get(x.get("semaforo"), 2), -x["paquetes"]))
            res = {"items": out[:limite], "total": len(out), "sospechosos": sum(1 for x in out if x.get("semaforo") in orden)}
            if len(self._cache_lista) > 20:
                self._cache_lista.clear()
            self._cache_lista[(q, limite)] = (ahora, res)
            return res

    def datos(self, mac, ref=None):
        with self.lock:
            d = self.dispositivos.get(mac)
            if d is None:
                return None
            ref = ref or (int(time.time()) if self._t_run else int(self.t_ultimo))
            cli = self.clientes.get(mac, (None, None))
            serie = []
            for t in range(ref - 119, ref + 1):
                v = d.serie.get(t, [0, 0, 0, 0])
                serie.append([t - ref, v[0], v[1], round(v[2] * 8 / 1000), round(v[3] * 8 / 1000)])
            convs = []
            cats = {}
            for (remoto, proto, rport), c in d.conv.items():
                dom = self.nombres_ip.get(remoto)
                cat, serv, expl = servicios.describir(proto, rport, dom)
                by = c["bo"] + c["bi"]
                a = cats.setdefault(cat, {"bytes": 0, "paquetes": 0, "servicios": {}})
                a["bytes"] += by
                a["paquetes"] += c["po"] + c["pi"]
                a["servicios"][serv] = a["servicios"].get(serv, 0) + by
                w = c["w"]
                convs.append({"remoto": remoto, "dominio": dom, "proto": proto, "puerto": rport, "categoria": cat,
                              "servicio": serv, "explicacion": expl, "po": c["po"], "pi": c["pi"], "bo": c["bo"],
                              "bi": c["bi"], "pps": round(sum(w.get(t, 0) for t in range(ref - 3, ref)) / 3),
                              "activa": c["t1"] >= ref - 5, "bytes": by})
            convs.sort(key=lambda x: (-x["pps"], -x["bytes"]))
            total_b = sum(a["bytes"] for a in cats.values()) or 1
            categorias = []
            for k, a in sorted(cats.items(), key=lambda kv: -kv[1]["bytes"]):
                top = sorted(a["servicios"].items(), key=lambda kv: -kv[1])[:3]
                categorias.append({"clave": k, "nombre": servicios.CATEGORIAS[k][0],
                                   "descripcion": servicios.CATEGORIAS[k][1], "bytes": a["bytes"],
                                   "paquetes": a["paquetes"], "pct": round(100 * a["bytes"] / total_b),
                                   "servicios": [s for s, _ in top]})
            nombre = d.nombre or cli[0]
            # reparto por protocolo y por destino (para los gráficos de pastel)
            por_proto, por_dest = {}, {}
            for cv in convs:
                por_proto[cv["proto"]] = por_proto.get(cv["proto"], 0) + cv["bytes"]
                x = por_dest.setdefault(cv["remoto"], {"bytes": 0, "dominio": cv["dominio"], "servicio": cv["servicio"], "mejor": 0})
                x["bytes"] += cv["bytes"]
                if cv["bytes"] > x["mejor"]:
                    x["mejor"], x["servicio"] = cv["bytes"], cv["servicio"]
                x["dominio"] = x["dominio"] or cv["dominio"]
            protocolos = [{"nombre": k, "bytes": v, "pct": round(100 * v / total_b)}
                          for k, v in sorted(por_proto.items(), key=lambda kv: -kv[1])]
            ordenados = sorted(por_dest.items(), key=lambda kv: -kv[1]["bytes"])
            destinos = [{"nombre": v["dominio"] or k, "ip": k, "servicio": v["servicio"], "bytes": v["bytes"],
                         "pct": round(100 * v["bytes"] / total_b)} for k, v in ordenados[:5]]
            resto = sum(v["bytes"] for _, v in ordenados[5:])
            if resto:
                destinos.append({"nombre": "Otros destinos", "ip": "", "servicio": "%d más" % (len(ordenados) - 5),
                                 "bytes": resto, "pct": round(100 * resto / total_b)})
            return {"mac": mac, "nombre": nombre or "Dispositivo sin nombre", "ip": d.ip or cli[1] or "-",
                    "protocolos": protocolos, "destinos": destinos,
                    "fabricante": oui.fabricante(mac, self.tshark),
                    "mac_privada": oui.mac_privada(mac),
                    "totales": {"po": d.po, "pi": d.pi, "bo": d.bo, "bi": d.bi},
                    "ritmo": self._ritmo(d, ref), "serie": serie, "categorias": categorias,
                    "conexiones": convs[:120], "semaforo": self._semaforo(d, ref)}

    def paquetes(self, desde=0, mac=None, limite=300):
        with self.lock:
            filas = [f for f in self.anillo if f[0] > desde and (mac is None or f[2] == mac)]
            return {"filas": filas[-limite:], "ultimo": self.pid, "omitidos": self.omitidos}

    def resultado(self, mac):
        with self.lock:
            d = self.dispositivos.get(mac)
            return d.an.resultado(nombre=mac, activo_s=self.activo()) if d else None


# --------------------------------------------------------------- Windows / hotspot
_PS_CLIENTES = r"""
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
$null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
$p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
$m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p)
foreach ($c in $m.GetTetheringClients()) {
  $n = @(); foreach ($h in $c.HostNames) { $n += $h.DisplayName }
  "$($c.MacAddress)|" + ($n -join ",")
}
"""


def clientes_hotspot():
    """MAC -> (nombre, ip) de los dispositivos conectados al hotspot de Windows."""
    if os.name != "nt":
        return {}
    try:
        out = subprocess.run([sistema.POWERSHELL, "-NoProfile", "-Command", _PS_CLIENTES], capture_output=True,
                             text=True, timeout=25, errors="replace").stdout
    except Exception:
        return {}
    res = {}
    for line in out.splitlines():
        if "|" not in line:
            continue
        mac, nombres = line.strip().split("|", 1)
        mac = mac.replace("-", ":").lower()
        partes = [x for x in nombres.split(",") if x]
        ip = next((x for x in partes if _IP_RE.match(x)), None)
        nombre = next((x for x in partes if not _IP_RE.match(x)), None)
        res[mac] = (nombre, ip)
    return res


# ---------------------------------------------------------------- captura
class Captura:
    def __init__(self, estado, tshark, interfaz, mac_filtro=None, guardar_en=None):
        self.estado, self.tshark, self.interfaz = estado, tshark, interfaz
        self.mac_filtro, self.guardar_en = mac_filtro, guardar_en
        self.estado_txt = "detenida"          # detenida | capturando | pausada
        self.error = None
        self._proc = None
        self._hilo = None
        self._tee = None
        self._err = None

    def _lanzar(self):
        cmd = [self.tshark, "-q", "-l", "-i", self.interfaz, "-s", "300", "-F", "pcap", "-w", "-"]
        if self.mac_filtro:
            cmd += ["-f", "ether host " + self.mac_filtro]
        self._err = tempfile.TemporaryFile()
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=self._err)
        if self.guardar_en:
            self._tee = open(self.guardar_en, "ab")
        self._hilo = threading.Thread(target=self._leer, args=(self._proc,), daemon=True)
        self._hilo.start()

    def _leer(self, proc):
        try:
            for p in read_stream(proc.stdout, self._tee):
                try:
                    self.estado.procesar(p)
                except Exception:
                    self.estado.errores += 1
        except Exception as e:                # el flujo se cortó al detener tshark
            if self.estado_txt == "capturando":
                self.error = str(e)
        finally:
            if self.estado_txt == "capturando" and proc.poll() is not None and proc.returncode not in (0, None):
                try:
                    self._err.seek(0)
                    self.error = (self._err.read().decode("utf8", "replace").strip() or "tshark terminó con error")[-400:]
                except Exception:
                    self.error = "tshark terminó con error"
                self.estado_txt = "detenida"
                self.estado.marcha(False)

    def _parar_proc(self):
        p, self._proc = self._proc, None
        if p and p.poll() is None:
            if os.name == "nt":               # tshark lanza dumpcap: se cierra todo el árbol
                subprocess.run([sistema.TASKKILL, "/T", "/F", "/PID", str(p.pid)], capture_output=True)
            else:
                p.terminate()
        if self._hilo:
            self._hilo.join(timeout=3)
        if self._tee:
            self._tee.close()
            self._tee = None

    def iniciar(self):
        if self.estado_txt == "capturando":
            return
        self.error = None
        self._lanzar()
        self.estado_txt = "capturando"
        self.estado.marcha(True)

    continuar = iniciar

    def pausar(self):
        if self.estado_txt != "capturando":
            return
        self.estado_txt = "pausada"
        self.estado.marcha(False)
        self._parar_proc()

    def detener(self):
        self.estado_txt = "detenida"
        self.estado.marcha(False)
        self._parar_proc()
