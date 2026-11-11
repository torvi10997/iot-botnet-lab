"""Analizador: busca en una captura los indicios de un dispositivo IoT comprometido.

Detecta (por cada equipo de la red local):
  UDP_FLOOD   inundación UDP sostenida y sin respuestas
  C2_ORDER    paquete pequeño entrante justo antes de una inundación (orden de control)
  BEACON      latidos periódicos hacia un mismo destino (canal de control)
  DNS_RANDOM  consultas DNS con nombres aleatorios, directo a resolvers públicos
  DNS_BYPASS  uso masivo de resolvers públicos en vez del DNS del router
  SCAN        barrido de muchos destinos/puertos con SYN
"""
import ipaddress
import math
import statistics
from collections import Counter, defaultdict, deque

from .pcapio import read_packets

SEV_ORDER = {"alta": 0, "media": 1, "info": 2}
# Red local por defecto: RFC 1918 + link-local + CGNAT (no usar is_private: incluye rangos de documentación)
DEFAULT_LOCAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"]

# Topes de memoria. El dispositivo que se analiza puede ser hostil: si inventa miles de destinos, puertos o
# direcciones, la aplicación no debe crecer sin límite. Lo que supera un tope se ignora (no rompe el análisis).
MAX_PARES = 20000        # pares (origen, destino) con tráfico UDP saliente seguidos a la vez
MAX_SEGUNDOS = 4000      # segundos por par; al pasarse se descartan los que no llegan al umbral de inundación
MAX_PUERTOS = 64         # puertos distintos recordados por par
MAX_CLAVES = 20000       # claves de latido (origen, destino, puerto, tamaño)
MAX_EVENTOS = 3000       # latidos recordados por clave
MAX_HOSTS = 5000         # direcciones locales distintas recordadas
MAX_ENTRANTES = 2000     # mensajes pequeños entrantes recordados por equipo
MAX_UDP_IN = 50000       # pares (local, remoto) con tráfico UDP entrante
MAX_VENTANA_SYN = 500    # destinos/puertos recordados por ventana de 10 s
MAX_CACHE_IP = 100000    # direcciones cuya "localidad" se recuerda
MAX_ENTRADAS = 2000000   # presupuesto por defecto de un análisis suelto (archivos)


class Presupuesto:
    """Tope GLOBAL de entradas en memoria, compartido por todos los dispositivos de una sesión.

    Los topes por dispositivo no bastan: mil dispositivos falsos podrían llenar cada uno el suyo. Cada vez que se
    guarda algo nuevo (un par de direcciones, un puerto, una conversación...) se pide al presupuesto; si se agotó,
    lo nuevo se ignora y se cuenta en `rechazos` (la ventana avisa), mientras lo ya guardado sigue funcionando.
    """

    def __init__(self, limite):
        self.limite, self.usado, self.rechazos = limite, 0, 0

    def pedir(self, n=1):
        if self.usado + n > self.limite:
            self.rechazos += 1
            return False
        self.usado += n
        return True


class Finding:
    def __init__(self, code, severity, title, detail, evidence=None):
        self.code, self.severity, self.title = code, severity, title
        self.detail, self.evidence = detail, evidence or {}

    def as_dict(self):
        return {"code": self.code, "severity": self.severity, "title": self.title,
                "detail": self.detail, "evidence": self.evidence}


def _entropy(s):
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values()) if n else 0.0


def _qname(payload):
    """Primera etiqueta del nombre consultado, como bytes crudos (los bots usan etiquetas binarias)."""
    if len(payload) < 13:
        return None
    ln = payload[12]
    if ln == 0 or ln > 63:
        return None
    return bytes(payload[13:13 + ln])


_HOSTCHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _is_random_label(name):
    """Etiqueta larga que no parece un nombre de host: binaria o de alta entropía."""
    if not name:
        return False
    lab = name
    if len(lab) < 14:
        return False
    odd = sum(1 for b in lab if b not in _HOSTCHARS) / len(lab)
    return odd >= 0.3 or _entropy(lab) >= 3.3


def _show(name):
    lab = name
    if all(32 <= b < 127 for b in lab):
        return lab.decode("ascii")
    return "%d bytes binarios (%s...)" % (len(lab), lab[:6].hex())


def _episodes(secs, min_secs):
    """Agrupa segundos consecutivos (tolera 1 s de hueco)."""
    out, cur = [], []
    for s in sorted(secs):
        if cur and s - cur[-1] > 2:
            out.append(cur)
            cur = []
        cur.append(s)
    if cur:
        out.append(cur)
    return [e for e in out if (e[-1] - e[0] + 1) >= min_secs]


class Analizador:
    """Analiza paquetes uno a uno (feed) y puede dar el resultado en cualquier momento (resultado)."""

    def __init__(self, min_pps=200, min_secs=5, local_nets=None, device=None, presupuesto=None):
        self.min_pps, self.min_secs, self.device = min_pps, min_secs, device
        self.pres = presupuesto or Presupuesto(MAX_ENTRADAS)
        self.nets = [ipaddress.ip_network(n) for n in (local_nets or DEFAULT_LOCAL)]
        self._cache = {}
        self.n = 0
        self.t_first = self.t_last = None
        self.udp_out = defaultdict(lambda: defaultdict(lambda: [0, 0, None]))  # (src,dst) -> sec -> [pkts, bytes, first_ts]
        self.dports = defaultdict(Counter)
        self.udp_in = Counter()                                  # (local, remote) -> paquetes
        self.small_out = {}                                      # (src,dst,dport,plen) -> {"ev": [inicio de cada latido], "last": ts}
        self.small_in = {}                                       # local -> deque[(ts, remote, rport, plen)]
        self.dns = defaultdict(lambda: {"total": 0, "pub": 0, "rnd": 0, "t0": None, "t1": None,
                                        "resolvers": Counter(), "ex": None})
        self.syn = {}                                            # src -> {"w": ventana, "set": {(dst, puerto)}, "max": n}
        self.syn_ports = {}                                      # src -> Counter(puerto)
        self.hosts = Counter()

    def es_local(self, ip):
        r = self._cache.get(ip)
        if r is None:
            if len(self._cache) >= MAX_CACHE_IP:
                self._cache.clear()
            a = ipaddress.ip_address(ip)
            r = self._cache[ip] = any(a in n for n in self.nets)
        return r

    def _dns_query(self, p):
        if p.src not in self.dns and (len(self.dns) >= MAX_HOSTS or not self.pres.pedir(5)):
            return
        d = self.dns[p.src]
        d["total"] += 1
        if d["t0"] is None:
            d["t0"] = p.ts
        d["t1"] = p.ts
        if not self.es_local(p.dst):
            d["pub"] += 1
            d["resolvers"][p.dst] += 1
            name = _qname(p.payload)
            if _is_random_label(name):
                d["rnd"] += 1
                if d["ex"] is None:
                    d["ex"] = name

    def feed(self, p):
        self.n += 1
        if self.t_first is None:
            self.t_first = p.ts
        self.t_last = p.ts
        src_local, dst_local = self.es_local(p.src), self.es_local(p.dst)
        if src_local and (p.src in self.hosts or (len(self.hosts) < MAX_HOSTS and self.pres.pedir())):
            self.hosts[p.src] += 1
        if p.proto == 17:
            if src_local and not dst_local:
                key = (p.src, p.dst)
                secs = self.udp_out.get(key)
                if secs is None and len(self.udp_out) < MAX_PARES and self.pres.pedir(2):
                    secs = self.udp_out[key]
                if secs is not None:
                    b = secs[int(p.ts)]
                    b[0] += 1
                    b[1] += p.plen
                    if b[2] is None:
                        b[2] = p.ts
                    if len(secs) > MAX_SEGUNDOS:          # los segundos "fríos" nunca cuentan para una inundación
                        for k in [k for k, v in secs.items() if v[0] < self.min_pps]:
                            del secs[k]
                    dp = self.dports[key]
                    if p.dport in dp or (len(dp) < MAX_PUERTOS and self.pres.pedir()):
                        dp[p.dport] += 1
                if p.dport == 53:
                    self._dns_query(p)
            elif dst_local and not src_local:
                k = (p.dst, p.src)
                if k in self.udp_in or (len(self.udp_in) < MAX_UDP_IN and self.pres.pedir()):
                    self.udp_in[k] += 1
            elif src_local and dst_local and p.dport == 53:
                self._dns_query(p)
        elif p.proto == 6:
            if src_local and not dst_local:
                if 1 <= p.plen <= 128:
                    k = (p.src, p.dst, p.dport, p.plen)
                    e = self.small_out.get(k)
                    if e is None:
                        if len(self.small_out) < MAX_CLAVES and self.pres.pedir(2):
                            self.small_out[k] = {"ev": [p.ts], "last": p.ts}
                    else:
                        if p.ts - e["last"] > 2.0 and len(e["ev"]) < MAX_EVENTOS:   # un latido puede venir en pareja
                            e["ev"].append(p.ts)
                        e["last"] = p.ts
                if p.flags & 0x12 == 0x02:
                    self._syn(p)
            elif dst_local and not src_local and 1 <= p.plen <= 300:
                q = self.small_in.get(p.dst)
                if q is None and len(self.small_in) < MAX_HOSTS and self.pres.pedir(20):
                    q = self.small_in[p.dst] = deque(maxlen=MAX_ENTRANTES)
                if q is not None:
                    q.append((p.ts, p.src, p.sport, p.plen))

    def _syn(self, p):
        r = self.syn.get(p.src)
        if r is None:
            if len(self.syn) >= MAX_HOSTS or not self.pres.pedir(50):
                return
            r = self.syn[p.src] = {"w": int(p.ts // 10), "set": set(), "max": 0}
        w = int(p.ts // 10)
        if w != r["w"]:                                       # cambió la ventana de 10 s: se guarda el máximo
            r["max"] = max(r["max"], len(r["set"]))
            r["w"], r["set"] = w, set()
        if len(r["set"]) < MAX_VENTANA_SYN:
            r["set"].add((p.dst, p.dport))
        sp = self.syn_ports.setdefault(p.src, Counter())
        if p.dport in sp or len(sp) < 2000:
            sp[p.dport] += 1

    def resultado(self, nombre="captura", activo_s=None):
        """Devuelve el resultado actual. No modifica el estado: se puede llamar muchas veces."""
        findings = []
        device, min_pps, min_secs = self.device, self.min_pps, self.min_secs

        def want(ip):
            return device is None or ip == device

        # ---- inundaciones UDP y órdenes de control
        for (src, dst), secs in self.udp_out.items():
            if not want(src):
                continue
            hot = {s: v for s, v in secs.items() if v[0] >= min_pps}
            for ep in _episodes(hot.keys(), min_secs):
                pk = sum(hot[s][0] for s in ep if s in hot)
                by = sum(hot[s][1] for s in ep if s in hot)
                peak = max(hot[s][0] for s in ep if s in hot)
                first = min(hot[s][2] for s in ep if s in hot)
                dur = ep[-1] - ep[0] + 1
                replies = self.udp_in.get((src, dst), 0)
                ratio = replies / pk if pk else 0
                port = self.dports[(src, dst)].most_common(1)[0][0]
                if ratio >= 0.3:  # el destino responde de forma sostenida: descarga, QUIC, videollamada...
                    continue
                sev = "alta" if ratio < 0.05 else "media"
                findings.append(Finding(
                    "UDP_FLOOD", sev,
                    "Inundación UDP desde %s hacia %s:%d" % (src, dst, port),
                    "%d paquetes en ~%d s (pico %d pps, promedio %d B de datos), respuestas: %d%%."
                    % (pk, dur, peak, by // max(pk, 1), round(ratio * 100)),
                    {"src": src, "dst": dst, "dport": port, "packets": pk, "seconds": dur,
                     "peak_pps": peak, "reply_ratio": round(ratio, 3), "start_ts": first}))
                # ¿hubo una orden pequeña entrante justo antes?
                cand = [(first - t, r, rp, pl) for (t, r, rp, pl) in self.small_in.get(src, [])
                        if 0 <= first - t <= 2.0]
                if cand:
                    delay, r, rp, pl = min(cand)
                    findings.append(Finding(
                        "C2_ORDER", "alta",
                        "Orden de control %s:%d seguida de inundación a %s" % (r, rp, dst),
                        "Llegó un mensaje de %d bytes %.2f s antes de que empezara la inundación. "
                        "Un servidor de control que dispara ataques deja este patrón." % (pl, delay),
                        {"controller": r, "port": rp, "order_bytes": pl, "delay_s": round(delay, 3),
                         "victim": dst, "device": src}))

        # ---- latidos periódicos
        for (src, dst, dport, plen), e in self.small_out.items():
            if not want(src):
                continue
            ev = e["ev"]
            if len(ev) < 4:
                continue
            gaps = [b - a for a, b in zip(ev, ev[1:])]
            mean = statistics.mean(gaps)
            if mean < 2:
                continue
            cv = statistics.pstdev(gaps) / mean
            if cv < 0.2:
                findings.append(Finding(
                    "BEACON", "info" if dport in (80, 443, 8080, 8443) else "media",
                    "Latido periódico %s -> %s:%d" % (src, dst, dport),
                    "%d mensajes de %d bytes cada %.1f s (variación %.0f%%). Típico de un canal de control; "
                    "también lo hacen apps legítimas (notificaciones): confirma el destino con whois/RDAP."
                    % (len(ev), plen, mean, cv * 100),
                    {"src": src, "dst": dst, "dport": dport, "bytes": plen, "count": len(ev),
                     "interval_s": round(mean, 2), "cv": round(cv, 3)}))

        # ---- DNS
        for src, d in self.dns.items():
            if not want(src) or d["total"] < 30:
                continue
            dur = max(d["t1"] - d["t0"], 1)
            if d["rnd"] >= 30 and d["rnd"] / max(d["pub"], 1) > 0.3:
                findings.append(Finding(
                    "DNS_RANDOM", "alta",
                    "Consultas DNS con nombres aleatorios desde %s" % src,
                    "%d consultas con etiquetas largas y aleatorias (ej. %s), ~%.0f/s, directo a %s. "
                    "Se usa para sondear dominios del malware o mezclar tráfico."
                    % (d["rnd"], _show(d["ex"]), d["rnd"] / dur, ", ".join(sorted(d["resolvers"]))),
                    {"src": src, "queries": d["rnd"], "per_second": round(d["rnd"] / dur, 1),
                     "resolvers": dict(d["resolvers"])}))
            elif d["pub"] >= 0.8 * d["total"] and d["pub"] >= 100:
                findings.append(Finding(
                    "DNS_BYPASS", "info",
                    "%s ignora el DNS del router" % src,
                    "%d de %d consultas van directo a resolvers públicos (%s). No es malo por sí solo "
                    "(muchos dispositivos lo hacen) pero conviene revisarlo."
                    % (d["pub"], d["total"], ", ".join(sorted(d["resolvers"]))),
                    {"src": src, "public": d["pub"], "total": d["total"]}))

        # ---- barridos SYN
        for src, r in self.syn.items():
            if not want(src):
                continue
            worst = max(r["max"], len(r["set"]))
            if worst >= 50:
                ports = self.syn_ports[src].most_common(3)
                findings.append(Finding(
                    "SCAN", "alta",
                    "Barrido de puertos desde %s" % src,
                    "Hasta %d destinos/puertos distintos en 10 s con SYN. Puertos más usados: %s."
                    % (worst, ", ".join("%d (%d)" % x for x in ports)),
                    {"src": src, "distinct_per_10s": worst, "top_ports": ports}))

        controllers = {f.evidence["controller"] for f in findings if f.code == "C2_ORDER"}
        for f in findings:
            if f.code == "BEACON" and f.evidence["dst"] in controllers:
                f.severity = "alta"
                f.detail += " Es el MISMO servidor que dio las órdenes de ataque."

        findings.sort(key=lambda f: SEV_ORDER[f.severity])
        dur = round(self.t_last - self.t_first, 1) if self.n else 0
        return {
            "summary": {"file": nombre, "packets": self.n,
                        "duration_s": round(activo_s, 1) if activo_s is not None else dur,
                        "local_hosts": dict(self.hosts.most_common(10))},
            "verdict": "sospechoso" if any(f.severity == "alta" for f in findings) else
                       ("revisar" if any(f.severity == "media" for f in findings) else "sin indicios"),
            "findings": [f.as_dict() for f in findings],
        }


def analyze(path, min_pps=200, min_secs=5, local_nets=None, device=None):
    """Analiza uno o varios archivos de captura."""
    paths = [path] if isinstance(path, (str, bytes)) or hasattr(path, "__fspath__") else list(path)
    a = Analizador(min_pps, min_secs, local_nets, device)
    for x in paths:
        for p in read_packets(x):
            a.feed(p)
    return a.resultado(str(paths[0]) if len(paths) == 1 else "%d archivos" % len(paths))


ADVICE = (
    "Qué hacer: aísla el equipo (red de invitados o sin internet), apaga ADB/depuración, restablece de "
    "fábrica o reemplázalo por uno certificado, cambia las claves del router y vuelve a capturar para comprobar."
)


def render_text(res):
    s = res["summary"]
    lines = ["=== Análisis de %s ===" % s["file"],
             "Paquetes: %d · duración: %s s" % (s["packets"], s["duration_s"]),
             "Equipos locales más activos: " + (", ".join("%s (%d)" % kv for kv in s["local_hosts"].items()) or "-"),
             ""]
    if not res["findings"]:
        lines.append("Sin indicios en esta captura. (Una captura corta puede no contener la actividad.)")
    for f in res["findings"]:
        lines += ["[%s] %s  (%s)" % (f["severity"].upper(), f["title"], f["code"]), "    " + f["detail"]]
    lines += ["", "Veredicto: " + res["verdict"].upper()]
    if res["verdict"] != "sin indicios":
        lines.append(ADVICE)
    return "\n".join(lines)
