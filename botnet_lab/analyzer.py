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
import itertools
import math
import statistics
from collections import Counter, defaultdict

from .pcapio import read_packets

SEV_ORDER = {"alta": 0, "media": 1, "info": 2}
# Red local por defecto: RFC 1918 + link-local + CGNAT (no usar is_private: incluye rangos de documentación)
DEFAULT_LOCAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"]


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


def analyze(path, min_pps=200, min_secs=5, local_nets=None, device=None):
    paths = [path] if isinstance(path, (str, bytes)) or hasattr(path, "__fspath__") else list(path)
    nets = [ipaddress.ip_network(n) for n in (local_nets or DEFAULT_LOCAL)]
    cache = {}

    def is_local(ip):
        if ip not in cache:
            a = ipaddress.ip_address(ip)
            cache[ip] = any(a in n for n in nets)
        return cache[ip]

    n = 0
    t_first = t_last = None
    udp_out = defaultdict(lambda: defaultdict(lambda: [0, 0, None]))  # (src,dst) -> sec -> [pkts, bytes, first_ts]
    dports = defaultdict(Counter)
    udp_in = Counter()                                                # (local, remote) -> paquetes
    small_out = defaultdict(list)                                     # (src,dst,dport,plen) -> [ts]
    small_in = defaultdict(list)                                      # local -> [(ts, remote, rport, plen)]
    dns = defaultdict(list)                                           # src -> [(ts, resolver, qname)]
    syns = defaultdict(list)                                          # src -> [(ts, dst, dport)]
    hosts = Counter()

    for p in itertools.chain.from_iterable(read_packets(x) for x in paths):
        n += 1
        t_first = p.ts if t_first is None else t_first
        t_last = p.ts
        src_local, dst_local = is_local(p.src), is_local(p.dst)
        if src_local:
            hosts[p.src] += 1
        if p.proto == 17:
            if src_local and not dst_local:
                s = int(p.ts)
                b = udp_out[(p.src, p.dst)][s]
                b[0] += 1
                b[1] += p.plen
                if b[2] is None:
                    b[2] = p.ts
                dports[(p.src, p.dst)][p.dport] += 1
                if p.dport == 53:
                    dns[p.src].append((p.ts, p.dst, _qname(p.payload)))
            elif dst_local and not src_local:
                udp_in[(p.dst, p.src)] += 1
            elif src_local and dst_local and p.dport == 53:
                dns[p.src].append((p.ts, p.dst, _qname(p.payload)))
        elif p.proto == 6:
            if src_local and not dst_local:
                if 1 <= p.plen <= 128:
                    small_out[(p.src, p.dst, p.dport, p.plen)].append(p.ts)
                if p.flags & 0x12 == 0x02:
                    syns[p.src].append((p.ts, p.dst, p.dport))
            elif dst_local and not src_local and 1 <= p.plen <= 300:
                small_in[p.dst].append((p.ts, p.src, p.sport, p.plen))

    findings = []

    def want(ip):
        return device is None or ip == device

    # ---- inundaciones UDP y órdenes de control
    flood_remotes = defaultdict(set)
    for (src, dst), secs in udp_out.items():
        if not want(src):
            continue
        hot = {s: v for s, v in secs.items() if v[0] >= min_pps}
        for ep in _episodes(hot.keys(), min_secs):
            pk = sum(hot[s][0] for s in ep if s in hot)
            by = sum(hot[s][1] for s in ep if s in hot)
            peak = max(hot[s][0] for s in ep if s in hot)
            first = min(hot[s][2] for s in ep if s in hot)
            dur = ep[-1] - ep[0] + 1
            replies = udp_in.get((src, dst), 0)
            ratio = replies / pk if pk else 0
            port = dports[(src, dst)].most_common(1)[0][0]
            sev = "alta" if ratio < 0.05 else "media"
            findings.append(Finding(
                "UDP_FLOOD", sev,
                "Inundación UDP desde %s hacia %s:%d" % (src, dst, port),
                "%d paquetes en ~%d s (pico %d pps, promedio %d B de datos), respuestas: %d%%."
                % (pk, dur, peak, by // max(pk, 1), round(ratio * 100)),
                {"src": src, "dst": dst, "dport": port, "packets": pk, "seconds": dur,
                 "peak_pps": peak, "reply_ratio": round(ratio, 3), "start_ts": first}))
            flood_remotes[src].add((dst, first))
            # ¿hubo una orden pequeña entrante justo antes?
            cand = [(first - t, r, rp, pl) for (t, r, rp, pl) in small_in.get(src, [])
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
    for (src, dst, dport, plen), ts in small_out.items():
        if not want(src):
            continue
        ev = [ts[0]] if ts else []
        for prev, t in zip(ts, ts[1:]):
            if t - prev > 2.0:  # silencio de más de 2 s: empieza un latido nuevo (puede venir en pareja)
                ev.append(t)
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
    for src, q in dns.items():
        if not want(src) or len(q) < 30:
            continue
        pub = [x for x in q if not is_local(x[1])]
        dur = max(q[-1][0] - q[0][0], 1)
        rnd_q = [x for x in pub if _is_random_label(x[2])]
        resolvers = Counter(x[1] for x in pub)
        if len(rnd_q) >= 30 and len(rnd_q) / max(len(pub), 1) > 0.3:
            findings.append(Finding(
                "DNS_RANDOM", "alta",
                "Consultas DNS con nombres aleatorios desde %s" % src,
                "%d consultas con etiquetas largas y aleatorias (ej. %s), ~%.0f/s, directo a %s. "
                "Se usa para sondear dominios del malware o mezclar tráfico."
                % (len(rnd_q), _show(rnd_q[0][2]), len(rnd_q) / dur, ", ".join(sorted(resolvers))),
                {"src": src, "queries": len(rnd_q), "per_second": round(len(rnd_q) / dur, 1),
                 "resolvers": dict(resolvers)}))
        elif len(pub) >= 0.8 * len(q) and len(pub) >= 100:
            findings.append(Finding(
                "DNS_BYPASS", "info",
                "%s ignora el DNS del router" % src,
                "%d de %d consultas van directo a resolvers públicos (%s). No es malo por sí solo "
                "(muchos aparatos lo hacen) pero conviene revisarlo."
                % (len(pub), len(q), ", ".join(sorted(resolvers))),
                {"src": src, "public": len(pub), "total": len(q)}))

    # ---- barridos SYN
    for src, ev in syns.items():
        if not want(src):
            continue
        win = defaultdict(set)
        for t, d, p in ev:
            win[int(t // 10)].add((d, p))
        worst = max((len(v) for v in win.values()), default=0)
        if worst >= 50:
            ports = Counter(p for _, _, p in ev).most_common(3)
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
    return {
        "summary": {"file": str(paths[0]) if len(paths) == 1 else "%d archivos" % len(paths), "packets": n,
                    "duration_s": round((t_last - t_first), 1) if n else 0,
                    "local_hosts": dict(hosts.most_common(10))},
        "verdict": "sospechoso" if any(f.severity == "alta" for f in findings) else
                   ("revisar" if any(f.severity == "media" for f in findings) else "sin indicios"),
        "findings": [f.as_dict() for f in findings],
    }


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
