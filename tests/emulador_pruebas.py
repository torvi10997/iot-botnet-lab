"""Utilería SOLO PARA PRUEBAS: genera una captura SINTÉTICA de un dispositivo IoT infectado.

No es parte de la herramienta. No envía ni recibe nada por la red: solo escribe un archivo .pcap. Usa direcciones
de documentación (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), así que
ningún destino es real. Sirve para practicar la detección y para probar reglas.
"""
import random
import struct

from botnet_lab.pcapio import _csum, frame, tcp_segment, udp_segment, write_pcap

DEV_IP, GW_IP = "192.168.137.50", "192.168.137.1"
DEV_MAC, GW_MAC = bytes.fromhex("02aabbcc0050"), bytes.fromhex("02aabbcc0001")
C2_IP, C2_PORT = "198.51.100.10", 6969
SERVER_IP = "203.0.113.80"
RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]
# (IP, puerto, bytes por paquete): tipos de objetivo que vimos en el caso real
TARGETS = [("203.0.113.20", 19132, 1190), ("203.0.113.30", 30002, 67), ("203.0.113.40", 80, 900)]
SYN, ACK, PSH = 0x02, 0x10, 0x08
BASE_TS = 1700000000.0
SYN_ACK = 0x12
SYN_TARGET, SYN_PORT = "203.0.113.50", 80
ICMP_TARGET = "203.0.113.60"


def icmp_segment(tipo, payload=b"", ident=1, seq=0):
    """Mensaje ICMP: tipo 8 = eco (ping), 0 = respuesta de eco."""
    cab = struct.pack("!BBHHH", tipo, 0, 0, ident, seq)
    return struct.pack("!BBH", tipo, 0, _csum(cab + payload)) + cab[4:] + payload


def _dns_query(name, txid):
    lab = name if isinstance(name, bytes) else name.encode()
    q = b"".join(bytes([len(l)]) + l for l in lab.split(b".") if l) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def build(infected=True, duration=120, flood_pps=600, flood_secs=15, dns_rate=25,
          beacon_every=10, scan=False, seed=7, quic=False, syn_flood=False, icmp_flood=False,
          flood_replies=False, icmp_pps=None, lan_scan=0, lan_port=5555, lan_open=0):
    """Devuelve la lista de (timestamp, frame) del escenario."""
    rnd = random.Random(seed)
    blob = rnd.getrandbits(8 * 1500).to_bytes(1500, "big")
    frames = []

    def out(t, ip, proto, l4):
        frames.append((BASE_TS + t, frame(DEV_MAC, GW_MAC, DEV_IP, ip, proto, l4)))

    def inn(t, ip, proto, l4):
        frames.append((BASE_TS + t, frame(GW_MAC, DEV_MAC, ip, DEV_IP, proto, l4)))

    # --- tráfico normal: DNS al router y una sesión HTTPS
    names = ["www.example.com", "cdn.example.net", "api.example.org", "video.example.com"]
    t = 0.3
    while t < duration:
        q = _dns_query(rnd.choice(names), rnd.getrandbits(16))
        out(t, GW_IP, 17, udp_segment(DEV_IP, GW_IP, 40000 + rnd.randrange(2000), 53, q))
        inn(t + 0.02, GW_IP, 17, udp_segment(GW_IP, DEV_IP, 53, 40000, q + b"\0" * 16))
        t += rnd.uniform(0.8, 2.5)
    t = 0.1
    while t < duration:
        out(t, SERVER_IP, 6, tcp_segment(DEV_IP, SERVER_IP, 50123, 443, ACK | PSH, blob[:100]))
        inn(t + 0.03, SERVER_IP, 6, tcp_segment(SERVER_IP, DEV_IP, 443, 50123, ACK | PSH, blob[:1200]))
        t += rnd.uniform(0.3, 0.8)

    if infected:
        # --- DNS de nombres aleatorios directo a resolvers públicos (sin usar el router)
        for k in range(int(duration * dns_rate)):
            tt = k / dns_rate + rnd.uniform(0, 0.02)
            name = bytes(rnd.choice([c for c in range(1, 256) if c != 0x2E]) for _ in range(20))  # 20 bytes binarios, como el caso real
            r = RESOLVERS[k % len(RESOLVERS)]
            out(tt, r, 17, udp_segment(DEV_IP, r, 30000 + rnd.randrange(9000), 53,
                                       _dns_query(name, rnd.getrandbits(16))))
        # --- canal de control: latido de 33 bytes y respuesta vacía
        tt = 2.0
        while tt < duration:
            for dt in (0.0, 0.6):  # el latido se manda en pareja
                out(tt + dt, C2_IP, 6, tcp_segment(DEV_IP, C2_IP, 51000, C2_PORT, ACK | PSH, blob[:33]))
                inn(tt + dt + 0.05, C2_IP, 6, tcp_segment(C2_IP, DEV_IP, C2_PORT, 51000, ACK))
            # mensajes de otros tamaños mezclados, que no deben confundir al detector
            if rnd.random() < 0.3:  # irregular, como en el caso real
                out(tt + rnd.uniform(2.5, beacon_every - 1), C2_IP, 6,
                    tcp_segment(DEV_IP, C2_IP, 51000, C2_PORT, ACK | PSH, blob[:38]))
            tt += beacon_every
        # --- órdenes (54-57 bytes) seguidas de una inundación UDP sin respuesta
        for i, (ip, port, size) in enumerate(TARGETS):
            t_order = duration * (i + 1) / (len(TARGETS) + 1)
            if t_order + flood_secs >= duration:
                continue
            inn(t_order, C2_IP, 6, tcp_segment(C2_IP, DEV_IP, C2_PORT, 51000, ACK | PSH,
                                               blob[:54 + i], seq=100 + i))
            out(t_order + 0.01, C2_IP, 6, tcp_segment(DEV_IP, C2_IP, 51000, C2_PORT, ACK))
            start = t_order + 0.25
            for k in range(int(flood_secs * flood_pps)):
                tf = start + k / flood_pps + rnd.uniform(0, 0.0005)
                off = rnd.randrange(0, 1500 - size)
                out(tf, ip, 17, udp_segment(DEV_IP, ip, 40000 + rnd.randrange(20000), port,
                                            blob[off:off + size]))
        # --- barrido SYN opcional (puerto 22 en muchas direcciones)
        if scan:
            t0 = duration * 0.9
            for k in range(300):
                dst = "192.0.2.%d" % (1 + k % 250)
                out(t0 + k / 30.0, dst, 6, tcp_segment(DEV_IP, dst, 41000 + k, 22, SYN, seq=k))
    if quic:  # descarga de video por QUIC: mucho más entrante (1200 B) que saliente (ACK de 50 B)
        qs = "198.51.100.200"
        for start in (duration * 0.2, duration * 0.6):
            for k in range(int(20 * 600)):
                tq = start + k / 600.0
                inn(tq, qs, 17, udp_segment(qs, DEV_IP, 443, 52000, blob[:1200]))
                if k % 3 == 0:
                    out(tq + 0.0005, qs, 17, udp_segment(DEV_IP, qs, 52000, 443, blob[:50]))
    # --- inundaciones TCP (SYN) e ICMP, cada una precedida por una orden del servidor de control
    def orden(t_order, n):
        inn(t_order, C2_IP, 6, tcp_segment(C2_IP, DEV_IP, C2_PORT, 51000, ACK | PSH, blob[:55], seq=500 + n))
        out(t_order + 0.01, C2_IP, 6, tcp_segment(DEV_IP, C2_IP, 51000, C2_PORT, ACK))

    if syn_flood:
        t_order = duration * 0.3
        orden(t_order, 1)
        for k in range(int(flood_secs * flood_pps)):
            tf = t_order + 0.25 + k / flood_pps
            sport = 20000 + k % 40000
            out(tf, SYN_TARGET, 6, tcp_segment(DEV_IP, SYN_TARGET, sport, SYN_PORT, SYN, seq=k))
            if flood_replies:                    # el servidor acepta cada conexión (carga normal, no ataque)
                inn(tf + 0.001, SYN_TARGET, 6, tcp_segment(SYN_TARGET, DEV_IP, SYN_PORT, sport, SYN_ACK, seq=k))
    if icmp_flood:
        t_order = duration * 0.6
        orden(t_order, 2)
        pps = icmp_pps or flood_pps
        for k in range(int(flood_secs * pps)):
            tf = t_order + 0.25 + k / pps
            out(tf, ICMP_TARGET, 1, icmp_segment(8, blob[:56], seq=k))
            if flood_replies:
                inn(tf + 0.001, ICMP_TARGET, 1, icmp_segment(0, blob[:56], seq=k))
    if lan_scan:                                  # sondeo de la red local: SYN al mismo puerto de `lan_scan` equipos vecinos
        base = DEV_IP.rsplit(".", 1)[0]
        t0 = duration * 0.4
        for k in range(lan_scan):
            ip = "%s.%d" % (base, 100 + k)
            tt = t0 + k / 20.0
            out(tt, ip, 6, tcp_segment(DEV_IP, ip, 42000 + k, lan_port, SYN, seq=k))
            if k < lan_open:                          # algunos equipos tienen el puerto abierto y contestan
                inn(tt + 0.002, ip, 6, tcp_segment(ip, DEV_IP, lan_port, 42000 + k, SYN_ACK, seq=k))
    return frames


def generate(path, **kw):
    frames = build(**kw)
    write_pcap(path, frames)
    return len(frames)
