"""Lectura y escritura mínima de pcap / pcapng (solo biblioteca estándar).

Soporta Ethernet (1), Linux cooked (113) e IP crudo (101), solo IPv4 con TCP/UDP.
"""
import socket
import struct

ETH_P_IP = 0x0800


class Packet:
    __slots__ = ("ts", "src", "dst", "proto", "sport", "dport", "flags",
                 "plen", "payload", "wire_len")

    def __init__(self, ts, src, dst, proto, sport, dport, flags, plen, payload, wire_len):
        self.ts, self.src, self.dst, self.proto = ts, src, dst, proto
        self.sport, self.dport, self.flags = sport, dport, flags
        self.plen, self.payload, self.wire_len = plen, payload, wire_len


# ----------------------------------------------------------------- lectura
def _iter_pcap(f):
    h = f.read(24)
    if len(h) < 24:
        raise ValueError("archivo pcap incompleto")
    magic = h[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        raise ValueError("no es un archivo pcap/pcapng")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    link = struct.unpack(e + "I", h[20:24])[0]
    div = 1e9 if nano else 1e6
    while True:
        r = f.read(16)
        if len(r) < 16:
            return
        s, us, cap, orig = struct.unpack(e + "IIII", r)
        data = f.read(cap)
        if len(data) < cap:
            return
        yield s + us / div, link, data, orig


def _iter_pcapng(f):
    e = "<"
    ifaces = []
    while True:
        hdr = f.read(8)
        if len(hdr) < 8:
            return
        if hdr[:4] == b"\x0a\x0d\x0d\x0a":  # Section Header Block
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", hdr[4:8])[0]
            f.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack(e + "II", hdr)
        body = f.read(blen - 8)
        if len(body) < blen - 8:
            return
        body = body[:-4]
        if btype == 1:  # Interface Description Block
            link = struct.unpack(e + "H", body[:2])[0]
            div = 1e6
            opts, i = body[8:], 0
            while i + 4 <= len(opts):
                code, ln = struct.unpack(e + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and ln >= 1:
                    v = opts[i + 4]
                    div = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                i += 4 + ((ln + 3) & ~3)
            ifaces.append((link, div))
        elif btype == 6:  # Enhanced Packet Block
            iface, th, tl, cap, orig = struct.unpack(e + "IIIII", body[:20])
            link, div = ifaces[iface] if iface < len(ifaces) else (1, 1e6)
            yield ((th << 32) | tl) / div, link, body[20:20 + cap], orig


def _parse(ts, link, data, orig):
    if link == 1:
        if len(data) < 14:
            return None
        et = struct.unpack("!H", data[12:14])[0]
        off = 14
        while et in (0x8100, 0x88A8) and len(data) >= off + 4:
            et = struct.unpack("!H", data[off + 2:off + 4])[0]
            off += 4
        if et != ETH_P_IP:
            return None
    elif link == 113:
        if len(data) < 16 or struct.unpack("!H", data[14:16])[0] != ETH_P_IP:
            return None
        off = 16
    elif link == 101:
        off = 0
    else:
        return None
    ip = data[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:  # fragmento no inicial
        return None
    proto = ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    l4 = ip[ihl:]
    if proto == 17 and len(l4) >= 8:
        sport, dport = struct.unpack("!HH", l4[:4])
        return Packet(ts, src, dst, 17, sport, dport, 0,
                      max(total - ihl - 8, 0), l4[8:], orig)
    if proto == 6 and len(l4) >= 20:
        sport, dport = struct.unpack("!HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return Packet(ts, src, dst, 6, sport, dport, l4[13],
                      max(total - ihl - doff, 0), l4[doff:], orig)
    return Packet(ts, src, dst, proto, 0, 0, 0, 0, b"", orig)


def read_packets(path):
    """Genera objetos Packet de un archivo pcap o pcapng."""
    with open(path, "rb") as f:
        magic = f.read(4)
        f.seek(0)
        it = _iter_pcapng(f) if magic == b"\x0a\x0d\x0d\x0a" else _iter_pcap(f)
        for ts, link, data, orig in it:
            p = _parse(ts, link, data, orig)
            if p is not None:
                yield p


# --------------------------------------------------------------- escritura
def _csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _pseudo(src, dst, proto, ln):
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, ln)


def udp_segment(src, dst, sport, dport, payload):
    ln = 8 + len(payload)
    c = _csum(_pseudo(src, dst, 17, ln) + struct.pack("!HHHH", sport, dport, ln, 0) + payload)
    return struct.pack("!HHHH", sport, dport, ln, c or 0xFFFF) + payload


def tcp_segment(src, dst, sport, dport, flags, payload=b"", seq=1, ack=1):
    h = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    c = _csum(_pseudo(src, dst, 6, 20 + len(payload)) + h + payload)
    return h[:16] + struct.pack("!H", c) + h[18:] + payload


def frame(src_mac, dst_mac, src, dst, proto, l4):
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(l4), 0, 0x4000, 64, proto, 0)
    ip += socket.inet_aton(src) + socket.inet_aton(dst)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    return dst_mac + src_mac + struct.pack("!H", ETH_P_IP) + ip + l4


def write_pcap(path, frames, snaplen=200):
    """frames: lista de (ts, bytes). Se guarda truncado a `snaplen`, como tshark -s 200."""
    frames = sorted(frames, key=lambda x: x[0])
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for ts, data in frames:
            s = int(ts)
            us = int(round((ts - s) * 1e6))
            if us >= 1000000:
                s, us = s + 1, us - 1000000
            cap = data[:snaplen]
            f.write(struct.pack("<IIII", s, us, len(cap), len(data)) + cap)
