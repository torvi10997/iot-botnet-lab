"""Informe de visita: semáforo y texto en lenguaje simple para el cliente (HTML imprimible)."""
import datetime
import html

MIN_VERDE_S = 600      # menos de 10 min sin indicios NO se declara verde
MIN_PAQUETES = 200     # menos tráfico que esto: el aparato casi no habló (¿MAC o interfaz equivocada?)

SEMAFORO = {
    "rojo": ("ROJO", "Se encontraron señales claras de un aparato comprometido",
             "#b3201f", "#fbe9e8"),
    "amarillo": ("AMARILLO", "Hay señales que conviene revisar",
                 "#8a5a00", "#fdf3d8"),
    "verde": ("VERDE", "No se vieron señales durante la captura",
              "#1d6b3a", "#e6f4ea"),
    "corto": ("NO CONCLUYENTE", "La captura fue demasiado corta para opinar",
              "#52514e", "#eceae4"),
    "sin_datos": ("NO CONCLUYENTE", "El aparato casi no generó tráfico",
                  "#52514e", "#eceae4"),
}

ACCIONES = {
    "rojo": [
        "Desconectar el aparato de internet y de la red de la casa ahora.",
        "No usarlo para entrar a cuentas, bancos ni compras mientras siga conectado.",
        "Reemplazarlo por un equipo certificado (Google TV, Fire TV, Apple TV). Restablecerlo de fábrica "
        "no garantiza que quede limpio.",
        "Cambiar la clave del WiFi y la del router; apagar la depuración ADB si existe.",
        "Revisar los demás aparatos de la casa (teléfonos, otras cajas, cámaras).",
        "Si el aparato sigue conectado, el operador puede limitar el servicio para proteger a otros clientes.",
    ],
    "amarillo": [
        "Repetir la revisión con una captura más larga (15 minutos o más) y con el aparato en uso.",
        "Confirmar a quién pertenecen los destinos señalados en el detalle técnico.",
        "Mientras tanto, mantener el firmware actualizado y apagar la depuración ADB.",
    ],
    "verde": [
        "No es una garantía: un aparato infectado puede estar callado durante un rato.",
        "Mantener el firmware actualizado y apagar la depuración ADB.",
        "Preferir equipos certificados; los genéricos baratos son los que más vienen comprometidos.",
        "Si más adelante notan lentitud sin explicación o avisos del operador, repetir la revisión.",
    ],
    "corto": [
        "Repetir la captura durante al menos 10 minutos, con el aparato encendido y en uso (por ejemplo, "
        "reproduciendo video).",
    ],
    "sin_datos": [
        "Verificar que el aparato esté conectado al punto de acceso de la laptop y que la MAC y la interfaz "
        "elegidas sean las correctas.",
        "Repetir la captura con el aparato en uso.",
    ],
}


def semaforo(res):
    sev = {f["severity"] for f in res["findings"]}
    s = res["summary"]
    if "alta" in sev:
        return "rojo"
    if "media" in sev:
        return "amarillo"
    if sum(s["local_hosts"].values()) < MIN_PAQUETES:
        return "sin_datos"
    if s["duration_s"] < MIN_VERDE_S:
        return "corto"
    return "verde"


def explicar(f):
    """Frase en lenguaje simple para un hallazgo."""
    e, c = f["evidence"], f["code"]
    if c == "UDP_FLOOD":
        if e["reply_ratio"] < 0.05:
            return ("El aparato envió %d paquetes en unos %d segundos hacia el servidor externo %s, sin recibir "
                    "respuesta. Eso es lo que hace un equipo usado para atacar a otros." %
                    (e["packets"], e["seconds"], e["dst"]))
        return ("El aparato envió %d paquetes en unos %d segundos hacia el servidor externo %s y recibió muy "
                "pocas respuestas (%d%% de lo enviado). Puede ser un ataque, pero también tráfico legítimo muy "
                "intenso: conviene confirmarlo." %
                (e["packets"], e["seconds"], e["dst"], round(e["reply_ratio"] * 100)))
    if c == "C2_ORDER":
        return ("Justo antes de atacar, el aparato recibió un mensaje de %d bytes de %s. Indica que un servidor "
                "remoto le dio la orden." % (e["order_bytes"], e["controller"]))
    if c == "BEACON":
        return ("Mantiene un contacto muy regular (cada %.0f segundos) con %s, puerto %d. Los equipos "
                "controlados a distancia hacen esto para avisar que siguen activos." %
                (e["interval_s"], e["dst"], e["dport"]))
    if c == "DNS_RANDOM":
        return ("Hace unas %.0f consultas por segundo con nombres sin sentido a servidores públicos, "
                "ignorando el DNS del router." % e["per_second"])
    if c == "SCAN":
        return ("Está probando puertos de muchas direcciones distintas, como buscando otros equipos "
                "para infectar.")
    if c == "DNS_BYPASS":
        return "Ignora el DNS del router y usa servidores públicos. Por sí solo no es grave."
    return f["title"]


def frases(findings):
    """Una frase por tipo de hallazgo (varias inundaciones u órdenes se resumen juntas)."""
    out, por = [], {}
    for f in findings:
        por.setdefault(f["code"], []).append(f)
    for code in ("UDP_FLOOD", "C2_ORDER", "BEACON", "DNS_RANDOM", "SCAN", "DNS_BYPASS"):
        g = por.get(code)
        if not g:
            continue
        sev = max(g, key=lambda f: 0 if f["severity"] == "alta" else 1)["severity"]
        if len(g) == 1:
            out.append((sev, explicar(g[0])))
        elif code == "UDP_FLOOD" and any(f["evidence"]["reply_ratio"] >= 0.05 for f in g):
            out.append((sev, "El aparato lanzó %d ráfagas de tráfico UDP con pocas respuestas. Puede ser un ataque "
                        "o tráfico legítimo muy intenso: conviene confirmarlo en el detalle técnico." % len(g)))
        elif code == "UDP_FLOOD":
            pk = sum(f["evidence"]["packets"] for f in g)
            dst = sorted({f["evidence"]["dst"] for f in g})
            out.append((sev, "El aparato lanzó %d ráfagas de tráfico (%d paquetes en total) hacia %d servidores "
                        "externos (%s), sin recibir respuesta. Eso es lo que hace un equipo usado para atacar a otros."
                        % (len(g), pk, len(dst), ", ".join(dst))))
        elif code == "C2_ORDER":
            ctl = sorted({f["evidence"]["controller"] for f in g})
            out.append((sev, "Antes de cada ráfaga recibió un mensaje corto de %s (%d veces). Indica que un "
                        "servidor remoto le daba las órdenes." % (", ".join(ctl), len(g))))
        else:
            out.append((sev, explicar(g[0])))
    return out


def _dur(s):
    m, sec = divmod(int(s), 60)
    return "%d min %02d s" % (m, sec)


def render_html(res, ref="", tecnico="", fecha=None, capturado=True):
    fecha = fecha or datetime.datetime.now().strftime("%d/%m/%Y %H:%M")
    esc = html.escape
    color = semaforo(res)
    etiqueta, titulo, fg, bg = SEMAFORO[color]
    s = res["summary"]
    reales = [f for f in res["findings"] if f["severity"] != "info"]
    notas = [f for f in res["findings"] if f["severity"] == "info"]
    fr = frases(res["findings"])
    hall = "".join("<li>%s</li>" % esc(t) for sv, t in fr if sv != "info") or "<li>Ninguno.</li>"
    nota = "".join("<li>%s</li>" % esc(t) for sv, t in fr if sv == "info")
    acc = "".join("<li>%s</li>" % esc(a) for a in ACCIONES[color])
    tec = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" %
        (esc(f["severity"].upper()), esc(f["code"]), esc(f["title"] + ". " + f["detail"]))
        for f in res["findings"]) or '<tr><td colspan="3">Sin hallazgos.</td></tr>'
    hosts = ", ".join("%s (%d)" % kv for kv in s["local_hosts"].items()) or "-"
    return """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de revisión de red</title>
<style>
 body{font-family:"Segoe UI",Arial,sans-serif;color:#0b0b0b;background:#fcfcfb;max-width:800px;margin:0 auto;padding:24px 16px;line-height:1.45}
 h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:26px 0 8px}
 .meta{color:#52514e;font-size:14px}
 .sem{border:3px solid %(fg)s;background:%(bg)s;border-radius:14px;padding:16px 20px;margin:18px 0;display:flex;gap:16px;align-items:center}
 .dot{flex:0 0 46px;width:46px;height:46px;border-radius:50%%;background:%(fg)s}
 .sem b{display:block;font-size:22px;color:%(fg)s;letter-spacing:.04em} .sem span{font-size:17px}
 ul{padding-left:20px} li{margin:5px 0}
 table{border-collapse:collapse;width:100%%;font-size:13px} td,th{border:1px solid #dcdad3;padding:6px 8px;text-align:left;vertical-align:top}
 th{background:#f3f2ee} .lim{background:#f3f2ee;border-radius:10px;padding:10px 14px;font-size:14px;color:#52514e}
 @media (prefers-color-scheme:dark){body{background:#161615;color:#f1f0ec}.meta,.lim{color:#b9b7b0}.lim,th{background:#23231f}td,th{border-color:#3a3934}}
 @media print{body{background:#fff;color:#000}}
</style></head><body>
<h1>Informe de revisión de red</h1>
<div class="meta">Fecha: %(fecha)s%(ref)s%(tec)s</div>
<div class="sem"><div class="dot" aria-hidden="true"></div><div><b>%(etq)s</b><span>%(titulo)s</span></div></div>

<h2>Qué se encontró</h2>
<ul>%(hall)s</ul>
%(nota)s
<h2>Qué hacer</h2>
<ul>%(acc)s</ul>

<h2>Qué se hizo</h2>
<p>Se observó el tráfico del aparato durante <b>%(dur)s</b> (%(pk)d paquetes en total). %(cap)s</p>
<p class="lim"><b>Límites:</b> esta revisión no es un antivirus. Un aparato infectado puede permanecer callado
durante la captura; por eso un resultado verde significa solo "no se vieron señales en este tiempo".</p>

<h2>Detalle técnico (para el técnico)</h2>
<p class="meta">Equipos locales vistos: %(hosts)s</p>
<table><tr><th>Nivel</th><th>Código</th><th>Descripción</th></tr>%(tec_rows)s</table>
</body></html>""" % {
        "fg": fg, "bg": bg, "fecha": esc(fecha),
        "ref": (" · Referencia: " + esc(ref)) if ref else "",
        "tec": (" · Técnico: " + esc(tecnico)) if tecnico else "",
        "etq": esc(etiqueta), "titulo": esc(titulo), "hall": hall,
        "nota": ("<p class='meta'>Notas:</p><ul>%s</ul>" % nota) if nota else "",
        "acc": acc, "dur": _dur(s["duration_s"]), "pk": s["packets"],
        "cap": "La captura se borró al terminar." if capturado else "",
        "hosts": esc(hosts), "tec_rows": tec}


def resumen_consola(res):
    color = semaforo(res)
    etiqueta, titulo, _, _ = SEMAFORO[color]
    lineas = ["", "=" * 60, "  RESULTADO: %s - %s" % (etiqueta, titulo), "=" * 60]
    for sv, t in frases(res["findings"]):
        if sv != "info":
            lineas.append("  - " + t)
    lineas.append("")
    lineas += ["  Qué hacer:"] + ["   * " + a for a in ACCIONES[color]]
    return "\n".join(lineas)
