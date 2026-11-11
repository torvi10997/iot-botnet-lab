"""Modo visita: asistente para que un técnico revise un dispositivo en casa del cliente."""
import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

from .analyzer import analyze
from .informe import render_html, resumen_consola, semaforo
from .pcapio import read_packets

SEGMENTO_S = 20
MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)

PASOS = """
PASOS ANTES DE EMPEZAR (en la laptop del técnico)
  1. Que la laptop tenga internet por CABLE (Ethernet).
  2. Windows: Configuración > Red e Internet > Zona con cobertura inalámbrica móvil.
     Banda 2,4 GHz, nombre y clave sencillos. Activarla.
  3. Conectar el dispositivo (TV box, cámara...) a ese WiFi y comprobar que tiene IP.
  4. Avisar al cliente: se observará SOLO el tráfico de ese dispositivo y la captura se borra al terminar.
  5. Dejar el dispositivo encendido y EN USO (por ejemplo, reproduciendo video).
"""


def buscar_tshark():
    for c in (shutil.which("tshark"), r"C:\Program Files\Wireshark\tshark.exe",
              r"C:\Program Files (x86)\Wireshark\tshark.exe", "/usr/bin/tshark"):
        if c and os.path.exists(c):
            return c
    return None


def listar_interfaces(tshark):
    out = subprocess.run([tshark, "-D"], capture_output=True, text=True, errors="replace").stdout
    res = []
    for line in out.splitlines():
        m = re.match(r"^\d+\.\s+(\S+)\s*(?:\((.*)\))?", line.strip())
        if m:
            res.append((m.group(1), m.group(2) or m.group(1)))
    return res


def interfaz_hotspot(interfaces):
    """Intenta reconocer el adaptador del hotspot de Windows (IP 192.168.137.1)."""
    if os.name != "nt":
        return None
    ps = ("(Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.168.137.1' | "
          "ForEach-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).InterfaceGuid })")
    try:
        g = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True,
                           text=True, timeout=20).stdout.strip().lower()
    except Exception:
        return None
    if not g:
        return None
    for ident, desc in interfaces:
        if g in ident.lower():
            return ident
    return None


def _preguntar(texto, defecto=None):
    try:
        r = input("%s%s: " % (texto, " [%s]" % defecto if defecto else "")).strip()
    except EOFError:
        r = ""
    return r or (defecto or "")


def capturar(tshark, interfaz, mac, minutos, carpeta):
    """Captura en segmentos de 20 s. Corta antes si ve un ataque en curso."""
    total = max(1, int(minutos * 60 / SEGMENTO_S))
    archivos = []
    filtro = ["-f", "ether host " + mac.replace("-", ":")] if mac else []
    print("\nCapturando %.0f minuto(s). Ctrl+C para terminar antes.\n" % minutos)
    try:
        for i in range(total):
            f = os.path.join(carpeta, "seg_%03d.pcap" % i)
            subprocess.run([tshark, "-q", "-i", interfaz, "-s", "200", "-F", "pcap", "-w", f,
                            "-a", "duration:%d" % SEGMENTO_S] + filtro,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not os.path.exists(f):
                print("\nNo se pudo capturar. ¿Ejecutaste como administrador / tienes permisos de captura?")
                break
            archivos.append(f)
            n = sum(1 for _ in read_packets(f))
            print("  %2d/%d  %3d s transcurridos · %6d paquetes en este tramo" %
                  (i + 1, total, (i + 1) * SEGMENTO_S, n))
            if n and any(x["code"] == "UDP_FLOOD" and x["severity"] == "alta"
                         for x in analyze(f, min_secs=3)["findings"]):
                print("\n!! Se detectó un ataque en curso. Se detiene la captura: DESCONECTA el dispositivo "
                      "de internet ahora.")
                break
    except KeyboardInterrupt:
        print("\nCaptura detenida por el técnico.")
    return archivos


def ejecutar(args):
    carpeta_tmp = None
    if args.desde_captura:
        archivos, guardar = list(args.desde_captura), True
    else:
        tshark = buscar_tshark()
        if not tshark:
            print("No encuentro tshark. Instala Wireshark (https://www.wireshark.org) y marca "
                  "'TShark' durante la instalación.")
            return 1
        if not args.sin_preguntas:
            print(PASOS)
            _preguntar("Cuando esté listo, pulsa Enter")
        interfaces = listar_interfaces(tshark)
        interfaz = args.interfaz
        if not interfaz:
            sugerida = interfaz_hotspot(interfaces)
            if sugerida:
                desc = dict(interfaces).get(sugerida, sugerida)
                print("\nDetecté el hotspot de Windows: %s" % desc)
                interfaz = sugerida
            else:
                print("\nInterfaces disponibles:")
                for i, (ident, desc) in enumerate(interfaces, 1):
                    print("  %2d. %s" % (i, desc))
                n = _preguntar("Número de la interfaz donde está conectado el dispositivo")
                if not n.isdigit() or not 1 <= int(n) <= len(interfaces):
                    print("Interfaz no válida.")
                    return 1
                interfaz = interfaces[int(n) - 1][0]
        mac = args.mac
        if mac is None and not args.sin_preguntas:
            mac = _preguntar("MAC del dispositivo (opcional, Enter para capturar todo)")
        if mac and not MAC_RE.match(mac):
            print("La MAC debe verse así: aa:bb:cc:dd:ee:ff")
            return 1
        carpeta_tmp = tempfile.mkdtemp(prefix="visita_")
        archivos = capturar(tshark, interfaz, mac, args.minutos, carpeta_tmp)
        guardar = args.guardar
        if not archivos:
            shutil.rmtree(carpeta_tmp, ignore_errors=True)
            return 1

    res = analyze(archivos, local_nets=args.local_net)
    print(resumen_consola(res))

    os.makedirs(args.salida, exist_ok=True)
    nombre = os.path.join(args.salida, "informe_%s.html" % datetime.datetime.now().strftime("%Y%m%d_%H%M"))
    with open(nombre, "w", encoding="utf8") as f:
        f.write(render_html(res, ref=args.referencia or "", tecnico=args.tecnico or "",
                            capturado=not (guardar or args.desde_captura)))
    print("\nInforme para el cliente: %s" % os.path.abspath(nombre))

    if carpeta_tmp:
        if guardar:
            print("Capturas guardadas en: %s" % carpeta_tmp)
        else:
            shutil.rmtree(carpeta_tmp, ignore_errors=True)
            print("La captura se borró (usa --guardar para conservarla como evidencia).")
    return 2 if semaforo(res) == "rojo" else 0
