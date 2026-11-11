"""Diagnóstico de requisitos: ¿está todo listo para capturar? Si no, qué falta y cómo arreglarlo.

`recoger()` consulta el sistema (tshark, PowerShell). `evaluar()` es pura: recibe esos datos y devuelve la lista
de comprobaciones, así se puede probar sin Windows y sin permisos.
"""
import os
import re
import subprocess
import sys
import tempfile

URL_NPCAP = "https://npcap.com/#download"
WINGET_WIRESHARK = ("winget install --id WiresharkFoundation.Wireshark -e --source winget --interactive "
                    "--accept-source-agreements --accept-package-agreements")

_PS = r"""
$o = [ordered]@{}
try { $o.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
try { $o.servicios = ((Get-Service -Name npcap,npf -ErrorAction SilentlyContinue | ForEach-Object { "$($_.Name)=$($_.Status)" }) -join ",") } catch {}
foreach ($n in 'npcap','npf') { try { $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$n\Parameters" -ErrorAction Stop).AdminOnly; if ($null -ne $v) { $o.adminonly = "$v" } } catch {} }
try {
  Add-Type -AssemblyName System.Runtime.WindowsRuntime
  $null = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
  $null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
  $p = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
  if ($null -eq $p) { $o.sin_internet = "1" } else {
    $o.tipo = "$($p.NetworkAdapter.IanaInterfaceType)"
    $m = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($p)
    $c = $m.GetCurrentAccessPointConfiguration()
    $o.estado = "$($m.TetheringOperationalState)"; $o.banda = "$($c.Band)"; $o.ssid = "$($c.Ssid)"; $o.clientes = "$($m.ClientCount)"
  }
} catch { $o.hotspot_error = $_.Exception.Message }
$o.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
"""

_NO_REALES = ("USBPcap", "ciscodump", "etwdump", "randpkt", "sshdump", "udpdump", "wifidump", "dpauxmon",
              "androiddump", "Loopback")


def recoger(tshark, interfaces, edge=None):
    """Reúne los datos del sistema. Nunca lanza: lo que no se pueda leer queda vacío."""
    d = {"os": os.name, "python": "%d.%d.%d" % sys.version_info[:3], "tshark": tshark, "tshark_v": "",
         "interfaces": interfaces or [], "ps": {}, "edge": edge}
    if tshark:
        try:
            d["tshark_v"] = subprocess.run([tshark, "-v"], capture_output=True, text=True, errors="replace",
                                           timeout=20).stdout
        except Exception:
            pass
    if os.name == "nt":
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command", _PS], capture_output=True, text=True,
                                 errors="replace", timeout=30).stdout
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    d["ps"][k.strip()] = v.strip()
        except Exception:
            pass
    return d


def _c(id_, titulo, estado, detalle, solucion="", accion=None, boton=None):
    return {"id": id_, "titulo": titulo, "estado": estado, "detalle": detalle, "solucion": solucion,
            "accion": accion, "boton": boton}


def evaluar(d):
    """estado: 'ok' | 'aviso' | 'error' | 'pendiente'"""
    r, ps = [], d.get("ps", {})
    es_win = d.get("os") == "nt"
    admin = ps.get("admin", "").lower() == "true"

    r.append(_c("python", "Python", "ok", "Versión %s." % d.get("python", "?")))

    # --- Wireshark / TShark
    ts = d.get("tshark")
    if ts:
        m = re.search(r"TShark \(Wireshark\) ([\d.]+)", d.get("tshark_v", ""))
        r.append(_c("tshark", "Wireshark (TShark)", "ok",
                    "Instalado%s." % (", versión " + m.group(1) if m else "")))
    else:
        r.append(_c("tshark", "Wireshark (TShark)", "error", "No se encontró TShark, el programa que copia los paquetes.",
                    "Instala Wireshark y deja marcada la opción TShark. El instalador te ofrecerá también Npcap.",
                    "instalar_wireshark", "Instalar Wireshark"))

    # --- Npcap / WinPcap
    v = d.get("tshark_v", "")
    npcap = re.search(r"Npcap version ([\d.]+)", v)
    winpcap = re.search(r"WinPcap version ([\d.]+)", v)
    if not ts:
        r.append(_c("npcap", "Npcap (captura de paquetes)", "pendiente", "Se comprobará cuando TShark esté instalado."))
    elif npcap:
        r.append(_c("npcap", "Npcap (captura de paquetes)", "ok", "Instalado, versión %s." % npcap.group(1)))
    elif winpcap:
        r.append(_c("npcap", "Npcap (captura de paquetes)", "aviso",
                    "Se detectó WinPcap %s, un programa antiguo que suele fallar en Windows 10 y 11." % winpcap.group(1),
                    "Desinstala WinPcap e instala Npcap (no pueden convivir).", "abrir_npcap", "Abrir descarga de Npcap"))
    elif es_win:
        r.append(_c("npcap", "Npcap (captura de paquetes)", "error",
                    "No se encontró Npcap: sin él, Wireshark no puede capturar y la lista de interfaces sale vacía.",
                    "Instala Npcap con las opciones por defecto. La licencia gratuita permite un número limitado de "
                    "instalaciones; en una empresa con muchos equipos conviene revisarla.",
                    "abrir_npcap", "Abrir descarga de Npcap"))

    # --- interfaces
    reales = [(i, n) for i, n in d.get("interfaces", []) if "NPF_" in i and not any(x in n for x in _NO_REALES)]
    if ts:
        if reales:
            r.append(_c("interfaces", "Interfaces de red", "ok", "TShark ve %d interfaces para capturar." % len(reales)))
        else:
            r.append(_c("interfaces", "Interfaces de red", "error",
                        "TShark no ve ninguna interfaz de red (solo puertos USB o ninguna).",
                        "Suele ser Npcap sin instalar, instalado sin la opción de adaptadores, o falta de permisos. "
                        "Reinstala Npcap y abre la aplicación como administrador."))

    # --- permisos
    if es_win:
        solo_admin = ps.get("adminonly") == "1"
        if solo_admin and not admin:
            r.append(_c("permisos", "Permisos", "error",
                        "Npcap está configurado solo para administradores y esta aplicación no lo es.",
                        "Abre la aplicación con Abrir_app.bat (pide permisos) o con clic derecho, Ejecutar como administrador."))
        elif admin:
            r.append(_c("permisos", "Permisos", "ok", "La aplicación se ejecuta como administrador."))
        else:
            r.append(_c("permisos", "Permisos", "ok", "No hace falta ser administrador en este equipo."))

    # --- hotspot e internet (solo Windows)
    if es_win:
        if ps.get("sin_internet") or ps.get("hotspot_error") or "estado" not in ps:
            motivo = ("Este PC no tiene conexión a internet, y el hotspot de Windows la necesita para encenderse."
                      if ps.get("sin_internet") else "No pude leer el estado del hotspot de Windows.")
            r.append(_c("hotspot", "Hotspot de Windows", "aviso", motivo,
                        "Conecta el PC a internet y activa la 'Zona con cobertura inalámbrica móvil'.",
                        "abrir_hotspot", "Abrir configuración del hotspot"))
        else:
            enc = ps["estado"].lower() == "on"
            banda = {"TwoPointFourGigahertz": "2,4 GHz", "FiveGigahertz": "5 GHz"}.get(ps.get("banda", ""), ps.get("banda", "?"))
            if enc:
                extra = " Algunos dispositivos baratos no ven 5 GHz." if "5" in banda else ""
                r.append(_c("hotspot", "Hotspot de Windows", "ok" if not extra else "aviso",
                            "Encendido (red «%s», banda %s, %s conectados).%s" % (ps.get("ssid", ""), banda, ps.get("clientes", "0"), extra),
                            "Si el dispositivo no ve la red, usa 2,4 GHz (ver siguiente punto)." if extra else ""))
            else:
                r.append(_c("hotspot", "Hotspot de Windows", "aviso", "Está apagado: el dispositivo no tendrá a qué conectarse.",
                            "Actívalo en 'Zona con cobertura inalámbrica móvil', con banda 2,4 GHz.",
                            "abrir_hotspot", "Abrir configuración del hotspot"))
            if ps.get("tipo") == "71":
                r.append(_c("cable", "Internet del PC", "aviso",
                            "Tu PC sale a internet por WiFi. Windows obliga entonces al hotspot a usar 5 GHz, y muchos "
                            "dispositivos baratos (TV box, cámaras) solo ven 2,4 GHz.",
                            "Conecta el PC a internet por cable de red (Ethernet). Después el hotspot podrá usar 2,4 GHz."))
            elif ps.get("tipo") == "6":
                r.append(_c("cable", "Internet del PC", "ok", "Sale a internet por cable: el hotspot puede usar 2,4 GHz."))

    # --- ventana
    if d.get("edge"):
        r.append(_c("ventana", "Ventana de la aplicación", "ok", "Se abrirá como aplicación (Edge/Chrome)."))
    else:
        r.append(_c("ventana", "Ventana de la aplicación", "aviso", "No se encontró Edge ni Chrome; se abrirá en tu navegador.",
                    "Funciona igual; solo cambia el aspecto de la ventana."))

    # --- prueba de captura (se hace con un botón)
    if ts and reales:
        r.append(_c("captura", "Prueba de captura", "pendiente",
                    "Aún no probada. Captura 4 segundos para confirmar que todo funciona.",
                    "", "probar_captura", "Probar captura (4 s)"))
    return r


def resumen(checks):
    n = {k: sum(1 for c in checks if c["estado"] == k) for k in ("ok", "aviso", "error", "pendiente")}
    n["listo"] = n["error"] == 0
    return n


def probar_captura(tshark, interfaz, segundos=4):
    """Captura unos segundos y dice si funcionó. Devuelve {ok, paquetes, mensaje}."""
    from .pcapio import read_packets
    if not tshark or not interfaz:
        return {"ok": False, "paquetes": 0, "mensaje": "Falta TShark o una interfaz para probar."}
    fd, ruta = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        p = subprocess.run([tshark, "-q", "-i", interfaz, "-a", "duration:%d" % segundos, "-F", "pcap", "-w", ruta],
                           capture_output=True, text=True, errors="replace", timeout=segundos + 20)
        err = (p.stderr or "").strip()
        if p.returncode != 0:
            return {"ok": False, "paquetes": 0, "mensaje": ("TShark no pudo capturar: " + err)[:300]}
        n = sum(1 for _ in read_packets(ruta))
        msg = ("La captura funciona: %d paquetes en %d s." % (n, segundos)) if n else (
            "La captura funciona, pero no pasó tráfico en %d s (normal si el dispositivo está inactivo)." % segundos)
        return {"ok": True, "paquetes": n, "mensaje": msg}
    except Exception as e:
        return {"ok": False, "paquetes": 0, "mensaje": "No se pudo probar: %s" % e}
    finally:
        try:
            os.remove(ruta)
        except OSError:
            pass
