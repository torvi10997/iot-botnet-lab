"""Fabricante de un dispositivo a partir de su MAC, usando la base que ya trae Wireshark (sin internet)."""
import subprocess

_tabla = None


def _cargar(tshark):
    global _tabla
    if _tabla is not None:
        return
    _tabla = {}
    if not tshark:
        return
    try:
        out = subprocess.run([tshark, "-G", "manuf"], capture_output=True, text=True,
                             errors="replace", timeout=30).stdout
    except Exception:
        return
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and len(parts[0]) == 8 and parts[0].count(":") == 2:
            _tabla[parts[0].upper()] = (parts[2] if len(parts) > 2 and parts[2] else parts[1]).strip()


def mac_privada(mac):
    """Una MAC con el bit 'administrada localmente' activo es aleatoria/privada."""
    try:
        return bool(int(mac.split(":")[0], 16) & 2)
    except Exception:
        return False


def fabricante(mac, tshark=None):
    if mac_privada(mac):
        return "Dirección privada (aleatoria)"
    _cargar(tshark)
    return _tabla.get(mac.upper()[:8], "Fabricante no registrado")
