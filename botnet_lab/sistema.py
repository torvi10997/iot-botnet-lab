"""Rutas seguras a programas del sistema.

En Windows, una orden como `powershell` o `tshark` sin ruta se busca primero en el directorio actual. Si esa carpeta
trae un ejecutable con ese nombre (por ejemplo, descargado junto a una captura), se ejecutaría en su lugar. Por eso
se usan rutas absolutas del sistema y se ignora el directorio actual al buscar en el PATH.
"""
import os
import shutil

_RAIZ = os.environ.get("SystemRoot", r"C:\Windows")


def _existe(ruta, alternativa):
    return ruta if os.path.exists(ruta) else alternativa


POWERSHELL = _existe(os.path.join(_RAIZ, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "powershell")
TASKKILL = _existe(os.path.join(_RAIZ, "System32", "taskkill.exe"), "taskkill")
CMD = _existe(os.path.join(_RAIZ, "System32", "cmd.exe"), "cmd.exe")


def _mismo_dir(a, b):
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def buscar_en_path(nombre):
    """Como shutil.which, pero sin mirar el directorio actual."""
    actual = os.getcwd()
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or d == "." or _mismo_dir(d, actual):
            continue
        r = shutil.which(nombre, path=d)
        if r and not _mismo_dir(os.path.dirname(r), actual):
            return r
    return None
