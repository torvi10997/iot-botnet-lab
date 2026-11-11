@echo off
chcp 65001 >nul
title Revisor de red
cd /d "%~dp0"
set NoDefaultCurrentDirectoryInExePath=1

python --version >nul 2>&1
if errorlevel 1 (
  echo No encuentro Python.
  echo Instalalo desde https://www.python.org/downloads/ y marca "Add Python to PATH" durante la instalacion.
  echo Despues vuelve a abrir este archivo.
  echo.
  pause
  exit /b 1
)

echo Abriendo el Revisor de red...
echo Si no aparece la ventana, se abrira en tu navegador. Para terminar, cierra la ventana de la aplicacion.
echo.
python -m botnet_lab app %*
if errorlevel 1 (
  echo.
  echo Ocurrio un error. Copia el mensaje de arriba y revisa docs\APP.md, seccion "Solucion de problemas".
  echo.
  pause
)
