@echo off
chcp 65001 >nul
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Se necesitan permisos de administrador para capturar trafico.
  echo Acepta el aviso de Windows que aparece a continuacion...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

where python >nul 2>&1
if errorlevel 1 (
  echo No encuentro Python. Instalalo desde https://www.python.org/downloads/
  echo y marca "Add Python to PATH" durante la instalacion.
  pause
  exit /b 1
)

echo Abriendo el Revisor de red... Cierra su ventana para terminar.
python -m botnet_lab app %*
if errorlevel 1 pause
