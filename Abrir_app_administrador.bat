@echo off
chcp 65001 >nul
title Revisor de red (administrador)
cd /d "%~dp0"
set NoDefaultCurrentDirectoryInExePath=1
echo Pidiendo permisos de administrador. Acepta el aviso de Windows que aparece...
rem la ruta viaja en una variable de entorno: asi no se rompe (ni se inyecta nada) con apostrofes o simbolos en el nombre de la carpeta
set "BAT_APP=%~dp0Abrir_app.bat"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command "Start-Process -FilePath $env:BAT_APP -WorkingDirectory (Split-Path $env:BAT_APP) -Verb RunAs"
if errorlevel 1 (
  echo.
  echo No se pudieron obtener los permisos. Prueba con clic derecho sobre Abrir_app.bat, "Ejecutar como administrador".
  pause
)
