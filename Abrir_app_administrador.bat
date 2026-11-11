@echo off
chcp 65001 >nul
title Revisor de red (administrador)
cd /d "%~dp0"
echo Pidiendo permisos de administrador. Acepta el aviso de Windows que aparece...
powershell -NoProfile -Command "Start-Process -FilePath '%~dp0Abrir_app.bat' -WorkingDirectory '%~dp0' -Verb RunAs"
if errorlevel 1 (
  echo.
  echo No se pudieron obtener los permisos. Prueba con clic derecho sobre Abrir_app.bat, "Ejecutar como administrador".
  pause
)
