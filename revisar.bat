@echo off
chcp 65001 >nul
title Revisar un dispositivo (consola)
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
  echo No encuentro Python.
  echo Instalalo desde https://www.python.org/downloads/ y marca "Add Python to PATH" durante la instalacion.
  echo.
  pause
  exit /b 1
)

python -m botnet_lab visita %*
echo.
pause
