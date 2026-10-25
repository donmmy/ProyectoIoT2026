@echo off
rem Abre la interfaz grafica del escaner con permisos de administrador
rem (necesarios para capturar en vivo con Npcap). Doble clic para usarlo.
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "PY=.venv\Scripts\pythonw.exe"
if not exist "%PY%" set "PY=pythonw"
start "" "%PY%" gui.py
