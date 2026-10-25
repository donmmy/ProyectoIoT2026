@echo off
rem Abre la interfaz grafica del escaner. Doble clic para usarlo.
rem  - Pide permisos de administrador (necesarios para capturar en vivo con Npcap).
rem  - La primera vez crea el entorno virtual ..\.venv e instala las dependencias.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

set "VENV=..\.venv"
if exist "%VENV%\Scripts\pythonw.exe" goto :check_deps

echo === Primera ejecucion: preparando el entorno ===
set "PYBASE="
py -3 --version >nul 2>&1 && set "PYBASE=py -3"
if not defined PYBASE (
    python --version >nul 2>&1 && set "PYBASE=python"
)
if not defined PYBASE (
    echo.
    echo [!] No se encuentra Python 3. Instalalo desde https://www.python.org/downloads/
    echo     marcando "Add python.exe to PATH" y vuelve a abrir este archivo.
    pause
    exit /b 1
)
echo Creando entorno virtual con: %PYBASE%
%PYBASE% -m venv "%VENV%"
if errorlevel 1 goto :fail

:check_deps
rem Instala o completa las dependencias si falta alguna (scapy)
"%VENV%\Scripts\python.exe" -c "import scapy" >nul 2>&1
if %errorlevel% equ 0 goto :launch
echo Instalando dependencias (puede tardar un minuto)...
"%VENV%\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto :fail

:launch
start "" "%VENV%\Scripts\pythonw.exe" gui.py
exit /b 0

:fail
echo.
echo [!] No se pudo preparar el entorno. Revisa los mensajes de arriba
echo     (conexion a internet, version de Python...).
pause
exit /b 1
