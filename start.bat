@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
  echo [*] Erstelle virtuelles Environment .venv ...
  py -3 -m venv .venv 2>nul || python -m venv .venv
)

echo [*] Installiere Abhaengigkeiten ...
call ".venv\Scripts\python.exe" -m pip install --upgrade pip
call ".venv\Scripts\pip.exe" install -r requirements.txt

echo [*] Starte Anwendung ...
set PYTHONUTF8=1
call ".venv\Scripts\python.exe" app.py %*
pause
