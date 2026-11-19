@echo off
setlocal
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Installez ARKS en suivant README.md avant le premier lancement.
  pause
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" -I -B "%~dp0tools\public_demo.py" serve
exit /b %errorlevel%
