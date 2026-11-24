@echo off
setlocal
cd /d "%~dp0"
call _env.bat
if errorlevel 1 (
  pause
  exit /b 1
)
start "" "http://127.0.0.1:5000"
".venv\Scripts\python.exe" app.py --mode demo
pause
