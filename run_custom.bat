@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
call _env.bat
if errorlevel 1 (
  pause
  exit /b 1
)
".venv\Scripts\python.exe" tools\check_system.py
echo.
echo Type the adapter name(s) to capture on, separated by commas.
echo Example: Wi-Fi, Local Area Connection* 10   (the Mobile hotspot adapter)
set /p IFACE=Adapters (empty = automatic): 
start "" "http://127.0.0.1:5000"
if "%IFACE%"=="" (
  ".venv\Scripts\python.exe" app.py --mode auto
) else (
  ".venv\Scripts\python.exe" app.py --mode live --iface "%IFACE%"
)
pause
