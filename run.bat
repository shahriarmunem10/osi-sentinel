@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting administrator rights for live packet capture...
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
call _env.bat
if errorlevel 1 (
  pause
  exit /b 1
)
if not exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
  echo.
  echo NOTE: Npcap was not found. Live capture will not work and the dashboard will start in Demo mode.
  echo Install Npcap from https://npcap.com and tick "Install Npcap in WinPcap API-compatible Mode"
  echo and "Support loopback traffic". See README.md section 3.
  echo.
)
start "" "http://127.0.0.1:5000"
".venv\Scripts\python.exe" app.py --mode auto
pause
