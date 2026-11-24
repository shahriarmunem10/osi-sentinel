@echo off
setlocal
cd /d "%~dp0"
call _env.bat
if errorlevel 1 (
  pause
  exit /b 1
)
echo.
echo OSI Sentinel attack simulator (your own machine only)
echo   1 = port scan        2 = connection flood (SYN flood)
echo   3 = malicious HTTP   4 = ICMP flood
echo   5 = ping sweep       6 = ARP spoofing (injected into the engine)
echo   7 = all of the above
echo.
set /p choice=Choose 1-7: 
set "S=all"
if "%choice%"=="1" set "S=portscan"
if "%choice%"=="2" set "S=synflood"
if "%choice%"=="3" set "S=http"
if "%choice%"=="4" set "S=icmp"
if "%choice%"=="5" set "S=sweep"
if "%choice%"=="6" set "S=arp"
".venv\Scripts\python.exe" tools\attack_simulator.py %S%
pause
