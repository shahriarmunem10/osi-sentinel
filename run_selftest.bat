@echo off
setlocal
cd /d "%~dp0"
call _env.bat
if errorlevel 1 (
  pause
  exit /b 1
)
".venv\Scripts\python.exe" tests\selftest.py
pause
