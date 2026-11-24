@echo off
cd /d "%~dp0"
set "PYCMD="
where py >nul 2>&1
if %errorlevel%==0 set "PYCMD=py -3"
if not defined PYCMD (
  where python >nul 2>&1
  if %errorlevel%==0 set "PYCMD=python"
)
if not defined PYCMD goto nopython
if not exist ".venv\Scripts\python.exe" (
  echo Creating virtual environment...
  %PYCMD% -m venv .venv
  if errorlevel 1 goto fail
)
if not exist ".venv\.deps_ok" (
  echo Installing dependencies, this needs internet only the first time...
  ".venv\Scripts\python.exe" -m pip install --upgrade pip
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto fail
  echo ok> ".venv\.deps_ok"
)
exit /b 0
:nopython
echo Python was not found. Install Python 3.10 or newer from python.org and tick "Add python.exe to PATH".
exit /b 1
:fail
echo Setup failed. Read the messages above.
exit /b 1
