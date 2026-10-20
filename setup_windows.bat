@echo off
setlocal
cd /d "%~dp0"
title Keystone setup
echo.
echo  Keystone setup - one time only (about 2 to 5 minutes, needs internet)
echo.

rem --- find Python 3.11 or newer (3.13, 3.12, 3.11 first: the versions Keystone is tested on) ---
set "PY="
for %%V in (3.13 3.12 3.11) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1
    if not errorlevel 1 set "PY=py -%%V"
  )
)
if not defined PY (
  py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 set "PY=py -3"
)
if not defined PY (
  python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
  if not errorlevel 1 set "PY=python"
)
if not defined PY goto :nopython

echo  Python found:
%PY% --version
echo.

rem --- private Python folder ---------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
  echo  Creating the private Python folder .venv ...
  %PY% -m venv .venv
  if errorlevel 1 goto :failed
)

rem --- packages -----------------------------------------------------------------
echo  Installing packages ...
".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
".venv\Scripts\python.exe" -m pip install -r requirements-lock.txt
if errorlevel 1 (
  echo.
  echo  The pinned package list did not install. Trying the flexible list instead ...
  ".venv\Scripts\python.exe" -m pip install -r requirements.txt
  if errorlevel 1 goto :failed
)

rem --- self check ----------------------------------------------------------------
echo.
echo  Checking the installation ...
".venv\Scripts\python.exe" verify_install.py
if errorlevel 1 goto :failed

echo.
echo  Setup finished. Start Keystone with start_windows.bat
if /i not "%~1"=="nopause" pause
exit /b 0

:nopython
echo  Python 3.11 or newer was not found on this computer.
echo.
echo    1. Download Python 3.12 or 3.13 from https://www.python.org/downloads/windows/
echo    2. Run the installer. If it offers "Add python.exe to PATH", tick it.
echo    3. Close this window and run setup_windows.bat again.
echo.
if /i not "%~1"=="nopause" pause
exit /b 1

:failed
echo.
echo  Setup did not finish. Read the last lines above.
echo    - No internet or a company proxy: fix that, then run this file again.
echo    - Antivirus blocked a file: allow the Keystone folder, then run this file again.
echo    - Full list of fixes: README.md, section Troubleshooting.
echo.
if /i not "%~1"=="nopause" pause
exit /b 1
