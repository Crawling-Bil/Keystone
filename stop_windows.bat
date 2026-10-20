@echo off
setlocal
cd /d "%~dp0"
set "PORT=%NES_PORT%"
if not defined PORT set "PORT=8002"
set "FOUND="
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%PORT% " ^| findstr "LISTENING"') do (
  taskkill /PID %%a /F >nul 2>&1
  set "FOUND=1"
)
if defined FOUND (
  echo Keystone stopped.
) else (
  echo Keystone was not running on port %PORT%.
)
pause
