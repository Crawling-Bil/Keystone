@echo off
setlocal
cd /d "%~dp0"
title Keystone

if not exist ".venv\Scripts\python.exe" (
  echo.
  echo  First start on this computer: Keystone installs itself now.
  echo  This happens once, takes a few minutes and needs internet. Keep this window open.
  echo.
  call "%~dp0setup_windows.bat" nopause
  if errorlevel 1 (
    echo.
    echo  Keystone could not be installed. Read the message above.
    pause
    exit /b 1
  )
)

echo.
".venv\Scripts\python.exe" run.py
if errorlevel 1 (
  echo.
  echo  Keystone stopped. If there is a message above, read it first.
  pause
)
