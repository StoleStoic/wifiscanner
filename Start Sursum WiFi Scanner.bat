@echo off
rem Stole Sursum WiFi Scanner - double-click to start.
title Stole Sursum WiFi Scanner
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py -3"
) else (
  where python >nul 2>nul
  if errorlevel 1 (
    echo Python is not installed.
    echo.
    echo Install "Python 3.12" or newer from the Microsoft Store, or from https://www.python.org/downloads/
    echo ^(tick "Add python.exe to PATH" in the installer^), then double-click this file again.
    echo.
    pause
    exit /b 1
  )
  set "PY=python"
)

%PY% -m sursum %*
if errorlevel 1 (
  echo.
  echo The scanner stopped with an error. The message above says why.
  pause
)
