@echo off
setlocal EnableExtensions
rem Development launcher for Helicoid Manager.
rem Explicit loopback development flags only. No credentials, no production
rem default, no server install/setup/policy changes.

set "HS_MANAGER_EXE=%~dp0Helicoid.Manager.exe"

if not exist "%HS_MANAGER_EXE%" (
  echo start-development-manager: Helicoid.Manager.exe not found.
  echo Expected sibling: "%HS_MANAGER_EXE%"
  echo Place this script in the same folder as the published Helicoid.Manager.exe
  echo and run it again. No server, install, or policy change has been made.
  echo Press any key to close this window.
  pause >nul
  exit /b 1
)

rem %~dp0 path is quoted, so folders with spaces work from any cwd.
start "Helicoid Manager (development)" "%HS_MANAGER_EXE%" --development-server=http://127.0.0.1:8787 --development-manager-identity dev-manager-key
exit /b 0
