@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "CF_VERSION=2026.7.2"
set "CF_SHA256=cdb5d4432f6ae1595654a692a51308b69d2bf7af961f5578d9391837cf072df9"
set "CF_EXE=%~dp0cloudflared.exe"
set "CF_URL=https://github.com/cloudflare/cloudflared/releases/download/%CF_VERSION%/cloudflared-windows-amd64.exe"

if exist "%CF_EXE%" goto verify
:download
echo Downloading pinned cloudflared %CF_VERSION%...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing -Uri '%CF_URL%' -OutFile '%CF_EXE%'"
if errorlevel 1 goto fail

:verify
for /f "tokens=*" %%H in ('powershell -NoProfile -Command "(Get-FileHash -Algorithm SHA256 '%CF_EXE%').Hash.ToLower()"') do set "ACTUAL_SHA=%%H"
if /I not "%ACTUAL_SHA%"=="%CF_SHA256%" (
  echo cloudflared SHA256 verification FAILED.
  del /q "%CF_EXE%" >nul 2>&1
  goto fail
)
echo cloudflared verified.
"%CF_EXE%" tunnel --url http://127.0.0.1:8080
exit /b %errorlevel%

:fail
echo Unable to start verified Cloudflare tunnel.
pause
exit /b 1
