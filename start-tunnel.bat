@echo off
chcp 65001 >nul
title Trojan Fast Tester - Public Tunnel
color 0A
cd /d "%~dp0"

echo.
echo  =========================================
echo     Public Tunnel via Cloudflare (Free)
echo     No account needed!
echo  =========================================
echo.
echo  STEP 1: Make sure start-server.bat is running!
echo  STEP 2: A URL like https://xxxx.trycloudflare.com
echo          will appear - share it with anyone!
echo.

if not exist "%~dp0cloudflared.exe" (
  echo Downloading cloudflared...
  curl -Lo "%~dp0cloudflared.exe" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
  echo Done!
  echo.
)
echo Starting tunnel to http://127.0.0.1:8080 ...
echo.
"%~dp0cloudflared.exe" tunnel --url http://127.0.0.1:8080
pause
