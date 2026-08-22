@echo off
chcp 65001 >nul
title Trojan Fast Tester - Server + Tunnel (All-in-One)
color 0A
cd /d "%~dp0"

echo.
echo  =========================================
echo     Trojan Fast Tester (All-in-One)
echo     Server + Public Tunnel
echo  =========================================
echo.

:: Check Python
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found! Please install Python.
    pause
    exit /b
)

:: Get local IP
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /C:"IPv4 Address"') do (
    set "LIP=%%a"
    goto :found
)
:found
set "LIP=%LIP: =%"

echo  [1/2] Starting Python server on port 8080...
start "Trojan Server (Port 8080)" /min cmd /c "cd /d ""%~dp0"" && python -m http.server 8080 --bind 0.0.0.0"

timeout /t 2 /nobreak >nul

echo  ✅ Local server is running!
echo.
echo  📌 Local URLs:
echo     PC:      http://127.0.0.1:8080
echo     Mobile:  http://%LIP%:8080
echo.
echo  [2/2] Starting Cloudflare Public Tunnel...
echo  (Public URL will appear below in a few seconds)
echo.
echo  ─────────────────────────────────────────────────────────────
echo.

if not exist "%~dp0cloudflared.exe" (
    echo  Downloading cloudflared...
    curl -Lo "%~dp0cloudflared.exe" "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
    echo  Done!
    echo.
)

start "" "http://127.0.0.1:8080"
"%~dp0cloudflared.exe" tunnel --url http://127.0.0.1:8080

pause
