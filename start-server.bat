@echo off
chcp 65001 >nul
title Trojan Fast Tester - Server
color 0B
cd /d "%~dp0"

echo.
echo  =========================================
echo     Trojan Fast Tester - Local Server
echo  =========================================
echo.
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /C:"IPv4 Address"') do (
    set "LIP=%%a"
    goto :found
)
:found
set "LIP=%LIP: =%"
echo  PC:      http://127.0.0.1:8080
echo  Mobile:  http://%LIP%:8080
echo.
echo  For public access: run start-tunnel.bat or start-all.bat
echo  Press Ctrl+C to stop
echo  ─────────────────────────────────────────
echo.
timeout /t 1 /nobreak >nul
start "" "http://127.0.0.1:8080"
python -m http.server 8080 --bind 0.0.0.0
pause
