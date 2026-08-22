@echo off
chcp 65001 >nul
cd /d "%~dp0"
start "Trojan Tester Frontend" /min cmd /c ""%~dp0start-server.bat""
timeout /t 2 /nobreak >nul
start "" "http://127.0.0.1:8080"
call "%~dp0start-tunnel.bat"
