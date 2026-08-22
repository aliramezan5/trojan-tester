@echo off
chcp 65001 >nul
cd /d "%~dp0"
where python >nul 2>&1
if errorlevel 1 (echo Python was not found.& pause& exit /b 1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0prepare-vendor.ps1"
if errorlevel 1 (echo Vendor preparation failed.& pause& exit /b 1)
echo Frontend: http://127.0.0.1:8080
python -m http.server 8080 --bind 0.0.0.0
