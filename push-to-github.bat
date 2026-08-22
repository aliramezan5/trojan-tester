@echo off
chcp 65001 >nul
title Push to GitHub - Trojan Tester
color 0A
cd /d "%~dp0"

echo.
echo ==============================================
echo    Sending Updates to GitHub Pages
echo ==============================================
echo.

git add .
git commit -m "update web app"
echo.
echo Pushing to GitHub...
git push -u origin main

echo.
echo Done!
echo Website: https://aliramezan5.github.io/trojan-tester/
echo.
pause
