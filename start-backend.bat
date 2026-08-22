@echo off
chcp 65001 >nul
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 20+ was not found.
  pause
  exit /b 1
)
where sing-box >nul 2>&1
if errorlevel 1 (
  echo sing-box was not found in PATH. Use Docker or install sing-box first.
  pause
  exit /b 1
)
if "%TT_API_TOKEN%"=="" echo WARNING: TT_API_TOKEN is empty. Do not expose this backend publicly without a token.
node backend\server.mjs
