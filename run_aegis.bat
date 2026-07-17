@echo off
setlocal

cd /d "%~dp0"

where uv >nul 2>nul
if errorlevel 1 (
    echo uv is not installed or is not on PATH.
    echo Install uv first, then run this file again.
    pause
    exit /b 1
)

if not exist "config.json" (
    echo config.json was not found in this folder.
    echo Copy config.example.json to config.json and add your Discord bot token first.
    pause
    exit /b 1
)

echo Starting Aegis API and Discord bot...
echo.

start "Aegis API" cmd /k "cd /d ""%~dp0"" && uv run uvicorn apps.api.main:app --host 127.0.0.1 --port 8000 --reload"
start "Aegis Bot" cmd /k "cd /d ""%~dp0"" && uv run aegis-bot"

echo Started both windows.
echo API: http://localhost:8000
echo Bot: check the Aegis Bot window for Discord login/sync status.
echo.
pause
