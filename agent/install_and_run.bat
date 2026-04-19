@echo off
:: AEGIS Firewall Agent — Windows Installer
:: Right-click this file → "Run as Administrator"

echo ============================================
echo   AEGIS Firewall Agent Installer
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install from https://python.org
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install psutil requests --quiet

echo [2/3] Setting backend URL...
:: Change this to your actual deployed backend URL
set AEGIS_BACKEND=http://YOUR_BACKEND_URL_HERE:8000

echo [3/3] Starting AEGIS agent...
echo.
echo Your machine is now being monitored.
echo Check the AEGIS dashboard to see your connections live.
echo Press Ctrl+C to stop monitoring.
echo.

python agent.py

pause
