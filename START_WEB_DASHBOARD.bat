@echo off
cd /d "%~dp0"
echo ===================================================
echo     STARTING INTERACTIVE WEB DASHBOARD
echo ===================================================
echo.
echo Opening browser at http://127.0.0.1:5000 ...
start http://127.0.0.1:5000
python web_app.py
pause
