@echo off
cd /d "%~dp0"
echo ===================================================
echo     CHECKING RECEIVED FILE INTEGRITY STATUS
echo ===================================================
echo.
python check_status.py
echo.
pause
