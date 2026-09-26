@echo off
setlocal
cd /d "%~dp0"
echo ===================================================
echo Starting Phishing Detection System Web Application
echo Local URL: http://127.0.0.1:5000
echo ===================================================
python app.py
pause
