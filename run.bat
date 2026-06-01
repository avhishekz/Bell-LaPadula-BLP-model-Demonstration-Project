@echo off
echo.
echo Bell-LaPadula Security Model -- Setup
echo ======================================
echo.

where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat
echo Installing dependencies...
pip install -q -r requirements.txt

echo.
echo Starting server at http://localhost:5000
echo.
python app.py
pause
