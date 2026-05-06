@echo off
setlocal enabledelayedexpansion

:: ─────────────────────────────────────────────────────────────────────────────
:: SKYFALL BABIES - Setup & Build Script
:: ─────────────────────────────────────────────────────────────────────────────

echo.
echo ===========================================================================
echo   SKYFALL BABIES - Setup Utility
echo ===========================================================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: Python is not installed or not in PATH.
    echo Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

:: Create Virtual Environment
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [+] Virtual environment created.
) else (
    echo [*] Virtual environment already exists.
)

:: Activate and install dependencies
echo [*] Installing dependencies...
call .venv\Scripts\activate
python -m pip install --upgrade pip
if exist "requirements.txt" (
    python -m pip install -r requirements.txt
) else (
    echo [!] Warning: requirements.txt not found. Installing core packages...
    python -m pip install flask requests python-dotenv psutil pandas dnspython openpyxl
)

echo.
echo [+] Setup complete!
echo.
echo To start the project, run:
echo   python skyfallbabies.py
echo.
echo [*] Launching Skyfall Babies now...
echo.
python skyfallbabies.py

pause
