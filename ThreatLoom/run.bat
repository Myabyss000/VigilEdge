@echo off
:: ===========================================================================
::  ThreatLoom SOC Platform — One-Click Launcher
::  Usage: double-click run.bat  or  run.bat from a terminal
:: ===========================================================================
title ThreatLoom SOC Platform
color 0A
echo.
echo  ========================================
echo    ThreatLoom SOC Platform Launcher
echo  ========================================
echo.

:: ── Resolve project root (wherever this bat lives) ────────────────────────
cd /d "%~dp0"

:: ── Check Python is available ─────────────────────────────────────────────
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    color 0C
    echo  [ERROR] Python is not installed or not on PATH.
    echo          Install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

:: ── Create venv if it doesn't exist ───────────────────────────────────────
if not exist "venv\Scripts\activate.bat" (
    echo  [SETUP] Creating virtual environment...
    python -m venv venv
    if %ERRORLEVEL% neq 0 (
        color 0C
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [SETUP] Virtual environment created.
)

:: ── Activate venv ─────────────────────────────────────────────────────────
call venv\Scripts\activate.bat

:: ── Install / update dependencies ─────────────────────────────────────────
echo  [SETUP] Installing dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% neq 0 (
    color 0C
    echo  [ERROR] Dependency installation failed.
    pause
    exit /b 1
)

:: ── Create .env from example if missing ───────────────────────────────────
if not exist ".env" (
    echo  [SETUP] Creating .env from .env.example...
    copy .env.example .env >nul
    echo  [SETUP] .env created. Edit it to customise settings.
)

:: ── Create required directories ───────────────────────────────────────────
if not exist "logs"  mkdir logs
if not exist "data"  mkdir data

:: ── Launch the application ────────────────────────────────────────────────
echo.
echo  ========================================
echo    Starting ThreatLoom on port 8443
echo    Dashboard:  http://localhost:8443
echo    API Docs:   http://localhost:8443/api/docs
echo    Login:      admin / changeme
echo  ========================================
echo.
echo  Press Ctrl+C to stop the server.
echo.

python -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload

:: ── If server exits ───────────────────────────────────────────────────────
echo.
echo  Server stopped.
pause
