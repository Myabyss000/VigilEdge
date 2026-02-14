@echo off
:: ===========================================================================
::  ThreatLoom SOC Platform — First-Time Setup
::  Run this once before using run.bat (or run.bat will do it automatically).
:: ===========================================================================
title ThreatLoom Setup
color 0B
cd /d "%~dp0"

echo.
echo  ========================================
echo    ThreatLoom — First-Time Setup
echo  ========================================
echo.

:: ── Check Python ──────────────────────────────────────────────────────────
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    color 0C
    echo  [ERROR] Python not found. Install Python 3.10+ first.
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do (
    echo  [OK]    Python %%v detected.
)

:: ── Create virtual environment ────────────────────────────────────────────
if exist "venv\Scripts\activate.bat" (
    echo  [SKIP]  Virtual environment already exists.
) else (
    echo  [SETUP] Creating virtual environment...
    python -m venv venv
    echo  [OK]    Virtual environment created.
)

:: ── Activate ──────────────────────────────────────────────────────────────
call venv\Scripts\activate.bat

:: ── Install dependencies ──────────────────────────────────────────────────
echo  [SETUP] Installing Python dependencies...
pip install --upgrade pip --quiet --disable-pip-version-check
pip install -r requirements.txt --quiet --disable-pip-version-check
echo  [OK]    Dependencies installed.

:: ── .env ──────────────────────────────────────────────────────────────────
if exist ".env" (
    echo  [SKIP]  .env already exists.
) else (
    copy .env.example .env >nul
    echo  [OK]    .env created from .env.example — edit it to customise.
)

:: ── Directories ───────────────────────────────────────────────────────────
if not exist "logs" mkdir logs
if not exist "data" mkdir data
echo  [OK]    directories ensured: logs/ data/

:: ── Done ──────────────────────────────────────────────────────────────────
echo.
echo  ========================================
echo    Setup complete!
echo    Run "run.bat" to start ThreatLoom.
echo  ========================================
echo.
pause
