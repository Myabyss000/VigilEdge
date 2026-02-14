@echo off
REM ========================================
REM Request Administrator Privileges
REM ========================================
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting Administrator privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo ========================================
echo Starting VigilEdge Complete System
echo        (Running as Administrator)
echo ========================================
echo.
echo Starting 4 servers:
echo [1] Chatbot Server    (Port 5001)
echo [2] ThreatLoom SOC    (Port 8443)
echo [3] Vulnerable App    (Port 8080)
echo [4] WAF Dashboard     (Port 5000) - With Windows Defender + ThreatLoom
echo.
echo ========================================

REM Save starting directory
set START_DIR=%~dp0
set VIGILEDGE_DIR=%START_DIR%project-null-2.0\vigiledge-collage-project--main\VigilEdge
set THREATLOOM_DIR=%START_DIR%ThreatLoom

REM Start Chatbot Server (uses venv, runs from start directory)
echo [1/4] Starting AI Chatbot Server...
start "VigilEdge AI Chatbot" cmd /k "cd /d "%START_DIR%" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" chatbot_server.py"
timeout /t 3 /nobreak >nul

REM Start ThreatLoom SOC (uses its own venv, must start BEFORE WAF)
echo [2/4] Starting ThreatLoom SOC Platform...
start "ThreatLoom SOC" cmd /k "cd /d "%THREATLOOM_DIR%" && "%THREATLOOM_DIR%\venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload"
timeout /t 5 /nobreak >nul

REM Navigate to VigilEdge directory
cd /d "%VIGILEDGE_DIR%"

REM Start Vulnerable App (uses venv)
echo [3/4] Starting Vulnerable App...
start "Vulnerable App" cmd /k "cd /d "%VIGILEDGE_DIR%\vulnerable-app" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" app.py"
timeout /t 3 /nobreak >nul

REM Start WAF (uses venv with uvicorn app:app)
echo [4/4] Starting WAF Dashboard (with ThreatLoom integration)...
start "VigilEdge WAF" cmd /k "cd /d "%VIGILEDGE_DIR%\waf" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload"
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo All systems are starting...
echo ========================================
echo.
echo AI Chatbot:        http://localhost:5001
echo ThreatLoom SOC:    http://localhost:8443
echo   ThreatLoom Docs: http://localhost:8443/api/docs
echo   ThreatLoom Login: admin / changeme
echo Vulnerable App:    http://localhost:8080
echo WAF Dashboard:     http://localhost:5000/admin/dashboard
echo Protected App:     http://localhost:5000/protected
echo AI Analysis:       http://localhost:5000/ai-analysis
echo.
echo Integrations: Windows Defender + ThreatLoom SOC
echo Security events will appear in both WAF dashboard and ThreatLoom.
echo.
echo Opening WAF Dashboard in 8 seconds...
timeout /t 8 /nobreak >nul

start http://localhost:5000/admin/dashboard
start http://localhost:5000/protected
start http://localhost:8443/
echo.
echo ========================================
echo Complete System Ready!
echo ========================================
echo.
echo Make sure LM Studio is running for AI chat!
echo.
echo Press any key to close this window...
pause >nul
