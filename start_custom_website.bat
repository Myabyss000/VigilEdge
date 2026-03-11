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

call :check_port 5001 "Chatbot Server"
if errorlevel 1 goto portConflict
call :check_port 8443 "ThreatLoom SOC"
if errorlevel 1 goto portConflict
call :check_port 5000 "VigilEdge WAF"
if errorlevel 1 goto portConflict

set "DEFAULT_CUSTOM_URL=http://localhost:3000"
set /p CUSTOM_TARGET_URL=Enter your custom website URL [%DEFAULT_CUSTOM_URL%]: 
if "%CUSTOM_TARGET_URL%"=="" set "CUSTOM_TARGET_URL=%DEFAULT_CUSTOM_URL%"

echo.
echo Your website must already be running at:
echo %CUSTOM_TARGET_URL%
echo.
choice /C YN /N /M "Continue launching Chatbot, ThreatLoom, and the WAF? [Y/N]: "
if errorlevel 2 exit /B 0

echo.
echo ========================================
echo Starting VigilEdge Custom Website Mode
echo        (Running as Administrator)
echo ========================================
echo.
echo Starting 3 core services:
echo [1] Chatbot Server    (Port 5001)
echo [2] ThreatLoom SOC    (Port 8443)
echo [3] WAF Dashboard     (Port 5000)
echo.
echo Protected custom website target:
echo [*] %CUSTOM_TARGET_URL%
echo.
echo ========================================

set START_DIR=%~dp0
set VIGILEDGE_DIR=%START_DIR%project-null-2.0\vigiledge-collage-project--main\VigilEdge
set THREATLOOM_DIR=%START_DIR%ThreatLoom

echo [1/3] Starting AI Chatbot Server...
start "VigilEdge AI Chatbot" cmd /k "cd /d "%START_DIR%" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" chatbot_server.py"
timeout /t 3 /nobreak >nul

echo [2/3] Starting ThreatLoom SOC Platform...
start "ThreatLoom SOC" cmd /k "cd /d "%THREATLOOM_DIR%" && "%THREATLOOM_DIR%\venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload"
timeout /t 5 /nobreak >nul

echo [3/3] Starting WAF Dashboard...
start "VigilEdge WAF" cmd /k "cd /d "%VIGILEDGE_DIR%\waf" && set "UPSTREAM_USE_DEMO_TARGET=false" && set "UPSTREAM_CUSTOM_TARGET_URL=%CUSTOM_TARGET_URL%" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload"
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo Custom website mode is starting...
echo ========================================
echo.
echo AI Chatbot:        http://localhost:5001
echo ThreatLoom SOC:    http://localhost:8443
echo   ThreatLoom Docs: http://localhost:8443/api/docs
echo   ThreatLoom Login: use the first-run bootstrap form or your existing admin account
echo WAF Dashboard:     http://localhost:5000/admin/dashboard
echo Website via WAF:   http://localhost:5000/
echo Protected Access:  http://localhost:5000/protected
echo Upstream Target:   %CUSTOM_TARGET_URL%
echo.
echo If the website is not reachable yet, the WAF will show a backend-unavailable page until it comes online.
echo Opening the main pages in 8 seconds...
timeout /t 8 /nobreak >nul

start http://localhost:5000/admin/dashboard
start http://localhost:5000/
start http://localhost:8443/

echo.
echo ========================================
echo Custom Website Mode Ready!
echo ========================================
echo.
echo Make sure LM Studio is running for AI chat.
echo.
echo Press any key to close this window...
pause >nul
exit /B 0

:check_port
set "PORT_TO_CHECK=%~1"
set "SERVICE_NAME=%~2"
powershell -NoProfile -Command "$conn = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq %PORT_TO_CHECK% } | Select-Object -First 1; if ($conn) { $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue; if ($proc) { Write-Host ('[ERROR] Port %PORT_TO_CHECK% is already in use by ' + $proc.ProcessName + ' (PID ' + $proc.Id + '). ' + '%SERVICE_NAME%' + ' cannot start.'); } else { Write-Host ('[ERROR] Port %PORT_TO_CHECK% is already in use. ' + '%SERVICE_NAME%' + ' cannot start.'); }; exit 1 }"
if errorlevel 1 exit /B 1
exit /B 0

:portConflict
echo.
echo Resolve the port conflict, then run start_custom_website.bat again.
echo.
pause
exit /B 1