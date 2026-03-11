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
call :check_port 8080 "Demo Website"
if errorlevel 1 goto portConflict
call :check_port 5000 "VigilEdge WAF"
if errorlevel 1 goto portConflict

echo ========================================
echo Starting VigilEdge Complete Demo System
echo        (Running as Administrator)
echo ========================================
echo.
echo Starting 4 servers:
echo [1] Chatbot Server    (Port 5001)
echo [2] ThreatLoom SOC    (Port 8443)
echo [3] Demo Website      (Port 8080)
echo [4] WAF Dashboard     (Port 5000)
echo.
echo ========================================

set START_DIR=%~dp0
set VIGILEDGE_DIR=%START_DIR%project-null-2.0\vigiledge-collage-project--main\VigilEdge
set THREATLOOM_DIR=%START_DIR%ThreatLoom

echo [1/4] Starting AI Chatbot Server...
start "VigilEdge AI Chatbot" cmd /k "cd /d "%START_DIR%" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" chatbot_server.py"
timeout /t 3 /nobreak >nul

echo [2/4] Starting ThreatLoom SOC Platform...
start "ThreatLoom SOC" cmd /k "cd /d "%THREATLOOM_DIR%" && "%THREATLOOM_DIR%\venv\Scripts\python.exe" -m uvicorn main:app --host 0.0.0.0 --port 8443 --reload"
timeout /t 5 /nobreak >nul

cd /d "%VIGILEDGE_DIR%"

echo [3/4] Starting Demo Website...
start "Demo Website" cmd /k "cd /d "%VIGILEDGE_DIR%\vulnerable-app" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" app.py"
timeout /t 3 /nobreak >nul

echo [4/4] Starting WAF Dashboard...
start "VigilEdge WAF" cmd /k "cd /d "%VIGILEDGE_DIR%\waf" && set "UPSTREAM_USE_DEMO_TARGET=true" && set "UPSTREAM_DEMO_TARGET_URL=http://localhost:8080" && "%VIGILEDGE_DIR%\venv\Scripts\python.exe" -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload"
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo All demo services are starting...
echo ========================================
echo.
echo AI Chatbot:        http://localhost:5001
echo ThreatLoom SOC:    http://localhost:8443
echo   ThreatLoom Docs: http://localhost:8443/api/docs
echo   ThreatLoom Login: use the first-run bootstrap form or your existing admin account
echo Demo Website:      http://localhost:8080
echo WAF Dashboard:     http://localhost:5000/admin/dashboard
echo Protected Demo:    http://localhost:5000/protected
echo Root via WAF:      http://localhost:5000/
echo AI Analysis:       http://localhost:5000/ai-analysis
echo.
echo Opening the main pages in 8 seconds...
timeout /t 8 /nobreak >nul

start http://localhost:5000/admin/dashboard
start http://localhost:5000/protected
start http://localhost:8443/

echo.
echo ========================================
echo Complete Demo System Ready!
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
echo Resolve the port conflict, then run start_demo.bat again.
echo.
pause
exit /B 1