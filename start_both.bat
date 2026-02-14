@echo off
echo ========================================
echo Starting VigilEdge WAF System
echo ========================================
echo.

cd /d "%~dp0\project-null-2.0\vigiledge-collage-project--main\VigilEdge"

echo Starting Vulnerable App on port 8080...
start "Vulnerable App" cmd /k "cd vulnerable-app && python app.py"
timeout /t 3 /nobreak >nul

echo Starting WAF on port 5000...
start "VigilEdge WAF" cmd /k "cd waf && python -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload"
timeout /t 5 /nobreak >nul

echo.
echo ========================================
echo Both services are starting...
echo ========================================
echo.
echo Vulnerable App: http://localhost:8080
echo WAF Dashboard:   http://localhost:5000/dashboard
echo Protected Access: http://localhost:5000/protected
echo.
echo Opening protected app in 5 seconds...
timeout /t 5 /nobreak >nul

start http://localhost:5000/protected

echo.
echo ========================================
echo System is ready!
echo ========================================
echo.
echo Press any key to close this window...
pause >nul
