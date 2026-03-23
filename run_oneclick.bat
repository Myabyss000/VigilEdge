@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy_oneclick.ps1" %*
set EXITCODE=%ERRORLEVEL%

if not "%EXITCODE%"=="0" (
    echo.
    echo Deployment failed with exit code %EXITCODE%.
    pause
)

exit /b %EXITCODE%
