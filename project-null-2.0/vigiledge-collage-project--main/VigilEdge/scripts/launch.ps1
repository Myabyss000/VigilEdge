# VigilEdge WAF - PowerShell Launch Script
# Uses the correct Python installation path

Write-Host "====================================" -ForegroundColor Cyan
Write-Host "       VigilEdge WAF - Starting" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[INFO] Starting VigilEdge WAF..." -ForegroundColor Green
Write-Host "[INFO] Dashboard will be available at: http://127.0.0.1:5000" -ForegroundColor Yellow
Write-Host "[INFO] API Documentation at: http://127.0.0.1:5000/docs" -ForegroundColor Yellow
Write-Host "[INFO] Press Ctrl+C to stop the server" -ForegroundColor Red
Write-Host ""

& "C:\Users\Arghya\AppData\Local\Programs\Python\Python313\python.exe" main.py
