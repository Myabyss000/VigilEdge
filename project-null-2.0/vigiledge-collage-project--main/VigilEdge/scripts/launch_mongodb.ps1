# VulnShop MongoDB Edition Launcher (PowerShell)
Write-Host "=====================================" -ForegroundColor Green
Write-Host " VulnShop MongoDB Edition Launcher" -ForegroundColor Green  
Write-Host "=====================================" -ForegroundColor Green
Write-Host ""

Write-Host "[1/4] Checking Python environment..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ ERROR: Python not found!" -ForegroundColor Red
    Write-Host "Please install Python 3.7+ and add it to PATH" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[2/4] Checking MongoDB packages..." -ForegroundColor Yellow
try {
    python -c "import pymongo; import bson; print('✅ MongoDB packages available')"
} catch {
    Write-Host "⚠️ MongoDB packages not found, installing..." -ForegroundColor Yellow
    pip install pymongo
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install MongoDB packages" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
}

Write-Host ""
Write-Host "[3/4] Setting up MongoDB database..." -ForegroundColor Yellow
python setup_mongodb.py
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "❌ ERROR: MongoDB setup failed!" -ForegroundColor Red
    Write-Host "Make sure MongoDB is running on localhost:27017" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To start MongoDB:" -ForegroundColor Cyan
    Write-Host "1. Download MongoDB Community Server from https://www.mongodb.com/try/download/community" -ForegroundColor White
    Write-Host "2. Install and run 'mongod' in a terminal" -ForegroundColor White
    Write-Host "3. Or use MongoDB Atlas cloud service" -ForegroundColor White
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host ""
Write-Host "[4/4] Starting VulnShop MongoDB Edition..." -ForegroundColor Yellow
Write-Host ""
Write-Host "⚠️ WARNING: This application contains intentional vulnerabilities!" -ForegroundColor Red
Write-Host "🔥 FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION" -ForegroundColor Red
Write-Host ""
Write-Host "🚀 Starting server..." -ForegroundColor Green
Write-Host ""

python vulnerable_app_mongodb.py

Write-Host ""
Read-Host "Press Enter to exit"
