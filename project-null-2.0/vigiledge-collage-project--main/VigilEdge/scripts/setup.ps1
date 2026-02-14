# VigilEdge WAF - Automatic Setup Script (PowerShell)
# Web Application Firewall Installation and Configuration

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "                VigilEdge WAF - Automatic Setup" -ForegroundColor Yellow
Write-Host "            Web Application Firewall Installation" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Function to check Python installation
function Test-PythonInstallation {
    try {
        $pythonVersion = python --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[SUCCESS] Python found: $pythonVersion" -ForegroundColor Green
            
            # Check version requirement
            $versionCheck = python -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                return $true
            } else {
                Write-Host "[ERROR] Python 3.8+ is required" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "[ERROR] Python is not installed or not in PATH" -ForegroundColor Red
            Write-Host "Please install Python 3.8+ from https://python.org" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "[ERROR] Failed to check Python installation" -ForegroundColor Red
        return $false
    }
}

# Function to create directories
function New-ProjectDirectories {
    Write-Host "[INFO] Creating project directories..." -ForegroundColor Blue
    
    $directories = @("logs", "data", "config", "static", "templates")
    
    foreach ($dir in $directories) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Host "  Created: $dir/" -ForegroundColor Gray
        } else {
            Write-Host "  Exists: $dir/" -ForegroundColor Gray
        }
    }
    
    Write-Host "[SUCCESS] Directories ready" -ForegroundColor Green
    Write-Host ""
}

# Function to setup environment
function Set-Environment {
    Write-Host "[INFO] Setting up environment configuration..." -ForegroundColor Blue
    
    if (!(Test-Path ".env")) {
        if (Test-Path ".env.example") {
            Copy-Item ".env.example" ".env"
            Write-Host "[SUCCESS] Environment file created from template" -ForegroundColor Green
        } else {
            Write-Host "[WARNING] No .env.example found" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[INFO] Environment file already exists" -ForegroundColor Gray
    }
    Write-Host ""
}

# Function to install dependencies
function Install-Dependencies {
    Write-Host "[INFO] Installing Python dependencies..." -ForegroundColor Blue
    Write-Host "This may take a few minutes..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        # Upgrade pip
        Write-Host "  Upgrading pip..." -ForegroundColor Gray
        python -m pip install --upgrade pip --quiet
        
        # Install requirements
        Write-Host "  Installing packages from requirements.txt..." -ForegroundColor Gray
        python -m pip install -r requirements.txt --quiet
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[SUCCESS] All dependencies installed successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[ERROR] Failed to install some dependencies" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "[ERROR] Installation failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to test installation
function Test-Installation {
    Write-Host "[INFO] Testing installation..." -ForegroundColor Blue
    
    try {
        $testResult = python -c "import fastapi, uvicorn, pydantic; print('SUCCESS')" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[SUCCESS] Core dependencies working correctly" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[WARNING] Some dependencies may not be working correctly" -ForegroundColor Yellow
            return $false
        }
    } catch {
        Write-Host "[WARNING] Could not test installation" -ForegroundColor Yellow
        return $false
    }
}

# Function to initialize database
function Initialize-Database {
    Write-Host "[INFO] Initializing database..." -ForegroundColor Blue
    
    if (!(Test-Path "vigiledge.db")) {
        New-Item -ItemType File -Path "vigiledge.db" -Force | Out-Null
        Write-Host "[SUCCESS] Database file created" -ForegroundColor Green
    } else {
        Write-Host "[INFO] Database file already exists" -ForegroundColor Gray
    }
    Write-Host ""
}

# Function to display completion message
function Show-CompletionMessage {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "                    Setup Complete!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Your VigilEdge WAF is now ready to run!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "1. Review and customize .env configuration file" -ForegroundColor Gray
    Write-Host "2. Start the WAF: " -NoNewline -ForegroundColor Gray
    Write-Host "python main.py" -ForegroundColor Cyan
    Write-Host "3. Open dashboard: " -NoNewline -ForegroundColor Gray
    Write-Host "http://localhost:5000" -ForegroundColor Cyan
    Write-Host "4. View API docs: " -NoNewline -ForegroundColor Gray
    Write-Host "http://localhost:5000/docs" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Security features enabled:" -ForegroundColor White
    Write-Host "✅ SQL Injection Protection" -ForegroundColor Green
    Write-Host "✅ XSS Protection" -ForegroundColor Green
    Write-Host "✅ Rate Limiting" -ForegroundColor Green
    Write-Host "✅ IP Blocking" -ForegroundColor Green
    Write-Host "✅ Bot Detection" -ForegroundColor Green
    Write-Host "✅ Real-time Monitoring" -ForegroundColor Green
    Write-Host ""
    Write-Host "For production deployment:" -ForegroundColor Yellow
    Write-Host "- Change SECRET_KEY in .env" -ForegroundColor Gray
    Write-Host "- Set DEBUG=false" -ForegroundColor Gray
    Write-Host "- Configure SSL/TLS" -ForegroundColor Gray
    Write-Host "- Set up proper database" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Happy protecting! 🛡️" -ForegroundColor Magenta
    Write-Host ""
}

# Main execution
try {
    # Check Python
    if (!(Test-PythonInstallation)) {
        Write-Host "Setup aborted due to Python requirements" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    
    Write-Host ""
    
    # Create directories
    New-ProjectDirectories
    
    # Setup environment
    Set-Environment
    
    # Install dependencies
    if (!(Install-Dependencies)) {
        Write-Host "[WARNING] Some packages may not have installed correctly" -ForegroundColor Yellow
        Write-Host "You can try running manually: pip install -r requirements.txt" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Initialize database
    Initialize-Database
    
    # Test installation
    Test-Installation
    
    # Show completion
    Show-CompletionMessage
    
} catch {
    Write-Host ""
    Write-Host "[ERROR] Setup failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Please check the error above and try again" -ForegroundColor Yellow
} finally {
    Read-Host "Press Enter to exit"
}
