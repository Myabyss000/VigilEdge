[CmdletBinding()]
param(
    [ValidateSet("full", "custom")]
    [string]$Mode = "full",
    [string]$UpstreamUrl,
    [switch]$SkipChatbot,
    [switch]$OpenBrowser,
    [string]$LocalPackageDir
)

$ErrorActionPreference = "Stop"

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("INFO", "OK", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "OK"    { Write-Host $line -ForegroundColor Green }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "ERROR" { Write-Host $line -ForegroundColor Red }
        default  { Write-Host $line -ForegroundColor Cyan }
    }

    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $line
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-RelaunchArguments {
    $argumentList = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PSCommandPath),
        "-Mode", $Mode
    )

    if ($UpstreamUrl) {
        $argumentList += @("-UpstreamUrl", ('"{0}"' -f $UpstreamUrl))
    }

    if ($SkipChatbot.IsPresent) {
        $argumentList += "-SkipChatbot"
    }

    if ($OpenBrowser.IsPresent) {
        $argumentList += "-OpenBrowser"
    }

    if ($LocalPackageDir) {
        $argumentList += @("-LocalPackageDir", ('"{0}"' -f $LocalPackageDir))
    }

    return ($argumentList -join " ")
}

function Invoke-CommandChecked {
    param(
        [string]$Executable,
        [string[]]$Arguments,
        [string]$StepName
    )

    Write-Status "$StepName" "INFO"
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$StepName failed with exit code $LASTEXITCODE"
    }
}

function Invoke-InstallWithFallback {
    param(
        [string]$PipExe,
        [string]$RequirementsFile,
        [string]$Label,
        [string]$OfflineDir
    )

    Write-Status "Installing dependencies for $Label from $RequirementsFile" "INFO"
    & $PipExe install -r $RequirementsFile --disable-pip-version-check
    if ($LASTEXITCODE -eq 0) {
        Write-Status "$Label dependency install completed (online/default path)." "OK"
        return
    }

    Write-Status "$Label dependency install failed using default pip source." "WARN"

    if (-not $OfflineDir) {
        throw "No offline package directory available for fallback install."
    }

    Write-Status "Retrying $Label install using offline packages in $OfflineDir" "INFO"
    & $PipExe install -r $RequirementsFile --no-index --find-links $OfflineDir --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) {
        throw "$Label offline dependency install failed."
    }

    Write-Status "$Label dependency install completed (offline fallback)." "OK"
}

function Resolve-OfflinePackageDirectory {
    param([string]$RootPath, [string]$UserProvidedPath)

    $candidates = @()

    if ($UserProvidedPath) {
        $candidates += $UserProvidedPath
    }

    $candidates += @(
        (Join-Path $RootPath "offline_packages"),
        (Join-Path $RootPath "offline-packages"),
        (Join-Path $RootPath "packages"),
        (Join-Path $RootPath "wheels")
    )

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            continue
        }

        $hasPackage = Get-ChildItem -Path $candidate -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @(".whl", ".gz", ".zip") } |
            Select-Object -First 1

        if ($hasPackage) {
            return (Resolve-Path $candidate).Path
        }
    }

    return $null
}

function Add-FirewallRules {
    param([int[]]$Ports)

    foreach ($port in $Ports) {
        $displayName = "VigilEdge-OneClick-$port"
        $existing = Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue

        if ($existing) {
            Write-Status "Firewall rule already exists: $displayName" "OK"
            continue
        }

        New-NetFirewallRule `
            -DisplayName $displayName `
            -Direction Inbound `
            -Action Allow `
            -Protocol TCP `
            -LocalPort $port `
            -Profile Private | Out-Null

        Write-Status "Firewall rule created for TCP $port (Private profile)." "OK"
    }
}

function Test-PortAvailable {
    param([int]$Port)

    $conn = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPort -eq $Port } |
        Select-Object -First 1

    if ($conn) {
        $owner = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($owner) {
            throw "Port $Port is already in use by $($owner.ProcessName) (PID $($owner.Id))."
        }

        throw "Port $Port is already in use."
    }
}

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSeconds = 30)

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    while ($stopwatch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $conn = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -eq $Port } |
            Select-Object -First 1

        if ($conn) {
            return $true
        }

        Start-Sleep -Seconds 1
    }

    return $false
}

function Copy-TemplateIfMissing {
    param([string]$TargetFile, [string]$TemplateFile)

    if (Test-Path -LiteralPath $TargetFile) {
        Write-Status "Keeping existing file: $TargetFile" "OK"
        return
    }

    Copy-Item -Path $TemplateFile -Destination $TargetFile -Force
    Write-Status "Created $TargetFile from template." "OK"
}

function New-RandomHex {
    param([int]$ByteCount = 32)

    $bytes = New-Object byte[] $ByteCount
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $_.ToString("x2") })
}

function Set-OrAppendEnvValue {
    param(
        [string]$EnvFile,
        [string]$Key,
        [string]$Value,
        [string[]]$PlaceholderPatterns
    )

    $content = Get-Content -Path $EnvFile
    $linePattern = "^" + [Regex]::Escape($Key) + "="
    $index = -1

    for ($i = 0; $i -lt $content.Count; $i++) {
        if ($content[$i] -match $linePattern) {
            $index = $i
            break
        }
    }

    if ($index -eq -1) {
        Add-Content -Path $EnvFile -Value "$Key=$Value"
        Write-Status "Added new env key $Key in $EnvFile" "OK"
        return
    }

    $currentLine = $content[$index]
    $currentValue = $currentLine.Substring($Key.Length + 1)

    foreach ($placeholder in $PlaceholderPatterns) {
        if ($currentValue -like $placeholder) {
            $content[$index] = "$Key=$Value"
            Set-Content -Path $EnvFile -Value $content
            Write-Status "Updated placeholder value for $Key in $EnvFile" "OK"
            return
        }
    }
}

function Get-AppEnv {
    param([string]$EnvFile)

    if (-not (Test-Path -LiteralPath $EnvFile)) {
        return "development"
    }

    $line = Get-Content -Path $EnvFile | Where-Object { $_ -match "^APP_ENV=" } | Select-Object -First 1
    if (-not $line) {
        return "development"
    }

    $parts = $line -split "=", 2
    if ($parts.Count -lt 2) {
        return "development"
    }

    $value = $parts[1].Trim().ToLowerInvariant()
    if (-not $value) {
        return "development"
    }

    return $value
}

function Start-ServiceWindow {
    param(
        [string]$Title,
        [string]$WorkingDirectory,
        [string]$Command
    )

    $escapedWorkDir = $WorkingDirectory.Replace("'", "''")
    $launcher = "`$Host.UI.RawUI.WindowTitle = '$Title'; Set-Location -LiteralPath '$escapedWorkDir'; $Command"

    Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoExit", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", $launcher) `
        -WorkingDirectory $WorkingDirectory | Out-Null
}

$scriptRoot = Split-Path -Parent $PSCommandPath
Set-Location -LiteralPath $scriptRoot

$logDir = Join-Path $scriptRoot "logs"
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

$script:LogFile = Join-Path $logDir ("oneclick_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))
Write-Status "Starting autonomous one-click deployment." "INFO"
Write-Status "Log file: $script:LogFile" "INFO"

if (-not (Test-Administrator)) {
    Write-Status "Requesting administrator privileges for firewall configuration..." "WARN"
    $argsForRelaunch = Get-RelaunchArguments
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $argsForRelaunch | Out-Null
    exit 0
}

if ($Mode -eq "custom" -and -not $UpstreamUrl) {
    $defaultUrl = "http://localhost:3000"
    $promptValue = Read-Host "Enter your custom upstream website URL [$defaultUrl]"
    if ([string]::IsNullOrWhiteSpace($promptValue)) {
        $UpstreamUrl = $defaultUrl
    } else {
        $UpstreamUrl = $promptValue.Trim()
    }
}

$vigilEdgeDir = Join-Path $scriptRoot "project-null-2.0\vigiledge-collage-project--main\VigilEdge"
$wafDir = Join-Path $vigilEdgeDir "waf"
$vulnerableAppDir = Join-Path $vigilEdgeDir "vulnerable-app"
$threatLoomDir = Join-Path $scriptRoot "ThreatLoom"

$wafVenvDir = Join-Path $vigilEdgeDir "venv"
$threatVenvDir = Join-Path $threatLoomDir "venv"

$wafRequirements = Join-Path $wafDir "requirements.txt"
$threatRequirements = Join-Path $threatLoomDir "requirements.txt"

$threatEnvTemplate = Join-Path $threatLoomDir ".env.example"
$threatEnvFile = Join-Path $threatLoomDir ".env"
$wafEnvTemplate = Join-Path $wafDir ".env.example"
$wafEnvFile = Join-Path $wafDir ".env"

$requiredPaths = @(
    $vigilEdgeDir,
    $wafDir,
    $vulnerableAppDir,
    $threatLoomDir,
    $wafRequirements,
    $threatRequirements,
    $threatEnvTemplate,
    $wafEnvTemplate,
    (Join-Path $scriptRoot "chatbot_server.py")
)

foreach ($path in $requiredPaths) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required path not found: $path"
    }
}

if (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonExe = "py"
    $pythonPrefix = @("-3")
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonExe = "python"
    $pythonPrefix = @()
} else {
    throw "Python 3 was not found. Install Python 3.10+ and rerun deploy_oneclick.ps1"
}

$pythonVersionOutput = (& $pythonExe @pythonPrefix --version) 2>&1
Write-Status "Python detected: $pythonVersionOutput" "OK"

$offlineDir = Resolve-OfflinePackageDirectory -RootPath $scriptRoot -UserProvidedPath $LocalPackageDir
if ($offlineDir) {
    Write-Status "Offline package directory detected: $offlineDir" "OK"
} else {
    Write-Status "No offline package directory detected. Online pip source will be attempted first." "WARN"
}

$portsToCheck = @(5000, 8443)
if ($Mode -eq "full") {
    $portsToCheck += 8080
}
if (-not $SkipChatbot.IsPresent) {
    $portsToCheck += 5001
}

foreach ($port in $portsToCheck) {
    Test-PortAvailable -Port $port
}
Write-Status "Port availability checks passed for: $($portsToCheck -join ', ')" "OK"

Add-FirewallRules -Ports @(5000, 5001, 8080, 8443)

if (-not (Test-Path -LiteralPath (Join-Path $wafVenvDir "Scripts\python.exe"))) {
    Invoke-CommandChecked -Executable $pythonExe -Arguments ($pythonPrefix + @("-m", "venv", $wafVenvDir)) -StepName "Creating WAF virtual environment"
} else {
    Write-Status "WAF virtual environment already exists." "OK"
}

if (-not (Test-Path -LiteralPath (Join-Path $threatVenvDir "Scripts\python.exe"))) {
    Invoke-CommandChecked -Executable $pythonExe -Arguments ($pythonPrefix + @("-m", "venv", $threatVenvDir)) -StepName "Creating ThreatLoom virtual environment"
} else {
    Write-Status "ThreatLoom virtual environment already exists." "OK"
}

$wafPip = Join-Path $wafVenvDir "Scripts\pip.exe"
$wafPython = Join-Path $wafVenvDir "Scripts\python.exe"
$threatPip = Join-Path $threatVenvDir "Scripts\pip.exe"
$threatPython = Join-Path $threatVenvDir "Scripts\python.exe"

Invoke-InstallWithFallback -PipExe $wafPip -RequirementsFile $wafRequirements -Label "WAF" -OfflineDir $offlineDir
Invoke-InstallWithFallback -PipExe $threatPip -RequirementsFile $threatRequirements -Label "ThreatLoom" -OfflineDir $offlineDir

Copy-TemplateIfMissing -TargetFile $threatEnvFile -TemplateFile $threatEnvTemplate
Copy-TemplateIfMissing -TargetFile $wafEnvFile -TemplateFile $wafEnvTemplate

Set-OrAppendEnvValue -EnvFile $threatEnvFile -Key "SECRET_KEY" -Value (New-RandomHex -ByteCount 48) -PlaceholderPatterns @("change*", "", "default*")
Set-OrAppendEnvValue -EnvFile $threatEnvFile -Key "JWT_SECRET" -Value (New-RandomHex -ByteCount 48) -PlaceholderPatterns @("change*", "", "default*")
Set-OrAppendEnvValue -EnvFile $threatEnvFile -Key "FIREWALL_WEBHOOK_SECRET" -Value (New-RandomHex -ByteCount 32) -PlaceholderPatterns @("change*", "", "default*")
Set-OrAppendEnvValue -EnvFile $wafEnvFile -Key "SECRET_KEY" -Value (New-RandomHex -ByteCount 48) -PlaceholderPatterns @("change*", "", "default*")

$threatAppEnv = Get-AppEnv -EnvFile $threatEnvFile
$threatReloadFlag = "--reload"
if ($threatAppEnv -eq "production") {
    Write-Status "APP_ENV=production detected in ThreatLoom .env. Running Alembic migrations..." "INFO"
    Push-Location $threatLoomDir
    try {
        Invoke-CommandChecked -Executable $threatPython -Arguments @("-m", "alembic", "upgrade", "head") -StepName "Running ThreatLoom Alembic migrations"
    } finally {
        Pop-Location
    }
    $threatReloadFlag = ""
} else {
    Write-Status "ThreatLoom APP_ENV is $threatAppEnv. Starting in development mode with --reload." "INFO"
}

if (-not (Test-Path -LiteralPath (Join-Path $threatLoomDir "logs"))) {
    New-Item -Path (Join-Path $threatLoomDir "logs") -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path -LiteralPath (Join-Path $wafDir "logs"))) {
    New-Item -Path (Join-Path $wafDir "logs") -ItemType Directory -Force | Out-Null
}

if (-not $SkipChatbot.IsPresent) {
    $chatbotCommand = "& '$wafPython' 'chatbot_server.py'"
    Start-ServiceWindow -Title "VigilEdge AI Chatbot" -WorkingDirectory $scriptRoot -Command $chatbotCommand
    Start-Sleep -Seconds 2
} else {
    Write-Status "Chatbot startup skipped by user request (-SkipChatbot)." "WARN"
}

$threatloomCommand = "& '$threatPython' -m uvicorn main:app --host 0.0.0.0 --port 8443 $threatReloadFlag"
Start-ServiceWindow -Title "ThreatLoom SOC" -WorkingDirectory $threatLoomDir -Command $threatloomCommand
Start-Sleep -Seconds 3

if ($Mode -eq "full") {
    $demoCommand = "& '$wafPython' 'app.py'"
    Start-ServiceWindow -Title "VigilEdge Demo App" -WorkingDirectory $vulnerableAppDir -Command $demoCommand
    Start-Sleep -Seconds 2

    $wafCommand = ('$env:UPSTREAM_USE_DEMO_TARGET=''true''; $env:UPSTREAM_DEMO_TARGET_URL=''http://localhost:8080''; Remove-Item Env:UPSTREAM_CUSTOM_TARGET_URL -ErrorAction SilentlyContinue; & ''{0}'' -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload' -f $wafPython)
    Start-ServiceWindow -Title "VigilEdge WAF" -WorkingDirectory $wafDir -Command $wafCommand
} else {
    $wafCommand = ('$env:UPSTREAM_USE_DEMO_TARGET=''false''; $env:UPSTREAM_CUSTOM_TARGET_URL=''{0}''; & ''{1}'' -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload' -f $UpstreamUrl, $wafPython)
    Start-ServiceWindow -Title "VigilEdge WAF" -WorkingDirectory $wafDir -Command $wafCommand
}

$portsToVerify = @(8443, 5000)
if ($Mode -eq "full") {
    $portsToVerify += 8080
}
if (-not $SkipChatbot.IsPresent) {
    $portsToVerify += 5001
}

foreach ($port in $portsToVerify) {
    if (Wait-ForPort -Port $port -TimeoutSeconds 45) {
        Write-Status "Service reported on port $port" "OK"
    } else {
        Write-Status "Timed out waiting for service on port $port" "WARN"
    }
}

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "VigilEdge One-Click Deployment Complete" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "WAF  : http://localhost:5000" -ForegroundColor White
Write-Host "SOC  : http://localhost:8443" -ForegroundColor White
if ($Mode -eq "full") {
    Write-Host "Demo : http://localhost:8080" -ForegroundColor White
} else {
    Write-Host "Demo : custom upstream mode enabled -> $UpstreamUrl" -ForegroundColor White
}
if (-not $SkipChatbot.IsPresent) {
    Write-Host "Chat : http://localhost:5001" -ForegroundColor White
} else {
    Write-Host "Chat : skipped (-SkipChatbot)" -ForegroundColor White
}
Write-Host "Log  : $script:LogFile" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
Write-Host ""

if ($OpenBrowser.IsPresent) {
    Start-Process "http://localhost:5000/admin/dashboard" | Out-Null
    Start-Process "http://localhost:8443" | Out-Null
    if ($Mode -eq "full") {
        Start-Process "http://localhost:8080" | Out-Null
    }
    if (-not $SkipChatbot.IsPresent) {
        Start-Process "http://localhost:5001" | Out-Null
    }
}

Write-Status "Deployment flow finished." "OK"
