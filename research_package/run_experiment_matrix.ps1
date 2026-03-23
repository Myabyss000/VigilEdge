Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = "c:\Users\Arghya\OneDrive\Desktop\python projects\vigiledge part 3"
$wafDir = Join-Path $root "project-null-2.0\vigiledge-collage-project--main\VigilEdge\waf"
$tlDir = Join-Path $root "ThreatLoom"
$pyVenv = Join-Path $root "project-null-2.0\vigiledge-collage-project--main\VigilEdge\venv\Scripts\python.exe"
$profileRunner = Join-Path $root "research_package\run_repeated_profile.py"
$runSession = Get-Date -Format "run_yyyyMMdd_HHmmss"

# Safer defaults to avoid multi-hour runs if the firewall degrades.
$runnerCommonArgs = @(
    "--trials", "3",
    "--base-url", "http://localhost:5000",
    "--out-dir", "research_package/results",
    "--run-session", $runSession,
    "--timeout", "6",
    "--request-pause-ms", "40",
    "--settle-seconds", "8",
    "--expected-latency-ms", "150",
    "--timeout-rate-estimate", "0.35",
    "--progress-every", "20",
    "--max-status0-ratio", "0.35",
    "--max-consecutive-status0", "12",
    "--min-requests-before-abort", "40"
)

Write-Host "[SESSION] $runSession" -ForegroundColor Cyan

function Stop-PortProcess {
    param([int]$Port)
    $conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $Port }
    foreach ($c in $conns) {
        try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue } catch {}
    }
}

function Wait-Http {
    param([string]$Url, [int]$Retries = 40, [int]$DelaySeconds = 1)
    for ($i=0; $i -lt $Retries; $i++) {
        try {
            $r = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 4
            if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 500) { return $true }
        } catch {}
        Start-Sleep -Seconds $DelaySeconds
    }
    return $false
}

function Start-ThreatLoom {
    param([bool]$BehavioralEnabled, [bool]$CorrelationEnabled)
    Stop-PortProcess -Port 8443
    Start-Sleep -Seconds 1

    $be = if ($BehavioralEnabled) { 'true' } else { 'false' }
    $ce = if ($CorrelationEnabled) { 'true' } else { 'false' }

    $cmd = "Set-Location '$tlDir'; `$env:DETECTION_BEHAVIORAL_ENABLED='$be'; `$env:DETECTION_CORRELATION_ENABLED='$ce'; '$pyVenv' -m uvicorn main:app --host 0.0.0.0 --port 8443"
    Start-Process powershell -ArgumentList "-NoProfile", "-Command", $cmd | Out-Null

    if (-not (Wait-Http -Url "http://localhost:8443/health")) {
        throw "ThreatLoom failed to become healthy on :8443"
    }
}

function Start-Waf {
    param([bool]$ThreatLoomEnabled, [bool]$BotDetectionEnabled)
    Stop-PortProcess -Port 5000
    Start-Sleep -Seconds 1

    $tle = if ($ThreatLoomEnabled) { 'true' } else { 'false' }
    $bde = if ($BotDetectionEnabled) { 'true' } else { 'false' }

    $cmd = "Set-Location '$wafDir'; `$env:UPSTREAM_USE_DEMO_TARGET='true'; `$env:UPSTREAM_DEMO_TARGET_URL='http://localhost:8080'; `$env:THREATLOOM_ENABLED='$tle'; `$env:BOT_DETECTION_ENABLED='$bde'; '$pyVenv' -m uvicorn app:app --host 0.0.0.0 --port 5000"
    Start-Process powershell -ArgumentList "-NoProfile", "-Command", $cmd | Out-Null

    if (-not (Wait-Http -Url "http://localhost:5000/")) {
        throw "WAF failed to become healthy on :5000"
    }
}

function Assert-WafReachable {
    if (-not (Wait-Http -Url "http://localhost:5000/" -Retries 8 -DelaySeconds 1)) {
        throw "WAF is not reachable on :5000. Aborting matrix before traffic generation."
    }
}

Set-Location $root

# Ensure demo app is up (started by user side normally)
if (-not (Wait-Http -Url "http://localhost:8080/" -Retries 15 -DelaySeconds 1)) {
    throw "Demo app is not reachable on :8080. Start it before running the matrix."
}

# Profile A: signature-only WAF (SOC ingestion disabled)
Start-ThreatLoom -BehavioralEnabled $true -CorrelationEnabled $true
Start-Waf -ThreatLoomEnabled $false -BotDetectionEnabled $true
Assert-WafReachable
& $pyVenv $profileRunner --profile "profile_a_signature_only_repeat" @runnerCommonArgs

# Profile B: WAF + SOC rule/threshold only (behavioral/correlation disabled)
Start-ThreatLoom -BehavioralEnabled $false -CorrelationEnabled $false
Start-Waf -ThreatLoomEnabled $true -BotDetectionEnabled $true
Assert-WafReachable
& $pyVenv $profileRunner --profile "profile_b_rules_threshold_repeat" @runnerCommonArgs

# Profile C: full hybrid (behavioral/correlation enabled)
Start-ThreatLoom -BehavioralEnabled $true -CorrelationEnabled $true
Start-Waf -ThreatLoomEnabled $true -BotDetectionEnabled $true
Assert-WafReachable
& $pyVenv $profileRunner --profile "profile_c_full_hybrid_repeat" @runnerCommonArgs

# Profile B tuned: same as B but bot detection relaxed to reduce benign overblocking
Start-ThreatLoom -BehavioralEnabled $false -CorrelationEnabled $false
Start-Waf -ThreatLoomEnabled $true -BotDetectionEnabled $false
Assert-WafReachable
& $pyVenv $profileRunner --profile "profile_b_tuned_repeat" @runnerCommonArgs

Write-Host "Experiment matrix complete. Results in research_package/results/$runSession" -ForegroundColor Green
