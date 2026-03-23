# Experiment Runbook (Windows PowerShell)

This runbook is command-by-command and aligned to your current project layout.

## 1. Open Workspace Root
```powershell
Set-Location "c:\Users\Arghya\OneDrive\Desktop\python projects\vigiledge part 3"
```

## 2. Optional: Clean Previous Runtime Logs
```powershell
if (Test-Path ".\logs") { Remove-Item ".\logs\*" -Force -Recurse -ErrorAction SilentlyContinue }
if (Test-Path ".\ThreatLoom\logs") { Remove-Item ".\ThreatLoom\logs\*" -Force -Recurse -ErrorAction SilentlyContinue }
```

## 3. Start Full Demo Stack (Profile C Candidate)

Preferred startup path (autonomous one-command deployment):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1
```

Legacy startup path (still supported):

```powershell
.\start_demo.bat
```

Wait until services are reachable:
- WAF: http://localhost:5000
- ThreatLoom: http://localhost:8443
- Demo app: http://localhost:8080
- Chatbot: http://localhost:5001

For custom-upstream experiments, use:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\deploy_oneclick.ps1 -Mode custom -UpstreamUrl "http://localhost:3000"
```

## 4. Verify Service Health Quickly
```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/v1/health" -UseBasicParsing | Select-Object StatusCode
Invoke-WebRequest -Uri "http://localhost:5001/health" -UseBasicParsing | Select-Object StatusCode
```

## 5. Benign Traffic Phase
```powershell
1..200 | ForEach-Object {
    Invoke-WebRequest -Uri "http://localhost:5000/" -UseBasicParsing | Out-Null
}
```

## 6. SQLi Traffic Phase
```powershell
$payloads = @(
    "admin' OR '1'='1'--",
    "1 UNION SELECT 1,2,3--",
    "' OR 1=1#",
    "1; DROP TABLE users;--"
)
foreach ($p in $payloads) {
    $u = "http://localhost:5000/protected/admin?username=$([uri]::EscapeDataString($p))"
    try { Invoke-WebRequest -Uri $u -UseBasicParsing | Out-Null } catch {}
}
```

## 7. XSS Traffic Phase
```powershell
$xss = @(
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>"
)
foreach ($p in $xss) {
    $u = "http://localhost:5000/protected/search?q=$([uri]::EscapeDataString($p))"
    try { Invoke-WebRequest -Uri $u -UseBasicParsing | Out-Null } catch {}
}
```

## 8. Traversal and Command-Injection Phase
```powershell
$misc = @(
    "../../etc/passwd",
    "..%2f..%2f..%2fwindows/win.ini",
    "$(whoami)",
    "`"; cat /etc/passwd;`""
)
foreach ($p in $misc) {
    $u = "http://localhost:5000/protected/file?name=$([uri]::EscapeDataString($p))"
    try { Invoke-WebRequest -Uri $u -UseBasicParsing | Out-Null } catch {}
}
```

## 9. Burst Traffic Phase
```powershell
1..500 | ForEach-Object {
    try { Invoke-WebRequest -Uri "http://localhost:5000/" -UseBasicParsing | Out-Null } catch {}
}
```

## 10. Pull WAF Metrics Snapshot
```powershell
Invoke-WebRequest -Uri "http://localhost:5000/api/v1/metrics" -UseBasicParsing | Select-Object -ExpandProperty Content | Out-File ".\research_package\out_waf_metrics_profile_c.json" -Encoding utf8
```

## 11. Pull ThreatLoom Firewall Status (Requires Auth in Normal Flow)
If your ThreatLoom endpoints require login token, capture token first. If not authenticated, skip this step.

```powershell
# Example login flow (edit credentials)
$body = @{ username = "<your_user>"; password = "<your_password>" } | ConvertTo-Json
$resp = Invoke-WebRequest -Uri "http://localhost:8443/api/v1/users/login" -Method Post -Body $body -ContentType "application/json"
$token = ($resp.Content | ConvertFrom-Json).access_token

Invoke-WebRequest -Uri "http://localhost:8443/api/v1/firewall/status" -Headers @{ Authorization = "Bearer $token" } -UseBasicParsing |
Select-Object -ExpandProperty Content | Out-File ".\research_package\out_threatloom_firewall_status_profile_c.json" -Encoding utf8
```

## 12. Export Local Result Summary Template
```powershell
@"
profile,precision,recall,f1,false_positive_rate,p50_ms,p95_ms,throughput_rps,mitigation_delay_ms
profile_c,TBD,TBD,TBD,TBD,TBD,TBD,TBD,TBD
"@ | Out-File ".\research_package\results_template_profile_c.csv" -Encoding utf8
```

## 13. Repeat for Profile A and Profile B
For each profile, update settings/config so only the intended detection components are enabled, then rerun Sections 5-12.

Suggested mapping:
- Profile A: WAF signatures only, no SOC correlation, no playbook response.
- Profile B: WAF + SOC rules/thresholds, no behavioral/correlation playbook automation.
- Profile C: Full hybrid.

## 14. Archive Artifacts
```powershell
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$dest = ".\research_package\artifacts_$ts"
New-Item -ItemType Directory -Path $dest | Out-Null
Copy-Item ".\research_package\out_*" $dest -ErrorAction SilentlyContinue
Copy-Item ".\research_package\results_template_*.csv" $dest -ErrorAction SilentlyContinue
```

## 15. Fill Manuscript Tables
Update:
- [research_package/MANUSCRIPT.md](research_package/MANUSCRIPT.md)
- [research_package/MANUSCRIPT_IEEE_SUBMISSION.md](research_package/MANUSCRIPT_IEEE_SUBMISSION.md)
- [research_package/MANUSCRIPT_PREPRINT.md](research_package/MANUSCRIPT_PREPRINT.md)

with measured values from your artifact files.
