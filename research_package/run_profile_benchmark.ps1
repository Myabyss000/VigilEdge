param(
    [Parameter(Mandatory=$true)]
    [string]$ProfileName
)

Set-Location "c:\Users\Arghya\OneDrive\Desktop\python projects\vigiledge part 3"

$script:results = @()

function Invoke-TestReq {
    param(
        [string]$label,
        [string]$url
    )

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 20
        $sw.Stop()
        $code = [int]$r.StatusCode
    } catch {
        $sw.Stop()
        $resp = $_.Exception.Response
        if ($resp) {
            $code = [int]$resp.StatusCode.value__
        } else {
            $code = 0
        }
    }

    $script:results += [pscustomobject]@{
        label = $label
        status = $code
        latency_ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
    }
}

# Benign
1..80 | ForEach-Object { Invoke-TestReq 'benign' 'http://localhost:5000/' }

# SQLi
$sqli = @(
    "admin' OR '1'='1'--",
    "1 UNION SELECT 1,2,3--",
    "' OR 1=1#",
    "1; DROP TABLE users;--"
)
foreach ($p in $sqli) {
    1..8 | ForEach-Object {
        $u = 'http://localhost:5000/protected/admin?username=' + [uri]::EscapeDataString($p)
        Invoke-TestReq 'sqli' $u
    }
}

# XSS
$xss = @(
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    'javascript:alert(1)',
    '<svg onload=alert(1)>'
)
foreach ($p in $xss) {
    1..8 | ForEach-Object {
        $u = 'http://localhost:5000/protected/search?q=' + [uri]::EscapeDataString($p)
        Invoke-TestReq 'xss' $u
    }
}

# Misc attack-like
$misc = @(
    '../../etc/passwd',
    '..%2f..%2f..%2fwindows/win.ini',
    '$(whoami)',
    '; cat /etc/passwd;'
)
foreach ($p in $misc) {
    1..8 | ForEach-Object {
        $u = 'http://localhost:5000/protected/file?name=' + [uri]::EscapeDataString($p)
        Invoke-TestReq 'misc' $u
    }
}

# Burst
1..180 | ForEach-Object { Invoke-TestReq 'burst' 'http://localhost:5000/' }

$csv = "research_package\benchmark_${ProfileName}_requests.csv"
$script:results | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8

$all = $script:results | Where-Object { $_.status -gt 0 }
$lat = ($all | Select-Object -ExpandProperty latency_ms | Sort-Object)
$count = $lat.Count
$p50 = 0
$p95 = 0
if ($count -gt 0) {
    $p50 = $lat[[math]::Floor(0.50 * ($count - 1))]
    $p95 = $lat[[math]::Floor(0.95 * ($count - 1))]
}

$blocked = ($script:results | Where-Object { $_.status -eq 403 }).Count
$total = $script:results.Count
$sumMs = ($script:results | Measure-Object -Property latency_ms -Sum).Sum
$throughput = 0
if ($sumMs -gt 0) {
    $throughput = [math]::Round(($total / ($sumMs / 1000)), 2)
}

$attacks = $script:results | Where-Object { $_.label -in @('sqli', 'xss', 'misc') }
$tp = ($attacks | Where-Object { $_.status -eq 403 }).Count
$fn = ($attacks | Where-Object { $_.status -ne 403 }).Count
$benign = $script:results | Where-Object { $_.label -eq 'benign' }
$fp = ($benign | Where-Object { $_.status -eq 403 }).Count
$tn = ($benign | Where-Object { $_.status -ne 403 }).Count

$precision = 0
$recall = 0
$f1 = 0
$fpr = 0
if (($tp + $fp) -gt 0) { $precision = [math]::Round($tp / ($tp + $fp), 4) }
if (($tp + $fn) -gt 0) { $recall = [math]::Round($tp / ($tp + $fn), 4) }
if (($precision + $recall) -gt 0) { $f1 = [math]::Round((2 * $precision * $recall) / ($precision + $recall), 4) }
if (($fp + $tn) -gt 0) { $fpr = [math]::Round($fp / ($fp + $tn), 4) }

$summary = [pscustomobject]@{
    profile = $ProfileName
    total_requests = $total
    blocked_403 = $blocked
    p50_ms = $p50
    p95_ms = $p95
    throughput_req_per_sec = $throughput
    tp = $tp
    fp = $fp
    fn = $fn
    tn = $tn
    precision = $precision
    recall = $recall
    f1 = $f1
    false_positive_rate = $fpr
}

$summaryPath = "research_package\benchmark_${ProfileName}_summary.json"
$summary | ConvertTo-Json | Out-File -FilePath $summaryPath -Encoding utf8
$summary | Format-List
