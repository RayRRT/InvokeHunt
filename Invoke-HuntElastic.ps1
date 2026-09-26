#Requires -Version 5.1
<#
.SYNOPSIS
    Invoke-HuntElastic - Test a binary against Elastic Security detections.
.DESCRIPTION
    Interactive pipeline: YARA Scan -> PE Analysis -> Deliver (HTTP) -> Elastic Detection -> Verdict.
    Receives a pre-compiled binary and tests it against Elastic Security (Elastic Defend).
.EXAMPLE
    .\Invoke-HuntElastic.ps1 -Binary .\loader.exe
    .\Invoke-HuntElastic.ps1 -Binary .\loader.exe -SkipElastic
    .\Invoke-HuntElastic.ps1 -Binary .\loader.exe -Port 9090 -WaitSeconds 60
#>
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$ConfigPath   = ".\config.json",
    [switch]$SkipElastic,
    [int]$WaitSeconds     = 0,
    [int]$Port            = 0
)

$ErrorActionPreference = "Stop"

# ===================================================================
#  UI HELPERS
# ===================================================================

function Write-Banner {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host ""
    Write-Host "  ==============================================================" -ForegroundColor Cyan
    Write-Host "                   RTO2 LOADER TEST PIPELINE                     " -ForegroundColor Cyan
    Write-Host ""                                                                  -ForegroundColor Cyan
    Write-Host "        YARA  -->  PE Check  -->  Deliver  -->  Elastic            " -ForegroundColor Cyan
    Write-Host "  ==============================================================" -ForegroundColor Cyan
    Write-Host "  $ts" -ForegroundColor DarkGray
}

function Write-Phase {
    param([string]$Num, [string]$Title)
    Write-Host ""
    Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  [$Num] $Title" -ForegroundColor Cyan
    Write-Host "  --------------------------------------------------------------" -ForegroundColor DarkGray
}

function Write-Ok   { param([string]$m) Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Fail { param([string]$m) Write-Host "  [-] $m" -ForegroundColor Red }
function Write-Info { param([string]$m) Write-Host "  [*] $m" -ForegroundColor Gray }

function Write-Prompt {
    param([string]$Question)
    Write-Host ""
    Write-Host "  [?] $Question" -ForegroundColor Yellow
    Write-Host ""
    $answer = Read-Host "      >"
    return $answer.Trim()
}

function Write-Menu {
    param([string]$Question, [string[]]$Options)
    Write-Host ""
    Write-Host "  [?] $Question" -ForegroundColor Yellow
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "      [$($i + 1)] $($Options[$i])" -ForegroundColor White
    }
    Write-Host ""
    $choice = Read-Host "      >"
    return $choice.Trim()
}

function Write-Card {
    param(
        [string]$Label,
        [string]$Color,
        [hashtable[]]$Fields
    )
    $w = 64
    $hdr = "+-- $Label " + ("-" * ($w - $Label.Length - 6)) + "+"
    Write-Host ""
    Write-Host "  $hdr" -ForegroundColor $Color
    foreach ($f in $Fields) {
        $name = $f.Name
        $val  = $f.Value
        $vc   = if ($f.Color) { $f.Color } else { "White" }
        $line = "${name}: $val"
        $pad  = $w - $line.Length - 6
        if ($pad -lt 0) {
            $trimLen = $val.Length + $pad - 3
            if ($trimLen -lt 1) { $trimLen = 1 }
            $val  = $val.Substring(0, $trimLen) + "..."
            $line = "${name}: $val"
            $pad  = $w - $line.Length - 6
            if ($pad -lt 0) { $pad = 0 }
        }
        Write-Host "  | " -NoNewline -ForegroundColor $Color
        Write-Host "${name}: " -NoNewline -ForegroundColor Gray
        Write-Host "$val" -NoNewline -ForegroundColor $vc
        Write-Host (" " * $pad) -NoNewline
        Write-Host " |" -ForegroundColor $Color
    }
    $footer = "+" + ("-" * ($w - 2)) + "+"
    Write-Host "  $footer" -ForegroundColor $Color
}

function Get-LocalIP {
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
            Sort-Object -Property InterfaceIndex |
            Select-Object -First 1).IPAddress
        return $ip
    }
    catch { return "YOUR-IP" }
}

# ===================================================================
#  LOAD CONFIG
# ===================================================================

if (-not (Test-Path $ConfigPath)) {
    Write-Host ""
    Write-Fail "Config not found: $ConfigPath"
    Write-Info "Run from the rto2-tester directory or pass -ConfigPath"
    exit 1
}

$cfg = Get-Content $ConfigPath -Raw | ConvertFrom-Json

if ($WaitSeconds -gt 0) { $cfg.elastic.wait_seconds = $WaitSeconds }
if ($Port -gt 0)        { $cfg.delivery.http_port = $Port }

$resultsDir = $cfg.output.results_dir
if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir -Force | Out-Null
}

$report = @{
    timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    binary    = ""
    phases    = @{}
    verdict   = ""
}

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

Write-Banner

# ===================================================================
#  VALIDATE BINARY
# ===================================================================

if (-not (Test-Path $Binary)) {
    Write-Host ""
    Write-Fail "Binary not found: $Binary"
    exit 1
}

$binaryPath = (Resolve-Path $Binary).Path

$report.binary = $binaryPath
$binaryName = Split-Path $binaryPath -Leaf

# ===================================================================
#  PHASE 2: YARA STATIC ANALYSIS
# ===================================================================

Write-Phase "1/5" "YARA STATIC ANALYSIS"

$yaraResult = $null

if (-not (Test-Path $cfg.yara.rules_dir)) {
    Write-Warn "Rules directory not found: $($cfg.yara.rules_dir)"
    Write-Info "Clone: git clone --depth 1 https://github.com/elastic/protections-artifacts C:\tools\protections-artifacts"
    $report.phases["yara"] = @{ status = "skipped"; reason = "rules not found" }
}
else {
    Write-Info "Launching YARA scan..."
    Write-Host ""

    $jsonRaw = & python $cfg.yara.scanner_script --json $binaryPath $cfg.yara.rules_dir 2>$null
    if ($LASTEXITCODE -ne $null) {
        try {
            $yaraResult = $jsonRaw | Out-String | ConvertFrom-Json
        }
        catch {
            $yaraResult = $null
        }
    }

    if (-not $yaraResult) {
        Write-Warn "JSON mode failed, running interactive scan..."
        Write-Host ""
        & python $cfg.yara.scanner_script $binaryPath $cfg.yara.rules_dir
        $report.phases["yara"] = @{ status = "ran_interactive" }
    }
    else {
        $report.phases["yara"] = @{
            status        = $yaraResult.status
            rules_scanned = $yaraResult.rules_scanned
            rules_errors  = $yaraResult.rules_errors
            hits          = $yaraResult.hits
            entropy       = $yaraResult.entropy
            elapsed_sec   = $yaraResult.elapsed_sec
        }

        Write-Info "Binary:  $binaryPath"
        Write-Info "Size:    $([math]::Round($yaraResult.size_bytes / 1KB, 1)) KB"
        Write-Info "Entropy: $($yaraResult.entropy) / 8.0"
        Write-Info "Scanned: $($yaraResult.rules_scanned) rules in $($yaraResult.elapsed_sec)s"

        if ($yaraResult.status -eq "clean") {
            Write-Host ""
            Write-Ok "CLEAN - 0 YARA hits"
        }
        else {
            Write-Host ""
            Write-Fail "$($yaraResult.hits) YARA signature(s) matched!"

            foreach ($det in $yaraResult.details) {
                $sevColor = switch ($det.severity) {
                    "critical" { "Red" }
                    "high"     { "Red" }
                    "medium"   { "Yellow" }
                    default    { "Gray" }
                }
                $tagsStr = if ($det.tags) { ($det.tags | Select-Object -First 5) -join ", " } else { "none" }
                $fields = @(
                    @{ Name = "Rule";     Value = $det.rule;     Color = "White" }
                    @{ Name = "Source";   Value = $det.file;     Color = "Gray" }
                    @{ Name = "Severity"; Value = $det.severity; Color = $sevColor }
                    @{ Name = "Tags";     Value = $tagsStr;      Color = "Gray" }
                )
                if ($det.strings -and $det.strings.Count -gt 0) {
                    $fields += @{ Name = "Strings"; Value = "$($det.strings.Count) string(s) matched"; Color = "Yellow" }
                }
                $desc = $null
                if ($det.meta) { $desc = $det.meta.description }
                if ($desc) {
                    $fields += @{ Name = "Info"; Value = $desc; Color = "DarkGray" }
                }
                Write-Card -Label "DETECTION" -Color "Red" -Fields $fields
            }

            $answer = Write-Prompt "Static signatures detected. Continue to PE analysis? (y/n)"
            if ($answer -ne "y") {
                Write-Info "Aborted by user."
                $report.verdict = "ABORTED - Static signatures detected"
                $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json") -Encoding utf8
                exit 0
            }
        }
    }
}

# ===================================================================
#  PHASE 3: PE METADATA ANALYSIS
# ===================================================================

Write-Phase "2/5" "PE METADATA ANALYSIS"

$fileInfo    = Get-Item $binaryPath
$sizeKB      = [math]::Round($fileInfo.Length / 1KB, 1)
$versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($binaryPath)
$sig         = Get-AuthenticodeSignature $binaryPath
$isSigned    = ($sig.Status -eq "Valid")

$entropy = 0
if ($yaraResult -and $yaraResult.entropy) {
    $entropy = $yaraResult.entropy
}
else {
    try {
        $entropyOut = & python -c "import math,collections,sys;d=open(sys.argv[1],'rb').read();f=collections.Counter(d);n=len(d);print(round(-sum((c/n)*math.log2(c/n) for c in f.values()),2))" $binaryPath 2>$null
        $entropy = [double]$entropyOut
    }
    catch { $entropy = -1 }
}

$entropyColor = if ($entropy -gt 7.5) { "Red" } elseif ($entropy -gt 7.0) { "Yellow" } else { "Green" }

$peFields = @(
    @{ Name = "Size";    Value = "$sizeKB KB";     Color = "White" }
    @{ Name = "Entropy"; Value = "$entropy / 8.0"; Color = $entropyColor }
    @{ Name = "Signed";  Value = "$isSigned";      Color = $(if ($isSigned) { "Green" } else { "Yellow" }) }
)
if ($versionInfo.FileDescription) {
    $peFields += @{ Name = "Description"; Value = $versionInfo.FileDescription; Color = "White" }
}
if ($versionInfo.CompanyName) {
    $peFields += @{ Name = "Company"; Value = $versionInfo.CompanyName; Color = "White" }
}
if ($versionInfo.OriginalFilename) {
    $peFields += @{ Name = "OrigName"; Value = $versionInfo.OriginalFilename; Color = "White" }
}

Write-Card -Label "PE INFO" -Color "Cyan" -Fields $peFields

$warnings = @()
if ($sizeKB -lt 10)       { $warnings += "Very small binary (<10KB) - may look suspicious to EDR" }
if ($sizeKB -gt 5000)     { $warnings += "Large binary (>5MB) - may attract attention" }
if (-not $isSigned)        { $warnings += "Unsigned binary - some EDRs flag unsigned executables" }
if ($entropy -gt 7.5)     { $warnings += "Very high entropy ($entropy) - likely detected as packed" }
elseif ($entropy -gt 7.0) { $warnings += "Elevated entropy ($entropy) - may trigger packing heuristics" }

if ($warnings.Count -gt 0) {
    Write-Host ""
    foreach ($w in $warnings) { Write-Warn $w }
}
else {
    Write-Host ""
    Write-Ok "No PE metadata red flags"
}

$report.phases["pe_analysis"] = @{
    size_kb  = $sizeKB
    entropy  = $entropy
    signed   = $isSigned
    warnings = $warnings
}

# ===================================================================
#  PHASE 4: DELIVERY
# ===================================================================

Write-Phase "3/5" "DELIVERY"

$executionTimestamp = $null

if ($SkipElastic) {
    Write-Info "Elastic check skipped (-SkipElastic), no delivery needed"
    $report.phases["delivery"] = @{ status = "skipped" }
}
else {
    $yaraStatus = if ($report.phases["yara"]) { $report.phases["yara"].status } else { "skipped" }
    if ($yaraStatus -eq "detected") {
        Write-Warn "Binary has YARA detections - delivering anyway (you chose to continue)"
    }

    # -- Helper: display download commands box --
    function Show-DownloadBox {
        param([string]$Url, [string]$Name, [int]$HttpPort)
        Write-Host ""
        Write-Host "  +-- HTTP SERVER ACTIVE ----------------------------------------+" -ForegroundColor Green
        Write-Host "  |                                                               |" -ForegroundColor Green
        Write-Host "  | " -NoNewline -ForegroundColor Green
        Write-Host "Run one of these on the Elastic VM:                          " -NoNewline -ForegroundColor Gray
        Write-Host "|" -ForegroundColor Green
        Write-Host "  |                                                               |" -ForegroundColor Green
        $psCmd = "iwr $Url -OutFile $Name"
        $pad1 = 59 - $psCmd.Length; if ($pad1 -lt 0) { $pad1 = 0 }
        Write-Host "  | " -NoNewline -ForegroundColor Green
        Write-Host "PS> " -NoNewline -ForegroundColor DarkGray
        Write-Host "$psCmd$(" " * $pad1)" -NoNewline -ForegroundColor Yellow
        Write-Host " |" -ForegroundColor Green
        Write-Host "  |                                                               |" -ForegroundColor Green
        $curlCmd = "curl $Url -o $Name"
        $pad2 = 59 - $curlCmd.Length; if ($pad2 -lt 0) { $pad2 = 0 }
        Write-Host "  | " -NoNewline -ForegroundColor Green
        Write-Host "sh> " -NoNewline -ForegroundColor DarkGray
        Write-Host "$curlCmd$(" " * $pad2)" -NoNewline -ForegroundColor Yellow
        Write-Host " |" -ForegroundColor Green
        Write-Host "  |                                                               |" -ForegroundColor Green
        Write-Host "  +---------------------------------------------------------------+" -ForegroundColor Green
    }

    # -- Helper: execution confirmation loop --
    function Wait-ExecutionConfirmation {
        param([int]$DefaultWait)
        Write-Host ""
        Write-Host "  STEP 2: Execute on VM" -ForegroundColor Cyan
        Write-Info "Run the binary on the Elastic VM."
        Write-Info "After you confirm, the pipeline will wait and query Elastic for detections."

        while ($true) {
            $step = Write-Menu "Have you executed the binary?" @(
                "Yes - check detections now (${DefaultWait}s wait)"
                "Yes - but use a custom wait time"
                "Not yet - I need more time"
                "Abort pipeline"
            )
            switch ($step) {
                "1" {
                    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                    Write-Ok "Execution confirmed"
                    return @{ timestamp = $ts; wait = $DefaultWait }
                }
                "2" {
                    $custom = Read-Host "      Wait time in seconds"
                    try {
                        $customInt = [int]$custom
                        $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Write-Ok "Execution confirmed - will wait ${customInt}s"
                        return @{ timestamp = $ts; wait = $customInt }
                    }
                    catch { Write-Warn "Invalid number, try again" }
                }
                "3" {
                    Write-Info "Take your time. Select again when ready."
                }
                default {
                    return $null
                }
            }
        }
    }

    $choice = Write-Menu "How would you like to deliver the binary to the Elastic VM?" @(
        "Start HTTP server (recommended)"
        "Binary is already on the target"
        "Abort pipeline"
    )

    $serverProc = $null

    switch ($choice) {
        "1" {
            $httpPort = $cfg.delivery.http_port
            $localIP  = Get-LocalIP
            $serveDir = Split-Path $binaryPath -Parent

            Write-Info "Starting HTTP server on port $httpPort..."

            $serverProc = Start-Process -FilePath python `
                -ArgumentList "-m http.server $httpPort --directory `"$serveDir`" --bind 0.0.0.0" `
                -PassThru -WindowStyle Hidden

            Start-Sleep -Seconds 2

            if ($serverProc.HasExited) {
                Write-Fail "HTTP server failed to start (port $httpPort may be in use)"
                Write-Info "Try a different port with -Port <number>"
                $report.phases["delivery"] = @{ status = "failed" }
                exit 1
            }

            $downloadUrl = "http://${localIP}:${httpPort}/${binaryName}"
            Write-Ok "HTTP server running on port $httpPort"

            Show-DownloadBox -Url $downloadUrl -Name $binaryName -HttpPort $httpPort

            # --- Step 1: Download ---
            Write-Host ""
            Write-Host "  STEP 1: Download on VM" -ForegroundColor Cyan

            $downloaded = $false
            while (-not $downloaded) {
                $step = Write-Menu "Have you downloaded the binary on the VM?" @(
                    "Yes - proceed to execution step"
                    "Verify server is reachable"
                    "Show download commands again"
                    "Abort pipeline"
                )
                switch ($step) {
                    "1" {
                        $downloaded = $true
                        Write-Ok "Download confirmed"
                    }
                    "2" {
                        Write-Info "Testing http://localhost:$httpPort/ ..."
                        try {
                            $test = Invoke-WebRequest "http://localhost:$httpPort/" -TimeoutSec 5 -UseBasicParsing
                            Write-Ok "Server responding (HTTP $($test.StatusCode))"
                            Write-Info "If the VM can't reach it, check firewall rules for port $httpPort"
                        }
                        catch {
                            Write-Fail "Server not responding: $($_.Exception.Message)"
                        }
                    }
                    "3" {
                        Show-DownloadBox -Url $downloadUrl -Name $binaryName -HttpPort $httpPort
                    }
                    default {
                        try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
                        Write-Info "HTTP server stopped. Pipeline aborted."
                        $report.verdict = "ABORTED - User cancelled at download step"
                        $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json") -Encoding utf8
                        exit 0
                    }
                }
            }

            # --- Step 2: Execute ---
            $execResult = Wait-ExecutionConfirmation -DefaultWait $cfg.elastic.wait_seconds

            if (-not $execResult) {
                try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
                Write-Info "HTTP server stopped. Pipeline aborted."
                $report.verdict = "ABORTED - User cancelled at execution step"
                $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json") -Encoding utf8
                exit 0
            }

            $executionTimestamp      = $execResult.timestamp
            $cfg.elastic.wait_seconds = $execResult.wait

            try { Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue } catch {}
            Write-Ok "HTTP server stopped"

            $report.phases["delivery"] = @{
                status    = "http"
                port      = $httpPort
                url       = $downloadUrl
                timestamp = $executionTimestamp
            }
        }
        "2" {
            Write-Ok "Binary is already on the target VM"

            $execResult = Wait-ExecutionConfirmation -DefaultWait $cfg.elastic.wait_seconds

            if (-not $execResult) {
                Write-Info "Pipeline aborted."
                $report.verdict = "ABORTED - User cancelled at execution step"
                $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json") -Encoding utf8
                exit 0
            }

            $executionTimestamp      = $execResult.timestamp
            $cfg.elastic.wait_seconds = $execResult.wait

            $report.phases["delivery"] = @{ status = "manual"; timestamp = $executionTimestamp }
        }
        default {
            Write-Info "Pipeline aborted by user."
            $report.verdict = "ABORTED - User cancelled delivery"
            $report | ConvertTo-Json -Depth 10 | Out-File (Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json") -Encoding utf8
            exit 0
        }
    }

    # ===============================================================
    #  PHASE 5: ELASTIC DETECTION CHECK
    # ===============================================================

    Write-Phase "4/5" "ELASTIC DETECTION CHECK"

    $esConfigured = ($cfg.elastic.es_url -and
                     $cfg.elastic.es_url -ne "https://YOUR-ID.es.cloud.elastic.co:9243" -and
                     $cfg.elastic.api_key -and
                     $cfg.elastic.api_key -ne "YOUR-API-KEY-BASE64")

    if (-not $esConfigured) {
        Write-Warn "Elastic not configured in config.json"
        Write-Info "Set elastic.es_url and elastic.api_key to enable this phase"
        $report.phases["elastic"] = @{ status = "not_configured" }
    }
    else {
        $waitSec = $cfg.elastic.wait_seconds
        Write-Info "Waiting ${waitSec}s for Elastic to process telemetry..."

        for ($i = $waitSec; $i -gt 0; $i -= 5) {
            $done  = [math]::Floor((($waitSec - $i) / $waitSec) * 20)
            $left  = 20 - $done
            $bar   = ("#" * $done) + ("." * $left)
            Write-Host "`r  [*] [$bar] ${i}s remaining   " -NoNewline -ForegroundColor Gray
            Start-Sleep -Seconds ([math]::Min(5, $i))
        }
        Write-Host "`r  [*] [####################] Done.                " -ForegroundColor Gray

        # PS 5.1 TLS cert bypass for Elastic Cloud
        try {
            if (-not ([System.Management.Automation.PSTypeName]"TrustAllCertsPolicy").Type) {
                Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
"@
            }
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        catch {}

        $headers = @{
            "Authorization" = "ApiKey $($cfg.elastic.api_key)"
            "Content-Type"  = "application/json"
        }

        $elasticResults = @{
            alerts   = @()
            proc     = 0
            dll      = 0
            query_ok = $true
        }

        # -- Alerts --
        Write-Info "Querying security alerts..."
        try {
            $body = @{
                query = @{ bool = @{ must = @(
                    @{ range = @{ "@timestamp" = @{ gte = $executionTimestamp } } }
                )}}
                size = 50
                sort = @(@{ "@timestamp" = "desc" })
            } | ConvertTo-Json -Depth 10

            $resp = Invoke-RestMethod -Uri "$($cfg.elastic.es_url)/.alerts-security.alerts-default/_search" `
                -Method POST -Headers $headers -Body $body

            foreach ($hit in $resp.hits.hits) {
                $src = $hit._source
                $ruleName = $src.'kibana.alert.rule.name'
                $severity = $src.'kibana.alert.severity'
                $procName = "N/A"
                if ($src.process -and $src.process.name) { $procName = $src.process.name }

                $technique = "N/A"
                $threat = $src.'kibana.alert.rule.threat'
                if ($threat -and $threat.Count -gt 0) {
                    $tech = $threat[0].technique
                    if ($tech -and $tech.Count -gt 0) {
                        $technique = "$($tech[0].id) - $($tech[0].name)"
                    }
                }

                $sevColor = switch ($severity) {
                    "critical" { "Red" }
                    "high"     { "Red" }
                    "medium"   { "Yellow" }
                    default    { "Gray" }
                }

                Write-Card -Label "ALERT" -Color "Red" -Fields @(
                    @{ Name = "Rule";      Value = $ruleName;  Color = "White" }
                    @{ Name = "Severity";  Value = $severity;  Color = $sevColor }
                    @{ Name = "Process";   Value = $procName;  Color = "Gray" }
                    @{ Name = "Technique"; Value = $technique; Color = "Gray" }
                )

                $elasticResults.alerts += @{
                    rule      = $ruleName
                    severity  = $severity
                    process   = $procName
                    technique = $technique
                }
            }

            if ($resp.hits.hits.Count -eq 0) {
                Write-Ok "No security alerts triggered"
            }
            else {
                Write-Host ""
                Write-Fail "$($resp.hits.hits.Count) alert(s) triggered (see cards above)"
            }
        }
        catch {
            Write-Warn "Alert query failed: $($_.Exception.Message)"
            $elasticResults.query_ok = $false
        }

        # -- Process events --
        Write-Info "Querying process events..."
        try {
            $body = @{
                query = @{ bool = @{ must = @(
                    @{ match = @{ "process.name" = $binaryName } }
                    @{ range = @{ "@timestamp" = @{ gte = $executionTimestamp } } }
                )}}
                size = 0
                track_total_hits = $true
            } | ConvertTo-Json -Depth 10

            $resp = Invoke-RestMethod -Uri "$($cfg.elastic.es_url)/.ds-logs-endpoint.events.process-*/_search" `
                -Method POST -Headers $headers -Body $body
            $elasticResults.proc = $resp.hits.total.value
            Write-Info "$($elasticResults.proc) process event(s) logged"
        }
        catch { Write-Warn "Process event query failed (non-critical)" }

        # -- DLL events --
        Write-Info "Querying library load events..."
        try {
            $body = @{
                query = @{ bool = @{ must = @(
                    @{ match = @{ "process.name" = $binaryName } }
                    @{ range = @{ "@timestamp" = @{ gte = $executionTimestamp } } }
                )}}
                size = 0
                track_total_hits = $true
            } | ConvertTo-Json -Depth 10

            $resp = Invoke-RestMethod -Uri "$($cfg.elastic.es_url)/.ds-logs-endpoint.events.library-*/_search" `
                -Method POST -Headers $headers -Body $body
            $elasticResults.dll = $resp.hits.total.value
            Write-Info "$($elasticResults.dll) DLL load event(s) logged"
        }
        catch { Write-Warn "Library event query failed (non-critical)" }

        $report.phases["elastic"] = $elasticResults
    }
}

# ===================================================================
#  PHASE 6: VERDICT
# ===================================================================

Write-Phase "5/5" "VERDICT"

$yPhase = $report.phases["yara"]
$ePhase = $report.phases["elastic"]
$pPhase = $report.phases["pe_analysis"]

$yStatus     = if ($yPhase) { $yPhase.status } else { "skipped" }
$yaraClean   = ($yStatus -eq "clean") -or ($yStatus -eq "skipped")
$yaraHits    = if ($yPhase -and $yPhase.hits) { $yPhase.hits } else { 0 }

$eSkipped    = $true
$alertCount  = 0
$alertsClean = $true
if ($ePhase -and $ePhase.status -ne "not_configured" -and $ePhase.status -ne "skipped") {
    $eSkipped    = $false
    $alertCount  = $ePhase.alerts.Count
    $alertsClean = ($alertCount -eq 0)
}

$peWarns = if ($pPhase -and $pPhase.warnings) { $pPhase.warnings.Count } else { 0 }

# Build verdict table
Write-Host ""
Write-Host "  ==============================================================" -ForegroundColor White
Write-Host "                        TEST RESULTS                             " -ForegroundColor White
Write-Host "  ==============================================================" -ForegroundColor White
Write-Host ""

# Row: YARA
Write-Host "   YARA Static     : " -NoNewline -ForegroundColor Gray
if ($yStatus -eq "clean") {
    Write-Host "PASS" -NoNewline -ForegroundColor Green
    Write-Host "      0 hits" -ForegroundColor DarkGray
}
elseif ($yStatus -eq "skipped") {
    Write-Host "SKIP" -NoNewline -ForegroundColor DarkGray
    Write-Host "      not configured" -ForegroundColor DarkGray
}
else {
    Write-Host "FAIL" -NoNewline -ForegroundColor Red
    Write-Host "      $yaraHits hit(s)" -ForegroundColor Red
}

# Row: PE
Write-Host "   PE Metadata     : " -NoNewline -ForegroundColor Gray
if ($peWarns -eq 0) {
    Write-Host "OK" -NoNewline -ForegroundColor Green
    Write-Host "        no red flags" -ForegroundColor DarkGray
}
else {
    Write-Host "WARN" -NoNewline -ForegroundColor Yellow
    Write-Host "      $peWarns warning(s)" -ForegroundColor Yellow
}

# Row: Elastic
Write-Host "   Elastic Alerts  : " -NoNewline -ForegroundColor Gray
if ($eSkipped -or $SkipElastic) {
    Write-Host "SKIP" -NoNewline -ForegroundColor DarkGray
    Write-Host "      not checked" -ForegroundColor DarkGray
}
elseif ($alertsClean) {
    Write-Host "PASS" -NoNewline -ForegroundColor Green
    Write-Host "      0 alerts" -ForegroundColor DarkGray
}
else {
    Write-Host "FAIL" -NoNewline -ForegroundColor Red
    Write-Host "      $alertCount alert(s)" -ForegroundColor Red
}

# Row: Telemetry
if (-not $eSkipped -and -not $SkipElastic -and $ePhase.query_ok) {
    Write-Host "   Telemetry       : " -NoNewline -ForegroundColor Gray
    Write-Host "INFO" -NoNewline -ForegroundColor DarkGray
    Write-Host "      $($ePhase.proc) proc / $($ePhase.dll) dll events" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  --------------------------------------------------------------" -ForegroundColor White

# Overall verdict
if ($yaraClean -and $alertsClean -and -not $eSkipped) {
    $verdict = "CLEAN - No detections across all phases"
    $vColor  = "Green"
}
elseif ($yaraClean -and ($eSkipped -or $SkipElastic)) {
    $verdict = "PARTIAL - YARA clean, Elastic not checked"
    $vColor  = "Yellow"
}
elseif (-not $yaraClean -and -not $alertsClean) {
    $verdict = "DETECTED - Static (YARA) + Behavioral (Elastic)"
    $vColor  = "Red"
}
elseif (-not $yaraClean) {
    $verdict = "DETECTED - Static signatures (YARA)"
    $vColor  = "Red"
}
elseif (-not $alertsClean) {
    $verdict = "DETECTED - Behavioral (Elastic)"
    $vColor  = "Red"
}
else {
    $verdict = "CLEAN - YARA passed, Elastic clear"
    $vColor  = "Green"
}

Write-Host "   VERDICT: " -NoNewline -ForegroundColor White
Write-Host $verdict -ForegroundColor $vColor

Write-Host ""
Write-Host "  ==============================================================" -ForegroundColor White

$report.verdict = $verdict

# ===================================================================
#  SAVE REPORT
# ===================================================================

$reportFile = Join-Path $resultsDir "report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
$report | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding utf8

Write-Host ""
Write-Info "Report saved: $reportFile"
Write-Host ""
