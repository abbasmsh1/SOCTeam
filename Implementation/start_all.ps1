<#
.SYNOPSIS
    SOC System - Unified Startup Script (Robust Version)
.PARAMETER SkipAgents
    Skip tier microservices (monolith-only mode).
.PARAMETER SkipHexstrike
    Skip HexStrike server + MCP launch.
.PARAMETER SkipLiveCapture
    Skip auto-starting live-capture on the Wi-Fi adapter.
.PARAMETER RunFeeder
    Also launch the CSV flow feeder.
.PARAMETER CaptureInterface
    Scapy NPF interface name to capture on (default: Wi-Fi).
#>
param(
    [switch]$SkipAgents,
    [switch]$SkipHexstrike,
    [switch]$SkipLiveCapture,
    [switch]$RunFeeder,
    [string]$CaptureInterface = '\Device\NPF_{B62790C3-44DC-4D2B-9748-4E5D3472D2D4}',
    [int]$CaptureCycleSec = 12
)

# ---------------------------------------------------------------------------
# 0. Configuration
# ---------------------------------------------------------------------------
$ProjectRoot = "E:\IMT\2nd Sem\Project"
$ImplRoot = Join-Path $ProjectRoot "Implementation"
$FrontendRoot = Join-Path $ProjectRoot "frontend"
$LogDir = Join-Path $ImplRoot "logs"
$HexstrikeRoot = Join-Path $ProjectRoot "hexstrike-fresh"
$HexstrikePy = Join-Path $HexstrikeRoot "hexstrike_env\Scripts\python.exe"

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

$env:PYTHONPATH = $ProjectRoot
$PythonExe = Join-Path $ProjectRoot "venv\Scripts\python.exe"

# Load .env
$envFile = Join-Path $ImplRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^\s*([^#][^=\s]+)\s*=\s*(.+)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
    Write-Host "[OK] Loaded environment from .env" -ForegroundColor Green
}

# Always start clean: never inherit stale TIER*_URL envs from the parent shell.
# These are only set below if the matching microservice actually comes up.
Remove-Item Env:TIER1_URL, Env:TIER2_URL, Env:TIER3_URL, Env:WARROOM_URL, Env:REPORTER_URL, Env:REMEDIATION_URL -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Header($title) {
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

function Wait-ForService($url, $name, $timeoutSec = 30) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    Write-Host "  [~] Waiting for $name ($url)..." -ForegroundColor Yellow -NoNewline
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
            if ($r.StatusCode -lt 500) {
                Write-Host " UP" -ForegroundColor Green
                return $true
            }
        }
        catch { }
        Start-Sleep -Milliseconds 1000
        Write-Host "." -NoNewline
    }
    Write-Host " TIMEOUT" -ForegroundColor Red
    return $false
}

# ---------------------------------------------------------------------------
# 0.5 Cleanup Ghost Processes
# ---------------------------------------------------------------------------
Write-Header "Cleaning up previous runs"
# SOC ports + HexStrike (8888) + MCP (usually stdio, but free 8889 if used)
$Ports = @(6050..6056) + @(8888, 8889)
foreach ($p in $Ports) {
    $netstat = netstat -ano | findstr ":$p "
    if ($netstat) {
        $pidStr = ($netstat[-1] -split '\s+')[-1]
        if ($pidStr -match '^\d+$') {
            Write-Host "  [-] Killing process $pidStr on port $p" -ForegroundColor Gray
            Stop-Process -Id ([int]$pidStr) -Force -ErrorAction SilentlyContinue
        }
    }
}
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*IMT*" -or $_.CommandLine -like "*Implementation*" -or $_.CommandLine -like "*hexstrike*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Environment sanitized." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 1. HexStrike Server + MCP (own venv: hexstrike-fresh/hexstrike_env)
# ---------------------------------------------------------------------------
$hexstrikeProcs = @()
if (-not $SkipHexstrike) {
    Write-Header "Starting HexStrike Server + MCP"
    if (-not (Test-Path $HexstrikePy)) {
        Write-Host "  [X] hexstrike_env python not found at $HexstrikePy" -ForegroundColor Red
        Write-Host "      -- skipping HexStrike launch; pipeline will degrade gracefully." -ForegroundColor Yellow
    }
    else {
        # HexStrike server (Flask) on :8888
        $env:HEXSTRIKE_HOST = "127.0.0.1"
        $env:HEXSTRIKE_PORT = "8888"
        $hexSrvProc = Start-Process -FilePath $HexstrikePy `
            -ArgumentList "hexstrike_server.py" `
            -WorkingDirectory $HexstrikeRoot `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $LogDir "hexstrike_server.log") `
            -RedirectStandardError  (Join-Path $LogDir "hexstrike_server_err.log")
        $hexstrikeProcs += $hexSrvProc
        Write-Host "  [+] HexStrike server PID $($hexSrvProc.Id) -> port 8888" -ForegroundColor DarkGray
        Wait-ForService "http://127.0.0.1:8888/health" "HexStrike server" 60 | Out-Null

        # HexStrike MCP client (talks to the server over stdio/HTTP)
        $hexMcpProc = Start-Process -FilePath $HexstrikePy `
            -ArgumentList "hexstrike_mcp.py", "--server", "http://127.0.0.1:8888" `
            -WorkingDirectory $HexstrikeRoot `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput (Join-Path $LogDir "hexstrike_mcp.log") `
            -RedirectStandardError  (Join-Path $LogDir "hexstrike_mcp_err.log")
        $hexstrikeProcs += $hexMcpProc
        Write-Host "  [+] HexStrike MCP    PID $($hexMcpProc.Id)" -ForegroundColor DarkGray
    }
}

# ---------------------------------------------------------------------------
# 2. Agent Microservices
# ---------------------------------------------------------------------------
$agentProcesses = @()
$agents = @()

if (-not $SkipAgents) {
    Write-Header "Starting Agent Microservices"

    $agents = @(
        @{ name = "tier1"; port = 6051 },
        @{ name = "tier2"; port = 6052 },
        @{ name = "tier3"; port = 6053 },
        @{ name = "warroom"; port = 6054 },
        @{ name = "reporter"; port = 6055 },
        @{ name = "remediation"; port = 6056 }
    )

    foreach ($agent in $agents) {
        $pname = $agent.name
        $pport = $agent.port

        $pyArgs = @("-m", "Implementation.src.agent_server", "--agent", $pname, "--port", $pport)

        $stdOut = Join-Path $LogDir "$pname.log"
        $stdErr = Join-Path $LogDir "$($pname)_err.log"

        $proc = Start-Process $PythonExe -ArgumentList $pyArgs `
            -WorkingDirectory $ProjectRoot `
            -PassThru -NoNewWindow `
            -RedirectStandardOutput $stdOut `
            -RedirectStandardError $stdErr

        $agentProcesses += $proc
        Write-Host "  [+] $pname PID $($proc.Id) -> port $pport" -ForegroundColor DarkGray
    }

    Write-Host "`n  Waiting for agents to open ports..." -ForegroundColor Yellow
    $urlVarByName = @{
        "tier1"       = "TIER1_URL"
        "tier2"       = "TIER2_URL"
        "tier3"       = "TIER3_URL"
        "warroom"     = "WARROOM_URL"
        "reporter"    = "REPORTER_URL"
        "remediation" = "REMEDIATION_URL"
    }
    foreach ($agent in $agents) {
        $up = Wait-ForService "http://127.0.0.1:$($agent.port)/health" $agent.name 30
        if ($up) {
            $var = $urlVarByName[$agent.name]
            if ($var) {
                [System.Environment]::SetEnvironmentVariable($var, "http://127.0.0.1:$($agent.port)", "Process")
                Write-Host "    [+] $var -> http://127.0.0.1:$($agent.port)" -ForegroundColor DarkGray
            }
        }
        else {
            Write-Host "    [!] $($agent.name) did not come up -- backend will use the in-process fallback" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 3. IDS Backend Gateway (FastAPI on port 6050)
# ---------------------------------------------------------------------------
Write-Header "Starting IDS Backend Gateway (port 6050)"

$backendArgs = @(
    "-m", "uvicorn", "Implementation.src.IDS.IDS:app",
    "--host", "0.0.0.0", "--port", "6050",
    "--timeout-keep-alive", "5",        # drop idle HTTP keepalive after 5s -- prevents CloseWait buildup
    "--limit-concurrency", "128"         # reject excess load instead of queueing into deadlock
)
$backendProc = Start-Process $PythonExe -ArgumentList $backendArgs `
    -WorkingDirectory $ProjectRoot `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $LogDir "ids_backend.log") `
    -RedirectStandardError  (Join-Path $LogDir "ids_backend_err.log")

Write-Host "  [+] IDS Backend  PID $($backendProc.Id) -> port 6050" -ForegroundColor DarkGray
$backendOk = Wait-ForService "http://127.0.0.1:6050/health" "IDS Backend" 40

# ---------------------------------------------------------------------------
# 4. Frontend (Vite / React on port 5173)
# ---------------------------------------------------------------------------
Write-Header "Starting Frontend (Vite, port 5173)"

$frontendProc = Start-Process npm.cmd -ArgumentList "run dev", "--", "--host", "127.0.0.1" `
    -WorkingDirectory $FrontendRoot `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $LogDir "frontend.log") `
    -RedirectStandardError  (Join-Path $LogDir "frontend_err.log")

Write-Host "  [+] Frontend     PID $($frontendProc.Id) -> port 5173" -ForegroundColor DarkGray
$frontendOk = Wait-ForService "http://127.0.0.1:5173/" "Frontend" 30

# ---------------------------------------------------------------------------
# 5. Auto-start live capture (pipes laptop traffic into the IDS)
# ---------------------------------------------------------------------------
if ($backendOk -and -not $SkipLiveCapture) {
    Write-Header "Starting live network capture"
    $adminKey = [System.Environment]::GetEnvironmentVariable("IDS_ADMIN_API_KEY", "Process")
    if (-not $adminKey) { $adminKey = [System.Environment]::GetEnvironmentVariable("IDS_API_KEY", "Process") }
    if (-not $adminKey) {
        Write-Host "  [!] No IDS_ADMIN_API_KEY/IDS_API_KEY in env; skipping /start-live-capture" -ForegroundColor Yellow
    }
    else {
        $body = @{ interface = $CaptureInterface; duration_per_cycle = $CaptureCycleSec } | ConvertTo-Json -Compress
        try {
            $r = Invoke-WebRequest `
                -Uri "http://127.0.0.1:6050/start-live-capture" `
                -Method POST `
                -Headers @{ "X-API-Key" = $adminKey; "Content-Type" = "application/json" } `
                -Body $body `
                -UseBasicParsing -TimeoutSec 15
            Write-Host "  [+] Live capture started on $CaptureInterface (cycle=$CaptureCycleSec s)" -ForegroundColor Green
            Write-Host "      status: $($r.StatusCode) -- check GET /capture-status" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  [!] /start-live-capture failed: $_" -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Summary
# ---------------------------------------------------------------------------
Write-Header "System Status"

$services = @(
    @{ name = "IDS Backend"; url = "http://127.0.0.1:6050/health" },
    @{ name = "Frontend"; url = "http://127.0.0.1:5173/" }
)
if (-not $SkipHexstrike) {
    $services += @{ name = "HexStrike"; url = "http://127.0.0.1:8888/health" }
}
if (-not $SkipAgents) {
    foreach ($a in $agents) {
        $services += @{ name = "$($a.name) Agent"; url = "http://127.0.0.1:$($a.port)/health" }
    }
}

foreach ($svc in $services) {
    try {
        $r = Invoke-WebRequest -Uri $svc.url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $statusStr = "RUNNING"
        $color = "Green"
    }
    catch {
        $statusStr = "OFFLINE"
        $color = "Red"
    }
    Write-Host ("  {0,-20} {1,-35} {2}" -f $svc.name, $svc.url, $statusStr) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# 7. Optional CSV Feeder
# ---------------------------------------------------------------------------
if ($RunFeeder) {
    Write-Header "Launching CSV Flow Feeder"
    $feederArgs = @("-m", "Implementation.tools.feed_csv_flows", "--priority")
    Start-Process $PythonExe -ArgumentList $feederArgs `
        -WorkingDirectory $ProjectRoot `
        -NoNewWindow
}

Write-Host "`n[OK] SOC System is running." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 8. Keep alive
# ---------------------------------------------------------------------------
try {
    while ($true) {
        Start-Sleep -Seconds 60
        $t = Get-Date -Format "HH:mm:ss"
        Write-Host "[$t] Heartbeat..." -ForegroundColor DarkGray
    }
}
finally {
    Write-Header "Shutting Down"
    # Stop live capture gracefully first so the backend doesn't keep spawning subprocs
    if (-not $SkipLiveCapture) {
        try {
            $adminKey = [System.Environment]::GetEnvironmentVariable("IDS_ADMIN_API_KEY", "Process")
            if ($adminKey) {
                Invoke-WebRequest -Uri "http://127.0.0.1:6050/stop-live-capture" `
                    -Method POST -Headers @{ "X-API-Key" = $adminKey } `
                    -UseBasicParsing -TimeoutSec 5 | Out-Null
            }
        }
        catch { }
    }
    $allProcs = $agentProcesses + $backendProc + $frontendProc + $hexstrikeProcs
    foreach ($p in $allProcs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
