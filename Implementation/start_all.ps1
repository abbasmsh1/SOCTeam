<#
.SYNOPSIS
    SOC System - Unified Startup Script (Robust Version)
#>
param(
    [switch]$SkipAgents,
    [switch]$RunFeeder
)

# ---------------------------------------------------------------------------
# 0. Configuration
# ---------------------------------------------------------------------------
$ProjectRoot = "E:\IMT\2nd Sem\Project"
$ImplRoot = Join-Path $ProjectRoot "Implementation"
$FrontendRoot = Join-Path $ProjectRoot "frontend"
$LogDir = Join-Path $ImplRoot "logs"

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
}

$env:PYTHONPATH = $ProjectRoot
$PythonExe = "C:\ProgramData\anaconda3\python.exe"

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

# Agent microservice URLs
$env:TIER1_URL = "http://127.0.0.1:6051"
$env:TIER2_URL = "http://127.0.0.1:6052"
$env:TIER3_URL = "http://127.0.0.1:6053"
$env:WARROOM_URL = "http://127.0.0.1:6054"
$env:REPORTER_URL = "http://127.0.0.1:6055"
$env:REMEDIATION_URL = "http://127.0.0.1:6056"

# ---------------------------------------------------------------------------
# Helper: Print header
# ---------------------------------------------------------------------------
function Write-Header($title) {
    $line = "=" * 60
    Write-Host "`n$line" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Cyan
    Write-Host "$line" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Helper: Wait for HTTP service to respond
# ---------------------------------------------------------------------------
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
$Ports = 6050..6056
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
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "*IMT*" -or $_.CommandLine -like "*Implementation*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Environment sanitized." -ForegroundColor Gray

# ---------------------------------------------------------------------------
# 1. Agent Microservices
# ---------------------------------------------------------------------------
$agentProcesses = @()

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
        
        # Use array for arguments to avoid manual quoting hell
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
    foreach ($agent in $agents) {
        Wait-ForService "http://127.0.0.1:$($agent.port)/health" $agent.name 30 | Out-Null
    }
}

# ---------------------------------------------------------------------------
# 2. IDS Backend Gateway (FastAPI on port 6050)
# ---------------------------------------------------------------------------
Write-Header "Starting IDS Backend Gateway (port 6050)"

$backendArgs = @("-m", "uvicorn", "Implementation.src.IDS.IDS:app", "--host", "0.0.0.0", "--port", "6050")
$backendProc = Start-Process $PythonExe -ArgumentList $backendArgs `
    -WorkingDirectory $ProjectRoot `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $LogDir "ids_backend.log") `
    -RedirectStandardError  (Join-Path $LogDir "ids_backend_err.log")

Write-Host "  [+] IDS Backend  PID $($backendProc.Id) -> port 6050" -ForegroundColor DarkGray
$backendOk = Wait-ForService "http://127.0.0.1:6050/health" "IDS Backend" 40

# ---------------------------------------------------------------------------
# 3. Frontend (Vite / React on port 5173)
# ---------------------------------------------------------------------------
Write-Header "Starting Frontend (Vite, port 5173)"

# Force 127.0.0.1 to avoid [::1] (IPv6) binding which can cause polling failures
$frontendProc = Start-Process npm.cmd -ArgumentList "run dev", "--", "--host", "127.0.0.1" `
    -WorkingDirectory $FrontendRoot `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $LogDir "frontend.log") `
    -RedirectStandardError  (Join-Path $LogDir "frontend_err.log")

Write-Host "  [+] Frontend     PID $($frontendProc.Id) -> port 5173" -ForegroundColor DarkGray
$frontendOk = Wait-ForService "http://127.0.0.1:5173/" "Frontend" 30

# ---------------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------------
Write-Header "System Status"

$services = @(
    @{ name = "IDS Backend"; url = "http://127.0.0.1:6050/health" },
    @{ name = "Frontend"; url = "http://127.0.0.1:5173/" }
)
if (-not $SkipAgents) {
    foreach ($a in $agents) {
        $services += @{ name = "$($a.name) Agent"; url = "http://127.0.0.1:$($a.port)/health" }
    }
}

foreach ($svc in $services) {
    try {
        # Increased timeout to 5s for the final status report
        $r = Invoke-WebRequest -Uri $svc.url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $statusStr = "RUNNING"
        $color = "Green"
    }
    catch {
        $statusStr = "OFFLINE"
        $color = "Red"
    }
    Write-Host ("  {0,-20} {1,-25} {2}" -f $svc.name, $svc.url, $statusStr) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# 5. Optional CSV Feeder
# ---------------------------------------------------------------------------
if ($RunFeeder) {
    Write-Header "Launching CSV Flow Feeder"
    $feederArgs = @("-m", "Implementation.tools.feed_csv_flows")
    Start-Process $PythonExe -ArgumentList $feederArgs `
        -WorkingDirectory $ProjectRoot `
        -NoNewWindow
}

Write-Host "`n[OK] SOC System is running." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 6. Keep alive
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
    $allProcs = $agentProcesses + $backendProc + $frontendProc
    foreach ($p in $allProcs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
}
