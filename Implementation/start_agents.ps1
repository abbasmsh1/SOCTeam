$env:PYTHONPATH = "E:\IMT\2nd Sem\Project"

# Load API key from .env
$envFile = Join-Path $PSScriptRoot ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match "^\s*([^#][^=]+)=(.+)$") {
            [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), "Process")
        }
    }
    Write-Host "Loaded environment from .env"
}

$env:TIER1_URL = "http://localhost:6051"
$env:TIER2_URL = "http://localhost:6052"
$env:TIER3_URL = "http://localhost:6053"
$env:WARROOM_URL = "http://localhost:6054"
$env:REPORTER_URL = "http://localhost:6055"

Write-Host "Starting Agent Microservices..."

$t1 = Start-Process python -ArgumentList "-m Implementation.src.agent_server --agent tier1 --port 6051" -PassThru -NoNewWindow
$t2 = Start-Process python -ArgumentList "-m Implementation.src.agent_server --agent tier2 --port 6052" -PassThru -NoNewWindow
$t3 = Start-Process python -ArgumentList "-m Implementation.src.agent_server --agent tier3 --port 6053" -PassThru -NoNewWindow
$wr = Start-Process python -ArgumentList "-m Implementation.src.agent_server --agent warroom --port 6054" -PassThru -NoNewWindow
$rp = Start-Process python -ArgumentList "-m Implementation.src.agent_server --agent reporter --port 6055" -PassThru -NoNewWindow

Write-Host "Waiting for microservices to initialize..."
Start-Sleep -Seconds 10

Write-Host "Starting Main IDS API Gateway on port 6050..."
python -m uvicorn Implementation.src.IDS.IDS:app --port 6050

# When you hit Ctrl+C, cleanup the processes
Stop-Process -Id $t1.Id -Force
Stop-Process -Id $t2.Id -Force
Stop-Process -Id $t3.Id -Force
Stop-Process -Id $wr.Id -Force
Stop-Process -Id $rp.Id -Force
