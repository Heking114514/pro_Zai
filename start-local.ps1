$ErrorActionPreference = "Stop"

Set-Location $PSScriptRoot

if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "Creating virtual environment..."
    python -m venv .venv
}

& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
& .\.venv\Scripts\playwright.exe install chromium

if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

$env:PRO_ZAI_DATA_DIR = $PSScriptRoot
$env:PRO_ZAI_LOG_DIR = Join-Path $PSScriptRoot "logs"

Write-Host ""
Write-Host "pro-zai local manual-slider console"
Write-Host "URL:   http://127.0.0.1:8765"
Write-Host "Log:   $env:PRO_ZAI_LOG_DIR\register-debug.log"
Write-Host "Ctrl+C stops the service."
Write-Host ""

& .\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8765
