$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
docker build -t pro-zai:latest .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "Image pro-zai:latest is ready."
