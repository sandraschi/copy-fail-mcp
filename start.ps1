# copy-fail-mcp starter
param([switch]$BackendOnly)
$ErrorActionPreference = "Stop"
$Repo = $PSScriptRoot
$UV = "C:\Users\sandr\.local\bin\uv.exe"
Write-Host "=== copy-fail-mcp ===" -ForegroundColor Cyan
& $UV run python -m copy_fail_mcp
