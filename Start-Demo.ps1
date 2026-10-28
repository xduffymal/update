$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    & py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12 (64-bit), then try again.' }
    & $taskPython -m pip install -r requirements-lock.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. Review the error above.' }
}
$taskDemo = Join-Path $PSScriptRoot 'demo_workspace'
if (-not (Test-Path -LiteralPath $taskDemo)) {
    & $taskPython tools/prepare_demo_workspace.py
    if ($LASTEXITCODE -ne 0) { throw 'Demo preparation did not complete. Review the message above.' }
}
$env:LAB_ROOT = $taskDemo
Write-Host 'Open http://127.0.0.1:5000/lab/ and sign in with your demo-admin account.'
Write-Host 'The original saved databases remain unchanged. Press Ctrl+C to stop.'
& $taskPython run.py
