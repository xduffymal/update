$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$taskPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    Write-Host 'Creating a Python 3.12 virtual environment...'
    & py -3.12 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Install Python 3.12 and try again.' }
    & $taskPython -m pip --cache-dir .pip-cache install -r requirements-lock.txt
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed. See the displayed error.' }
}
& $taskPython -c "from neural_training import availability; import sys; sys.exit(0 if all(v['ready'] for v in availability().values()) else 2)"
if ($LASTEXITCODE -eq 2) {
    Write-Host 'Preparing official BERT and CTI-BERT model checkpoints...'
    & $taskPython setup_models.py
    if ($LASTEXITCODE -ne 0) { throw 'Model setup failed. Check network/certificate access.' }
}
Write-Host 'Open http://127.0.0.1:5000/lab/ in your browser.'
& $taskPython run.py
