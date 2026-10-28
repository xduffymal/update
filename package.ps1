$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$packageTarget = Join-Path $PSScriptRoot 'NLP-Threat-Intelligence-source.zip'
if (Test-Path -LiteralPath $packageTarget) { throw 'NLP-Threat-Intelligence-source.zip already exists; rename it before packaging again.' }
$packageFiles = @('app.py','database.py','schema_sqlite.sql','run.py','lab_core.py','lab_web.py','model_backends.py','neural_training.py','setup_models.py','attachment_safety.py','source_importer.py','validation_service.py','experiment_settings.py','threat_workspace.py','scan_report.py','bert_transformer_layer.py','templates','static','requirements.txt','requirements-lock.txt','requirements-transformer.txt','Start-NLP-Threat-Intelligence.ps1','Start-NLP-Threat-Intelligence.cmd','README.md','README_INSTRUCTION_MANUAL.md','USER_GUIDE.md','TRAINING_README.md','DATASET_README.md','TESTING_REPORT.md','tests','pytest.ini')
Compress-Archive -LiteralPath $packageFiles -DestinationPath $packageTarget -CompressionLevel Optimal
Write-Host "Created $packageTarget. Private databases, emails, models, secrets, backups and virtual environments are excluded. First startup installs dependencies and downloads official checkpoints."
