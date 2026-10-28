# Working files created or changed

Original recovered files remain untouched. Working source, GUI, tests, docs and verification records:

- .gitignore
- ADDITIONAL_FEATURE_VERIFICATION.json
- CHANGED_FILES.md
- CHANGED_FILES.txt
- DATASET_README.md
- HANDOFF.md
- PRESERVATION_VERIFICATION.json
- README.md
- REAL_MODEL_VERIFICATION.json
- Start-NLP-Threat-Intelligence.cmd
- Start-NLP-Threat-Intelligence.ps1
- TESTING_REPORT.md
- TRAINING_README.md
- USER_GUIDE.md
- app.py
- attachment_safety.py
- bert_transformer_layer.py
- build_validation_candidates.py
- database.py
- evaluate_transformer.py
- evaluate_validation.py
- experiment_settings.py
- lab_core.py
- lab_web.py
- model_backends.py
- model_metadata.json
- model_training.py
- neural_training.py
- package.ps1
- pytest.ini
- recovery_manifest.csv
- requirements-lock.txt
- requirements-transformer.txt
- requirements.txt
- run.py
- scan_report.py
- schema.sql
- schema_mysql_original.sql
- schema_sqlite.sql
- setup_models.py
- source_importer.py
- static/lab.css
- templates/active_model_info.html
- templates/base.html
- templates/dashboard.html
- templates/dashboard_metrics.html
- templates/error.html
- templates/lab.html
- templates/login.html
- templates/model_readiness.html
- templates/public_sources.html
- templates/reports.html
- templates/results.html
- templates/retention.html
- templates/threat_collection.html
- templates/upload.html
- templates/validation.html
- tests/__init__.py
- tests/preview_server.py
- tests/test_actual_app.py
- tests/test_additional_safety.py
- tests/test_completion.py
- tests/test_workflow.py
- tests/verify_additional_features.py
- tests/verify_pdf.py
- tests/verify_real_models.py
- threat_workspace.py
- tools/finalize_docs.py
- tools/finish_package_docs.py
- tools/package_app.py
- tools/verification_summary.py
- transformer_comparison.json
- validation_errors.csv
- validation_metrics.json
- validation_service.py
- validation_set.1.csv
- validation_set.csv

Runtime outputs: data/ contains source caches, manifests, CSVs and divided files; models/checkpoints/ holds official pinned weights; models/versions/ holds trained versions; results/ contains measured metrics/errors; cyber_threat.db and .session-key are private. All acceptance test data and models are in tmp/. Backups are in backups/before-completion/. NLP-Threat-Intelligence-source.zip excludes these private/runtime folders.

Collection fix also changes source_importer.py and templates/public_sources.html and adds tests/test_source_download.py.

New documentation: README_INSTRUCTION_MANUAL.md; linked from README.md. Dataset guidance and package lists updated to match current functionality.
