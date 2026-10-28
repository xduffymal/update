# Natural Language Processing for Cybersecurity Threat Intelligence — NLP for Cybersecurity Threat Intelligence

CST 499 Senior Project II · Group 2 · Skylah Dangerfield and Malekhi Murphy.

Start with [the complete instruction manual](README_INSTRUCTION_MANUAL.md) for step-by-step GUI use, dataset provenance, model training, and a presentation-ready explanation of the experiment.

The recovered Flask threat-intelligence application now includes a primary phishing-email experiment workspace. It imports labeled records from multiple user-supplied sources, saves combined CSV files with provenance, divides them into disjoint stratified training/testing files, trains comparable models, saves real results, deploys a chosen version, and tests unseen emails. No performance numbers or training records are supplied as fabricated product data.

## Run on this computer

The virtual environment and required dependencies have already been installed in this workspace.

```powershell
Set-Location 'C:\Users\malek\OneDrive\Documents\ChatGPT\nlp cyber security phishing'
.\.venv\Scripts\python.exe run.py
```

Open http://127.0.0.1:5000/lab/. On first use, create your administrator account with a password of at least 12 characters, then log in. Stop the server with Ctrl+C in its terminal. No default production password is created.

## Fresh installation

Install Python 3.12 from the official Python distribution, then:

```powershell
Set-Location 'C:\Users\malek\OneDrive\Documents\ChatGPT\nlp cyber security phishing'
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe setup_models.py
.\.venv\Scripts\python.exe run.py
```

Activation is unnecessary, so PowerShell execution-policy changes are unnecessary. requirements.txt lists direct dependencies; requirements-lock.txt records the complete tested environment. The locked environment includes every model backend, MSG parsing, and PDF inspection. setup_models.py downloads the official BERT and CTI-BERT weights, pins their revisions, and records SHA-256 checksums. These checkpoints are already prepared on this computer.

## Architecture

- app.py: recovered Flask application, original login, report and feed logic; missing original model artifacts are handled without preventing startup.
- database.py and schema_sqlite.sql: existing SQLite adapter and additive schema. No old tables are dropped. The working schema no longer seeds plaintext default credentials.
- lab_web.py: authenticated GUI routes, roles, CSRF validation, uploads, export, deployment, feedback and model-job coordination.
- lab_core.py: provenance, CSV persistence, validation isolation, reproducible splits, TF-IDF pipelines, metrics, versioning, safe message parsing and risk scoring.
- model_backends.py / neural_training.py: verified learned-embedding LSTM and real pretrained BERT/CTI-BERT contextual encoders with trained classification heads.
- source_importer.py, attachment_safety.py, validation_service.py, threat_workspace.py and experiment_settings.py: verified public collection, bounded attachment inspection, independent evaluation, legacy threat feeds and retention.
- run.py: supported entry point, schema initialization, interrupted-job recovery, local Flask startup.
- templates/ and static/: rebuilt interface; charts and counts come from saved records and results.
- recovered-original/: untouched recovery copies, including duplicates and historical results. recovery_manifest.csv contains their original checksums.

The original database and trained artifacts were never supplied. A new empty cyber_threat.db is initialized; historical users/reports cannot be reconstructed. The old launcher is preserved in recovered-original/ but should not be used: it depends on missing compatibility shims and a different database path.

## Outputs

| Location | Contents |
|---|---|
| cyber_threat.db | Users, legacy tables, imports, runs, versions, deployment pointers, scans, approved/pending feedback and audit logs |
| data/raw/ | Per-user collection drafts, removed after saving/clearing |
| data/processed/dataset_ID.csv | Combined labeled records with source and permitted-use metadata |
| data/validation/dataset_ID.csv | Independently designated validation-only datasets |
| data/processed/SPLIT_ID/ | training_set.csv, testing_set.csv, split.json and SHA-256 checksums |
| data/dataset_manifest.csv | Per-source provenance, balance, usage notes and dataset checksum |
| models/versions/VERSION_ID/ | Complete inference pipeline, model metadata, and individual model/vectorizer artifacts where applicable |
| results/RUN_ID.json | Experiment configuration and complete measured metrics |
| results/RUN_ID_comparison.csv | Comparable metrics for that run |
| results/RUN_ID_VERSION_ID_errors.csv | False-positive/false-negative record IDs and predictions |
| Browser downloads | Scan PDF/CSV exports and downloaded datasets/results |
| .session-key | Locally generated session-signing secret; keep private |

The pipeline contains fitted vectorizers so feature extraction is consistent during inference. Calibrated SVM artifacts contain fitted pipelines for each calibration fold; extracting one standalone vectorizer would be incorrect. URL versions have separate phishing_url_model.pkl, url_tfidf_vectorizer.pkl, and url_model_metadata.json inside their version directory.

See USER_GUIDE.md, DATASET_README.md, TRAINING_README.md and TESTING_REPORT.md for the complete workflow and known gaps.

## Verified functionality and limitations

All seven email choices (Logistic Regression, Naive Bayes, calibrated Linear SVM, Random Forest, LSTM, BERT, CTI-BERT) trained, serialized, loaded, deployed and analyzed unseen content on this computer. REAL_MODEL_VERIFICATION.json records an isolated functional experiment with 80 actual Enron/Nazario records, 64 training / 16 testing. ADDITIONAL_FEATURE_VERIFICATION.json records 20 separately collected validation records, Outlook MSG parsing, live NVD/MITRE/OpenPhish collection and a separate three-class threat-report model. These small experiments establish functionality, not broad detection accuracy. False positives and false negatives are retained.

BERT and CTI-BERT use frozen pretrained contextual encoders and supervised Logistic Regression heads; the application does not perform full transformer fine-tuning. LSTM learns its embedding/recurrent weights. The original historical threat model cannot be recovered from missing files; the GUI can train and deliberately deploy a new separate threat model from collected feeds.

Attachment-only and EML/MSG scans inspect hashes, MIME/signatures, bounded PDF/Office/archive text, encryption/macro/script/path/expansion warnings and extracted URLs. This static inspection is not antivirus. Supplied Authentication-Results headers are not independently authenticated. Entities use explicit pattern extraction; correlation uses locally collected indicators and scan history. Alerts are saved locally; no external email is sent. Retention is disabled by default and makes a recoverable SQLite snapshot before explicit cleanup.

No supplied EML test pack or EXPECTED_RESULTS.csv was found, so that specific external acceptance comparison cannot be claimed. Run your professor's pack when available. Original recovery files remain untouched; verification records and models are under tmp/, outside the production database.

Missing models return an explicit manual-review result. Collect labeled records, divide them, train, and deploy a completed email version. Shared exact URLs are grouped during splitting; requested and actual ratios are recorded. Invalid or impossible divisions fail clearly. Interrupted jobs become Failed on restart and can be retrained. Keep the server on localhost.

For portability, run `.\.venv\Scripts\python.exe tools/package_app.py` to create NLP-Threat-Intelligence-source.zip. It excludes private databases, emails, secrets, checkpoints, fitted models and environments. On another Windows computer with Python 3.12, extract it and double-click Start-NLP-Threat-Intelligence.cmd, or use the fresh-install commands above. This is a source package with Windows launch scripts, not a standalone executable installer.

For this computer, double-click Start-NLP-Threat-Intelligence.cmd to start. Python 3.12 is required on a fresh computer; the command launcher installs dependencies and downloads official weights. PowerShell script policy does not need to change. The manual Python commands above also work.
