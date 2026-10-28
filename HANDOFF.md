# Completed workflow handoff — October 1, 2026

The six requested GUI capabilities are implemented and verified: collect multiple sources, save CSV, load/divide records, train selected models, compare measured results, deploy and test unseen email content. All seven email choices including LSTM/BERT/CTI-BERT run with installed dependencies and official local checkpoints. See TESTING_REPORT.md, REAL_MODEL_VERIFICATION.json and ADDITIONAL_FEATURE_VERIFICATION.json for evidence and precise limits. BERT/CTI-BERT train classification heads on frozen pretrained encoders.

Run `.\.venv\Scripts\python.exe run.py`, then open http://127.0.0.1:5000/lab/. The production account/setup and database are preserved. Verification users, source records, deployed checks and models stay in tmp/. Recovered originals are unchanged; backups/before-completion/ contains the pre-completion working code/database snapshot.

44 tests pass. Public-source GUI collection, all-model training/comparison, deployment and new-content classification passed. Live threat feeds, independent validation, actual MSG parsing, retention/roles and PDF/CSV evidence exports are verified. NLP-Threat-Intelligence-source.zip supports a fresh Windows/Python 3.12 setup using Start-NLP-Threat-Intelligence.cmd. This package excludes private data and downloads official checkpoints on first setup.

Remaining external/research limits: no supplied EML/EXPECTED_RESULTS test pack; no recoverable missing historical database/model; no full transformer fine-tuning, antivirus, comprehensive semantic campaign grouping or external alert dispatch; no standalone executable installer. Small-source performance is not a broad detection guarantee.

The audit below records earlier recovery stages. Its earlier unavailable/unverified status and incomplete-feature lists are superseded by this completion section and TESTING_REPORT.md.

---

# Project recovery audit — October 1, 2026

Project: Natural Language Processing for Cybersecurity Threat Intelligence, CST 499 Senior Project II, Group 2.

## Verified state

The workspace contained only `.git/` before this document was created. No application source, README, prior HANDOFF, templates, static assets, requirements, datasets, model artifacts, test pack, or SQLite database was present. No numbered duplicate application files were present.

Git configuration contains no remote. HEAD references `refs/heads/master`, but no branch reference or commit history is present. The only stored reference is a Codex capture pointing to the empty-tree object. Git is unavailable on PATH and was not found at the standard Program Files Git locations; status, log, branch, and tracked-file commands could not run.

Database path, tables, and user/report/scan/feed/training counts are unavailable because no database was supplied. They must not be reported as zero. Existing features and previous-computer completion cannot be verified. Syntax checks, automated tests, Flask startup, and GUI verification cannot run without the project files.

## Inputs reviewed

Read both attached pasted requirement documents. The requested workflow is GUI collection from multiple sources, provenance-preserving CSV saving/loading, leakage-safe stratified division, compatible model selection and comparison, explicit deployment, and analysis of unseen emails. The attached methodology image identifies the stages and transformer/BERT/LSTM choices. The research PDF has not yet been reviewed; implementation is blocked at recovery.

## Preservation

No existing files were modified, moved, deleted, reset, or retrained. No replacement application or database was created. There were no application files to back up. Preserve the recovered project and make a backup before any future edits.

## Required next step

Restore the existing project folder or archive from the previous computer, including database, models, datasets, templates/static assets, requirements, and test pack. Alternatively provide its actual local path or repository location. Do not replace important work or publish credentials.

## Implementation sequence after recovery

1. Complete Phase 0: inspect instructions and history, identify active app/database, back up files, inventory database counts, run existing checks, start Flask, and record working/partial/missing features.
2. Implement and verify Phase 1: collection GUI, source provenance and manifest, combined CSV preview/save/load, deduplication, stratified train/test files, and validation isolation.
3. Implement and verify traditional model comparison using identical splits, followed by new-email analysis and the separate character TF-IDF URL detector.
4. Integrate optional LSTM/BERT/CTI-BERT with clear dependency failures; preserve traditional-model operation.
5. Verify feedback approval, deliberate deployment/rollback, exports, RBAC, audit history, documentation, and the full demonstration.

Only HANDOFF.md was created in this audit. All implementation and acceptance testing remain pending project recovery.

## Supplied backup inspection

Inspected `C:\Users\malek\Downloads\threat.intel.zip` using .NET ZipFile in read-only mode. The archive is 22 bytes and contains zero entries: it is a valid empty ZIP. No files could be recovered, and no extraction or application changes were performed. A populated backup or the original project folder is still required.

## Partial recovery from individually supplied files

Recovered all 21 user-supplied files into `recovered-original/`, retaining original filenames, including both app versions and both validation datasets. Downloads originals remain untouched. `recovery_manifest.csv` records each recovered file's size and SHA-256 checksum. This folder is the preserved recovery copy; use a separate working copy for implementation.

All nine recovered Python files pass `ast.parse` syntax checks using the bundled Python runtime. No existing automated tests were supplied. `app.py` and `app (1).py` have identical SHA-256 hashes. Bundled Git is now located at `C:\Users\malek\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe`; status shows only untracked recovery/documentation files.

Source contains login, dashboard APIs, threat-report upload/results/review, threat prediction/alerts, NVD/MITRE/OpenPhish collection, optional transformer analysis, and offline traditional model training. These are source-level findings, not verified working features. The existing trainer uses threat-intelligence categories; it is not evidence of a trained binary legitimate/phishing email classifier. Saved validation JSON reports 30 independent records, 20 correct and 10 incorrect, accuracy approximately 66.67%; historical artifacts have not been reproduced. The 100% best split accuracy in model metadata must not be presented as new email-detection performance.

Missing runtime assets: `templates/` (including login.html, dashboard.html, upload.html, and the results template), `static/`, `threat_model.pkl`, `tfidf_vectorizer.pkl`, `cyber_threat.db`, and the launcher-referenced `compat/` folder. Database counts remain unavailable, not zero. No EML test pack or EXPECTED_RESULTS.csv was supplied.

Runtime inconsistencies: database.py uses cyber_threat.db, while launcher.py expects threatintel.db and mysql compatibility shims. requirements.txt omits directly imported dotenv, nltk, and apscheduler because it assumes absent compatibility files. app.py loads both missing model artifacts at import and attempts NLTK downloads. The supplied schema seeds a plaintext default password; review authentication and seeding before executing it. Packaging guide statements about successful tests describe another environment and are not current verification.

The bundled Python lacks Flask, scikit-learn, joblib, dotenv, nltk, apscheduler, and requests. Flask startup is blocked by missing dependencies and assets; it was not executed because direct startup initializes a database and starts feeds, which the recovery audit must not do. No database was created and no models retrained.

Next: recover templates/static, model artifacts, and the original cyber_threat.db (or establish which original database is active). Then create a backed-up working copy, reconcile launcher/dependencies, verify existing login and data preservation, and continue the GUI collection/splitting phase. Implementation remains pending those recovery requirements.

## Authorized reconstruction and verified working state

The user subsequently said the missing assets were unavailable and explicitly authorized rebuilding them, emphasizing multi-source GUI collection, CSV save/load, division/training, model comparison and unseen-email testing. That authorization supersedes the earlier recovery blocker. The recovered originals remain untouched and are the backup; working copies and new modules/templates implement the requested workflow.

Active entry point: run.py. Active app: root app.py with lab_web.py blueprint and lab_core.py services. Active database: root cyber_threat.db. New templates/static assets were rebuilt. Do not use the old launcher. A project-local .venv was created using the bundled Python 3.12 runtime, with baseline packages installed and locked.

Verified functionality: first-run administrator setup, recovered login, server-side role restrictions/CSRF, multi-source CSV/EML/TXT/MBOX collection, provenance preview and combined CSV/manifest saving, saved-dataset loading, stratified 70/30–80/20 splitting, duplicate/conflicting-label rejection, validation isolation, exact shared-URL leakage rejection, compatible model selection, one-at-a-time background job statuses, all four traditional email classifiers, character TF-IDF/Logistic Regression URL classifier, saved real metrics/confusion matrices/F1 bars/error CSVs, explicit email/URL deployment and rollback, pasted/EML/batch inference, basic safe attachment metadata checks, rule/model confidence separation, history, sanitized feedback approval, and PDF/CSV response exports.

All nine original Python files passed syntax parsing at recovery. Final rebuilt syntax check passed using `.\.venv\Scripts\python.exe -m compileall -q app.py database.py lab_core.py lab_web.py neural_training.py run.py tests`. Final automated run: `.\.venv\Scripts\python.exe -m pytest -q` — **31 passed, 8 datetime-adapter deprecation warnings, 67.27 seconds**. Tests use isolated temporary databases and artificial test fixtures, not product datasets. Tests include actual recovered Flask login and async GUI training/deployment of three traditional models followed by unseen-text inference.

Started Flask successfully via `.\.venv\Scripts\python.exe run.py`. Browser verified first-run setup on port 5000. A separate disposable QA server on port 5001 verified actual login, dashboard visual layout and every main navigation page; that server was stopped. The real database remains empty for the user's setup, with zero users, reports, email scans, feed runs and training runs. It contains the recovered legacy schema plus additive lab tables; no previous database was supplied, so this is not a reconstruction of historical records. Repeated initialization preserved sentinel users/reports in integration tests. All preserved recovery files were checked against recovery_manifest.csv and remain unchanged.

The attached research PDF was text-inspected using the PDF skill. It supports the separate character-TF-IDF Logistic Regression URL detector and inclusion of legitimate login URLs. No paper/historical accuracy was used as new email-model performance. No real training corpus or deployed model is fabricated or preinstalled; the user imports their own labeled data and trains it through the GUI.

Required launch commands:

```powershell
Set-Location 'C:\Users\malek\OneDrive\Documents\ChatGPT\nlp cyber security phishing'
.\.venv\Scripts\python.exe run.py
```

Open http://127.0.0.1:5000/lab/, create a username/password at first-run setup, and log in. See README.md for fresh-install commands and USER_GUIDE.md for the complete demonstration. CHANGED_FILES.txt lists working/rebuilt files; recovery_manifest.csv lists the 21 preserved source files.

Partial/incomplete broader acceptance requirements: optional LSTM/BERT/CTI-BERT training backends are implemented but only missing-dependency behavior was tested; actual neural training requires installed dependencies/local checkpoints. MSG parsing, independent-validation GUI/evaluation, deep archive/Office/PDF extraction, attachment-only scanning, automatic live OSINT collection in the new lab, full threat entity/correlation integration, automatic report/alert dispatch, retention settings, model-parameter editing, comprehensive grouped campaign splitting and executable packaging remain incomplete. Original threat-report inference/feeds require missing original model artifacts; recovered source is preserved and automatic scheduling is off. PDF export responses are tested, but long/non-Latin PDF layouts were not visually validated. No supplied EML pack or EXPECTED_RESULTS.csv was available. This is a verified local core workflow, not completion of every broad acceptance requirement or real-world detection validation.
