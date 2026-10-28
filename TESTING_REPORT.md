# Verification report — October 1, 2026

Final suite: **44 passed**, no skips, eight recorded Python 3.12 datetime-adapter deprecation warnings, 23.44 seconds. Syntax compilation passed. Tests use temporary databases and declared fixtures, never deployed product data.

Coverage includes multiple-source CSV import/provenance/save/load, custom column mapping, deduplication/conflicts, reproducible stratification, transitive shared-URL grouping, validation isolation, split tampering, every traditional/URL classifier, calibrated SVM, saved-artifact inference, deployment/rollback, missing-model/dependency behavior, EML/TXT/MBOX/actual MSG parsing, batch upload, bounded Office/archive extraction, unsafe paths/expansion limits, attachment hashes/signatures, URL display mismatch, invalid/oversized files, RBAC/role updates/last-administrator protection, CSRF, feedback approval, additive database preservation, retention backup, separate three-class threat training, CSV/PDF exports and every primary GUI route.

## Actual model experiment

80 real public-source records: 40 legitimate Enron and 40 phishing Nazario, collected from the publisher corpus with checksum/provenance verification. Identical saved seed-42 division: 64 training / 16 testing. Each of seven models trained, serialized, reloaded, deliberately deployed and analyzed new content. These are small functional checks, not a production accuracy claim.

| Model | Split accuracy | Split F1 | FP | FN | Independent accuracy | Independent FP | Independent FN |
|---|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression | 1.000 | 1.000 | 0 | 0 | 0.900 | 1 | 1 |
| Naive Bayes | 0.875 | 0.889 | 2 | 0 | 0.900 | 2 | 0 |
| Linear SVM | 1.000 | 1.000 | 0 | 0 | 0.900 | 1 | 1 |
| Random Forest | 0.812 | 0.800 | 1 | 2 | 0.850 | 1 | 2 |
| LSTM | 0.625 | 0.625 | 3 | 3 | 0.550 | 3 | 6 |
| BERT | 0.875 | 0.875 | 1 | 1 | 0.950 | 1 | 0 |
| CTI-BERT | 1.000 | 1.000 | 0 | 0 | 0.950 | 0 | 1 |

Independent evaluation used 20 additional records (10 per class), excluding previously divided content/shared URLs; no fitting or deployment occurred during evaluation. JSON records contain complete measured results; version folders retain artifacts, split files and error CSVs under tmp/real-model-verification/.

BERT/CTI-BERT use actual pretrained encoders with frozen weights and trained supervised heads; they are not fully fine-tuned transformers. LSTM trains learned embeddings/recurrent weights. All neural backends were exercised, not just missing-dependency paths.

## GUI and external-source acceptance

Browser verification in tmp/qa-preview/: signed in, collected 20 Enron + 20 Nazario records through the GUI, saved/reloaded CSV, saved 32/8 division, selected all seven models, observed Completed and measured comparison, deployed CTI-BERT, analyzed an unseen pasted email, inspected evidence and submitted sanitized feedback. All primary pages and role-aware navigation were checked. Final exports include URL, attachment, entity/correlation and rule evidence. A two-page PDF was rendered and visually inspected without clipping; arbitrary long/non-Latin layouts are not exhaustively verified.

Actual Outlook MSG fixture from the official parser repository parsed successfully and temporary files were removed. Actual live NVD, MITRE ATT&CK and OpenPhish collection each added 10 reports in an isolated database. A separate three-class source-category threat classifier trained, saved, deployed and predicted successfully. Source categories can introduce bias; this is not independent threat-model validation.

All 21 recovered originals match the recovery SHA-256 manifest. Pre-completion production SQLite counts were preserved; verification does not install test users/emails/models into production. Historical users/models were absent from the supplied backup and cannot be reconstructed. The old 30-record historical results remain archived and are not presented as new performance.

No supplied EML pack or EXPECTED_RESULTS.csv was available. That specific acceptance comparison remains pending its files. Static attachment inspection is not antivirus; entity extraction uses explicit patterns, correlation is local, alerts are stored locally, and there is no external alert dispatch. Retention is explicit and recoverable. Grouping prevents exact shared-URL leakage, not all semantic/campaign overlap. The Windows source ZIP/launch script is provided, not an executable installer.

## Commands

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m tests.verify_real_models
.\.venv\Scripts\python.exe -m tests.verify_additional_features
.\.venv\Scripts\python.exe run.py
```

Repeated verification writes fresh versioned artifacts only inside isolated tmp directories. The official MSG sample must be available under tmp/msg-fixtures/ for its external-fixture acceptance check.

Source package: 53 files, ZIP integrity verified, private runtime folders excluded. Extracted-package administrator setup rendered successfully. Final browser PDF and CSV downloads succeeded.

Collection fix: repeated requests shared a Windows temporary download file. Per-source serialization, unique temporary filenames, checksum-before-publication, bounded lock retries, and a disabled collecting button now prevent this crash. Three regression tests and live collection of 100 Enron records passed.
