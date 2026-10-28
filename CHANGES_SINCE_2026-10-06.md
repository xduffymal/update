# Changes since the October 6 partner ZIP

This comparison uses actual file contents from `NLP-Cybersecurity-Partner-Package-2026-10-06.zip`, not a reconstruction from memory. The October 22 teacher-data ZIP was a documentation/data package, not a newer application release.

## Existing work since that application package

- Added controlled seven-method preprocessing comparisons, training-only correlations and the separate 96-record synthetic demonstration.
- Added the 1,992-message public dataset and its saved experiments, plus the revised cited poster and teacher source-tracing package.
- Alternate `-Mal` working files and the larger `cyber_threat-Mal.db` preserve the extended experiment registry. The normal entry point imports the unsuffixed modules.

## Integration fixes made October 27

- Restored `/lab/preprocessing` in `lab_web.py` and its sidebar entry in `templates/base.html`. Before this fix, two preprocessing tests returned HTTP 404.
- Restored the 16 MiB CSV field limit in `lab_core.read_csv`, needed for long source email bodies.
- Restored the guard that keeps synthetic multiclass demonstrations out of the normal production training path.
- Added `Start-Demo.cmd`, `Start-Demo.ps1` and `tools/prepare_demo_workspace.py`. They create a separate demo database, let the operator choose an account password, and deploy the saved Character TF-IDF email model without changing original databases.
- Added this current report, raw test evidence, demonstration inputs and complete packaging with database snapshots and official local checkpoints.

## Source/document changes detected

| File | Compared with October 6 |
| --- | --- |
| `CHANGED_FILES.txt` | added |
| `lab_core-Mal.py` | added |
| `lab_core.py` | modified |
| `lab_web-Mal.py` | added |
| `lab_web.py` | modified |
| `preprocessing_experiment.py` | added |
| `Start-Demo.cmd` | added |
| `Start-Demo.ps1` | added |
| `synthetic_attack_data.py` | added |
| `USER_GUIDE-Mal.md` | added |
| `templates/base-Mal.html` | added |
| `templates/base.html` | modified |
| `templates/preprocessing.html` | added |
| `tests/test_preprocessing.py` | added |
| `tools/prepare_demo_workspace.py` | added |

Runtime datasets, database snapshots, results and checkpoint files are listed separately in `FILES_SHA256.csv`. No change to existing trained-model scores is claimed by the route integration fix.
