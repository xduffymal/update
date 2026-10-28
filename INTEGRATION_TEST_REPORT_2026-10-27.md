# Integration testing report

Project: Natural Language Processing for Cybersecurity Threat Intelligence
Prepared: October 27, 2026
Authors: Skylah Dangerfield and Malekhi Murphy

## Current result

**48 automated tests passed, 0 failed, 0 skipped, with 8 non-fatal SQLite datetime-adapter deprecation warnings.** The corrected source suite completed in 30.24 seconds in the existing Windows / Python 3.12.14 environment. It used disposable databases and fixtures. A separate 17-route HTTP check returned 200 for every route, including the real and synthetic preprocessing result pages. A fresh scanner submission, two-file TXT batch, CSV export and PDF export succeeded.

The initial fresh run recorded 46 passed and 2 failed: both failures were HTTP 404 on the unregistered preprocessing route. The October 27 integration patch restored that existing alternate implementation and navigation. The initial and corrected logs are both retained. An earlier attempt failed before test execution because the environment's default temporary directory was not writable. Successful runs use an explicit writable workspace `--basetemp`.

Passing tests establishes the covered functional behavior. It does not establish that every feature is free of defects or that the classifier detects all real attacks. Live feeds, a fresh dependency installation on another computer, and end-to-end native browser interaction were not revalidated in this release.

## Evidence locations

- `evidence/2026-10-27/pytest-fixed-output.txt` and `junit-fixed.xml`: corrected source suite.
- `evidence/2026-10-27/pytest-output.txt` and `junit.xml`: initial two failing integration tests.
- `evidence/2026-10-27/fresh-model-verification.json` and `model-output.txt`: new seven-model functional run.
- `evidence/2026-10-27/scanner-smoke.json`: phishing-like and legitimate-like saved-model checks.
- `evidence/2026-10-27/http/verification.json`: route, scanner, batch and export checks.
- `evidence/2026-10-27/http/*.html`: offline styled captures of actual Flask responses. These are not screenshots.
- `evidence/2026-10-27/http/scanner-export.pdf` and `.csv`: fresh scan report examples.
- `evidence/2026-10-27/database-snapshots.json`: database integrity and preservation checks.
- `evidence/historical/`: earlier real-source, independent-validation and live-feed checks, clearly dated and separate from new evidence.

## Fresh model test

The run used 80 real public-source records (40 Enron legitimate and 40 Nazario phishing) with the same 64-training / 16-testing split, seed 42. Every model trained, serialized, reloaded, deliberately deployed and classified a new message. BERT/CTI-BERT used local official checkpoints, frozen encoders and trained Logistic Regression heads. The LSTM trained its embeddings and recurrent weights. Model accuracy varies substantially.

| Model | Test accuracy | Phishing F1 | FP | FN | Reload/deploy/inference |
| --- | ---: | ---: | ---: | ---: | --- |
| Logistic Regression | 100.00% | 100.00% | 0 | 0 | Passed |
| Naive Bayes | 87.50% | 88.89% | 2 | 0 | Passed |
| Linear SVM | 100.00% | 100.00% | 0 | 0 | Passed |
| Random Forest | 81.25% | 80.00% | 1 | 2 | Passed |
| LSTM | 62.50% | 62.50% | 3 | 3 | Passed |
| BERT | 87.50% | 87.50% | 1 | 1 | Passed |
| CTI-BERT | 100.00% | 100.00% | 0 | 0 | Passed |

These scores reproduce the small functional experiment, not the separate 399-message poster experiment. Example probabilities are uncalibrated model outputs.

## Feature status

| Feature | Current assessment | Evidence | Limitations / prerequisites |
| --- | --- | --- | --- |
| Email threat scanner | Verified functional | Fresh HTTP scan, saved-model reload/inference, attachment and URL tests | An email model must be deployed. Risk scores combine learned output and rules. This is not guaranteed real-world detection. |
| Public email data collection | Verified local/cache and mocked network paths | Publisher checksum sampling in fresh 80-message model run; concurrent download/Windows lock regression tests | Live internet downloads were not repeated in this release. Raw public source files are included. |
| CSV import, mapping, deduplication and saved splits | Verified functional | Automated workflow, mapping, conflict, leakage and tamper tests | Campaign/domain independence is not established by exact shared URL grouping. |
| Four TF-IDF/count classifiers | Verified functional | Fresh train/save/reload/deploy/infer for LR, NB, calibrated SVM, RF | Small held-out scores are not broad accuracy estimates. |
| LSTM, BERT and CTI-BERT options | Verified functional in installed environment | Fresh training, serialization, reload, deployment and inference for all three | BERT encoders are frozen with trained supervised heads. Weights included, Python packages still require installation. |
| Preprocessing and correlation page | Verified functional after integration fix | Both formerly failing tests now pass; fresh real and synthetic saved comparison pages HTTP 200 | Previously disconnected route restored. Synthetic models remain separate. |
| EML, MSG, TXT, MBOX and batch handling | Verified functional | Automated parser/batch/oversize tests, real official MSG fixture, fresh two-TXT HTTP upload | Large/unsupported files are rejected. Unicode/very long export layouts are not exhaustively tested. |
| Attachment inspection | Verified functional for covered static checks | Hash, signature, extension, Office/archive extraction, traversal and expansion-limit tests | Static inspection does not execute files and is not antivirus or sandbox detonation. |
| URL evidence and optional URL classifier | Verified functional for covered paths | URL model train/deploy test, displayed-link mismatch and extraction tests | Extracted destinations are not visited. No live reputation guarantee. |
| History, analyst feedback and approval | Verified functional | Saved scan, feedback, approval and training-isolation tests | Private scans do not automatically become training records. |
| CSV/PDF reports | Verified functional for covered cases | Fresh successful CSV and PDF scanner exports plus automated export tests | Arbitrary document layouts and non-Latin text are not exhaustively validated. |
| Accounts, RBAC, CSRF and last-admin protection | Verified functional for covered cases | Integration login/setup, role restrictions, CSRF and last-admin tests | Included original databases retain their existing account records. Demo setup adds an account only in a separate copy. |
| Deployment, rollback and missing-model behavior | Verified functional | Fresh seven-model deployment and saved-model inference plus rollback/fallback tests | The two original saved databases have no deployed models. Use Start-Demo or deploy explicitly in Model Management. |
| Retention and preservation | Verified functional for covered cases | Backup-before-retention, user/model preservation and migration tests | Retention only runs when explicitly requested. |
| Threat-intelligence feeds and source-category classifier | Classifier verified with fixtures; live feed evidence historical | Fresh separate threat-category training test, prior live NVD/MITRE/OpenPhish report in historical evidence | Live feed endpoints were not retested October 27. External rate limits, availability and credentials can affect collection. |
| Local alerts, entity extraction and correlation | Verified for covered code paths | Automated scan evidence/report tests and historical feature acceptance | Pattern extraction and local correlation have limited scope. External email/SMS alert delivery is not implemented. |

## Database state and demo readiness

`cyber_threat.db` is the unsuffixed application's original saved database: 200 dataset records, 4 model versions, no deployed model, and no saved scans. `cyber_threat-Mal.db` is the larger alternate working database: 2,192 dataset records across saved imports, 15 model versions, no deployed model, and no saved scans. Both snapshots pass SQLite integrity checks. These counts describe preserved project state, not test fixtures.

`Start-Demo.cmd` creates a separate `demo_workspace` from the larger snapshot, copies the matching data and fitted versions, asks the operator to choose a password, and deploys the saved Character TF-IDF email model. The originals remain unchanged. The helper was exercised in a disposable destination, and that prepared workspace supplied the fresh scanner and HTTP checks.

## Screenshots and UI evidence

Saved preprocessing and synthetic prediction screenshots are in `evidence/screenshots/`. They are existing project evidence, not new October 27 captures. Fresh native browser screenshots could not be captured because Windows computer use could not confidently determine the current Chrome URL and stopped. Current functional evidence therefore consists of Flask HTTP response checks, styled HTML captures, JSON outputs, and report exports. Do not label those HTML captures as browser screenshots or claim a new native GUI acceptance run.

## Remaining acceptance work

1. Install the ZIP on the actual demo computer and verify dependency installation, startup, account login and display scaling.
2. Perform the manual cases in `DEMO_TEST_CASES.md` in a native browser. Record actual screenshots and observations.
3. Retest live NVD, MITRE ATT&CK and OpenPhish collection shortly before the demo if those external integrations will be shown.
4. Supply independently labeled real acceptance emails if expected classifier accuracy is to be measured. No external expected-results message pack was supplied.
5. Use a larger, independently sourced validation set to assess detection accuracy and campaign independence.
