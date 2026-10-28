# Reproducible training

The GUI creates immutable split folders rather than overwriting shared training/testing CSVs. Save the dataset, choose a split ratio/seed, and retain split.json with its original dataset and train/test SHA-256 checksums. Every model compared in a run uses exactly those files. Tampering is detected before training. Preprocessing is fitted only on training records; cross-validation fits feature extraction inside its folds. Independent validation remains separate.

| Feature method | Compatible models |
|---|---|
| Word TF-IDF, lowercase/unicode accents, 1–2 word n-grams | Logistic Regression, Multinomial Naive Bayes, Random Forest, calibrated Linear SVM |
| Character TF-IDF, lowercase, 2–5 character n-grams | URL Logistic Regression |
| Learned word embeddings | LSTM |
| Contextual transformer representations | BERT / CTI-BERT |

GUI controls disable incompatible models; the server rejects invalid requests too. Core parameters are fixed and recorded; random seed is user-selectable in Dataset Manager. Parameter-editing controls are not supplied.

Traditional models save accuracy, binary precision/recall/F1 (phishing positive), macro metrics, training-fold cross-validation macro F1 where data supports it, timing, correct/incorrect counts, per-class reports, confusion matrices, false positives and false negatives. Matrix order: legitimate, phishing; rows actual, columns predicted. If SVM has too little data for nested calibration, its CV score is explicitly unavailable. LSTM uses training-fold cross-validation with embeddings fitted within each fold. BERT heads use training-fold cross-validation on frozen pretrained contextual representations.

Each run saves its ID, initiating user, original dataset checksum, split filenames/checksums, sizes/class counts, ratio, seed, preprocessing/features, model parameters, Python/package versions, completion timestamp, total/model durations, status/error, artifact names and results. CPU/library differences can affect exact reproducibility; use the locked environment and identical settings/data. Run timestamps and identifiers will naturally differ.

Complete pipelines preserve the fitted vectorizer and classifier for inference. SVM uses CalibratedClassifierCV wrapping an entire TF-IDF/LinearSVC pipeline, preventing feature-fitting leakage into calibration folds. Its reported confidence uses sigmoid calibration, not an uncalibrated margin. Other probability estimates are explicitly not guaranteed calibrated; neural softmax is uncalibrated. Risk scoring is a separate heuristic defined in Settings/README.

## Verified neural backends

All dependencies are in requirements-lock.txt. Run `.\.venv\Scripts\python.exe setup_models.py` on a fresh installation. The GUI also provides checkpoint preparation under Model Management. Official BERT and CTI-BERT revisions and file checksums are saved locally; remote model code is never executed. Optional BERT_CHECKPOINT/CTI_BERT_CHECKPOINT environment variables can reference compatible local checkpoints.

LSTM learns 64-dimensional embeddings and recurrent weights for three epochs, batch size eight, maximum 128 tokens. BERT and CTI-BERT use frozen real pretrained encoders, masked mean pooling, and a supervised Logistic Regression head trained only on experiment training records. They do not perform full transformer fine-tuning. Settings/parameters, checkpoint provenance and actual cross-validation scores are saved. Compare all email feature methods enables all seven email models in one run.

Actual all-model training, saved-artifact reload, deployment and unseen inference passed. See REAL_MODEL_VERIFICATION.json and ADDITIONAL_FEATURE_VERIFICATION.json. Small corpus performance is not evidence of universal phishing detection.

Jobs run one at a time in a background thread. Duplicate starts while a job is active are rejected. Closing the server interrupts workers; next startup marks unfinished jobs Failed. Retrain explicitly. Intermediate status changes can be quick; refresh to see current persisted state.

Deployment is deliberately separate: only a completed run's version is eligible. Active email and URL pointers include deploying user, timestamp and previous version. Administrator rollback uses the prior pointer. Version files are preserved; a missing deployed artifact returns unavailable-model output and manual-review behavior.
