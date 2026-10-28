# Natural Language Processing for Cybersecurity Threat Intelligence: instruction manual and data-source explanation

Natural Language Processing for Cybersecurity Threat Intelligence · Senior Project II · Group 2

This manual explains how to use the application, how training works, and how to document where your data came from. Example counts describe a demonstration; your actual counts and scores come from saved files and completed experiments.

## 1. What the program does

The primary task is binary email classification: **legitimate** or **phishing**. The GUI supports this complete workflow:

**Collect different sources → preview → save CSV → load CSV → divide training/testing → select models → train and compare → deploy a chosen version → analyze new emails.**

| Project requirement | Where you perform it |
|---|---|
| Collect data from different sources | Data Collection: public-source collection or file imports |
| Save collected data to a file through the GUI | Save combined CSV |
| Load the saved file and divide data | Dataset Manager |
| Train and compare choices such as Figure 3 | Train and Compare |
| Select the model used for new emails | Model Management |
| Enter new email content for phishing testing | Analyze Email |

Training, evaluation, and deployment are separate actions. Collecting or saving records does not train a model. Successful training does not automatically deploy it.

## 2. Start and log in

If the app is already running, open [the local workspace](http://127.0.0.1:5000/lab/).

On this computer, you can double-click **Start-NLP-Threat-Intelligence.cmd** in the project folder. Alternatively, use PowerShell:

```powershell
Set-Location 'C:\Users\malek\OneDrive\Documents\ChatGPT\nlp cyber security phishing'
.\.venv\Scripts\python.exe run.py
```

Keep its terminal open while using the website. Do not launch a second server if port 5000 is already occupied. Stop the server with Ctrl+C when finished.

On first use, create your administrator account with a password of at least 12 characters, then log in. On later visits, use that account. No default production password is supplied.

For a fresh computer, install Python 3.12, extract the source package, and run these commands from its folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.\.venv\Scripts\python.exe setup_models.py
.\.venv\Scripts\python.exe run.py
```

Internet access is needed for public collection and checkpoint setup. Saved users, datasets, trained versions, and scans persist in the project folder.

## 3. Exactly where the email training data comes from

The built-in sources come from **Phishing Email Curated Datasets**, hosted on Zenodo, DOI **10.5281/zenodo.8339691**. The publisher record provides Enron.csv and Nazario.csv, checksums, and requested citations. See the [publisher dataset record](https://zenodo.org/records/8339691).

| GUI source | Downloaded file | Records this application selects | Normalized label |
|---|---|---|---|
| Enron · legitimate emails | Enron.csv | Existing rows whose original label is 0 | legitimate |
| Nazario · phishing emails | Nazario.csv | Existing rows whose original label is 1 | phishing |

These are curated historical email records. The app downloads them from the publisher; it does not collect them from your inbox, scrape live phishing websites, or generate them with an AI model. Labels are inherited from the curated files, not inferred during collection. They should still be reviewed for suitability.

Direct file endpoints used by the application:

- [Enron.csv download](https://zenodo.org/api/records/8339691/files/Enron.csv/content)
- [Nazario.csv download](https://zenodo.org/api/records/8339691/files/Nazario.csv/content)

The downloader checks CC BY 4.0 metadata for a new download and verifies the expected publisher MD5 checksum before importing. The expected values are:

```text
Enron.csv:   10489e0fdcc8af6fe62135c689367d40
Nazario.csv: 4022d055bb7cf8602f30f768f652e91e
```

A checksum confirms that the file matches the expected download; it does not prove every label is correct. SHA-256 checksums are also saved for local source files and experiment datasets.

### How the program chooses your requested records

On first collection, the full source CSV is downloaded and cached. Asking for 100 records still requires this first download. The app filters for the required label and nonempty text, then uses deterministic reservoir sampling with your collection seed. It removes duplicate content afterward, so fewer unique records may remain than requested.

The first download can take minutes depending on the connection; cached collection is usually much faster. Click Collect once and wait for the success message. Repeating the same source/count/seed generally selects the same records and does not add another distinct set of 100.

In this program, multiple email sources means different underlying corpora: Enron and Nazario. They are both obtained through the same Zenodo publisher record. NVD, MITRE ATT&CK, and OpenPhish are separate threat-intelligence feeds, not automatic additions to the email training dataset.

## 4. Collect from two sources through the GUI

Open **Data Collection** and use **Collect directly from public sources**:

1. Select **Enron · legitimate emails**.
2. Set **Records per source** to 100.
3. Set **Use** to **Training / experiment split**.
4. Leave **Collection sample seed** at 42.
5. Click **Collect selected source into preview** and wait.
6. Scroll down to **Combined preview**. The first collection should contain legitimate records only.
7. Return to the source selector and choose **Nazario · phishing emails**.
8. Enter 100 and leave the same intended use and seed.
9. Collect again and inspect the combined preview.

If 100 unique records from each source are available, the preview now contains **100 legitimate + 100 phishing = 200 records**. Both classes are necessary for training. The success message means records entered your preview; they are not yet your saved experiment CSV.

### Import additional files

The lower collection form accepts CSV, EML, MSG, TXT, and MBOX files. Import each actual source separately:

1. Enter its real source name.
2. Enter its actual permitted-use/attribution notes.
3. Select intended use.
4. Select the correct default label for files without labels.
5. Choose files and click **Add to combined preview**.

For CSV, use a text column such as body, text, content, or email, and a label column. Subject is optional. Expand **CSV column mapping** if the headings differ. Labels can be legitimate/phishing or 0/1. The app also accepts ham/spam and benign/malicious mappings, but spam is not automatically equivalent to phishing: establish that your source's labels are appropriate before using it.

Do not assign one default label to a mixed collection of unlabeled legitimate and phishing messages. Default labels are supplied by the importer, not verified by the app. The reviewed checkbox means you actually reviewed the records; do not select it merely because import succeeded.

Imports are limited to 50 files, 8 MB per file, and 16 MB per request. Keep training, validation, and testing-only collections separate.

## 5. Save the collected data to a file

Below the combined preview, click **Save combined CSV**. The program creates:

```text
data/processed/dataset_<unique-id>.csv
data/dataset_manifest.csv
```

Your preview is a per-user draft, stored under data/raw/. Saving creates a separate versioned dataset and clears the draft. **Clear draft** discards the preview; it does not delete previously saved datasets.

Each saved record includes text/subject, normalized label, original label, source name/type, collection timestamp, original filename or source URL, review status, intended use, split assignment, and usage notes. URL and attachment-name fields are also retained when available.

The manifest summarizes source counts, class balance, permitted use, review status, and dataset checksum. The GUI redirects to Dataset Manager after saving.

## 6. Load the file and divide the data

Open **Dataset Manager**:

1. Choose your saved CSV under **Saved CSV**.
2. Click **Load dataset preview**.
3. Inspect its sources and both labels.
4. Choose **80 / 20** and split seed **42**.
5. Click **Save training and testing files**.

For an ordinary 200-record division, 160 records train the models and 40 are held out for testing. Stratification aims to preserve the class balance in both parts. Transitive groups of messages sharing exact URLs stay together; grouping can change the actual ratio. The requested and actual ratios are recorded.

The program writes a unique split folder containing:

```text
data/processed/<split-id>/training_set.csv
data/processed/<split-id>/testing_set.csv
data/processed/<split-id>/split.json
```

The split JSON records dataset identity/checksum, filenames/checksums, counts, ratio, and seed. Training records are marked training; held-out records are marked testing. Validation-only or testing-only datasets cannot be divided for training. Both classes need at least four unique records, but that minimum is a software constraint, not enough evidence for reliable detection.

## 7. Choose models like Figure 3 and train

Open **Train and Compare** and select your saved division.

To compare across the Figure 3 feature/model categories, choose **Compare all email feature methods**, select the models you want, and click **Start selected models** once.

| Feature option | Valid model choices | What learns from your saved training records |
|---|---|---|
| Word TF-IDF | Logistic Regression, Naive Bayes, calibrated Linear SVM, Random Forest | Fitted word features and classifier parameters |
| Word embeddings | LSTM | Vocabulary, word embeddings, recurrent weights, and output weights |
| Contextual representations | BERT, CTI-BERT | A supervised Logistic Regression classification head using frozen pretrained features |
| Compare all email feature methods | All seven email models above | Each model's corresponding training method, using the same saved division |
| Character TF-IDF | URL Logistic Regression | Separate URL character features and URL classifier |

Incompatible choices are disabled and also rejected by the server. The URL detector is separate because its input is a labeled URL, not an entire email.

### How learning works

Email input is the subject plus body. TF-IDF converts words into numeric features using 1–2 word n-grams, learned from training records. The classifier learns relationships between those features and the supplied labels. The SVM uses sigmoid calibration rather than treating a raw decision margin as a probability.

LSTM learns 64-dimensional word embeddings and a 64-unit recurrent representation, using three epochs and batches of eight. BERT variants tokenize text and produce contextual features; the app averages unmasked token representations and learns a classification head from your labeled training subset. Neural inputs are limited to 128 tokens, so long messages can be truncated. These settings are fixed in the implementation and recorded; they are not editable hyperparameter controls in the GUI.

### Pretrained weights are a different source from your email dataset

BERT loads [google-bert/bert-base-uncased](https://huggingface.co/google-bert/bert-base-uncased). CTI-BERT loads [ibm-research/CTI-BERT](https://huggingface.co/ibm-research/CTI-BERT). Their model cards explain upstream pretraining; CTI-BERT is intended for cybersecurity text.

Those pretrained weights provide language representations. Your saved email training records teach the local classification head the legitimate/phishing task. **The application freezes the transformer encoders; it does not fully fine-tune BERT or CTI-BERT and did not create their original pretraining corpora.** Checkpoint manifests record the model repository, pinned revision, and weight/configuration checksums.

Watch **Queued → Preprocessing → Training → Evaluating → Completed**. Use **Refresh status**. Neural models can take longer than traditional models; there is no fixed completion time. A failed run retains its error. One email-training job can run at a time. Restarting the server interrupts training; unfinished jobs become Failed and require explicit retraining.

## 8. Compare real results

All models in a run use the same saved training/testing records. Compare versions with the same run ID. Evaluation on the held-out testing set produces:

| Metric | How to explain it |
|---|---|
| Accuracy | Fraction of all test records classified correctly |
| Precision | Fraction of predicted phishing records that really have phishing labels |
| Recall | Fraction of phishing-labeled records detected |
| F1 | Balance between precision and recall |
| False positive | Legitimate email incorrectly predicted phishing |
| False negative | Phishing email incorrectly predicted legitimate |
| Confusion matrix | Actual labels in rows, predicted labels in columns; legitimate then phishing |
| Training time | Time required for that model's training procedure, including its evaluation preparation |

Expand model details to inspect the matrix and per-class results. Training-fold cross-validation provides another measured score; it does not replace independent validation. Feature learning stays within training folds; pretrained frozen representations are not learned from your test labels.

Download **Comparison CSV** and **Full experiment JSON** from a completed run. Error CSVs retain incorrect record IDs and expected/predicted labels. Report errors rather than hiding them. Never quote the attached paper's accuracy, historical recovered metrics, or a small verification result as the accuracy of your own experiment.

## 9. Evaluate independently collected records

After making your experiment split, collect additional records with **Use: Independent validation only**, save them, and open **Independent Validation**. Select the validation CSV and completed model versions, then click **Evaluate selected versions**.

Public validation collection excludes previously divided content and shared URLs. Evaluation checks overlap again, fits no model, and changes no deployment. It saves measured validation metrics, comparisons, and error files. Keep this dataset separate from future training data.

An unlabeled new email can receive a prediction, but it cannot establish accuracy. To measure accuracy, you need a trustworthy expected label for every evaluated record.

## 10. Deploy a version before testing new emails

Open **Model Management** and click **Deploy model** beside your preferred completed version. The active detector then uses that version for future scans. Its identity, deploying user/date, metrics, and previous version are recorded. Administrators can roll back to the previous version.

You do not have to deploy every comparison model. To inspect the same email under another model, deliberately deploy that version and run a new scan; history retains the earlier result and version. Training alone never replaces the active detector.

## 11. Test new email content

Open **Analyze Email**:

1. Paste an optional subject and new email content, or select message files.
2. Click **Analyze email / attachments**.
3. Inspect the prediction, confidence, risk, findings, and recommendation.

Pasted text and TXT files provide text only. EML/MSG can provide supplied headers, attachment information, and link destinations. Multiple files and MBOX support batches. Expand the attachment-only section to inspect supported attachments without an email.

The app uses the deployed email pipeline, extracts HTTP(S) URLs, checks configured rules, inspects attachments without executing them, and stores the scan. With a separately deployed URL detector, URLs also receive learned predictions. Otherwise, URL model output explicitly says unavailable while rule findings remain available.

Email-model confidence is different from final risk. Risk combines available email-model phishing probability (weight 0.55), maximum available URL-model phishing probability (0.25), and rule score (0.20), renormalizing available weights. Each counted rule finding adds 20 points to the rule score, capped at 100. Final risk is phishing at 70 or above, suspicious at 35–69.99, otherwise legitimate. An unavailable email model forces manual-review behavior if the result would otherwise appear legitimate. This heuristic is not a calibrated probability of real-world harm.

The program does not visit extracted links, execute uploaded files, connect to an email account, or automatically add private scans to training. Attachment findings are static risk evidence, not proof of malware. Authentication headers are supplied input, not independently verified sender authentication.

## 12. History, feedback, reports, and roles

- **Batch Scans & History:** revisit saved evidence and predictions. Authorized users export PDF/CSV reports.
- **Analyst Review:** approve or reject corrected labels and explicitly sanitized feedback. Approval creates a separate dataset; retraining/deployment remain deliberate.
- **Reports & Alerts:** download generated results and view locally stored high-risk alerts. Alerts are not automatically emailed externally.
- **Threat Intelligence:** optionally collect NVD, MITRE ATT&CK, and OpenPhish records with attribution notes. Its source-category classifier is separate from the binary email and URL classifiers; its labels are feed categories, not independent threat ground truth.
- **User Management:** administrators create users/change roles. Analysts collect/scan/submit feedback; senior analysts also divide/train/compare/deploy/review/export; administrators also manage retention and rollback.
- **Settings & Methodology:** inspect risk rules and configure retention. Saving a policy does not remove records. Explicit cleanup first creates a recoverable database snapshot.

## 13. Files you can show to explain your experiment

Paths below are relative to the project folder.

| File or folder | Evidence it provides |
|---|---|
| data/raw/public_sources/Enron.csv and Nazario.csv | Downloaded source CSVs |
| data/raw/public_sources/enron_provenance.json and nazario_provenance.json | Latest collection's source URL, checksums, sample seed, and counts; later collections update these summaries |
| data/processed/dataset_<id>.csv | Your saved combined records, original labels, sources, dates, permissions, and review metadata |
| data/dataset_manifest.csv | Dataset/source summaries and dataset checksum |
| data/processed/<split-id>/ | Actual training/testing files and reproducible split settings |
| data/validation/ | Saved independent validation-only datasets |
| results/<run-id>.json | Dataset/split identifiers, parameters, library versions, timing, and measured metrics |
| results/<run-id>_comparison.csv | Model comparison from one run |
| results/<run-id>_<version-id>_errors.csv | Misclassified held-out record IDs |
| results/validation_* | Independent validation results and errors |
| models/checkpoints/<model>/checkpoint_manifest.json | Pretrained repository, revision, and file checksums |
| models/versions/<version-id>/ | Saved inference pipeline and version metadata |
| cyber_threat.db | Users, imports, runs, deployment pointers, scans, feedback, and audit history |

Retain the original dataset, split files, experiment JSON, lockfile, and model metadata together. Record both collection seed and split seed. This lets someone identify the input and reproduce the experiment with the same data/environment. UUIDs/timestamps differ on reruns; platform/library differences can affect exact numerical results.

### A presentation explanation you can adapt

> We obtained labeled emails from the Enron and Nazario files in the Phishing Email Curated Datasets collection on Zenodo. Through our GUI, we selected legitimate Enron rows and phishing Nazario rows, recorded their provenance, and saved a combined CSV. We divided that saved dataset into training and held-out testing records with a recorded seed. We trained selected classifiers on the training subset and compared their measured predictions on the same held-out subset. We then deployed a chosen version and tested new email content. For BERT and CTI-BERT, we used pretrained frozen language encoders and trained local classification heads on our labeled training records.

Replace this explanation's counts, ratios, model selection, dates, and performance with the actual saved values from your experiment. Bring the manifest, split JSON, comparison CSV, and error counts as supporting evidence.

### Source attribution for the written report

Use the citation details requested on the [Zenodo record](https://zenodo.org/records/8339691): A. I. Champa, M. F. Rabbi, and M. F. Zibran, “Curated datasets and feature analysis for phishing email detection with machine learning,” ICMI, 2024; and “Why phishing emails escape detection: A closer look at the failure points,” ISDFS, 2024. Include dataset DOI 10.5281/zenodo.8339691 and your actual retrieval date. Cite the linked model cards when describing pretrained encoders.

## 14. Limits and troubleshooting

Using legitimate records from one corpus and phishing records from another can introduce source/style bias. Exact duplicate/shared-URL safeguards do not eliminate all similar campaigns, semantic duplicates, or corpus overlap. Historical messages may differ from current attacks. High scores on a small split do not establish reliable real-world protection.

| Situation | What to do |
|---|---|
| First 100 records are all legitimate | Expected for Enron; collect Nazario before training |
| Collected message appears but no dataset is listed | Scroll to preview and click Save combined CSV |
| Repeated collection does not increase counts | The same source/count/seed can select duplicates; deduplication keeps unique records |
| Collection takes time | Wait for the initial full download; do not repeatedly submit |
| Source/network/checksum error | Read the displayed message; do not relabel, bypass checks, or assume import succeeded |
| No saved division or training button unavailable | Save/load a training-use dataset and divide it first |
| LSTM/BERT disabled | Select its compatible feature option or Compare all email feature methods |
| Checkpoint setup needed | Administrator prepares official checkpoints in Model Management or runs setup_models.py |
| No email model deployed | Finish training and deploy a completed email version |
| One model misses an obvious example | Inspect version/data/features, record the error, and improve your labeled experiment; a prediction is not ground truth |
| Training stops after closing the terminal | Restart the server and explicitly restart the failed experiment |

No supplied EML test pack or EXPECTED_RESULTS.csv was available during initial verification. If your professor supplies them, evaluate and report their actual false positives/negatives. Historical missing database/model artifacts cannot be reconstructed from the supplied source files.

For implementation and verification details, see README.md, TRAINING_README.md, DATASET_README.md, and TESTING_REPORT.md. The instruction manual describes behavior; the saved experiment artifacts establish what you actually ran.
