# GUI demonstration

1. Start `run.py` using the commands in README.md. Create the first administrator account if prompted and log in.
2. Open **Data Collection**. Select labeled CSV, EML, MSG, TXT or MBOX files, enter the real source name and usage notes, choose a default label for files without labels, and select intended use. Import legitimate and phishing records from at least two real sources. Import sources in separate actions so provenance is correct.
3. Inspect the combined preview and class counts. Duplicates are removed; conflicts or missing text are reported. Select **Save combined CSV**. The manifest is saved automatically.
4. Open **Dataset Manager**. Select that saved CSV and press **Load dataset preview**. Inspect labels and source records. Choose **80 / 20** and a random seed such as 42, then **Save training and testing files**. Download links let you inspect the separate files.
5. Open **Train and Compare**. Choose the saved division and **Word TF-IDF**. Select Logistic Regression, Naive Bayes, and Random Forest; optionally select calibrated Linear SVM. Press **Start selected models** once. Refresh status to see Queued, Preprocessing, Training, Evaluating, Completed or Failed.
6. Review accuracy, precision, recall, F1, false positives/negatives, timing, per-class metrics and confusion matrices. The F1 bars use saved measured values. Compare only versions sharing the same run ID. Download experiment JSON/comparison CSV when needed.
7. Open **Model Management** and **Deploy model** for your preferred completed version. Email and URL detectors are deployed separately. Training never deploys automatically. Administrators can restore the previous version with **Roll back**.
8. Open **Analyze Email**. Paste unseen text and optionally a subject, or upload EML/MSG/TXT files. Multiple files and MBOX process a batch. Dragging onto the native file chooser may work in your browser; a custom drop zone is not provided.
9. Inspect email-model prediction/confidence, URL-model output, supplied headers, rule/attachment evidence, combined risk and recommendation. No extracted link is visited. With no deployed email model, the application explicitly requires manual review.
10. Open **Batch Scans & History** to revisit results. Senior analysts/administrators can export each saved scan to CSV or PDF.
11. Submit a corrected label and explicitly sanitized text. Remove names, private identifiers, account data and tokens. A senior analyst must approve the record in **Analyst Review** before it becomes a new dataset. Approval does not train or deploy anything automatically. Add approved records to a future explicitly prepared experiment through collection.

Administrators can create analysts/senior analysts in **User Management**. Role controls are enforced on the server as well as in navigation. Analysts cannot split, train, deploy, approve feedback, export reports or roll back models.

**Settings & Methodology** documents the exact risk formula and limitations. **Threat Intelligence** retains access to the recovered report/feed workspace; collect NVD, MITRE ATT&CK and OpenPhish with attribution notes, then train and deliberately deploy its separate threat-report model. These labels are feed source categories, not independent ground truth.

Data Collection also downloads real public Enron legitimate and Nazario phishing subsets directly into the combined preview. Select a source and count, collect each source separately, inspect, then save. Attribution, collection seed, original labels and checksums are preserved. Optional CSV column mapping supports differently named text/label/subject fields.

To select the Figure 3 options together, choose **Compare all email feature methods** in Train and Compare, then select LSTM, BERT, CTI-BERT and any traditional email models. Every selected model uses the same saved split. The separate character URL detector needs URL-labeled records, including legitimate login URLs.

For independent testing, collect records with **Independent validation only**, save them, then open **Independent Validation**, select the dataset and trained versions, and evaluate. This fits nothing and changes no deployment. Reports & Alerts lists generated comparisons/errors and local high-risk alerts. Analyze Email also accepts attachment-only scans. Entities and correlation appear in expandable evidence.

Administrators can update roles in User Management; the last administrator cannot be demoted. Settings saves retention days (0 disables). Cleanup is explicit, preserves model/user/dataset data, and first saves a recoverable database snapshot.

## Preprocessing comparison and statistical correlation

Open **Preprocessing & Correlation** as a senior analyst or administrator. Select a saved division and click **Train all preprocessing methods**. Refresh status until completion, then open the saved comparison. Seven methods use the same Logistic Regression parameters: word counts, word TF-IDF, cleaned TF-IDF, stopword TF-IDF, stemmed TF-IDF, word bigram TF-IDF, and character TF-IDF applied to complete email text. This comparison does not exhaust every possible NLP preprocessing method.

The selected method has the highest training cross-validation macro F1. Each fold fits its own preprocessing and vocabulary. Ties select the first listed method. Accuracy, phishing precision/recall/F1, confusion matrices, per-class classification reports, timings and downloadable predictions describe the same held-out records. Bar graphs compare metrics and class counts. Avoid repeatedly tuning against these test results; use Independent Validation for a final separate evaluation.

The Pearson heatmap measures training-data relationships among message length, word count, URL count, exclamation marks, urgency terms and the binary phishing label. Correlation with the label is point-biserial. Constant columns show Undefined. These relationships can reflect source differences and do not establish causation.

Enter email content in **Test one new email**, then click **Predict and save result**. The selected pipeline loads from disk and saves the text, prediction and uncalibrated class probabilities to a downloadable JSON file. The supplied example is illustrative, with no verified ground truth. Prediction labels are legitimate and phishing. Identifying ransomware or other attack types needs separately labeled multiclass data and evaluation.

To train with more data, collect larger samples from both sources or import additional independently labeled email sources, save a new CSV and create a new split. More records or training iterations alone do not guarantee improved accuracy.

**Create synthetic data and train** generates 96 explicitly synthetic records with legitimate, phishing, ransomware and malware labels. It saves a complete dataset CSV, 72 training records and 24 testing records. All variants of a template stay in the same partition. Seven preprocessing methods use the same Logistic Regression classifier; multiclass results show macro precision/recall/F1 and four-class confusion matrices. The selected method can predict new text and save its result. These models stay separate from deployment and real datasets. This is a demonstration of category wording, not a validated attack detector.
