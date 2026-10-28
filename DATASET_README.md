# Data collection and provenance

No fabricated training corpus or real-source labels are bundled. Obtain legitimately labeled data from sources you are permitted to use and import it through the GUI. Source names and license/usage notes are entered by the importer and are not independently verified. Collecting data is an explicit user action; the app does not scrape private email accounts or ask for their passwords.

CSV accepts one text column named body, text, content, or email, or a url column. Optional columns include subject, sender, reply_to, urls, attachment_names, label and split_assignment. Use the target column `label`; optional CSV column mapping lets you select different text, subject, and label headings. Labels must be legitimate/phishing, 0/1, ham/spam, or benign/malicious. A spam label does not establish phishing: only use that mapping when justified by the actual dataset definition. Unsupported labels and missing content are rejected rather than silently guessed. Unlabeled files receive the label explicitly selected by the importer.

EML, MSG, TXT and MBOX imports are labeled using the explicitly selected default label. Import files from different sources separately. Uploaded EML analysis scans are not collection imports and never automatically become training records.

Saved fields: record_id, subject, body, sender, reply_to, urls, attachment_names, label, source, source_type, original_label, collected_at (UTC), origin (import filename or source URL), reviewed, split_assignment, intended_use and usage_notes. Each saved CSV and per-source dataset_manifest.csv row receives a SHA-256 checksum. Original uploaded files are parsed in memory and not saved under their filenames; draft records are stored outside static/.

Deduplication compares case-normalized, whitespace-normalized subject/body (or URL if text is absent) and rejects conflicting labels/assignments. Stratified division requires both classes and at least four unique examples per class; realistic evaluation requires substantially more diverse data. Existing validation and testing-only assignments prevent division. Messages sharing exact URLs are grouped together during division. This is conservative leakage prevention, not semantic detection of paraphrases, campaign families or similar domains.

Independent validation-only CSVs are saved under data/validation/. Their content and URLs are checked when creating future training splits; validation records cannot be reassigned through the GUI. Validation that duplicates an existing experiment's content is rejected. Mixed-use collections should be saved as separate datasets; collections containing testing/validation records cannot be divided for training. The Independent Validation page evaluates selected completed versions without fitting or deploying them.

Historical validation_set.csv, validation_set.1.csv, validation_metrics.json and validation_errors.csv belong to the old three-class threat-report experiment. They are preserved in the recovery copy and working root; they are never imported into the new binary email model automatically.

For URL training, import one complete HTTP(S) URL per record and real labels. Include legitimate login pages, not only homepages. The selected character TF-IDF pipeline lowercases URLs and uses 2–5 character n-grams with Logistic Regression. The attached research paper motivates this separate detector; its reported accuracy is not an application result. False positives and false negatives are reported from your own held-out records.

## Direct public collection

The GUI downloads the Enron and Nazario CSV files from Champa, Rabbi and Zibran's curated corpus at https://zenodo.org/records/8339691. Published MD5 checksums and CC BY 4.0 metadata are verified before import. Only legitimate Enron records and phishing Nazario records are selected; labels are retained explicitly. This source separation can produce dataset bias, so report limitations alongside performance. Deterministic reservoir sampling uses the selected collection seed. Independent validation excludes previously divided content and shared URLs before sampling.

During division, transitive groups sharing exact URLs remain together. This prevents exact URL leakage, but does not establish campaign/domain-level independence. Grouping may alter the requested split ratio; the actual ratio is recorded. Cached public files are under data/raw/public_sources/. Never add private scan history automatically.
