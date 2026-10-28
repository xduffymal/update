"""Compare optional CTI-BERT semantic classification with the frozen baseline."""

import json
import time
from datetime import datetime

import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

from bert_transformer_layer import MODEL_NAME, predict_batch
from evaluate_validation import clean_text

VALIDATION_FILE = "validation_set.csv"
BASELINE_MODEL_FILE = "threat_model.pkl"
BASELINE_VECTORIZER_FILE = "tfidf_vectorizer.pkl"
OUTPUT_FILE = "transformer_comparison.json"
LABELS = ["attack_technique", "phishing", "vulnerability"]


def calculate_metrics(y_true, y_pred, elapsed):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average="weighted", zero_division=0
    )
    macro_p, macro_r, macro_f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average="macro", zero_division=0
    )
    per_p, per_r, per_f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average=None, zero_division=0
    )
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision), "recall": float(recall), "f1_score": float(f1),
        "macro_precision": float(macro_p), "macro_recall": float(macro_r), "macro_f1_score": float(macro_f1),
        "processing_seconds": round(elapsed, 4),
        "milliseconds_per_record": round((elapsed * 1000) / len(y_true), 2),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=LABELS).tolist(),
        "per_class": {
            label: {"precision": float(per_p[i]), "recall": float(per_r[i]),
                    "f1_score": float(per_f1[i]), "support": int(support[i])}
            for i, label in enumerate(LABELS)
        }
    }


def main():
    df = pd.read_csv(VALIDATION_FILE)
    df = df[df["true_label"].isin(LABELS) & df["text"].fillna("").str.strip().ne("")].copy()
    if set(df["true_label"]) != set(LABELS):
        raise ValueError("The frozen validation set must contain all three classes.")

    baseline_model = joblib.load(BASELINE_MODEL_FILE)
    baseline_vectorizer = joblib.load(BASELINE_VECTORIZER_FILE)
    start = time.perf_counter()
    baseline_pred = baseline_model.predict(baseline_vectorizer.transform(df["text"].map(clean_text)))
    baseline_elapsed = time.perf_counter() - start

    start = time.perf_counter()
    transformer_output = predict_batch(df["text"].tolist())
    transformer_elapsed = time.perf_counter() - start
    transformer_pred = [item["label"] for item in transformer_output]

    comparison = {
        "status": "completed", "evaluated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "validation_records": int(len(df)), "labels": LABELS,
        "holdout_policy": "The same frozen 30-record validation set was used for both models and was not used for training.",
        "baseline": {"model_name": type(baseline_model).__name__, **calculate_metrics(df["true_label"], baseline_pred, baseline_elapsed)},
        "transformer": {"model_name": MODEL_NAME, "method": "cyber-domain semantic prototype classification",
                        **calculate_metrics(df["true_label"], transformer_pred, transformer_elapsed)},
    }
    comparison["accuracy_change"] = comparison["transformer"]["accuracy"] - comparison["baseline"]["accuracy"]
    comparison["phishing_recall_change"] = (
        comparison["transformer"]["per_class"]["phishing"]["recall"]
        - comparison["baseline"]["per_class"]["phishing"]["recall"]
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(comparison, file, indent=4)

    print("\nCTI-BERT COMPARISON")
    print("=" * 48)
    print(f"Validation records: {len(df)}")
    print(f"Baseline accuracy:   {comparison['baseline']['accuracy']:.4f}")
    print(f"CTI-BERT accuracy:   {comparison['transformer']['accuracy']:.4f}")
    print(f"Baseline phishing recall: {comparison['baseline']['per_class']['phishing']['recall']:.4f}")
    print(f"CTI-BERT phishing recall: {comparison['transformer']['per_class']['phishing']['recall']:.4f}")
    print(f"Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
