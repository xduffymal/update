import re
import json
import joblib
import pandas as pd

from datetime import datetime

from database import get_db_connection

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)

MODEL_FILE = "threat_model.pkl"
VECTORIZER_FILE = "tfidf_vectorizer.pkl"
METADATA_FILE = "model_metadata.json"


def clean_text(text):
    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"[^a-zA-Z0-9\s.:/_-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def normalize_source(source):
    return (source or "").strip().lower()


def source_to_label(source):
    """
    Assign labels only when the source itself provides a clear category.

    This avoids training directly on the model's prior predictions.
    """
    source_name = normalize_source(source)

    # Vulnerability-focused authoritative sources
    if source_name in {
        "nvd",
        "cisa kev"
    }:
        return "vulnerability"

    # ATT&CK technique source
    if source_name in {
        "mitre",
        "mitre att&ck",
        "mitre attack"
    }:
        return "attack_technique"

    # Phishing-specific source
    if source_name in {
        "openphish"
    }:
        return "phishing"

    # Other sources are useful for ingestion but are not automatically
    # assigned a training label because their records may span categories.
    return None


def normalize_review_label(label):
    if not label:
        return None

    label = str(label).strip().lower()

    mapping = {
        "phishing": "phishing",
        "attack technique": "attack_technique",
        "attack_technique": "attack_technique",
        "vulnerability exploit": "vulnerability",
        "vulnerability": "vulnerability"
    }

    return mapping.get(label)


def load_training_data():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    training_rows = []

    # ------------------------------------------------------------
    # 1. Source-derived labels
    # ------------------------------------------------------------
    cursor.execute("""
        SELECT report_id, source, content
        FROM reports
        WHERE content IS NOT NULL
          AND TRIM(content) != ''
    """)

    for row in cursor.fetchall():
        label = source_to_label(row.get("source"))

        if label:
            training_rows.append({
                "report_id": row.get("report_id"),
                "source": row.get("source"),
                "content": row.get("content"),
                "label": label,
                "label_origin": "authoritative_source"
            })

    # ------------------------------------------------------------
    # 2. Analyst-corrected labels
    # ------------------------------------------------------------
    cursor.execute("""
        SELECT
            r.report_id,
            r.source,
            r.content,
            ar.corrected_threat_type
        FROM analyst_reviews ar
        JOIN reports r
          ON ar.report_id = r.report_id
        WHERE ar.use_for_retraining = 1
          AND ar.corrected_threat_type IS NOT NULL
          AND TRIM(ar.corrected_threat_type) != ''
          AND r.content IS NOT NULL
          AND TRIM(r.content) != ''
    """)

    for row in cursor.fetchall():
        label = normalize_review_label(row.get("corrected_threat_type"))

        if label:
            training_rows.append({
                "report_id": row.get("report_id"),
                "source": row.get("source"),
                "content": row.get("content"),
                "label": label,
                "label_origin": "analyst_review"
            })

    cursor.close()
    conn.close()

    df = pd.DataFrame(training_rows)

    if df.empty:
        raise ValueError(
            "No source-labeled training data found. "
            "Run NVD, MITRE ATT&CK, and OpenPhish feeds first."
        )

    df["cleaned_text"] = df["content"].apply(clean_text)

    df = df[df["cleaned_text"].str.strip() != ""]

    # If an analyst-reviewed version of the exact same report/text exists,
    # keep that over the automatic source label.
    df["origin_priority"] = df["label_origin"].map({
        "authoritative_source": 1,
        "analyst_review": 2
    }).fillna(0)

    df = df.sort_values("origin_priority", ascending=False)
    df = df.drop_duplicates(subset=["cleaned_text"], keep="first")

    # Require usable representation for every class.
    label_counts = df["label"].value_counts()

    required_labels = {
        "phishing",
        "attack_technique",
        "vulnerability"
    }

    missing_labels = sorted(required_labels - set(label_counts.index))

    if missing_labels:
        raise ValueError(
            "Training data is missing required class(es): "
            + ", ".join(missing_labels)
            + ". Run the corresponding live feeds before training."
        )

    low_count_labels = label_counts[label_counts < 4]

    if not low_count_labels.empty:
        raise ValueError(
            "Not enough examples for: "
            + ", ".join(
                f"{label} ({count})"
                for label, count in low_count_labels.items()
            )
            + ". At least 4 examples per class are required."
        )

    return df


def metric_bundle(y_true, y_pred, labels):
    accuracy = accuracy_score(y_true, y_pred)

    macro_precision, macro_recall, macro_f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="macro",
        zero_division=0
    )

    weighted_precision, weighted_recall, weighted_f1, _ = precision_recall_fscore_support(
        y_true,
        y_pred,
        labels=labels,
        average="weighted",
        zero_division=0
    )

    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0
    )

    matrix = confusion_matrix(
        y_true,
        y_pred,
        labels=labels
    )

    total_predictions = len(y_true)
    correct_predictions = int((y_true.to_numpy() == y_pred).sum())
    misclassified_predictions = int(total_predictions - correct_predictions)

    per_class = {}

    for class_index, label in enumerate(labels):
        tp = int(matrix[class_index, class_index])
        fp = int(matrix[:, class_index].sum() - tp)
        fn = int(matrix[class_index, :].sum() - tp)
        tn = int(matrix.sum() - tp - fp - fn)

        class_report = report.get(label, {})

        per_class[label] = {
            "precision": float(class_report.get("precision", 0)),
            "recall": float(class_report.get("recall", 0)),
            "f1_score": float(class_report.get("f1-score", 0)),
            "support": int(class_report.get("support", 0)),
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn
        }

    return {
        "accuracy": float(accuracy),
        "macro_precision": float(macro_precision),
        "macro_recall": float(macro_recall),
        "macro_f1_score": float(macro_f1),
        "weighted_precision": float(weighted_precision),
        "weighted_recall": float(weighted_recall),
        "weighted_f1_score": float(weighted_f1),
        "test_records": int(total_predictions),
        "correct_predictions": correct_predictions,
        "misclassified_predictions": misclassified_predictions,
        "confusion_matrix": matrix.tolist(),
        "per_class_metrics": per_class
    }


def train_models():
    df = load_training_data()

    print("\n========================================")
    print("SOURCE-LABELED DATASET")
    print("========================================")
    print(f"Total usable records: {len(df)}")
    print("\nClass distribution:")
    print(df["label"].value_counts())
    print("\nLabel origins:")
    print(df["label_origin"].value_counts())

    X_text = df["cleaned_text"]
    y = df["label"]

    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=1,
        max_df=0.95,
        sublinear_tf=True
    )

    X = vectorizer.fit_transform(X_text)

    label_order = [
        "attack_technique",
        "phishing",
        "vulnerability"
    ]

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y
    )

    models = {
        "Naive Bayes": MultinomialNB(),
        "Logistic Regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced"
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced"
        ),
        "Linear SVM": LinearSVC(
            class_weight="balanced"
        )
    }

    deployable_models = {
        "Naive Bayes",
        "Logistic Regression",
        "Random Forest"
    }

    results = []

    best_model = None
    best_name = ""
    best_metrics = None
    best_accuracy = -1.0

    for name, model in models.items():
        model.fit(X_train, y_train)
        predictions = model.predict(X_test)

        metrics = metric_bundle(
            y_test,
            predictions,
            label_order
        )

        try:
            cv_scores = cross_val_score(
                model,
                X,
                y,
                cv=3,
                scoring="accuracy"
            )
            cv_average = float(cv_scores.mean())
            cv_scores_list = [float(score) for score in cv_scores]
        except Exception as error:
            print(f"Cross-validation warning for {name}: {error}")
            cv_average = None
            cv_scores_list = []

        result = {
            "model_name": name,
            **metrics,
            "cross_validation_average": cv_average,
            "cross_validation_scores": cv_scores_list,
            "deployable_with_current_dashboard": name in deployable_models
        }

        results.append(result)

        print("\n========================================")
        print(f"MODEL: {name}")
        print("========================================")
        print(f"Accuracy:           {metrics['accuracy']:.4f}")
        print(f"Weighted Precision: {metrics['weighted_precision']:.4f}")
        print(f"Weighted Recall:    {metrics['weighted_recall']:.4f}")
        print(f"Weighted F1 Score:  {metrics['weighted_f1_score']:.4f}")
        print(f"Macro Precision:    {metrics['macro_precision']:.4f}")
        print(f"Macro Recall:       {metrics['macro_recall']:.4f}")
        print(f"Macro F1 Score:     {metrics['macro_f1_score']:.4f}")

        if cv_average is not None:
            print(f"3-Fold CV Average:  {cv_average:.4f}")

        print(f"Correct:            {metrics['correct_predictions']}")
        print(f"Misclassified:      {metrics['misclassified_predictions']}")

        print("\nClassification Report:")
        print(
            classification_report(
                y_test,
                predictions,
                labels=label_order,
                zero_division=0
            )
        )

        print("Confusion Matrix:")
        print(
            confusion_matrix(
                y_test,
                predictions,
                labels=label_order
            )
        )

        if (
            name in deployable_models
            and metrics["accuracy"] > best_accuracy
        ):
            best_accuracy = metrics["accuracy"]
            best_model = model
            best_name = name
            best_metrics = metrics

    if best_model is None:
        raise RuntimeError("No deployable model was selected.")

    joblib.dump(best_model, MODEL_FILE)
    joblib.dump(vectorizer, VECTORIZER_FILE)

    best_result = next(
        item for item in results
        if item["model_name"] == best_name
    )

    metadata = {
        "status": "trained",
        "dataset_strategy": (
            "Labels are derived from authoritative source categories "
            "(NVD/CISA KEV=vulnerability, MITRE ATT&CK=attack_technique, "
            "OpenPhish=phishing) with analyst-reviewed corrections taking priority."
        ),
        "best_model": best_name,
        "best_accuracy": float(best_metrics["accuracy"]),
        "precision": float(best_metrics["weighted_precision"]),
        "recall": float(best_metrics["weighted_recall"]),
        "f1_score": float(best_metrics["weighted_f1_score"]),
        "macro_precision": float(best_metrics["macro_precision"]),
        "macro_recall": float(best_metrics["macro_recall"]),
        "macro_f1_score": float(best_metrics["macro_f1_score"]),
        "cross_validation_average": best_result["cross_validation_average"],
        "training_records": int(len(df)),
        "training_split_records": int(len(y_train)),
        "validation_records": int(len(y_test)),
        "correct_predictions": int(best_metrics["correct_predictions"]),
        "misclassified_predictions": int(best_metrics["misclassified_predictions"]),
        "labels": label_order,
        "label_distribution": {
            str(label): int(count)
            for label, count in df["label"].value_counts().to_dict().items()
        },
        "label_origin_distribution": {
            str(origin): int(count)
            for origin, count in df["label_origin"].value_counts().to_dict().items()
        },
        "confusion_matrix": best_metrics["confusion_matrix"],
        "per_class_metrics": best_metrics["per_class_metrics"],
        "model_results": results,
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "evaluation_note": (
            "This is a stronger source-labeled baseline evaluation. "
            "For the final formal capstone validation, preserve a separately "
            "reviewed holdout set that is not used during model selection or retraining."
        )
    }

    with open(METADATA_FILE, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4)

    print("\n========================================")
    print("BEST DEPLOYABLE MODEL SELECTED")
    print("========================================")
    print(f"Model:              {best_name}")
    print(f"Accuracy:           {metadata['best_accuracy']:.4f}")
    print(f"Precision:          {metadata['precision']:.4f}")
    print(f"Recall:             {metadata['recall']:.4f}")
    print(f"F1 Score:           {metadata['f1_score']:.4f}")
    print(f"Cross Validation:   {metadata['cross_validation_average']:.4f}")
    print(f"Training Records:   {metadata['training_records']}")
    print(f"Validation Records: {metadata['validation_records']}")
    print(f"Correct:            {metadata['correct_predictions']}")
    print(f"Misclassified:      {metadata['misclassified_predictions']}")
    print("\nClass Distribution:")
    for label, count in metadata["label_distribution"].items():
        print(f"  {label}: {count}")
    print(f"\nSaved: {MODEL_FILE}")
    print(f"Saved: {VECTORIZER_FILE}")
    print(f"Saved: {METADATA_FILE}")

    return metadata


def predict_sample_texts():
    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)

    sample_texts = [
        "This vulnerability allows remote attackers to execute arbitrary code on exposed systems.",
        "Adversaries use command and scripting interpreters to execute malicious commands.",
        "A fake login page was used to steal usernames and passwords from employees."
    ]

    cleaned_samples = [
        clean_text(text)
        for text in sample_texts
    ]

    vectors = vectorizer.transform(cleaned_samples)
    predictions = model.predict(vectors)

    print("\nSample Predictions:")

    for text, prediction in zip(sample_texts, predictions):
        print(f"\nText: {text}")
        print(f"Predicted Label: {prediction}")


if __name__ == "__main__":
    metadata = train_models()
    predict_sample_texts()
