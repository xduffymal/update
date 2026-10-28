import json
import re
import joblib
import pandas as pd

from datetime import datetime

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)


VALIDATION_FILE = "validation_set.csv"

MODEL_FILE = "threat_model.pkl"

VECTORIZER_FILE = "tfidf_vectorizer.pkl"

OUTPUT_JSON = "validation_metrics.json"

ERRORS_CSV = "validation_errors.csv"


ALLOWED_LABELS = {
    "phishing",
    "vulnerability",
    "attack_technique"
}


def clean_text(text):

    if not text:
        return ""

    text = str(text).lower()

    text = re.sub(
        r"[^a-zA-Z0-9\s.:/_-]",
        " ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    return text


def load_validation_data():

    df = pd.read_csv(VALIDATION_FILE)

    required_columns = {
        "text",
        "true_label"
    }

    missing = required_columns - set(df.columns)

    if missing:

        raise ValueError(
            "validation_set.csv is missing required column(s): "
            + ", ".join(sorted(missing))
        )


    df["true_label"] = (
        df["true_label"]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.lower()
    )


    df["text"] = (
        df["text"]
        .fillna("")
        .astype(str)
    )


    # Only evaluate rows that have been manually labeled.
    df = df[
        (df["true_label"] != "")
        &
        (df["text"].str.strip() != "")
    ].copy()


    invalid_labels = sorted(
        set(df["true_label"]) - ALLOWED_LABELS
    )


    if invalid_labels:

        raise ValueError(
            "Invalid true_label value(s): "
            + ", ".join(invalid_labels)
            + ". Allowed labels are: "
            "phishing, vulnerability, attack_technique."
        )


    if len(df) < 15:

        raise ValueError(
            f"Only {len(df)} labeled validation records were found. "
            "At least 15 labeled records are required."
        )


    present_classes = sorted(
        set(df["true_label"])
    )


    missing_classes = sorted(
        ALLOWED_LABELS - set(df["true_label"])
    )


    if missing_classes:

        print()
        print("========================================")
        print("VALIDATION WARNING")
        print("========================================")

        print(
            "Independent validation does not currently include: "
            + ", ".join(missing_classes)
        )

        print(
            "Results will be reported as a PARTIAL independent "
            "validation using only the classes currently present."
        )

        print()


    return df


def evaluate():

    df = load_validation_data()


    print()
    print("Loading trained model...")


    model = joblib.load(
        MODEL_FILE
    )


    vectorizer = joblib.load(
        VECTORIZER_FILE
    )


    cleaned_text = df[
        "text"
    ].apply(
        clean_text
    )


    vectors = vectorizer.transform(
        cleaned_text
    )


    predictions = model.predict(
        vectors
    )


    df["predicted_label"] = predictions


    # ------------------------------------------------------------
    # Confidence Score
    # ------------------------------------------------------------

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = model.predict_proba(
            vectors
        )

        df["confidence_score"] = (
            probabilities.max(
                axis=1
            )
        )

    else:

        df["confidence_score"] = None


    # ------------------------------------------------------------
    # Only evaluate classes actually present in the validation set
    # ------------------------------------------------------------

    label_order = sorted(
        df[
            "true_label"
        ].unique().tolist()
    )


    missing_classes = sorted(
        ALLOWED_LABELS - set(label_order)
    )


    # ------------------------------------------------------------
    # Accuracy
    # ------------------------------------------------------------

    accuracy = accuracy_score(

        df["true_label"],

        df["predicted_label"]

    )


    # ------------------------------------------------------------
    # Macro Metrics
    # ------------------------------------------------------------

    (
        macro_precision,
        macro_recall,
        macro_f1,
        _
    ) = precision_recall_fscore_support(

        df["true_label"],

        df["predicted_label"],

        labels=label_order,

        average="macro",

        zero_division=0

    )


    # ------------------------------------------------------------
    # Weighted Metrics
    # ------------------------------------------------------------

    (
        weighted_precision,
        weighted_recall,
        weighted_f1,
        _
    ) = precision_recall_fscore_support(

        df["true_label"],

        df["predicted_label"],

        labels=label_order,

        average="weighted",

        zero_division=0

    )


    # ------------------------------------------------------------
    # Classification Report
    # ------------------------------------------------------------

    report = classification_report(

        df["true_label"],

        df["predicted_label"],

        labels=label_order,

        output_dict=True,

        zero_division=0

    )


    # ------------------------------------------------------------
    # Confusion Matrix
    # ------------------------------------------------------------

    matrix = confusion_matrix(

        df["true_label"],

        df["predicted_label"],

        labels=label_order

    )


    # ------------------------------------------------------------
    # Find Incorrect Predictions
    # ------------------------------------------------------------

    errors = df[

        df["true_label"]
        !=
        df["predicted_label"]

    ].copy()


    errors.to_csv(

        ERRORS_CSV,

        index=False,

        encoding="utf-8-sig"

    )


    # ------------------------------------------------------------
    # Per-Class Error Analysis
    # ------------------------------------------------------------

    per_class = {}


    for index, label in enumerate(
        label_order
    ):


        true_positive = int(
            matrix[
                index,
                index
            ]
        )


        false_positive = int(
            matrix[
                :,
                index
            ].sum()
            - true_positive
        )


        false_negative = int(
            matrix[
                index,
                :
            ].sum()
            - true_positive
        )


        true_negative = int(
            matrix.sum()
            - true_positive
            - false_positive
            - false_negative
        )


        class_report = report.get(
            label,
            {}
        )


        per_class[
            label
        ] = {

            "precision": float(
                class_report.get(
                    "precision",
                    0
                )
            ),

            "recall": float(
                class_report.get(
                    "recall",
                    0
                )
            ),

            "f1_score": float(
                class_report.get(
                    "f1-score",
                    0
                )
            ),

            "support": int(
                class_report.get(
                    "support",
                    0
                )
            ),

            "true_positives":
                true_positive,

            "false_positives":
                false_positive,

            "false_negatives":
                false_negative,

            "true_negatives":
                true_negative
        }


    # ------------------------------------------------------------
    # Overall Correct / Incorrect
    # ------------------------------------------------------------

    correct_predictions = int(

        (
            df["true_label"]
            ==
            df["predicted_label"]
        ).sum()

    )


    misclassified_predictions = int(
        len(errors)
    )


    # ------------------------------------------------------------
    # Validation Type
    # ------------------------------------------------------------

    if missing_classes:

        evaluation_type = (
            "partial_independent_human_labeled_validation"
        )

        validation_status = "partial"

    else:

        evaluation_type = (
            "independent_mixed_provenance_labeled_validation"
        )

        validation_status = "complete"


    # ------------------------------------------------------------
    # Save Metrics
    # ------------------------------------------------------------

    metrics = {

        "status":
            "completed",

        "validation_status":
            validation_status,

        "evaluation_type":
            evaluation_type,

        "evaluated_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "classes_evaluated":
            label_order,

        "classes_missing":
            missing_classes,

        "validation_records":
            int(len(df)),

        "accuracy":
            float(accuracy),

        "precision":
            float(
                weighted_precision
            ),

        "recall":
            float(
                weighted_recall
            ),

        "f1_score":
            float(
                weighted_f1
            ),

        "macro_precision":
            float(
                macro_precision
            ),

        "macro_recall":
            float(
                macro_recall
            ),

        "macro_f1_score":
            float(
                macro_f1
            ),

        "correct_predictions":
            correct_predictions,

        "misclassified_predictions":
            misclassified_predictions,

        "labels":
            label_order,

        "confusion_matrix":
            matrix.tolist(),

        "per_class_metrics":
            per_class,

        "class_distribution": {

            str(label):
                int(count)

            for label, count

            in df[
                "true_label"
            ].value_counts().to_dict().items()

        },

        "error_file":
            ERRORS_CSV,

        "external_validation_source":
            "University of Twente / Zenodo phishing validation emails dataset",

        "external_validation_doi":
            "10.5281/zenodo.13474746",

        "holdout_policy":
            "Validation records are excluded from training, model selection, and retraining.",

        "validation_note":

            (
                "This evaluation uses independently reviewed records "
                "that were not used as automatic source labels during training. "
                "Because phishing is not currently represented in this validation "
                "set, these results should be interpreted as a partial validation "
                "of the classes that are present."
                if missing_classes
                else
                "This evaluation uses independently reviewed vulnerability and "
                "attack-technique records plus distinct phishing examples from an "
                "external curated validation dataset. All validation records are "
                "held out from training and model selection."
            )
    }


    with open(

        OUTPUT_JSON,

        "w",

        encoding="utf-8"

    ) as file:

        json.dump(

            metrics,

            file,

            indent=4

        )


    # ------------------------------------------------------------
    # Terminal Output
    # ------------------------------------------------------------

    print()

    print(
        "========================================"
    )

    if validation_status == "partial":

        print(
            "PARTIAL INDEPENDENT VALIDATION RESULTS"
        )

    else:

        print(
            "INDEPENDENT VALIDATION RESULTS"
        )

    print(
        "========================================"
    )


    print(
        f"Validation Records: "
        f"{metrics['validation_records']}"
    )


    print(
        f"Classes Evaluated:  "
        f"{', '.join(label_order)}"
    )


    if missing_classes:

        print(
            f"Classes Missing:    "
            f"{', '.join(missing_classes)}"
        )


    print()


    print(
        f"Accuracy:           "
        f"{metrics['accuracy']:.4f}"
    )


    print(
        f"Precision:          "
        f"{metrics['precision']:.4f}"
    )


    print(
        f"Recall:             "
        f"{metrics['recall']:.4f}"
    )


    print(
        f"F1 Score:           "
        f"{metrics['f1_score']:.4f}"
    )


    print()


    print(
        f"Macro Precision:    "
        f"{metrics['macro_precision']:.4f}"
    )


    print(
        f"Macro Recall:       "
        f"{metrics['macro_recall']:.4f}"
    )


    print(
        f"Macro F1 Score:     "
        f"{metrics['macro_f1_score']:.4f}"
    )


    print()


    print(
        f"Correct:            "
        f"{metrics['correct_predictions']}"
    )


    print(
        f"Misclassified:      "
        f"{metrics['misclassified_predictions']}"
    )


    # ------------------------------------------------------------
    # Class Distribution
    # ------------------------------------------------------------

    print()

    print(
        "CLASS DISTRIBUTION"
    )


    for label, count in (

        metrics[
            "class_distribution"
        ].items()

    ):

        print(
            f"{label}: {count}"
        )


    # ------------------------------------------------------------
    # Confusion Matrix
    # ------------------------------------------------------------

    print()

    print(
        "CONFUSION MATRIX"
    )

    print(
        "Label order:",
        label_order
    )

    print(
        matrix
    )


    # ------------------------------------------------------------
    # Per-Class Error Analysis
    # ------------------------------------------------------------

    print()

    print(
        "PER-CLASS ERROR ANALYSIS"
    )


    for label, values in (
        per_class.items()
    ):

        print(

            f"{label}: "
            f"Precision={values['precision']:.4f} | "
            f"Recall={values['recall']:.4f} | "
            f"F1={values['f1_score']:.4f} | "
            f"FP={values['false_positives']} | "
            f"FN={values['false_negatives']}"

        )


    # ------------------------------------------------------------
    # Misclassified Examples
    # ------------------------------------------------------------

    print()

    if len(errors) > 0:

        print(
            "MISCLASSIFIED EXAMPLES"
        )

        for _, row in errors.iterrows():

            title = (
                row.get(
                    "title",
                    ""
                )
                if "title" in row
                else ""
            )

            source = (
                row.get(
                    "source",
                    ""
                )
                if "source" in row
                else ""
            )

            print()

            print(
                f"Validation ID: "
                f"{row.get('validation_id', '')}"
            )

            print(
                f"Source: "
                f"{source}"
            )

            print(
                f"Title: "
                f"{title}"
            )

            print(
                f"True Label: "
                f"{row['true_label']}"
            )

            print(
                f"Predicted: "
                f"{row['predicted_label']}"
            )

            if (
                "confidence_score" in row
                and
                pd.notna(
                    row[
                        "confidence_score"
                    ]
                )
            ):

                print(
                    f"Confidence: "
                    f"{row['confidence_score']:.4f}"
                )

    else:

        print(
            "No misclassified examples "
            "were found in this validation set."
        )


    # ------------------------------------------------------------
    # Files Saved
    # ------------------------------------------------------------

    print()

    print(
        f"Saved metrics: "
        f"{OUTPUT_JSON}"
    )

    print(
        f"Saved errors: "
        f"{ERRORS_CSV}"
    )


if __name__ == "__main__":

    evaluate()
