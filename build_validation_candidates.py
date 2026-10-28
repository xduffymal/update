import csv
from database import get_db_connection

OUTPUT_FILE = "validation_set.csv"
MAX_RECORDS = 60

# These sources were already used to create the training labels.
# We exclude them here so the validation data is more independent.
EXCLUDED_TRAINING_SOURCES = {
    "NVD",
    "CISA KEV",
    "MITRE ATT&CK",
    "MITRE",
    "OpenPhish"
}


def build_validation_candidates():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT report_id, title, source, content, upload_date
        FROM reports
        WHERE content IS NOT NULL
          AND TRIM(content) != ''
        ORDER BY upload_date DESC
    """)

    rows = cursor.fetchall()

    cursor.close()
    conn.close()

    candidates = []

    for row in rows:
        source = (row.get("source") or "Unknown").strip()

        # Do not use the same source categories used for training.
        if source in EXCLUDED_TRAINING_SOURCES:
            continue

        candidates.append({
            "validation_id": len(candidates) + 1,
            "report_id": row.get("report_id"),
            "source": source,
            "title": row.get("title") or "",
            "text": row.get("content") or "",
            "true_label": "",
            "reviewer_notes": ""
        })

        if len(candidates) >= MAX_RECORDS:
            break

    if not candidates:
        raise ValueError(
            "No independent validation candidates were found. "
            "Run the URLhaus, Feodo Tracker, CISA Advisories, "
            "or add manual reports first."
        )

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "validation_id",
                "report_id",
                "source",
                "title",
                "text",
                "true_label",
                "reviewer_notes"
            ]
        )

        writer.writeheader()
        writer.writerows(candidates)

    print()
    print("========================================")
    print("VALIDATION CANDIDATE SET CREATED")
    print("========================================")
    print(f"File: {OUTPUT_FILE}")
    print(f"Candidate Records: {len(candidates)}")

    print()
    print("NEXT STEP:")
    print("Open validation_set.csv")
    print()
    print("Fill true_label with ONE of:")
    print("phishing")
    print("vulnerability")
    print("attack_technique")
    print()
    print("Leave unclear records blank.")
    print()
    print(
        "Try to label at least 30 total records "
        "with examples from all 3 classes."
    )


if __name__ == "__main__":
    build_validation_candidates()