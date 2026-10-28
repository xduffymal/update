PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL,
    access_level INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    source TEXT,
    content TEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INTEGER,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
);

CREATE TABLE IF NOT EXISTS threat_classifications (
    classification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    threat_type TEXT,
    severity TEXT,
    confidence_score REAL,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    indicator_type TEXT,
    indicator_value TEXT,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS summaries (
    summary_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    summary_text TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS attack_events (
    attack_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    country TEXT,
    region TEXT,
    city TEXT,
    endpoint TEXT,
    method TEXT,
    payload_snippet TEXT,
    attack_type TEXT,
    technique TEXT,
    severity TEXT,
    confidence_score REAL,
    denied INTEGER DEFAULT 0,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    block_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    reason TEXT,
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analyst_reviews (
    review_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    review_status TEXT,
    review_note TEXT,
    reviewer_name TEXT,
    corrected_threat_type TEXT,
    corrected_severity TEXT,
    escalated INTEGER DEFAULT 0,
    use_for_retraining INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS feed_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT,
    records_fetched INTEGER,
    records_added INTEGER,
    run_status TEXT,
    notes TEXT,
    run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_predictions (
    prediction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    input_text TEXT,
    cleaned_text TEXT,
    predicted_label TEXT,
    confidence_score REAL,
    source_ip TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS threat_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prediction_id INTEGER,
    alert_message TEXT,
    alert_level TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (prediction_id)
        REFERENCES threat_predictions(prediction_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS report_correlations (
    correlation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    related_report_id INTEGER NOT NULL,
    shared_iocs TEXT,
    similarity_score REAL,
    relationship_type TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id)
        REFERENCES reports(report_id)
        ON DELETE CASCADE,

    FOREIGN KEY (related_report_id)
        REFERENCES reports(report_id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cve_data (
    cve_data_id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT UNIQUE,
    description TEXT,
    published_date TEXT
);

CREATE TABLE IF NOT EXISTS extracted_relations (
    relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    subject_type TEXT,
    subject_value TEXT,
    relation_type TEXT,
    object_type TEXT,
    object_value TEXT,
    confidence_score REAL DEFAULT 0.75,
    explanation TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (report_id)
        REFERENCES reports(report_id)
        ON DELETE CASCADE
);


