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
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
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
);

CREATE TABLE IF NOT EXISTS indicators (
    indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    indicator_type TEXT,
    indicator_value TEXT,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
);

CREATE TABLE IF NOT EXISTS summaries (
    summary_id INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL,
    summary_text TEXT,
    generated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
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
    event_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    block_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    reason TEXT,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);

INSERT OR IGNORE INTO users (
    username,
    password,
    role,
    access_level
)
VALUES (
    'analyst1',
    'password123',
    'analyst',
    1
);