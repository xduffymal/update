CREATE DATABASE IF NOT EXISTS nlp_cyber_db;
USE nlp_cyber_db;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    access_level INT NOT NULL
);

CREATE TABLE reports (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    source VARCHAR(255),
    content LONGTEXT NOT NULL,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INT,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id)
);

CREATE TABLE threat_classifications (
    classification_id INT AUTO_INCREMENT PRIMARY KEY,
    report_id INT NOT NULL,
    threat_type VARCHAR(100),
    severity VARCHAR(50),
    confidence_score DECIMAL(5,2),
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
);

CREATE TABLE indicators (
    indicator_id INT AUTO_INCREMENT PRIMARY KEY,
    report_id INT NOT NULL,
    indicator_type VARCHAR(100),
    indicator_value VARCHAR(255),
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
);

CREATE TABLE summaries (
    summary_id INT AUTO_INCREMENT PRIMARY KEY,
    report_id INT NOT NULL,
    summary_text TEXT,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (report_id) REFERENCES reports(report_id)
);

CREATE TABLE attack_events (
    attack_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50) NOT NULL,
    country VARCHAR(100),
    region VARCHAR(100),
    city VARCHAR(100),
    endpoint VARCHAR(255),
    method VARCHAR(10),
    payload_snippet TEXT,
    attack_type VARCHAR(100),
    technique VARCHAR(255),
    severity VARCHAR(20),
    confidence_score DECIMAL(5,2),
    denied TINYINT(1) DEFAULT 0,
    event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE blocked_ips (
    block_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(50) NOT NULL UNIQUE,
    reason VARCHAR(255),
    blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL
);

INSERT INTO users (username, password, role, access_level)
VALUES ('analyst1', 'password123', 'analyst', 1);