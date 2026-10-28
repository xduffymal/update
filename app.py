from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
import sqlite3
from database import get_db_connection, initialize_database

Error = sqlite3.Error
from dotenv import load_dotenv
import os
import re
import json
import csv
import io
import xml.etree.ElementTree as ET
import requests
import nltk
import joblib
import atexit
import time
from datetime import datetime, timedelta
from nltk.tokenize import word_tokenize
from sklearn.metrics.pairwise import cosine_similarity
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash

# Transformer/BERT layer is optional for the demo.
# Default is OFF so the app starts fast and never hangs while loading transformers.
# To enable it later, set ENABLE_TRANSFORMER=1 in your .env file.
def analyze_with_transformer(text):
    if os.getenv("ENABLE_TRANSFORMER", "0") != "1":
        return {
            "status": "not_available",
            "model_name": "Transformer disabled for stable demo mode",
            "transformer_label": "Unavailable",
            "transformer_score": 0,
            "interpreted_intent": "Transformer analysis is disabled so the Flask app starts quickly and reliably.",
            "analyzed_at": "N/A"
        }

    try:
        from bert_transformer_layer import analyze_with_transformer as real_analyze
        return real_analyze(text)
    except BaseException as import_error:
        print(f"Transformer layer import warning: {import_error}")
        return {
            "status": "not_available",
            "model_name": "Transformer unavailable",
            "transformer_label": "Unavailable",
            "transformer_score": 0,
            "interpreted_intent": "Transformer analysis is not available right now.",
            "analyzed_at": "N/A"
        }


def get_transformer_status():
    if os.getenv("ENABLE_TRANSFORMER", "0") != "1":
        return {
            "status": "not_available",
            "model_name": "Transformer disabled for stable demo mode",
            "message": "Set ENABLE_TRANSFORMER=1 to enable the BERT/Transformer layer."
        }

    try:
        from bert_transformer_layer import get_transformer_status as real_status
        return real_status()
    except BaseException as import_error:
        print(f"Transformer status warning: {import_error}")
        return {
            "status": "not_available",
            "model_name": "Transformer unavailable",
            "message": "Transformer layer is not available right now."
        }

load_dotenv()
from nltk.tokenize import wordpunct_tokenize
word_tokenize = wordpunct_tokenize

app = Flask(__name__)
from pathlib import Path
import secrets
_secret_path = Path(__file__).with_name('.session-key')
if not _secret_path.exists():
    _secret_path.write_text(secrets.token_hex(32), encoding='utf-8')
app.secret_key = os.getenv("SECRET_KEY") or _secret_path.read_text(encoding='utf-8')
app.config.update(MAX_CONTENT_LENGTH=16 * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', TEMPLATES_AUTO_RELOAD=True)

MAX_FAILED_LOGINS = 5
BLOCK_MINUTES = 60
SYSTEM_USER_ID = int(os.getenv("SYSTEM_USER_ID", "1"))
FEED_INTERVAL_MINUTES = int(os.getenv("FEED_INTERVAL_MINUTES", "5"))

model = joblib.load("threat_model.pkl") if os.path.exists("threat_model.pkl") else None
vectorizer = joblib.load("tfidf_vectorizer.pkl") if os.path.exists("tfidf_vectorizer.pkl") else None

scheduler = BackgroundScheduler()


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"


def is_private_ip(ip):
    return (
        ip.startswith("127.") or
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip == "::1"
    )


def geolocate_ip(ip):
    if not ip or is_private_ip(ip):
        return {"country": "Local/Private", "region": "N/A", "city": "N/A"}

    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        data = response.json()
        return {
            "country": data.get("country_name", "Unknown"),
            "region": data.get("region", "Unknown"),
            "city": data.get("city", "Unknown")
        }
    except Exception:
        return {"country": "Unknown", "region": "Unknown", "city": "Unknown"}


def safe_fetchall_dict(cursor):
    columns = [col[0] for col in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def normalize_source_name(source):
    if not source:
        return "Unknown"

    s = str(source).strip().lower()

    if "nvd" in s:
        return "NVD"
    if "mitre" in s or "attack" in s:
        return "MITRE ATT&CK"
    if "openphish" in s:
        return "OpenPhish"
    if "manual" in s or "upload" in s:
        return "Manual Upload"

    return str(source).strip()


def log_feed_run(source_name, records_fetched, records_added, run_status="success", notes=""):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO feed_runs (source_name, records_fetched, records_added, run_status, notes)
            VALUES (%s, %s, %s, %s, %s)
        """, (source_name, records_fetched, records_added, run_status, notes))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"Feed log error: {e}")


def clean_text(text):
    if not text:
        return ""

    text = text.lower()
    text = re.sub(r"[^a-zA-Z0-9\s.:/_-]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    tokens = word_tokenize(text)
    return " ".join(tokens)


def ml_predict_text(text):
    cleaned = clean_text(text)
    vector = vectorizer.transform([cleaned])
    prediction = model.predict(vector)[0]
    probabilities = model.predict_proba(vector)[0]
    confidence = float(max(probabilities))
    return cleaned, str(prediction), confidence


def get_confidence_interpretation(confidence_score):
    try:
        confidence = float(confidence_score)
    except (TypeError, ValueError):
        return {
            "level": "Unknown",
            "message": "Confidence could not be interpreted from the available score.",
            "analyst_guidance": "Review this result manually before making a final determination."
        }

    if confidence >= 0.85:
        return {
            "level": "High Confidence",
            "message": "The model found strong threat-related patterns in the processed text.",
            "analyst_guidance": "Prioritize validation of indicators and related reports, but this result is likely reliable."
        }
    elif confidence >= 0.65:
        return {
            "level": "Moderate Confidence",
            "message": "The model found meaningful threat indicators, but the result should still be verified.",
            "analyst_guidance": "Review extracted IOCs, ATT&CK mapping, and report context before confirming the classification."
        }
    else:
        return {
            "level": "Lower Confidence",
            "message": "The model found some suspicious patterns, but the classification is less certain.",
            "analyst_guidance": "Manual analyst review is strongly recommended before acting on this result."
        }


def build_preprocessing_details(report_content):
    raw_text = report_content or ""
    cleaned_text = clean_text(raw_text)
    tokens = word_tokenize(cleaned_text) if cleaned_text else []

    preview_limit = 500
    cleaned_preview = cleaned_text[:preview_limit]
    if len(cleaned_text) > preview_limit:
        cleaned_preview += " ..."

    raw_preview = raw_text[:500]
    if len(raw_text) > 500:
        raw_preview += " ..."

    return {
        "raw_length": len(raw_text),
        "cleaned_length": len(cleaned_text),
        "token_count": len(tokens),
        "raw_preview": raw_preview,
        "cleaned_preview": cleaned_preview
    }


def group_indicators_by_type(indicators):
    grouped = {
        "IP Address": [],
        "Domain": [],
        "CVE": [],
        "Email": []
    }

    for item in indicators or []:
        indicator_type = item.get("indicator_type", "Other")
        indicator_value = item.get("indicator_value", "")
        if indicator_type in grouped:
            grouped[indicator_type].append(indicator_value)
        else:
            grouped.setdefault(indicator_type, []).append(indicator_value)

    indicator_counts = {key: len(value) for key, value in grouped.items()}

    return {
        "grouped": grouped,
        "counts": indicator_counts
    }


def should_trigger_alert(predicted_label, confidence):
    if predicted_label == "phishing":
        return True, "high"
    if predicted_label == "attack_technique" and confidence >= 0.70:
        return True, "medium"
    if predicted_label == "vulnerability" and confidence >= 0.80:
        return True, "low"
    return False, "none"


def save_prediction(input_text, cleaned_text, predicted_label, confidence_score, source_ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO threat_predictions
            (input_text, cleaned_text, predicted_label, confidence_score, source_ip)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            str(input_text),
            str(cleaned_text),
            str(predicted_label),
            float(confidence_score),
            str(source_ip)
        ))

        conn.commit()
        prediction_id = cursor.lastrowid
        cursor.close()
        conn.close()
        return prediction_id
    except Error as e:
        print(f"Prediction save error: {e}")
        return None


def save_alert(prediction_id, alert_message, alert_level):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO threat_alerts
            (prediction_id, alert_message, alert_level)
            VALUES (%s, %s, %s)
        """, (prediction_id, str(alert_message), str(alert_level)))

        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"Alert save error: {e}")


def extract_iocs(text: str) -> dict:
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
    cve_pattern = r"\bCVE-\d{4}-\d{4,7}\b"
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    ips = re.findall(ip_pattern, text)
    domains = re.findall(domain_pattern, text)
    cves = re.findall(cve_pattern, text, flags=re.IGNORECASE)
    emails = re.findall(email_pattern, text)
    cves = [cve.upper() for cve in cves]

    return {
        "ips": list(set(ips)),
        "domains": list(set(domains)),
        "cves": list(set(cves)),
        "emails": list(set(emails))
    }


def map_ml_label_to_display(predicted_label: str):
    mapping = {
        "phishing": ("Phishing", "High"),
        "attack_technique": ("Attack Technique", "Medium"),
        "vulnerability": ("Vulnerability Exploit", "Medium")
    }
    return mapping.get(predicted_label, ("Other", "Low"))


def summarize_report(text: str):
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(sentences[:3]) if sentences else text[:300]


def generate_recommendation(threat_type, severity):
    recommendations = {
        "Phishing": "Reset impacted credentials, review email headers, block sender domains, and notify users.",
        "Attack Technique": "Investigate execution paths, review logs, isolate suspicious systems, and validate adversary behavior.",
        "Vulnerability Exploit": "Patch exposed systems, validate affected software versions, and check exploitation evidence.",
        "Other": "Review report manually and investigate suspicious indicators."
    }
    return recommendations.get(threat_type, "Review report manually and investigate suspicious indicators.")


def detect_attack_attempt(req):
    combined = " ".join([
        req.path or "",
        json.dumps(req.args.to_dict(flat=False)),
        json.dumps(req.form.to_dict(flat=False)),
        req.headers.get("User-Agent", "")
    ]).lower()

    patterns = [
        {
            "attack_type": "SQL Injection",
            "technique": "Suspicious SQL syntax in request",
            "severity": "High",
            "confidence": 0.94,
            "regex": r"(\bunion\b\s+\bselect\b|\bdrop\s+table\b|\binsert\s+into\b|\bdelete\s+from\b|\bor\s+1=1\b|--)"
        },
        {
            "attack_type": "Cross-Site Scripting",
            "technique": "Script or HTML injection attempt",
            "severity": "High",
            "confidence": 0.92,
            "regex": r"(<script|javascript:|onerror=|onload=|alert\()"
        },
        {
            "attack_type": "Path Traversal",
            "technique": "Directory traversal payload",
            "severity": "High",
            "confidence": 0.90,
            "regex": r"(\.\./|\.\.\\|/etc/passwd|boot.ini)"
        },
        {
            "attack_type": "Command Injection",
            "technique": "Shell command pattern in request",
            "severity": "High",
            "confidence": 0.91,
            "regex": r"(\||&&|;|\bwget\b|\bcurl\b|\bcat\b|\bwhoami\b|\bchmod\b)"
        },
        {
            "attack_type": "Credential Attack",
            "technique": "Likely credential stuffing or brute-force input",
            "severity": "Medium",
            "confidence": 0.80,
            "regex": r"(admin|root|letmein|qwerty)"
        }
    ]

    for rule in patterns:
        if re.search(rule["regex"], combined, re.IGNORECASE):
            return {
                "attack_type": rule["attack_type"],
                "technique": rule["technique"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "payload_snippet": combined[:500]
            }

    return None


def log_attack_event(ip, endpoint, method, payload_snippet, attack_type, technique, severity, confidence, denied):
    geo = geolocate_ip(ip)

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_events
            (ip_address, country, region, city, endpoint, method, payload_snippet, attack_type, technique, severity, confidence_score, denied)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            ip, geo["country"], geo["region"], geo["city"],
            endpoint, method, payload_snippet, attack_type,
            technique, severity, confidence, 1 if denied else 0
        ))
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"Attack logging error: {e}")


def is_ip_blocked(ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM blocked_ips
            WHERE ip_address = %s
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        """, (ip,))
        blocked = cursor.fetchone()
        cursor.close()
        conn.close()
        return blocked is not None
    except Error:
        return False


def block_ip(ip, reason):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        expires_at = datetime.now() + timedelta(minutes=BLOCK_MINUTES)

        cursor.execute("""
            INSERT INTO blocked_ips (ip_address, reason, expires_at)
            VALUES (%s, %s, %s)
            ON CONFLICT(ip_address) DO UPDATE SET
                reason = excluded.reason,
                expires_at = excluded.expires_at
        """, (ip, reason, expires_at))

        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"IP block error: {e}")


def get_recent_failed_login_count(ip):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*)
            FROM attack_events
            WHERE ip_address = %s
            AND attack_type = 'Failed Login'
            AND event_time >= datetime('now', '-15 minutes')
        """, (ip,))
        count = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        return count
    except Error:
        return 0


def calculate_report_similarity(text1, text2):
    try:
        cleaned1 = clean_text(text1)
        cleaned2 = clean_text(text2)
        vectors = vectorizer.transform([cleaned1, cleaned2])
        similarity = cosine_similarity(vectors[0:1], vectors[1:2])[0][0]
        return float(similarity)
    except Exception as e:
        print(f"Similarity error: {e}")
        return 0.0


def find_matching_reports(new_report_id, content, iocs):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT report_id, title, content
            FROM reports
            WHERE report_id != %s
        """, (new_report_id,))
        existing_reports = cursor.fetchall()

        correlations = []
        new_ioc_set = set(iocs["ips"] + iocs["domains"] + iocs["cves"] + iocs["emails"])

        for report in existing_reports:
            old_report_id = report["report_id"]
            old_content = report["content"] or ""

            cursor.execute("""
                SELECT indicator_value
                FROM indicators
                WHERE report_id = %s
            """, (old_report_id,))
            old_indicators = cursor.fetchall()
            old_ioc_set = set([row["indicator_value"] for row in old_indicators])

            shared_iocs = sorted(list(new_ioc_set.intersection(old_ioc_set)))
            similarity_score = calculate_report_similarity(content, old_content)

            relationship_type = None

            if similarity_score >= 0.90:
                relationship_type = "Duplicate"
            elif similarity_score >= 0.60 and len(shared_iocs) > 0:
                relationship_type = "Related Campaign"
            elif len(shared_iocs) >= 2:
                relationship_type = "Shared IOCs"
            elif similarity_score >= 0.45:
                relationship_type = "Similar Content"

            if relationship_type:
                correlations.append({
                    "related_report_id": old_report_id,
                    "shared_iocs": shared_iocs,
                    "similarity_score": round(similarity_score, 4),
                    "relationship_type": relationship_type
                })

        cursor.close()
        conn.close()
        return correlations

    except Error as e:
        print(f"Correlation search error: {e}")
        return []


def save_report_correlations(report_id, correlations):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        for correlation in correlations:
            cursor.execute("""
                INSERT INTO report_correlations
                (report_id, related_report_id, shared_iocs, similarity_score, relationship_type)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                report_id,
                correlation["related_report_id"],
                ", ".join(correlation["shared_iocs"]),
                correlation["similarity_score"],
                correlation["relationship_type"]
            ))

        conn.commit()
        cursor.close()
        conn.close()

    except Error as e:
        print(f"Save correlation error: {e}")


def get_report_correlations(report_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT rc.correlation_id,
                   rc.related_report_id,
                   r.title,
                   r.source,
                   rc.shared_iocs,
                   rc.similarity_score,
                   rc.relationship_type,
                   strftime('%Y-%m-%d %H:%M:%S', rc.created_at) AS created_at
            FROM report_correlations rc
            JOIN reports r ON rc.related_report_id = r.report_id
            WHERE rc.report_id = %s
            ORDER BY rc.similarity_score DESC, rc.created_at DESC
        """, (report_id,))
        rows = cursor.fetchall()

        cursor.close()
        conn.close()
        return rows

    except Error as e:
        print(f"Get correlation error: {e}")
        return []


def report_exists(title, source):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT report_id
            FROM reports
            WHERE title = %s AND source = %s
            LIMIT 1
        """, (title, source))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row["report_id"] if row else None
    except Error as e:
        print(f"Report exists check error: {e}")
        return None


def save_cve_feed_record(cve_id, description, published_date):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT cve_id FROM cve_data WHERE cve_id = %s LIMIT 1", (cve_id,))
        existing = cursor.fetchone()

        if not existing:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO cve_data (cve_id, description, published_date)
                VALUES (%s, %s, %s)
            """, (cve_id, description, published_date))
            conn.commit()

        cursor.close()
        conn.close()
    except Error as e:
        print(f"CVE data save error: {e}")



def ensure_relation_extraction_table():
    """Creates the relation extraction table if it does not already exist."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
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
                FOREIGN KEY (report_id) REFERENCES reports(report_id)
                    ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_extracted_relations_report_id
            ON extracted_relations(report_id)
        """)
        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"Relation table setup error: {e}")


def build_relation_extractions(report_id, report, classification, indicators, attack_mapping):
    """
    Rule-assisted relation extraction for capstone demo/research alignment.
    It links reports, IOCs, CVEs, threat types, and ATT&CK techniques.
    """
    relations = []
    report_title = report.get("title", f"Report {report_id}") if report else f"Report {report_id}"
    source = report.get("source", "Unknown") if report else "Unknown"
    content = (report.get("content", "") if report else "").lower()
    threat_type = classification.get("threat_type", "Unknown") if classification else "Unknown"
    severity = classification.get("severity", "Unknown") if classification else "Unknown"

    def add_relation(subject_type, subject_value, relation_type, object_type, object_value, confidence, explanation):
        if subject_value and object_value:
            relations.append({
                "subject_type": subject_type,
                "subject_value": str(subject_value)[:255],
                "relation_type": relation_type,
                "object_type": object_type,
                "object_value": str(object_value)[:255],
                "confidence_score": float(confidence),
                "explanation": explanation
            })

    add_relation(
        "Report", report_title, "classified_as", "Threat Type", threat_type, 0.90,
        "The ML classifier assigned this report to a cybersecurity threat category."
    )

    add_relation(
        "Report", report_title, "has_severity", "Severity", severity, 0.85,
        "The severity level is tied to the report classification and analyst prioritization."
    )

    add_relation(
        "Report", report_title, "ingested_from", "Source", source, 0.95,
        "This links the report to the intelligence source that produced or supplied it."
    )

    if attack_mapping:
        add_relation(
            "Threat Type", threat_type, "maps_to_attack_technique", "MITRE ATT&CK",
            f"{attack_mapping.get('technique_id')} - {attack_mapping.get('technique_name')}",
            0.82,
            "The system mapped report behavior to a MITRE ATT&CK tactic/technique using rule-based context."
        )

    for item in indicators or []:
        indicator_type = item.get("indicator_type", "Indicator")
        indicator_value = item.get("indicator_value", "")

        add_relation(
            "Report", report_title, "contains_indicator", indicator_type, indicator_value, 0.92,
            "The indicator was extracted from the report text using IOC extraction patterns."
        )

        add_relation(
            indicator_type, indicator_value, "associated_with", "Threat Type", threat_type, 0.78,
            "The extracted indicator is associated with the report's predicted threat classification."
        )

        if indicator_type == "CVE":
            add_relation(
                "CVE", indicator_value, "may_be_exploited_using", "MITRE ATT&CK", "T1190 - Exploit Public-Facing Application", 0.80,
                "CVE mentions often indicate vulnerability exploitation behavior aligned with public-facing application exploitation."
            )

        if indicator_type in ["IP Address", "Domain"]:
            if "phishing" in threat_type.lower() or "phishing" in content:
                add_relation(
                    indicator_type, indicator_value, "may_host_or_deliver", "Threat Activity", "Phishing Infrastructure", 0.76,
                    "A network indicator appeared in phishing-related context."
                )
            elif "malware" in content or "payload" in content:
                add_relation(
                    indicator_type, indicator_value, "may_host_or_deliver", "Threat Activity", "Malware Payload", 0.76,
                    "A network indicator appeared in malware or payload delivery context."
                )

    if "credential" in content or "password" in content or "login" in content:
        add_relation(
            "Threat Behavior", "Credential Targeting", "maps_to_attack_technique", "MITRE ATT&CK", "T1078 - Valid Accounts", 0.74,
            "Credential-related language suggests potential account abuse or credential theft."
        )

    if "script" in content or "command" in content or "powershell" in content or "cmd" in content:
        add_relation(
            "Threat Behavior", "Command Execution", "maps_to_attack_technique", "MITRE ATT&CK", "T1059 - Command and Scripting Interpreter", 0.74,
            "Command or scripting language indicates possible execution behavior."
        )

    return relations


def save_extracted_relations(report_id, relations):
    if not relations:
        return

    try:
        ensure_relation_extraction_table()
        conn = get_db_connection()
        cursor = conn.cursor()

        for rel in relations:
            cursor.execute("""
                INSERT INTO extracted_relations
                (report_id, subject_type, subject_value, relation_type, object_type, object_value, confidence_score, explanation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                report_id,
                rel["subject_type"],
                rel["subject_value"],
                rel["relation_type"],
                rel["object_type"],
                rel["object_value"],
                rel["confidence_score"],
                rel["explanation"]
            ))

        conn.commit()
        cursor.close()
        conn.close()
    except Error as e:
        print(f"Save extracted relations error: {e}")


def get_extracted_relations(report_id):
    try:
        ensure_relation_extraction_table()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT relation_id, subject_type, subject_value, relation_type,
                   object_type, object_value, confidence_score, explanation,
                   strftime('%Y-%m-%d %H:%M:%S', created_at) AS created_at
            FROM extracted_relations
            WHERE report_id = %s
            ORDER BY confidence_score DESC, created_at DESC
        """, (report_id,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Error as e:
        print(f"Get extracted relations error: {e}")
        return []


def get_total_extracted_relations():
    try:
        ensure_relation_extraction_table()
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT COUNT(*) AS count FROM extracted_relations")
        count = cursor.fetchone()["count"]
        cursor.close()
        conn.close()
        return count
    except Error:
        return 0

def process_report(title, source, content, uploaded_by=SYSTEM_USER_ID, source_ip="system"):
    existing_report_id = report_exists(title, source)
    if existing_report_id:
        return existing_report_id, False

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO reports (title, source, content, uploaded_by)
            VALUES (%s, %s, %s, %s)
        """, (title, source, content, uploaded_by))
        report_id = cursor.lastrowid

        cleaned_text, predicted_label, confidence = ml_predict_text(content)
        threat_type, severity = map_ml_label_to_display(predicted_label)

        cursor.execute("""
            INSERT INTO threat_classifications (report_id, threat_type, severity, confidence_score)
            VALUES (%s, %s, %s, %s)
        """, (report_id, threat_type, severity, float(confidence)))

        iocs = extract_iocs(content)

        for ip_value in iocs["ips"]:
            cursor.execute("""
                INSERT INTO indicators (report_id, indicator_type, indicator_value)
                VALUES (%s, %s, %s)
            """, (report_id, "IP Address", ip_value))

        for domain in iocs["domains"]:
            cursor.execute("""
                INSERT INTO indicators (report_id, indicator_type, indicator_value)
                VALUES (%s, %s, %s)
            """, (report_id, "Domain", domain))

        for cve in iocs["cves"]:
            cursor.execute("""
                INSERT INTO indicators (report_id, indicator_type, indicator_value)
                VALUES (%s, %s, %s)
            """, (report_id, "CVE", cve))

        for email in iocs["emails"]:
            cursor.execute("""
                INSERT INTO indicators (report_id, indicator_type, indicator_value)
                VALUES (%s, %s, %s)
            """, (report_id, "Email", email))

        summary = summarize_report(content)
        recommendation = generate_recommendation(threat_type, severity)

        cursor.execute("""
            INSERT INTO summaries (report_id, summary_text)
            VALUES (%s, %s)
        """, (report_id, f"{summary}\n\nRecommended Response: {recommendation}"))

        conn.commit()
        cursor.close()
        conn.close()

        report_context = {"report_id": report_id, "title": title, "source": source, "content": content}
        classification_context = {"threat_type": threat_type, "severity": severity, "confidence_score": float(confidence)}
        indicator_context = []
        for ip_value in iocs["ips"]:
            indicator_context.append({"indicator_type": "IP Address", "indicator_value": ip_value})
        for domain in iocs["domains"]:
            indicator_context.append({"indicator_type": "Domain", "indicator_value": domain})
        for cve in iocs["cves"]:
            indicator_context.append({"indicator_type": "CVE", "indicator_value": cve})
        for email in iocs["emails"]:
            indicator_context.append({"indicator_type": "Email", "indicator_value": email})

        attack_mapping_context = map_report_to_attack_ttp(report_context, classification_context, indicator_context)
        relation_items = build_relation_extractions(
            report_id,
            report_context,
            classification_context,
            indicator_context,
            attack_mapping_context
        )
        save_extracted_relations(report_id, relation_items)

        correlations = find_matching_reports(report_id, content, iocs)
        if correlations:
            save_report_correlations(report_id, correlations)

        prediction_id = save_prediction(content, cleaned_text, predicted_label, confidence, source_ip)

        trigger, alert_level = should_trigger_alert(predicted_label, confidence)
        if trigger and prediction_id:
            alert_message = f"Threat detected: {predicted_label} from IP {source_ip} with confidence {confidence:.2f}"
            save_alert(prediction_id, alert_message, alert_level)

        return report_id, True

    except Error as e:
        print(f"Process report error: {e}")
        return None, False


def fetch_nvd_reports():
    api_key = os.getenv("NVD_API_KEY", "").strip()
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    now = datetime.utcnow()
    start = now - timedelta(hours=12)

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "resultsPerPage": 25,
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000")
    }

    response = requests.get(url, params=params, headers=headers, timeout=20)
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])


def fetch_mitre_reports():
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    data = response.json()
    objects = data.get("objects", [])

    techniques = []
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            ext_refs = obj.get("external_references", [])
            technique_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id", "")
                    break

            title = f"{technique_id} {obj.get('name', 'MITRE Technique')}".strip()
            description = obj.get("description", "")
            if title and description:
                techniques.append({
                    "title": title,
                    "description": description
                })

    return techniques[:20]


def fetch_openphish_reports():
    url = "https://openphish.com/feed.txt"
    response = requests.get(url, timeout=20)
    response.raise_for_status()
    lines = response.text.splitlines()

    reports = []
    for idx, line in enumerate(lines[:25], start=1):
        url_value = line.strip()
        if url_value:
            reports.append({
                "title": f"OpenPhish URL {idx}",
                "description": f"Reported phishing URL detected in OpenPhish feed: {url_value}"
            })

    return reports


def ingest_nvd_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        vulnerabilities = fetch_nvd_reports()

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown CVE")

            descriptions = cve.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            if not description and descriptions:
                description = descriptions[0].get("value", "")

            published = cve.get("published", "")
            title = f"{cve_id} from NVD"
            source = "NVD"
            content = f"{cve_id}. {description}. Published: {published}"

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="nvd_feed"
            )

            if created:
                created_count += 1
                save_cve_feed_record(cve_id, description, published)
                latest_items.append({
                    "title": title,
                    "source": source,
                    "published": published
                })
            else:
                skipped_count += 1

        log_feed_run("NVD", len(vulnerabilities), created_count, "success", "NVD feed ingestion completed")

        return {
            "created": created_count,
            "skipped": skipped_count,
            "latest_items": latest_items
        }

    except Exception as e:
        print(f"NVD ingestion error: {e}")
        log_feed_run("NVD", 0, 0, "failed", str(e))
        return {
            "created": 0,
            "skipped": 0,
            "latest_items": [],
            "error": str(e)
        }


def ingest_mitre_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        techniques = fetch_mitre_reports()

        for item in techniques:
            title = item["title"]
            source = "MITRE ATT&CK"
            content = item["description"]

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="mitre_feed"
            )

            if created:
                created_count += 1
                latest_items.append({
                    "title": title,
                    "source": source,
                    "published": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            else:
                skipped_count += 1

        log_feed_run("MITRE ATT&CK", len(techniques), created_count, "success", "MITRE ATT&CK feed ingestion completed")

        return {
            "created": created_count,
            "skipped": skipped_count,
            "latest_items": latest_items
        }

    except Exception as e:
        print(f"MITRE ingestion error: {e}")
        log_feed_run("MITRE ATT&CK", 0, 0, "failed", str(e))
        return {
            "created": 0,
            "skipped": 0,
            "latest_items": [],
            "error": str(e)
        }


def ingest_openphish_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        reports = fetch_openphish_reports()

        for item in reports:
            title = item["title"]
            source = "OpenPhish"
            content = item["description"]

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="openphish_feed"
            )

            if created:
                created_count += 1
                latest_items.append({
                    "title": title,
                    "source": source,
                    "published": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
            else:
                skipped_count += 1

        log_feed_run("OpenPhish", len(reports), created_count, "success", "OpenPhish feed ingestion completed")

        return {
            "created": created_count,
            "skipped": skipped_count,
            "latest_items": latest_items
        }

    except Exception as e:
        print(f"OpenPhish ingestion error: {e}")
        log_feed_run("OpenPhish", 0, 0, "failed", str(e))
        return {
            "created": 0,
            "skipped": 0,
            "latest_items": [],
            "error": str(e)
        }



def fetch_cisa_kev_reports():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    data = response.json()
    return data.get("vulnerabilities", [])[:25]


def ingest_cisa_kev_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        vulnerabilities = fetch_cisa_kev_reports()

        for item in vulnerabilities:
            cve_id = item.get("cveID", "Unknown CVE")
            vendor = item.get("vendorProject", "Unknown Vendor")
            product = item.get("product", "Unknown Product")
            vulnerability_name = item.get("vulnerabilityName", "Known Exploited Vulnerability")
            date_added = item.get("dateAdded", "")
            due_date = item.get("dueDate", "")
            action = item.get("requiredAction", "")
            notes = item.get("notes", "")

            title = f"{cve_id} CISA KEV - {vendor} {product}"
            source = "CISA KEV"
            content = (
                f"{cve_id}. {vulnerability_name}. Vendor: {vendor}. Product: {product}. "
                f"This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog. "
                f"Date added: {date_added}. Due date: {due_date}. Required action: {action}. Notes: {notes}"
            )

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="cisa_kev_feed"
            )

            if created:
                created_count += 1
                latest_items.append({"title": title, "source": source, "published": date_added})
            else:
                skipped_count += 1

        log_feed_run("CISA KEV", len(vulnerabilities), created_count, "success", "CISA KEV feed ingestion completed")
        return {"created": created_count, "skipped": skipped_count, "latest_items": latest_items}

    except Exception as e:
        print(f"CISA KEV ingestion error: {e}")
        log_feed_run("CISA KEV", 0, 0, "failed", str(e))
        return {"created": 0, "skipped": 0, "latest_items": [], "error": str(e)}


def fetch_urlhaus_recent_reports():
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    lines = [line for line in response.text.splitlines() if line and not line.startswith("#")]
    if not lines:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    return list(reader)[:25]


def ingest_urlhaus_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        rows = fetch_urlhaus_recent_reports()

        for idx, item in enumerate(rows, start=1):
            url_value = item.get("url", "")
            threat = item.get("threat", "malware_url")
            date_added = item.get("dateadded", "")
            status = item.get("url_status", "")
            tags = item.get("tags", "")
            link = item.get("urlhaus_link", "")

            if not url_value:
                continue

            title = f"URLhaus {threat} {idx}: {url_value[:80]}"
            source = "URLhaus"
            content = (
                f"URLhaus reported a malicious URL used for malware distribution. URL: {url_value}. "
                f"Threat: {threat}. Status: {status}. Tags: {tags}. Date added: {date_added}. Reference: {link}"
            )

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="urlhaus_feed"
            )

            if created:
                created_count += 1
                latest_items.append({"title": title, "source": source, "published": date_added})
            else:
                skipped_count += 1

        log_feed_run("URLhaus", len(rows), created_count, "success", "URLhaus recent malware URL feed ingestion completed")
        return {"created": created_count, "skipped": skipped_count, "latest_items": latest_items}

    except Exception as e:
        print(f"URLhaus ingestion error: {e}")
        log_feed_run("URLhaus", 0, 0, "failed", str(e))
        return {"created": 0, "skipped": 0, "latest_items": [], "error": str(e)}


def fetch_feodo_reports():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    lines = [line for line in response.text.splitlines() if line and not line.startswith("#")]
    if not lines:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    return list(reader)[:25]


def ingest_feodo_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        rows = fetch_feodo_reports()

        for idx, item in enumerate(rows, start=1):
            dst_ip = item.get("dst_ip", "") or item.get("ip_address", "")
            dst_port = item.get("dst_port", "")
            malware = item.get("malware", "botnet")
            first_seen = item.get("first_seen_utc", "")
            status = item.get("c2_status", "")

            if not dst_ip:
                continue

            title = f"Feodo Tracker C2 {dst_ip}:{dst_port}"
            source = "Feodo Tracker"
            content = (
                f"Feodo Tracker reported a botnet command and control indicator. IP Address: {dst_ip}. "
                f"Port: {dst_port}. Malware family: {malware}. C2 status: {status}. First seen: {first_seen}. "
                f"This indicator may be related to botnet infrastructure, malware callbacks, or command and control activity."
            )

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="feodo_feed"
            )

            if created:
                created_count += 1
                latest_items.append({"title": title, "source": source, "published": first_seen})
            else:
                skipped_count += 1

        log_feed_run("Feodo Tracker", len(rows), created_count, "success", "Feodo Tracker C2 feed ingestion completed")
        return {"created": created_count, "skipped": skipped_count, "latest_items": latest_items}

    except Exception as e:
        print(f"Feodo ingestion error: {e}")
        log_feed_run("Feodo Tracker", 0, 0, "failed", str(e))
        return {"created": 0, "skipped": 0, "latest_items": [], "error": str(e)}


def fetch_cisa_advisory_reports():
    url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    response = requests.get(url, timeout=25)
    response.raise_for_status()
    root = ET.fromstring(response.content)
    items = []
    for item in root.findall(".//item")[:15]:
        title = item.findtext("title", default="CISA Cybersecurity Advisory")
        description = item.findtext("description", default="")
        link = item.findtext("link", default="")
        pub_date = item.findtext("pubDate", default="")
        items.append({"title": title, "description": description, "link": link, "pub_date": pub_date})
    return items


def ingest_cisa_advisories_feed():
    created_count = 0
    skipped_count = 0
    latest_items = []

    try:
        items = fetch_cisa_advisory_reports()

        for item in items:
            title = item.get("title", "CISA Cybersecurity Advisory")
            source = "CISA Advisories"
            content = f"{item.get('description', '')} Reference: {item.get('link', '')}. Published: {item.get('pub_date', '')}"

            report_id, created = process_report(
                title=title,
                source=source,
                content=content,
                uploaded_by=SYSTEM_USER_ID,
                source_ip="cisa_advisories_feed"
            )

            if created:
                created_count += 1
                latest_items.append({"title": title, "source": source, "published": item.get("pub_date", "")})
            else:
                skipped_count += 1

        log_feed_run("CISA Advisories", len(items), created_count, "success", "CISA advisories feed ingestion completed")
        return {"created": created_count, "skipped": skipped_count, "latest_items": latest_items}

    except Exception as e:
        print(f"CISA advisories ingestion error: {e}")
        log_feed_run("CISA Advisories", 0, 0, "failed", str(e))
        return {"created": 0, "skipped": 0, "latest_items": [], "error": str(e)}

def run_all_feeds():
    started_at = datetime.now()
    perf_start = time.perf_counter()

    nvd_result = ingest_nvd_feed()
    mitre_result = ingest_mitre_feed()
    openphish_result = ingest_openphish_feed()
    cisa_kev_result = ingest_cisa_kev_feed()
    urlhaus_result = ingest_urlhaus_feed()
    feodo_result = ingest_feodo_feed()
    cisa_advisories_result = ingest_cisa_advisories_feed()

    feed_results = [
        {"source": "NVD", "created": nvd_result.get("created", 0), "skipped": nvd_result.get("skipped", 0), "fetched": nvd_result.get("created", 0) + nvd_result.get("skipped", 0)},
        {"source": "MITRE ATT&CK", "created": mitre_result.get("created", 0), "skipped": mitre_result.get("skipped", 0), "fetched": mitre_result.get("created", 0) + mitre_result.get("skipped", 0)},
        {"source": "OpenPhish", "created": openphish_result.get("created", 0), "skipped": openphish_result.get("skipped", 0), "fetched": openphish_result.get("created", 0) + openphish_result.get("skipped", 0)},
        {"source": "CISA KEV", "created": cisa_kev_result.get("created", 0), "skipped": cisa_kev_result.get("skipped", 0), "fetched": cisa_kev_result.get("created", 0) + cisa_kev_result.get("skipped", 0)},
        {"source": "URLhaus", "created": urlhaus_result.get("created", 0), "skipped": urlhaus_result.get("skipped", 0), "fetched": urlhaus_result.get("created", 0) + urlhaus_result.get("skipped", 0)},
        {"source": "Feodo Tracker", "created": feodo_result.get("created", 0), "skipped": feodo_result.get("skipped", 0), "fetched": feodo_result.get("created", 0) + feodo_result.get("skipped", 0)},
        {"source": "CISA Advisories", "created": cisa_advisories_result.get("created", 0), "skipped": cisa_advisories_result.get("skipped", 0), "fetched": cisa_advisories_result.get("created", 0) + cisa_advisories_result.get("skipped", 0)}
    ]

    results = {
        "nvd": nvd_result,
        "mitre": mitre_result,
        "openphish": openphish_result,
        "cisa_kev": cisa_kev_result,
        "urlhaus": urlhaus_result,
        "feodo": feodo_result,
        "cisa_advisories": cisa_advisories_result
    }

    processing_seconds = time.perf_counter() - perf_start
    total_fetched = sum(item["fetched"] for item in feed_results)
    total_new = sum(item["created"] for item in feed_results)
    throughput = (total_fetched / processing_seconds) if processing_seconds > 0 else 0.0

    return {
        "source_results": feed_results,
        "sources_checked": len(feed_results),
        "processing_seconds": round(processing_seconds, 4),
        "throughput_reports_per_second": round(throughput, 4),
        "started_at": started_at.strftime("%Y-%m-%d %H:%M:%S"),
        "completed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nvd_new": nvd_result.get("created", 0),
        "mitre_new": mitre_result.get("created", 0),
        "openphish_new": openphish_result.get("created", 0),
        "cisa_kev_new": cisa_kev_result.get("created", 0),
        "urlhaus_new": urlhaus_result.get("created", 0),
        "feodo_new": feodo_result.get("created", 0),
        "cisa_advisories_new": cisa_advisories_result.get("created", 0),
        "total_new": total_new,
        "total_fetched": total_fetched,
        "latest_items": (
            nvd_result.get("latest_items", []) +
            mitre_result.get("latest_items", []) +
            openphish_result.get("latest_items", []) +
            cisa_kev_result.get("latest_items", []) +
            urlhaus_result.get("latest_items", []) +
            feodo_result.get("latest_items", []) +
            cisa_advisories_result.get("latest_items", [])
        ),
        "errors": {key: value.get("error") for key, value in results.items()}
    }

def run_feed_ingestion():
    print(f"[{datetime.now()}] Running automatic feed ingestion...")
    run_all_feeds()


def start_scheduler():
    if scheduler.running:
        return

    scheduler.add_job(
        func=run_feed_ingestion,
        trigger="interval",
        minutes=FEED_INTERVAL_MINUTES,
        id="all_feeds_job",
        replace_existing=True
    )
    scheduler.start()
    print(f"Scheduler started. Feed ingestion runs every {FEED_INTERVAL_MINUTES} minute(s).")


atexit.register(lambda: scheduler.shutdown(wait=False) if scheduler.running else None)


def generate_ai_explanation(report, classification, indicators, correlations):
    threat_type = classification.get("threat_type", "Unknown") if classification else "Unknown"
    severity = classification.get("severity", "Unknown") if classification else "Unknown"
    confidence = classification.get("confidence_score", 0) if classification else 0

    indicator_summary = {}
    for item in indicators or []:
        i_type = item.get("indicator_type", "Other")
        indicator_summary[i_type] = indicator_summary.get(i_type, 0) + 1

    top_indicator_type = "No major indicators"
    if indicator_summary:
        top_indicator_type = max(indicator_summary, key=indicator_summary.get)

    correlation_count = len(correlations or [])

    explanation_parts = [
        f"The system classified this report as {threat_type.lower()} with a {severity.lower()} severity level.",
        f"The confidence score is {confidence}, indicating how strongly the model detected threat-related patterns.",
        f"This classification is based on textual patterns, extracted indicators, and similarity to previously analyzed reports."
    ]

    if indicators:
        explanation_parts.append(
            f"The report includes {len(indicators)} extracted indicators, with {top_indicator_type.lower()} being the most significant indicator category."
        )
    else:
        explanation_parts.append(
            "The report did not produce many structured indicators, so the classification relied more on textual threat patterns."
        )

    if correlation_count > 0:
        explanation_parts.append(
            f"The system also found {correlation_count} related or similar reports, which strengthens the likelihood that this activity is part of a broader pattern or campaign."
        )
    else:
        explanation_parts.append(
            "No directly related reports were found, which may mean this is either a new event or a low-overlap threat report."
        )

    explanation_parts.append(
        "The model uses natural language processing and TF-IDF vectorization to identify patterns commonly associated with cyber threats."
    )

    if severity == "High":
        recommended_action = "Immediate analyst review is recommended. Validate the indicators, review linked reports, and consider escalation."
    elif severity == "Medium":
        recommended_action = "Analyst review is recommended. Investigate the extracted indicators and compare them with recent activity."
    else:
        recommended_action = "Monitor this report, validate the indicators, and review whether it should be grouped with related activity."

    return {
        "summary": " ".join(explanation_parts),
        "recommended_action": recommended_action,
        "top_indicator_type": top_indicator_type,
        "correlation_count": correlation_count
    }


def map_report_to_attack_ttp(report, classification, indicators):
    content = (report.get("content", "") if report else "").lower()
    threat_type = (classification.get("threat_type", "") if classification else "").lower()

    joined_indicators = " ".join([
        (item.get("indicator_value", "") or "").lower()
        for item in (indicators or [])
    ])

    if "phishing" in threat_type or "login" in content or "credential" in content or "email" in joined_indicators:
        return {
            "technique_id": "T1566",
            "technique_name": "Phishing",
            "tactic": "Initial Access",
            "description": "This report aligns with phishing-related behavior commonly used to gain initial access through deceptive messages or links."
        }

    if "vulnerability" in threat_type or "cve-" in content:
        return {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "This report appears related to exploitation of a vulnerability, often associated with public-facing applications or exposed services."
        }

    if "attack technique" in threat_type or "script" in content or "command" in content:
        return {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "This report suggests execution-related behavior where commands or scripts may be used to carry out attacker actions."
        }

    if "account" in content or "valid credentials" in content or "password" in content:
        return {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
            "description": "This report may involve the abuse of legitimate credentials or account access."
        }

    return {
        "technique_id": "T1588",
        "technique_name": "Obtain Capabilities",
        "tactic": "Resource Development",
        "description": "The report does not strongly match a single ATT&CK technique, but it may still relate to adversary capability development or preparation."
    }


def get_allowed_threat_types():
    return ["Phishing", "Attack Technique", "Vulnerability Exploit", "Other"]


def get_allowed_severity_levels():
    return ["High", "Medium", "Low"]


def save_analyst_review(
    report_id,
    review_status,
    review_note="",
    reviewer_name="",
    corrected_threat_type="",
    corrected_severity="",
    escalated=False,
    use_for_retraining=False
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO analyst_reviews (
                report_id,
                review_status,
                review_note,
                reviewer_name,
                corrected_threat_type,
                corrected_severity,
                escalated,
                use_for_retraining
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            report_id,
            review_status,
            review_note,
            reviewer_name,
            corrected_threat_type if corrected_threat_type else None,
            corrected_severity if corrected_severity else None,
            1 if escalated else 0,
            1 if use_for_retraining else 0
        ))
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Error as e:
        print(f"Analyst review save error: {e}")
        return False


def get_latest_analyst_review(report_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT
                review_status,
                review_note,
                reviewer_name,
                corrected_threat_type,
                corrected_severity,
                escalated,
                use_for_retraining,
                strftime('%Y-%m-%d %H:%M:%S', created_at) AS created_at
            FROM analyst_reviews
            WHERE report_id = %s
            ORDER BY created_at DESC
            LIMIT 1
        """, (report_id,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row
    except Error as e:
        print(f"Get analyst review error: {e}")
        return None


def get_daily_threat_digest():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM reports
            WHERE upload_date >= %s
        """, (start,))
        new_reports_today = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT source, COUNT(*) AS count
            FROM reports
            WHERE upload_date >= %s
            GROUP BY source
            ORDER BY count DESC
            LIMIT 4
        """, (start,))
        top_sources_raw = cursor.fetchall()

        normalized_source_counts = {}
        for item in top_sources_raw:
            name = normalize_source_name(item["source"])
            normalized_source_counts[name] = normalized_source_counts.get(name, 0) + item["count"]

        top_sources = [{"source": k, "count": v} for k, v in sorted(normalized_source_counts.items(), key=lambda x: x[1], reverse=True)]

        cursor.execute("""
            SELECT tc.threat_type, COUNT(*) AS count
            FROM threat_classifications tc
            JOIN reports r ON tc.report_id = r.report_id
            WHERE r.upload_date >= %s
            GROUP BY tc.threat_type
            ORDER BY count DESC
            LIMIT 4
        """, (start,))
        top_threats = cursor.fetchall()

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM threat_classifications tc
            JOIN reports r ON tc.report_id = r.report_id
            WHERE LOWER(tc.severity) = 'high'
            AND r.upload_date >= %s
        """, (start,))
        high_today = cursor.fetchone()["count"]

        cursor.execute("""
            SELECT COUNT(*) AS count
            FROM reports r
            LEFT JOIN analyst_reviews ar ON r.report_id = ar.report_id
            WHERE ar.review_id IS NULL
        """)
        pending_reviews = cursor.fetchone()["count"]

        cursor.close()
        conn.close()

        summary_lines = [
            f"{new_reports_today} new report(s) were added today."
        ]

        if top_sources:
            summary_lines.append("Most active sources today: " + ", ".join([f"{item['source']} ({item['count']})" for item in top_sources]) + ".")
        else:
            summary_lines.append("No source activity has been recorded yet today.")

        if top_threats:
            summary_lines.append("Top threat categories today: " + ", ".join([f"{item['threat_type']} ({item['count']})" for item in top_threats]) + ".")
        else:
            summary_lines.append("No classified threat activity has been recorded yet today.")

        summary_lines.append(f"{high_today} high severity item(s) were identified today.")
        summary_lines.append(f"{pending_reviews} report(s) are still waiting for analyst review.")

        return {
            "summary_lines": summary_lines,
            "new_reports_today": new_reports_today,
            "top_sources": top_sources,
            "top_threats": top_threats,
            "high_today": high_today,
            "pending_reviews": pending_reviews
        }
    except Exception as e:
        print(f"Daily digest error: {e}")
        return {
            "summary_lines": ["Unable to load daily threat digest right now."],
            "new_reports_today": 0,
            "top_sources": [],
            "top_threats": [],
            "high_today": 0,
            "pending_reviews": 0
        }


def get_ai_summary():
    data = build_dashboard_payload()
    digest = get_daily_threat_digest()

    top_source = data["source_ingestion_counts"][0]["source"] if data["source_ingestion_counts"] else "None"
    top_threat = data["threat_type_data"][0]["threat_type"] if data["threat_type_data"] else "None"

    summary = (
        f"The system currently contains {data['total_reports']} total reports, "
        f"{data['total_alerts']} alerts, and {data['total_correlations']} detected report correlations. "
        f"The most active source is {top_source}, while the most common threat category is {top_threat}. "
        f"Today, {digest['new_reports_today']} new reports were added. "
        f"Analysts should prioritize high severity reports, recent alerts, and items still waiting for review."
    )

    return {
        "summary": summary,
        "top_source": top_source,
        "top_threat": top_threat,
        "new_reports_today": digest["new_reports_today"],
        "pending_reviews": digest["pending_reviews"]
    }


def get_change_summary():
    data = build_dashboard_payload()

    latest_source = data["source_ingestion_counts"][0]["source"] if data["source_ingestion_counts"] else "None"

    return {
        "summary": (
            f"{data['total_reports']} reports are currently tracked across the system. "
            f"There are {data['total_alerts']} active alerts, {data['total_predictions']} prediction records, "
            f"and {data['total_correlations']} correlation links. "
            f"The most active source currently visible on the dashboard is {latest_source}."
        )
    }


def get_recent_feed_runs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, source_name, records_fetched, records_added, run_status, notes,
                   strftime('%Y-%m-%d %H:%M:%S', run_time) AS run_time
            FROM feed_runs
            ORDER BY run_time DESC
            LIMIT 8
        """)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except Exception as e:
        print(f"Recent feed runs error: {e}")
        return []




def get_topic_modeling_summary():
    try:
        with open("topic_model_metadata.json", "r") as file:
            return json.load(file)
    except Exception:
        return {
            "status": "not_available",
            "generated_at": "Not generated yet",
            "total_reports_analyzed": 0,
            "num_topics": 0,
            "topics": [],
            "report_topics": []
        }

def ai_assistant_response(user_question):
    question = (user_question or "").lower().strip()

    try:
        data = build_dashboard_payload()
        digest = get_daily_threat_digest()
        topic_modeling = get_topic_modeling_summary()
        transformer_status = get_transformer_status()

        total_reports = data.get("total_reports", 0)
        total_alerts = data.get("total_alerts", 0)
        total_indicators = data.get("total_indicators", 0)
        total_correlations = data.get("total_correlations", 0)
        total_predictions = data.get("total_predictions", 0)

        top_threat = data["threat_type_data"][0]["threat_type"] if data.get("threat_type_data") else "None"
        top_source = data["source_ingestion_counts"][0]["source"] if data.get("source_ingestion_counts") else "None"

        if "what changed" in question or "changed" in question or "today" in question:
            return (
                f"Today, {digest['new_reports_today']} new report(s) were added. "
                f"There are {digest['high_today']} high severity item(s) today and "
                f"{digest['pending_reviews']} report(s) waiting for analyst review. "
                "The best next step is to review high severity items, recent alerts, and reports marked for analyst review."
            )

        if "topic" in question or "theme" in question or "lda" in question:
            if topic_modeling.get("status") == "completed":
                topics = topic_modeling.get("topics", [])
                topic_text = "; ".join([
                    f"{topic.get('topic_name', 'Threat Theme')}: {', '.join(topic.get('keywords', [])[:5])}"
                    for topic in topics
                ])
                return (
                    f"The topic modeling system analyzed {topic_modeling.get('total_reports_analyzed', 0)} report(s) "
                    f"and found {len(topics)} threat theme(s). {topic_text}"
                )
            return "Topic modeling has not been generated yet. Run python topic_modeling.py first."

        if "bert" in question or "transformer" in question or "semantic" in question:
            return (
                f"The transformer layer status is {transformer_status.get('status')}. "
                f"Model: {transformer_status.get('model_name')}. "
                "It supports semantic cyber threat interpretation by analyzing threat language context and intent beyond TF-IDF classification."
            )

        if "alert" in question or "alerts" in question:
            return (
                f"The system currently has {total_alerts} alert(s). "
                "Alerts are triggered when the model detects high-risk phishing, attack technique, or vulnerability-related activity. "
                "Analysts should prioritize high severity alerts first."
            )

        if "correlation" in question or "related" in question or "ioc" in question or "indicator" in question:
            return (
                f"The system currently has {total_correlations} correlation link(s) and {total_indicators} extracted indicator(s). "
                "Correlations help identify related reports, shared IOCs, duplicate reports, and possible campaign-level activity."
            )

        if "model" in question or "accuracy" in question or "training" in question:
            try:
                with open("model_metadata.json", "r") as file:
                    metadata = json.load(file)
                return (
                    f"The selected model is {metadata.get('best_model', 'Unknown')} with an accuracy of "
                    f"{round(float(metadata.get('best_accuracy', 0)) * 100, 2)}%. "
                    f"It was trained on {metadata.get('training_records', 0)} record(s)."
                )
            except Exception:
                return (
                    "Model metadata is not available yet. Run python model_training.py to train and save model performance details."
                )

        if "explain" in question or "dashboard" in question or "overview" in question:
            return (
                f"This dashboard summarizes {total_reports} reports, {total_indicators} extracted indicators, "
                f"{total_predictions} predictions, {total_alerts} alerts, and {total_correlations} correlations. "
                f"The most active source is {top_source}, and the most common threat type is {top_threat}."
            )

        if "review" in question or "analyst" in question:
            return (
                f"There are {digest['pending_reviews']} report(s) waiting for analyst review. "
                "The analyst review workflow allows users to confirm classifications, correct threat labels, escalate reports, "
                "and mark reviewed reports for future retraining."
            )

        return (
            f"The system is monitoring {total_reports} report(s), {total_indicators} indicator(s), "
            f"{total_predictions} prediction(s), {total_alerts} alert(s), and {total_correlations} correlation link(s). "
            f"The leading source is {top_source}, and the top threat category is {top_threat}. "
            "You can ask about alerts, topics, BERT, correlations, model accuracy, analyst reviews, or what changed today."
        )

    except Exception as e:
        print(f"AI assistant error: {e}")
        return "The AI assistant could not load system context right now. Check the server logs for details."


def explain_dashboard_section(section_name):
    explanations = {
        "overview": "The overview cards show the total number of reports, indicators, predictions, alerts, and correlations currently stored in the system.",
        "source_activity": "Source activity shows which feeds or report sources are contributing the most data so the analyst can compare external intelligence feeds and manual uploads.",
        "threat_digest": "The daily threat digest summarizes what changed today, which threat categories are most active, and what still needs analyst attention.",
        "ai_summary": "The AI executive summary turns dashboard statistics into a plain language explanation so a user can quickly understand the current threat posture.",
        "feed_activity": "Recent feed activity shows when threat feeds ran, how many records were fetched, and how many new reports were added.",
        "correlations": "The correlation section helps identify related campaigns, duplicate reports, and overlapping indicators of compromise.",
        "attck_mapping": "ATT&CK mapping connects system findings to adversary tactics and techniques so the threat can be understood in a more operational way."
    }
    return explanations.get(section_name, "This dashboard section helps explain threat activity and analyst workflow.")


def build_dashboard_payload():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT r.report_id, r.title, r.source, r.upload_date,
               t.threat_type, t.severity, t.confidence_score
        FROM reports r
        LEFT JOIN threat_classifications t ON r.report_id = t.report_id
        ORDER BY r.upload_date DESC
    """)
    reports = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) AS total_reports FROM reports")
    total_reports = cursor.fetchone()["total_reports"]

    cursor.execute("SELECT COUNT(*) AS total_indicators FROM indicators")
    total_indicators = cursor.fetchone()["total_indicators"]

    cursor.execute("SELECT COUNT(*) AS total_predictions FROM threat_predictions")
    total_predictions = cursor.fetchone()["total_predictions"]

    cursor.execute("SELECT COUNT(*) AS total_alerts FROM threat_alerts")
    total_alerts = cursor.fetchone()["total_alerts"]

    cursor.execute("SELECT COUNT(*) AS total_correlations FROM report_correlations")
    total_correlations = cursor.fetchone()["total_correlations"]

    total_extracted_relations = get_total_extracted_relations()

    cursor.execute("""
        SELECT COALESCE(threat_type, 'Unclassified') AS threat_type, COUNT(*) AS count
        FROM threat_classifications
        GROUP BY threat_type
        ORDER BY count DESC
    """)
    threat_type_data = cursor.fetchall()

    cursor.execute("""
        SELECT COALESCE(severity, 'Unknown') AS severity, COUNT(*) AS count
        FROM threat_classifications
        GROUP BY severity
        ORDER BY count DESC
    """)
    severity_data = cursor.fetchall()

    cursor.execute("""
        SELECT report_day, count
        FROM (
            SELECT DATE(upload_date) AS report_day, COUNT(*) AS count
            FROM reports
            GROUP BY DATE(upload_date)
        ) grouped_reports
        ORDER BY report_day ASC
    """)
    reports_over_time = cursor.fetchall()

    cursor.execute("""
        SELECT relationship_type, COUNT(*) AS count
        FROM report_correlations
        GROUP BY relationship_type
        ORDER BY count DESC
    """)
    correlation_type_data = cursor.fetchall()

    cursor.execute("""
        SELECT indicator_type, indicator_value, COUNT(*) AS count
        FROM indicators
        GROUP BY indicator_type, indicator_value
        HAVING COUNT(*) > 1
        ORDER BY count DESC
        LIMIT 10
    """)
    recurring_iocs = cursor.fetchall()

    cursor.execute("""
        SELECT rc.report_id, rc.related_report_id, rc.shared_iocs, rc.similarity_score,
               rc.relationship_type, r1.title AS report_title, r2.title AS related_title
        FROM report_correlations rc
        JOIN reports r1 ON rc.report_id = r1.report_id
        JOIN reports r2 ON rc.related_report_id = r2.report_id
        ORDER BY rc.created_at DESC
        LIMIT 10
    """)
    recent_correlations = cursor.fetchall()

    cursor.execute("""
        SELECT id, prediction_id, alert_message, alert_level,
               strftime('%Y-%m-%d %H:%M:%S', created_at) AS created_at
        FROM threat_alerts
        ORDER BY created_at DESC
        LIMIT 8
    """)
    recent_alerts = cursor.fetchall()

    cursor.execute("""
        SELECT predicted_label, COUNT(*) AS count
        FROM threat_predictions
        GROUP BY predicted_label
        ORDER BY count DESC
    """)
    threat_counts = cursor.fetchall()

    cursor.execute("""
        SELECT source, COUNT(*) AS count
        FROM reports
        GROUP BY source
        ORDER BY count DESC
    """)
    source_ingestion_counts = cursor.fetchall()

    cursor.execute("""
        SELECT report_id, title, source, upload_date
        FROM reports
        ORDER BY upload_date DESC
        LIMIT 10
    """)
    recent_ingested_reports = cursor.fetchall()

    cursor.close()
    conn.close()

    return {
        "reports": reports,
        "total_reports": total_reports,
        "total_indicators": total_indicators,
        "total_predictions": total_predictions,
        "total_alerts": total_alerts,
        "total_correlations": total_correlations,
        "total_extracted_relations": total_extracted_relations,
        "threat_type_data": threat_type_data,
        "severity_data": severity_data,
        "reports_over_time": reports_over_time,
        "correlation_type_data": correlation_type_data,
        "recurring_iocs": recurring_iocs,
        "recent_correlations": recent_correlations,
        "recent_alerts": recent_alerts,
        "threat_counts": threat_counts,
        "source_ingestion_counts": source_ingestion_counts,
        "recent_ingested_reports": recent_ingested_reports
    }


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("lab.dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error_message = None
    ip = get_client_ip()

    if is_ip_blocked(ip):
        abort(403, description="Access denied. Your IP is temporarily blocked.")

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute(
                "SELECT * FROM users WHERE username = %s",
                (username,)
            )
            user = cursor.fetchone()
            cursor.close()
            conn.close()

            password_valid = False

            if user:
                stored_password = user.get("password", "") or ""

                if stored_password.startswith(("scrypt:", "pbkdf2:")):
                    password_valid = check_password_hash(stored_password, password)
                else:
                    # Temporary compatibility for the SQLite seed account.
                    # After the first successful login, upgrade it to a secure hash.
                    password_valid = stored_password == password

                    if password_valid:
                        try:
                            upgrade_conn = get_db_connection()
                            upgrade_cursor = upgrade_conn.cursor()
                            upgrade_cursor.execute(
                                "UPDATE users SET password = %s WHERE user_id = %s",
                                (generate_password_hash(password), user["user_id"])
                            )
                            upgrade_conn.commit()
                            upgrade_cursor.close()
                            upgrade_conn.close()
                        except Error as upgrade_error:
                            print(f"Password hash upgrade warning: {upgrade_error}")

            if user and password_valid:
                session["user_id"] = user["user_id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                return redirect(url_for("lab.dashboard"))

            log_attack_event(
                ip=ip,
                endpoint="/login",
                method="POST",
                payload_snippet=f"username={username}",
                attack_type="Failed Login",
                technique="Invalid login credentials",
                severity="Medium",
                confidence=0.85,
                denied=False
            )

            failed_count = get_recent_failed_login_count(ip)
            if failed_count >= MAX_FAILED_LOGINS:
                block_ip(ip, "Too many failed login attempts")
                error_message = "Too many failed attempts. IP temporarily blocked."
            else:
                error_message = "Invalid username or password."

        except Error as e:
            error_message = f"Database error: {e}"

    return render_template("login.html", error_message=error_message)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        data = build_dashboard_payload()
        data["digest"] = get_daily_threat_digest()
        data["ai_summary"] = get_ai_summary()
        data["change_summary"] = get_change_summary()
        data["feed_runs"] = get_recent_feed_runs()
        data["topic_modeling"] = get_topic_modeling_summary()
        data["username"] = session["username"]
        return render_template("dashboard.html", **data)
    except Error as e:
        return f"Database error: {e}"


@app.route("/dashboard_data", methods=["GET"])
def dashboard_data():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        data = build_dashboard_payload()
        data["digest"] = get_daily_threat_digest()
        data["ai_summary"] = get_ai_summary()
        data["change_summary"] = get_change_summary()
        data["feed_runs"] = get_recent_feed_runs()
        data["topic_modeling"] = get_topic_modeling_summary()
        return jsonify(data)
    except Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/daily_digest")
def api_daily_digest():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_daily_threat_digest())


@app.route("/api/ai_summary")
def api_ai_summary():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_ai_summary())


@app.route("/api/change_summary")
def api_change_summary():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_change_summary())


@app.route("/api/feed_runs")
def api_feed_runs():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(get_recent_feed_runs())


@app.route("/api/explain_dashboard")
def api_explain_dashboard():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    section = request.args.get("section", "overview")
    return jsonify({"section": section, "explanation": explain_dashboard_section(section)})




@app.route("/api/ai_assistant", methods=["POST"])
def api_ai_assistant():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    question = data.get("question", "") if data else ""
    answer = ai_assistant_response(question)

    return jsonify({
        "question": question,
        "answer": answer
    })


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form["title"]
        source = request.form["source"]
        content = request.form["content"]
        ip = get_client_ip()

        report_id, created = process_report(
            title=title,
            source=source,
            content=content,
            uploaded_by=session["user_id"],
            source_ip=ip
        )

        if report_id:
            log_feed_run("Manual Upload", 1, 1 if created else 0, "success", "Manual report uploaded by user")
            return redirect(url_for("results", report_id=report_id))
        return "Database error while processing uploaded report."

    return render_template("upload.html")


@app.route("/run_feeds", methods=["POST"])
def run_feeds():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    result = run_all_feeds()

    return jsonify({
        "status": "ok",
        "total_fetched": result.get("total_fetched", 0),
        "total_new": result.get("total_new", 0),
        "sources_checked": result.get("sources_checked", 0),
        "processing_seconds": result.get("processing_seconds", 0),
        "throughput_reports_per_second": result.get("throughput_reports_per_second", 0),
        "started_at": result.get("started_at"),
        "completed_at": result.get("completed_at"),
        "source_results": result.get("source_results", []),
        "latest_items": result.get("latest_items", []),
        "errors": result.get("errors", {})
    })


@app.route("/results/<int:report_id>")
def results(report_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM reports WHERE report_id = %s", (report_id,))
        report = cursor.fetchone()

        cursor.execute("SELECT * FROM threat_classifications WHERE report_id = %s", (report_id,))
        classification = cursor.fetchone()

        cursor.execute("SELECT * FROM summaries WHERE report_id = %s", (report_id,))
        summary = cursor.fetchone()

        cursor.execute("SELECT * FROM indicators WHERE report_id = %s", (report_id,))
        indicators = cursor.fetchall()

        cursor.close()
        conn.close()

        correlations = get_report_correlations(report_id)
        extracted_relations = get_extracted_relations(report_id)
        attack_mapping = map_report_to_attack_ttp(report, classification, indicators)
        ai_explanation = generate_ai_explanation(report, classification, indicators, correlations)
        latest_review = get_latest_analyst_review(report_id)

        preprocessing_details = build_preprocessing_details(report.get("content", "") if report else "")
        indicator_data = group_indicators_by_type(indicators)
        confidence_value = classification.get("confidence_score") if classification else None
        confidence_info = get_confidence_interpretation(confidence_value)
        transformer_result = analyze_with_transformer(report.get("content", "") if report else "")
        transformer_status = get_transformer_status()

        return render_template(
            "results.html",
            report=report,
            classification=classification,
            summary=summary,
            indicators=indicators,
            correlations=correlations,
            extracted_relations=extracted_relations,
            attack_mapping=attack_mapping,
            ai_explanation=ai_explanation,
            latest_review=latest_review,
            preprocessing_details=preprocessing_details,
            indicator_data=indicator_data,
            confidence_info=confidence_info,
            transformer_result=transformer_result,
            transformer_status=transformer_status,
            allowed_threat_types=get_allowed_threat_types(),
            allowed_severity_levels=get_allowed_severity_levels(),
            current_username=session.get("username", "Analyst")
        )

    except Error as e:
        return f"Database error: {e}"


@app.route("/review_report/<int:report_id>", methods=["POST"])
def review_report(report_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    review_status = request.form.get("review_status", "").strip()
    review_note = request.form.get("review_note", "").strip()
    reviewer_name = request.form.get("reviewer_name", "").strip()
    corrected_threat_type = request.form.get("corrected_threat_type", "").strip()
    corrected_severity = request.form.get("corrected_severity", "").strip()
    escalated = request.form.get("escalated") == "1"
    use_for_retraining = request.form.get("use_for_retraining") == "1"

    if not review_status:
        return redirect(url_for("results", report_id=report_id))

    save_analyst_review(
        report_id=report_id,
        review_status=review_status,
        review_note=review_note,
        reviewer_name=reviewer_name,
        corrected_threat_type=corrected_threat_type,
        corrected_severity=corrected_severity,
        escalated=escalated,
        use_for_retraining=use_for_retraining
    )

    return redirect(url_for("results", report_id=report_id))


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    input_text = data["text"]
    source_ip = get_client_ip()

    cleaned_text, predicted_label, confidence = ml_predict_text(input_text)
    transformer_result = analyze_with_transformer(input_text)
    prediction_id = save_prediction(input_text, cleaned_text, predicted_label, confidence, source_ip)

    trigger, alert_level = should_trigger_alert(predicted_label, confidence)
    alert_message = None

    if trigger and prediction_id:
        alert_message = f"Threat detected: {predicted_label} from IP {source_ip} with confidence {confidence:.2f}"
        save_alert(prediction_id, alert_message, alert_level)

    return jsonify({
        "input_text": input_text,
        "cleaned_text": cleaned_text,
        "predicted_label": predicted_label,
        "confidence_score": round(float(confidence), 4),
        "source_ip": source_ip,
        "alert_triggered": trigger,
        "alert_level": alert_level,
        "alert_message": alert_message,
        "transformer_result": transformer_result
    })


@app.route("/predictions", methods=["GET"])
def predictions():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM threat_predictions ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(rows)
    except Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/alerts", methods=["GET"])
def alerts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM threat_alerts ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(rows)
    except Error as e:
        return jsonify({"error": str(e)}), 500


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(error):
    return f"<h2>403 Forbidden</h2><p>{error.description}</p>", 403


from lab_web import register_lab
register_lab(app)

if __name__ == "__main__":
    initialize_database()
    import lab_core
    lab_core.init()
    ensure_relation_extraction_table()
    should_start_scheduler = (
        os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug
    )
    if should_start_scheduler and os.getenv('ENABLE_FEEDS', '0') == '1':
        start_scheduler()

    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=int(os.getenv("PORT", "5000")), debug=debug_mode, use_reloader=debug_mode)
    
