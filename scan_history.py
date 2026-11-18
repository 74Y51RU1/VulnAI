
import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent / "vulnai_history.db"


def get_connection():
    return sqlite3.connect(DB_PATH, timeout=10)


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target_url TEXT NOT NULL,
                nmap_evidence TEXT NOT NULL,
                http_evidence TEXT NOT NULL,
                findings TEXT NOT NULL,
                assessment TEXT NOT NULL
            )
        """)


def save_assessment(
    target_url,
    nmap_evidence,
    http_evidence,
    all_findings,
    assessment
):
    initialize_database()

    timestamp = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    )

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO assessments (
                timestamp,
                target_url,
                nmap_evidence,
                http_evidence,
                findings,
                assessment
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                target_url,
                nmap_evidence,
                json.dumps(http_evidence),
                json.dumps(all_findings),
                assessment
            )
        )

        return cursor.lastrowid


def get_scan_history(limit=50):
    initialize_database()

    with get_connection() as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                target_url,
                findings
            FROM assessments
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    history = []

    for row in rows:
        findings = json.loads(row["findings"])

        history.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "target_url": row["target_url"],
            "total_findings": len(findings),
            "confirmed": sum(
                1 for f in findings
                if f.get("status", "").lower() == "confirmed"
            )
        })

    return history


def get_assessment(assessment_id):
    initialize_database()

    with get_connection() as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT * FROM assessments WHERE id = ?",
            (assessment_id,)
        ).fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "target_url": row["target_url"],
        "nmap_evidence": row["nmap_evidence"],
        "http_evidence": json.loads(row["http_evidence"]),
        "all_findings": json.loads(row["findings"]),
        "assessment": row["assessment"]
    }
