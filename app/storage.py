"""Simple SQLite storage for prediction logs."""

from __future__ import annotations

import sqlite3
from hashlib import sha256
from pathlib import Path

from app.features import redact_query

SCHEMA = """
CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  url TEXT NOT NULL,
  url_sha256 TEXT NOT NULL,
  score REAL NOT NULL,
  malicious INTEGER NOT NULL,
  model_version TEXT NOT NULL,
  latency_ms REAL NOT NULL
);
"""


def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(SCHEMA)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(predictions)")}
        if "url_sha256" not in cols:
            conn.execute("ALTER TABLE predictions ADD COLUMN url_sha256 TEXT DEFAULT ''")
        conn.commit()


def insert_prediction(
    db_path: str,
    *,
    url: str,
    score: float,
    malicious: bool,
    model_version: str,
    latency_ms: float,
) -> None:
    sanitized_url = redact_query(url)
    url_hash = sha256(sanitized_url.encode("utf-8")).hexdigest()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO predictions (url, url_sha256, score, malicious, model_version, latency_ms)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (sanitized_url, url_hash, score, int(malicious), model_version, latency_ms),
        )
        conn.commit()
