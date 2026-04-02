"""Simple SQLite storage for prediction logs."""

from __future__ import annotations

import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS predictions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP,
  url TEXT NOT NULL,
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
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO predictions (url, score, malicious, model_version, latency_ms)
            VALUES (?, ?, ?, ?, ?)
            """,
            (url, score, int(malicious), model_version, latency_ms),
        )
        conn.commit()
