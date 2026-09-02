from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[1]
DB_PATH = BASE_DIR / "data" / "nes.db"


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize() -> None:
    with _connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                module TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'success'
            )
            """
        )
        connection.commit()


def log_activity(module: str, action: str, detail: str = "", status: str = "success") -> None:
    initialize()
    timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    with _connect() as connection:
        connection.execute(
            "INSERT INTO activity (created_at, module, action, detail, status) VALUES (?, ?, ?, ?, ?)",
            (timestamp, module, action, detail[:2000], status),
        )
        connection.commit()


def recent_activity(limit: int = 12) -> list[dict[str, Any]]:
    initialize()
    with _connect() as connection:
        rows = connection.execute(
            "SELECT created_at, module, action, detail, status FROM activity ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 100)),),
        ).fetchall()
    return [dict(row) for row in rows]
