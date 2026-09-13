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
    # Activity logging is a best-effort audit trail, not a feature the rest
    # of the app depends on to function -- a transient sqlite error here
    # (e.g. disk I/O errors seen on some network-mounted deployments) must
    # never take down app startup or an otherwise-successful request.
    try:
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
    except sqlite3.Error as exc:
        print(f"[core.database] activity log unavailable, continuing without it: {exc}")


def log_activity(module: str, action: str, detail: str = "", status: str = "success") -> None:
    try:
        initialize()
        timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        with _connect() as connection:
            connection.execute(
                "INSERT INTO activity (created_at, module, action, detail, status) VALUES (?, ?, ?, ?, ?)",
                (timestamp, module, action, detail[:2000], status),
            )
            connection.commit()
    except sqlite3.Error as exc:
        # Never let a logging failure mask (or crash) an otherwise-successful
        # request -- see initialize() above for why this is intentionally
        # swallowed rather than re-raised.
        print(f"[core.database] failed to log activity ({module}/{action}), continuing: {exc}")


def recent_activity(limit: int = 12) -> list[dict[str, Any]]:
    try:
        initialize()
        with _connect() as connection:
            rows = connection.execute(
                "SELECT created_at, module, action, detail, status FROM activity ORDER BY id DESC LIMIT ?",
                (max(1, min(limit, 100)),),
            ).fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as exc:
        print(f"[core.database] failed to read activity log, returning empty: {exc}")
        return []
