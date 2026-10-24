"""Saved LLD Index projects: the form, the inventory and the config files.

Every successful build is saved under its index key (customer, project name,
code), so building again later starts from the saved state instead of an
empty form. Config texts are kept too: a rebuild needs no re-upload, and a
newly uploaded file replaces the saved one with the same name.
Stored in Keystone's data/nes.db (table lld_idx_projects).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from core import database

DB_PATH = None          # tests point this at a temporary file
MAX_CONFIG_BYTES = 30 * 1024 * 1024
_ready: set = set()

SCHEMA = """
CREATE TABLE IF NOT EXISTS lld_idx_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    customer TEXT NOT NULL DEFAULT '',
    code TEXT NOT NULL DEFAULT '',
    payload TEXT NOT NULL,
    configs TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL
);
"""


def _conn() -> sqlite3.Connection:
    path = str(DB_PATH or database.DB_PATH)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    if path not in _ready:
        conn.executescript(SCHEMA)
        _ready.add(path)
    return conn


def index_key(project: dict) -> str:
    parts = [" ".join(str(project.get(k) or "").split()).lower() for k in ("customer", "project_name", "project_code")]
    return "|".join(parts)


def save(project: dict, technologies: list, inventory: list, files: dict) -> int:
    """Upsert by key; configs merge (new names added, same names replaced)."""
    key = index_key(project)
    with _conn() as conn:
        row = conn.execute("SELECT id, configs FROM lld_idx_projects WHERE key = ?", (key,)).fetchone()
        configs = json.loads(row["configs"]) if row else {}
        configs.update(files)
        while configs and len(json.dumps(configs)) > MAX_CONFIG_BYTES:   # keep the newest when it grows too big
            configs.pop(next(iter(configs)))
        payload = json.dumps({"project": project, "technologies": technologies, "inventory": inventory})
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        values = (project.get("project_name") or "", project.get("customer") or "", project.get("project_code") or "",
                  payload, json.dumps(configs), now)
        if row:
            conn.execute("UPDATE lld_idx_projects SET name=?, customer=?, code=?, payload=?, configs=?, updated_at=? WHERE id=?",
                         (*values, row["id"]))
            return row["id"]
        cur = conn.execute("INSERT INTO lld_idx_projects (key, name, customer, code, payload, configs, updated_at) "
                           "VALUES (?, ?, ?, ?, ?, ?, ?)", (key, *values))
        return cur.lastrowid


def listing() -> list[dict]:
    with _conn() as conn:
        rows = conn.execute("SELECT id, name, customer, code, payload, configs, updated_at FROM lld_idx_projects "
                            "ORDER BY updated_at DESC").fetchall()
    out = []
    for r in rows:
        payload = json.loads(r["payload"])
        out.append({"id": r["id"], "name": r["name"], "customer": r["customer"], "code": r["code"],
                    "updated_at": r["updated_at"], "devices": len(payload.get("inventory") or []),
                    "configs": len(json.loads(r["configs"]))})
    return out


def load(project_id: int) -> dict | None:
    with _conn() as conn:
        r = conn.execute("SELECT * FROM lld_idx_projects WHERE id = ?", (project_id,)).fetchone()
    if not r:
        return None
    payload = json.loads(r["payload"])
    configs = json.loads(r["configs"])
    return {"id": r["id"], **payload, "config_names": sorted(configs),
            "config_sizes": {k: len(v.encode("utf-8", "ignore")) for k, v in configs.items()}}


def configs(project_id: int) -> dict:
    with _conn() as conn:
        r = conn.execute("SELECT configs FROM lld_idx_projects WHERE id = ?", (project_id,)).fetchone()
    return json.loads(r["configs"]) if r else {}


def drop_config(project_id: int, name: str) -> None:
    with _conn() as conn:
        r = conn.execute("SELECT configs FROM lld_idx_projects WHERE id = ?", (project_id,)).fetchone()
        if r:
            data = json.loads(r["configs"])
            data.pop(name, None)
            conn.execute("UPDATE lld_idx_projects SET configs = ? WHERE id = ?", (json.dumps(data), project_id))


def delete(project_id: int) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM lld_idx_projects WHERE id = ?", (project_id,))
