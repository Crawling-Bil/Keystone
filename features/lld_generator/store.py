"""LLD Generator data: master templates, projects, chapter tree, content blocks.

Ported from the Document Generator's db.py (same functions, same shapes) with
the tables renamed ``lld_gen_*`` and stored in Keystone's ``data/nes.db``.
Every function opens its own short connection; ``import_index`` and
``legacy_import`` run in one transaction each. Plain dicts in and out, so the
routes return them as JSON unchanged.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from core import database

# Resolved per call, so tests can point it at a temporary file.
DB_PATH = None


def _db_path():
    return str(DB_PATH or database.DB_PATH)


SCHEMA = """
CREATE TABLE IF NOT EXISTS lld_gen_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    closing_heading TEXT DEFAULT '',
    auto_numbered_levels TEXT NOT NULL DEFAULT '[1,2]',
    max_heading_level INTEGER NOT NULL DEFAULT 4,
    figure_seq_name TEXT NOT NULL DEFAULT 'Gambar',
    table_seq_name TEXT NOT NULL DEFAULT 'Tabel',
    legacy_id INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lld_gen_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client TEXT DEFAULT '',
    version TEXT DEFAULT '0.1',
    project_code TEXT DEFAULT '',
    company TEXT DEFAULT 'Multipolar Technology',
    prepared_by TEXT DEFAULT '',
    doc_date TEXT DEFAULT '',
    logo TEXT DEFAULT '',
    template_id INTEGER NOT NULL REFERENCES lld_gen_templates(id),
    lld_index_key TEXT DEFAULT '',
    legacy_id INTEGER,
    history TEXT DEFAULT '[]',
    approvers TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lld_gen_chapters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES lld_gen_projects(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES lld_gen_chapters(id) ON DELETE CASCADE,
    level INTEGER NOT NULL,
    order_index INTEGER NOT NULL
    ,title TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lld_gen_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chapter_id INTEGER NOT NULL REFERENCES lld_gen_chapters(id) ON DELETE CASCADE,
    order_index INTEGER NOT NULL,
    block_type TEXT NOT NULL,
    content TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lld_gen_approver_book (
    customer_key TEXT PRIMARY KEY,
    approvers TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS lld_gen_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS lld_gen_chapters_project ON lld_gen_chapters(project_id, parent_id, order_index);
CREATE INDEX IF NOT EXISTS lld_gen_blocks_chapter ON lld_gen_blocks(chapter_id, order_index);
"""


_ready = set()


def now():
    return datetime.now(timezone.utc).isoformat()


def get_conn():
    path = _db_path()
    if path not in _ready:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if path not in _ready:
        conn.executescript(SCHEMA)
        for stmt in ("ALTER TABLE lld_gen_projects ADD COLUMN history TEXT DEFAULT '[]'",
                     "ALTER TABLE lld_gen_projects ADD COLUMN approvers TEXT DEFAULT '[]'"):
            try:
                conn.execute(stmt)                       # databases made before the column existed
            except sqlite3.OperationalError:
                pass
        _ready.add(path)
    return conn


@contextmanager
def db_conn():
    """Open a connection for the duration of a `with` block, commit on clean
    exit, roll back on exception, always close. Replaces the previous
    repeated open/commit/close boilerplate in every function below, and lets
    a function that needs more than one statement do it on a single
    connection instead of opening a fresh one per statement."""
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    get_conn().close()


def row_to_dict(row):
    return dict(row) if row else None


# ---------------- templates ----------------

def create_template(name, filename, closing_heading, auto_numbered_levels, max_heading_level,
                     figure_seq_name="Gambar", table_seq_name="Tabel"):
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO lld_gen_templates (name, filename, closing_heading, auto_numbered_levels, max_heading_level, "
            "figure_seq_name, table_seq_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, filename, closing_heading, json.dumps(auto_numbered_levels), max_heading_level,
             figure_seq_name, table_seq_name, now()),
        )
        tid = cur.lastrowid
    return get_template(tid)


def list_templates():
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM lld_gen_templates ORDER BY created_at DESC").fetchall()
    return [row_to_dict(r) for r in rows]


def get_template(template_id):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_templates WHERE id = ?", (template_id,)).fetchone()
    return row_to_dict(row)


def update_template(template_id, **fields):
    if not fields:
        return get_template(template_id)
    if "auto_numbered_levels" in fields:
        fields["auto_numbered_levels"] = json.dumps(fields["auto_numbered_levels"])
    with db_conn() as conn:
        cols = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE lld_gen_templates SET {cols} WHERE id = ?", (*fields.values(), template_id))
    return get_template(template_id)


def count_projects_using_template(template_id):
    """Berapa project yang masih pakai template ini — dipakai buat cek aman
    sebelum hapus template (lihat delete_template)."""
    with db_conn() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM lld_gen_projects WHERE template_id = ?", (template_id,)
        ).fetchone()
    return row["n"]


def delete_template(template_id):
    with db_conn() as conn:
        conn.execute("DELETE FROM lld_gen_templates WHERE id = ?", (template_id,))


# ---------------- projects ----------------

def create_project(name, client, version, template_id, project_code="", company="Multipolar Technology",
                   prepared_by="", doc_date="", lld_index_key="", legacy_id=None):
    ts = now()
    with db_conn() as conn:
        cur = conn.execute(
            "INSERT INTO lld_gen_projects (name, client, version, template_id, project_code, company, prepared_by, doc_date,"
            " lld_index_key, legacy_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (name, client, version, template_id, project_code, company or "Multipolar Technology", prepared_by,
             doc_date, lld_index_key, legacy_id, ts, ts),
        )
        pid = cur.lastrowid
    return get_project(pid)


def list_projects():
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT p.*, t.name AS template_name FROM lld_gen_projects p "
            "LEFT JOIN lld_gen_templates t ON t.id = p.template_id ORDER BY p.updated_at DESC"
        ).fetchall()
    return [row_to_dict(r) for r in rows]


def get_project(project_id):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_projects WHERE id = ?", (project_id,)).fetchone()
    return row_to_dict(row)


def update_project(project_id, **fields):
    if not fields:
        return get_project(project_id)
    fields["updated_at"] = now()
    with db_conn() as conn:
        cols = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE lld_gen_projects SET {cols} WHERE id = ?", (*fields.values(), project_id))
    return get_project(project_id)


def delete_project(project_id):
    with db_conn() as conn:
        conn.execute("DELETE FROM lld_gen_projects WHERE id = ?", (project_id,))


# ---------------- chapters ----------------

def _next_order_index(conn, project_id, parent_id):
    if parent_id is None:
        row = conn.execute(
            "SELECT COALESCE(MAX(order_index), -1) + 1 AS n FROM lld_gen_chapters WHERE project_id = ? AND parent_id IS NULL",
            (project_id,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT COALESCE(MAX(order_index), -1) + 1 AS n FROM lld_gen_chapters WHERE project_id = ? AND parent_id = ?",
            (project_id, parent_id),
        ).fetchone()
    return row["n"]


def next_order_index(project_id, parent_id):
    """Public wrapper kept for callers outside this module; internal
    functions in this file use `_next_order_index(conn, ...)` directly so
    they can share one connection/transaction instead of opening a second."""
    with db_conn() as conn:
        return _next_order_index(conn, project_id, parent_id)


def create_chapter(project_id, parent_id, title):
    with db_conn() as conn:
        if parent_id is None:
            level = 1
        else:
            prow = conn.execute("SELECT level FROM lld_gen_chapters WHERE id = ?", (parent_id,)).fetchone()
            if prow is None:
                raise ValueError("parent chapter not found")
            level = prow["level"] + 1
        order_index = _next_order_index(conn, project_id, parent_id)
        cur = conn.execute(
            "INSERT INTO lld_gen_chapters (project_id, parent_id, level, order_index, title) VALUES (?, ?, ?, ?, ?)",
            (project_id, parent_id, level, order_index, title),
        )
        cid = cur.lastrowid
    return get_chapter(cid)


def get_chapter(chapter_id):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_chapters WHERE id = ?", (chapter_id,)).fetchone()
    return row_to_dict(row)


def list_chapters_flat(project_id):
    """Return all chapters of a project ordered for a depth-first walk."""
    with db_conn() as conn:
        rows = conn.execute("SELECT * FROM lld_gen_chapters WHERE project_id = ?", (project_id,)).fetchall()
    chapters = [row_to_dict(r) for r in rows]
    by_parent = {}
    for c in chapters:
        by_parent.setdefault(c["parent_id"], []).append(c)
    for k in by_parent:
        by_parent[k].sort(key=lambda c: c["order_index"])

    ordered = []

    def walk(parent_id):
        for c in by_parent.get(parent_id, []):
            ordered.append(c)
            walk(c["id"])

    walk(None)
    return ordered


def update_chapter(chapter_id, **fields):
    if not fields:
        return get_chapter(chapter_id)
    with db_conn() as conn:
        cols = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE lld_gen_chapters SET {cols} WHERE id = ?", (*fields.values(), chapter_id))
    return get_chapter(chapter_id)


def _recompute_levels_below(conn, chapter_id, new_level):
    rows = conn.execute("SELECT id FROM lld_gen_chapters WHERE parent_id = ?", (chapter_id,)).fetchall()
    for r in rows:
        conn.execute("UPDATE lld_gen_chapters SET level = ? WHERE id = ?", (new_level + 1, r["id"]))
        _recompute_levels_below(conn, r["id"], new_level + 1)


def move_chapter(chapter_id, new_parent_id, new_order_index):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_chapters WHERE id = ?", (chapter_id,)).fetchone()
        if row is None:
            raise ValueError("chapter not found")
        if new_parent_id is None:
            new_level = 1
        else:
            prow = conn.execute("SELECT level FROM lld_gen_chapters WHERE id = ?", (new_parent_id,)).fetchone()
            if prow is None:
                raise ValueError("target parent not found")
            new_level = prow["level"] + 1
        conn.execute(
            "UPDATE lld_gen_chapters SET parent_id = ?, level = ?, order_index = ? WHERE id = ?",
            (new_parent_id, new_level, new_order_index, chapter_id),
        )
        _recompute_levels_below(conn, chapter_id, new_level)
    return get_chapter(chapter_id)


def delete_chapter(chapter_id):
    with db_conn() as conn:
        conn.execute("DELETE FROM lld_gen_chapters WHERE id = ?", (chapter_id,))


# ---------------- content blocks ----------------

def list_blocks(chapter_id):
    with db_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM lld_gen_blocks WHERE chapter_id = ? ORDER BY order_index", (chapter_id,)
        ).fetchall()
    out = []
    for r in rows:
        d = row_to_dict(r)
        d["content"] = json.loads(d["content"])
        out.append(d)
    return out


def create_block(chapter_id, block_type, content):
    with db_conn() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(order_index), -1) + 1 AS n FROM lld_gen_blocks WHERE chapter_id = ?",
            (chapter_id,),
        ).fetchone()
        order_index = row["n"]
        cur = conn.execute(
            "INSERT INTO lld_gen_blocks (chapter_id, order_index, block_type, content) VALUES (?, ?, ?, ?)",
            (chapter_id, order_index, block_type, json.dumps(content)),
        )
        bid = cur.lastrowid
    return get_block(bid)


def get_block(block_id):
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_blocks WHERE id = ?", (block_id,)).fetchone()
    d = row_to_dict(row)
    if d:
        d["content"] = json.loads(d["content"])
    return d


def update_block(block_id, content=None, order_index=None):
    fields = {}
    if content is not None:
        fields["content"] = json.dumps(content)
    if order_index is not None:
        fields["order_index"] = order_index
    if not fields:
        return get_block(block_id)
    with db_conn() as conn:
        cols = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(f"UPDATE lld_gen_blocks SET {cols} WHERE id = ?", (*fields.values(), block_id))
    return get_block(block_id)


def delete_block(block_id):
    with db_conn() as conn:
        conn.execute("DELETE FROM lld_gen_blocks WHERE id = ?", (block_id,))


# ============================================================= import Excel Index
def _is_placeholder_block(block_type, content):
    """Block yang isinya cuma penanda 'belum diisi' dari Keystone (TBD)."""
    if block_type == "paragraph":
        texts = [t.strip() for t in content.get("paragraphs") or [] if str(t).strip()]
        return not texts or texts == ["TBD"]
    if block_type == "table":
        rows = content.get("rows") or []
        cells = [str(c).strip() for r in rows for c in r if str(c).strip()]
        return not cells or cells == ["TBD"]
    if block_type == "image":
        return not content.get("filename")
    return False


def _merge_blocks(old, new):
    """Isi baru buat satu bab di mode update.
    old: [(block_type, content)] yang ada di DB, new: dari Index.
    - Gambar yang udah diupload selalu dipertahankan (Index nggak pernah bawa file gambar).
    - Paragraf/tabel dari Index menggantikan yang lama, KECUALI Index cuma bawa TBD
      dan yang lama udah diisi manual: yang lama dipakai.
    """
    old_by_type = {}
    for block_type, content in old:
        old_by_type.setdefault(block_type, []).append(content)
    out = []
    used = {k: 0 for k in old_by_type}
    for block in new:
        block_type, content = block["block_type"], block["content"]
        candidates = old_by_type.get(block_type) or []
        i = used.get(block_type, 0)
        previous = candidates[i] if i < len(candidates) else None
        used[block_type] = i + 1
        if previous is not None and _is_placeholder_block(block_type, content) \
                and not _is_placeholder_block(block_type, previous):
            if block_type == "image" and content.get("caption") and not previous.get("caption"):
                previous = {**previous, "caption": content["caption"]}
            out.append((block_type, previous))
        else:
            out.append((block_type, content))
    # gambar lama yang nggak kebagian slot (diupload manual di luar Index): jangan dibuang
    for block_type, contents in old_by_type.items():
        if block_type == "image":
            out += [("image", c) for c in contents[used.get("image", 0):] if c.get("filename")]
    return out


def import_index(project_id, items, mode="append"):
    """Bangun struktur bab dari hasil importer.parse_index_workbook() dalam SATU
    transaksi: gagal di tengah = nggak ada yang berubah.

    mode:
      append  - tambahkan di bawah struktur yang ada
      replace - hapus semua bab dulu
      update  - cocokkan bab lewat jalur judulnya (Bab > Sub-bab > ...): isi tabel/
                paragraf diganti data baru, gambar yang udah diupload dan isi yang
                diisi manual (Index cuma TBD) dipertahankan, bab yang nggak ada di
                Index baru dibiarkan. Urutan ngikutin Index.
    """
    stats = {"chapters": 0, "blocks": 0, "updated": 0, "kept_blocks": 0, "not_in_index": []}
    conn = get_conn()
    try:
        conn.execute("BEGIN")
        existing = {}
        if mode == "replace":
            conn.execute("DELETE FROM lld_gen_chapters WHERE project_id = ? AND parent_id IS NULL", (project_id,))
        elif mode == "update":
            rows = conn.execute("SELECT * FROM lld_gen_chapters WHERE project_id = ?", (project_id,)).fetchall()
            by_id = {r["id"]: dict(r) for r in rows}

            def path_of(ch):
                parts = []
                while ch is not None:
                    parts.append(ch["title"].strip().lower())
                    ch = by_id.get(ch["parent_id"])
                return tuple(reversed(parts))

            for ch in by_id.values():
                existing.setdefault(path_of(ch), ch)
            seen_ids = set()

        stack = []          # [(level, chapter_id, path)]
        order = {}          # parent_id -> next order index (update mode reorders)
        for item in items:
            level = max(1, item["level"])
            while stack and stack[-1][0] >= level:
                stack.pop()
            parent_id = stack[-1][1] if stack else None
            parent_path = stack[-1][2] if stack else ()
            path = parent_path + (item["title"].strip().lower(),)
            match = existing.get(path) if mode == "update" else None
            if match is not None:
                cid = match["id"]
                seen_ids.add(cid)
                old = [(r["block_type"], json.loads(r["content"])) for r in conn.execute(
                    "SELECT block_type, content FROM lld_gen_blocks WHERE chapter_id = ? ORDER BY order_index", (cid,))]
                blocks = _merge_blocks(old, item["blocks"])
                stats["kept_blocks"] += sum(1 for b in blocks if any(b[1] is o[1] for o in old))
                conn.execute("DELETE FROM lld_gen_blocks WHERE chapter_id = ?", (cid,))
                idx = order.get(parent_id, 0)
                order[parent_id] = idx + 1
                conn.execute("UPDATE lld_gen_chapters SET order_index = ?, title = ? WHERE id = ?", (idx, item["title"], cid))
                stats["updated"] += 1
            else:
                if mode == "update":
                    idx = order.get(parent_id, 0)
                    order[parent_id] = idx + 1
                else:
                    idx = _next_order_index(conn, project_id, parent_id)
                real_level = 1 if parent_id is None else conn.execute(
                    "SELECT level FROM lld_gen_chapters WHERE id = ?", (parent_id,)).fetchone()["level"] + 1
                cur = conn.execute(
                    "INSERT INTO lld_gen_chapters (project_id, parent_id, level, order_index, title) VALUES (?, ?, ?, ?, ?)",
                    (project_id, parent_id, real_level, idx, item["title"]))
                cid = cur.lastrowid
                blocks = [(b["block_type"], b["content"]) for b in item["blocks"]]
                stats["chapters"] += 1
            for i, (block_type, content) in enumerate(blocks):
                conn.execute(
                    "INSERT INTO lld_gen_blocks (chapter_id, order_index, block_type, content) VALUES (?, ?, ?, ?)",
                    (cid, i, block_type, json.dumps(content)))
                stats["blocks"] += 1
            stack.append((level, cid, path))

        if mode == "update":
            # bab lama yang nggak ada di Index: tetap ada, ditaruh setelah yang dari Index
            for path, ch in sorted(existing.items(), key=lambda kv: (len(kv[0]), kv[1]["order_index"])):
                if ch["id"] in seen_ids:
                    continue
                idx = order.get(ch["parent_id"], 0)
                order[ch["parent_id"]] = idx + 1
                conn.execute("UPDATE lld_gen_chapters SET order_index = ? WHERE id = ?", (idx, ch["id"]))
                parent_seen = ch["parent_id"] is None or ch["parent_id"] in seen_ids
                if parent_seen:
                    stats["not_in_index"].append(ch["title"])
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return stats


def find_project_by_index_key(key):
    """The project made from an LLD Index build with this key (newest first)."""
    if not key:
        return None
    with db_conn() as conn:
        row = conn.execute("SELECT * FROM lld_gen_projects WHERE lld_index_key = ? ORDER BY updated_at DESC LIMIT 1",
                           (key,)).fetchone()
    return row_to_dict(row)


# ---------------- approvers ----------------

def customer_key(client):
    return " ".join(str(client or "").split()).lower()


def get_approver_book(client):
    key = customer_key(client)
    if not key:
        return []
    with db_conn() as conn:
        row = conn.execute("SELECT approvers FROM lld_gen_approver_book WHERE customer_key = ?", (key,)).fetchone()
    return json.loads(row["approvers"]) if row else []


def set_approver_book(client, approvers):
    key = customer_key(client)
    if not key:
        return
    with db_conn() as conn:
        conn.execute("INSERT INTO lld_gen_approver_book (customer_key, approvers, updated_at) VALUES (?, ?, ?) "
                     "ON CONFLICT(customer_key) DO UPDATE SET approvers = excluded.approvers, updated_at = excluded.updated_at",
                     (key, json.dumps(approvers), now()))


def get_setting(key, default=None):
    with db_conn() as conn:
        row = conn.execute("SELECT value FROM lld_gen_settings WHERE key = ?", (key,)).fetchone()
    return json.loads(row["value"]) if row else default


def set_setting(key, value):
    with db_conn() as conn:
        conn.execute("INSERT INTO lld_gen_settings (key, value) VALUES (?, ?) "
                     "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))
