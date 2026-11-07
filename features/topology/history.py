"""The topology history: every build kept in ``exports/topology``, listed, opened, renamed, pinned, downloaded and deleted.

One build is one folder named by a 32-character hex id (see ``retention.py`` for how many are kept).  This module reads and
changes those folders for the "Topology history" panel of the Topology Builder.  Rules that keep it safe:

* every function takes a run id and checks it against ``RUN_ID`` before it builds a path, so an id can never leave the export folder,
* a folder that is a symbolic link is ignored,
* only the small marker files written here (``_meta.json``, ``_name.txt``, ``_pinned``) are ever created or changed; the build files are
  only read or removed together with the whole folder,
* the folder's modified time is the age the clean-up measures, so every change made here puts the time back (an old run that is renamed
  or pinned must not look new),
* nothing here raises for a damaged or half-deleted folder: such a run is skipped or reported as unreadable.

The list is built from ``_meta.json`` (written at build time, or the first time an older run is listed) so that showing twenty runs does
not mean reading twenty ``topology.json`` files of several megabytes each.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import gzip
import json
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

from .retention import PIN_FILE, RUN_ID, _remove

META_FILE = "_meta.json"
NAME_FILE = "_name.txt"
NOTE_FILE = "_note.txt"               # a few words of the user: why this run was built ("before the change window", "after the core swap")
MAX_NOTE = 300
META_VERSION = 1
RESULT_FILE = "_result.json.gz"        # the answer of the build as the page showed it (tables, diagrams): "Open again" shows it without building again
MAX_RESULT_BYTES = 64 * 1024 * 1024  # an unpacked result larger than this is not read back
MAX_PINNED = 30                      # a pinned run is exempt from the clean-up, so the number of them is bounded (about 2 MB each)
MAX_LISTED = 100
MAX_NAME = 60
TOP_FINDINGS = 12
OPTION_KEYS = ("view", "group_used", "line_style", "line_shape", "show_ports", "show_link_ips", "bundle_members", "exclude_endpoints", "collapse_endpoints", "collapse_aps",
               "infer_neighbors", "include_routed", "hide_mgmt", "include_hosts", "overlay_sites", "tool_version")
NAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


# ---------------------------------------------------------------- helpers
def valid_id(run_id: object) -> bool:
    return isinstance(run_id, str) and bool(RUN_ID.match(run_id))


def folder_of(export_dir: Path, run_id: object) -> Path | None:
    """The folder of a run, or None for a bad id, a missing folder or a symbolic link."""
    if not valid_id(run_id):
        return None
    folder = export_dir / str(run_id)
    try:
        if folder.is_dir() and not folder.is_symlink():
            return folder
    except OSError:
        pass
    return None


@contextlib.contextmanager
def keep_modified_time(folder: Path) -> Iterator[None]:
    """Put the folder's modified time back after the block: adding or removing a marker file would otherwise make an old run look new."""
    try:
        stat = folder.stat()
        stamp: tuple[float, float] | None = (stat.st_atime, stat.st_mtime)
    except OSError:
        stamp = None
    try:
        yield
    finally:
        if stamp is not None:
            try:
                os.utime(folder, stamp)
            except OSError:
                pass


def clean_name(text: object) -> str:
    """The name rules of the build form: letters, digits, dot, dash and underscore; spaces become a dash; at most 60 characters."""
    cleaned = re.sub(r"-{2,}", "-", NAME_SAFE.sub("", re.sub(r"\s+", "-", str(text or "").strip())))
    return cleaned.strip(".-_")[:MAX_NAME]


def folder_size(folder: Path) -> int:
    total = 0
    try:
        for root, _dirs, files in os.walk(folder):
            for name in files:
                try:
                    total += (Path(root) / name).stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _stamp(folder: Path) -> float:
    try:
        return folder.stat().st_mtime
    except OSError:
        return 0.0


# ---------------------------------------------------------------- meta (the small summary written beside the build files)
def meta_from_tables(devices: list[dict], links: list[dict], hosts: list[dict], findings: list[dict], settings: dict[str, Any] | None) -> dict[str, Any]:
    """The summary of one build, from its tables.  Counts and names of device kinds only: no capture text, no address."""
    severity = Counter(str(f.get("severity", "info")).lower() for f in findings if isinstance(f, dict))
    captured = [d for d in devices if str(d.get("captured", "yes")).lower() in ("yes", "true", "1")]
    top = []
    for f in findings:
        if isinstance(f, dict) and len(top) < TOP_FINDINGS:
            top.append({"id": str(f.get("id", ""))[:40], "severity": str(f.get("severity", ""))[:12], "title": str(f.get("title", ""))[:160]})
    options = {key: (settings or {}).get(key) for key in OPTION_KEYS if settings and key in settings and isinstance(settings[key], (str, int, float, bool))}
    return {
        "v": META_VERSION,
        "devices": len(devices), "captured": len(captured), "links": len(links), "hosts": len(hosts),
        "findings": {"total": sum(severity.values()), **{k: severity[k] for k in ("medium", "low", "info")}},
        "vendors": dict(Counter(str(d.get("vendor", "") or "unknown") for d in captured).most_common(8)),
        "roles": dict(Counter(str(d.get("role", "") or "unknown") for d in devices).most_common(10)),
        "top_findings": top,
        "options": options,
        "built": str((settings or {}).get("created", "")),
    }


def write_meta(folder: Path, meta: dict[str, Any]) -> None:
    with keep_modified_time(folder):
        try:
            (folder / META_FILE).write_text(json.dumps(meta, separators=(",", ":")), encoding="utf-8")
        except OSError:
            pass


def write_result(folder: Path, payload: dict[str, Any]) -> bool:
    """Keep the build's answer next to its files (gzip, written through a temporary name). A failure only means "Open again" is not offered for this run."""
    try:
        temporary = folder / (RESULT_FILE + ".tmp")
        with gzip.open(temporary, "wb", compresslevel=6) as handle:
            handle.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        os.replace(temporary, folder / RESULT_FILE)
        return True
    except (OSError, TypeError, ValueError):
        return False


def read_result(export_dir: Path, run_id: object) -> dict[str, Any] | None:
    """The stored answer of one kept run, or None (unknown id, a run built before this existed, a damaged or oversized file)."""
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return None
    try:
        with gzip.open(folder / RESULT_FILE, "rb") as handle:
            raw = handle.read(MAX_RESULT_BYTES + 1)
        if len(raw) > MAX_RESULT_BYTES:
            return None
        data = json.loads(raw.decode("utf-8"))
    except (OSError, EOFError, ValueError):
        return None
    return data if isinstance(data, dict) and data.get("ok") and data.get("export_id") == folder.name else None


def read_meta(folder: Path) -> dict[str, Any] | None:
    meta = _read_json(folder / META_FILE)
    return meta if isinstance(meta, dict) and meta.get("v") == META_VERSION else None


def ensure_meta(folder: Path) -> dict[str, Any] | None:
    """The summary of a run; for a run built before the summary existed it is read once from ``topology.json`` and kept."""
    meta = read_meta(folder)
    if meta is not None:
        return meta
    document = _read_json(folder / "topology.json")
    if not isinstance(document, dict):
        return None
    try:
        meta = meta_from_tables(list(document.get("devices") or []), list(document.get("links") or []), list(document.get("hosts") or []),
                                list(document.get("findings") or []), document.get("build") if isinstance(document.get("build"), dict) else None)
    except (TypeError, AttributeError):
        return None
    write_meta(folder, meta)
    return meta


# ---------------------------------------------------------------- one run
def name_of(folder: Path) -> str:
    try:
        return (folder / NAME_FILE).read_text(encoding="utf-8").strip()[:MAX_NAME]
    except OSError:
        return ""


def clean_note(text: object) -> str:
    """A note is plain text: control characters are dropped, line breaks kept (at most three), at most 300 characters."""
    lines = [re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", line).strip() for line in str(text or "").replace("\r", "").split("\n")]
    return "\n".join([line for line in lines if line][:3])[:MAX_NOTE].strip()


def note_of(folder: Path) -> str:
    try:
        return clean_note((folder / NOTE_FILE).read_text(encoding="utf-8", errors="replace")[: MAX_NOTE * 4])
    except OSError:
        return ""


def is_pinned(folder: Path) -> bool:
    return (folder / PIN_FILE).is_file()


def built_at(folder: Path, meta: dict[str, Any] | None) -> tuple[str, float]:
    """The build time as ``(text, seconds)``: the time written in the settings, else the time ``topology.json`` was written."""
    text = str((meta or {}).get("built", ""))
    for pattern in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            when = dt.datetime.strptime(text[:19] if "%S" in pattern else text[:16], pattern)
            return when.strftime("%Y-%m-%d %H:%M"), when.timestamp()
        except ValueError:
            continue
    seconds = _stamp(folder / "topology.json") or _stamp(folder)
    return dt.datetime.fromtimestamp(seconds).strftime("%Y-%m-%d %H:%M"), seconds


def expires_text(folder: Path, pinned: bool, max_age_days: float, now: float | None = None) -> str:
    """When the clean-up will remove the run by age ('' when pinned: it stays until it is deleted).  A run can go earlier when newer runs push it out."""
    if pinned:
        return ""
    stamp = _stamp(folder)
    return dt.datetime.fromtimestamp(stamp + max_age_days * 86400).strftime("%Y-%m-%d") if stamp else ""


def run_row(folder: Path, max_age_days: float) -> dict[str, Any] | None:
    meta = ensure_meta(folder)
    if meta is None:
        return None
    built, seconds = built_at(folder, meta)
    pinned = is_pinned(folder)
    findings = meta.get("findings") or {}
    return {
        "id": folder.name, "name": name_of(folder), "note": note_of(folder), "built": built, "built_seconds": seconds, "pinned": pinned,
        "devices": int(meta.get("devices", 0)), "captured": int(meta.get("captured", 0)), "links": int(meta.get("links", 0)), "hosts": int(meta.get("hosts", 0)),
        "findings": int(findings.get("total", 0)), "findings_medium": int(findings.get("medium", 0)),
        "view": str((meta.get("options") or {}).get("view", "")),
        "size": folder_size(folder), "expires": expires_text(folder, pinned, max_age_days),
        "anonymized": (folder / "keystone-topology-pack-anonymized.zip").is_file(), "has_l3": (folder / "_trace.json").is_file(),
        "has_pack": (folder / "keystone-topology-pack.zip").is_file(), "has_result": (folder / RESULT_FILE).is_file(),
    }


def list_runs(export_dir: Path, max_age_days: float, limit: int = MAX_LISTED) -> list[dict[str, Any]]:
    """Every kept run, newest first (pinned runs are marked, not moved)."""
    rows: list[tuple[float, dict[str, Any]]] = []
    try:
        entries = [e for e in export_dir.iterdir() if valid_id(e.name) and e.is_dir() and not e.is_symlink()]
    except OSError:
        return []
    for entry in entries:
        row = run_row(entry, max_age_days)
        if row is not None:
            rows.append((row["built_seconds"], row))
    rows.sort(key=lambda item: (item[0], item[1]["id"]), reverse=True)
    listed = [row for _seconds, row in rows[:limit]]
    for row in listed:                                      # the newest pinned run is the baseline that every new build is compared with
        row["baseline"] = False
    first = next((row for row in listed if row["pinned"]), None)
    if first is not None:
        first["baseline"] = True
    return listed


def baseline_of(export_dir: Path, max_age_days: float, exclude: object = None) -> dict[str, Any] | None:
    """The baseline: the newest pinned run (other than ``exclude``).  Every new build is compared with it."""
    for row in list_runs(export_dir, max_age_days):
        if row["pinned"] and row["id"] != exclude:
            return row
    return None


_HASH_LINE = re.compile(r"^([0-9a-f]{64})\s")


def pack_hash(folder: Path) -> str:
    """SHA-256 of the documentation pack as it was written (the line kept next to it), or an empty string."""
    try:
        match = _HASH_LINE.match((folder / "keystone-topology-pack.zip.sha256").read_text(encoding="ascii", errors="replace"))
    except OSError:
        return ""
    return match.group(1) if match else ""


def run_detail(export_dir: Path, run_id: object, max_age_days: float, file_names: dict[str, str]) -> dict[str, Any] | None:
    """The row plus what the details view shows: findings, kinds of device, the options of the build and the files that can be downloaded.
    ``file_names`` maps a downloadable file name to the label the panel shows."""
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return None
    row = run_row(folder, max_age_days)
    meta = ensure_meta(folder)
    if row is None or meta is None:
        return None
    files = []
    for name, label in file_names.items():
        path = folder / name
        try:
            if path.is_file():
                files.append({"name": name, "label": label, "size": path.stat().st_size})
        except OSError:
            continue
    return {**row, "pack_sha256": pack_hash(folder), "vendors": meta.get("vendors") or {}, "roles": meta.get("roles") or {}, "top_findings": meta.get("top_findings") or [],
            "findings_by_severity": {k: (meta.get("findings") or {}).get(k, 0) for k in ("medium", "low", "info")},
            "options": meta.get("options") or {}, "files": files}


# ---------------------------------------------------------------- changes
def set_pinned(export_dir: Path, run_id: object, pinned: bool) -> tuple[bool, str]:
    """Pin (exempt from the clean-up) or unpin a run.  Returns ``(ok, message)``."""
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return False, "This run is no longer kept."
    if pinned and not is_pinned(folder):
        count = sum(1 for e in _run_folders(export_dir) if is_pinned(e))
        if count >= MAX_PINNED:
            return False, f"At most {MAX_PINNED} runs can be pinned. Unpin or delete one first."
    with keep_modified_time(folder):
        try:
            if pinned:
                (folder / PIN_FILE).write_text("pinned\n", encoding="utf-8")
            else:
                (folder / PIN_FILE).unlink(missing_ok=True)
        except OSError:
            return False, "The run could not be changed. Is the file open in another program?"
    return True, ""


def rename(export_dir: Path, run_id: object, name: object) -> tuple[bool, str, str]:
    """Rename a run.  Returns ``(ok, message, saved_name)``; the saved name follows the rules of the name field on the page."""
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return False, "This run is no longer kept.", ""
    saved = clean_name(name)
    with keep_modified_time(folder):
        try:
            (folder / NAME_FILE).write_text(saved, encoding="utf-8")
        except OSError:
            return False, "The run could not be renamed. Is the file open in another program?", ""
    return True, "", saved


def set_note(export_dir: Path, run_id: object, note: object) -> tuple[bool, str, str]:
    """Write or remove the note of a run.  Returns ``(ok, message, saved_note)``; an empty note removes the file."""
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return False, "This run is no longer kept.", ""
    saved = clean_note(note)
    with keep_modified_time(folder):
        try:
            if saved:
                (folder / NOTE_FILE).write_text(saved, encoding="utf-8")
            else:
                (folder / NOTE_FILE).unlink(missing_ok=True)
        except OSError:
            return False, "The note could not be saved. Is the file open in another program?", ""
    return True, "", saved


def delete(export_dir: Path, run_id: object) -> tuple[bool, str]:
    folder = folder_of(export_dir, run_id)
    if folder is None:
        return False, "This run is no longer kept."
    try:
        gone = _remove(folder)
    except OSError:
        gone = False
    return (True, "") if gone else (False, "The run could not be fully deleted. A file is probably open in another program; close it and try again.")


def _run_folders(export_dir: Path) -> list[Path]:
    try:
        return [e for e in export_dir.iterdir() if valid_id(e.name) and e.is_dir() and not e.is_symlink()]
    except OSError:
        return []


def clear(export_dir: Path, keep_pinned: bool = True, protect: str | None = None, grace_seconds: float = 0.0) -> list[str]:
    """Delete every run (pinned runs stay unless ``keep_pinned`` is false; a young folder with no summary yet is a build in progress and stays).  Returns the ids deleted."""
    removed: list[str] = []
    now = time.time()
    for folder in _run_folders(export_dir):
        unfinished = bool(grace_seconds) and now - _stamp(folder) < grace_seconds and not (folder / META_FILE).is_file()      # a build still writing its files
        if folder.name == protect or (keep_pinned and is_pinned(folder)) or unfinished:
            continue
        try:
            if _remove(folder):
                removed.append(folder.name)
        except OSError:
            continue
    return removed


def disk_usage(export_dir: Path) -> int:
    return sum(folder_size(folder) for folder in _run_folders(export_dir))
