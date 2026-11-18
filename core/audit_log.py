"""An append-only record of what was started from the Operate tools (Lifecycle Manager, Zero-touch provisioning).

Audit practice (change management, ISO/IEC 27001:2022 Annex A 8.15 "Logging", PCI DSS v4.0 requirement 10) wants to answer "who pushed what to which
device and when" after the fact.  Keystone is a local single-user tool, so the record is a JSON-lines file next to the other runtime folders
(``logs/audit.jsonl``):

* one line per state-changing request (POST, PUT, PATCH, DELETE) to an Operate tool: time (UTC), method, path, status, client address, the NAMES
  of the submitted fields, and the value of a few fields that name the target (host, ip, serial ...), each cut to 200 characters;
* no password, token, community string, key or configuration text is ever written: values of every other field are not read at all;
* every line carries the SHA-256 of the previous line, so an edited or removed line is found by ``verify()``;
* the file is only appended to; at 10 MB it is renamed ``audit.1.jsonl``, ``audit.2.jsonl`` ... and a new one starts (the chain continues across files).

Documentation: https://owasp.org/www-project-cheat-sheets/cheatsheets/Logging_Cheat_Sheet.html (what to log and what to leave out),
https://csrc.nist.gov/pubs/sp/800/92/final (NIST SP 800-92, guide to log management).
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_DIR = Path(__file__).resolve().parents[1] / "logs"
LOG_FILE = LOG_DIR / "audit.jsonl"
MAX_BYTES = 10 * 1024 * 1024
GENESIS = "0" * 64
PREFIXES = ("/lifecycle", "/ztp")                 # the Operate tools: they reach live devices
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
TARGET_KEYS = ("host", "hostname", "ip", "ip_address", "address", "device", "devices", "serial", "vendor", "platform", "action", "job", "job_id", "template", "firmware", "version")
VALUE_LIMIT = 200

_lock = threading.Lock()


def _digest(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _last_line(path: Path) -> str | None:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 65536))
            tail = handle.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return None
    return next((line for line in reversed(tail) if line.strip()), None)


def _rotate_if_needed(path: Path) -> None:
    try:
        if path.stat().st_size < MAX_BYTES:
            return
    except OSError:
        return
    number = 1
    while path.with_name(f"{path.stem}.{number}{path.suffix}").exists():
        number += 1
    path.rename(path.with_name(f"{path.stem}.{number}{path.suffix}"))


def _previous_hash(path: Path) -> str:
    line = _last_line(path)
    if line is None:                                            # a fresh file after rotation: continue the chain from the newest rotated file
        rotated = sorted(path.parent.glob(f"{path.stem}.*{path.suffix}"), key=lambda p: p.stat().st_mtime)
        line = _last_line(rotated[-1]) if rotated else None
    return _digest(line) if line else GENESIS


def _clean(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        value = ",".join(str(item) for item in value)
    return " ".join(str(value).split())[:VALUE_LIMIT]


def record(event: str, **fields: Any) -> dict[str, Any]:
    """Append one line.  ``fields`` must already be free of secrets; ``record_request`` is the filtered entry point."""
    entry: dict[str, Any] = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "event": event}
    entry.update({key: value for key, value in fields.items() if value not in (None, "", [], {})})
    with _lock:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _rotate_if_needed(LOG_FILE)
        entry["prev"] = _previous_hash(LOG_FILE)
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with open(LOG_FILE, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
    return entry


def record_request(method: str, path: str, status: int, client: str, form: Any = None, payload: Any = None) -> dict[str, Any] | None:
    """Log one finished request when it changes something in an Operate tool; returns the entry, or None when the request is not logged."""
    if method.upper() not in MUTATING or not path.startswith(PREFIXES):
        return None
    names: set[str] = set()
    targets: dict[str, str] = {}
    sources = []
    if form is not None:
        sources.append(form)
    if isinstance(payload, dict):
        sources.append(payload)
    for source in sources:
        for key in source.keys():
            names.add(str(key)[:60])
        for key in TARGET_KEYS:
            if key in source and not isinstance(source[key], (dict, bytes)):
                value = source.get(key)
                if value not in (None, ""):
                    targets[key] = _clean(value)
    return record("request", method=method.upper(), path=path, status=status, client=client, fields=sorted(names), target=targets)


def verify(path: Path | None = None) -> tuple[bool, int, int | None]:
    """Check the hash chain of one file: (intact, lines read, first broken line number).  The first line is checked against the previous file when there is one."""
    path = path or LOG_FILE
    previous = None
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for number, raw in enumerate(handle, start=1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                return False, count, number
            if previous is not None and entry.get("prev") != _digest(previous):
                return False, count, number
            previous = line
            count += 1
    return True, count, None


def register(app) -> None:
    """Log finished mutating requests to the Operate tools (called once from the app factory)."""
    from flask import request

    @app.after_request
    def _audit(response):
        try:
            if request.method in MUTATING and request.path.startswith(PREFIXES):
                record_request(request.method, request.path, response.status_code, request.remote_addr or "", form=request.form if request.mimetype in ("application/x-www-form-urlencoded", "multipart/form-data") else None, payload=request.get_json(silent=True))
        except Exception:                                       # the log must never break the tool it watches
            pass
        return response
