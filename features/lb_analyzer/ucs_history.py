"""Configuration change history from a UCS archive.

BIG-IP keeps a reverse diff of ``bigip.conf`` / ``bigip_base.conf`` every time the configuration is saved, in
``/config/.diffVersions/config/<file>/<n>.patch``.  A UCS carries those patches, so the archive is also an audit
trail: when each save happened (the archive member's modification time), which objects it touched and what changed.

Direction, checked against a captured device: a patch is the diff from the *newer* file (``---``) to the *older* one
(``+++``), so a line starting with ``-`` exists only in the newer version, i.e. the save **added** it, and a line
starting with ``+`` only exists in the older version, i.e. the save **removed** it.  The summaries below speak in
the engineer's direction (added / removed).

The patches say *what* and *when* but not *who*: BIG-IP does not record the administrator in them.  Secrets are
scrubbed from every line that is kept (password hashes, passphrases, shared secrets, SNMP communities).
"""

from __future__ import annotations

import re
from collections import Counter
from datetime import date, datetime, timezone
from typing import Any

from .tmsh_tree import SECRET_KEYS, _HASH

PATCH_PATH = re.compile(r"^config/\.diffVersions/config/(?P<file>bigip\.conf|bigip_base\.conf|bigip_user\.conf|bigip_script\.conf)/(?P<rev>\d+)\.patch$")
# BigDB.dat patches are counters that change on every save; automatic housekeeping lines are not administrator changes
AUTOMATIC = (("asm device-sync", "timestamp"),)
BOOKKEEPING_KEYS = {"last-modified-time", "creation-time", "revision"}      # maintained by mcpd on every object, never typed by an administrator
MAX_PATCH_BYTES = 1024 * 1024
MAX_PATCHES = 5000
SAMPLE_LINES = 10
LINE_WIDTH = 150
MODULES = {"ltm", "net", "sys", "auth", "cm", "security", "asm", "apm", "gtm", "pem", "wom", "ilx", "analytics", "cli", "ecm", "vcmp", "ip", "pps", "wam", "disk"}
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@ ?(?P<ctx>.*)$")
_MEMBER = re.compile(r"^\s+(?P<member>\S+:\w+) \{\s*$")
_HEADER_TIME = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? ([+-]\d{4})\s*$")


def is_patch(name: str) -> re.Match[str] | None:
    return PATCH_PATH.match(name)


def _stanza(text: str) -> str:
    """``ltm pool /Common/x`` from a column-0 line such as ``ltm pool /Common/x {``; empty when it is not one."""
    if not text or text[0].isspace() or "{" not in text:
        return ""
    head = text.split("{", 1)[0].split()
    if len(head) >= 2 and head[0] in MODULES:
        return " ".join(head)
    return ""


def _scrub(body: str) -> str:
    tokens = body.split()
    if not tokens or tokens[0].startswith("-----BEGIN"):
        return "" if tokens else body
    indent = body[: len(body) - len(body.lstrip())]
    if tokens[0] in SECRET_KEYS and len(tokens) > 1:
        return f"{indent}{tokens[0]} <hidden>"
    return indent + " ".join("<hidden>" if _HASH.match(t) else t for t in tokens)


def _header_time(line: str) -> datetime | None:
    match = _HEADER_TIME.search(line)
    if not match:
        return None
    try:
        return datetime.strptime(f"{match[1]} {match[2]}", "%Y-%m-%d %H:%M:%S %z").astimezone(timezone.utc)
    except ValueError:
        return None


def parse_patch(file: str, revision: int, mtime: float, raw: bytes) -> dict[str, Any]:
    """One saved change: when, which objects, how many lines, the object-level events and a scrubbed sample."""
    added = removed = 0
    objects: list[str] = []
    events: list[dict[str, str]] = []
    sample: list[str] = []
    stanza = member = ""
    older: datetime | None = None
    in_hunk = False
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not in_hunk:
            if line.startswith("+++ "):
                older = _header_time(line)
            if line.startswith("@@"):
                in_hunk = True
            else:
                continue
        hunk = _HUNK.match(line)
        if hunk:
            stanza, member = _stanza(hunk["ctx"] + " {"), ""
            continue
        if not line or line[0] not in " +-":
            continue
        sign, body = line[0], line[1:]
        head = _stanza(body)
        if head:
            stanza, member = head, ""
        found = _MEMBER.match(body)
        if found:
            member = found["member"]
        if sign == " ":
            continue
        gained = sign == "-"                                                 # '-' = only in the newer version = added by this save
        first_word = body.split()[:1]
        if first_word and first_word[0] in BOOKKEEPING_KEYS or any(stanza.startswith(prefix) and first_word == [key] for prefix, key in AUTOMATIC):
            continue
        added += gained
        removed += not gained
        if stanza and stanza not in objects and len(objects) < 40:
            objects.append(stanza)
        parts = stanza.split()
        words = body.split()
        if head:
            events.append({"kind": "object-created" if gained else "object-deleted", "object": head})
        elif parts[:2] == ["ltm", "pool"] and member and len(words) == 2 and body.startswith(" " * 12):
            pool = parts[-1]
            if words == ["session", "user-disabled"]:
                events.append({"kind": "member-disabled" if gained else "member-enabled", "object": pool, "member": member})
            elif words == ["state", "user-down"]:
                events.append({"kind": "member-forced-offline" if gained else "member-forced-online", "object": pool, "member": member})
        elif parts[:2] == ["ltm", "virtual"] and body == "    disabled":
            events.append({"kind": "virtual-disabled" if gained else "virtual-enabled", "object": parts[-1]})
        if len(sample) < SAMPLE_LINES:
            clean = _scrub(body).rstrip()
            if clean.strip():
                sample.append(("+ " if gained else "- ") + clean[:LINE_WIDTH])
    if not (added or removed):
        return {}                                                            # only automatic housekeeping changed
    return {"file": file, "revision": revision, "when": datetime.fromtimestamp(mtime, tz=timezone.utc), "previous": older, "added": added, "removed": removed,
            "objects": objects, "events": events, "sample": sample}


# --------------------------------------------------------------------------- summaries
def summarize(changes: list[dict[str, Any]], today: date) -> dict[str, Any]:
    changes = sorted(changes, key=lambda c: c["when"])
    per_month = Counter(c["when"].strftime("%Y-%m") for c in changes)
    hot: dict[str, dict[str, Any]] = {}
    for c in changes:
        for obj in c["objects"]:
            row = hot.setdefault(obj, {"object": obj, "changes": 0, "last": c["when"], "first": c["when"]})
            row["changes"] += 1
            row["last"] = max(row["last"], c["when"])
    return {
        "count": len(changes), "first": changes[0]["when"] if changes else None, "last": changes[-1]["when"] if changes else None, "changes": changes,
        "per_month": sorted(per_month.items())[-24:], "hot_objects": sorted(hot.values(), key=lambda r: (-r["changes"], r["object"]))[:25],
        "last_30_days": sum(1 for c in changes if (today - c["when"].date()).days <= 30),
        "disabled_since": _disabled_since(changes),
    }


def _disabled_since(changes: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    """Replay the member and virtual-server events in time order: what is *still* disabled or forced offline, and since when."""
    state: dict[tuple[str, str], dict[str, Any]] = {}
    for c in changes:
        for ev in c["events"]:
            kind = ev["kind"]
            if kind.startswith("member-"):
                key = (ev["object"], ev["member"])
                entry = state.setdefault(key, {"disabled": None, "offline": None})
                if kind == "member-disabled":
                    entry["disabled"] = c["when"]
                elif kind == "member-enabled":
                    entry["disabled"] = None
                elif kind == "member-forced-offline":
                    entry["offline"] = c["when"]
                elif kind == "member-forced-online":
                    entry["offline"] = None
            elif kind.startswith("virtual-"):
                key = (ev["object"], "")
                entry = state.setdefault(key, {"disabled": None, "offline": None})
                entry["disabled"] = c["when"] if kind == "virtual-disabled" else None
            elif kind == "object-deleted":
                for k in [k for k in state if k[0] == ev["object"].split()[-1]]:
                    state.pop(k)
    return {k: v for k, v in state.items() if v["disabled"] or v["offline"]}
