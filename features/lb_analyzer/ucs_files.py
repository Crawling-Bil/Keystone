"""Parsers for the small, non-TMSH files inside a UCS archive.

Each function takes the decoded text (or the file name) and returns plain Python data.  They are deliberately
selective: the license keeps module names and dates but never the registration key or dossier, ``BigDB.dat`` keeps
only the values changed from their default (secret-looking ones are hidden), ``/etc/passwd`` keeps the account name
and login shell only, and nothing here ever sees a private key or a password hash.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

SECRET_DB = re.compile(r"pass|secret|key|token|psk|cred|community", re.I)
NO_LOGIN_SHELLS = ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/sync", "/sbin/halt", "/sbin/shutdown")


def keyvalue(text: str, sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if sep in line and not line.lstrip().startswith("#"):
            key, value = line.split(sep, 1)
            out[key.strip()] = value.strip()
    return out


def _yyyymmdd(text: str) -> date | None:
    try:
        return datetime.strptime(text.strip(), "%Y%m%d").date()
    except ValueError:
        return None


# --------------------------------------------------------------------------- license
def parse_license(text: str) -> dict[str, Any]:
    """Module list and dates only; ``Registration key``, ``Dossier`` and ``Authorization`` lines are not read."""
    out: dict[str, Any] = {"active": [], "optional": [], "timelimited": [], "fields": {}}
    for line in text.splitlines():
        if line.startswith("#") or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        low = key.lower()
        if low == "active module":
            out["active"].append(value.split("|")[0].strip())
        elif low == "optional module":
            out["optional"].append(value.split("|")[0].strip())
        elif low == "timelimited module":
            parts = value.split("|")
            start, end = (parts[2], parts[3]) if len(parts) >= 4 else ("", "")
            out["timelimited"].append({"module": parts[0].strip(), "start": _yyyymmdd(start), "end": _yyyymmdd(end), "kind": parts[4].strip() if len(parts) > 4 else ""})
        elif low in ("usage", "vendor", "licensed date", "licensed version", "service check date", "platform id", "evaluation", "license start", "license end", "perf_ssl_mbps", "perf_http_rps", "gtm_dns_queries_per_sec"):
            out["fields"][key] = value
    return out


# --------------------------------------------------------------------------- sys db
def parse_bigdb(text: str) -> dict[str, dict[str, str]]:
    """Only the values an administrator (or a script) changed from the default."""
    sections: dict[str, dict[str, str]] = {}
    current = ""
    for line in text.splitlines():
        match = re.match(r"\[(.+)\]\s*$", line)
        if match:
            current = match.group(1)
            sections[current] = {}
        elif current and "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            sections[current][key] = value
    out = {}
    for key, props in sections.items():
        if "value" in props and props["value"] != props.get("default", ""):
            hidden = bool(SECRET_DB.search(key))
            out[key] = {"value": "<hidden>" if hidden else props["value"], "default": "<hidden>" if hidden else props.get("default", "")}
    return out


# --------------------------------------------------------------------------- operating system
def parse_tcp_wrappers(text: str) -> list[dict[str, str]]:
    """``/etc/hosts.allow`` and ``/etc/hosts.deny`` rules: ``daemon : clients``."""
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and ":" in line:
            daemon, clients = (part.strip() for part in line.split(":", 1))
            rules.append({"daemon": daemon, "clients": clients})
    return rules


def parse_passwd(text: str) -> list[dict[str, Any]]:
    """Account name and login shell; the password field, uid and home are dropped."""
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[0]:
            out.append({"name": parts[0], "shell": parts[6].strip(), "login": parts[6].strip() not in NO_LOGIN_SHELLS})
    return out


def parse_role_partitions(text: str) -> list[dict[str, str]]:
    """``/config/bigip/auth/userrolepartitions``: ``<user> <role id> [<partitions>]``."""
    out = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            out.append({"user": parts[0], "role_id": parts[1], "partitions": parts[2].strip("[] ") if len(parts) > 2 else ""})
    return out


def parse_session_limit(text: str) -> str:
    """``sshglobalsessionlimit`` / ``sshuserlimit``: the last non-comment line, as stored."""
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    return lines[-1] if lines else ""


_RPM = re.compile(r"^(?P<name>.+?)-(?P<version>\d[\w.]*)-(?P<release>[\w.]+)\.(?P<arch>noarch|x86_64)\.rpm$")


def parse_rpm_name(filename: str) -> dict[str, str] | None:
    """Package name and version from an iApp LX RPM file name (the package itself is never opened)."""
    match = _RPM.match(filename)
    return {"name": match["name"], "version": match["version"], "release": match["release"]} if match else None


def active_script_lines(text: str) -> int:
    """Lines of a shell script that are neither blank, comments nor the shebang - 0 means the F5 default stub."""
    return sum(1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
