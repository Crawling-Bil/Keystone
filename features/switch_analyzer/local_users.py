"""Local user accounts configured on a switch: who can log in without a central server.

The Single Device page answers one question here: **are there local users on this device, and which**.  It lists the account names, the privilege
level / role / group, the services a Huawei account may use and how the credential is stored (hashed, reversible or clear text).  The credential
itself (hash, cipher text, key) is read to classify it and never copied into the result.

Syntax read, one form per platform family:

* Cisco IOS / IOS XE / NX-OS: ``username NAME [privilege N] [role R] [algorithm-type T] (secret|password) [TYPE] VALUE`` | ``nopassword`` | ``sshkey ...``
  https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/command_reference/b_1715_9300_cr/security.html
  (NX-OS: https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/102x/configuration/security/cisco-nexus-9000-nx-os-security-configuration-guide-102x/m-configuring-user-accounts-and-rbac.html)
* Huawei VRP (AAA view): ``local-user NAME password (irreversible-cipher|cipher|simple) VALUE`` / ``privilege level N`` / ``service-type ...``
* ArubaOS-CX: ``user NAME group G password (ciphertext|plaintext) VALUE``
* ArubaOS-Switch: ``password (manager|operator) user-name NAME (sha1|sha256|plaintext) VALUE``

Users of a central server (TACACS+ / RADIUS / LDAP) are not local and are not listed.  A capture without a configuration says so instead of
reporting "none".
"""
from __future__ import annotations

import re
from typing import Any

from features.analyzer_core.redaction import secret_strength

CISCO_FAMILY = "cisco"
_HUAWEI_NOT_A_USER = {"password", "max-number", "user-name", "user-group", "change-password", "expire-time", "lock-time", "authentication"}


def _row(user: str) -> dict[str, Any]:
    return {"user": user, "privilege": "", "role": "", "services": "", "credential": "", "storage": "", "strength": ""}


def _unquote(token: str) -> str:
    return token.strip('"\'')


def _cisco(lines: list[str]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in lines:
        match = re.match(r"username\s+(\S+)\s*(.*)$", line)
        if not match:
            continue
        name, rest = _unquote(match.group(1)), match.group(2)
        tokens = rest.split()
        # NX-OS password-lifetime and other per-user policy lines are not accounts of their own.
        if tokens[:1] in (["passphrase"], ["common-criteria-policy"]):
            continue
        row = rows.setdefault(name, _row(name))
        for i, token in enumerate(tokens):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if token == "privilege" and nxt:
                row["privilege"] = nxt
            elif token in ("role", "view") and nxt:
                row["role"] = (row["role"] + ", " if row["role"] else "") + nxt
            elif token in ("secret", "password") and not row["credential"]:
                row["credential"] = token
                stype = nxt if nxt in ("0", "5", "6", "7", "8", "9") and i + 2 < len(tokens) else None
                if token == "secret" and stype is None:
                    row["storage"], row["strength"] = "secret, hash type not shown", "unknown"
                else:
                    row["storage"], row["strength"] = secret_strength(stype)
                    if token == "password" and stype is None:
                        row["storage"], row["strength"] = "clear text", "weak"
            elif token == "nopassword":
                row["credential"], row["storage"], row["strength"] = "none", "no password", "none"
            elif token in ("sshkey", "ssh-key") and not row["credential"]:
                row["credential"], row["storage"], row["strength"] = "ssh key", "public key", "strong"
    return list(rows.values())


def _huawei(lines: list[str]) -> list[dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for line in lines:
        match = re.match(r"local-user\s+(\S+)\s*(.*)$", line)
        if not match or _unquote(match.group(1)).lower() in _HUAWEI_NOT_A_USER:
            continue
        name, rest = _unquote(match.group(1)), match.group(2).split()
        if not rest:
            continue
        row = rows.setdefault(name, _row(name))
        if rest[0] == "password" and len(rest) > 1:
            kind = rest[1]
            row["credential"] = "password"
            row["storage"], row["strength"] = {"irreversible-cipher": ("irreversible cipher (hashed)", "strong"), "cipher": ("reversible cipher", "weak"),
                                                "simple": ("clear text", "weak")}.get(kind, (kind, "unknown"))
        elif rest[:2] == ["privilege", "level"] and len(rest) > 2:
            row["privilege"] = rest[2]
        elif rest[0] == "service-type":
            row["services"] = ", ".join(sorted(set(filter(None, (row["services"] + " " + " ".join(rest[1:])).replace(",", " ").split()))))
        elif rest[0] == "user-group" and len(rest) > 1:
            row["role"] = rest[1]
    return list(rows.values())


def _aoscx(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"user\s+(\S+)\s*(.*)$", line)
        if not match:
            continue
        tokens = match.group(2).split()
        row = _row(_unquote(match.group(1)))
        for i, token in enumerate(tokens):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if token == "group" and nxt:
                row["role"] = nxt
            elif token == "password" and nxt in ("ciphertext", "plaintext"):
                row["credential"] = "password"
                row["storage"], row["strength"] = ("hashed (ciphertext)", "strong") if nxt == "ciphertext" else ("clear text", "weak")
        rows.append(row)
    return rows


def _aruba(lines: list[str]) -> list[dict[str, Any]]:
    rows = []
    for line in lines:
        match = re.match(r"password\s+(manager|operator)\b\s*(.*)$", line)
        if match:
            tokens = match.group(2).split()
            name = _unquote(tokens[tokens.index("user-name") + 1]) if "user-name" in tokens and tokens.index("user-name") + 1 < len(tokens) else f"({match.group(1)} password, no user name)"
            row = _row(name)
            row["role"] = match.group(1)
            row["credential"] = "password"
            hashed = next((t for t in tokens if t in ("sha1", "sha256", "plaintext")), "")
            row["storage"], row["strength"] = {"sha256": ("SHA-256 hash", "ok"), "sha1": ("SHA-1 hash", "weak"), "plaintext": ("clear text", "weak")}.get(hashed, ("hash type not shown", "unknown"))
            rows.append(row)
            continue
        match = re.match(r"aaa authentication local-user\s+(\S+)\s*(.*)$", line)
        if match:
            tokens = match.group(2).split()
            row = _row(_unquote(match.group(1)))
            row["role"] = _unquote(tokens[tokens.index("group") + 1]) if "group" in tokens and tokens.index("group") + 1 < len(tokens) else ""
            row["credential"] = "password"
            hashed = next((t for t in tokens if t in ("sha1", "sha256", "plaintext")), "")
            row["storage"], row["strength"] = {"sha256": ("SHA-256 hash", "ok"), "sha1": ("SHA-1 hash", "weak"), "plaintext": ("clear text", "weak")}.get(hashed, ("hash type not shown", "unknown"))
            rows.append(row)
    return rows


READERS = {"cisco": _cisco, "huawei": _huawei, "aoscx": _aoscx, "aruba": _aruba}


def extract(clean: list[str], family: str, config_present: bool) -> dict[str, Any]:
    """``{"captured", "rows", "summary"}``; ``captured`` is False when the capture has no configuration (then "none" would be a guess)."""
    reader = READERS.get(family)
    stripped = [line.strip() for line in clean]
    rows = reader(stripped) if reader else []
    config_present = config_present or bool(rows)            # account lines are configuration, even in a fragment the baseline check does not call a configuration
    weak = sum(1 for r in rows if r["strength"] in ("weak", "none"))
    if not reader:
        text = "Local users are read for Cisco, Huawei and Aruba switches."
    elif not config_present:
        text = "Not in this capture: it holds no configuration. Add the running configuration to see the local users."
    elif rows:
        text = f"{len(rows)} local user account(s) configured" + (f", {weak} with a weak or missing password" if weak else "") + "."
    else:
        text = "No local user is configured on this device (logins use a central server, line passwords or the platform default)."
    return {"captured": bool(reader and config_present), "rows": rows,
            "summary": {"count": len(rows), "weak": weak, "text": text}}
