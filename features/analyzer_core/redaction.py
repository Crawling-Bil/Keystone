"""Secret handling for analyzer output.

Rule for every analyzer: a credential value never reaches the browser, the
Excel export, a log line or a finding.  Parsers keep only the *kind* and
*strength* of a secret ("enable secret: type 5 / MD5-crypt") so reviewers can
judge hygiene without the analyzer becoming a credential leak.

``redact_line`` is the safety net for any code path that has to show a raw
configuration line (for example an "other / unparsed" table).
"""

from __future__ import annotations

import re

HIDDEN = "<hidden>"

# Cisco IOS password/secret types.  See "Configuring Security with Passwords,
# Privilege Levels, and Login Usernames" in the Cisco IOS XE Security
# Configuration Guide: type 0 clear text, 5 MD5, 7 Vigenere (reversible),
# 8 PBKDF2-SHA256, 9 scrypt.
CISCO_SECRET_TYPES = {
    "0": ("clear text", "weak"),
    "5": ("MD5-crypt", "weak"),
    "6": ("AES-reversible (type 6, keyed)", "ok"),
    "7": ("Vigenere (reversible)", "weak"),
    "8": ("PBKDF2-SHA256", "strong"),
    "9": ("scrypt", "strong"),
}


def secret_strength(type_code: str | None) -> tuple[str, str]:
    """Return (human description, strength class) for a Cisco secret type."""
    if type_code is None or type_code == "":
        return ("clear text (no type keyword)", "weak")
    return CISCO_SECRET_TYPES.get(str(type_code), (f"unknown type {type_code}", "unknown"))


# Each pattern keeps a group named ``keep`` (the context) and hides the rest.
_REDACTIONS: list[re.Pattern[str]] = [
    # <cmd> [0|5|6|7|8|9] <secret>
    re.compile(r"(?P<keep>\b(?:enable\s+(?:secret|password)|password|secret|key-string|key|pre-shared-key|authentication-key|"
               r"community|passphrase|psksecret|shared-secret|send-secret|receive-secret|encrypted-password)\s+(?:(?:[0-9]|ENC)\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # snmp-server community NAME RO
    re.compile(r"(?P<keep>\bsnmp-server\s+community\s+)(?P<val>\S+)", re.IGNORECASE),
    # crypto isakmp key NAME address ...
    re.compile(r"(?P<keep>\bcrypto\s+isakmp\s+key\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # username X ... password|secret [type] value   (handled by first pattern)
    # tacacs/radius key
    re.compile(r"(?P<keep>\b(?:tacacs-server|radius-server)\s+key\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # FortiOS: set password ENC xxxx / set psksecret ENC xxxx
    re.compile(r"(?P<keep>\bset\s+(?:password|psksecret|passwd|secret|key)\s+(?:ENC\s+)?)(?P<val>\S+)", re.IGNORECASE),
]


def redact_line(line: str) -> str:
    """Hide credential values in a single configuration line."""
    out = line
    for pattern in _REDACTIONS:
        out = pattern.sub(lambda m: m.group("keep") + HIDDEN, out)
    return out


def contains_secret(line: str) -> bool:
    return any(pattern.search(line) for pattern in _REDACTIONS)
