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
    # ip ospf message-digest-key <id> md5 [0|7] <key>, ntp authentication-key <id> md5 <key>
    re.compile(r"(?P<keep>\b(?:message-digest-key|authentication-key)\s+\d+\s+md5\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # <cmd> [0|5|6|7|8|9|cipher|irreversible-cipher|simple] <secret>   (the Huawei keyword is part of the command, the value follows it)
    re.compile(r"(?P<keep>\b(?:enable\s+(?:secret|password)|password|secret|key-string|(?<![\w-])key(?!\s+chain\b)|shared-key|pre-shared-key|authentication-key|"
               r"community(?!\s+(?:read|write)\b)|pass-?phrase|psksecret|shared-secret|send-secret|receive-secret|encrypted-password)\s+"
               r"(?:(?:[0-9]|ENC|(?:irreversible-)?cipher|simple|plain(?:text)?|ciphertext)\s+)?)(?![0-9]{1,2}(?:\s|$)|md5\b)(?P<val>\S+)", re.IGNORECASE),
    # Cisco WLC WLAN key: security wpa psk set-key ascii|hex [0|8] <key>
    re.compile(r"(?P<keep>\bpsk\s+set-key\s+(?:ascii|hex)\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # Huawei: anything written as `cipher <value>` (usm-user keys, ospf/ntp md5 key, vty password, trap securityname) and md5 keys
    re.compile(r"(?P<keep>\b(?:irreversible-)?cipher\s+)(?P<val>\S+)", re.IGNORECASE),
    re.compile(r"(?P<keep>\bmd5\s+(?:[0-9]\s+)?)(?!(?:irreversible-)?cipher\b|[0-9]+\b)(?P<val>\S+)", re.IGNORECASE),
    # snmp-server community NAME RO
    re.compile(r"(?P<keep>\bsnmp-server\s+community\s+)(?P<val>\S+)", re.IGNORECASE),
    # crypto isakmp key NAME address ...
    re.compile(r"(?P<keep>\bcrypto\s+isakmp\s+key\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # username X ... password|secret [type] value   (handled by first pattern)
    # tacacs/radius key
    re.compile(r"(?P<keep>\b(?:tacacs-server|radius-server)\s+key\s+(?:[0-9]\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # FortiOS: set password ENC xxxx / set psksecret ENC xxxx
    re.compile(r"(?P<keep>\bset\s+(?:password|psksecret|passwd|secret|key)\s+(?:ENC\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # Huawei VRP: snmp-agent community read|write [cipher|irreversible-cipher] NAME
    re.compile(r"(?P<keep>\bsnmp-agent\s+community\s+(?:read|write)\s+(?:(?:cipher|irreversible-cipher)\s+)?)(?P<val>\S+)", re.IGNORECASE),
    # SNMPv3 user keys: ... auth md5|sha|sha256 KEY priv des|aes [128] KEY
    re.compile(r"(?P<keep>\bauth\s+(?:md5|sha(?:-?\d+)?|sha\d+)\s+)(?P<val>\S+)", re.IGNORECASE),
    re.compile(r"(?P<keep>\bpriv\s+(?:des|3des|aes(?:\s*\d+)?|aes\d+)\s+)(?P<val>\S+)", re.IGNORECASE),
    # trap receivers carry a community: snmp-server host 10.1.1.5 [traps|informs] [version 1|2c] NAME
    re.compile(r"(?P<keep>\bsnmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?version\s+(?:1|2c)\s+)(?P<val>\S+)", re.IGNORECASE),
    re.compile(r"(?P<keep>\bsnmp-server\s+host\s+\S+\s+)(?!(?:traps|informs|version|vrf|udp-port|use-vrf)\b)(?P<val>\S+)", re.IGNORECASE),
]

# SNMP community names that are the vendor or textbook defaults. They are shown as they are because the finding is about the name itself
# ("the community is public"); any other name is a shared secret and is hidden.
GUESSABLE_COMMUNITIES = frozenset({"public", "private", "cisco", "test", "snmp", "snmpd", "default", "secret", "admin", "community", "manager", "monitor", "write", "read",
                                   "internal", "network", "ilmi", "cable-docsis", "manager", "openview", "snmp-read", "snmp-write"})


def mask_community(name: str) -> str:
    """A community name for the screen and the exports: a default name as it is, any other name hidden (its length is kept so a short one can be told from a long one)."""
    text = str(name or "").strip().strip('"')
    if text.lower() in GUESSABLE_COMMUNITIES:
        return text
    return f"{HIDDEN} ({len(text)} characters)"


def redact_snmp_line(line: str) -> str:
    """``redact_line`` for an ``snmp`` command, except that a default community name stays readable (see ``GUESSABLE_COMMUNITIES``)."""
    match = re.search(r"\b(?:snmp-server\s+community|snmp-agent\s+community\s+(?:read|write)(?:\s+(?:cipher|irreversible-cipher))?)\s+\"?([^\s\"]+)", str(line), re.IGNORECASE)
    if match and match.group(1).lower() in GUESSABLE_COMMUNITIES and "cipher" not in match.group(0).lower():
        return str(line)
    return redact_line(str(line))


def redact_line(line: str) -> str:
    """Hide credential values in a single configuration line."""
    out = line
    for pattern in _REDACTIONS:
        out = pattern.sub(lambda m: m.group("keep") + HIDDEN, out)
    return out


def contains_secret(line: str) -> bool:
    return any(pattern.search(line) for pattern in _REDACTIONS)
