"""Hide credential values in a converted configuration.

The converter keeps password hashes, SNMP community names and shared keys visible by default: the migration engineer needs them to paste a
working configuration or to compare with the source (the Huawei local-user block says so in its own comment).  That also makes the output a
credential file, so the Convert pages offer "Hide passwords and keys in the output".  When it is on, every value this module recognises is
replaced by ``<hidden>`` in the output, in two ways that cover each other:

* a set of command patterns (``secret 9 X``, ``cipher X``, ``key 7 X``, ``snmp-server community X`` ...) applied to each output line, and
* the same patterns applied to the *source*, which gives the exact values; any other place the translator copied one of them into (a REVIEW
  comment, a pass-through line, a different command) is hidden too.

Vendor references for the syntax the patterns follow:
Cisco IOS XE password types https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-usr-cfg-xe-16-book/sec-cfg-pw-privilege.html ;
Huawei VRP ``cipher`` / ``irreversible-cipher`` keywords https://support.huawei.com/enterprise/en/doc/EDOC1100333463 ;
Aruba AOS-S ``password manager`` / ``radius-server key`` and AOS-CX ``password ciphertext`` https://arubanetworking.hpe.com/techdocs/AOS-CX/10.14/HTML/security_6200/ .
"""

from __future__ import annotations

import re

HIDDEN = "<hidden>"

# The value is the group named ``val``.  A value may be quoted ("...").  ``_TYPE`` is the optional Cisco type digit or an Aruba/Huawei keyword.
_V = r"""["']?(?P<val>[^\s"']+)["']?"""
_TYPE = r"(?:(?:[0-9]|cipher|irreversible-cipher|simple|plain(?:text)?|ciphertext|encrypted|sha1|sha256|md5)\s+)?"

_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        # enable secret|password [type] X
        rf"\benable\s+(?:secret|password)\s+(?:[0-9]\s+)?{_V}",
        # username X ... secret|password [type] X, line password, local-user ... password [cipher] X, AOS-CX "password ciphertext X"
        rf"(?<![\w-])(?:secret|password)\s+{_TYPE}{_V}",
        # AOS-S: password manager|operator user-name "X" [sha1] HASH
        rf"(?<![\w-])password\s+(?:manager|operator)\s+user-name\s+\S+\s+{_TYPE}{_V}",
        # Huawei: ... cipher X / irreversible-cipher X (community, shared-key, usm-user keys, ospf key, vty password, trap securityname)
        rf"\b(?:irreversible-)?cipher\s+{_V}",
        # key [type] X (tacacs / radius server blocks, radius-server host ... key X, AOS-CX "key ciphertext X")
        rf"(?<![\w-])key\s+{_TYPE}{_V}",
        rf"\b(?:shared-key|key-string|pre-shared-key|psk|passphrase|authentication-key|send-secret|receive-secret)\s+{_TYPE}{_V}",
        # md5 [type] X (ospf message-digest-key, ntp authentication-key, authentication-mode md5 N cipher X is caught above)
        rf"\bmd5\s+(?:[0-9]\s+)?{_V}",
        # SNMP communities and trap receivers
        rf"\bsnmp-server\s+community\s+{_V}",
        rf"\bsnmp-agent\s+community\s+(?:read|write)\s+(?:(?:cipher|irreversible-cipher)\s+)?{_V}",
        rf"\bsnmp-server\s+host\s+\S+\s+(?:(?:traps|informs)\s+)?version\s+(?:1|2c)\s+{_V}",
        rf"\bsnmp-server\s+host\s+\S+\s+community\s+{_V}",
        rf"\bsecurityname\s+(?:cipher\s+)?{_V}",
        # SNMPv3 users: auth sha X priv aes [128] X
        rf"\bauth(?:entication)?\s+(?:md5|sha\d*|sha-?\d+)\s+{_V}",
        rf"\bpriv(?:acy)?\s+(?:des|3des|aes(?:\s*\d+)?)\s+{_V}",
        # lines this converter writes itself to carry the source value
        rf"#\s*SOURCE-PASSWORD\s+\S+:\s+{_V}",
        rf"REVIEW-PASSWORD-HASH\s+\S+:\s+.*?\btype\s+\d+\s+{_V}",
    )
)

# Words that follow the patterns above but are keywords, never a value.
_KEYWORDS = frozenset(
    {"chain", "config-key", "cipher", "irreversible-cipher", "simple", "plain", "plaintext", "ciphertext", "encrypted", "md5", "sha1", "sha256",
     "sha", "none", "disable", "enable", "required", "optional", "read", "write", "manager", "operator", "user-name", "type", "mode", "local",
     "login", "aes", "des", "3des", "priv", "auth", "hmac", "encryption", "authentication", "password", "secret", "key", "level", "group"}
)


def _is_value(value: str, comment: bool = False) -> bool:
    """``comment``: the line is a comment, where "the encrypted key must be entered again" is prose; a plain lower-case word there is not taken for a value
    (the source sweep still hides the real value wherever it appears)."""
    low = value.lower()
    if not value or low in _KEYWORDS or (value.startswith("<") and value.endswith(">")) or low.startswith("review-"):  # <hidden> and the converter's own placeholders
        return False
    if comment and re.fullmatch(r"[a-z]+", value):
        return False
    if re.fullmatch(r"[0-9]{1,2}", value):  # a key id or a type digit, not a secret
        return False
    return True


def source_values(source_text: str) -> set[str]:
    """Every credential value the patterns find in the source configuration (at least 4 characters)."""
    found: set[str] = set()
    for line in str(source_text or "").splitlines():
        for pattern in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.group("val")
                if _is_value(value) and len(value) >= 4:
                    found.add(value)
    return found


_FREE_TEXT = ("description ", "remark ", "name ", "alias ", "location ", "contact ")


def mask_line(line: str) -> str:
    """One output line with every recognised credential value replaced by ``<hidden>``."""
    out = str(line)
    if out.strip().lower().startswith(_FREE_TEXT):  # a text field may say "password" without holding one
        return out
    comment = _is_comment(out)

    def hide(match: re.Match[str]) -> str:
        if not _is_value(match.group("val"), comment):
            return match.group(0)
        start = match.start()
        return match.group(0)[: match.start("val") - start] + HIDDEN + match.group(0)[match.end("val") - start:]

    for pattern in _PATTERNS:
        out = pattern.sub(hide, out)
    return out


def _is_comment(line: str) -> bool:
    return str(line).lstrip().startswith(("#", "!", ";"))


def has_secret(line: str) -> bool:
    if str(line).strip().lower().startswith(_FREE_TEXT):
        return False
    comment = _is_comment(line)
    return any(_is_value(m.group("val"), comment) for pattern in _PATTERNS for m in pattern.finditer(str(line)))


def count_secret_lines(output_text: str) -> int:
    """How many output lines carry a credential value (before hiding)."""
    return sum(1 for line in str(output_text or "").splitlines() if has_secret(line))


def hide_secrets(output_text: str, source_text: str = "") -> str:
    """``output_text`` with credential values hidden (see the module docstring)."""
    values = sorted(source_values(source_text), key=len, reverse=True)
    lines = []
    for line in str(output_text or "").split("\n"):
        masked = mask_line(line)
        for value in values:
            if value in masked:
                masked = masked.replace(value, HIDDEN)
        lines.append(masked)
    return "\n".join(lines)
