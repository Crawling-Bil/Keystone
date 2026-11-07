"""The source pane of the firewall converter without the credentials of the uploaded file.

The converters never write a password hash, pre-shared key, SNMP community or private key into their output, but the page also shows the file that was
uploaded.  A firewall export is full of them, so the pane shows the file with every credential value replaced by ``<hidden>``:

* PAN-OS XML: the credential leaves are removed with the same rule the Panorama reader uses (:func:`features.firewall_analyzer.panorama_parse.strip_secrets`),
  SNMPv3 ``authpwd`` / ``privpwd`` and ``phash`` included;
* PAN-OS ``set`` and curly views and FortiOS ``show`` output: the value after ``password``, ``passwd``, ``phash``, ``psksecret``, ``pre-shared-key``,
  ``secret``, ``passphrase``, ``authpwd``, ``privpwd``, ``snmp-community`` ... and the body of a PEM block.

Only the display is masked; what the converter reads is untouched.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

HIDDEN = "<hidden>"

_WORDS = (r"password|passwd|phash|psksecret|pre-shared-key|secret|passphrase|authpwd|privpwd|auth-password|priv-password|snmp-community|community-string|"
          r"api-key|auth-key|private-key|shared-secret|md5-key|key-chain-key")
_LINE = re.compile(rf"(?P<head>(?:^|[\s;{{])(?:{_WORDS})\s+(?:ENC\s+|ciphertext\s+|encrypted\s+)?(?:[{{]\s*key\s+|key\s+)?)(?P<val>\"[^\"]*\"|[^\s;\"]+)", re.IGNORECASE)
_PEM = re.compile(r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----", re.DOTALL)
_NOT_A_VALUE = re.compile(r"^(?:yes|no|enable|disable|enabled|disabled|\d{1,3}|ENC|none|any)$", re.IGNORECASE)
_XML_LEAF = re.compile(rf"<(?P<tag>[A-Za-z0-9_-]*(?:{_WORDS})[A-Za-z0-9_-]*)>(?P<val>[^<]{{3,}})</(?P=tag)>", re.IGNORECASE)


def _line(match: re.Match[str]) -> str:
    value = match.group("val")
    if _NOT_A_VALUE.match(value.strip('"')):
        return match.group(0)
    return match.group("head") + (f'"{HIDDEN}"' if value.startswith('"') else HIDDEN)


def mask_source(text: str) -> str:
    """``text`` with its credential values hidden (the display copy; never the conversion input)."""
    if not text:
        return text
    stripped = text.lstrip()
    if stripped.startswith("<"):
        try:
            from features.firewall_analyzer import panorama_parse as pp
            root = ET.fromstring(stripped)
            pp.strip_secrets(root)
            body = ET.tostring(root, encoding="unicode")
            return body
        except ET.ParseError:
            masked = _XML_LEAF.sub(lambda m: f"<{m.group('tag')}>{HIDDEN}</{m.group('tag')}>", text)
            return _PEM.sub(HIDDEN, masked)
    text = _PEM.sub(HIDDEN, text)
    out: list[str] = []
    in_key_block = False
    for ln in text.split("\n"):
        if in_key_block and re.match(r"^\s*key\s+\S", ln):
            ln = re.sub(r"(key\s+)[^\s;]+", rf"\g<1>{HIDDEN}", ln, count=1)       # curly view: "pre-shared-key {" and the key on the next line
        in_key_block = bool(re.search(r"(?:pre-shared-key|shared-secret|authentication-key)\s*\{\s*$", ln))
        out.append(_LINE.sub(_line, ln))
    return "\n".join(out)
