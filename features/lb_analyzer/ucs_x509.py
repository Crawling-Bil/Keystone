"""Minimal X.509 reader (standard library only) for the certificates inside a UCS file store.

The sandbox and many customer servers do not have ``cryptography`` installed, and the analyzer only needs
subject, issuer, validity, key type/size, signature algorithm, subject alternative names and the CA flag, so a small
DER walker is enough.  Anything that does not parse returns ``None`` and is simply skipped; nothing here can raise.
"""

from __future__ import annotations

import base64
import re
from datetime import date, datetime, timezone
from typing import Any

_OIDS = {
    "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C",
    "1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521", "1.3.101.112": "Ed25519",
}
WEAK_SIGNATURES = ("md5", "sha1")


def _tlv(data: bytes, pos: int) -> tuple[int, int, int, int]:
    """(tag, header_end, value_end, next) for the element at ``pos``."""
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("bad length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("truncated")
    return tag, pos, end, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, pos = [], start
    while pos < end:
        tag, vstart, vend, nxt = _tlv(data, pos)
        out.append((tag, vstart, vend))
        pos = nxt
    return out


def _oid(data: bytes, start: int, end: int) -> str:
    first = data[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in data[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _name(data: bytes, start: int, end: int) -> dict[str, str]:
    out: dict[str, str] = {}
    for _tag, s, e in _children(data, start, end):                       # RDN SET
        for _t2, s2, e2 in _children(data, s, e):                        # AttributeTypeAndValue SEQ
            parts = _children(data, s2, e2)
            if len(parts) >= 2:
                label = _OIDS.get(_oid(data, parts[0][1], parts[0][2]), "")
                if label and label not in out:
                    out[label] = data[parts[1][1]:parts[1][2]].decode("utf-8", errors="replace")
    return out


def _time(data: bytes, tag: int, start: int, end: int) -> date | None:
    text = data[start:end].decode("ascii", errors="ignore")
    try:
        if tag == 0x17:                                                  # UTCTime YYMMDDHHMMSSZ
            year = int(text[:2])
            return date(2000 + year if year < 50 else 1900 + year, int(text[2:4]), int(text[4:6]))
        return date(int(text[:4]), int(text[4:6]), int(text[6:8]))      # GeneralizedTime
    except ValueError:
        return None


def parse_certificate(raw: bytes) -> dict[str, Any] | None:
    """Subject, issuer, validity, key and signature algorithm of the first certificate in a PEM or DER file.

    Returns None when the file is not a certificate (empty placeholder, key, bundle without a readable first cert)."""
    try:
        text = raw.decode("ascii", errors="ignore")
        match = re.search(r"-----BEGIN (?:TRUSTED )?CERTIFICATE-----(.+?)-----END (?:TRUSTED )?CERTIFICATE-----", text, re.S)
        der = base64.b64decode("".join(match.group(1).split())) if match else (raw if raw[:1] == b"\x30" else b"")
        if not der:
            return None
        _t, vs, ve, _n = _tlv(der, 0)
        cert = _children(der, vs, ve)
        tbs = _children(der, cert[0][1], cert[0][2])
        index = 1 if tbs[0][0] == 0xA0 else 0                           # skip [0] version
        sig_alg = _oid(der, *_children(der, cert[1][1], cert[1][2])[0][1:])
        issuer = _name(der, tbs[index + 2][1], tbs[index + 2][2])
        validity = _children(der, tbs[index + 3][1], tbs[index + 3][2])
        not_before = _time(der, validity[0][0], validity[0][1], validity[0][2])
        not_after = _time(der, validity[1][0], validity[1][1], validity[1][2])
        subject = _name(der, tbs[index + 4][1], tbs[index + 4][2])
        spki = _children(der, tbs[index + 5][1], tbs[index + 5][2])
        alg_parts = _children(der, spki[0][1], spki[0][2])
        key_oid = _oid(der, alg_parts[0][1], alg_parts[0][2])
        key_type, key_size = _OIDS.get(key_oid, key_oid), None
        if key_oid == "1.2.840.113549.1.1.1":
            bits = der[spki[1][1] + 1:spki[1][2]]                       # skip unused-bits byte
            rsa = _children(bits, *_children(bits, 0, len(bits))[0][1:])
            modulus = bits[rsa[0][1]:rsa[0][2]].lstrip(b"\x00")
            key_type, key_size = "RSA", len(modulus) * 8
        elif key_oid == "1.2.840.10045.2.1" and len(alg_parts) > 1 and alg_parts[1][0] == 0x06:
            curve = _OIDS.get(_oid(der, alg_parts[1][1], alg_parts[1][2]), "")
            key_type, key_size = "EC", {"P-256": 256, "P-384": 384, "P-521": 521}.get(curve)
        sans: list[str] = []
        is_ca = None
        for tag, s, e in tbs[index + 6:]:
            if tag != 0xA3:
                continue
            for _t3, s3, e3 in _children(der, *_children(der, s, e)[0][1:]):    # extensions SEQ OF SEQ
                ext = _children(der, s3, e3)
                ext_oid = _oid(der, ext[0][1], ext[0][2])
                value = ext[-1]
                if ext_oid == "2.5.29.17":                                       # subjectAltName
                    inner = der[value[1]:value[2]]
                    for gtag, gs, ge in _children(inner, *_children(inner, 0, len(inner))[0][1:]):
                        if gtag == 0x82:
                            sans.append(inner[gs:ge].decode("ascii", errors="replace"))
                elif ext_oid == "2.5.29.19":                                     # basicConstraints
                    inner = der[value[1]:value[2]]
                    fields = _children(inner, *_children(inner, 0, len(inner))[0][1:])
                    is_ca = bool(fields and fields[0][0] == 0x01 and inner[fields[0][1]] != 0)
        return {
            "subject": _dn(subject), "issuer": _dn(issuer), "cn": subject.get("CN", ""), "issuer_cn": issuer.get("CN", ""), "not_before": not_before, "not_after": not_after,
            "key_type": key_type, "key_size": key_size, "signature": _OIDS.get(sig_alg, sig_alg), "san": sans, "ca": is_ca, "self_signed": bool(subject) and subject == issuer,
        }
    except (ValueError, IndexError, KeyError, TypeError):
        return None


def _dn(parts: dict[str, str]) -> str:
    return ", ".join(f"{k}={parts[k]}" for k in ("CN", "OU", "O", "C") if k in parts)


def days_until(when: date | None, today: date | None = None) -> int | None:
    return None if when is None else (when - (today or datetime.now(timezone.utc).date())).days
