"""Mask a raw device capture before any part of it is copied into this repository.

Real captures contain hostnames, management IPs, MAC addresses, serial
numbers and sometimes credentials. Those files stay on the engineer's own
machine. What is committed are small, masked excerpts that keep the exact
column layout of the real output, so a parser regression test still
exercises the real format.

What the masking guarantees
  * Hostnames (taken from CLI prompts and from hostname/System Name/Device ID
    fields) are replaced by a deterministic pseudonym of the SAME LENGTH,
    character class for character class (upper, lower, digit; punctuation is
    kept). Cisco truncates long LLDP/CDP Device IDs to a fixed column width,
    so prefixes of a known name (8 characters or more) are replaced
    consistently with the matching prefix of the pseudonym.
  * MAC addresses keep their notation and length (aabb.ccdd.eeff,
    aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb-ccdd-eeff and the ArubaOS-Switch
    form aabbcc-ddeeff).
  * IPv6 addresses (link-local ones embed the interface MAC) keep their notation
    and length, hex digits replaced.
  * IPv4 addresses are mapped one-to-one into 10.255.0.0/16. Subnet masks and
    wildcard masks are left alone.
  * Serial numbers (`Serial Number:`, `SN:`, `Processor board ID`, Huawei
    `Equipment SN(ESN):`, `BarCode=` and the SN column of `display device elabel
    brief`) and anything that follows password/secret/community/key keywords are
    replaced, including IPsec pre-shared keys (`crypto isakmp key KEY address ...`
    and IKEv2 `pre-shared-key local|remote KEY`), which are also checked again
    after masking.
  * After masking, the script re-scans the output and refuses to write it if
    any original hostname, IP, MAC or serial number is still present.

The salt is fixed on purpose: masking the same capture twice gives the same
fixture, so a re-generated fixture produces no diff.

Usage
  python mask_capture.py RAW.txt OUT.txt --extract "show vlan brief" \
      --extract "show lldp neighbors" [--name EXTRA_NAME ...]

--name masks extra words you know are sensitive, for example site codes that
appear inside VLAN names or interface descriptions.
--extract copies only the output of that command (from its prompt line to the
next prompt line). Without --extract the whole file is masked.
Never commit RAW.txt.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

SALT = "keystone-fixture-v1"

PROMPT_RE = re.compile(
    r"^(?:<(?P<h1>[^<>\s]+)>|\[(?P<h2>[^\[\]\s]+)\]|(?P<h3>[A-Za-z0-9_.\-]+)(?:\(config[^)]*\))?[#>])\s*(?P<cmd>\S.*)?$"
)
NAME_FIELD_RES = [
    re.compile(r"^\s*(?:System Name|Device ID|SysName|Sysname|sysname|hostname)\s*[:\s]\s*(\S+)\s*$"),
    # ArubaOS-Switch `show system`: free text that names the site and a person's extension.
    re.compile(r"^\s*System (?:Contact|Location)\s*:\s*(\S.*?)\s*$"),
]
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
MAC_RES = [
    re.compile(r"\b[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\b"),
    re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),
    re.compile(r"\b(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}\b"),
    re.compile(r"\b[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}\b"),
    # ArubaOS-Switch prints aabbcc-ddeeff. It was missing here, so real Aruba MACs
    # reached two committed fixtures; verify() could not catch it either because it
    # only re-scans for the patterns it knows.
    re.compile(r"\b[0-9a-fA-F]{6}-[0-9a-fA-F]{6}\b"),
]
SERIAL_RE = re.compile(r"(?i)((?:serial\s*(?:number|no\.?)?|\bSN)\s*[:=]\s*)(\S+)")
# "Processor board ID FOC0000ABCD" is the chassis serial on IOS/IOS-XE `show version`: no colon, no "serial" word.
BOARD_ID_RE = re.compile(r"(?i)(\bprocessor\s+board\s+id\s+)(\S+)")
# Huawei: "Equipment SN(ESN): 4E26..." / "License ESN: --" and the barcode of `display device elabel`.
ESN_RE = re.compile(r"(?i)(\b(?:equipment\s+SN\s*\(ESN\)|license\s+ESN)\s*:\s*)(\S+)")
BARCODE_RE = re.compile(r"(?i)(\bBarCode\s*=\s*)(\S+)")
# `display device elabel brief`: SlotID Sub Type SN P/N  (the SN column is the unit's own serial)
ELABEL_HEADER_RE = re.compile(r"^\s*SlotID\s+Sub\s+Type\s+SN\b")
NO_SERIAL = {"n/a", "na", "none", "--", "-", "unknown"}
SECRET_RE = re.compile(
    r"(?i)(\b(?:password|secret|community|key-string|pre-shared-key|shared-key|cipher|auth-key)\s+(?:\d\s+)?)(?!(?:local|remote)\s)(\S+)"
)
# Pre-shared keys that SECRET_RE cannot see: IKEv1 `crypto isakmp key [type] KEY address|hostname X` (the word is only
# "key") and IKEv2 `pre-shared-key local|remote [type] KEY` (the first word after the keyword is a direction, not the key).
ISAKMP_KEY_RE = re.compile(r"(?i)(\bcrypto\s+isakmp\s+key\s+(?:\d\s+)?)(\S+)(?=\s+(?:address|hostname)\b)")
PSK_DIRECTION_RE = re.compile(r"(?i)(\bpre-shared-key\s+(?:local|remote)\s+(?:\d\s+)?)(\S+)")
IPV6_RE = re.compile(r"(?<![0-9A-Za-z:])[0-9A-Fa-f]{1,4}(?::{1,2}[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Za-z:])")
CLOCK_RE = re.compile(r"\d{1,2}:\d{2}(?::\d{2})?")
# Words that show up as a "name" field on some devices (a neighbor that kept its
# factory hostname) but are also ordinary words in output we want to keep intact.
COMMON_WORDS = {"switch", "router", "default", "localhost", "cisco", "huawei", "aruba", "linux", "unknown", "none"}
# Hardware labels that look like a bracketed Huawei prompt (`[PWR1]` is a section header of
# `display device`, not a CLI prompt). Taken for hostnames they were replaced by a
# pseudonym everywhere, which rewrote the Sub column of `display device elabel brief`
# (FAN1 -> GJI6) and hid which sub-row is a power supply.
HARDWARE_LABEL_RE = re.compile(r"(?i)(?:FAN|PWR|PSU|PAC|PDC|MPU|LPU|SFU|CPU|CARD|SLOT|MODULE)[-_ ]?\d*")
MASK_OCTETS = {"0", "255", "254", "252", "248", "240", "224", "192", "128"}


def _digest(text: str, index: int) -> int:
    return int(hashlib.sha256(f"{SALT}:{text}:{index}".encode()).hexdigest()[:8], 16)


def pseudonym(token: str) -> str:
    """Same length, same character classes, deterministic."""
    out = []
    for index, char in enumerate(token):
        value = _digest(token, index)
        if char.isupper():
            out.append(chr(65 + value % 26))
        elif char.islower():
            out.append(chr(97 + value % 26))
        elif char.isdigit():
            out.append(str(value % 10))
        else:
            out.append(char)
    return "".join(out)


def _mask_hex(match: re.Match) -> str:
    text = match.group(0)
    out = []
    for index, char in enumerate(text):
        out.append("0123456789abcdef"[_digest(text.lower(), index) % 16] if char in "0123456789abcdefABCDEF" else char)
    return "".join(out)


def _mask_v6(match: re.Match) -> str:
    # 14:02:40 / 00:05:47 (a clock or an NX-OS ARP age) has the shape of a short
    # IPv6 address but is not one; masking it would destroy the layout the
    # fixture exists to preserve (session-log timestamps, ARP ages).
    if CLOCK_RE.fullmatch(match.group(0)):
        return match.group(0)
    return _mask_hex(match)


def _serial(value: str, originals: dict[str, set[str]]) -> str:
    """Pseudonym of a serial number; the original is remembered so verify() can
    prove it is gone. Placeholders such as N/A are not serial numbers."""
    if value.lower() in NO_SERIAL:
        return value
    originals["serials"].add(value)
    return pseudonym(value)


def _mask_elabel_row(line: str, originals: dict[str, set[str]]) -> str:
    """One data row of the elabel table, spacing preserved:
    ``1   --   S5735-S24T4XE-V2   4E26...   98012016-003``  (slot row, SN is word 4)
    ``    PWR1   PAC80S12-CN   2102000000USS0000001   02131835``  (sub-part row, SN is word 3)."""
    parts = re.split(r"(\s+)", line)
    index = [i for i, part in enumerate(parts) if part and not part.isspace()]
    words = [parts[i] for i in index]
    if len(words) >= 5 and words[0].isdigit():
        position = 3
    elif len(words) >= 4 and re.fullmatch(r"(?i)(?:PWR|FAN)\d*", words[0]):
        position = 2
    else:
        return line
    parts[index[position]] = _serial(parts[index[position]], originals)
    return "".join(parts)


def split_blocks(lines: list[str]) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for line in lines:
        match = PROMPT_RE.match(line.rstrip())
        if match and match.group("cmd") and not line.startswith(" "):
            current = (match.group("cmd").strip(), [line])
            blocks.append(current)
        elif current is not None:
            current[1].append(line)
    return blocks


def collect_names(lines: list[str], extra: list[str]) -> set[str]:
    names: set[str] = set()
    for line in lines:
        match = PROMPT_RE.match(line.rstrip())
        if match and not line.startswith(" "):
            names.add(match.group("h1") or match.group("h2") or match.group("h3"))
        for pattern in NAME_FIELD_RES:
            field = pattern.match(line)
            if field:
                names.add(field.group(1))
    auto = {
        name for name in names
        if name and len(name) >= 4 and name.lower() not in COMMON_WORDS and not HARDWARE_LABEL_RE.fullmatch(name)
    }
    # --name values are the engineer's own list (site codes, customer names) and
    # are masked even when short.
    return auto | {name for name in extra if name}


def build_name_map(names: set[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for name in names:
        fake = pseudonym(name)
        mapping[name] = fake
        # Cisco LLDP/CDP brief tables cut long Device IDs at a fixed width.
        for cut in range(len(name) - 1, 7, -1):
            mapping.setdefault(name[:cut], fake[:cut])
    return mapping


def mask(text: str, extra_names: list[str]) -> tuple[str, dict[str, set[str]]]:
    lines = text.splitlines()
    names = collect_names(lines, extra_names)
    name_map = build_name_map(names)
    originals = {"names": set(names), "ips": set(), "macs": set(), "serials": set(), "secrets": set()}

    def _psk(match: re.Match) -> str:
        originals["secrets"].add(match.group(2))
        return match.group(1) + "<REDACTED>"

    ip_map: dict[str, str] = {}

    def _ip(match: re.Match) -> str:
        value = match.group(1)
        octets = value.split(".")
        if any(int(o) > 255 for o in octets) or all(o in MASK_OCTETS for o in octets):
            return value
        originals["ips"].add(value)
        if value not in ip_map:
            serial = len(ip_map) + 1
            ip_map[value] = f"10.255.{serial // 256}.{serial % 256}"
        return ip_map[value]

    lower_map = {key.lower(): value for key, value in name_map.items()}
    ordered = sorted(name_map, key=len, reverse=True)
    name_re = re.compile(
        r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in ordered) + r")", re.IGNORECASE
    ) if ordered else None

    masked_lines = []
    in_elabel = False
    for line in lines:
        line = PSK_DIRECTION_RE.sub(_psk, ISAKMP_KEY_RE.sub(_psk, line))   # first: the IPv6/MAC patterns below would otherwise rewrite part of a key
        if ELABEL_HEADER_RE.match(line):
            in_elabel = True
        elif PROMPT_RE.match(line.rstrip()) and not line.startswith(" "):
            in_elabel = False
        elif in_elabel:
            line = _mask_elabel_row(line, originals)
        for found in IPV6_RE.findall(line):
            if not CLOCK_RE.fullmatch(found):
                originals["macs"].add(found.lower())
        line = IPV6_RE.sub(_mask_v6, line)
        for pattern in MAC_RES:
            for found in pattern.findall(line):
                originals["macs"].add(found.lower())
            line = pattern.sub(_mask_hex, line)
        for serial_re in (SERIAL_RE, BOARD_ID_RE, ESN_RE, BARCODE_RE):
            line = serial_re.sub(lambda m: m.group(1) + _serial(m.group(2), originals), line)
        line = SECRET_RE.sub(lambda m: m.group(1) + "<REDACTED>", line)
        line = IPV4_RE.sub(_ip, line)
        if name_re:
            line = name_re.sub(lambda m: lower_map[m.group(1).lower()], line)
        masked_lines.append(line)
    return "\n".join(masked_lines) + "\n", originals


def verify(masked: str, originals: dict[str, set[str]]) -> list[str]:
    leaks = []
    low = masked.lower()
    for kind in ("names", "ips", "macs", "serials", "secrets"):
        for value in originals.get(kind, ()):
            if value.lower() in low:
                leaks.append("secret still present (value not printed)" if kind == "secrets" else f"{kind[:-1]} still present: {value}")
    return leaks


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("raw", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--extract", action="append", default=[], help="command whose output to keep")
    parser.add_argument("--name", action="append", default=[], help="extra hostname/neighbor name to mask")
    args = parser.parse_args(argv)

    text = args.raw.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    if args.extract:
        blocks = split_blocks(lines)
        kept: list[str] = []
        for wanted in args.extract:
            matches = [b for b in blocks if b[0].lower() == wanted.lower()]
            if not matches:
                print(f"command not found in capture: {wanted}", file=sys.stderr)
                return 2
            kept.extend(matches[0][1])
        # Names must be collected from the WHOLE capture so a neighbor name that
        # only appears elsewhere in the file is still treated as a name.
        masked, originals = mask("\n".join(lines), args.name)
        name_set = originals["names"]
        masked, originals = mask("\n".join(kept), sorted(name_set))
    else:
        masked, originals = mask(text, args.name)
    leaks = verify(masked, originals)
    if leaks:
        print("refusing to write, masking incomplete:\n  " + "\n  ".join(leaks), file=sys.stderr)
        return 3
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(masked, encoding="utf-8")
    print(f"wrote {args.out} ({len(masked.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
