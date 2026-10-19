"""Structural checks on the CONVERTED configuration (what is about to be pasted onto the target).

These run on the output text of a switch conversion, per target vendor, and report problems that the line-by-line translators cannot see
because each one only looks at one source command:

* ``CHK-ACL-DUPLICATE``   the same rule appears more than once in one ACL (typically an object-group expansion that overlapped);
* ``CHK-ACL-PERMIT-ALL``  an ACL contains an unconditional ``permit`` - rules below it can never match;
* ``CHK-ACL-NO-DENY``     an ACL has rules but no ``deny`` rule, so what happens to unmatched traffic is decided by the platform default,
                          which differs between vendors and must be confirmed on the target;
* ``CHK-LAG-EMPTY``       an Eth-Trunk / LAG / Port-channel is defined but no interface is a member of it.

The checks are text-only on purpose: they are meant to run on the exact bytes the engineer will paste.
"""
from __future__ import annotations

import re

_NUM = re.compile(r"^\d+\s+")
_ANY_WORDS = {"any", "ip", "source", "destination"}


def _acl_blocks(lines: list[str], vendor: str):
    """Yield ``(name, [rule body, ...])``; the rule body has its sequence number removed."""
    vendor = vendor.lower()
    start = {
        "huawei": re.compile(r"^acl\s+(?:name\s+(\S+)|number\s+(\d+))"),
        "aruba": re.compile(r"^access-list\s+ip\s+(\S+)"),
        "cisco": re.compile(r"^ip\s+access-list\s+(?:(?:standard|extended)\s+)?(\S+)"),
    }.get(vendor)
    if start is None:
        return
    name, rules = None, []
    for raw in lines:
        text = raw.rstrip()
        match = start.match(text)
        if match:
            if name is not None:
                yield name, rules
            name, rules = next(g for g in match.groups() if g), []
            continue
        if name is None:
            continue
        stripped = text.strip()
        if vendor == "huawei":
            if stripped == "#" or (text and not text[0].isspace() and not stripped.startswith("# ")):
                yield name, rules
                name, rules = None, []
                continue
            if stripped.startswith("rule "):
                rules.append(_NUM.sub("", stripped[5:], count=1))
        else:
            if text and not text[0].isspace():
                yield name, rules
                name, rules = None, []
                continue
            body = _NUM.sub("", stripped, count=1)
            if body.startswith(("permit ", "deny ")) or body in ("permit", "deny"):
                rules.append(body)
    if name is not None:
        yield name, rules


def _is_permit_all(rule: str) -> bool:
    words = rule.replace(" log", "").split()
    if not words or words[0] != "permit":
        return False
    rest = words[1:]
    if not rest or rest == ["ip"]:               # Huawei "rule N permit" with no match condition
        return True
    return "any" in rest and all(w in _ANY_WORDS for w in rest)


def _lag_checks(lines: list[str], vendor: str):
    vendor = vendor.lower()
    if vendor == "huawei":
        defined = re.compile(r"^interface\s+Eth-Trunk(\d+)\s*$", re.I)
        member = re.compile(r"^\s+eth-trunk\s+(\d+)\s*$", re.I)
        label = "Eth-Trunk"
    elif vendor == "aruba":
        defined = re.compile(r"^interface\s+lag\s+(\d+)(?:\s+multi-chassis)?\s*$", re.I)
        member = re.compile(r"^\s+lag\s+(\d+)\s*$", re.I)
        label = "lag"
    elif vendor == "cisco":
        defined = re.compile(r"^interface\s+Port-channel(\d+)\s*$", re.I)
        member = re.compile(r"^\s+channel-group\s+(\d+)\b", re.I)
        label = "Port-channel"
    else:
        return
    ids, used = [], set()
    for line in lines:
        m = defined.match(line)
        if m:
            ids.append(m.group(1))
            continue
        m = member.match(line)
        if m:
            used.add(m.group(1))
    for lag in ids:
        if lag not in used:
            yield f"{label} {lag}"


def check_output(output_text: str, target_vendor: str) -> list[dict]:
    """All structural findings for one converted switch configuration, in a stable order."""
    lines = output_text.splitlines()
    findings: list[dict] = []
    for name, rules in _acl_blocks(lines, target_vendor):
        seen: dict[str, int] = {}
        for rule in rules:
            seen[rule] = seen.get(rule, 0) + 1
        duplicates = sum(count - 1 for count in seen.values() if count > 1)
        if duplicates:
            findings.append({
                "code": "CHK-ACL-DUPLICATE", "subject": f"ACL {name}",
                "message": f"{duplicates} duplicate rule(s); object-group expansion can repeat a rule - remove the repeats to save ACL resources",
            })
        permit_all = next((i for i, rule in enumerate(rules) if _is_permit_all(rule)), None)
        if permit_all is not None:
            below = len(rules) - permit_all - 1
            findings.append({
                "code": "CHK-ACL-PERMIT-ALL", "subject": f"ACL {name}",
                "message": "contains an unconditional permit" + (f"; the {below} rule(s) after it can never match" if below else ""),
            })
        elif rules and not any(rule.split()[0] == "deny" for rule in rules):
            findings.append({
                "code": "CHK-ACL-NO-DENY", "subject": f"ACL {name}",
                "message": "has no deny rule; confirm what the target does with traffic that matches no rule before relying on this ACL",
            })
    for subject in _lag_checks(lines, target_vendor):
        findings.append({
            "code": "CHK-LAG-EMPTY", "subject": subject,
            "message": "is defined but no interface is a member of it (members may be on another stack member, a module or a port that was not converted)",
        })
    return findings
