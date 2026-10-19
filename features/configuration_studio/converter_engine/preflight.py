"""Pre-flight summary of one switch conversion: what is ready, what needs a person's decision, what was left out, and does the target fit.

Everything here is derived from the converted text itself (``REVIEW-<CODE>`` markers and the structural ``CHK-`` findings of
``postcheck``) plus the target-fit verdict of the interface map, so the numbers always agree with what the engineer is about to paste.
"""
from __future__ import annotations

import re
from collections import Counter

from .postcheck import check_output

_CODE = re.compile(r"REVIEW-[A-Z0-9][A-Z0-9>\-]*")

# A REVIEW code in these families means the source command was NOT carried to the target; everything else is a value or a behaviour a
# person has to confirm.
_DROPPED_MARKERS = ("UNSUPPORTED", "NO-EQUIVALENT", "UNMAPPED", "NO-CDP", "CISCO", "HOLD-TIMER", "DROPPED", "NOT-CONVERTED")


def review_group(code: str) -> str:
    """``dropped`` when the source command did not reach the target, otherwise ``decision``."""
    return "dropped" if any(marker in code for marker in _DROPPED_MARKERS) else "decision"


def build_preflight(output_text: str, target_vendor: str, fit: dict | None = None) -> dict:
    lines = output_text.splitlines()
    counts: Counter = Counter()
    review_lines = 0
    for line in lines:
        codes = _CODE.findall(line)
        if codes:
            review_lines += 1
            counts[codes[0]] += 1
    configuration = [
        line for line in lines
        if line.strip() and not line.strip().startswith(("#", "!")) and "REVIEW" not in line
    ]
    by_code = [
        {"code": code, "count": count, "group": review_group(code)}
        for code, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]
    groups = {"decision": 0, "dropped": 0}
    for row in by_code:
        groups[row["group"]] += row["count"]
    checks = check_output(output_text, target_vendor)
    verdict = (fit or {}).get("verdict")
    if verdict == "does-not-fit":
        readiness = "blocked"
    elif review_lines or checks or verdict == "partial":
        readiness = "decisions"
    else:
        readiness = "ready"
    return {
        "readiness": readiness,
        "converted_lines": len(configuration),
        "review_lines": review_lines,
        "decision": groups["decision"],
        "dropped": groups["dropped"],
        "by_code": by_code,
        "checks": checks,
        "fit": fit if fit and fit.get("verdict") not in (None, "unknown") else None,
    }
