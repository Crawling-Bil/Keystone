"""Common finding model shared by all analyzers.

A finding is a plain dict so it serialises straight to JSON and Excel:

    {"id": "RTR-BGP-001", "severity": "high", "category": "BGP",
     "title": "...", "object": "neighbor 10.0.0.1", "detail": "...",
     "recommendation": "...", "reference": "https://..."}

Two optional fields serve audit work and are left out of the dict when empty (so existing results and exports do not change):
``standards`` is a list of control identifiers the rule maps to, written the way the framework writes them (for example
``"CIS Benchmark for Palo Alto Networks PAN-OS 1.1.0 - 2.1"``, ``"NIST SP 800-53 Rev. 5 AC-6"``, ``"PCI DSS v4.0 1.3.1"``) and
``evidence`` is the configuration line(s) the finding was raised from, so a reviewer can find it in the capture without re-reading it.

``reference`` is always a vendor documentation URL.  The analyzers keep a
small registry of those so every rule can cite real documentation.
"""

from __future__ import annotations

from typing import Any, Iterable

SEVERITIES = ("high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def finding(
    rule_id: str,
    severity: str,
    category: str,
    title: str,
    *,
    obj: str = "",
    detail: str = "",
    recommendation: str = "",
    reference: str = "",
    standards: Iterable[str] = (),
    evidence: str = "",
) -> dict[str, Any]:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity {severity!r}")
    item = {
        "id": rule_id,
        "severity": severity,
        "category": category,
        "title": title,
        "object": obj,
        "detail": detail,
        "recommendation": recommendation,
        "reference": reference,
    }
    controls = [str(code).strip() for code in ([standards] if isinstance(standards, str) else standards) if str(code).strip()]
    if controls:
        item["standards"] = controls
    if evidence:
        item["evidence"] = evidence
    return item


def sort_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (SEVERITY_RANK.get(item.get("severity", "info"), 9), item.get("category", ""), item.get("id", ""), item.get("object", "")),
    )


def dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out: list[dict[str, Any]] = []
    for item in findings:
        key = (item["id"], item.get("object", ""), item.get("title", ""))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITIES}
    for item in findings:
        counts[item.get("severity", "info")] = counts.get(item.get("severity", "info"), 0) + 1
    return counts


def cap_per_rule(items: Iterable[dict[str, Any]], limit: int = 25) -> list[dict[str, Any]]:
    """Keep at most ``limit`` findings per rule id (highest severity first) and add one info line for the rest.

    The limit is per rule id on purpose: capping a whole group let two noisy rules fill the quota and silently hide
    every other finding type of that group."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        buckets.setdefault(item["id"], []).append(item)
    out: list[dict[str, Any]] = []
    for rule_id, group in buckets.items():
        if len(group) <= limit:
            out.extend(group)
            continue
        group = sorted(group, key=lambda g: SEVERITY_RANK.get(g["severity"], 9))
        out.extend(group[:limit])
        sample = group[0]
        out.append(finding(rule_id, "info", sample["category"], f"{len(group) - limit} more finding(s) of rule {rule_id} not listed",
                           detail=f"{len(group)} objects match '{sample['title']}'; the first {limit} (highest severity first) are listed.", reference=sample.get("reference", "")))
    return out
