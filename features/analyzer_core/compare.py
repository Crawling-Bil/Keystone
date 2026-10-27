"""Compare two analysis results: a backup against an older backup, or one HA peer against the other.

Works on the common result schema (``result.py``), so the Router, Firewall and Load Balancer analyzers all get it.
Nothing is parsed again: tables are matched row by row on a key, key-value sections label by label, and findings by
(rule id, object).  The answer is itself a result - a summary, one row per change, the findings that appeared or went
away - so the normal tabs, filters and Excel export work on it.

Keys.  A table is matched on its scope columns (``vdom``, ``vsys``, ``vrf``, ``partition``) plus its first column;
if that is not unique the next column is added, and as a last resort the occurrence number.  This is a heuristic:
a table whose first column is not an identity can show a renamed object as one removal plus one addition.

Expect noise when comparing two *different* devices (HA peers): their own hostnames, addresses, serial numbers and
uptime-like values always differ.  Filter on the ``section`` or ``change`` buttons to look at policy and object drift
and ignore those.  When the two hostnames differ, the tables of the "Change history" group (save log, saves per month, ...)
are left out and a note says so.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .findings import SEVERITY_RANK, finding as _finding, sort_findings
from .result import card, map_as_table, new_result, table_section

SCOPE_KEYS = ("vdom", "vsys", "vrf", "partition", "scope")
PEER_NOISE_GROUPS = {"Change history"}      # a save log is per device: between two HA peers every line differs and says nothing about drift
MAX_CHANGE_ROWS = 6000
MAX_SHOWN = 160                      # characters of one before/after value
DESCRIBE_COLUMNS = 4


def _text(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return "" if value is None else str(value)


def _shown(value: Any) -> str:
    text = _text(value)
    return text if len(text) <= MAX_SHOWN else text[: MAX_SHOWN - 1] + "…"


def _comparable(value: Any) -> str:
    """Order of a list does not matter for most tables (members, networks); order of rows does not either."""
    if isinstance(value, (list, tuple)):
        return "␟".join(sorted(str(v) for v in value))
    return _text(value)


def _key_columns(columns: list[dict[str, Any]], before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[str]:
    keys = [c["key"] for c in columns]
    scope = [k for k in keys if k in SCOPE_KEYS]
    rest = [k for k in keys if k not in SCOPE_KEYS]
    for width in range(1, min(len(rest), 3) + 1):
        chosen = scope + rest[:width]
        for rows in (before, after):
            seen = {tuple(_comparable(r.get(k)) for k in chosen) for r in rows}
            if len(seen) != len(rows):
                break
        else:
            return chosen
    return scope + rest[:3]


def _row_keys(rows: list[dict[str, Any]], key_cols: list[str]) -> dict[tuple, dict[str, Any]]:
    out: dict[tuple, dict[str, Any]] = {}
    seen: Counter = Counter()
    for row in rows:
        base = tuple(_comparable(row.get(k)) for k in key_cols)
        seen[base] += 1
        out[base + (seen[base],) if seen[base] > 1 else base] = row
    return out


def _label(columns: list[dict[str, Any]], row: dict[str, Any], key_cols: list[str]) -> str:
    parts = [_text(row.get(k)) for k in key_cols if _text(row.get(k))]
    return " / ".join(parts) or "(row)"


def _describe(columns: list[dict[str, Any]], row: dict[str, Any], key_cols: list[str]) -> str:
    extra = [f"{c['label']}: {_text(row.get(c['key']))}" for c in columns if c["key"] not in key_cols and _text(row.get(c["key"]))]
    return "; ".join(extra[:DESCRIBE_COLUMNS]) or "—"


def _table_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    # sections of the two captures may not have exactly the same columns; compare on the columns both have
    after_cols = {c["key"] for c in after["columns"]}
    columns = [c for c in before["columns"] if c["key"] in after_cols]
    if not columns:
        return []
    key_cols = _key_columns(columns, before["rows"], after["rows"])
    old, new = _row_keys(before["rows"], key_cols), _row_keys(after["rows"], key_cols)
    changes: list[dict[str, Any]] = []
    title = before["title"]
    for key, row in old.items():
        if key not in new:
            changes.append({"section": title, "change": "removed", "object": _label(columns, row, key_cols), "field": "(row)", "before": _describe(columns, row, key_cols), "after": ""})
    for key, row in new.items():
        if key not in old:
            changes.append({"section": title, "change": "added", "object": _label(columns, row, key_cols), "field": "(row)", "before": "", "after": _describe(columns, row, key_cols)})
            continue
        was = old[key]
        for col in columns:
            if col["key"] in key_cols:
                continue
            if _comparable(was.get(col["key"])) != _comparable(row.get(col["key"])):
                changes.append({"section": title, "change": "changed", "object": _label(columns, row, key_cols), "field": col["label"], "before": _shown(was.get(col["key"])), "after": _shown(row.get(col["key"]))})
    return changes


def _kv_changes(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    old = {p["label"]: p["value"] for p in before["pairs"]}
    new = {p["label"]: p["value"] for p in after["pairs"]}
    out = []
    for label in [*old, *[k for k in new if k not in old]]:
        if _comparable(old.get(label)) == _comparable(new.get(label)):
            continue
        change = "removed" if label not in new else ("added" if label not in old else "changed")
        out.append({"section": before["title"], "change": change, "object": label, "field": "value", "before": _shown(old.get(label)), "after": _shown(new.get(label))})
    return out


def _finding_key(item: dict[str, Any]) -> tuple[str, str]:
    return item.get("id", ""), item.get("object", "")


def _flat(result: dict[str, Any]) -> dict[str, Any]:
    """A map (tree) section is compared as the table of its objects."""
    if not any(section.get("kind") == "map" for section in result.get("sections", [])):
        return result
    return dict(result, sections=[map_as_table(section) if section.get("kind") == "map" else section for section in result["sections"]])


def compare_results(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    before, after = _flat(before), _flat(after)
    changes: list[dict[str, Any]] = []
    per_section: dict[str, Counter] = {}
    after_sections = {s["id"]: s for s in after.get("sections", [])}
    only_before, only_after = [], []
    peers = bool(before.get("hostname") and after.get("hostname") and before["hostname"] != after["hostname"])
    skipped: list[str] = []
    for old in before.get("sections", []):
        new = after_sections.get(old["id"])
        if new is None:
            only_before.append(old["title"])
            continue
        if peers and old.get("group") in PEER_NOISE_GROUPS:
            skipped.append(old["title"])
            continue
        if old["kind"] != new["kind"]:
            continue
        found = _table_changes(old, new) if old["kind"] == "table" else _kv_changes(old, new)
        if found:
            per_section[old["title"]] = Counter(c["change"] for c in found)
            changes.extend(found)
    only_after = [s["title"] for s in after.get("sections", []) if s["id"] not in {o["id"] for o in before.get("sections", [])}]

    old_findings = {_finding_key(f): f for f in before.get("findings", [])}
    new_findings = {_finding_key(f): f for f in after.get("findings", [])}
    appeared = [f for k, f in new_findings.items() if k not in old_findings]
    resolved = [f for k, f in old_findings.items() if k not in new_findings]

    total = Counter(c["change"] for c in changes)
    title = f"{before.get('hostname') or before.get('source_name')} → {after.get('hostname') or after.get('source_name')}"
    result = new_result(
        after.get("analyzer", before.get("analyzer", "compare")),
        hostname=title, vendor=after.get("vendor", ""), platform="Comparison", source_name=f"{before.get('source_name', '')} ↔ {after.get('source_name', '')}",
        title=title, subtitle=f"{sum(total.values()):,} change(s) · {len(appeared)} new finding(s) · {len(resolved)} resolved",
        comparison=True,
    )
    worst = max((SEVERITY_RANK.get(f["severity"], 0) for f in appeared), default=0)
    result["cards"] = [
        card("Rows added", total["added"], "info", "present only in the second capture", "compare_changes"),
        card("Rows removed", total["removed"], "info", "present only in the first capture", "compare_changes"),
        card("Values changed", total["changed"], "warn" if total["changed"] else "ok", "same object, different value", "compare_changes"),
        card("New findings", len(appeared), "bad" if worst >= SEVERITY_RANK["high"] else ("warn" if appeared else "ok"), "in the second capture only", "findings"),
        card("Resolved findings", len(resolved), "ok" if resolved else "mute", "in the first capture only", "findings"),
        card("Sections that differ", len(per_section), "info", "", "compare_summary"),
    ]
    result["info"] = [{"label": "First capture", "value": f"{before.get('hostname', '')} · {before.get('source_name', '')}"}, {"label": "Second capture", "value": f"{after.get('hostname', '')} · {after.get('source_name', '')}"},
                      {"label": "Platforms", "value": f"{before.get('platform', '')} → {after.get('platform', '')}"}]
    summary_rows = [{"section": name, "added": c["added"], "removed": c["removed"], "changed": c["changed"]} for name, c in per_section.items()]
    sections = [table_section("compare_summary", "Sections that differ", [("section", "Section"), ("added", "Added", "num"), ("removed", "Removed", "num"), ("changed", "Changed", "num")], summary_rows, group="Changes",
                              empty="The two captures hold the same rows and values in every table.")]
    shown = changes[:MAX_CHANGE_ROWS]
    tones = {"added": "ok", "removed": "bad", "changed": "warn"}
    sections.append(table_section("compare_changes", "Every change", [("section", "Section"), ("change", "Change", "status"), ("object", "Object", "mono"), ("field", "Field"), ("before", "First capture", "wrap"), ("after", "Second capture", "wrap")],
                                  [dict(c, _tones={"change": tones[c["change"]]}) for c in shown], group="Changes", total=len(changes), page_size=100,
                                  facets=[{"key": "section", "label": "section"}, {"key": "change", "label": "change", "order": ["added", "removed", "changed"]}],
                                  hint="'added' exists only in the second capture, 'removed' only in the first. Lists are compared without regard to order."))
    if only_before or only_after:
        sections.append(table_section("compare_scope", "Sections present in one capture only", [("where", "Present in"), ("section", "Section")],
                                      [{"where": "first capture only", "section": s} for s in only_before] + [{"where": "second capture only", "section": s} for s in only_after], group="Changes",
                                      hint="Usually a different command output or a feature that is configured on one side only."))
    info_changes = [c for c in [{"label": i["label"], "before": i["value"], "after": next((j["value"] for j in after.get("info", []) if j["label"] == i["label"]), "")} for i in before.get("info", [])]
                    if _comparable(c["before"]) != _comparable(c["after"])]
    if info_changes:
        sections.append(table_section("compare_info", "Device details that differ", [("label", "Detail"), ("before", "First capture", "wrap"), ("after", "Second capture", "wrap")], info_changes, group="Changes"))
    result["sections"] = sections
    findings = [dict(f, title=f"New: {f['title']}") for f in appeared]
    findings += [_finding(f["id"], "info", f.get("category", ""), f"Resolved: {f['title']}", obj=f.get("object", ""), detail="This finding was in the first capture and is gone in the second.",
                          recommendation="", reference=f.get("reference", "")) for f in resolved]
    result["findings"] = sort_findings(findings)
    result["coverage"] = []
    notes = []
    if before.get("platform") != after.get("platform"):
        notes.append(f"The captures come from different platforms or versions ({before.get('platform', '?')} and {after.get('platform', '?')}); expect version-driven differences.")
    if skipped:
        notes.append(f"The captures come from different devices, so {len(skipped)} change-history table(s) were left out of the comparison (they differ on every line between HA peers).")
    if len(changes) > MAX_CHANGE_ROWS:
        notes.append(f"{len(changes):,} changes were found; the first {MAX_CHANGE_ROWS:,} are listed.")
    result["warnings"] = notes
    return result

