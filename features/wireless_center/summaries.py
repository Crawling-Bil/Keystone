from __future__ import annotations

from collections import defaultdict
from typing import Any


def _value(value: Any, fallback: str) -> str:
    text = str(value or "").strip()
    return text or fallback


def build_ap_device_summary(aps: list[dict[str, Any]]) -> dict[str, Any]:
    """Group operational AP inventory by device model and software version."""
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for ap in aps:
        model = _value(ap.get("model") or ap.get("type_id"), "Unknown model")
        version = _value(ap.get("version"), "Unknown version")
        grouped[model][version].append(ap)

    rows: list[dict[str, Any]] = []
    unknown_versions = 0
    mixed_models = 0
    known_versions: set[str] = set()
    for model, versions in grouped.items():
        known_for_model = {name for name in versions if name != "Unknown version"}
        unknown_for_model = len(versions.get("Unknown version", []))
        unknown_versions += unknown_for_model
        known_versions.update(known_for_model)
        if len(known_for_model) > 1:
            consistency = "Mixed versions"
            mixed_models += 1
        elif known_for_model and unknown_for_model:
            consistency = "Partial data"
        elif known_for_model:
            consistency = "Consistent"
        else:
            consistency = "Runtime data unavailable"

        version_rows = []
        for version, records in versions.items():
            statuses: dict[str, int] = defaultdict(int)
            for ap in records:
                statuses[_value(ap.get("status"), "Unknown")] += 1
            version_rows.append({
                "version": version,
                "count": len(records),
                "statuses": dict(sorted(statuses.items())),
                "status_text": " · ".join(
                    f"{count} {status}" for status, count in sorted(statuses.items())
                ),
            })
        version_rows.sort(key=lambda item: (
            item["version"] == "Unknown version",
            -item["count"],
            item["version"].lower(),
        ))
        rows.append({
            "model": model,
            "total": sum(item["count"] for item in version_rows),
            "version_count": len(known_for_model),
            "unknown_version_count": unknown_for_model,
            "consistency": consistency,
            "versions": version_rows,
        })

    rows.sort(key=lambda item: (-item["total"], item["model"].lower()))
    return {
        "summary": {
            "models": len(grouped),
            "versions": len(known_versions),
            "mixed_models": mixed_models,
            "unknown_versions": unknown_versions,
        },
        "rows": rows,
    }
