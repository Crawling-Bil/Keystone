"""The result structure every analyzer returns and the browser renders.

Keeping one shape for Router / Firewall / Load Balancer means one JS
renderer and one Excel exporter, while each analyzer still decides *what*
tables exist -- a router gets Routing/BGP/Crypto tabs, a load balancer gets
Virtual Servers/Pools/Monitors.

    {
      "schema": "keystone.analysis/1",
      "analyzer": "router",
      "hostname": "...", "vendor": "...", "platform": "...", "source_name": "...",
      "title": "...", "subtitle": "...",
      "cards":    [{"label","value","tone","hint","section"}],
      "info":     [{"label","value"}],
      "findings": [ ... see findings.py ... ],
      "sections": [{"id","title","group","kind":"table"|"kv"|"map","hint", ...}],
      "coverage": [{"command","status","lines","note"}],
      (table rows may carry "_tone" for the whole row and "_tones" {column: tone}
       for single cells; tones are ok / warn / bad / info / mute)
      "warnings": ["..."]
    }
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

SCHEMA = "keystone.analysis/1"
COLUMN_KINDS = {"text", "status", "severity", "mono", "num", "id", "wrap", "list"}
TONES = {"ok", "warn", "bad", "info", "mute", ""}
MAX_CELL_CHARS = 2000


def clean_value(value: Any) -> Any:
    """JSON/Excel friendly cell value: scalars stay, lists become lists of
    strings, everything else becomes str."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_CELL_CHARS else value[: MAX_CELL_CHARS - 1] + "…"
    if isinstance(value, (list, tuple, set)):
        return [str(clean_value(item)) for item in value]
    return str(value)


def column(key: str, label: str | None = None, kind: str = "text") -> dict[str, str]:
    if kind not in COLUMN_KINDS:
        raise ValueError(f"unknown column kind {kind!r}")
    return {"key": key, "label": label or key.replace("_", " ").title(), "kind": kind}


def columns_from(spec: Sequence[Any]) -> list[dict[str, str]]:
    """Accept ``"key"``, ``("key","Label")`` or ``("key","Label","kind")``."""
    out: list[dict[str, str]] = []
    for item in spec:
        if isinstance(item, dict):
            out.append(column(item["key"], item.get("label"), item.get("kind", "text")))
        elif isinstance(item, str):
            out.append(column(item))
        else:
            out.append(column(*item))
    return out


def table_section(
    section_id: str,
    title: str,
    columns: Sequence[Any],
    rows: Iterable[dict[str, Any]],
    *,
    group: str = "",
    hint: str = "",
    total: int | None = None,
    empty: str = "Nothing of this kind was found in the capture.",
    searchable: bool = True,
    page_size: int = 200,
    facets: Sequence[dict[str, str]] | None = None,
) -> dict[str, Any]:
    cols = columns_from(columns)
    keys = [col["key"] for col in cols]
    cleaned: list[dict[str, Any]] = []
    for row in rows:
        item = {key: clean_value(row.get(key)) for key in keys}
        tone = row.get("_tone")
        if tone:
            item["_tone"] = tone
        tones = row.get("_tones")
        if tones:
            item["_tones"] = {key: value for key, value in tones.items() if key in keys and value in TONES and value}
        cleaned.append(item)
    return {
        "id": section_id,
        "title": title,
        "group": group,
        "kind": "table",
        "hint": hint,
        "columns": cols,
        "rows": cleaned,
        "total": total if total is not None else len(cleaned),
        "empty": empty,
        "searchable": searchable,
        "page_size": page_size,
        "facets": [dict(facet) for facet in (facets or [])],
    }


def kv_section(
    section_id: str,
    title: str,
    pairs: Iterable[Sequence[Any]],
    *,
    group: str = "",
    hint: str = "",
    empty: str = "Nothing of this kind was found in the capture.",
) -> dict[str, Any]:
    items = []
    for pair in pairs:
        label, value = pair[0], pair[1]
        entry = {"label": str(label), "value": clean_value(value)}
        if len(pair) > 2 and pair[2]:
            entry["tone"] = pair[2]
        items.append(entry)
    return {"id": section_id, "title": title, "group": group, "kind": "kv", "hint": hint, "pairs": items, "empty": empty}


MAP_NODE_FIELDS = ("id", "parent", "type", "name", "status", "badge", "source", "reason", "ref", "section")
MAX_MAP_NODES = 30000


def map_section(
    section_id: str,
    title: str,
    nodes: Iterable[dict[str, Any]],
    *,
    statuses: Sequence[dict[str, Any]],
    types: Sequence[dict[str, Any]],
    group: str = "",
    hint: str = "",
    empty: str = "Nothing to draw.",
    notes: Sequence[str] = (),
    references: Sequence[dict[str, str]] = (),
    live: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A clickable parent -> child map (the Load Balancer Analyzer draws virtual server -> pool -> member -> monitor with it).

    ``nodes`` is a flat list; each node carries ``id`` and ``parent`` ("" for a root), a ``type`` from ``types`` and a ``status``
    from ``statuses`` ("" = none), and optionally ``badge`` (short secondary text), ``reason``, ``source`` (live / config /
    derived), ``ref`` (an entity key - the same pool under two virtual servers shares it), ``section`` (id of the table that lists
    the object) and ``detail`` (key/value pairs for the side panel).  Order of the list is the order of the siblings.
    """
    cleaned: list[dict[str, Any]] = []
    for node in nodes:
        item: dict[str, Any] = {key: clean_value(node.get(key, "")) for key in MAP_NODE_FIELDS}
        item["detail"] = [{"label": str(pair[0]), "value": clean_value(pair[1])} for pair in node.get("detail", []) if len(pair) > 1 and pair[1] not in (None, "", [])]
        if node.get("tone"):
            item["tone"] = node["tone"]
        cleaned.append(item)
    truncated = len(cleaned) > MAX_MAP_NODES
    if truncated:
        keep = {item["id"] for item in cleaned[:MAX_MAP_NODES]}
        cleaned = [item for item in cleaned[:MAX_MAP_NODES] if not item["parent"] or item["parent"] in keep]
    return {
        "id": section_id, "title": title, "group": group, "kind": "map", "hint": hint, "empty": empty, "nodes": cleaned,
        "statuses": [dict(status) for status in statuses], "types": [dict(kind) for kind in types],
        "references": [dict(ref) for ref in references], "live": dict(live or {}),
        "notes": list(notes) + ([f"The map was cut at {MAX_MAP_NODES:,} objects."] if truncated else []),
    }


def map_depths(section: dict[str, Any]) -> list[tuple[dict[str, Any], int, str]]:
    """Depth-first walk of a map section: ``(node, depth, path)`` in display order, ``path`` being the names from the root down."""
    kids: dict[str, list[dict[str, Any]]] = {}
    for node in section.get("nodes", []):
        kids.setdefault(node.get("parent", ""), []).append(node)
    out: list[tuple[dict[str, Any], int, str]] = []
    seen: set[str] = set()

    def walk(parent: str, depth: int, path: str) -> None:
        for node in kids.get(parent, []):
            if node["id"] in seen:
                continue
            seen.add(node["id"])
            here = f"{path} > {node['name']}" if path else node["name"]
            out.append((node, depth, here))
            walk(node["id"], depth + 1, here)

    walk("", 0, "")
    return out


def map_as_table(section: dict[str, Any]) -> dict[str, Any]:
    """A map flattened to a table section (one row per object, path from the root) for the Excel export and the comparison."""
    type_labels = {kind["key"]: kind.get("label", kind["key"]) for kind in section.get("types", [])}
    rows = []
    for node, depth, path in map_depths(section):
        details = "; ".join(f"{pair['label']}: {', '.join(pair['value']) if isinstance(pair['value'], list) else pair['value']}" for pair in node.get("detail", []))
        rows.append({"path": path, "level": depth, "type": type_labels.get(node["type"], node["type"]), "name": node["name"], "status": node.get("status", ""), "badge": node.get("badge", ""),
                     "reason": node.get("reason", ""), "source": node.get("source", ""), "detail": details})
    return table_section(section["id"], section["title"], [("path", "Path", "wrap"), ("level", "Level", "num"), ("type", "Type"), ("name", "Name", "mono"), ("status", "Status", "status"), ("badge", "Address / note"),
                                                          ("reason", "Reason", "wrap"), ("source", "Source"), ("detail", "Detail", "wrap")], rows, group=section.get("group", ""), hint=section.get("hint", ""), page_size=300)


def card(label: str, value: Any, tone: str = "", hint: str = "", section: str = "") -> dict[str, Any]:
    if tone not in TONES:
        raise ValueError(f"unknown tone {tone!r}")
    return {"label": label, "value": clean_value(value), "tone": tone, "hint": hint, "section": section}


def new_result(analyzer: str, **fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": SCHEMA,
        "analyzer": analyzer,
        "device_type": analyzer,
        "hostname": "",
        "vendor": "",
        "platform": "",
        "source_name": "",
        "title": "",
        "subtitle": "",
        "cards": [],
        "info": [],
        "findings": [],
        "sections": [],
        "coverage": [],
        "warnings": [],
    }
    base.update(fields)
    return base


def info_rows(pairs: Iterable[Sequence[Any]]) -> list[dict[str, Any]]:
    return [{"label": str(label), "value": clean_value(value)} for label, value, *_ in pairs if value not in (None, "", [])]


def section_by_id(result: dict[str, Any], section_id: str) -> dict[str, Any] | None:
    for section in result.get("sections", []):
        if section["id"] == section_id:
            return section
    return None


def validate_result(result: dict[str, Any]) -> list[str]:
    """Return a list of structural problems (empty list == valid).  Used by
    the unit tests and, defensively, before an export."""
    problems: list[str] = []
    if result.get("schema") != SCHEMA:
        problems.append("schema missing or wrong")
    for key in ("analyzer", "hostname", "cards", "info", "findings", "sections", "coverage"):
        if key not in result:
            problems.append(f"missing key {key}")
    ids: set[str] = set()
    for section in result.get("sections", []):
        sid = section.get("id")
        if not sid:
            problems.append("section without id")
            continue
        if sid in ids:
            problems.append(f"duplicate section id {sid}")
        ids.add(sid)
        if section.get("kind") == "table":
            keys = [col["key"] for col in section.get("columns", [])]
            if len(set(keys)) != len(keys):
                problems.append(f"section {sid}: duplicate column keys")
            for row in section.get("rows", []):
                missing = [key for key in keys if key not in row]
                if missing:
                    problems.append(f"section {sid}: row missing {missing}")
                    break
        elif section.get("kind") == "kv":
            if "pairs" not in section:
                problems.append(f"section {sid}: kv without pairs")
        elif section.get("kind") == "map":
            node_ids = [node.get("id") for node in section.get("nodes", [])]
            if len(set(node_ids)) != len(node_ids):
                problems.append(f"section {sid}: duplicate map node ids")
            known = set(node_ids)
            orphans = [node["id"] for node in section.get("nodes", []) if node.get("parent") and node["parent"] not in known]
            if orphans:
                problems.append(f"section {sid}: map nodes with an unknown parent {orphans[:3]}")
            status_keys = {status["key"] for status in section.get("statuses", [])} | {""}
            type_keys = {kind["key"] for kind in section.get("types", [])}
            for node in section.get("nodes", []):
                if node.get("status") not in status_keys or node.get("type") not in type_keys:
                    problems.append(f"section {sid}: map node {node.get('id')} uses an undeclared status or type")
                    break
        else:
            problems.append(f"section {sid}: unknown kind {section.get('kind')!r}")
    for item in result.get("findings", []):
        for key in ("id", "severity", "title"):
            if not item.get(key):
                problems.append(f"finding missing {key}")
                break
    for item in result.get("cards", []):
        target = item.get("section")
        if target and target not in ids and target not in ("findings", "overview", "coverage"):
            problems.append(f"card {item.get('label')!r} points at unknown section {target!r}")
    return problems
