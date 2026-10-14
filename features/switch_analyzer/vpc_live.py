"""Pairing check for a vPC (Cisco/Nexus NX-OS) or M-LAG (Huawei CloudEngine)
pair: same domain, a healthy primary/secondary (or priority) split, the
consistency checks passing, and the same vPC / Eth-Trunk IDs up and
consistent on both sides.

Mirrors fhrp_live.pair_check and ospf_db.pair_check's house style: one
row per thing being checked, a verdict, and a plain-English reason only
when something needs a look.

``runtime_parser.parse_vpc_mlag`` already normalises field names across
vendors (domain_id, role, peer_status, keepalive_status,
consistency_status — see its _VPC_FIELD_MAP / _MLAG_FIELD_MAP /
_HUAWEI_DFS_GROUP_FIELD_MAP), but not every field exists on every
vendor: Huawei M-LAG has no "peer status" concept the way NX-OS vPC
does, and its "role" is really a DFS-group priority number, not a
primary/secondary word. A field absent from BOTH sides is left out of
this check rather than reported as a difference; "role" gets its own
primary/secondary-or-numeric-priority handling below.
"""
from __future__ import annotations

from typing import Any

_FIELD_LABELS = (
    ("peer_status", "Peer link status"),
    ("keepalive_status", "Keepalive status"),
    ("consistency_status", "Configuration consistency check"),
    ("per_vlan_consistency", "Per-VLAN consistency check"),
    ("type2_consistency", "Type-2 consistency check"),
    ("peer_gateway", "Peer gateway"),
)

# Values parse_vpc_mlag reports when the feature is simply off / the domain was never built —
# the same wording the Switch Analyzer's own "feature vpc is not enabled" finding already uses.
_NOT_CONFIGURED = {"", "none established", "not configured", "disabled", "not applicable"}

_BAD_CONSISTENCY = {"failed", "fail", "inconsistent"}
_GOOD_CONSISTENCY = {"success", "consistent", "pass"}


def _configured(summary: dict[str, Any]) -> bool:
    role = str(summary.get("role") or "").strip().lower()
    domain = str(summary.get("domain_id") or "").strip().lower()
    return bool(summary) and role not in _NOT_CONFIGURED and domain not in _NOT_CONFIGURED


def is_configured(summary: dict[str, Any]) -> bool:
    """Public wrapper around :func:`_configured` for callers outside this module (``compare.py``'s
    Device Info Side-by-Side summary) that need the same "is there actually a vPC/M-LAG domain here,
    or is the feature just off / the summary empty" test ``pair_check`` already uses."""
    return _configured(summary)


def _role_row(va: str, vb: str) -> tuple[str, str]:
    """"role" doubles as Cisco's primary/secondary word and Huawei's DFS-group priority number."""
    if not va or not vb:
        return "Only on one side", ""
    if va.isdigit() and vb.isdigit():
        if va == vb:
            return "Same priority", "same DFS-group priority on both sides — check the tie-breaker (system MAC) actually decided a master"
        return "Different priority", ""
    la, lb = va.lower(), vb.lower()
    primary_a, primary_b = "primary" in la and "secondary" not in la, "primary" in lb and "secondary" not in lb
    secondary_a, secondary_b = "secondary" in la, "secondary" in lb
    if (primary_a and secondary_b) or (secondary_a and primary_b):
        return "Healthy split", ""
    if primary_a and primary_b:
        return "Both primary", "both switches claim the primary role — exactly one should hold it"
    if secondary_a and secondary_b:
        return "Both secondary", "neither switch claims the primary role: if the peer link drops, nothing is left to take over"
    return "Check", f"A reports '{va}', B reports '{vb}' — not a recognised primary/secondary split"


def _member_key(row: dict[str, Any]) -> str:
    return str(row.get("id") or "").strip()


def _pair_members(a_members: list[dict[str, Any]], b_members: list[dict[str, Any]]) -> list[tuple[dict | None, dict | None]]:
    used_b: set[int] = set()
    pairs: list[tuple[dict | None, dict | None]] = []
    for member in a_members:
        key = _member_key(member)
        match = next((row for row in b_members if _member_key(row) == key and id(row) not in used_b), None)
        if match is not None:
            used_b.add(id(match))
        pairs.append((member, match))
    pairs += [(None, row) for row in b_members if id(row) not in used_b]
    pairs.sort(key=lambda pair: (pair[0] or pair[1]).get("id", ""))
    return pairs


def _member_row(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any]:
    item = a or b or {}
    a_status, b_status = str((a or {}).get("status") or "").lower(), str((b or {}).get("status") or "").lower()
    a_cons, b_cons = str((a or {}).get("consistency") or "").lower(), str((b or {}).get("consistency") or "").lower()
    reasons: list[str] = []
    if a is None or b is None:
        verdict = "Only on B" if a is None else "Only on A"
        reasons.append("this vPC / Eth-Trunk ID is configured on one switch only")
    elif "down" in a_status or "down" in b_status:
        verdict = "Down"
        side = " and ".join(name for name, status in (("A", a_status), ("B", b_status)) if "down" in status)
        reasons.append(f"member down on {side}")
    elif any(bad in a_cons or bad in b_cons for bad in _BAD_CONSISTENCY):
        verdict = "Inconsistent"
        reasons.append("the per-vPC/Eth-Trunk consistency check failed")
    elif "up" in a_status and "up" in b_status:
        verdict = "Up on both"
    else:
        verdict = "Check"
        reasons.append(f"A '{a_status or 'unknown'}', B '{b_status or 'unknown'}'")
    return {
        "id": item.get("id", ""), "port": item.get("port", ""),
        "a_status": (a or {}).get("status") or "—", "b_status": (b or {}).get("status") or "—",
        "a_consistency": (a or {}).get("consistency") or "—", "b_consistency": (b or {}).get("consistency") or "—",
        "verdict": verdict, "reason": "; ".join(reasons) or "up and consistent on both sides",
    }


def pair_check(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Two members of one vPC / M-LAG pair: do domain, role and the consistency checks agree, and is every bundle up on both sides."""
    sa, sb = (a or {}).get("summary") or {}, (b or {}).get("summary") or {}
    conf_a, conf_b = _configured(sa), _configured(sb)
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}

    def add(label: str, va: str, vb: str, verdict: str, reason: str = "") -> None:
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append({"check": label, "a": va or "—", "b": vb or "—", "verdict": verdict, "reason": reason})

    if not conf_a and not conf_b:
        return {"rows": [], "counts": {}, "member_rows": [], "configured_a": False, "configured_b": False}
    if not conf_a or not conf_b:
        who = "Device A" if not conf_a else "Device B"
        add("Configured", "Yes" if conf_a else "No", "Yes" if conf_b else "No", "Only on one side",
            f"{who} has no vPC domain / DFS-group configured (or the feature is disabled) — the pair cannot be checked any further.")
        return {"rows": rows, "counts": counts, "member_rows": [], "configured_a": conf_a, "configured_b": conf_b}

    da, db = sa.get("domain_id", ""), sb.get("domain_id", "")
    if da and db:
        add("Domain / DFS-group ID", da, db, "Same" if da == db else "Differs",
            "" if da == db else "a vPC/M-LAG pair must share one domain ID — this looks like two unrelated domains, not a pair")
    role_verdict, role_reason = _role_row(sa.get("role", ""), sb.get("role", ""))
    add("Role / priority", sa.get("role", ""), sb.get("role", ""), role_verdict, role_reason)
    for key, label in _FIELD_LABELS:
        va, vb = sa.get(key, ""), sb.get(key, "")
        if not va and not vb:
            continue
        if not va or not vb:
            add(label, va, vb, "Only on one side", "")
            continue
        if va.lower() == vb.lower():
            bad = any(token in va.lower() for token in _BAD_CONSISTENCY) or ("down" in va.lower() and key == "peer_status")
            add(label, va, vb, "Failed on both" if bad else "Same", "both sides report this check has failed" if bad else "")
        else:
            add(label, va, vb, "Differs", "")

    member_rows = [_member_row(m_a, m_b) for m_a, m_b in _pair_members(a.get("members") or [], b.get("members") or [])]
    for row in member_rows:
        counts[row["verdict"]] = counts.get(row["verdict"], 0) + 1

    return {"rows": rows, "counts": counts, "member_rows": member_rows, "configured_a": True, "configured_b": True}
