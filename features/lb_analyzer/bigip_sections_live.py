"""Tabs built from the live ``show`` output of a terminal capture (sync and failover status, virtual-server and pool availability)."""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import kv_section, table_section


def live_sections(runtime: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    pairs = []
    version = runtime.get("version")
    if version:
        pairs += [(k.title(), v) for k, v in version.items()]
    sync = runtime.get("sync")
    if sync and sync.get("status"):
        pairs.append(("Config sync", sync["status"], "ok" if sync["status"].lower() in ("in sync", "standalone") else "bad"))
        if sync.get("summary"):
            pairs.append(("Sync summary", sync["summary"]))
    fo = runtime.get("failover")
    if fo and fo.get("status"):
        pairs.append(("Failover", fo["status"], "ok" if fo["status"].lower() in ("active", "standby", "standalone") else "bad"))
        if fo.get("summary"):
            pairs.append(("Failover summary", fo["summary"]))
    if pairs:
        out.append(kv_section("status_live", "System status (live)", pairs, group="Live state"))
    vs = runtime.get("virtuals")
    if vs is not None:
        rows = [dict(v, _tones={"availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(v["availability"].lower(), "mute"), "state": "ok" if v["state"].lower() == "enabled" else "mute"}) for v in vs]
        out.append(table_section("virtuals_live", "Virtual servers (live)", [("name", "Virtual server", "mono"), ("destination", "Destination", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("connections", "Current connections", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No virtual server status in the capture.", page_size=100))
    ps = runtime.get("pools")
    if ps is not None:
        rows = []
        for p in ps:
            tone = "ok"
            if p["total"] and p["available"] == 0:
                tone = "bad"
            elif p["total"] and p["available"] is not None and p["available"] < p["total"]:
                tone = "warn"
            rows.append(dict(p, members=f"{p['available']}/{p['total']}" if p["total"] is not None else "", _tones={"members": tone, "availability": {"available": "ok", "offline": "bad", "unavailable": "warn"}.get(p["availability"].lower(), "mute")}))
        out.append(table_section("pools_live", "Pools (live)", [("name", "Pool", "mono"), ("availability", "Availability", "status"), ("state", "State", "status"), ("members", "Available / total", "num"), ("reason", "Reason", "wrap")],
                                 rows, group="Live state", empty="No pool status in the capture.", page_size=100))
    return out
