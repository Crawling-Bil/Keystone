"""Findings that need the archive around the configuration: license subscriptions, customised ``sys db`` values,
boot-time commands and the saved-configuration history (members and virtual servers left disabled).

Without a UCS (``data["ucs"]`` is ``None``) nothing here runs.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_context import LCtx
from .refs import F5

STALE_AFTER_DAYS = 30
VERY_STALE_AFTER_DAYS = 180


def ucs_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    ucs = ctx.data.get("ucs")
    if not ucs:
        return []
    bundle, today = ucs["bundle"], ctx.today
    out: list[dict[str, Any]] = []
    for m in bundle.license.get("timelimited", []):
        if not m["end"]:
            continue
        days = (m["end"] - today).days
        if days < 0:
            out.append(finding("LB-LIC-001", "medium", "License", f"Subscription '{m['module']}' expired {-days} days ago", obj=m["module"], detail=f"The time-limited license module ended on {m['end']}; the feature stops updating or enforcing.",
                               recommendation="Renew the subscription and re-activate the license.", reference=F5["licensing"]))
        elif days <= 90:
            out.append(finding("LB-LIC-002", "low", "License", f"Subscription '{m['module']}' ends in {days} days", obj=m["module"], detail=f"Ends on {m['end']}.", recommendation="Renew before it lapses and re-activate the license.", reference=F5["licensing"]))
    for key, entry in bundle.db.items():
        if key.lower().startswith("log.") and key.lower().endswith(".level") and entry["value"].lower() == "debug":
            out.append(finding("LB-SYS-010", "low", "Logging", f"{key} is set to debug", obj=key, detail="Debug logging on a production unit fills /var/log and slows the module.",
                               recommendation="Return it to the default level (tmsh modify sys db <name> value ...).", reference=F5["sys_db"]))
    if bundle.has_startup_additions:
        out.append(finding("LB-SYS-011", "info", "System", "/config/startup contains custom commands", obj="/config/startup", detail="Commands in /config/startup run at boot outside tmsh configuration management and are easy to forget during upgrades and migrations.",
                           recommendation="Document them or move the settings into the tmsh configuration.", reference=F5["ucs_archives"]))
    for item in bundle.custom_files:
        if item["kind"].startswith("failover script"):
            out.append(finding("LB-SYS-014", "info", "System", "Custom commands in a failover script", obj=item["path"], detail=f"{item['path']} holds {item['kind'].split('with ')[1]}. It runs on every failover event outside the tmsh configuration.",
                               recommendation="Document what it does and test it after upgrades.", reference=F5["dsc_failover"]))
    out += _stale_state(ctx, ucs["history"])
    return out


def _stale_state(ctx: LCtx, history: dict[str, Any]) -> list[dict[str, Any]]:
    """Members and virtual servers that the history shows were disabled/forced offline and that the current configuration still has that way."""
    out: list[dict[str, Any]] = []
    if not history["count"]:
        return out
    since = history["disabled_since"]
    window = f"The saved-configuration history starts {history['first']:%Y-%m-%d}; older changes are not visible."

    def severity(days: int) -> str:
        return "medium" if days >= VERY_STALE_AFTER_DAYS else "low"

    for pool in ctx.data["pools"]:
        for m in pool["members"]:
            entry = since.get((pool["name"], m["name"]))
            if not entry or not (m["disabled"] or m["forced_down"]):
                continue
            kind, when = ("forced offline", entry["offline"]) if m["forced_down"] and entry["offline"] else ("disabled", entry["disabled"] or entry["offline"])
            days = (ctx.today - when.date()).days
            if days >= STALE_AFTER_DAYS:
                out.append(finding("LB-CHG-001", severity(days), "Change history", f"Pool member left {kind} for {days} days", obj=f"{pool['short']} → {m['address']}:{m['port'] or 'any'}",
                                   detail=f"The configuration history shows this member of pool {pool['short']} was {kind} on {when:%Y-%m-%d} and it still is. {window}",
                                   recommendation="Re-enable it, or remove the member if it was retired; a parked member is easy to forget and silently reduces capacity.", reference=F5["pool"]))
    for v in ctx.data["virtuals"]:
        entry = since.get((v["name"], ""))
        if entry and not v["enabled"]:
            days = (ctx.today - entry["disabled"].date()).days
            if days >= STALE_AFTER_DAYS:
                out.append(finding("LB-CHG-002", severity(days), "Change history", f"Virtual server left disabled for {days} days", obj=v["short"],
                                   detail=f"The configuration history shows {v['short']} was disabled on {entry['disabled']:%Y-%m-%d} and it still is. {window}",
                                   recommendation="Delete it if the service is retired, or enable it; disabled virtual servers keep their addresses, profiles and certificates in use.", reference=F5["virtual"]))
    return out
