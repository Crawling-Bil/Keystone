"""PAN-OS routing checks: which routing engine is in use, and whether the default routes can fail over.

A firewall that runs the **Advanced Routing Engine** keeps routes in ``network/logical-router``; the classic ``virtual-router``
section stays in the file after the migration but is no longer used.  Reading both as live routing (as a plain export lists
them) shows routes that are not in the forwarding table.  ``show system info`` says which engine is on (``advanced-routing:
on``); a bare XML export does not, so the rows are then marked "unknown" when both engines are present.

Reference: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/advanced-routing/logical-router-overview
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..analyzer_core.findings import finding
from .refs import PALO

DEFAULT_METRIC = 10                     # PAN-OS default route metric
CLASSIC, ADVANCED = "virtual-router", "logical-router"


def engines_present(d: dict[str, Any]) -> set[str]:
    return {row.get("engine", CLASSIC) for row in d.get("routing_protocols", [])}


def annotate(d: dict[str, Any], advanced: bool | None) -> None:
    """Add ``active`` to every router and route row: ``yes``, ``no`` (the other engine is on) or ``unknown`` (both engines present, no show output)."""
    both = len(engines_present(d)) > 1
    for row in d.get("routing_protocols", []) + d.get("static_routes", []):
        engine = row.get("engine", CLASSIC)
        if advanced is None:
            row["active"] = "unknown" if both else "yes"
        else:
            row["active"] = "yes" if (engine == ADVANCED) == advanced else "no"


def _where(row: dict[str, Any]) -> str:
    return f"{row.get('virtual_router', '')} ({'advanced routing' if row.get('engine') == ADVANCED else 'classic virtual router'})"


def evaluate(d: dict[str, Any], advanced: bool | None) -> list[dict[str, Any]]:
    routes = d.get("static_routes", [])
    if not routes:
        return []
    out: list[dict[str, Any]] = []
    by_engine: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in routes:
        by_engine[r.get("engine", CLASSIC)].append(r)

    if len(by_engine) > 1:
        names = ", ".join(f"{len(rows)} in the {('logical routers' if e == ADVANCED else 'virtual routers')}" for e, rows in sorted(by_engine.items()))
        if advanced is None:
            out.append(finding("PAN-RT-004", "info", "Routing", "Both routing engines hold static routes", obj=f"{len(routes)} static routes",
                               detail=f"This export has static routes in both engines ({names}). Only one engine runs: with Advanced Routing on, the classic virtual-router section is ignored. The file alone does not say which is on.",
                               recommendation="Run 'show system info | match advanced-routing' (or include 'show system info' in the capture) to see which engine is active; delete the other section so the configuration cannot be misread.", reference=PALO["advanced_routing"]))
        else:
            stale = ADVANCED if not advanced else CLASSIC
            rows = by_engine.get(stale, [])
            if rows:
                out.append(finding("PAN-RT-004", "low", "Routing", f"{len(rows)} static route(s) belong to the inactive {'advanced routing' if stale == ADVANCED else 'classic virtual router'} engine", obj=f"{len(rows)} static routes",
                                   detail=f"advanced-routing is {'on' if advanced else 'off'}, so the {'logical-router' if stale == ADVANCED else 'virtual-router'} routes are not used: {', '.join(r['name'] if 'name' in r else r['destination'] for r in rows[:8])}{' and more' if len(rows) > 8 else ''}. "
                                          "They still appear in the file and in reviews, and they may differ from the live routing table.",
                                   recommendation="Read routes from the active engine only and remove the unused section after confirming it holds nothing the active engine lacks.", reference=PALO["advanced_routing"]))

    classic = {r.get("name"): r for r in by_engine.get(CLASSIC, [])}
    drift = []
    for r in by_engine.get(ADVANCED, []):
        c = classic.get(r.get("name"))
        if c and bool(c.get("path_monitor") or c.get("bfd")) != bool(r.get("path_monitor") or r.get("bfd")):
            drift.append((r, c))
    if drift:
        lost = [(r, c) for r, c in drift if c.get("path_monitor") or c.get("bfd")]
        default = any(r.get("destination") == "0.0.0.0/0" for r, _ in drift)
        names = ", ".join(f"{r['name']} ({'classic has path monitoring/BFD, advanced has none' if (c.get('path_monitor') or c.get('bfd')) else 'advanced has it, classic has none'})" for r, c in drift[:8])
        state = ("Advanced routing is on, so the advanced side is what runs" if advanced else "Advanced routing is off, so the classic side is what runs" if advanced is False else "The file does not say which engine runs")
        out.append(finding("PAN-RT-006", "medium" if default and lost and advanced is not False else "low", "Routing", f"{len(drift)} route(s) have failure detection in one routing engine and not in the other", obj=", ".join(r["name"] for r, _ in drift[:6]),
                           detail=f"The same route name exists in both engines but path monitoring / BFD differs: {names}. {state}. A route that lost its path monitoring when the configuration was migrated to the Advanced Routing Engine keeps pointing traffic at a dead upstream.",
                           recommendation="Re-create path monitoring on the active engine's route (Network > Routing > Logical Routers > Static > Path Monitoring) and delete the unused engine's section.", reference=PALO["path_monitor"]))

    live = [r for r in routes if r.get("active") in ("yes", None)]
    other = {(r.get("name") or r.get("destination")): r for r in routes if r.get("active") == "no"}
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for r in live:
        if r.get("destination") == "0.0.0.0/0":
            groups[(r.get("engine", CLASSIC), r.get("virtual_router", ""))].append(r)
    for (_engine, _router), defaults in groups.items():
        if len(defaults) < 2:
            continue
        best = min((r.get("metric") if isinstance(r.get("metric"), int) else DEFAULT_METRIC) for r in defaults)
        for r in defaults:
            metric = r.get("metric") if isinstance(r.get("metric"), int) else DEFAULT_METRIC
            if metric != best or r.get("path_monitor") or r.get("bfd"):
                continue
            was = other.get(r.get("name"))
            lost = (f" The same route in the inactive {'classic virtual router' if r.get('engine') == ADVANCED else 'advanced routing section'} still has path monitoring, so it was probably dropped when the routes were migrated."
                    if was and was.get("path_monitor") else "")
            backups = ", ".join(f"{b.get('name')} (metric {b.get('metric') if isinstance(b.get('metric'), int) else DEFAULT_METRIC}, {b.get('interface') or b.get('nexthop') or '-'})" for b in defaults if b is not r)
            out.append(finding("PAN-RT-005", "medium", "Routing", "Primary default route has no path monitoring or BFD", obj=f"route {r.get('name') or r['destination']} in {_where(r)}",
                               detail=f"{r.get('name')} (0.0.0.0/0 via {r.get('interface') or '-'}{' ' + r['nexthop'] if r.get('nexthop') else ''}, metric {metric}) is the preferred default route and the backup default route(s) {backups} only take over when this route disappears. "
                                      f"Without path monitoring or BFD the route stays installed while the link is up and the upstream is dead, so traffic is black-holed instead of failing over.{lost}",
                               recommendation="Enable path monitoring on the primary default route (ICMP to two or more reachable Internet addresses, failure condition 'all', short hold time) or attach a BFD profile.", reference=PALO["path_monitor"]))
    return out
