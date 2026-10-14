"""Router Analyzer entry point: terminal capture in, ``keystone.analysis/1`` out.

``analyze`` accepts

* a terminal log of a Cisco IOS / IOS-XE / IOS-XE SD-WAN router (prompts,
  commands and output, including abbreviated and failed commands), or
* a bare ``show running-config`` export without prompts.

It never raises for a missing command: whatever the capture contains is
analysed and the Coverage tab lists what was missing and what it would add.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from ..analyzer_core.findings import severity_counts
from ..analyzer_core.result import card, info_rows, new_result
from . import context as ctxmod
from . import rules, sections as sec
from .context import bgp_sessions

# parsers written from Cisco's documented output format but not yet run on a real capture
# (show version and show ip bgp summary left this list when real INET2 / PRJ / BH / PTNR2 / JKT captures confirmed them;
#  show ip ospf neighbor / interface brief, show ntp status and show crypto isakmp sa left it on the 2026-10 ASR captures;
#  show vrrp brief and show standby brief have only been seen without rows, so they stay here)
UNVALIDATED = {
    "eigrp_neighbors": "show ip eigrp neighbors", "standby": "show standby brief", "vrrp": "show vrrp brief",
}

COVERAGE_TONE = {"analysed": "ok", "covered": "info", "ignored": "mute", "not parsed": "warn", "error": "bad", "missing": "warn"}


def analyze(content: str, filename: str = "", platform: str = "auto") -> dict[str, Any]:
    ctx = ctxmod.gather(content, filename)
    if not ctx.used_blocks:
        switchy = ctx.capture is not None and any(b.norm.startswith(("show vlan", "show spanning", "show mac", "show interfaces status", "show etherchannel", "display ")) for b in ctx.capture.blocks)
        raise ValueError(
            ("This looks like a switch capture — open the Switch Analyzer for it. " if switchy else "")
            + "No router configuration or supported router show output was recognised. The Router Analyzer reads 'show running-config', 'show ip route', "
              "'show ip bgp', 'show interfaces' and the other commands listed on the Collect tab."
        )
    findings = rules.evaluate(ctx)
    built = sec.build_all(ctx)
    d = ctx.dialect
    model = d.get("model") or "Cisco router"

    result = new_result(
        "router",
        hostname=ctx.hostname or filename.rsplit(".", 1)[0],
        vendor="Cisco",
        platform=f"{model} · {d.get('family', '')}".strip(" ·"),
        source_name=filename,
        title=ctx.hostname or "Router",
        subtitle=_subtitle(d, model),
    )
    result["cards"] = _cards(ctx, findings)
    known = {item["id"] for item in built} | {"findings", "overview", "coverage"}
    for item in result["cards"]:
        if item.get("section") and item["section"] not in known:
            item["section"] = ""
    result["info"] = _info(ctx)
    result["findings"] = findings
    result["sections"] = built
    result["coverage"] = _coverage(ctx)
    result["warnings"] = list(ctx.warnings) + _notes(ctx)
    result["capture"] = {"commands": len(ctx.capture.blocks) if ctx.capture else 0, "lines": ctx.capture.raw_lines if ctx.capture else 0, "has_config": ctx.cfg is not None}
    return result


# ---------------------------------------------------------------------------


def _subtitle(d: dict[str, Any], model: str) -> str:
    release, family = d.get("release", ""), d.get("family", "")
    if release.startswith("IOS-XE") and family.startswith("IOS-XE"):
        return " · ".join(filter(None, [model, release, "SD-WAN cEdge" if d.get("sdwan") else ""]))
    return " · ".join(filter(None, [model, family, release]))


def _cards(ctx: ctxmod.Ctx, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards = []
    d = ctx.dialect
    cards.append(card("Platform", d.get("model") or "Cisco", "info", " · ".join(filter(None, [d.get("family"), d.get("release")])), "device"))

    states = Counter()
    for rec in ctx.interfaces:
        cfg, brief = rec.get("config") or {}, rec.get("brief") or {}
        if cfg.get("shutdown") or brief.get("status") == "administratively down":
            states["admin"] += 1
        elif brief:
            states["up" if brief.get("protocol") == "up" else "down"] += 1
        elif rec.get("stats"):
            states["up" if rec["stats"].get("protocol") == "up" else "down"] += 1
        else:
            states["unknown"] += 1
    total = sum(states.values())
    if total:
        known_live = states["up"] + states["down"]
        hint = f"{states['admin']} admin down" + (f", {states['down']} down" if states["down"] else "") + ("" if known_live else " · live state not captured")
        cards.append(card("Interfaces up", f"{states['up']}/{total}" if known_live else str(total), "warn" if states["down"] else ("ok" if known_live else "mute"), hint, "interfaces"))

    if ctx.has("routes"):
        counts: Counter = Counter()
        for route in ctx.routes:
            counts[route["protocol"]] += 1
        top = ", ".join(f"{name} {count:,}" for name, count in counts.most_common(3))
        cards.append(card("Routes", f"{len(ctx.routes):,}", "info", top, "route_summary"))
    else:
        cards.append(card("Routes", "not captured", "mute", "add 'show ip route'", "routes"))

    sessions = bgp_sessions(ctx)
    if sessions:
        active = [s for s in sessions if not s.get("admin_shutdown")]
        established = [s for s in active if s["state"] == "Established"]
        shut = len(sessions) - len(active)
        cards.append(card("BGP sessions", f"{len(established)}/{len(active)}", "bad" if len(established) < len(active) else "ok",
                          f"established / active · {shut} admin shut" if shut else "established / active", "bgp_neighbors"))
    elif ctx.cfg and ctx.cfg.get("bgp"):
        neighbors = sum(1 for p in ctx.cfg["bgp"] for n in p["neighbors"] if not n["is_peer_group"])
        cards.append(card("BGP neighbors", str(neighbors), "mute", "configured · state not captured", "bgp_process"))

    if ctx.cfg:
        undefined = len(ctx.xref["undefined"]) if ctx.xref else 0
        unused = sum(1 for kind, names in (ctx.xref["defined"].items() if ctx.xref else []) for name in names if not _used(ctx, kind, name))
        cards.append(card("ACLs", str(len(ctx.cfg["acls"])), "bad" if undefined else "info", f"{undefined} undefined reference(s) · {unused} object(s) unreferenced", "undefined_refs" if undefined else "objects"))

    _health_cards(ctx, cards)
    nat = ctx.models.get("nat")
    if nat:
        stats = nat.get("stats") or {}
        limit = stats.get("limit") or {}
        if stats:
            pct = round(100 * limit.get("used", 0) / limit["max"], 1) if limit.get("max") else None
            hint = f"{pct}% of the {limit['max']:,} limit · " if pct is not None else ""
            tone = "bad" if (limit.get("missed") or (pct or 0) >= 95) else ("warn" if (pct or 0) >= 80 or any((p.get("misses") or 0) for p in nat["pools"]) else "ok")
            cards.append(card("NAT translations", f"{stats.get('total', 0):,}", tone, f"{hint}{len(nat['dynamic'])} rules · {len(nat['static'])} static", "nat_summary"))
        else:
            cards.append(card("NAT", f"{len(nat['dynamic'])} rules", "mute", f"{len(nat['pools'])} pools · {len(nat['static'])} static · no live statistics", "nat_summary"))
    ipsec = ctx.models.get("ipsec")
    ospf = ctx.models.get("ospf")
    if ospf and ospf.get("processes"):
        states = [p["state"] for p in ospf["processes"]]
        bad = [s for s in states if s != "running"]
        ifaces = len(ospf["interfaces"])
        live = f"{ospf['up']}/{ospf['neighbors']} neighbours FULL" if ospf["neighbors"] else f"{ifaces} interface(s) enabled"
        cards.append(card("OSPF", "running" if not bad else ("no interface" if states == ["empty"] else "check"), "ok" if not bad else "warn", live + ("" if not bad else " · " + ", ".join(bad)), "ospf_state"))
    gdoi = ctx.get("gdoi")
    sessions_vpn = ctx.get("crypto_session") or []
    if ipsec and ipsec.get("tunnels"):
        weak = sum(1 for t in ipsec["tunnels"] if t["weak"])
        serious = sum(1 for i in ipsec["issues"] if i["severity"] == "high")
        cards.append(card("IPsec tunnels", str(len(ipsec["tunnels"])), "bad" if serious else ("warn" if weak or ipsec["reuse"] else "ok"),
                          f"{ipsec['peer_count']} peers · {weak} with weak crypto" + (f" · {serious} configuration error(s)" if serious else ""), "vpn_tunnels"))
    if gdoi is not None:
        cards.append(card("GETVPN", "registered" if gdoi.get("active_ks") else "not registered", "ok" if gdoi.get("active_ks") else "bad",
                          f"key server {gdoi.get('active_ks')}" if gdoi.get("active_ks") else "no active key server", "gdoi_state"))
    elif sessions_vpn:
        up = sum(1 for s in sessions_vpn if s.get("status") == "UP-ACTIVE")
        cards.append(card("Crypto sessions", f"{up}/{len(sessions_vpn)}", "ok" if up == len(sessions_vpn) else "bad", "UP-ACTIVE", "crypto_sessions"))
    elif ctx.cfg and not (ipsec and ipsec.get("tunnels")) and (ctx.cfg["crypto"]["crypto_maps"] or ctx.cfg["crypto"]["gdoi_groups"] or ctx.cfg["crypto"]["isakmp_policies"]):
        cards.append(card("VPN", "configured", "mute", "no live crypto state captured", "ike_policies"))

    if d.get("sdwan"):
        control = ctx.get("sdwan_control") or []
        bfd = ctx.get("sdwan_bfd") or []
        sd_status = ctx.get("sdwan_status") or {}
        managed = str(sd_status.get("vManaged", "")).strip().lower()
        if managed in ("true", "false"):
            template = sd_status.get("Configuration template", "")
            cards.append(card("vManage", managed, "ok" if managed == "true" else "warn",
                              f"template {template}" if managed == "true" and template else "CLI mode · no template attached", "sdwan_status"))
        if control or bfd:
            c_up, b_up = sum(1 for c in control if c.get("state") == "up"), sum(1 for b in bfd if b.get("state") == "up")
            ok = (not control or c_up == len(control)) and (not bfd or b_up == len(bfd))
            cards.append(card("SD-WAN", f"{c_up}/{len(control)} ctl · {b_up}/{len(bfd)} BFD", "ok" if ok else "bad", "control connections · overlay tunnels up", "sdwan_control"))

    counts = severity_counts(findings)
    cards.append(card("High findings", counts["high"], "bad" if counts["high"] else "ok", "", "findings"))
    cards.append(card("Medium findings", counts["medium"], "warn" if counts["medium"] else "ok", f"{counts['low']} low · {counts['info']} info", "findings"))
    return cards


def _health_cards(ctx: ctxmod.Ctx, cards: list[dict[str, Any]]) -> None:
    cpu = ctx.get("cpu")
    pools = ((ctx.get("memory_statistics") or {}).get("pools")) or ((ctx.get("process_memory") or {}).get("pools")) or []
    processor = next((p for p in pools if p["pool"] == "Processor"), None)
    if cpu and cpu.get("five_min") is not None:
        value = f"{cpu['five_min']}%" + (f" · {processor['used_pct']:g}%" if processor else "")
        worst = max(cpu["five_min"], processor["used_pct"] if processor else 0)
        cards.append(card("CPU · memory", value, "bad" if worst >= 85 else ("warn" if worst >= 70 else "ok"), "control-plane CPU (5 min) · IOS memory used", "health_summary"))
    elif processor:
        cards.append(card("IOS memory", f"{processor['used_pct']:g}%", "bad" if processor["used_pct"] >= 90 else ("warn" if processor["used_pct"] >= 80 else "ok"), "Processor pool used", "memory_pools"))
    util = ctx.get("qfp_utilization")
    if util:
        peak = util["processing_peak"]
        cards.append(card("QFP load", f"{util['processing_5min']}%", "bad" if peak >= 85 else ("warn" if peak >= 70 else "ok"), f"forwarding plane, 5 min · peak {peak}%", "qfp_load"))


def _used(ctx: ctxmod.Ctx, kind: str, name: str) -> bool:
    from . import xref

    return xref.is_used(ctx.xref, kind, name)


def _info(ctx: ctxmod.Ctx) -> list[dict[str, Any]]:
    d = ctx.dialect
    system = (ctx.cfg or {}).get("system", {})
    version = ctx.get("version") or {}
    sd_status = ctx.get("sdwan_status") or {}
    pairs = [
        ("Hostname", ctx.hostname), ("Model", d.get("model")), ("Serial number", d.get("serial")), ("Platform family", d.get("family")),
        ("Operating mode", version.get("operating_mode")), ("SD-WAN role", sd_status.get("Device role")), ("vManaged", sd_status.get("vManaged")),
        ("Configuration template", sd_status.get("Configuration template")), ("Commit pending", sd_status.get("Commit pending")), ("Software", d.get("release") or (f"config version {d.get('config_version')}" if d.get("config_version") else "")),
        ("Boot image", ", ".join(d.get("images", []))), ("Release train", version.get("release_name")), ("Boot mode", {"install": "install (packages.conf)", "bundle": "bundle (.bin)"}.get(version.get("boot_mode", ""), "")),
        ("Uptime", version.get("uptime")), ("Last reload reason", version.get("last_reload_reason")), ("Licensing", version.get("smart_licensing")), ("Capture time", ctx.get("clock")), ("Last config change", system.get("last_change")),
        ("NVRAM last saved", system.get("nvram_updated")), ("Domain", system.get("domain_name")), ("Time zone", system.get("timezone")),
        ("Capture", f"{len(ctx.capture.blocks)} commands · {ctx.capture.raw_lines:,} lines" if ctx.capture else ""),
    ]
    return info_rows(pairs)


def _coverage(ctx: ctxmod.Ctx) -> list[dict[str, Any]]:
    rows = [{"command": r["command"], "status": r["status"], "lines": r["lines"], "note": r["note"], "tone": COVERAGE_TONE.get(r["status"], "")} for r in ctx.coverage]
    for gap in ctxmod.missing_commands(ctx):
        rows.append({"command": gap["command"], "status": "missing", "lines": 0, "note": "Not in this capture — would add: " + gap["why"], "tone": "warn"})
    return rows


def _notes(ctx: ctxmod.Ctx) -> list[str]:
    used = [label for key, label in UNVALIDATED.items() if ctx.has(key)]
    if not used:
        return []
    return ["Parsed from Cisco's documented output format but not yet validated against a real capture: " + ", ".join(used) + ". Check these tables against the device before relying on them."]
