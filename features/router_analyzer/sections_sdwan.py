"""SD-WAN overlay tabs: OMP sessions, overlay routes, TLOCs, WAN interface identity, tunnel quality and the pushed policy.

Same contract as :mod:`.sections`: every builder takes the :class:`~.context.Ctx` and returns table /
key-value sections.  Values that identify the device to the controllers (token, serial numbers,
organization name) are read by the parser but never shown here.
"""

from __future__ import annotations

from typing import Any

from ..analyzer_core.result import kv_section, table_section
from .context import Ctx

GROUP = "SD-WAN overlay"
MAX_OMP_ROWS = 20000
_UNUSABLE_TONE = "warn"


def local_colors(ctx: Ctx) -> set[str]:
    """Transport colors this router has a tunnel interface, WAN interface or BFD session for."""
    colors: set[str] = set()
    colors |= {i["color"] for i in (ctx.get("sdwan_local") or {}).get("interfaces", []) if i.get("color")}
    colors |= {t["color"] for t in (ctx.sdwan_cfg or {}).get("tunnel_interfaces", []) if t.get("color")}
    colors |= {b["source_color"] for b in ctx.get("sdwan_bfd") or [] if b.get("source_color")}
    return colors


def sla_classes(ctx: Ctx) -> list[dict[str, Any]]:
    return (ctx.get("sdwan_policy") or {}).get("sla_classes", [])


def classes_met(tunnel: dict[str, Any], classes: list[dict[str, Any]]) -> list[str] | None:
    """Names of the SLA classes whose limits the tunnel's device-reported means stay within; None when a mean or the classes are missing."""
    values = (tunnel.get("mean_loss"), tunnel.get("mean_latency"), tunnel.get("mean_jitter"))
    if not classes or any(v is None for v in values):
        return None
    met = []
    for klass in classes:
        limits = (klass.get("loss"), klass.get("latency"), klass.get("jitter"))
        if all(limit is None or value <= limit for value, limit in zip(values, limits)):
            met.append(klass["name"])
    return met


def _num(value: Any) -> Any:
    return "" if value is None else value


def _code_meaning(status: str, legend: dict[str, str]) -> str:
    return ", ".join(legend.get(code, code) for code in status.split(","))


def omp(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    peers = ctx.get("sdwan_omp_peers")
    routes = ctx.get("sdwan_omp_routes")
    if peers is not None or routes:
        pairs: list[tuple] = []
        if peers:
            up = sum(1 for p in peers if p["state"] == "up")
            pairs.append(("OMP sessions up", f"{up} of {len(peers)}", "ok" if up == len(peers) else "bad"))
        if routes:
            usable = routes["prefix_count"] - routes["unusable_prefixes"]
            pairs.append(("Overlay prefixes", f"{routes['prefix_count']:,} in {len(routes['vpns'])} VPN(s) · {routes['paths']:,} paths", ""))
            pairs.append(("Prefixes with a resolved path", f"{usable:,}", "ok" if usable else "bad"))
            pairs.append(("Prefixes with no resolved path", f"{routes['unusable_prefixes']:,}", _UNUSABLE_TONE if routes["unusable_prefixes"] else "ok"))
            for vpn, count in sorted(routes["vpns"].items(), key=lambda kv: kv[0].zfill(8)):
                rib = sum(1 for r in ctx.routes if r.get("protocol") == "OMP" and str(r.get("vrf")) == vpn)
                if ctx.has("routes") and (rib or len(routes["vpns"]) == 1):
                    mine = sum(1 for r in routes["prefixes"] if r["vpn"] == vpn and r["installed"])
                    pairs.append((f"VPN {vpn}: installed in OMP vs routing table", f"{mine:,} OMP prefixes marked installed · {rib:,} OMP routes in 'show ip route vrf {vpn}'", "ok" if mine == rib else "warn"))
        sections.append(kv_section("sdwan_omp_summary", "OMP overview", pairs, group=GROUP,
                                   hint="'Resolved' follows the device's own legend (R). A path whose TLOC the router cannot resolve is printed Inv,U and is never installed."))
    if peers:
        rows = [dict(p, _tones={"state": "ok" if p["state"] == "up" else "bad"}) for p in peers]
        sections.append(table_section("sdwan_omp_peers", "OMP sessions", [("peer", "Peer", "mono"), ("type", "Type"), ("site_id", "Site"), ("domain_id", "Domain"), ("overlay_id", "Overlay"), ("state", "State", "status"), ("uptime", "Uptime (d:h:m:s)"),
                                                                     ("received", "Routes received", "num"), ("installed", "Installed", "num"), ("sent", "Sent", "num")], rows, group=GROUP,
                                      hint="Routes received / installed / sent. A second controller usually shows 0 installed because the first one's paths won."))
    if routes:
        legend = routes["legend"]
        total = routes["paths"]
        rows = []
        for status, count in sorted(routes["by_status"].items(), key=lambda kv: -kv[1]):
            flags = set(status.split(","))
            usable = "R" in flags and "Inv" not in flags
            rows.append({"status": status, "meaning": _code_meaning(status, legend), "paths": count, "share": f"{100 * count / total:.1f}%", "_tones": {"status": "ok" if usable else _UNUSABLE_TONE}})
        sections.append(table_section("sdwan_omp_status", "Overlay paths by status", [("status", "Status", "status"), ("meaning", "Meaning (device legend)", "wrap"), ("paths", "Paths", "num"), ("share", "Share")], rows, group=GROUP, searchable=False))
        mine = local_colors(ctx)
        bfd = ctx.get("sdwan_bfd") or []
        rows = []
        for color, slot in sorted(routes["by_color"].items(), key=lambda kv: -kv[1]["paths"]):
            sessions = sum(1 for b in bfd if b.get("remote_color") == color)
            rows.append({"color": color, "local": "Yes" if color in mine else "No", "paths": slot["paths"], "usable": slot["usable"], "unresolved": slot["unresolved"], "tlocs": slot["unresolved_tlocs"],
                         "bfd": sessions if bfd else "", "_tones": {"unresolved": _UNUSABLE_TONE if slot["unresolved"] else "", "usable": "ok" if slot["usable"] else ""}})
        sections.append(table_section("sdwan_omp_colors", "Overlay paths by remote color", [("color", "Remote color"), ("local", "Also a local color"), ("paths", "Paths", "num"), ("usable", "Resolved", "num"), ("unresolved", "Unresolved", "num"),
                                                                                   ("tlocs", "Unresolved TLOCs", "num"), ("bfd", "BFD sessions to this color", "num")], rows, group=GROUP, searchable=False,
                                      hint="Paths are grouped by the color of the TLOC they point at. 'BFD sessions to this color' counts captured BFD sessions whose remote color is this one."))
        shown = routes["prefixes"][:MAX_OMP_ROWS]
        rows = []
        for r in shown:
            usable = bool(r["usable"])
            rows.append({"vpn": r["vpn"], "prefix": r["prefix"], "paths": r["paths"], "usable_paths": r["usable"], "resolved": "Yes" if usable else "No", "via": r["best_color"] or "", "tloc": r["best_tloc"],
                         "colors": [f"{c} ×{n}" for c, n in sorted(r["colors"].items())], "statuses": [f"{s} ×{n}" for s, n in sorted(r["statuses"].items())],
                         "_tones": {"resolved": "ok" if usable else _UNUSABLE_TONE}})
        sections.append(table_section("sdwan_omp_prefixes", "Overlay prefixes", [("vpn", "VPN"), ("prefix", "Prefix", "mono"), ("resolved", "Resolved path", "status"), ("paths", "Paths", "num"), ("usable_paths", "Resolved paths", "num"),
                                                                           ("via", "Chosen color"), ("tloc", "Chosen TLOC", "mono"), ("colors", "Path colors", "list"), ("statuses", "Path status", "list")], rows, group=GROUP,
                                      total=routes["prefix_count"], page_size=100,
                                      facets=[{"key": "vpn", "label": "VPN", "prefix": "VPN "}, {"key": "resolved", "label": "resolved path", "order": ["Yes", "No"]}],
                                      hint=f"One row per prefix. 'Chosen' is the path the device marked C; a prefix without one is not installed in the VPN routing table."
                                           + (f" Only the first {MAX_OMP_ROWS:,} prefixes are listed." if routes["prefix_count"] > MAX_OMP_ROWS else "")))
    tlocs = ctx.get("sdwan_omp_tlocs")
    if tlocs:
        rows = []
        for t in tlocs[:5000]:
            rows.append({"tloc": t["tloc_ip"], "color": t["color"], "encap": t["encap"], "direction": "received from" if t["direction"] == "received" else "advertised to", "peer": t.get("peer", ""), "status": t.get("status", ""),
                         "bfd": t.get("bfd_status", ""), "site": t.get("site_id", ""), "preference": t.get("preference", ""), "restrict": t.get("restrict", ""), "carrier": t.get("carrier", ""), "crypto": t.get("encrypt", ""),
                         "_tones": {"bfd": "ok" if t.get("bfd_status") == "up" else ("bad" if t.get("bfd_status") else ""), "status": "ok" if "R" in t.get("status", "").split(",") and "Inv" not in t.get("status", "") else "warn"}})
        sections.append(table_section("sdwan_omp_tlocs", "Transport locators (TLOCs)", [("tloc", "TLOC system IP", "mono"), ("color", "Color"), ("encap", "Encap"), ("direction", "Direction"), ("peer", "Peer", "mono"), ("status", "Status", "status"),
                                                                                     ("bfd", "BFD", "status"), ("site", "Site"), ("preference", "Preference"), ("restrict", "Restrict"), ("carrier", "Carrier"), ("crypto", "Encryption")], rows, group=GROUP,
                                      total=len(tlocs), page_size=100, facets=[{"key": "direction", "label": "direction"}, {"key": "color", "label": "color"}]))
    return sections


_IDENTITY_KEYS = (
    ("personality", "Personality"), ("device-role", "Device role"), ("site-id", "Site ID"), ("domain-id", "Domain ID"), ("system-ip", "System IP"), ("protocol", "Control protocol"), ("region-id-set", "Regions"),
    ("certificate-status", "Certificate"), ("certificate-validity", "Certificate validity"), ("certificate-not-valid-before", "Valid from"), ("certificate-not-valid-after", "Valid until"),
    ("root-ca-chain-status", "Root CA chain"), ("root-ca-crl-status", "Root CA CRL"), ("enterprise-cert-status", "Enterprise certificate"), ("embargo-check", "Embargo check"),
    ("port-hopped", "Port-hopped"), ("time-since-last-port-hop", "Since last port hop (d:h:m:s)"), ("number-vbond-peers", "vBond peers"), ("number-active-wan-interfaces", "Active WAN interfaces"),
)


def identity(ctx: Ctx) -> list[dict[str, Any]]:
    local = ctx.get("sdwan_local")
    if not local:
        return []
    props = local["properties"]

    def tone(key: str, value: str) -> str:
        low = value.lower()
        if key == "certificate-validity":
            return "ok" if low == "valid" else "bad"
        if key in ("certificate-status", "root-ca-chain-status"):
            return "ok" if low == "installed" else "bad"
        if key == "embargo-check":
            return "ok" if low == "success" else "warn"
        return ""

    pairs = [(label, props[key], tone(key, props[key])) for key, label in _IDENTITY_KEYS if key in props]
    sections = [kv_section("sdwan_identity", "Control-plane identity", pairs, group=GROUP,
                           hint="Token, serial numbers and organization name are in the output but are deliberately not shown.")]
    rows = []
    for i in local["interfaces"]:
        shut = i["state"] != "up"
        rows.append({"interface": i["interface"], "color": i["color"], "state": i["state"], "public": f"{i['public_ip']}:{i['public_port']}", "private": f"{i['private_ip']}:{i['private_port']}", "nat": i["nat_type"],
                     "max": i["max_control"], "rcs": i["restrict_control_stun"], "lrlb": i["lr_lb"], "last": i["last_connection"], "spi": i["spi_remaining"],
                     "_tones": {"state": "bad" if shut else "ok", "nat": "warn" if i["nat_type"] == "A" else ""}})
    sections.append(table_section("sdwan_wan_interfaces", "WAN interfaces (TLOCs of this router)", [("interface", "Interface", "mono"), ("color", "Color"), ("state", "State", "status"), ("public", "Public address", "mono"), ("private", "Private address", "mono"),
                                                                                               ("nat", "NAT type"), ("max", "Max control conns"), ("rcs", "Restrict / control / STUN"), ("lrlb", "Last resort / low bandwidth"),
                                                                                               ("last", "Last control connection (d:h:m:s)"), ("spi", "SPI time remaining (d:h:m:s)")], rows, group=GROUP, searchable=False,
                                  hint="NAT type, as the device prints it: E endpoint-independent mapping, A address-port dependent mapping, N not learned (it needs at least two vBond peers)."))
    return sections


def tunnel_quality(ctx: Ctx) -> list[dict[str, Any]]:
    stats = ctx.get("sdwan_app_route")
    if not stats:
        return []
    classes = sla_classes(ctx)
    rows = []
    for t in stats:
        met = classes_met(t, classes)
        worst = {k: max((i.get(k) or 0 for i in t["intervals"]), default=None) for k in ("loss", "latency", "jitter")}
        verdict = "policy not captured" if met is None else ("meets none" if not met else f"{len(met)} of {len(classes)}")
        rows.append({"remote": t.get("remote_system_ip", ""), "local_color": t.get("local_color", ""), "remote_color": t.get("remote_color", ""), "proto": t["protocol"], "ports": f"{t['src_port']} → {t['dst_port']}",
                     "sla_index": t.get("sla_class_index", ""), "loss": _num(t.get("mean_loss")), "latency": _num(t.get("mean_latency")), "jitter": _num(t.get("mean_jitter")),
                     "worst_loss": _num(worst["loss"]), "worst_latency": _num(worst["latency"]), "worst_jitter": _num(worst["jitter"]), "intervals": len(t["intervals"]), "fit": verdict,
                     "_tones": {"fit": "bad" if met == [] else ("ok" if met else "mute")}})
    return [table_section("sdwan_tunnel_quality", "Tunnel quality (application-aware routing)", [
        ("remote", "Remote system IP", "mono"), ("local_color", "Local color"), ("remote_color", "Remote color"), ("proto", "Protocol"), ("ports", "Ports (local → remote)"), ("sla_index", "SLA class index"),
        ("loss", "Mean loss (%)", "num"), ("latency", "Mean latency (ms)", "num"), ("jitter", "Mean jitter (ms)", "num"), ("worst_loss", "Worst interval loss", "num"), ("worst_latency", "Worst interval latency (ms)", "num"),
        ("worst_jitter", "Worst interval jitter (ms)", "num"), ("intervals", "Intervals", "num"), ("fit", "SLA classes met", "status")], rows, group=GROUP, searchable=False,
        hint="Means are the device's own figures over the sliding interval window; the worst-interval columns are the largest single-interval values in that window. "
             "'SLA classes met' compares the means with the SLA classes of the pushed policy (loss in %, latency and jitter in ms).")]


def policy(ctx: Ctx) -> list[dict[str, Any]]:
    data = ctx.get("sdwan_policy")
    if not data:
        return []
    sections: list[dict[str, Any]] = []
    used: dict[str, int] = {}
    rules_rows: list[dict[str, Any]] = []
    for pol in data["policies"]:
        for vpn_list in pol["vpn_lists"]:
            for seq in vpn_list["sequences"]:
                act = seq["action"]
                if act["sla_class"]:
                    used[act["sla_class"]] = used.get(act["sla_class"], 0) + 1
                rules_rows.append({"policy": pol["name"], "vpn_list": vpn_list["name"], "sequence": seq["sequence"], "match": [f"{k} {v}".strip() for k, v in seq["match"].items()] or ["(all traffic)"],
                                   "sla_class": act["sla_class"], "strict": "Yes" if act["strict"] else "No", "preferred": act["preferred_colors"], "backup": act["backup_color"],
                                   "other": act["other"], "_tones": {"strict": "warn" if act["strict"] else ""}})
    sections.append(table_section("sdwan_sla_classes", "SLA classes (centralized policy)", [("name", "SLA class"), ("loss", "Max loss (%)", "num"), ("latency", "Max latency (ms)", "num"), ("jitter", "Max jitter (ms)", "num"), ("used", "Rules using it", "num")],
                                  [dict(c, used=used.get(c["name"], 0)) for c in data["sla_classes"]], group=GROUP, searchable=False, empty="The policy carries no SLA class.",
                                  hint="Application-aware routing keeps a tunnel eligible for a class while its mean loss, latency and jitter stay within these limits."))
    sections.append(table_section("sdwan_aar_rules", "Application-aware routing rules", [("policy", "Policy"), ("vpn_list", "VPN list"), ("sequence", "Seq", "num"), ("match", "Match", "list"), ("sla_class", "SLA class"), ("strict", "Strict", "status"),
                                                                                       ("preferred", "Preferred color", "list"), ("backup", "Backup SLA preferred color"), ("other", "Other actions", "list")], rules_rows, group=GROUP, page_size=100,
                                  empty="The policy carries no application-aware routing rule.",
                                  hint="Strict means traffic is dropped when no tunnel meets the SLA class; without it the router falls back to the backup color or any available tunnel (Cisco: Application-Aware Routing)."))
    list_rows = []
    for item in data["lists"]:
        entries = item["entries"]
        list_rows.append({"kind": item["kind"], "name": item["name"], "count": len(entries), "entries": entries[:12] + ([f"… +{len(entries) - 12} more"] if len(entries) > 12 else [])})
    sections.append(table_section("sdwan_policy_lists", "Policy lists", [("kind", "List type"), ("name", "Name"), ("count", "Entries", "num"), ("entries", "Entries (first 12)", "list")], list_rows, group=GROUP, page_size=100,
                                  facets=[{"key": "kind", "label": "type"}], empty="The policy carries no lists."))
    if data["other"]:
        sections.append(table_section("sdwan_policy_other", "Other policy objects (not interpreted)", [("heading", "Object", "mono"), ("lines", "Lines", "num")], data["other"], group=GROUP, searchable=False))
    return sections


def overlay(ctx: Ctx) -> list[dict[str, Any]]:
    if not ctx.dialect.get("sdwan") and not any(ctx.has(key) for key in ("sdwan_omp_peers", "sdwan_omp_routes", "sdwan_omp_tlocs", "sdwan_local", "sdwan_app_route", "sdwan_policy")):
        return []
    out: list[dict[str, Any]] = []
    for builder in (omp, identity, tunnel_quality, policy):
        out.extend(builder(ctx))
    return out
