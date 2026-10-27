"""SD-WAN overlay tabs: OMP sessions, overlay routes, TLOCs, WAN interface identity, tunnel quality and the pushed policy.

Same contract as :mod:`.sections`: every builder takes the :class:`~.context.Ctx` and returns table /
key-value sections.  Values that identify the device to the controllers (token, serial numbers,
organization name) are read by the parser but never shown here.
"""

from __future__ import annotations

from typing import Any

from datetime import datetime

from ..analyzer_core.result import kv_section, table_section
from .context import Ctx
from . import runtime_sdwan_extra as rse
from .netutil import human_bytes

GROUP = "SD-WAN overlay"
MAX_OMP_ROWS = 20000
MAX_TUNNEL_ROWS = 5000
ONE_WAY_MIN_PACKETS = 1000     # a tunnel's BFD hellos alone exceed this within minutes, so zero received after this many sent is not a quiet tunnel
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


def omp_counters(ctx: Ctx, summary: dict[str, Any], peers: list[dict[str, Any]] | None) -> dict[str, Any]:
    """'show sdwan omp summary': the router's own OMP counters, with the vSmart count checked against the OMP session table when both were captured."""
    up = summary.get("oper_state", "").upper() == "UP"
    count = summary.get("vsmart_peers")
    pairs: list[tuple] = [("OMP operational state", summary.get("oper_state", ""), "ok" if up else "bad"), ("OMP administrative state", summary.get("admin_state", ""), "ok" if summary.get("admin_state", "").upper() == "UP" else "warn"),
                          ("OMP uptime (d:h:m:s)", summary.get("omp_uptime", ""), "")]
    if count is not None:
        pairs.append(("vSmart controllers connected", count, "bad" if count == 0 else ("warn" if count == 1 else "ok")))
        if peers is not None:
            sessions = sum(1 for p in peers if p["type"] == "vsmart" and p["state"] == "up")
            pairs.append(("vSmart sessions up in 'show sdwan omp peers'", sessions, "ok" if sessions == count else "warn"))
    for key, label in (("routes", "Routes"), ("tlocs", "TLOCs"), ("services", "Services")):
        got, inst, sent = summary.get(f"{key}_received"), summary.get(f"{key}_installed"), summary.get(f"{key}_sent")
        if got is not None:
            pairs.append((f"{label} received / installed / sent", f"{got:,} / {inst if inst is None else format(inst, ',')} / {sent if sent is None else format(sent, ',')}", ""))
    for label, sent, received in (("OMP hello", "hello_sent", "hello_received"), ("OMP update", "update_sent", "update_received"), ("OMP handshake", "handshake_sent", "handshake_received"),
                                  ("OMP alert", "alert_sent", "alert_received"), ("OMP inform", "inform_sent", "inform_received"), ("Policy messages", "policy_sent", "policy_received")):
        if sent in summary:
            tone = "warn" if label == "OMP alert" and (summary[sent] or summary.get(received)) else ""
            pairs.append((f"{label} sent / received", f"{summary[sent]:,} / {summary.get(received, 0):,}", tone))
    return kv_section("sdwan_omp_counters", "OMP summary (this router)", pairs, group=GROUP,
                      hint="'show sdwan omp summary'. Cisco's API page for the same data lists these counters without defining them; sent and received hello counts that drift far apart, or a rising alert count, "
                           "point at an unstable control channel. A router normally shows 2 vSmart controllers.")


def omp(ctx: Ctx) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    peers = ctx.get("sdwan_omp_peers")
    routes = ctx.get("sdwan_omp_routes")
    summary = ctx.get("sdwan_omp_summary")
    if summary:
        sections.append(omp_counters(ctx, summary, peers))
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
                                      hint="Routes received / installed / sent. A second controller usually shows 0 installed because the first one's paths won.", facets=[{"key": "state", "label": "state"}]))
    if routes:
        legend = routes["legend"]
        total = routes["paths"]
        rows = []
        for status, count in sorted(routes["by_status"].items(), key=lambda kv: -kv[1]):
            flags = set(status.split(","))
            usable = "R" in flags and "Inv" not in flags
            rows.append({"status": status, "meaning": _code_meaning(status, legend), "paths": count, "share": f"{100 * count / total:.1f}%", "_tones": {"status": "ok" if usable else _UNUSABLE_TONE}})
        sections.append(table_section("sdwan_omp_status", "Overlay paths by status", [("status", "Status", "status"), ("meaning", "Meaning (device legend)", "wrap"), ("paths", "Paths", "num"), ("share", "Share")], rows, group=GROUP, searchable=False, facets=[{"key": "status", "label": "status"}]))
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
                                  hint="NAT type, as the device prints it: E endpoint-independent mapping, A address-port dependent mapping, N not learned (it needs at least two vBond peers).", facets=[{"key": "state", "label": "state"}]))
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


# ---------------------------------------------------------------------------
# Certificates, tunnel traffic, BFD history
# ---------------------------------------------------------------------------


def stamp_text(stamp: str) -> str:
    """ISO stamp -> 'YYYY-MM-DD HH:MM:SS' (the stamps are the router's own wall clock)."""
    return stamp.replace("T", " ") if stamp else ""


def days_left(stamp: str, now: datetime | None) -> int | None:
    """Whole days from the capture clock to an ISO stamp; negative when it is in the past, None without a clock or stamp."""
    if not stamp or now is None:
        return None
    try:
        return int((datetime.fromisoformat(stamp) - now).total_seconds() / 86400)     # whole days, toward zero
    except ValueError:
        return None


def days_ago(stamp: str, now: datetime | None) -> float | None:
    """Days from an ISO stamp up to the capture clock (negative when the stamp is later), None when either is missing."""
    if not stamp or now is None:
        return None
    try:
        return (now - datetime.fromisoformat(stamp)).total_seconds() / 86400
    except ValueError:
        return None


def cert_tone(days: int | None) -> str:
    if days is None:
        return ""
    return "bad" if days <= 30 else ("warn" if days <= 90 else "ok")


def certificates(ctx: Ctx) -> list[dict[str, Any]]:
    data = ctx.get("sdwan_certificates")
    if not data:
        return []
    now = ctx.capture_time()
    rows = []
    for c in data["certificates"]:
        days = days_left(c["not_after"], now)
        rows.append({"section": c["section"], "subject": c["subject"].get("CN", ""), "organization": c["subject"].get("O", ""), "issuer": c["issuer"].get("CN", ""), "valid_from": c["not_before"][:10], "valid_until": c["not_after"][:10],
                     "days": "expired" if days is not None and days < 0 else ("" if days is None else days), "key": f"{c['key_bits']} bit" if c["key_bits"] else "", "algorithm": c["algorithm"],
                     "_tones": {"days": cert_tone(days), "valid_until": cert_tone(days)}})
    empty = ", ".join(data["empty_sections"])
    return [table_section("sdwan_certificates", "Installed certificates", [("section", "Section"), ("subject", "Subject (CN)"), ("organization", "Organization"), ("issuer", "Issuer (CN)"), ("valid_from", "Valid from"), ("valid_until", "Valid until"),
                                                                       ("days", "Days left at capture", "num"), ("key", "Key"), ("algorithm", "Signature")], rows, group=GROUP, searchable=False,
                          empty="The command printed no certificate.",
                          hint=("The serial number of the router is in the subject but is deliberately not shown. " + (f"No certificate is printed under: {empty}. " if empty else "")
                                + ("Days are counted from 'show clock' of the capture." if now else "'show clock' was not captured, so the days left cannot be counted.")))]


def tunnel_flag(t: dict[str, Any]) -> str:
    tx, rx = t.get("tx_pkts"), t.get("rx_pkts")
    if tx is None or rx is None:
        return ""
    if rx == 0 and tx >= ONE_WAY_MIN_PACKETS:
        return "sends only"
    if tx == 0 and rx >= ONE_WAY_MIN_PACKETS:
        return "receives only"
    if tx == 0 and rx == 0:
        return "no traffic"
    return "both ways"


def tunnel_traffic(ctx: Ctx) -> list[dict[str, Any]]:
    tunnels = ctx.get("sdwan_tunnel_stats")
    if not tunnels:
        return []
    rows = []
    for t in tunnels[:MAX_TUNNEL_ROWS]:
        flag = tunnel_flag(t)
        tx, rx = t.get("tx_pkts"), t.get("rx_pkts")
        rows.append({"remote": t["system_ip"], "local_color": t["local_color"], "remote_color": t["remote_color"], "src": f"{t['src_ip']}:{t['src_port']}", "dst": f"{t['dst_ip']}:{t['dst_port']}", "mtu": _num(t["mtu"]), "mss": _num(t["tcp_mss"]),
                     "tx": _num(tx), "rx": _num(rx), "tx_bytes": human_bytes(t["tx_octets"]) if t["tx_octets"] is not None else "", "rx_bytes": human_bytes(t["rx_octets"]) if t["rx_octets"] is not None else "", "flag": flag,
                     "_tones": {"flag": "bad" if flag in ("sends only", "receives only") else ("mute" if flag == "no traffic" else "ok")}})
    by_pair: dict[tuple[str, str], dict[str, int]] = {}
    for t in tunnels:
        slot = by_pair.setdefault((t["local_color"], t["remote_color"]), {"tunnels": 0, "one_way": 0, "tx": 0, "rx": 0})
        slot["tunnels"] += 1
        slot["one_way"] += 1 if tunnel_flag(t) in ("sends only", "receives only") else 0
        slot["tx"] += t["tx_octets"] or 0
        slot["rx"] += t["rx_octets"] or 0
    pair_rows = [{"local_color": a, "remote_color": b, "tunnels": v["tunnels"], "one_way": v["one_way"], "tx": human_bytes(v["tx"]), "rx": human_bytes(v["rx"]), "_tones": {"one_way": "bad" if v["one_way"] else ""}}
                 for (a, b), v in sorted(by_pair.items(), key=lambda kv: -kv[1]["tunnels"])]
    return [
        table_section("sdwan_tunnel_pairs", "Overlay tunnels by color pair", [("local_color", "Local color"), ("remote_color", "Remote color"), ("tunnels", "Tunnels", "num"), ("one_way", "Sending or receiving only", "num"),
                                                                        ("tx", "Sent (total)"), ("rx", "Received (total)")], pair_rows, group=GROUP, searchable=False,
                      hint="'show sdwan tunnel statistics': IPv4 counters since each tunnel came up. Sent and received octets differ legitimately (a branch downloads more than it uploads); a tunnel that only sends is the symptom to look for."),
        table_section("sdwan_tunnel_traffic", "Overlay tunnel traffic", [("remote", "Remote system IP", "mono"), ("local_color", "Local color"), ("remote_color", "Remote color"), ("src", "Local endpoint", "mono"), ("dst", "Remote endpoint", "mono"),
                                                                       ("mtu", "Tunnel MTU", "num"), ("mss", "TCP MSS adjust", "num"), ("tx", "Packets sent", "num"), ("rx", "Packets received", "num"), ("tx_bytes", "Sent"), ("rx_bytes", "Received"),
                                                                       ("flag", "Direction", "status")], rows, group=GROUP, total=len(tunnels), page_size=100,
                      facets=[{"key": "flag", "label": "direction"}, {"key": "local_color", "label": "local color"}, {"key": "remote_color", "label": "remote color"}],
                      hint=f"One row per tunnel. 'Sends only' means at least {ONE_WAY_MIN_PACKETS:,} packets sent and none received: the peer's BFD hellos never come back. Tunnel MTU is the value path MTU discovery settled on."
                           + (f" Only the first {MAX_TUNNEL_ROWS:,} tunnels are listed." if len(tunnels) > MAX_TUNNEL_ROWS else "")),
    ]


def bfd_history_summary(ctx: Ctx) -> dict[str, Any] | None:
    rows = ctx.get("sdwan_bfd_history")
    if not rows:
        return None
    cached = ctx.models.get("bfd_history")
    if cached is None:
        cached = ctx.models["bfd_history"] = rse.summarize_bfd_history(rows)
    return cached


def live_bfd_state(ctx: Ctx, system_ip: str, color: str) -> tuple[str, str]:
    """('2 up', tone) from 'show sdwan bfd sessions' for the sessions to one remote TLOC; ('', '') when that table was not captured or lists none."""
    sessions = [b for b in ctx.get("sdwan_bfd") or [] if b.get("system_ip") == system_ip and b.get("remote_color") == color]
    if not sessions:
        return "", ""
    counts: dict[str, int] = {}
    for b in sessions:
        counts[b.get("state", "?")] = counts.get(b.get("state", "?"), 0) + 1
    text = ", ".join(f"{n} {state}" for state, n in sorted(counts.items(), key=lambda kv: kv[0] != "up"))
    return text, "ok" if set(counts) == {"up"} else "bad"


def bfd_history(ctx: Ctx) -> list[dict[str, Any]]:
    summary = bfd_history_summary(ctx)
    if not summary:
        return []
    now = ctx.capture_time()
    out: list[dict[str, Any]] = []
    pairs = [("Records", f"{summary['rows']:,}", ""), ("First record", stamp_text(summary["first"]), ""), ("Last record", stamp_text(summary["last"]), ""), ("Remote TLOCs", len(summary["sessions"]), ""),
             ("Drops (a tunnel that had carried packets went down)", summary["drops"], "warn" if summary["drops"] else "ok"),
             ("Moments when two or more remote TLOCs dropped together", len(summary["bursts"]), "warn" if summary["bursts"] else "ok")]
    quiet = days_between_text(summary["last"], now)
    if quiet:
        pairs.append(("Last record before the capture", quiet, ""))
    out.append(kv_section("sdwan_bfd_history_overview", "BFD history overview", pairs, group=GROUP,
                          hint="'show sdwan bfd history'. The router keeps a limited number of records, so the first record is the start of what it still remembers, not of the session. "
                               "The output has no local-color column: tunnels from two local colors to the same remote TLOC are listed together. "
                               "Cisco does not document the DEL column; a down record with DEL 1 is read as the deletion marker that the device writes in the same second as the final down record, and is not counted as a drop."))
    rows = []
    for s_ in summary["sessions"]:
        live, live_tone = live_bfd_state(ctx, s_["system_ip"], s_["color"])
        rows.append({"remote": s_["system_ip"], "site": s_["site_id"], "color": s_["color"], "dst": s_["dst_ip"], "ports": s_["ports"], "ups": s_["ups"], "drops": s_["drops"], "attempts": s_["attempts"], "teardowns": s_["teardowns"],
                     "first": stamp_text(s_["first"]), "last": stamp_text(s_["last"]), "state": s_["last_state"], "last_drop": stamp_text(s_["last_drop"]), "since": days_between_text(s_["last_drop"], now) if s_["last_drop"] else "",
                     "live": live, "_tones": {"drops": "warn" if s_["drops"] else "", "live": live_tone}})
    out.append(table_section("sdwan_bfd_history_sessions", "BFD history by remote TLOC", [("remote", "Remote system IP", "mono"), ("site", "Site"), ("color", "Color"), ("dst", "Remote public IP", "mono"), ("ports", "Port(s)", "list"),
                                                                                       ("ups", "Up records", "num"), ("drops", "Drops", "num"), ("attempts", "Down with no traffic", "num"), ("teardowns", "Deletion markers (DEL 1)", "num"),
                                                                                       ("first", "First record"), ("last", "Last record"), ("last_drop", "Last drop"), ("since", "Last drop before capture"), ("live", "Now (show sdwan bfd sessions)", "status")],
                              rows, group=GROUP, page_size=100, facets=[{"key": "color", "label": "color"}],
                              hint="A drop is a down record that carries packet counters. 'Down with no traffic' is a down record with zero counters and DEL 0: a tunnel that did not come up, or the first state after a restart. "
                                   "The remote port may change when the far router restarts or its NAT re-maps, so rows are keyed by remote address, not by port. The history cannot say whether a tunnel is up now: the last column takes that from 'show sdwan bfd sessions'."))
    if summary["bursts"]:
        out.append(table_section("sdwan_bfd_history_bursts", "Remote TLOCs that dropped together", [("time", "First drop"), ("sessions", "Remote TLOCs", "num"), ("seconds", "Spread (s)", "num"), ("colors", "Colors", "list"), ("remotes", "Remote system IPs", "list")],
                                 [{"time": stamp_text(b["time"]), "sessions": b["sessions"], "seconds": b["seconds"], "colors": b["colors"], "remotes": b["remotes"]} for b in summary["bursts"]], group=GROUP, page_size=100,
                                 hint="Drops toward different remote TLOCs at most 10 seconds apart. Several remote sites failing at the same second points at this router's own transport (WAN link, interface, NAT or ACL) rather than at each remote site."))
    return out


def days_between_text(stamp: str, now: datetime | None) -> str:
    """'3 days 5 h' between an ISO stamp and the capture clock, '' when either is missing or the stamp is later."""
    if not stamp or now is None:
        return ""
    try:
        seconds = (now - datetime.fromisoformat(stamp)).total_seconds()
    except ValueError:
        return ""
    if seconds < 0:
        return ""
    days, rest = divmod(int(seconds), 86400)
    return f"{days} d {rest // 3600} h" if days else f"{rest // 3600} h {rest % 3600 // 60} min"


def overlay(ctx: Ctx) -> list[dict[str, Any]]:
    if not ctx.dialect.get("sdwan") and not any(ctx.has(key) for key in ("sdwan_omp_peers", "sdwan_omp_routes", "sdwan_omp_tlocs", "sdwan_local", "sdwan_app_route", "sdwan_policy", "sdwan_omp_summary", "sdwan_certificates",
                                                                       "sdwan_tunnel_stats", "sdwan_bfd_history")):
        return []
    out: list[dict[str, Any]] = []
    for builder in (omp, identity, certificates, tunnel_quality, tunnel_traffic, bfd_history, policy):
        out.extend(builder(ctx))
    return out
