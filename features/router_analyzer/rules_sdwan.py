"""Findings for the SD-WAN overlay: OMP sessions and routes, WAN interfaces, tunnel quality and the pushed policy.

Each rule reads only what the capture shows and says which command it came from.  Where the capture
cannot tell whether something is intended (an OMP path nobody resolves, a policy color this router
does not have) the finding is low or info and says what to confirm; the documentation pages are the
ones listed in ``refs.py`` under "SD-WAN overlay".
"""

from __future__ import annotations

from typing import Any

from ..analyzer_core.findings import finding as F
from .context import Ctx
from . import runtime_sdwan_extra as rse
from .ifnames import canon
from .refs import REFS as R
from .rules import _names, rule
from .sections_sdwan import ONE_WAY_MIN_PACKETS, bfd_history_summary, classes_met, days_ago, days_between_text, days_left, live_bfd_state, local_colors, sla_classes, stamp_text, tunnel_flag


SETTLED_DAYS = 7    # drops older than this before the capture are history, not a problem in progress


def _usable(status: str) -> bool:
    flags = set(status.split(","))
    return "R" in flags and "Inv" not in flags


def _plural(count: int, word: str) -> str:
    return word if count == 1 else word + "s"


def _tunnel_name(t: dict[str, Any]) -> str:
    return f"{t.get('remote_system_ip') or '?'} {t.get('local_color') or '?'}→{t.get('remote_color') or '?'}"


# ---------------------------------------------------------------------------
# OMP
# ---------------------------------------------------------------------------


@rule
def sdwan_omp(ctx: Ctx):
    out = []
    peers = ctx.get("sdwan_omp_peers")
    if peers:
        down = [p for p in peers if p["state"] != "up"]
        for p in down:
            out.append(F("RTR-SDW-040", "high" if len(down) == len(peers) else "medium", "SD-WAN", f"OMP session to {p['type']} {p['peer']} is {p['state']}", obj=p["peer"],
                         detail=f"Site {p['site_id']}, uptime {p['uptime']}; routes received {p['received']:,}, installed {p['installed']:,}, sent {p['sent']:,}.",
                         recommendation="Look at the control connection to the same controller ('show sdwan control connections' and its history) before the OMP session itself.",
                         reference=R["sdwan_control_troubleshoot"]))
    routes = ctx.get("sdwan_omp_routes")
    if routes and routes["unusable_prefixes"]:
        total, bad = routes["prefix_count"], routes["unusable_prefixes"]
        bfd = ctx.get("sdwan_bfd")
        tunnel_colors = {b.get("remote_color") for b in bfd or []}
        unresolved = [(color, slot) for color, slot in routes["by_color"].items() if slot["unresolved"] and (not bfd or color not in tunnel_colors)]
        unresolved.sort(key=lambda item: -item[1]["unresolved"])
        worst = max((s for s in routes["by_status"] if not _usable(s)), key=lambda s: routes["by_status"][s])
        meaning = ", ".join(routes["legend"].get(code, code) for code in worst.split(","))
        detail = (f"{bad:,} of {total:,} overlay prefixes ({100 * bad / total:.0f}%) have only paths with status {worst} ({meaning}); the device does not install them. "
                  + (("The paths point at TLOCs of " + ("color " if len(unresolved) == 1 else "colors ") + "; ".join(f"{color} ({slot['unresolved']:,} {_plural(slot['unresolved'], 'path')}, {slot['unresolved_tlocs']:,} {_plural(slot['unresolved_tlocs'], 'TLOC')})" for color, slot in unresolved[:6]) + ". "
                      + (f"No captured BFD session goes to {'that color' if len(unresolved) == 1 else 'those colors'}; the resolved paths point at {', '.join(sorted(c for c in tunnel_colors if c)) or 'no color'}. " if bfd else "")) if unresolved else "")
                  + f"This router's own colors: {', '.join(sorted(local_colors(ctx))) or 'unknown'}.")
        out.append(F("RTR-SDW-041", "medium" if bad == total else "low", "SD-WAN", f"{bad:,} of {total:,} overlay prefixes have no resolved path ({worst})", obj=worst,
                     detail=detail,
                     recommendation="Confirm that this site is meant to reach those colors. If it is, check the tunnel-interface color and restrict setting, the control policy that advertises the TLOCs and the BFD sessions "
                                    "('show sdwan bfd sessions'); if the design keeps this site on one transport, no action is needed. Cisco's OMP best-path article defines the status codes.",
                     reference=R["sdwan_omp_bestpath"]))
    return out


# ---------------------------------------------------------------------------
# Control-plane identity and WAN interfaces
# ---------------------------------------------------------------------------


@rule
def sdwan_identity(ctx: Ctx):
    local = ctx.get("sdwan_local")
    if not local:
        return []
    props, out = local["properties"], []
    validity = props.get("certificate-validity", "")
    if validity and validity.lower() != "valid":
        out.append(F("RTR-SDW-050", "high", "SD-WAN", f"The device certificate is reported as {validity}", obj="certificate",
                     detail=f"'show sdwan control local-properties' prints certificate-status {props.get('certificate-status', '?')} and certificate-validity {validity}. Cisco lists CRTVERFL (certificate verification failure) among the causes "
                            "of a control connection that does not come up, usually a wrong clock or a missing root certificate.",
                     recommendation="Check the clock ('show clock'), the certificate dates in this output and the root CA chain; renew or reinstall the certificate.", reference=R["sdwan_control_troubleshoot"]))
    chain = props.get("root-ca-chain-status", "")
    if chain and chain.lower() != "installed":
        out.append(F("RTR-SDW-051", "high", "SD-WAN", f"The root CA chain is reported as {chain}", obj="root-ca-chain",
                     detail="Without the root certificate chain the device cannot verify the controllers' certificates.",
                     recommendation="Install the controllers' root certificate chain. The Cisco article shows the vEdge command 'request root-cert-chain install <file>'; the IOS XE spelling is in the Cisco SD-WAN command reference.", reference=R["sdwan_control_troubleshoot"]))
    shut = {canon(i["name"]) for i in (ctx.cfg or {}).get("interfaces", []) if i.get("shutdown")}
    bfd = ctx.get("sdwan_bfd")
    for i in local["interfaces"]:
        name = f"{i['interface']} ({i['color']})"
        if i["state"] != "up":
            admin = canon(i["interface"]) in shut
            out.append(F("RTR-SDW-052", "info" if admin else "medium", "SD-WAN", f"WAN interface {name} is {i['state']} in the control-plane table" + (" (shut down in the configuration)" if admin else ""), obj=i["interface"],
                         detail=f"Last control connection on this interface: {i['last_connection']} (d:h:m:s ago). Max control connections {i['max_control']}, restrict/control/STUN {i['restrict_control_stun']}.",
                         recommendation="No action if the interface is meant to be off. Otherwise check the link and the transport's reachability of the controllers." if admin else
                                        "Check the link, the address and the reachability of the controllers over this transport; this color carries no control connection while it is down.",
                         reference=R["sdwan_control_troubleshoot"]))
        if i["nat_type"] == "A":
            sessions = [b for b in bfd or [] if b.get("source_color") == i["color"]]
            degraded = bfd is not None and (not sessions or any(b.get("state") != "up" for b in sessions))
            out.append(F("RTR-SDW-053", "medium" if degraded else "info", "SD-WAN", f"{name} reports NAT type A (address-port dependent mapping)", obj=i["interface"],
                         detail="The local-properties legend defines A as address-port dependent mapping. Cisco documents a case where BFD stayed down between a device behind NAT and a peer that also had NAT on its transport interface. "
                                + (f"On this color {len(sessions)} BFD session(s) are captured, {sum(1 for b in sessions if b.get('state') != 'up')} not up." if bfd is not None else "No BFD sessions were captured to compare with."),
                         recommendation="Check whether the remote end of the affected tunnels is also behind NAT, and whether the NAT or an ACL on the peer's transport interface drops the data-plane UDP ports.", reference=R["sdwan_nat_types"]))
    return out


# ---------------------------------------------------------------------------
# Tunnel quality
# ---------------------------------------------------------------------------


@rule
def sdwan_tunnel_quality(ctx: Ctx):
    stats = ctx.get("sdwan_app_route")
    if not stats:
        return []
    out = []
    classes = sla_classes(ctx)
    none_met = [t for t in stats if classes_met(t, classes) == []]
    if none_met:
        limits = "; ".join(f"{c['name']}: loss {c['loss']}%, latency {c['latency']} ms, jitter {c['jitter']} ms" for c in classes[:6])
        out.append(F("RTR-SDW-060", "medium", "SD-WAN", f"{len(none_met)} of {len(stats)} overlay tunnels meet none of the SLA classes in the pushed policy", obj=_names([_tunnel_name(t) for t in none_met], 6),
                     detail=f"Measured means: " + "; ".join(f"{_tunnel_name(t)} loss {t.get('mean_loss')}%, latency {t.get('mean_latency')} ms, jitter {t.get('mean_jitter')} ms" for t in none_met[:4]) + f". SLA classes: {limits}.",
                     recommendation="Application-aware routing compares these means with the class limits; traffic that matches a rule for such a tunnel moves to another tunnel or to the rule's backup color. Check the underlay of the transport.",
                     reference=R["sdwan_bfd_approute"]))
    lossy = [t for t in stats if (t.get("mean_loss") or 0) >= 5]
    if lossy:
        out.append(F("RTR-SDW-061", "medium", "SD-WAN", f"{len(lossy)} overlay tunnel(s) show a mean loss of 5 % or more", obj=_names([_tunnel_name(t) for t in lossy], 6),
                     detail="Mean loss is the device's figure over the interval window. 5 % is the loss limit of Cisco's predefined Transactional-Data SLA class, used here only as a yardstick; "
                            + "; ".join(f"{_tunnel_name(t)}: {t.get('mean_loss')} %" for t in lossy[:4]) + ".",
                     recommendation="Check the underlay path (interface errors, congestion, policing) of the transport named here.", reference=R["sdwan_aar_deploy"]))
    return out


# ---------------------------------------------------------------------------
# Pushed policy
# ---------------------------------------------------------------------------


@rule
def sdwan_policy(ctx: Ctx):
    data = ctx.get("sdwan_policy")
    if not data:
        return []
    out = []
    sequences = [(pol["name"], vpn["name"], seq) for pol in data["policies"] for vpn in pol["vpn_lists"] for seq in vpn["sequences"]]
    strict = [s for s in sequences if s[2]["action"]["strict"]]
    if strict:
        out.append(F("RTR-SDW-070", "info", "SD-WAN", f"{len(strict)} application-aware routing rule(s) use 'strict'", obj=_names([f"{p} seq {s['sequence']}" for p, _, s in strict], 6),
                     detail="Cisco: with the strict option, traffic that matches the rule is dropped when no tunnel satisfies the SLA class.",
                     recommendation="Confirm that dropping is wanted for these flows when every tunnel is out of SLA; otherwise remove strict so the backup color or any available tunnel is used.", reference=R["sdwan_aar_policy"]))
    colors = local_colors(ctx)
    if colors:
        named: dict[str, int] = {}
        for _, _, seq in sequences:
            for color in seq["action"]["preferred_colors"] + [seq["action"]["backup_color"]]:
                if color and color not in colors:
                    named[color] = named.get(color, 0) + 1
        if named:
            out.append(F("RTR-SDW-071", "info", "SD-WAN", f"The policy names color(s) this router has no tunnel in: {', '.join(sorted(named))}", obj=", ".join(sorted(named)),
                         detail=f"Rules naming them: {', '.join(f'{c} ×{n}' for c, n in sorted(named.items()))}. This router's colors: {', '.join(sorted(colors))}. A centralized policy is shared by many sites, so this is normal unless the color was meant for this site.",
                         recommendation="No action if the color belongs to other sites. Cisco describes preferred and backup colors as loose matches: when none matches, any available tunnel is used.", reference=R["sdwan_aar_policy"]))
    defined = {(item["kind"], item["name"]) for item in data["lists"]}
    classes = {c["name"] for c in data["sla_classes"]}
    missing: set[str] = set()
    for _, vpn_name, seq in sequences:
        for key, value in seq["match"].items():
            if key.endswith("-list") and value and (key.split("-", 1)[-1] if key.startswith(("source-", "destination-")) else key, value) not in defined:
                missing.add(f"{key} {value}")
        if seq["action"]["sla_class"] and seq["action"]["sla_class"] not in classes:
            missing.add(f"sla-class {seq['action']['sla_class']}")
    for pol in data["policies"]:
        for vpn in pol["vpn_lists"]:
            if vpn["name"] and ("vpn-list", vpn["name"]) not in defined:
                missing.add(f"vpn-list {vpn['name']}")
    if missing:
        out.append(F("RTR-SDW-072", "low", "SD-WAN", f"The policy refers to {len(missing)} object(s) that the output does not define", obj=_names(sorted(missing), 6),
                     detail="The output of 'show sdwan policy from-vsmart' lists every list and SLA class the controller pushed; a rule that names one that is not listed cannot match or cannot be applied as written.",
                     recommendation="Compare with the policy on vManage; re-activate the centralized policy if the device holds a partial copy.", reference=R["sdwan_aar_policy"]))
    return out


# ---------------------------------------------------------------------------
# OMP summary, certificates, tunnel counters, BFD history
# ---------------------------------------------------------------------------


@rule
def sdwan_omp_summary_rules(ctx: Ctx):
    summary = ctx.get("sdwan_omp_summary")
    if not summary:
        return []
    out = []
    state = str(summary.get("oper_state", ""))
    peers = summary.get("vsmart_peers")
    if state.upper() != "UP":
        out.append(F("RTR-SDW-083", "high", "SD-WAN", f"OMP is {state or 'not up'} on this router", obj="omp",
                     detail=f"'show sdwan omp summary' prints oper-state {state}, admin-state {summary.get('admin_state', '?')}. Without OMP the router learns no overlay route or TLOC and advertises none.",
                     recommendation="Check the control connections to the vSmart controllers ('show sdwan control connections' and its history) and 'show sdwan omp peers'.", reference=R["sdwan_control_troubleshoot"]))
    elif peers == 0:
        out.append(F("RTR-SDW-083", "high", "SD-WAN", "OMP is up but no vSmart controller is connected", obj="omp",
                     detail="vsmart-peers is 0 in 'show sdwan omp summary'. The router keeps forwarding on the last routes it learned until the graceful-restart timer ends, and learns nothing new.",
                     recommendation="Check the control connection to every vSmart ('show sdwan control connections'); the connection history lists the error code of each failed attempt.", reference=R["sdwan_control_troubleshoot"]))
    elif peers == 1:
        out.append(F("RTR-SDW-084", "low", "SD-WAN", "Only one vSmart controller is connected", obj="omp",
                     detail="vsmart-peers is 1 in 'show sdwan omp summary'. With a single controller the overlay has no control plane while that controller is unreachable. Whether a second one is expected depends on the design and on the controller group list in the configuration.",
                     recommendation="If the fabric has two vSmart controllers, find out why the second one has no session (control connection history). If it has one by design, note the single point of failure.", reference=R["sdwan_design"]))
    table = ctx.get("sdwan_omp_peers")
    if table is not None and peers and state.upper() == "UP":
        sessions = sum(1 for p in table if p["type"] == "vsmart" and p["state"] == "up")
        if sessions != peers:
            out.append(F("RTR-SDW-084", "low", "SD-WAN", f"vSmart count differs between 'omp summary' ({peers}) and 'omp peers' ({sessions} up)", obj="omp",
                         detail="Both commands were captured at slightly different moments, or a session changed state between them.",
                         recommendation="Repeat both commands; if the numbers still differ, read the OMP session table and the control connection list together.", reference=R["sdwan_omp_summary_api"]))
    got, inst = summary.get("routes_received"), summary.get("routes_installed")
    if state.upper() == "UP" and got and inst == 0:
        out.append(F("RTR-SDW-086", "medium", "SD-WAN", f"OMP received {got:,} routes and installed none", obj="omp",
                     detail="routes-installed is 0 in 'show sdwan omp summary'. Received paths are installed only when their TLOC resolves and the routing policy accepts them.",
                     recommendation="Look at 'show sdwan omp routes' (status codes, unresolved TLOCs) and at the BFD sessions: a path needs a TLOC the router can reach.", reference=R["sdwan_omp_bestpath"]))
    return out


@rule
def sdwan_certificate_expiry(ctx: Ctx):
    now = ctx.capture_time()
    if now is None:
        return []
    items: dict[str, dict[str, Any]] = {}
    for c in (ctx.get("sdwan_certificates") or {}).get("certificates", []):
        if c["not_after"]:
            items[c["not_after"]] = {"name": c["subject"].get("CN") or c["section"], "section": c["section"], "until": c["not_after"], "issuer": c["issuer"].get("CN", "")}
    props = (ctx.get("sdwan_local") or {}).get("properties", {})
    if props.get("certificate-not-valid-after") and not items:
        until = rse.openssl_stamp(props["certificate-not-valid-after"])
        if until:
            items[until] = {"name": "device certificate", "section": "show sdwan control local-properties", "until": until, "issuer": ""}
    out = []
    for item in items.values():
        days = days_left(item["until"], now)
        if days is None or days > 180:
            continue
        severity = "high" if days <= 30 else ("medium" if days <= 90 else "low")
        when = f"expired {-days} day(s) before the capture" if days < 0 else f"expires in {days} day(s)"
        out.append(F("RTR-SDW-085", severity, "SD-WAN", f"The {item['name']} {when} ({item['until'][:10]})", obj=item["name"],
                     detail=f"Section '{item['section']}' of the certificate output; valid until {stamp_text(item['until'])}, capture clock {now:%Y-%m-%d %H:%M}. "
                            "When the certificate of a router has expired, the controllers reject it and the control connections stay down (Cisco's error legend lists CERTEXPRD, 'Certificate Expired'). "
                            "Thresholds (30 / 90 / 180 days) are Keystone heuristics.",
                     recommendation="Renew the certificate before the date (SD-WAN Manager certificate workflow for an enterprise certificate; a board-id certificate issued by Cisco has to be replaced through Cisco). "
                                    "Confirm that the router clock is correct: a wrong clock makes a valid certificate look expired.", reference=R["sdwan_troubleshoot_common"]))
    return out


@rule
def sdwan_one_way_tunnels(ctx: Ctx):
    tunnels = ctx.get("sdwan_tunnel_stats")
    if not tunnels:
        return []
    out = []
    one_way = [t for t in tunnels if tunnel_flag(t) in ("sends only", "receives only")]
    if one_way:
        bfd = {(b.get("system_ip"), b.get("remote_color")): b.get("state") for b in ctx.get("sdwan_bfd") or []}
        def label(t):
            state = bfd.get((t["system_ip"], t["remote_color"]))
            return f"{t['system_ip']} {t['local_color']}→{t['remote_color']} ({tunnel_flag(t)}, {t['tx_pkts']:,} sent / {t['rx_pkts']:,} received" + (f", BFD {state}" if state else "") + ")"
        out.append(F("RTR-SDW-082", "medium", "SD-WAN", f"{len(one_way)} of {len(tunnels):,} overlay tunnel(s) carry traffic in one direction only", obj=_names([f"{t['system_ip']} {t['local_color']}→{t['remote_color']}" for t in one_way], 6),
                     detail="'show sdwan tunnel statistics' counts packets since the tunnel came up. BFD hellos alone are exchanged in both directions, so a tunnel with at least "
                            f"{ONE_WAY_MIN_PACKETS:,} packets in one direction and none in the other is broken in the other direction. " + "; ".join(label(t) for t in one_way[:4]) + ".",
                     recommendation="Check for a NAT or ACL on the remote transport that drops the inbound IPsec/UDP packets, an asymmetric path through a firewall, and the BFD session state of the same tunnel.", reference=R["sdwan_bfd_troubleshoot"]))
    sizes = sorted(t["mtu"] for t in tunnels if t.get("mtu"))
    if len(sizes) >= 3:
        median = sizes[len(sizes) // 2]
        small = [t for t in tunnels if t.get("mtu") and t["mtu"] < 0.8 * median]
        if small:
            out.append(F("RTR-SDW-087", "info", "SD-WAN", f"{len(small)} overlay tunnel(s) have a tunnel MTU far below the usual {median}", obj=_names([f"{t['system_ip']} {t['remote_color']}" for t in small], 6),
                         detail=f"Smallest tunnel MTU {min(t['mtu'] for t in small)}; the median of all {len(sizes):,} tunnels is {median}. The tunnel MTU is what path MTU discovery found on the underlay path to that remote TLOC (it runs over BFD; "
                                "one Cisco community answer gives 20 minutes as the default timer), and the TCP MSS is lowered to match. 80 % of the median is a Keystone yardstick, not a Cisco value.",
                         recommendation="A low value means a link on that path carries small packets only (a tunnel, a PPPoE or a mobile link). Check the underlay MTU; large packets on these tunnels are fragmented or the sessions run with a small MSS.", reference=R["sdwan_mtu_community"]))
    return out


@rule
def sdwan_bfd_flaps(ctx: Ctx):
    summary = bfd_history_summary(ctx)
    if not summary or not summary["drops"]:
        return []
    now = ctx.capture_time()
    sessions = [s for s in summary["sessions"] if s["drops"]]
    worst = max(s["drops"] for s in sessions)
    latest = max(s["last_drop"] for s in sessions)
    recent = days_between_text(latest, now)
    live = ctx.get("sdwan_bfd")
    down_now = [s for s in summary["sessions"] if live_bfd_state(ctx, s["system_ip"], s["color"])[1] == "bad"] if live else []
    age = days_ago(latest, now)
    settled = age is not None and age > SETTLED_DAYS
    severity = "medium" if down_now or (worst >= 5 and not settled) else ("low" if worst >= 2 else "info")
    def line(s):
        return f"{s['system_ip']} {s['color']}: {s['drops']} drop(s), last {stamp_text(s['last_drop'])}"
    out = [F("RTR-SDW-080", severity, "SD-WAN", f"BFD tunnels toward {len(sessions)} remote TLOC(s) dropped {summary['drops']} time(s) between {stamp_text(summary['first'])[:16]} and {stamp_text(summary['last'])[:16]}",
             obj=_names([f"{s['system_ip']} {s['color']}" for s in sessions], 6),
             detail="'show sdwan bfd history' keeps the up/down records of every session. A drop is a down record that carries packet counters (the tunnel had been exchanging BFD packets); the output has no local-color column, so tunnels from different local colors to the same remote TLOC are counted together. " + "; ".join(line(s) for s in sessions[:5])
                    + (f". The most recent drop is {recent} before the capture" if recent else "") + (f". {len(down_now)} remote TLOC(s) have a tunnel that is down in 'show sdwan bfd sessions': " + ", ".join(f"{s['system_ip']} {s['color']}" for s in down_now[:4]) if down_now else "")
                    + ". Cisco defines no flap threshold; the severity is a Keystone heuristic (worst remote TLOC: 1 drop info, 2-4 low; 5 or more is medium unless the last drop is more than 7 days before the capture; a tunnel still down in the live table is medium).",
             recommendation="Look at the underlay of the colors named here ('show interfaces', 'show logging' around the drop times, the provider's circuit) and at the sessions' transition counters in 'show sdwan bfd sessions'. "
                            "Compare the times with the 'Sessions that dropped together' table.", reference=R["sdwan_bfd_troubleshoot"])]
    bursts = summary["bursts"]
    if bursts:
        colors = sorted({c for b in bursts for c in b["colors"]})
        newest = max(bursts, key=lambda b: b["time"])
        out.append(F("RTR-SDW-081", "medium" if len(bursts) >= 3 and not settled else "low", "SD-WAN",
                     f"BFD tunnels toward several remote TLOCs dropped at the same moment {len(bursts)} time(s)", obj=", ".join(colors),
                     detail=f"{len(bursts)} moments where tunnels toward two or more remote TLOCs dropped within 10 seconds of each other, the largest involving {max(b['sessions'] for b in bursts)} remote TLOCs; the latest at {stamp_text(newest['time'])}"
                            + (f" ({days_between_text(newest['time'], now)} before the capture)" if days_between_text(newest['time'], now) else "") + f". Colors involved: {', '.join(colors)}. "
                            "Independent failures at several remote sites rarely coincide to the second, so a common cause on this router's side is likely: the WAN interface or its provider circuit, a NAT or firewall in front of the router, or a restart of the SD-WAN process.",
                     recommendation="Match the first drop of each burst with interface up/down and SD-WAN messages in 'show logging', and with the provider's own outage notices for that circuit.", reference=R["sdwan_bfd_troubleshoot"]))
    return out
