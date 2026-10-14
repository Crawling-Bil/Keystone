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
from .ifnames import canon
from .refs import REFS as R
from .rules import _names, rule
from .sections_sdwan import classes_met, local_colors, sla_classes


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
