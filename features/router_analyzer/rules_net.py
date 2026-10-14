"""NAT, IPsec, OSPF and BGP findings built on the models of ``nat.py``, ``ipsec.py`` and ``ospf.py``.

The models join configuration with whatever live output was captured, so each rule
says whether it judged the configuration alone or also a live counter.  Nothing
here reads a pre-shared key: reuse is detected from per-run HMAC tokens.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from ..analyzer_core.findings import finding as F
from . import nat as natmod
from .context import Ctx
from .refs import REFS as R
from .rules import _cfg, _names, _worse, rule


def _public(address: str) -> bool | None:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return None


def _pct(part: float, whole: float) -> float:
    return round(100 * part / whole, 1) if whole else 0.0


# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------


@rule
def nat_configuration(ctx: Ctx):
    nat = ctx.models.get("nat")
    if not nat:
        return []
    out = []
    broken = [d for d in nat["dynamic"] if d.get("target_kind") == "pool" and d.get("pool_defined") is False]
    if broken:
        out.append(F("RTR-NAT-001", "high", "NAT", f"{len(broken)} NAT rule(s) use a pool that is not defined", obj=_names([d["target"] for d in broken]),
                     detail="Without the pool the rule never translates: " + _names([f"{d['text']}" for d in broken], 4),
                     recommendation="Define the pool ('ip nat pool <name> <start> <end> netmask <mask>') or remove the rule.", reference=R["nat"]))
    unused = [p["name"] for p in nat["pools"] if not p["used_by"]]
    if unused:
        out.append(F("RTR-NAT-003", "low", "NAT", f"{len(unused)} NAT pool(s) are defined but no rule uses them", obj=_names(unused),
                     detail="Pools that nothing references still reserve public addresses on paper and make the configuration harder to audit.",
                     recommendation="Remove the pools you no longer need; keep a list of which public addresses are free.", reference=R["nat"]))
    if (nat["dynamic"] or nat["static"]) and not nat["inside"]:
        out.append(F("RTR-NAT-011", "medium", "NAT", "NAT rules exist but no interface is marked 'ip nat inside'",
                     detail="NAT needs 'ip nat inside' and 'ip nat outside' on interfaces to know which way a packet is translated.",
                     recommendation="Add 'ip nat inside' to the LAN-facing interfaces.", reference=R["nat"]))
    if (nat["dynamic"] or nat["static"]) and not nat["outside"]:
        out.append(F("RTR-NAT-011", "medium", "NAT", "NAT rules exist but no interface is marked 'ip nat outside'",
                     recommendation="Add 'ip nat outside' to the interface(s) towards the translated network.", reference=R["nat"]))
    for group in nat["static_conflicts"]:
        first = group[0]
        out.append(F("RTR-NAT-012", "high", "NAT", f"Static NAT: {first['global']}{(':' + first['global_port']) if first['global_port'] else ''} is mapped to {len(group)} different inside hosts",
                     obj=first["global"], detail="; ".join(e["text"] for e in group), recommendation="Keep one static mapping per global address and port.", reference=R["nat"]))
    for group in nat["static_duplicates"]:
        first = group[0]
        out.append(F("RTR-NAT-013", "low", "NAT", f"Static NAT entry for {first['global']} is configured {len(group)} times", obj=first["global"], detail="; ".join(e["text"] for e in group),
                     recommendation="Remove the duplicate lines.", reference=R["nat"]))
    shared = nat["shared_addresses"]
    if shared:
        pools = sorted({name for item in shared for name in item["pools"]})
        out.append(F("RTR-NAT-014", "info", "NAT", f"{len(shared)} public address(es) belong to more than one NAT pool", obj=_names([s["address"] for s in shared], 6),
                     detail=_names([f"{s['address']}: {', '.join(s['pools'])}" for s in shared], 5)
                            + ". Translations from different rules then share the same public address (valid with overload), so the address alone does not tell which rule produced a connection, and each pool's utilisation counts the shared address.",
                     recommendation="Confirm the sharing is intended; document which source networks use which public address.", reference=R["nat"]))
    # a port forward that changes the port, with digits that look swapped
    typo = [s for s in nat["static"] if s.get("translates_port") and natmod.digits_transposed(s["local_port"], s["global_port"])]
    if typo:
        out.append(F("RTR-NAT-015", "low", "NAT", f"{len(typo)} static port-forward(s) translate a port to the same digits in a different order",
                     obj=_names([s["text"] for s in typo], 3), detail="; ".join(s["text"] for s in typo)
                            + ". A forward that changes the port number on purpose is legal; swapped digits (5535 → 5355) are a common typing mistake.",
                     recommendation="Compare with the service owner's request and fix the port on one side.", reference=R["nat"]))
    return out


@rule
def nat_exposure(ctx: Ctx):
    """Static port-forwards of management and database ports, judged against the inbound ACLs on the outside interfaces."""
    nat = ctx.models.get("nat")
    if not nat:
        return []
    sensitive = [s for s in nat["static"] if s.get("sensitive") and s["direction"] == "inside"]
    if not sensitive:
        return []
    interfaces = {i["name"]: i for i in _cfg(ctx).get("interfaces", [])}
    outside = nat["outside"]
    open_outside = [name for name in outside if not (interfaces.get(name) or {}).get("acl_in")]
    covered = [name for name in outside if name not in open_outside]
    public = [s for s in sensitive if _public(s["global"])]
    # An outside interface without an inbound ACL is a path to the published port; the router cannot tell which interface the traffic arrives on.
    if public:
        severity = "high" if open_outside else "medium"
    else:
        severity = "medium" if open_outside else "low"
    by_service: dict[str, int] = {}
    for entry in sensitive:
        by_service[entry["sensitive"]] = by_service.get(entry["sensitive"], 0) + 1
    scope = "public" if public else "private (RFC 1918)"
    where = ("none of the outside interfaces has an inbound ACL" if not covered else
             f"{len(covered)} of {len(outside)} outside interface(s) have an inbound ACL, {len(open_outside)} do not ({_names(open_outside, 4)})")
    return [F("RTR-NAT-020", severity, "NAT", f"{len(sensitive)} static NAT {'entry publishes' if len(sensitive) == 1 else 'entries publish'} management or database ports ({', '.join(f'{k} ×{v}' for k, v in sorted(by_service.items(), key=lambda kv: -kv[1]))})",
              obj=_names([f"{s['global']}:{s['global_port']} → {s['local']}" for s in sensitive], 6),
              detail=f"The global addresses are {scope} and {where}. A static NAT port-forward opens that service to everything that can reach the outside interface; the NAT entry itself filters nothing. "
                     + _names([s["text"] for s in sensitive], 4),
              recommendation="Restrict the sources with an inbound ACL on every outside interface (or a zone-based firewall policy) and publish management ports only over VPN.",
              reference=R["acl"])]


@rule
def nat_live(ctx: Ctx):
    nat = ctx.models.get("nat")
    stats = (nat or {}).get("stats")
    if not stats:
        return []
    out = []
    for pool in nat["pools"]:
        misses = pool.get("misses") or 0
        pct = pool.get("allocated_pct")
        if misses:
            out.append(F("RTR-NAT-030", "high", "NAT", f"NAT pool {pool['name']} could not allocate an address {misses:,} time(s)", obj=pool["name"],
                         detail=f"{pool['allocated']} of {pool['size']} address(es) allocated ({pct}%); a pool miss is a failed allocation: the pool had no free address (or, with overload, no free port) for a new connection.",
                         recommendation="Add addresses to the pool, enable overload, or shorten 'ip nat translation' timeouts for the busy protocol.", reference=R["nat_cat8000"]))
        elif pct is not None and pct >= 90 and not pool["overload"] and pool["used_by"]:
            out.append(F("RTR-NAT-031", "medium", "NAT", f"NAT pool {pool['name']} is {pct}% allocated and has no overload", obj=pool["name"],
                         detail=f"{pool['allocated']} of {pool['size']} address(es) in use. Without overload every inside host needs its own address; the next new host gets no translation.",
                         recommendation="Add 'overload' to the rule or enlarge the pool.", reference=R["nat_cat8000"]))
    limit = stats.get("limit") or {}
    if limit.get("max"):
        used_pct = _pct(limit.get("used", 0), limit["max"])
        if limit.get("missed"):
            out.append(F("RTR-NAT-032", "high", "NAT", f"{limit['missed']:,} translation(s) were refused because the NAT limit of {limit['max']:,} was reached",
                         detail=f"{limit.get('used', 0):,} translation entries in use ({used_pct}% of the limit).",
                         recommendation="Raise the limit if the platform has memory for it, or find the host creating the excess translations ('show ip nat translations total', per-host limits).", reference=R["nat_cat8000"]))
        elif used_pct >= 80:
            out.append(F("RTR-NAT-032", "high" if used_pct >= 95 else "medium", "NAT", f"NAT translation table is {used_pct}% of its configured limit",
                         detail=f"{limit.get('used', 0):,} of {limit['max']:,} entries.", recommendation="Raise the limit or reduce idle timeouts before it is reached; new connections are refused beyond it.", reference=R["nat_cat8000"]))
    drops = stats.get("drops") or {}
    hard = {k: v for k, v in drops.items() if k in ("pool", "mapping", "port_block", "ip_alias", "limit_entry") and v}
    if hard:
        out.append(F("RTR-NAT-033", "high", "NAT", "NAT drop counters point at resource exhaustion", obj=", ".join(hard),
                     detail=", ".join(f"{k.replace('_', ' ')} {v:,}" for k, v in hard.items()) + ". These counters count packets NAT dropped because of pool handling, mapping creation or the translation limit (Cisco's NAT troubleshooting note lists them next to pool exhaustion).",
                     recommendation="Check pool utilisation, the translation limit and 'show platform hardware qfp active feature nat datapath ...' on Catalyst 8000.", reference=R["nat_cat8000"]))
    flows = (drops.get("in_to_out") or 0) + (drops.get("out_to_in") or 0)
    hits = stats.get("hits") or 0
    if flows:
        share = _pct(flows, hits + (stats.get("misses") or 0))
        out.append(F("RTR-NAT-034", "low" if share >= 1 else "info", "NAT", f"NAT dropped {flows:,} packets ({share}% of translated packets)",
                     detail=f"In-to-out {drops.get('in_to_out', 0):,}, out-to-in {drops.get('out_to_in', 0):,} against {hits:,} hits and {stats.get('misses', 0):,} misses since the counters were last cleared. "
                            "Cisco describes out-to-in drops as inbound packets that match no translation, which on an Internet-facing router is mostly unsolicited traffic.",
                     recommendation="Only a rising out-to-in count for a service you publish needs a look; compare with the static entries.", reference=R["nat_cat8000"]))
    if nat["live_mappings_unmatched"]:
        out.append(F("RTR-NAT-035", "info", "NAT", f"{len(nat['live_mappings_unmatched'])} live NAT rule(s) are not in the captured configuration",
                     obj=_names([f"{m['acl']} → {m['target']}" for m in nat["live_mappings_unmatched"]]),
                     detail="'show ip nat statistics' and the configuration were captured at different moments, or the rule is defined in a VRF the parser does not pair.",
                     recommendation="Recapture both from the same session.", reference=R["nat"]))
    return out


# ---------------------------------------------------------------------------
# IPsec
# ---------------------------------------------------------------------------

_VPN_ISSUES = {
    # kind: (rule id, category title, recommendation, reference key)
    "no_psk": ("RTR-VPN-020", "IPsec peer(s) without a pre-shared key", "Add 'crypto isakmp key <key> address <peer>' (IKEv1) or a keyring entry (IKEv2), or switch to certificates.", "ipsec"),
    "undefined": ("RTR-VPN-021", "IPsec configuration refers to objects that do not exist", "Define the missing transform-set, ACL, proposal, profile or keyring, or remove the reference.", "ipsec"),
    "empty_acl": ("RTR-VPN-022", "Crypto ACL that protects no traffic", "Add the permit entries for the local and remote subnets (mirror image on the peer).", "ipsec"),
    "no_acl": ("RTR-VPN-022", "Crypto map entry without 'match address'", "Add 'match address <acl>' with the traffic selectors.", "ipsec"),
    "any_any": ("RTR-VPN-023", "Crypto ACL permits any to any", "Narrow the ACL to the local and remote subnets; 'permit ip any any' sends all traffic into one tunnel.", "ipsec"),
    "not_applied": ("RTR-VPN-025", "Crypto map is not applied to an interface", "Apply it with 'crypto map <name>' on the WAN interface, or remove it.", "ipsec"),
    "no_peer": ("RTR-VPN-026", "Crypto map entry without 'set peer'", "Add 'set peer <ip>' (or use a dynamic map).", "ipsec"),
    "profile_mismatch": ("RTR-VPN-027", "IKEv2 profile does not match the peer it is used for", "Make the profile's 'match identity remote' cover the peer address.", "ikev2"),
    "wildcard": ("RTR-VPN-028", "IKEv2 keyring accepts any address with a shared key", "Restrict the keyring peer to the remote address or use certificates.", "ikev2"),
}


@rule
def vpn_model_issues(ctx: Ctx):
    model = ctx.models.get("ipsec")
    if not model:
        return []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in model["issues"]:
        grouped.setdefault(item["kind"], []).append(item)
    out = []
    for kind, items in grouped.items():
        if kind == "pfs":
            weak = [i for i in items if i["severity"] != "low"]
            none = [i for i in items if i["severity"] == "low"]
            if weak:
                out.append(F("RTR-VPN-024", "medium", "VPN", f"{len(weak)} IPsec tunnel(s) use a PFS group that Cisco advises against", obj=_names([i["tunnel"] for i in weak], 6),
                             detail=_names(sorted({i["text"] for i in weak}), 4) + ". Cisco's Next Generation Cryptography guidance says to avoid IKE/DH groups 1, 2 and 5 and to use group 15 or 16, or the elliptic-curve groups 19 or 20, when possible.",
                             recommendation="'set pfs group19' (or group20; group15/16 for plain DH) on both ends. The peers must change together, and both platforms must support the group.", reference=R["ngc"]))
            if none:
                out.append(F("RTR-VPN-024", "low", "VPN", f"{len(none)} IPsec tunnel(s) have no PFS", obj=_names([i["tunnel"] for i in none], 6),
                             detail="Without perfect forward secrecy a rekey derives its keys from the same IKE key, so a stolen IKE key exposes recorded traffic of later rekeys too.",
                             recommendation="'set pfs group19' (or group20; group15/16 for plain DH) in the crypto map or IPsec profile, on both ends.", reference=R["ngc"]))
            continue
        if kind == "weak_transform":
            continue  # reported per transform set by RTR-VPN-005, which now lists the tunnels
        spec = _VPN_ISSUES.get(kind)
        if not spec:
            continue
        rule_id, title, recommendation, ref = spec
        severity = "low"
        for item in items:
            severity = _worse(severity, item["severity"]) if item["severity"] in ("low", "medium", "high") else severity
        out.append(F(rule_id, severity, "VPN", f"{len(items)} × {title.lower()}" if len(items) > 1 else title, obj=_names(sorted({i["tunnel"] for i in items}), 6),
                     detail=_names([f"{i['tunnel']}: {i['text']}" for i in items], 6), recommendation=recommendation, reference=R[ref]))
    return out


@rule
def vpn_model_extras(ctx: Ctx):
    model = ctx.models.get("ipsec")
    if not model:
        return []
    out = []
    if model["reuse"]:
        groups = model["reuse"]
        out.append(F("RTR-VPN-029", "low", "VPN", f"{len(groups)} pre-shared key(s) are used for more than one peer", obj="; ".join(" / ".join(g) for g in groups[:4]),
                     detail="Peers: " + "; ".join(" / ".join(g) for g in groups[:6]) + ". Detected by comparing salted hashes made for this analysis; no key is shown or stored. "
                            "Different peers of the same remote site may legitimately share a key; peers of different organisations should not.",
                     recommendation="Use a unique random key per peer (20+ characters) or certificates, so one leaked or retired key does not force a rekey of several tunnels.", reference=R["ipsec"]))
    weak_offers = [o for o in model["offered_ikev2"] if o["weak"]]
    if weak_offers:
        out.append(F("RTR-VPN-030", "medium", "VPN", f"IKEv2 policy offers {len(weak_offers)} proposal(s) with weak parameters", obj=_names([o["name"] for o in weak_offers]),
                     detail=_names([f"{o['name']}: {', '.join(o['weak'])} (policy {o['policy']})" for o in weak_offers], 5)
                            + ". The responder accepts the first proposal both sides share, so a peer that only supports the weak one will negotiate it.",
                     recommendation="Remove the weak proposals from the policy once every peer supports DH group 19/20 (or 15/16) with SHA-256 or better.", reference=R["ngc"]))
    tunnels = model["tunnels"]
    if tunnels and model["dpd"] is False:
        out.append(F("RTR-VPN-031", "low", "VPN", "No dead-peer detection is configured for the IPsec tunnels",
                     detail="Without DPD (IKEv2 'dpd' / IKEv1 'crypto isakmp keepalive') a peer that disappeared is noticed only when the SA lifetime expires, so traffic keeps going into a dead tunnel for hours.",
                     recommendation="'crypto isakmp keepalive 10 3 periodic' (IKEv1) or 'dpd 10 3 on-demand' in the IKEv2 profile.", reference=R["ikev2"]))
    unused = model.get("unused") or {}
    leftovers = {k: v for k, v in unused.items() if v}
    if leftovers:
        out.append(F("RTR-VPN-032", "low", "VPN", f"{sum(len(v) for v in leftovers.values())} unused IPsec object(s)", obj=_names([n for v in leftovers.values() for n in v], 8),
                     detail="; ".join(f"{k.replace('_', ' ')}: {_names(v, 5)}" for k, v in leftovers.items()), recommendation="Remove objects no tunnel references; they hide the real crypto policy.", reference=R["ipsec"]))
    return out


# ---------------------------------------------------------------------------
# OSPF
# ---------------------------------------------------------------------------


@rule
def ospf_model(ctx: Ctx):
    model = ctx.models.get("ospf")
    if not model:
        return []
    out = []
    for proc in model["processes"]:
        name = f"ospf {proc['process']}" + (f" vrf {proc['vrf']}" if proc.get("vrf") else "")
        state = proc["state"]
        if state == "empty":
            out.append(F("RTR-OSPF-020", "low", "OSPF", f"{name} is configured but no interface participates",
                         detail="The process has no 'network … area …' statement and no interface carries 'ip ospf <process> area <n>', so it forms no adjacency and advertises nothing.",
                         recommendation="Remove 'router ospf' if OSPF is not used, or enable it on the intended interfaces.", reference=R["ospf"]))
        elif state == "no_match":
            out.append(F("RTR-OSPF-021", "medium", "OSPF", f"{name}: none of its network statements matches an interface address",
                         detail=_names([n["network"] + f" area {n['area']}" for n in proc["networks"]], 6) + ". The most specific matching statement wins and only primary addresses of up/up interfaces are used.",
                         recommendation="Check the address and wildcard mask (inverse mask) of each statement.", reference=R["ospf"]))
        elif state == "all_passive":
            out.append(F("RTR-OSPF-022", "medium", "OSPF", f"{name}: every participating interface is passive or shut down",
                         detail="A passive interface advertises its prefix but sends no Hello, so no adjacency can form.",
                         recommendation="Add 'no passive-interface <name>' for the interfaces that should have neighbours.", reference=R["ospf"]))
        elif proc["networks"]:
            dead = [n for n in proc["networks"] if not n.get("matched")]
            if dead and len(dead) < len(proc["networks"]):
                out.append(F("RTR-OSPF-023", "low", "OSPF", f"{name}: {len(dead)} network statement(s) match no interface", obj=_names([n["network"] for n in dead]),
                             detail="They advertise nothing; they are usually left over from a removed interface or a typo in the wildcard mask.",
                             recommendation="Remove them or correct the address/wildcard.", reference=R["ospf"]))
        for item in proc.get("redistribute_detail", []):
            if item["source"] in ("connected", "static", "rip", "eigrp", "bgp", "ospf", "isis") and not item["subnets"]:
                out.append(F("RTR-OSPF-024", "medium", "OSPF", f"{name}: 'redistribute {item['text']}' has no 'subnets' keyword", obj=item["text"],
                             detail="Without 'subnets' OSPF redistributes only classful networks (see the linked Cisco TAC note): subnets of the redistributed source are silently left out.",
                             recommendation="Append 'subnets' (and a route-map if you need to filter).", reference=R["ospf_redistribute"]))
    if model["stray_neighbors"]:
        out.append(F("RTR-OSPF-025", "info", "OSPF", f"{len(model['stray_neighbors'])} live OSPF neighbour(s) on interfaces that the configuration does not enable for OSPF",
                     obj=_names([f"{n.get('neighbor_id', '?')} on {n.get('interface', '?')}" for n in model["stray_neighbors"]]),
                     detail="The configuration and the neighbour table were probably captured at different moments, or the interface is enabled through a construct the parser does not read.",
                     recommendation="Recapture 'show running-config' and 'show ip ospf neighbor' in the same session.", reference=R["ospf"]))
    return out


# ---------------------------------------------------------------------------
# BGP
# ---------------------------------------------------------------------------


@rule
def bgp_summary_states(ctx: Ctx):
    """Neighbour states that only the summary shows: 'Idle (PfxCt)' is a session torn down by maximum-prefix."""
    summary = ctx.get("bgp_summary")
    if not summary:
        return []
    out = []
    for row in summary["neighbors"]:
        value = row["state_or_prefixes"]
        if value.lower().startswith("idle (pfxct)"):
            out.append(F("RTR-BGP-030", "high", "BGP", f"neighbor {row['neighbor']} (AS {row['remote_as']}) was shut down by its maximum-prefix limit", obj=row["neighbor"],
                         detail="State 'Idle (PfxCt)': the peer sent more prefixes than 'neighbor … maximum-prefix' allows, so the router dropped the session and will not retry until the limit is cleared or the restart timer runs.",
                         recommendation="Check what the peer is announcing ('show ip bgp neighbors <ip> received-routes'); raise the limit only if the growth is legitimate, then 'clear ip bgp <ip>'.",
                         reference=R["bgp_max_prefix"]))
    return out
