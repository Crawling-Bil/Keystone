"""Findings about a main site and its recovery site (a data center and its DR site), read from the captures of both.

The sites are the ones the Overview draws (``auto_mode`` and ``groups_of``).  A recovery site is a site whose name says so (``sites.is_recovery``: HQ-DR, DRC); its twin is the
other site with the most cables to it, else the largest one.  Both need at least ``TWIN_MIN_DEVICES`` captured network devices: two sites of two switches are branches.

* TOPO-047  VLANs: a gateway interface (SVI or VLAN sub-interface) of one site that the other has no counterpart for,
* TOPO-048  routing: a routing protocol, an OSPF area or a VRF that one site uses and the other does not,
* TOPO-049  equipment: the number of firewalls, routers, load balancers ... differs between the two sites,
* TOPO-050  the data center interconnect (DCI): no cable at all between the captured devices of the two sites, one cable only, or every cable on one device at one end,
* TOPO-051  WAN providers (needs the L3 model): both sites reach the WAN through one and the same provider, or one site has a single provider,
* TOPO-052  first-hop gateways: the same HSRP / VRRP virtual address is configured at both sites (a stretched gateway: the hellos must not cross the interconnect),
* TOPO-053  MTU: a site runs jumbo frames and an interconnect port is at 1500 bytes (or the other way round: the interconnect is the smallest MTU on the path),
* TOPO-054  layer-2 stretch: the VLANs the interconnect trunks allow, every VLAN of them, and the VLANs that have a gateway at both sites,
* TOPO-055  layer-2 domains: the same vPC domain ID at both sites, or a different spanning-tree mode,
* TOPO-056  firewall high availability: the firewalls of the recovery site are not in HA like those of the main site, a pair has no captured peer or the same priority.

None of these is an error in itself: a recovery site may be smaller on purpose, and a VLAN may be stretched.  Each says what was compared and with what result, so the engineer
can set it against the design.  A comparison is made only when both sites showed the table in question (a site without a single SVI in its captures is not judged on VLANs).

References: Cisco Data Center Interconnect Design and Deployment Guide, System Release 2.0 (redundant devices and links at every layer, dual-homed sites)
https://www3-realm.cisco.com/en/US/docs/solutions/Enterprise/Data_Center/DCI/DCI2_External.pdf ;
Cisco, Understand and configure Nexus 9000 vPC https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html ;
NIST SP 800-34 Rev. 1, Contingency Planning Guide for Federal Information Systems https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final ;
IETF RFC 4116, IPv4 Multihoming Practices and Limitations https://www.rfc-editor.org/rfc/rfc4116.html ;
IETF RFC 2328, OSPF Version 2 (areas, section 3.1) https://datatracker.ietf.org/doc/html/rfc2328#section-3.1 ;
IETF RFC 7348, VXLAN, section 4.3 (the physical network's MTU must carry the encapsulation; a VTEP must not fragment) https://www.rfc-editor.org/rfc/rfc7348 ;
Cisco Press, CCNA Data Center, First Hop Redundancy Protocol Isolation (OTV filters the FHRP messages so each site keeps its own gateway) https://www.oreilly.com/library/view/ccna-data-center/9780133860429/ch04lev3sec7.html ;
Cisco, vPC best practices (each vPC domain within a contiguous Layer 2 network with a unique domain ID) https://community.cisco.com/t5/data-center-and-cloud-knowledge-base/vpc-best-practices-for-nexus-7000-and-5000/ta-p/3149258 ;
Palo Alto Networks, Configuration Guidelines for Active/Passive HA (same Group ID and mode on both firewalls, different device priorities) https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/high-availability/set-up-activepassive-ha/configuration-guidelines-for-activepassive-ha
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from . import sites
from .extract import Device
from .findings import _few, _row
from .functions import FUNCTION_LABEL
from .graph import Graph
from .layout import ENDPOINT_ROLES, auto_mode, groups_of
from . import evidence
from .paramfindings import _mtu, _record
from .peerfindings import _ACTIVE_STATES

DOC_DCI = "https://www3-realm.cisco.com/en/US/docs/solutions/Enterprise/Data_Center/DCI/DCI2_External.pdf"
DOC_VPC = "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"
DOC_DR_PLAN = "https://csrc.nist.gov/publications/detail/sp/800-34/rev-1/final"
DOC_MULTIHOMING = "https://www.rfc-editor.org/rfc/rfc4116.html"
DOC_OSPF_AREAS = "https://datatracker.ietf.org/doc/html/rfc2328#section-3.1"
DOC_VXLAN_MTU = "https://www.rfc-editor.org/rfc/rfc7348"
DOC_FHRP_ISOLATION = "https://www.oreilly.com/library/view/ccna-data-center/9780133860429/ch04lev3sec7.html"
DOC_VPC_DOMAIN = "https://community.cisco.com/t5/data-center-and-cloud-knowledge-base/vpc-best-practices-for-nexus-7000-and-5000/ta-p/3149258"
DOC_PAN_HA = "https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/high-availability/set-up-activepassive-ha/configuration-guidelines-for-activepassive-ha"

TWIN_MIN_DEVICES = 4            # a site needs this many captured network devices to be compared with its recovery site
TWIN_MIN_SHARE = 0.5            # a recovery site with no cable to a main site is its twin only when it has this share of its devices
_SVI = re.compile(r"^(?:vlan|vlanif|vl)\s*(\d{1,4})$", re.I)
_SUB = re.compile(r"[.](\d{1,4})$")
_PLAIN_VRF = {"", "management", "mgmt", "mgmt-intf", "root", "global", "default"}          # tables every device has: not a design choice
_NO_CABLE = ("host", "rollup")


def _network(graph: Graph, keys: list[str]) -> list[Device]:
    return [graph.nodes[k] for k in keys if k in graph.nodes and graph.nodes[k].captured and graph.nodes[k].role_hint not in ENDPOINT_ROLES]


def _cables(graph: Graph, owner: dict[str, str]) -> dict[tuple[str, str], list[Any]]:
    """The connections between two sites, by pair of site names (sorted)."""
    out: dict[tuple[str, str], list[Any]] = defaultdict(list)
    for conn in graph.connections:
        if conn.kind in _NO_CABLE or conn.kind in graph.hidden_kinds:
            continue
        a, b = owner.get(conn.a), owner.get(conn.b)
        if a and b and a != b:
            out[tuple(sorted((a, b)))].append(conn)
    return out


_NUMBERED = re.compile(r"^(.*\S)-(\d+)$")


def family_groups(groups: dict[str, list[str]]) -> dict[str, list[str]]:
    """The sites with the parts of one place joined again: the cables cut a place into HQ-1, HQ-2, HQ-3 (the firewall pair is not cabled to the switches) or DR-1, DR-2, and a
    data center is compared with its recovery site as a whole, not part by part.  Two or more sites named ``X-1``, ``X-2`` ..., or one of them beside the site ``X`` that kept the rest, are one site ``X`` here."""
    parts: dict[str, list[str]] = defaultdict(list)
    for name in groups:
        found = _NUMBERED.match(name) if name != sites.OTHER else None
        if found:
            parts[found.group(1)].append(name)
    joined = {base: names for base, names in parts.items() if len(names) >= 2 or base in groups}
    if not joined:
        return groups
    absorbed = {name for base, names in joined.items() for name in names + ([base] if base in groups else [])}
    out = {name: keys for name, keys in groups.items() if name not in absorbed}
    for base, names in joined.items():
        out[base] = [key for name in ([base] if base in groups else []) + names for key in groups[name]]
    return out


def twin_sites(graph: Graph, groups: dict[str, list[str]]) -> list[tuple[str, str]]:
    """(main site, recovery site) pairs: every site that is big enough and says in its name that it is a recovery site, with the other big site that has most cables to it.
    The parts of one place (HQ-1, HQ-2 ...) count as the place."""
    groups = family_groups(groups)
    devices = {name: _network(graph, keys) for name, keys in groups.items() if name != sites.OTHER}
    big = {name: len(found) for name, found in devices.items() if len(found) >= TWIN_MIN_DEVICES}
    owner = {key: name for name, keys in groups.items() for key in keys}
    cables = _cables(graph, owner)
    pairs: list[tuple[str, str]] = []
    for recovery in sorted(n for n in big if sites.is_recovery(n)):
        mains = [n for n in big if n != recovery and not sites.is_recovery(n)]
        if not mains:
            continue
        main = max(mains, key=lambda n: (len(cables.get(tuple(sorted((n, recovery))), [])), big[n], n))
        if not cables.get(tuple(sorted((main, recovery)))) and big[recovery] < TWIN_MIN_SHARE * big[main]:
            continue
        pairs.append((main, recovery))
    return pairs


def _vlans(nodes: list[Device]) -> dict[int, list[str]]:
    """VLAN id -> where the site has a gateway for it ("DEVICE Vlan10")."""
    out: dict[int, list[str]] = defaultdict(list)
    for node in nodes:
        for row in node.l3:
            if row.get("shutdown") or str(row.get("vrf", "")).lower() in ("management", "mgmt", "mgmt-intf"):
                continue
            kind, name = row.get("kind", ""), str(row.get("name", ""))
            found = _SVI.match(name) if kind == "SVI" else (_SUB.search(name) if kind == "Sub-interface" else None)
            if found:
                out[int(found.group(1))].append(f"{node.hostname} {name}")
    return out


def _areas(node: Device) -> set[str]:
    return {str(p["ospf"]["area"]) for p in (node.ifparams.get("ports") or {}).values() if isinstance(p, dict) and isinstance(p.get("ospf"), dict) and p["ospf"].get("area") not in (None, "")}


def _routing(nodes: list[Device]) -> dict[str, set[str]] | None:
    """What the site runs: protocols (from the routing neighbors), OSPF areas and VRFs; None when no device of the site showed a routing table or an address."""
    protocols = {str(n.get("protocol", "")).lower() for node in nodes for n in (node.l3facts.get("neighbors") or []) if n.get("protocol")}
    areas = {a for node in nodes for a in _areas(node)}
    vrfs = {str(r.get("vrf", "")) for node in nodes for r in node.l3 if not r.get("shutdown") and str(r.get("vrf", "")).lower() not in _PLAIN_VRF}
    if not (protocols or areas or any(node.l3 for node in nodes)):
        return None
    return {"protocol": protocols, "OSPF area": areas, "VRF": vrfs}


def _vlan_finding(main: str, recovery: str, m: dict[int, list[str]], r: dict[int, list[str]]) -> dict[str, Any] | None:
    if not (m and r):
        return None
    only_main, only_rec = sorted(set(m) - set(r)), sorted(set(r) - set(m))
    if not (only_main or only_rec):
        return None
    parts = []
    if only_main:
        parts.append(f"{main} has a gateway for VLAN {', '.join(map(str, only_main))} that {recovery} has not (" + _few([m[v][0] for v in only_main], 4) + ")")
    if only_rec:
        parts.append(f"{recovery} has a gateway for VLAN {', '.join(map(str, only_rec))} that {main} has not (" + _few([r[v][0] for v in only_rec], 4) + ")")
    devices = sorted({d.split()[0] for v in only_main for d in m[v]} | {d.split()[0] for v in only_rec for d in r[v]})
    return _row("TOPO-047", "low" if only_main else "info", f"{recovery} and {main} do not have the same VLAN gateways",
                f"{len(m)} VLAN gateways at {main}, {len(r)} at {recovery}. " + "; ".join(parts) + ".", devices,
                "If a VLAN is stretched over the interconnect, one site holds the gateway and this is the design; if the hosts of that VLAN must come up at the recovery site, "
                "it needs the same VLAN, a gateway (or an anycast gateway) and a trunk that allows it before the failover test, not after.", DOC_DR_PLAN)


def _routing_finding(main: str, recovery: str, m: dict[str, set[str]] | None, r: dict[str, set[str]] | None) -> dict[str, Any] | None:
    if not (m and r):
        return None
    lines = []
    for what in ("protocol", "OSPF area", "VRF"):
        a, b = m[what], r[what]
        if a == b or not (a or b):
            continue
        both = []
        if a - b:
            both.append(f"only at {main}: {', '.join(sorted(a - b))}")
        if b - a:
            both.append(f"only at {recovery}: {', '.join(sorted(b - a))}")
        lines.append(f"{what}: " + "; ".join(both))
    if not lines:
        return None
    return _row("TOPO-048", "low", f"{recovery} and {main} do not run the same routing", " | ".join(lines) + ".", [],
                "A recovery site that lacks the protocol, the OSPF area or the VRF of the main site cannot take its routes over unchanged. Compare it with the design: a different "
                "area or a missing VRF is a change to make before the failover, not during it.", DOC_OSPF_AREAS)


def _equipment_finding(main: str, recovery: str, m: list[Device], r: list[Device]) -> dict[str, Any] | None:
    a, b = Counter(n.role_hint or "other" for n in m), Counter(n.role_hint or "other" for n in r)
    diff = {role: (a[role], b[role]) for role in sorted(set(a) | set(b)) if a[role] != b[role]}
    fa, fb = Counter(getattr(n, "function", "") for n in m), Counter(getattr(n, "function", "") for n in r)
    fdiff = {f"{FUNCTION_LABEL[f].lower()}": (fa[f], fb[f]) for f in PARITY_FUNCTIONS if fa[f] != fb[f]}          # what the devices do: the same roles can still miss the edge or the management switch
    if not diff and not fdiff:
        return None
    fewer = any(y < x for x, y in list(diff.values()) + list(fdiff.values()))
    text = ", ".join(f"{role}: {x} at {main}, {y} at {recovery}" for role, (x, y) in list(diff.items()) + list(fdiff.items()))
    moved = {f for f in PARITY_FUNCTIONS if FUNCTION_LABEL[f].lower() in fdiff}
    return _row("TOPO-049", "low" if fewer else "info", f"{recovery} is not equipped like {main}", text + ".",
                sorted(n.hostname for n in (m + r) if (n.role_hint or "other") in diff or getattr(n, "function", "") in moved),
                "A smaller recovery site is a legitimate choice, but then the services it takes over must fit on it. Check that each role missing or reduced here "
                "(firewall pair, load balancer, WAN router, edge or management switch) is covered by the design and the capacity plan.", DOC_DR_PLAN)


def _dci_finding(graph: Graph, main: str, recovery: str, conns: list[Any], owner: dict[str, str]) -> dict[str, Any] | None:
    pair = f"{main} and {recovery}"
    if not conns:
        return _row("TOPO-050", "info", f"No cable between the captured devices of {pair}",
                    "The captures hold no link from a device of one site to a device of the other. Replication between them then rides the WAN or a provider circuit, "
                    "or an interconnect on a device that was not captured (a DWDM transponder, a provider handoff) that this diagram cannot show.", [],
                    "Capture the interconnect devices (or the switch ports that face them) so the DCI is drawn and checked for redundancy.", DOC_DCI)
    links = [(c, link) for c in conns for link in c.links]
    ends_main = Counter(c.a if owner.get(c.a) == main else c.b for c in conns)
    ends_rec = Counter(c.b if owner.get(c.a) == main else c.a for c in conns)
    cable_text = [f"{graph.nodes[c.a].hostname} {link.a_port} - {graph.nodes[c.b].hostname} {link.b_port}" for c, link in links]
    devices = sorted({graph.nodes[k].hostname for k in list(ends_main) + list(ends_rec)})
    if len(links) == 1:
        return _row("TOPO-050", "medium", f"One cable between {pair}", cable_text[0] + ".", devices,
                    "A single cable, transceiver or port is the whole interconnect. Add a second link on a second device at each end (a vPC or MLAG pair) so one failure "
                    "does not isolate the recovery site.", DOC_DCI)
    single = [(site, next(iter(ends))) for site, ends in ((main, ends_main), (recovery, ends_rec)) if len(ends) == 1]
    if single:
        names = " and ".join(f"{graph.nodes[k].hostname} at {site}" for site, k in single)
        return _row("TOPO-050", "medium", f"Every cable between {pair} ends on one device: {names}", f"{len(links)} cable(s): " + _few(cable_text, 6) + ".", devices,
                    "The cables are redundant but the device is not: its failure or reload cuts the interconnect. Spread the links over the two devices of a pair "
                    "(vPC, VSS or MLAG; on Nexus with vPC the two chassis form one bundle), or add a second interconnect device.", DOC_VPC)
    return None



STRETCH_ALL = 4000              # a trunk that allows this many VLANs or more allows every VLAN
JUMBO = 1500                    # an MTU above this is a jumbo frame setting


def _vlan_ids(text: Any) -> set[int]:
    """The VLAN ids of a trunk's allowed list as printed ("1-4094", "10,21-23", "all", "none")."""
    ids: set[int] = set()
    for part in re.split(r"[,\s]+", str(text or "").lower()):
        if part == "all":
            ids |= set(range(1, 4095))
            continue
        found = re.fullmatch(r"(\d{1,4})(?:-(\d{1,4}))?", part)
        if found:
            low, high = int(found.group(1)), int(found.group(2) or found.group(1))
            if 1 <= low <= high <= 4094:
                ids |= set(range(low, high + 1))
    return ids


def _interconnect(graph: Graph, conns: list[Any], owner: dict[str, str], main: str) -> list[tuple[Device, str, Device, str]]:
    """Every cable between the two sites as (main device, its port, recovery device, its port)."""
    out = []
    for conn in conns:
        for link in conn.links:
            near, far = (link.a, link.b) if owner.get(link.a) == main else (link.b, link.a)
            near_port, far_port = (link.a_port, link.b_port) if near == link.a else (link.b_port, link.a_port)
            if near in graph.nodes and far in graph.nodes:
                out.append((graph.nodes[near], near_port, graph.nodes[far], far_port))
    return out


def _fhrp_addresses(nodes: list[Device]) -> dict[str, list[dict[str, str]]]:
    """Virtual address -> the groups that use it at a site (device, protocol, group, interface, state)."""
    out: dict[str, list[dict[str, str]]] = defaultdict(list)
    for node in nodes:
        for row in (node.l3facts or {}).get("fhrp") or []:
            ip = str(row.get("virtual_ip") or "")
            if ip:
                out[ip].append({"device": node.hostname, "protocol": str(row.get("protocol") or "FHRP").upper(), "group": str(row.get("group", "")),
                                "interface": str(row.get("interface") or ""), "state": str(row.get("state") or "")})
    return out


def _fhrp_finding(main: str, recovery: str, m: list[Device], r: list[Device]) -> dict[str, Any] | None:
    a, b = _fhrp_addresses(m), _fhrp_addresses(r)
    shared = sorted(set(a) & set(b))
    if not shared:
        return None
    both_active = [ip for ip in shared if any(x["state"].lower() in _ACTIVE_STATES for x in a[ip]) and any(x["state"].lower() in _ACTIVE_STATES for x in b[ip])]
    lines = [f"{ip}: " + "; ".join(f"{x['protocol']} {x['group']} on {x['device']} {x['interface']}".replace("  ", " ") for x in (a[ip][:1] + b[ip][:1])) for ip in shared]
    detail = f"{len(shared)} gateway address(es) are configured at both {main} and {recovery}: " + _few(lines, 4) + "."
    if both_active:
        detail += f" The group is Active (Master) at both sites for {_few(both_active, 4)}."
    devices = sorted({x["device"] for ip in shared for x in a[ip] + b[ip]})
    return _row("TOPO-052", "medium" if both_active else "low", f"{main} and {recovery} use the same gateway address", detail, devices,
                "One virtual gateway address at two sites is a stretched VLAN. Keep the first-hop redundancy hellos (HSRP, VRRP) from crossing the interconnect (FHRP isolation: filter them "
                "on the interconnect devices) so each site keeps a local active gateway, and decide which site answers for the subnet during a failover. If the address is the same "
                "only because the recovery site was cloned from the main one, change it before the VLAN is ever stretched.", DOC_FHRP_ISOLATION)


def _port_mtus(node: Device) -> list[int]:
    return [int(v) for rec in ((node.ifparams or {}).get("ports") or {}).values() if isinstance(rec, dict) for k in ("mtu", "ip_mtu") for v in [rec.get(k)] if v]


def _mtu_finding(main: str, recovery: str, cables: list[tuple[Device, str, Device, str]], m: list[Device], r: list[Device]) -> dict[str, Any] | None:
    inside = [v for node in m + r for v in _port_mtus(node)]
    jumbo_inside = max(inside, default=0)
    global_jumbo = any((node.ifparams or {}).get("global_mtu") for node in m + r)
    if jumbo_inside <= JUMBO and not global_jumbo:
        return None
    lines, devices = [], set()
    for near, near_port, far, far_port in cables:
        for node, port in ((near, near_port), (far, far_port)):
            value = _mtu(node, _record(node, port))
            if value and value <= JUMBO:
                lines.append(f"{node.hostname} {node.bundle_of.get(port) or port}: {value} bytes")
                devices.add(node.hostname)
    if not lines:
        return None
    inside_text = f"up to {jumbo_inside} bytes" if jumbo_inside > JUMBO else "a jumbo setting (system-wide)"
    return _row("TOPO-053", "medium", f"The interconnect between {main} and {recovery} is at 1500 bytes while the sites use jumbo frames",
                f"Ports inside the sites use {inside_text}; on the interconnect: " + _few(sorted(set(lines)), 6) + ".", sorted(devices),
                "Frames larger than the smallest MTU on the path are dropped or fragmented, and a large replication or vMotion packet stalls while small ones (ping) pass. Set the "
                "interconnect ports (and every device in between) to the largest MTU inside the sites plus the encapsulation overhead - about 50 bytes for VXLAN over IPv4 "
                "(RFC 7348 section 4.3 says the physical network must carry it, and that a VTEP must not fragment) - or lower the MTU of the hosts. Test with "
                "a don't-fragment ping of the full size between the two sites.", DOC_VXLAN_MTU)


def _stretch(cables: list[tuple[Device, str, Device, str]]) -> set[int]:
    out: set[int] = set()
    for near, near_port, far, far_port in cables:
        a = near.port_allowed.get(near.bundle_of.get(near_port) or near_port) or near.port_allowed.get(near_port)
        b = far.port_allowed.get(far.bundle_of.get(far_port) or far_port) or far.port_allowed.get(far_port)
        out |= _vlan_ids(a) & _vlan_ids(b)
    return out


def _stretch_finding(main: str, recovery: str, cables: list[tuple[Device, str, Device, str]], m: dict[int, list[str]], r: dict[int, list[str]]) -> dict[str, Any] | None:
    stretched = _stretch(cables)
    if not stretched:
        return None
    everything = len(stretched) >= STRETCH_ALL
    both = sorted(stretched & set(m) & set(r))
    if not (everything or both):
        return None
    parts = [f"{len(stretched)} VLAN(s) are allowed on the interconnect trunks at both ends" + (" (every VLAN)" if everything else "")]
    if both:
        parts.append(f"VLAN {', '.join(map(str, both[:12]))}{' ...' if len(both) > 12 else ''} {'has' if len(both) == 1 else 'have'} a gateway at both {main} and {recovery}")
    devices = sorted({n.hostname for near, _, far, _ in cables for n in (near, far)})
    return _row("TOPO-054", "low", f"The interconnect between {main} and {recovery} stretches layer 2", "; ".join(parts) + ".", devices,
                "Allow only the VLANs that must exist at both sites on the interconnect trunk: a failure domain (a broadcast storm, a spanning-tree change) then stops at the interconnect. "
                "A VLAN that has a gateway at both sites and is stretched needs one active gateway and FHRP isolation, or the sites answer for the same subnet.", DOC_DCI)


def _layer2_interconnect(cables: list[tuple[Device, str, Device, str]]) -> bool:
    """Do the cables between the sites carry layer 2: a trunk or access port at either end, or VLANs allowed on it?  A routed interconnect does not join the two vPC domains."""
    for near, near_port, far, far_port in cables:
        for node, port in ((near, near_port), (far, far_port)):
            key = node.bundle_of.get(port) or port
            if node.port_modes.get(key) in ("trunk", "access") or node.port_modes.get(port) in ("trunk", "access") or node.port_allowed.get(key) or node.port_allowed.get(port):
                return True
    return False


def _l2_domain_finding(main: str, recovery: str, m: list[Device], r: list[Device], cables: list[tuple[Device, str, Device, str]]) -> dict[str, Any] | None:
    lines, devices = [], set()
    domains_m = {n.vpc_domain: n.hostname for n in m if n.vpc_domain}
    domains_r = {n.vpc_domain: n.hostname for n in r if n.vpc_domain}
    layer2 = _layer2_interconnect(cables)
    if layer2:
        for domain in sorted(set(domains_m) & set(domains_r)):
            lines.append(f"vPC domain {domain} at both sites ({domains_m[domain]} and {domains_r[domain]}) and the interconnect carries layer 2")
            devices.update((domains_m[domain], domains_r[domain]))
    modes_m, modes_r = {n.stp_protocol.lower() for n in m if n.stp_protocol}, {n.stp_protocol.lower() for n in r if n.stp_protocol}
    if layer2 and modes_m and modes_r and modes_m != modes_r:
        lines.append(f"spanning tree {'/'.join(sorted(modes_m))} at {main}, {'/'.join(sorted(modes_r))} at {recovery}")
        devices.update(n.hostname for n in m + r if n.stp_protocol)
    if not lines:
        return None
    return _row("TOPO-055", "low", f"{main} and {recovery}: the layer-2 domains are not set apart", "; ".join(lines) + ".", sorted(devices),
                "Cisco recommends a unique vPC domain ID in each contiguous Layer 2 network, because the domain ID makes the vPC system MAC (used by LACP and spanning tree): the same ID "
                "on both sides of a layer-2 interconnect is a vPC that can fail to come up or a bundle that flaps. Use a different domain ID at the recovery site, or keep the interconnect routed. "
                "Different spanning-tree modes meet at the interconnect: choose one mode for both sites, or keep the interconnect routed.", DOC_VPC_DOMAIN)


def _is_firewall(node: Device) -> bool:
    return node.role_hint == "firewall"


def _ha_state(graph: Graph, nodes: list[Device]) -> dict[str, Any]:
    units = [n for n in nodes if _is_firewall(n)]
    modes = Counter(str(n.l3facts.get("ha") or "") for n in units)
    assumed = sorted(n.hostname for n in units if any(l.a == n.key and l.b.startswith("HAPEER-") or l.b == n.key and l.a.startswith("HAPEER-") for l in graph.links if "HA" in l.protocols))
    return {"units": units, "modes": modes, "in_ha": sum(c for mode, c in modes.items() if mode), "assumed": assumed}


def _equal_priority(graph: Graph, nodes: list[Device]) -> list[str]:
    keys, out = {n.key for n in nodes}, []
    for link in graph.links:
        if "HA" not in link.protocols or link.a not in keys or link.b not in keys:
            continue
        a, b = (graph.nodes[link.a].l3facts.get("pan_ha") or {}), (graph.nodes[link.b].l3facts.get("pan_ha") or {})
        label = f"{graph.nodes[link.a].hostname} and {graph.nodes[link.b].hostname}"
        if a.get("priority") not in (None, "") and a.get("priority") == b.get("priority") and label not in out:
            out.append(label)
    return out


def _firewall_ha_finding(graph: Graph, main: str, recovery: str, m: list[Device], r: list[Device]) -> dict[str, Any] | None:
    a, b = _ha_state(graph, m), _ha_state(graph, r)
    if not (a["units"] and b["units"]):
        return None
    lines, weaker = [], False
    modes_a, modes_b = {k for k in a["modes"] if k}, {k for k in b["modes"] if k}
    share_a, share_b = a["in_ha"] / len(a["units"]), b["in_ha"] / len(b["units"])
    if share_b < share_a:
        weaker = True
        lines.append(f"{b['in_ha']} of {len(b['units'])} firewalls at {recovery} have high availability, {a['in_ha']} of {len(a['units'])} at {main}")
    if modes_a and modes_b and modes_a != modes_b:
        lines.append(f"HA mode {'/'.join(sorted(modes_a))} at {main}, {'/'.join(sorted(modes_b))} at {recovery}")
    for site, state in ((main, a), (recovery, b)):
        if state["assumed"]:
            lines.append(f"{site}: {_few(state['assumed'], 4)} named a peer that was not captured")
    same = _equal_priority(graph, m + r)
    if same:
        lines.append(f"the device priority is the same on both units of {_few(same, 3)}")
    if not lines:
        return None
    devices = sorted(n.hostname for n in a["units"] + b["units"])
    return _row("TOPO-056", "medium" if weaker else "low", f"{recovery} firewalls are not in high availability like {main}", "; ".join(lines) + ".", devices,
                "A recovery site whose firewalls are single units loses its protection on the first failure, and one failover test then ends the service. Configure the pair "
                "(same HA mode and Group ID on both units, different device priorities), capture both units so the pair is checked from both ends, and compare the pair "
                "with the main site.", DOC_PAN_HA)


def _providers(graph: Graph, model: Any, owner: dict[str, str]) -> dict[str, set[str]]:
    """Site -> the providers its devices are linked to in the L3 model (the clouds are named ``CLOUD:<kind>:<provider>``)."""
    out: dict[str, set[str]] = defaultdict(set)
    for edge in model.edges:
        for cloud, other in ((edge.a, edge.b), (edge.b, edge.a)):
            node = model.nodes.get(cloud)
            if node is not None and node.role_hint == "cloud" and other in owner and cloud.count(":") >= 2:
                out[owner[other]].add(cloud.split(":", 2)[2])
    return out


def _provider_finding(main: str, recovery: str, providers: dict[str, set[str]]) -> dict[str, Any] | None:
    m, r = providers.get(main, set()), providers.get(recovery, set())
    if not (m and r):
        return None
    if len(m | r) == 1:
        name = next(iter(m))
        return _row("TOPO-051", "medium", f"{main} and {recovery} reach the WAN through one provider only: {name}", f"Every provider cloud of both sites is {name}.", [],
                    "One provider outage, one fibre cut in its core or one billing dispute takes the main site and its recovery site off the WAN together. Take the circuits "
                    "of one site from another provider, on a separate physical route (ask for the route diversity in writing).", DOC_MULTIHOMING)
    single = [(site, next(iter(p))) for site, p in ((main, m), (recovery, r)) if len(p) == 1]
    if single:
        text = "; ".join(f"{site}: {name} only" for site, name in single)
        return _row("TOPO-051", "low", "A site of the pair has a single WAN provider", f"{text}; {main}: {', '.join(sorted(m))}; {recovery}: {', '.join(sorted(r))}.", [],
                    "A site with one provider has no WAN path left when that provider fails. For a data center or its recovery site, take a second provider on a separate route.",
                    DOC_MULTIHOMING)
    return None


def _pair_contexts(graph: Graph, model: Any = None) -> list[dict[str, Any]]:
    """Everything that compares one main site with its recovery site, for every pair ``twin_sites`` finds: the devices of both, the cables between them, the providers."""
    visible = [k for k in graph.nodes if k not in graph.hidden_nodes]
    if len(visible) < 2 * TWIN_MIN_DEVICES:
        return []
    mode = auto_mode(graph)
    if mode == "none":
        return []
    groups = family_groups(groups_of(graph, mode))
    pairs = twin_sites(graph, groups)
    if not pairs:
        return []
    owner = {key: name for name, keys in groups.items() for key in keys}
    cables = _cables(graph, owner)
    providers = _providers(graph, model, owner) if model is not None else {}
    out = []
    for main, recovery in pairs:
        conns = cables.get(tuple(sorted((main, recovery))), [])
        out.append({"main": main, "recovery": recovery, "m": _network(graph, groups[main]), "r": _network(graph, groups[recovery]), "conns": conns,
                    "cables": _interconnect(graph, conns, owner, main), "owner": owner, "providers": providers})
    return out


def _pair_findings(graph: Graph, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    main, recovery, m, r = ctx["main"], ctx["recovery"], ctx["m"], ctx["r"]
    vlans_m, vlans_r = _vlans(m), _vlans(r)
    found = [
        _vlan_finding(main, recovery, vlans_m, vlans_r),
        _routing_finding(main, recovery, _routing(m), _routing(r)),
        _equipment_finding(main, recovery, m, r),
        _dci_finding(graph, main, recovery, ctx["conns"], ctx["owner"]),
        _provider_finding(main, recovery, ctx["providers"]),
        _fhrp_finding(main, recovery, m, r),
        _mtu_finding(main, recovery, ctx["cables"], m, r),
        _stretch_finding(main, recovery, ctx["cables"], vlans_m, vlans_r),
        _l2_domain_finding(main, recovery, m, r, ctx["cables"]),
        _firewall_ha_finding(graph, main, recovery, m, r),
    ]
    for row in found:
        if row and row["id"] in ("TOPO-047", "TOPO-048"):
            row["detail"] += f" Compared on {len(m)} captured network device(s) at {main} and {len(r)} at {recovery}: a device that was not captured can hold what is missing."
    return [row for row in found if row]


def site_findings(graph: Graph, model: Any = None) -> list[dict[str, Any]]:
    """TOPO-047 to TOPO-056 for every main site and recovery site pair; ``model`` (the L3 model) is needed for the providers only."""
    return [row for ctx in _pair_contexts(graph, model) for row in _pair_findings(graph, ctx)]


# ----------------------------------------------------------------------------------------------------------------- the parity table
OUTSIDE_THE_CAPTURES = (
    ("Disaster recovery plan tested within the last 12 months", "The test record: date, scope (every critical application and infrastructure), who took part, result and the corrections.",
     f"{evidence.OJK} Pasal 18; {evidence.NIST} CP-4 Contingency Plan Testing; {evidence.ISO} A.5.30"),
    ("Recovery time and recovery point objective per application", "The business impact analysis. The diagram shows the path and the equipment, not how long a service may be down or how much data may be lost.",
     f"{evidence.OJK} Pasal 18; {evidence.NIST} CP-2 Contingency Plan; {evidence.ISO} A.5.30"),
    ("Distance and risk separation between the two sites", "The site survey: flood, power grid, seismic and access zones. A cable and a name cannot show it.",
     f"{evidence.OJK} Pasal 37; {evidence.NIST} CP-7 Alternate Processing Site"),
    ("Replication and failover method per application", "Storage, database and virtualization replication, DNS and load balancer switch-over: a capture of the network does not hold them.",
     f"{evidence.OJK} Pasal 37; {evidence.ISO} A.8.14; {evidence.NIST} CP-2 Contingency Plan"),
)


def _result(a: Any, b: Any, shown: bool = True) -> str:
    if not shown:
        return "not shown at one site"
    return "same" if a == b else "differs"


def _names(values: Any, limit: int = 8) -> str:
    items = sorted(str(v) for v in values)
    return _few(items, limit) if items else "none"


def _port_summary(nodes: list[Device]) -> tuple[int, bool]:
    return max([v for n in nodes for v in _port_mtus(n)], default=0), any((n.ifparams or {}).get("global_mtu") for n in nodes)


PARITY_FUNCTIONS = ("edge", "distribution", "tor", "management", "internet", "partner", "wan")      # the functions that the DR parity table lists beside the roles


def parity_rows(graph: Graph, model: Any = None) -> list[dict[str, str]]:
    """One row per thing that the captures show at both sites of every main / recovery pair: what the main site has, what the recovery site has, whether they are the same, and the
    finding that explains a difference.  Then the evidence an audit asks for that no capture holds, marked ``needs input``: the table is the sheet to fill in with the design."""
    rows: list[dict[str, str]] = []
    for ctx in _pair_contexts(graph, model):
        main, recovery, m, r = ctx["main"], ctx["recovery"], ctx["m"], ctx["r"]
        pair = f"{main} / {recovery}"
        ids = {row["id"] for row in _pair_findings(graph, ctx)}

        def add(area: str, aspect: str, a: Any, b: Any, result: str, finding: str = "", note: str = "") -> None:
            rows.append({"pair": pair, "area": area, "aspect": aspect, main_label(main): str(a), recovery_label(recovery): str(b), "result": result,
                         "finding": finding if finding in ids else "", "control": evidence.controls_text(finding), "note": note})

        def main_label(name: str) -> str:
            return "main site"

        def recovery_label(name: str) -> str:
            return "recovery site"

        add("Equipment", "Captured network devices", len(m), len(r), _result(len(m), len(r)), "TOPO-049")
        roles_m, roles_r = Counter(n.role_hint or "other" for n in m), Counter(n.role_hint or "other" for n in r)
        for role in sorted(set(roles_m) | set(roles_r)):
            add("Equipment", f"Role: {role}", roles_m[role], roles_r[role], _result(roles_m[role], roles_r[role]), "TOPO-049")
        fn_m, fn_r = Counter(getattr(n, "function", "") for n in m), Counter(getattr(n, "function", "") for n in r)
        for function in PARITY_FUNCTIONS:                       # what a device does (functions.py): the recovery site should have the same edge, rack and management switches
            if fn_m[function] or fn_r[function]:
                add("Equipment", f"Function: {FUNCTION_LABEL[function].lower()}", fn_m[function], fn_r[function], _result(fn_m[function], fn_r[function]), "TOPO-049",
                    "; ".join(f"{n.hostname}: {n.function_why}" for n in (m + r) if getattr(n, "function", "") == function and getattr(n, "function_why", ""))[:300])
        vm, vr = _vlans(m), _vlans(r)
        shown = bool(vm and vr)
        add("VLANs", "VLAN gateways (SVI, sub-interface)", len(vm), len(vr), _result(set(vm), set(vr), shown), "TOPO-047",
            f"only at {main}: {_names(set(vm) - set(vr))}; only at {recovery}: {_names(set(vr) - set(vm))}" if shown and set(vm) != set(vr) else "")
        rm, rr = _routing(m), _routing(r)
        for what in ("protocol", "OSPF area", "VRF"):
            a, b = (rm or {}).get(what, set()), (rr or {}).get(what, set())
            add("Routing", {"protocol": "Routing protocols", "OSPF area": "OSPF areas", "VRF": "VRFs"}[what], _names(a), _names(b), _result(a, b, bool(rm and rr)), "TOPO-048")
        fa, fb = _fhrp_addresses(m), _fhrp_addresses(r)
        add("Gateways", "HSRP / VRRP virtual addresses", len(fa), len(fb), "same virtual address at both sites" if set(fa) & set(fb) else _result(len(fa), len(fb), bool(fa and fb)),
            "TOPO-052", _names(set(fa) & set(fb)) if set(fa) & set(fb) else "")
        dm, dr = {n.vpc_domain for n in m if n.vpc_domain}, {n.vpc_domain for n in r if n.vpc_domain}
        add("Layer 2", "vPC domain IDs", _names(dm), _names(dr), "same domain ID at both sites" if dm & dr else _result(dm, dr, bool(dm and dr)), "TOPO-055")
        sm, sr = {n.stp_protocol.lower() for n in m if n.stp_protocol}, {n.stp_protocol.lower() for n in r if n.stp_protocol}
        add("Layer 2", "Spanning-tree mode", _names(sm), _names(sr), _result(sm, sr, bool(sm and sr)), "TOPO-055")
        ha_m, ha_r = _ha_state(graph, m), _ha_state(graph, r)
        if ha_m["units"] or ha_r["units"]:
            add("Firewalls", "Firewalls in high availability", f"{ha_m['in_ha']} of {len(ha_m['units'])}", f"{ha_r['in_ha']} of {len(ha_r['units'])}",
                _result((ha_m["in_ha"], len(ha_m["units"])), (ha_r["in_ha"], len(ha_r["units"])), bool(ha_m["units"] and ha_r["units"])), "TOPO-056")
        top_m, jumbo_m = _port_summary(m)
        top_r, jumbo_r = _port_summary(r)
        text = lambda top, jumbo: f"{top} bytes" if top else ("jumbo (system-wide)" if jumbo else "not set")
        add("MTU", "Largest MTU configured", text(top_m, jumbo_m), text(top_r, jumbo_r), _result((top_m, jumbo_m), (top_r, jumbo_r)), "TOPO-053")
        cables = ctx["cables"]
        ends_m, ends_r = {n.hostname for n, _, _, _ in cables}, {n.hostname for _, _, n, _ in cables}
        add("Interconnect", "Cables between the sites", len(cables), len(cables), "same" if cables else "no cable captured", "TOPO-050")
        add("Interconnect", "Devices that carry the interconnect", _names(ends_m), _names(ends_r), _result(len(ends_m), len(ends_r), bool(cables)), "TOPO-050")
        stretched = _stretch(cables)
        add("Interconnect", "VLANs allowed on the interconnect trunks", len(stretched), len(stretched), "stretched" if stretched else "none shown", "TOPO-054")
        pm, pr = ctx["providers"].get(main, set()), ctx["providers"].get(recovery, set())
        add("WAN", "Providers", _names(pm), _names(pr), _result(pm, pr, bool(pm and pr)), "TOPO-051")
        for aspect, where, control in OUTSIDE_THE_CAPTURES:
            rows.append({"pair": pair, "area": "Outside the captures", "aspect": aspect, "main site": "", "recovery site": "", "result": "needs input", "finding": "", "control": control, "note": where})
    return rows
