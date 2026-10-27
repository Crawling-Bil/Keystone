"""Turn a terminal capture into one parsed context object.

``gather`` finds the config block and each known ``show`` block, runs the
matching parser inside a try/except (a parser bug must degrade one tab, not
the whole analysis) and records which capture blocks were consumed so the
Coverage tab can say what was understood, what was ignored and why.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from ..analyzer_core import capture as cap
from ..analyzer_core.vendor_hint import wrong_page_hint
from . import config_extract, config_tree, ipsec as ipsecmod, nat as natmod, ospf as ospfmod, runtime, runtime_health as rh, runtime_logs as rl, runtime_protocols as rpr, runtime_routing as rr, runtime_sdwan as rsd, runtime_sdwan_extra as rse, runtime_vpn as rv, techsupport, xref
from .ifnames import canon

# Terminal log captured from a router (prompts present) or a bare config.
CONFIG_TEMPLATES = ("show running-config", "show startup-config")
SDWAN_CONFIG_TEMPLATES = ("show sdwan running-config",)


@dataclass
class Spec:
    key: str
    label: str
    templates: tuple[str, ...]
    parser: Callable[[list[str]], Any]
    # what the engineer loses when the command is missing
    purpose: str
    multi: bool = False  # parse every matching block (e.g. per-VRF routes)
    optional: bool = False  # absence is normal (SD-WAN commands on a classic router)
    # A command that ran fine but has nothing to list prints a header, a counter of zero or a one-line notice.  When the
    # parser returns nothing, these say whether the block is such an empty answer (a result) or an unreadable one (a gap).
    empty_marker: str = ""                 # regex searched in the block: an explicit "0 entries" statement
    empty_lines: tuple[str, ...] = ()      # regexes; the block is empty when every non-blank line matches one of them
    empty_note: str = "the device reports no entries"


SPECS: list[Spec] = [
    Spec("version", "show version", ("show version",), runtime.parse_version, "Exact software release, uptime, reload reason, memory and licence."),
    Spec("clock", "show clock", ("show clock",), lambda lines: runtime.parse_clock(lines), "Capture time, used to judge BGP/OSPF uptimes and counters."),
    Spec("clock_detail", "show clock detail", ("show clock detail",), runtime.parse_clock_detail, "Capture time plus whether it is sourced from NTP or set by hand."),
    Spec("ipbrief", "show ip interface brief", ("show ip interface brief",), runtime.parse_ip_interface_brief, "Live up/down state of every interface."),
    Spec("ifdesc", "show interfaces description", ("show interfaces description",), runtime.parse_interface_description, "Interface descriptions as the device sees them."),
    Spec("ifstats", "show interfaces", ("show interfaces",), runtime.parse_show_interfaces, "Errors, drops, load, duplex/speed and traffic rates per interface."),
    Spec("ifsummary", "show interfaces summary", ("show interfaces summary",), runtime.parse_interfaces_summary, "Queue drops and rates (cross-check for show interfaces)."),
    Spec("inventory", "show inventory", ("show inventory",), runtime.parse_inventory, "Chassis, modules, transceivers, serial numbers (support/RMA)."),
    Spec("access_lists", "show access-lists", ("show access-lists", "show ip access-lists"), runtime.parse_access_lists, "ACL hit counters: which entries are actually matched."),
    Spec("route_map_stats", "show route-map", ("show route-map",), runtime.parse_route_map_stats, "Route-map clause match counters."),
    Spec("cache_flow", "show ip cache flow", ("show ip cache flow",), runtime.parse_cache_flow, "Legacy NetFlow cache summary."),
    Spec("policy_interface", "show policy-map interface", ("show policy-map interface",), runtime.parse_policy_map_interface, "QoS class statistics where a policy is attached."),
    Spec("bgp_table", "show ip bgp", ("show ip bgp", "show bgp ipv4 unicast", "show ip bgp ipv4 unicast"), rr.parse_bgp_table, "BGP paths, best path, RIB-failures.", empty_marker=r"%\s*BGP not active", empty_note="BGP is not running on this device"),
    Spec("bgp_neighbors", "show ip bgp neighbors", ("show ip bgp neighbors", "show bgp ipv4 unicast neighbors", "show ip bgp ipv4 unicast neighbors"), rr.parse_bgp_neighbors, "BGP session state, uptime, prefixes, last reset reason.", empty_marker=r"%\s*BGP not active", empty_note="BGP is not running on this device"),
    Spec("bgp_summary", "show ip bgp summary", ("show ip bgp summary", "show bgp ipv4 unicast summary", "show ip bgp ipv4 unicast summary"), rr.parse_bgp_summary, "One-line-per-neighbor BGP state (used when neighbors detail is absent).", empty_marker=r"%\s*BGP not active", empty_note="BGP is not running on this device"),
    Spec("ospf_neighbors", "show ip ospf neighbor", ("show ip ospf neighbor",), rr.parse_ospf_neighbors, "OSPF adjacency state.", empty_lines=(r"Neighbor ID\s+Pri\s+State\s+Dead Time\s+Address\s+Interface",), empty_note="headers only: no OSPF neighbors"),
    Spec("ospf_interfaces", "show ip ospf interface brief", ("show ip ospf interface brief",), rr.parse_ospf_interface_brief, "OSPF enabled interfaces, cost, state."),
    Spec("eigrp_neighbors", "show ip eigrp neighbors", ("show ip eigrp neighbors",), rr.parse_eigrp_neighbors, "EIGRP adjacency state.", empty_lines=(r"(?:IP-EIGRP neighbors for process \d+|EIGRP-IPv4 Neighbors for AS\(\d+\)(?:/VRF\(\S+\))?)", r"H\s+Address\s+Interface\s+Hold Uptime\s+SRTT\s+RTO\s+Q\s+Seq", r"\(sec\)\s+\(ms\)\s+Cnt Num"), empty_note="headers only: no EIGRP neighbors"),
    Spec("standby", "show standby brief", ("show standby brief",), rr.parse_standby_brief, "HSRP active/standby state.", empty_lines=(r"Interface\s+Grp\s+(?:Pri\s+P\s+)?State\s+Active\s+Standby\s+Virtual IP",), empty_note="headers only: no HSRP groups"),
    Spec("vrrp", "show vrrp brief", ("show vrrp brief",), rr.parse_vrrp_brief, "VRRP master/backup state.", empty_lines=(r"Interface\s+Grp\s+Pri\s+Time\s+Own\s+Pre\s+State\s+Master addr\s+Group addr",), empty_note="headers only: no VRRP groups"),
    Spec("ip_protocols", "show ip protocols", ("show ip protocols",), rpr.parse_ip_protocols, "Which routing protocols the router runs now, their router IDs, redistribution and information sources.", empty_lines=(r"\*\*\* IP Routing is NSF aware \*\*\*",), empty_note="no routing protocol is running"),
    Spec("ntp_status", "show ntp status", ("show ntp status",), rr.parse_ntp_status, "Is the clock synchronised, and to whom."),
    Spec("ntp_associations", "show ntp associations", ("show ntp associations",), rr.parse_ntp_associations,
         "Per-peer NTP state: which configured server is actually the sync peer, and which one has never been reached.",
         empty_lines=(r"address\s+ref clock\s+st\s+when\s+poll reach\s+delay\s+offset\s+disp", r"\*\s*sys\.peer.*~\s*configured"), empty_note="no NTP peers are configured"),
    Spec("ip_sla_stats", "show ip sla statistics", ("show ip sla statistics",), rr.parse_ip_sla_statistics,
         "Live success/failure counters per IP SLA probe — whether a probe used for tracking or failover has ever actually succeeded.",
         empty_lines=(r"IPSLAs Latest Operation Statistics",), empty_note="no IP SLA operations are configured"),
    Spec("gdoi", "show crypto gdoi", ("show crypto gdoi",), rv.parse_gdoi, "GETVPN group, key servers, downloaded policy and TEK/KEK state."),
    Spec("gdoi_gm", "show crypto gdoi gm", ("show crypto gdoi gm",), rv.parse_gdoi_gm, "GETVPN group-member registration timers."),
    Spec("crypto_session", "show crypto session", ("show crypto session detail", "show crypto session"), rv.parse_crypto_session, "IPsec/GETVPN session state and flows."),
    Spec("ipsec_sa", "show crypto ipsec sa", ("show crypto ipsec sa",), rv.parse_ipsec_sa, "Encrypt/decrypt counters and errors per SA.", empty_marker=r"^\s*No SAs found", empty_note="no IPsec SAs exist"),
    Spec("isakmp_sa", "show crypto isakmp sa", ("show crypto isakmp sa",), rv.parse_isakmp_sa, "IKE phase-1 state.", empty_lines=(r"IPv[46] Crypto ISAKMP SA", r"dst\s+src\s+state\s+conn-id\s+(?:status|slot\s+status)"), empty_note="headers only: no IKE phase-1 SAs"),
    Spec("sdwan_status", "show sdwan system status", ("show sdwan system status",), rv.parse_sdwan_system_status, "SD-WAN daemons, controller compatibility, uptime.", optional=True),
    Spec("sdwan_control", "show sdwan control connections", ("show sdwan control connections",), rv.parse_sdwan_control_connections, "Control connections to vSmart/vManage/vBond.", optional=True),
    Spec("sdwan_history", "show sdwan control connection-history", ("show sdwan control connection-history",), rv.parse_sdwan_control_history, "Why control connections dropped or could not come up (device error codes, repeat counts).", optional=True),
    Spec("sdwan_bfd", "show sdwan bfd sessions", ("show sdwan bfd sessions",), rv.parse_sdwan_bfd_sessions, "Overlay tunnel (BFD) sessions between sites.", optional=True),
    Spec("sdwan_omp_peers", "show sdwan omp peers", ("show sdwan omp peers",), rsd.parse_omp_peers, "OMP sessions to the vSmart controllers and how many routes each sends and installs.", optional=True),
    Spec("sdwan_omp_tlocs", "show sdwan omp tlocs", ("show sdwan omp tlocs",), rsd.parse_omp_tlocs, "Transport locators (system IP, color, encapsulation) the router has learned or advertises, with their BFD state.", optional=True),
    Spec("sdwan_omp_routes", "show sdwan omp routes", ("show sdwan omp routes",), rsd.parse_omp_routes, "Overlay routes by status: which prefixes have a usable path and which are waiting for an unresolved TLOC.", optional=True),
    Spec("sdwan_local", "show sdwan control local-properties", ("show sdwan control local-properties",), rsd.parse_control_local_properties, "Certificate state, site identity and the WAN interfaces (color, NAT type, control connections allowed).", optional=True),
    Spec("sdwan_app_route", "show sdwan app-route stats", ("show sdwan app-route stats",), rsd.parse_app_route_stats, "Measured loss, latency and jitter of every overlay tunnel, as application-aware routing sees it.", optional=True),
    Spec("sdwan_policy", "show sdwan policy from-vsmart", ("show sdwan policy from-vsmart",), rsd.parse_policy_from_vsmart, "The centralized policy the vSmart pushed: SLA classes, application-aware routing rules and their lists.", optional=True),
    Spec("sdwan_omp_summary", "show sdwan omp summary", ("show sdwan omp summary",), rse.parse_omp_summary, "OMP state, uptime, the number of vSmart peers and the routes / TLOCs / services this router received, installed and sent.", optional=True),
    Spec("sdwan_certificates", "show sdwan certificate installed", ("show sdwan certificate installed",), rse.parse_certificates, "Validity dates of the board-id (SUDI) and the enterprise device certificate: an expired certificate takes every control connection down.", optional=True),
    Spec("sdwan_tunnel_stats", "show sdwan tunnel statistics", ("show sdwan tunnel statistics",), rse.parse_tunnel_statistics, "Packets and octets sent and received per overlay tunnel, and the tunnel MTU: tunnels that transmit but never receive.", optional=True),
    Spec("sdwan_bfd_history", "show sdwan bfd history", ("show sdwan bfd history",), rse.parse_bfd_history, "Every up/down record of every BFD session: how often tunnels dropped, and whether several dropped at the same moment.", optional=True,
         empty_lines=(r"DST PUBLIC\s+DST PUBLIC.*", r"SYSTEM IP\s+SITE ID\s+COLOR.*DEL", r"-{10,}"), empty_note="headers only: no BFD session has changed state since the router started"),
    # --- health / platform (show tech-support carries all of these) -------
    Spec("cpu", "show process cpu sorted", ("show process cpu sorted", "show process cpu"), rh.parse_cpu_sorted, "Current CPU load and the busiest processes."),
    Spec("cpu_history", "show process cpu history", ("show process cpu history",), rh.parse_cpu_history, "CPU peaks over the last 60 seconds, 60 minutes and 72 hours."),
    Spec("platform_resources", "show platform resources", ("show platform resources",), rh.parse_platform_resources, "IOS-XE data-plane and control-plane CPU / memory / bootflash headroom."),
    Spec("control_processor", "show platform software status control-processor brief", ("show platform software status control-processor brief",), rh.parse_control_processor, "Per-core CPU and memory of the control processor."),
    Spec("process_memory", "show process memory sorted", ("show process memory sorted", "show process memory"), rh.parse_process_memory, "IOS memory pools and the largest memory holders."),
    Spec("memory_statistics", "show memory statistics", ("show memory statistics",), rh.parse_memory_statistics, "IOS memory pools (classic IOS)."),
    Spec("environment", "show environment all", ("show environment all", "show environment"), rh.parse_environment, "Fans, power supplies, temperature sensors and alarms."),
    Spec("platform_slots", "show platform", ("show platform",), rh.parse_platform, "Chassis, line cards, power supplies and their state."),
    Spec("redundancy_states", "show redundancy states", ("show redundancy states",), rh.parse_redundancy_states, "Redundancy mode and peer state."),
    Spec("redundancy_history", "show redundancy history", ("show redundancy history",), rh.parse_redundancy_history, "Switchover history."),
    Spec("stacks", "show stacks", ("show stacks",), rh.parse_stacks, "Process stack headroom and crash stacks."),
    Spec("file_systems", "show file systems", ("show file systems",), rh.parse_file_systems, "Flash / bootflash capacity and free space."),
    Spec("bootflash", "show bootflash:", ("show bootflash:", "show flash:", "dir bootflash:", "dir flash:"), rh.parse_flash_listing, "Installed images, packages, crash cores and tracelogs."),
    Spec("license_summary", "show license summary", ("show license summary",), rh.parse_license_summary, "Licence level and Smart Licensing status."),
    Spec("license_usage", "show license usage", ("show license usage",), rh.parse_license_usage, "Features and throughput licences in use."),
    Spec("license_all", "show license all", ("show license all",), rh.parse_license_all, "Smart Licensing transport, policy and reporting deadlines."),
    Spec("license_detail", "show license detail", ("show license detail",), rh.parse_license_detail, "Classic (right-to-use) licences with the store each one lives in, their state and the evaluation time left."),
    Spec("license_status", "show license status", ("show license status",), rh.parse_license_status, "Smart Licensing transport, policy and reporting deadlines (the same fields as 'show license all'); on classic licensing the device credential state."),
    Spec("cdp_neighbors", "show cdp neighbors", ("show cdp neighbors",), rh.parse_cdp_neighbors, "Directly connected Cisco devices.", empty_marker=r"Total cdp entries displayed\s*:\s*0", empty_note="no CDP neighbors"),
    Spec("cdp_detail", "show cdp neighbors detail", ("show cdp neighbors detail",), rh.parse_cdp_detail, "Neighbour management addresses and platforms.", empty_marker=r"Total cdp entries displayed\s*:\s*0", empty_note="no CDP neighbors"),
    Spec("users", "show users", ("show users",), rh.parse_show_user, "Who is logged in to the router right now."),
    Spec("ip_ssh", "show ip ssh", ("show ip ssh",), runtime.parse_ip_ssh, "Negotiated SSH version, authentication timeout/retries and the minimum Diffie-Hellman key size actually enforced."),
    Spec("etherchannel", "show etherchannel summary", ("show etherchannel summary",), rh.parse_etherchannel_summary, "Port-channel bundles and member state.", empty_marker=r"channel-groups in use:\s*0", empty_note="no port-channels are configured"),
    Spec("logging", "show logging", ("show logging", "show logging last <n>"), rl.parse_logging, "Logging settings and the digest of the buffered messages."),
    Spec("logging_count", "show logging count", ("show logging count",), rl.parse_logging_count, "Per-mnemonic lifetime occurrence counts — catches a message that scrolled out of the buffer 'show logging' reads.",
         empty_lines=(r"Facility\s+Message Name\s+Sev\s+Occur\s+Last Time", r"=+"), empty_note="no messages have been counted since the counters were last cleared"),
    Spec("qfp_utilization", "show platform hardware qfp active datapath utilization", ("show platform hardware qfp active datapath utilization summary", "show platform hardware qfp active datapath utilization"), rh.parse_qfp_utilization, "Forwarding-plane (QFP) packet rate and processing load; the control-plane CPU can be idle while this is saturated."),
    Spec("qfp_drops", "show platform hardware qfp active statistics drop", ("show platform hardware qfp active statistics drop",), rh.parse_qfp_drops, "Global forwarding-plane drop counters (no adjacency, NAT, IPsec, TTL, reassembly...)."),
    Spec("qfp_exmem", "show platform hardware qfp active infrastructure exmem statistics", ("show platform hardware qfp active infrastructure exmem statistics",), rh.parse_qfp_exmem, "Forwarding-plane DRAM / IRAM use."),
    Spec("arp_summary", "show arp summary", ("show arp summary", "show ip arp summary"), runtime.parse_arp_summary, "ARP entry counts the router keeps (incomplete, static, per interface) and the learn limit."),
    Spec("ipv6_route_summary", "show ipv6 route summary", ("show ipv6 route summary",), rr.parse_ipv6_route_summary, "IPv6 routes per source with memory, and the prefix-length spread."),
    Spec("nat_stats", "show ip nat statistics", ("show ip nat statistics",), natmod.parse_nat_statistics, "Live NAT translations, hits/misses, pool utilisation and limits."),
]

# Commands whose presence adds no analysis but which are recognised, so the
# Coverage tab does not call them "unknown".
PARTIAL_VIEWS = (
    ("show running-config | ...", "partial view of the running-config (filtered)"),
    ("show run | ...", "partial view of the running-config (filtered)"),
    ("show run interface <name>", "one interface of the running-config"),
    ("show running-config interface <name>", "one interface of the running-config"),
    ("show run int <name> ...", "one interface of the running-config"),
    ("terminal length <n>", "terminal setting"),
    ("terminal width <n>", "terminal setting"),
    ("terminal pager <n>", "terminal setting"),
    ("terminal monitor", "terminal setting"),
    ("enable", "mode change"),
    ("configure terminal", "mode change"),
    ("exit", "mode change"),
    ("end", "mode change"),
)


# Recognised commands whose information is already read from another block.
COVERED = (
    ("show crypto gdoi gm acl", "downloaded policy ACL — already read from 'show crypto gdoi'"),
    ("show crypto session", "brief form — the 'detail' form (or the longest run) was parsed instead"),
    ("show policy-map", "policy-map definitions — already parsed from the running-config"),
    ("show interfaces counters protocol status", "per-interface protocol state — already known from 'show ip interface brief'"),
    ("show ip interface brief", "second copy — the longest run was parsed"),
    ("show interface description", "second copy — the longest run was parsed"),
    ("show interfaces <name>", "single-interface view — the analyzer reads the full 'show interfaces' output"),
)


# Output that belongs to another tool or carries no router-analysis value.  The
# Coverage tab lists these as "ignored" with the reason instead of "not parsed".
IGNORED_BY_DESIGN = (
    ("show vlan ...", "Layer-2 VLAN database — switching information, not part of the router analysis"),
    ("show vlan-switch ...", "Layer-2 VLAN database — switching information, not part of the router analysis"),
    ("show mac address-table ...", "Layer-2 forwarding table — use the Switch Analyzer"),
    ("show interfaces status", "switch-port summary — use the Switch Analyzer"),
    ("show interfaces switchport", "switch-port detail — use the Switch Analyzer"),
    ("show interfaces trunk", "switch-port detail — use the Switch Analyzer"),
    ("show spanning-tree ...", "spanning tree — use the Switch Analyzer"),
    ("show cube status", "Cisco Unified Border Element (voice) — not analyzed"),
    ("show memory statistics history ...", "memory trend — the current state is analyzed from 'show process memory' and 'show platform resources'"),
    ("show processes memory platform sorted", "per-process platform memory — the router-level view comes from 'show platform resources'"),
    ("show process memory platform ...", "per-process platform memory — the router-level view comes from 'show platform resources'"),
    ("show ip ports all", "listening sockets — not analyzed"),
    ("show history ...", "CLI history — not analyzed"),
    ("write memory", "action command that saves the configuration — it prints no information to analyze"),
    ("write ...", "action command that saves the configuration — it prints no information to analyze"),
    ("copy running-config startup-config", "action command that saves the configuration — it prints no information to analyze"),
    ("show version | ...", "filtered view of 'show version' (for example the uptime line) — the unfiltered output is the one that is analyzed"),
    ("ssh ...", "session hop through a jump host — not part of the analysis"),
    ("telnet ...", "session hop through a jump host — not part of the analysis"),
)


_CLOCK = re.compile(r"(\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s+\S+\s+(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(\d{4})")


@dataclass
class Ctx:
    filename: str = ""
    capture: cap.Capture | None = None
    hostname: str = ""
    cfg: dict[str, Any] | None = None
    tree: config_tree.ConfigTree | None = None
    sdwan_cfg: dict[str, Any] | None = None
    xref: dict[str, Any] | None = None
    data: dict[str, Any] = field(default_factory=dict)       # spec.key -> parsed output (first/longest block)
    present: set[str] = field(default_factory=set)            # spec keys that had a usable block
    empty: dict[str, str] = field(default_factory=dict)       # spec key -> why the captured block is an empty answer (no entries), not a gap
    routes: list[dict[str, Any]] = field(default_factory=list)
    route_tables: list[dict[str, Any]] = field(default_factory=list)
    route_summaries: list[dict[str, Any]] = field(default_factory=list)  # 'show ip route [vrf X] summary': the router's own route counters
    arp: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    used_blocks: dict[int, str] = field(default_factory=dict)  # block.index -> parser label
    dialect: dict[str, Any] = field(default_factory=dict)
    interfaces: list[dict[str, Any]] = field(default_factory=list)  # joined config + runtime
    models: dict[str, Any] = field(default_factory=dict)             # nat / ipsec / ospf models joined from config and live output
    split: dict[int, str] = field(default_factory=dict)              # block.index -> "show tech-support, split into N sections"

    def license_store(self) -> list[dict[str, Any]]:
        """Classic licence rows from 'show license all' (preferred: it carries the store headings) or, when only that was captured, 'show license detail'."""
        for key in ("license_all", "license_detail"):
            rows = (self.data.get(key) or {}).get("store")
            if rows:
                return rows
        return []

    def capture_time(self) -> datetime | None:
        """Router wall-clock time of the capture ('show clock'), as a naive datetime in the router's own time zone; None when it was not captured."""
        match = _CLOCK.search(str(self.data.get("clock") or ""))
        if not match:
            return None
        try:
            return datetime.strptime(f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}", "%H:%M:%S %b %d %Y")
        except ValueError:
            return None

    def has(self, key: str) -> bool:
        return key in self.present

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def _looks_like_config(text: str) -> bool:
    head = text[:200000]
    if not re.search(r"^hostname\s+\S+", head, re.M):
        return False
    # a hostname alone is not enough: require at least one more top-level IOS stanza
    return bool(re.search(r"^(interface\s+\S+|router\s+(bgp|ospf|eigrp|rip|isis)\b|ip route\s|ip access-list\s|line vty\b|snmp-server\s|aaa new-model)", head, re.M))


def empty_answer(spec: Spec, block: cap.Block) -> str:
    """Why this block, which the parser read as nothing, is a genuine empty answer; '' when it is not."""
    if spec.empty_marker and re.search(spec.empty_marker, "\n".join(block.lines), re.I | re.M):
        return spec.empty_note
    if spec.empty_lines:
        body = [line.strip() for line in block.lines if line.strip()]
        if body and all(any(re.fullmatch(pattern, line, re.I) for pattern in spec.empty_lines) for line in body):
            return spec.empty_note
    return ""


def _run(ctx: Ctx, label: str, func: Callable[[], Any]) -> Any:
    try:
        return func()
    except Exception as exc:  # a parser bug degrades one tab only
        ctx.warnings.append(f"{label}: parser error ({type(exc).__name__}: {exc}) — that tab is incomplete.")
        return None


def gather(content: str, filename: str = "") -> Ctx:
    ctx = Ctx(filename=filename)
    text = content.replace("\r\n", "\n").replace("\r", "\n")
    capture = cap.split_capture(text, [cap.CISCO_PROMPT])
    if not capture.blocks or not capture.has_prompts:
        if techsupport.looks_like_dump(text):
            capture = techsupport.dump_capture(text)
        elif _looks_like_config(text):
            capture = cap.single_block_capture(text, "show running-config")
        else:
            raise ValueError("No Cisco IOS / IOS-XE prompts or running-config were found in this file. "
                             "Upload a terminal capture that contains 'show running-config' or other show output." + wrong_page_hint(text, "router"))
    # 'show tech-support' is dozens of show commands in one block: cut it along its banners
    # so each embedded command is read by the same parser that reads a typed one.
    ctx.split = _run(ctx, "show tech-support", lambda: techsupport.expand(capture)) or {}
    ctx.capture = capture
    ctx.hostname = capture.hostname()

    # --- configuration ------------------------------------------------
    cfg_block = capture.first(*CONFIG_TEMPLATES)
    if cfg_block is None and not capture.has_prompts:
        cfg_block = capture.blocks[0]
    if cfg_block is not None and cfg_block.line_count > 5:
        ctx.tree = config_tree.parse_config(cfg_block.lines)
        ctx.cfg = _run(ctx, "running-config", lambda: config_extract.extract_config(ctx.tree))
        ctx.used_blocks[cfg_block.index] = "Configuration parser"
        if ctx.cfg is not None:
            ctx.xref = _run(ctx, "cross-reference", lambda: xref.build_xref(ctx.cfg, ctx.tree))
            host = ctx.cfg["system"].get("hostname")
            if host:
                ctx.hostname = host
    sd_block = capture.first(*SDWAN_CONFIG_TEMPLATES)
    if sd_block is not None:
        ctx.sdwan_cfg = _run(ctx, "show sdwan running-config", lambda: rv.parse_sdwan_config(sd_block.lines))
        ctx.used_blocks[sd_block.index] = "SD-WAN configuration parser"

    # --- show commands ------------------------------------------------
    for spec in SPECS:
        block = capture.first(*spec.templates)
        if block is None:
            continue
        if block.line_count == 0:
            # capture.first() only matches one of this spec's full, correctly-spelled
            # command templates — never a half-typed fragment (those never match a
            # template and fall through to Coverage's own "no output" guess below). On
            # real IOS-XE, several such commands routinely print nothing at all, not even
            # a header, when their feature is absent: 'show ip eigrp neighbors' with no
            # EIGRP, 'show standby brief' with no HSRP, 'show crypto ikev2 sa', 'show
            # track', 'show policy-map interface' with no service-policy applied anywhere
            # (all confirmed on a real ASR1002-X capture). That is a genuine empty
            # answer, not a sign the engineer mistyped — record it exactly like the
            # headers-only empty case below so Coverage calls it a result, not a gap.
            note = spec.empty_note
            if note.startswith("headers only: "):
                # that wording assumes the header line printed; here nothing did.
                note = "no output: " + note[len("headers only: "):]
            ctx.empty[spec.key] = note
            ctx.used_blocks[block.index] = f"{spec.label} — {note}"
            continue
        failed_before = len(ctx.warnings)
        parsed = _run(ctx, spec.label, lambda b=block, s=spec: s.parser(b.lines))
        if parsed is None or parsed == {} or parsed == [] or parsed == "":
            note = "" if len(ctx.warnings) > failed_before else empty_answer(spec, block)
            if note:
                ctx.empty[spec.key] = note
                ctx.used_blocks[block.index] = f"{spec.label} — {note}"
            continue
        ctx.data[spec.key] = parsed
        ctx.present.add(spec.key)
        ctx.used_blocks[block.index] = spec.label

    # 'show license status' carries the Smart Licensing fields that 'show license all' does; use it when the longer command was not captured
    status = ctx.data.get("license_status")
    if status and "license_all" not in ctx.data and (status.get("using_policy") or status.get("smart_licensing")):
        ctx.data["license_all"] = status
        ctx.present.add("license_all")

    # routes: global table plus every per-VRF table that was captured
    for block in capture.find("show ip route", "show ip route vrf <vrf>"):
        match = cap.command_matches(block.norm, "show ip route vrf <vrf>")
        vrf = match["vrf"] if match else ""
        table = _run(ctx, f"show ip route {('vrf ' + vrf) if vrf else ''}".strip(), lambda b=block, v=vrf: rr.parse_ip_route(b.lines, v))
        if table is not None and table.get("routes") is not None:
            ctx.route_tables.append(table)
            ctx.used_blocks[block.index] = "Route table parser"
    # route counters kept by the router: global table plus every per-VRF table that was captured
    for block in capture.find("show ip route summary", "show ip route vrf <vrf> summary"):
        match = cap.command_matches(block.norm, "show ip route vrf <vrf> summary")
        parsed = _run(ctx, "show ip route summary", lambda b=block: rr.parse_route_summary(b.lines))
        if parsed:
            if match and not parsed.get("vrf") and match["vrf"] not in ("*",):
                parsed["vrf"] = match["vrf"]
            ctx.route_summaries.append(parsed)
            ctx.used_blocks[block.index] = "Route counters (show ip route summary)"
    if ctx.route_summaries:
        ctx.present.add("route_summary")
    if ctx.route_tables:
        ctx.present.add("routes")
        for table in ctx.route_tables:
            ctx.routes.extend(table["routes"])

    for block in capture.find("show arp", "show ip arp", "show ip arp vrf <vrf>"):
        match = cap.command_matches(block.norm, "show ip arp vrf <vrf>")
        vrf = match["vrf"] if match else ""
        rows = _run(ctx, "show arp", lambda b=block: runtime.parse_arp(b.lines))
        if rows is not None:
            for row in rows:
                row["vrf"] = vrf
            ctx.arp.extend(rows)
            ctx.present.add("arp")
            ctx.used_blocks[block.index] = "ARP parser"

    for index, label in ctx.split.items():
        ctx.used_blocks[index] = label

    ctx.dialect = detect_dialect(ctx)
    ctx.interfaces = join_interfaces(ctx)
    live = {key: ctx.get(key) for key in ("ospf_neighbors", "ospf_interfaces", "crypto_session", "ipsec_sa", "isakmp_sa")}
    undefined_acls = {ref["name"] for ref in (ctx.xref or {}).get("undefined", []) if ref["kind"] == "acl"}
    nat_model = _run(ctx, "NAT", lambda: natmod.build(ctx.cfg, ctx.get("nat_stats"), undefined_acls))
    if nat_model:
        ctx.models["nat"] = nat_model
    ipsec_model = _run(ctx, "IPsec", lambda: ipsecmod.build(ctx.cfg, live))
    if ipsec_model:
        ctx.models["ipsec"] = ipsec_model
    ospf_model = _run(ctx, "OSPF", lambda: ospfmod.build(ctx.cfg, live))
    if ospf_model:
        ctx.models["ospf"] = ospf_model
    ctx.coverage = coverage_rows(ctx)
    return ctx


# ---------------------------------------------------------------------------
# Platform / dialect
# ---------------------------------------------------------------------------

_MODEL_FROM_IMAGE = (
    (re.compile(r"asr1002[-_]?x", re.I), "ASR1002-X"),
    (re.compile(r"asr1001[-_]?x", re.I), "ASR1001-X"),
    (re.compile(r"asr1001[-_]?hx", re.I), "ASR1001-HX"),
    (re.compile(r"c3825", re.I), "3825"),
    (re.compile(r"c2951", re.I), "2951"),
    (re.compile(r"c3945", re.I), "3945"),
    (re.compile(r"isr4\d{3}", re.I), None),
    (re.compile(r"c8000be", re.I), "Catalyst 8000 (C8200/C8300)"),
    (re.compile(r"c8000v", re.I), "Catalyst 8000V"),
)


def image_release(image: str) -> str:
    """Human release string from a boot image file name, '' if unknown.

    c3825-adventerprisek9-mz.124-24.T4.bin           -> 12.4(24)T4
    asr1002x-universalk9.03.07.07.S.152-4.S7.SPA.bin -> IOS-XE 3.7.7S
    c8000be-universalk9.17.09.03a.SPA.bin            -> IOS-XE 17.9.3a
    """
    name = image.rsplit(":", 1)[-1].rsplit("/", 1)[-1]
    classic = re.search(r"-mz\.(\d{2,3})-(\d+)(?:\.([A-Za-z]+\d*))?", name, re.I)
    if classic:
        digits, build, train = classic.groups()
        return f"{digits[:-1]}.{digits[-1]}({build}){train or ''}"
    modern = re.search(r"universalk9[^.]*\.(\d{2})\.(\d{2})\.(\d{2})([a-z]?)\.SPA", name, re.I)
    if modern:
        a, b, c, letter = modern.groups()
        return f"IOS-XE {int(a)}.{int(b)}.{int(c)}{letter}"
    older = re.search(r"universalk9[^.]*\.(\d{2})\.(\d{2})\.(\d{2})\.([A-Z])\b", name)
    if older:
        a, b, c, train = older.groups()
        return f"IOS-XE {int(a)}.{int(b)}.{int(c)}{train}"
    return ""


_XE_MODEL = re.compile(r"^(ASR ?1|ISR ?4|ISR ?1[0-9]{3}|ISR ?9|C8\d{3}|C8[0-9]{3}|CAT ?8|CSR|C11\d{2}|IR ?1|ESR|NCS ?4200|8[0-9]{3}-)", re.IGNORECASE)
_CLASSIC_MODEL = re.compile(r"^(CISCO ?)?(18|19|28|29|38|39|72|73|75|76)\d{2}", re.IGNORECASE)


def detect_dialect(ctx: Ctx) -> dict[str, Any]:
    cfg = ctx.cfg or {}
    system = cfg.get("system", {})
    images = system.get("boot_images", []) or []
    version = ctx.data.get("version") or {}
    sdwan = bool(ctx.sdwan_cfg) or ctx.has("sdwan_status") or str(version.get("operating_mode", "")).lower().startswith("controller") or any(
        (iface.get("tunnel") or {}).get("mode") == "sdwan" for iface in cfg.get("interfaces", [])
    )
    xe = sdwan or any(i.get("service_instances") for i in cfg.get("interfaces", [])) or any(
        "universalk9" in image.lower() and ".spa." in image.lower() for image in images
    ) or version.get("os") == "IOS-XE" or any(i["name"].startswith(("BDI", "Sdwan")) for i in cfg.get("interfaces", []))

    model = ""
    serial = ""
    chassis = ""
    for row in ctx.get("inventory", []) or []:
        name = (row.get("name") or "").strip('" ')
        if name.lower() in ("chassis", "chassis 1") or name.lower().startswith("chassis"):
            model = row.get("pid", "") or model
            serial = row.get("serial", "") or serial
            chassis = row.get("description", "")
            break
    if not model and (ctx.get("inventory") or []):
        first = ctx.get("inventory")[0]
        model, serial, chassis = first.get("pid", ""), first.get("serial", ""), first.get("description", "")
    if not model:
        model = version.get("model", "") or system.get("license_pid", "")
        serial = serial or system.get("license_sn", "")
    if not model:
        for image in images:
            for pattern, label in _MODEL_FROM_IMAGE:
                if pattern.search(image) and label:
                    model = label
                    break
            if model:
                break
    if not model:
        model = (ctx.get("sdwan_status") or {}).get("Model name", "")
    classic_evidence = version.get("os") == "IOS" or any(re.search(r"-mz\.\d", image, re.I) for image in images) or bool(_CLASSIC_MODEL.match(model or ""))
    xe = xe or bool(_XE_MODEL.match(model or ""))
    if sdwan:
        family = "IOS-XE SD-WAN (cEdge)"
    elif xe:
        family = "IOS-XE"
    elif classic_evidence:
        family = "IOS (classic)"
    else:
        family = "Cisco IOS family"
    release = version.get("version") and f"{version.get('os', '')} {version['version']}".strip()
    sd_version = (ctx.get("sdwan_status") or {}).get("Version", "")
    if not release and sd_version:
        parts = sd_version.split(".")
        release = "IOS-XE " + ".".join(str(int(p)) if p.isdigit() else p for p in parts[:3]) if len(parts) >= 3 else "IOS-XE " + sd_version
    if not release:
        for image in images:
            guess = image_release(image)
            if guess:
                release = guess
                break
    config_version = system.get("version", "")
    return {
        "family": family,
        "sdwan": sdwan,
        "xe": xe,
        "model": model,
        "serial": serial,
        "chassis": chassis,
        "release": release or "",
        "config_version": config_version,
        "images": images,
    }


# ---------------------------------------------------------------------------
# Interface join
# ---------------------------------------------------------------------------


def join_interfaces(ctx: Ctx) -> list[dict[str, Any]]:
    """One record per interface, merging running-config, brief, description
    and `show interfaces` data under the canonical interface name."""
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    def slot(name: str) -> dict[str, Any]:
        key = canon(name)
        if key not in merged:
            merged[key] = {"name": key, "config": None, "brief": None, "desc": None, "stats": None, "summary": None}
            order.append(key)
        return merged[key]

    for iface in (ctx.cfg or {}).get("interfaces", []):
        slot(iface["name"])["config"] = iface
    for row in ctx.get("ipbrief", []) or []:
        slot(row["interface"])["brief"] = row
    for row in ctx.get("ifdesc", []) or []:
        slot(row["interface"])["desc"] = row
    for row in ctx.get("ifstats", []) or []:
        slot(row["interface"])["stats"] = row
    for name, row in (ctx.get("ifsummary", {}) or {}).items():
        slot(name)["summary"] = row
    return [merged[key] for key in order]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

_EXPECTED = (
    # (spec key or marker, label, why it matters)
    ("cfg", "show running-config", "Everything configuration-based: policy, security, routing configuration, VPN, QoS."),
    ("ipbrief", "show ip interface brief", "Live interface state."),
    ("ifstats", "show interfaces", "Errors, drops, utilisation, duplex/speed."),
    ("routes", "show ip route", "Routing table, static routes installed or not, route counts per protocol."),
    ("bgp_table", "show ip bgp", "BGP table, RIB-failures."),
    ("bgp_neighbors", "show ip bgp neighbors", "BGP session state and prefixes."),
    ("access_lists", "show access-lists", "ACL hit counters."),
    ("inventory", "show inventory", "Model, serial numbers, modules."),
    ("version", "show version", "Software release, uptime, reload reason."),
    ("arp", "show ip arp", "Layer-2 neighbours."),
    ("clock", "show clock", "Capture time."),
)


def coverage_rows(ctx: Ctx) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    capture = ctx.capture
    assert capture is not None
    for block in capture.blocks:
        label = ctx.used_blocks.get(block.index)
        if label:
            status, note = "analyzed", label
        elif block.error:
            status, note = "error", f"device rejected the command: {block.error}"
        elif block.command.rstrip().endswith("?"):
            status, note = "ignored", "help request"
        elif block.line_count == 0:
            status, note = "ignored", "no output (half-typed or terminal setting)"
        else:
            note = ""
            by_design = ""
            for template, why in IGNORED_BY_DESIGN:
                if cap.command_matches(block.norm, template) is not None:
                    by_design = why
                    break
            if not by_design and techsupport.is_internal(block.norm):
                by_design = "platform internals of show tech-support — not used by the Router Analyzer"
            if by_design:
                rows.append({"command": block.command, "status": "ignored", "lines": block.line_count, "note": by_design, "line": block.start})
                continue
            second = next((spec for spec in SPECS if spec.key in ctx.present and any(cap.command_matches(block.norm, t) is not None for t in spec.templates)), None)
            if second is not None:
                rows.append({"command": block.command, "status": "covered", "lines": block.line_count, "note": f"second copy of {second.label} — the longest run was parsed", "line": block.start})
                continue
            for template, why in PARTIAL_VIEWS:
                if cap.command_matches(block.norm, template) is not None:
                    note = why
                    break
            if not note and block.norm.startswith("show run") and ("|" in block.norm or " int" in block.norm):
                note = "partial view of the running-config"
            covered = ""
            for template, why in COVERED:
                if cap.command_matches(block.norm, template) is not None:
                    covered = why
                    break
            if note:
                status, note = "ignored", note + (" — covered by the full running-config" if ctx.cfg else "")
            elif covered:
                status, note = "covered", covered
            else:
                status, note = "not parsed", "recognised output but this analyzer has no parser for it yet"
        rows.append({"command": block.command, "status": status, "lines": block.line_count, "note": note, "line": block.start})
    return rows


def missing_commands(ctx: Ctx) -> list[dict[str, str]]:
    missing = []
    # BGP commands add nothing on a router whose running-config has no BGP process, or that answered "BGP not active"
    bgp_off = any(key in ctx.empty for key in ("bgp_table", "bgp_neighbors", "bgp_summary")) or (ctx.cfg is not None and not ctx.cfg.get("bgp"))
    for key, label, why in _EXPECTED:
        have = ctx.cfg is not None if key == "cfg" else (ctx.has(key) or key in ctx.empty)
        if not have and not (bgp_off and key in ("bgp_table", "bgp_neighbors")):
            missing.append({"command": label, "why": why})
    if ctx.dialect.get("sdwan"):
        for key, label, why in (
            ("sdwan_status", "show sdwan system status", "SD-WAN daemons and controller compatibility."),
            ("sdwan_control", "show sdwan control connections", "Control-plane health."),
            ("sdwan_bfd", "show sdwan bfd sessions", "Overlay tunnel health."),
            ("sdwan_history", "show sdwan control connection-history", "Why control connections dropped or fail to connect (DCONFAIL, DISTLOC, certificate errors)."),
        ):
            if not ctx.has(key):
                missing.append({"command": label, "why": why})
        if ctx.sdwan_cfg is None:
            missing.append({"command": "show sdwan running-config", "why": "The sdwan stanza (system-ip, tunnel colors, allow-service) is not part of show running-config."})
    return missing


def bgp_sessions(ctx: Ctx) -> list[dict[str, Any]]:
    """BGP session state from ``show ip bgp neighbors`` (preferred) or, when
    only the summary was captured, from ``show ip bgp summary``."""
    detail = ctx.get("bgp_neighbors")
    if detail:
        return [dict(item, source="show ip bgp neighbors") for item in detail]
    summary = ctx.get("bgp_summary")
    out = []
    if summary:
        for row in summary["neighbors"]:
            value = row["state_or_prefixes"]
            established = value.isdigit()
            out.append({
                "neighbor": row["neighbor"], "vrf": "", "remote_as": row["remote_as"], "link": "", "state": "Established" if established else (value or "?"),
                "uptime": row["up_down"], "admin_shutdown": value.lower().startswith("idle (admin)") or "admin" in value.lower(),
                "description": "", "last_reset": "", "prefixes_received": int(value) if established else None, "prefixes_sent": None,
                "source": "show ip bgp summary",
            })
    return out
