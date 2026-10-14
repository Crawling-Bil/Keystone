"""Flask blueprint for the Router Analyzer (``/router-analyzer``)."""

from __future__ import annotations

from ..analyzer_core.blueprint import AnalyzerSpec, create_analyzer_blueprint
from . import context as ctxmod
from .service import analyze

# Commands that are read from the configuration or that have no parser of
# their own are listed first; then everything the runtime parsers understand,
# in the order the parsers are registered.
_CONFIG_COMMANDS = (
    ("show running-config", "The whole configuration: interfaces, routing, BGP/OSPF/EIGRP, ACLs, route-maps, AAA, SNMP, VPN, QoS — and every security finding."),
    ("show sdwan running-config", "SD-WAN (cEdge) only: system-ip, site-id, tunnel colors and allow-service, which are not part of show running-config."),
    ("show ip route", "Routing table per protocol, default routes, static routes that are installed or missing."),
    ("show ip route vrf *", "Per-VRF routing tables."),
    ("show ip arp", "Layer-2 neighbours, used to confirm next hops."),
    ("show ip bgp", "BGP table with best paths, AS-path summary and RIB-failures."),
)


def _command_reference() -> list[dict[str, str]]:
    rows = [{"command": command, "purpose": purpose} for command, purpose in _CONFIG_COMMANDS]
    seen = {row["command"] for row in rows}
    for spec in ctxmod.SPECS:
        if spec.label in seen:
            continue
        seen.add(spec.label)
        rows.append({"command": spec.label, "purpose": spec.purpose})
    return rows


SPEC = AnalyzerSpec(
    key="router",
    name="Router Analyzer",
    url_prefix="/router-analyzer",
    template="analyzer_page.html",
    analyze=analyze,
    collect_prefix="collect-router",
    activity_module="Router Analyzer",
    page_context={
        "analyzer_key": "router",
        "analyzer_title": "Router Analyzer",
        "analyzer_subtitle": "Cisco IOS, IOS-XE and SD-WAN cEdge router captures — interfaces, routing, BGP/OSPF, IPsec, NAT, device health, hardening findings and an Excel export.",
        "api_prefix": "/router-analyzer",
        "file_hint": "Terminal log with show running-config and the show commands from the Collect tab (.txt, .log, .cfg)",
        "accept": ".txt,.log,.cfg,.conf,.config",
        "platforms": [("auto", "Auto detect"), ("ios", "Cisco IOS"), ("iosxe", "Cisco IOS-XE"), ("sdwan", "Cisco IOS-XE SD-WAN")],
        "empty_title": "Router Analyzer is ready",
        "empty_text": (
            "Upload one or more router terminal captures. The prompt is used to split the log into commands, so abbreviated "
            "and failed commands are handled, and whatever is missing is listed on the Coverage tab with what it would add."
        ),
        "capabilities": [
            {"title": "Interfaces and routing", "text": "Live and configured state, EVC/BDI, routing table by protocol, static routes, next hops, VRFs, CDP neighbours and port-channels."},
            {"title": "BGP and IGPs", "text": "Neighbour state, prefixes, policies, RIB-failures; OSPF adjacencies, timers and which interfaces each network statement enables; redistribution without subnets."},
            {"title": "IPsec, NAT and SD-WAN", "text": "Tunnel inventory (crypto maps, VTIs, IKEv2), weak ciphers, DH groups and PFS, pre-shared-key reuse; NAT pools, static port-forwards, exposure and live translation limits; SD-WAN control connections and BFD."},
            {"title": "Health and logs", "text": "CPU, memory and forwarding-plane load, power and temperature, flash, licensing and throughput caps; link, OSPF and BGP flaps, config changes, logins and IPsec events from the log. Reads show tech-support too."},
            {"title": "Hardening findings", "text": "AAA, SSH, SNMP, management ACLs, logging, NTP and unused or undefined policy objects — each with a Cisco documentation link."},
        ],
        "commands": _command_reference(),
        "collect_prefix": "collect-router",
        "no_collect_message": "No router collect list has been added yet. Drop a file named collect-router-<platform>.txt into static/collect-scripts and it appears here automatically. Until then, the table below lists the commands this analyzer reads.",
    },
)

bp = create_analyzer_blueprint(SPEC)
