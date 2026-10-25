"""Single registry of the tools Keystone exposes.

The dashboard, the sidebar, the quick guide and ``/api/health`` all read
from here, so adding a module means adding one entry instead of editing
four places.

Each tool belongs to one work group (what the engineer is doing) and one
risk class (what the tool can do to a device). The risk classes are the
ones defined in docs/PRD.md:

* ``offline``   R0: works on uploaded files only, never opens a session
* ``read``      R1: opens SSH sessions but only runs read-only commands
* ``write``     R2: changes device state (firmware, config, DHCP on a segment)
"""

from __future__ import annotations

from dataclasses import dataclass, field

GROUPS = (
    ("analyze", "Analyze", "Read a capture or backup and report what needs attention."),
    ("convert", "Convert", "Prepare configuration for a new platform."),
    ("operate", "Operate", "Run jobs against live devices."),
    ("document", "Document", "Turn the inventory and configs into project documents."),
)

RISK_LABELS = {
    "offline": "Local",
    "read": "Read-only",
    "write": "Writes to devices",
}


@dataclass(frozen=True)
class Tool:
    key: str            # active_page value and /api/health key
    name: str
    group: str
    risk: str
    version: str
    href: str
    icon: str
    description: str
    task: str = ""      # "Not sure which tool?" prompt; empty = not listed
    status: str = ""    # "planned" = the page opens but no converter exists yet
    keywords: tuple[str, ...] = field(default_factory=tuple)

    @property
    def risk_label(self) -> str:
        return RISK_LABELS[self.risk]

    @property
    def search_text(self) -> str:
        return " ".join((self.name, self.description, self.task, *self.keywords)).lower()


TOOLS: tuple[Tool, ...] = (
    Tool("wireless", "Wireless Analyzer", "analyze", "offline", "1.11.0", "/wireless", "wireless",
         "Huawei and Cisco 9800 WLC assessment, AP master validation, AP role diff and Source-to-Target config delta.",
         task="Check AP or WLC inventory, or compare two controllers", keywords=("wlc", "ap", "vap", "ssid")),
    Tool("switch_analyzer", "Switch Analyzer", "analyze", "offline", "1.2", "/switch-analyzer", "switch",
         "Cisco, Huawei, Aruba and NX-OS switch dashboards: inventory, VLANs, spanning tree, port-channels, PoE, LLDP/CDP, compare and sizing.",
         task="Review a switch capture (VLANs, STP, port-channels, PoE)", keywords=("catalyst", "nexus", "vrp", "aos-cx")),
    Tool("router_analyzer", "Router Analyzer", "analyze", "offline", "1.0", "/router-analyzer", "router",
         "Cisco IOS, IOS-XE and SD-WAN captures: interfaces, routing, BGP/OSPF, VPN and hardening findings with Cisco references.",
         task="Review a router capture (routing, BGP/OSPF, VPN, SD-WAN)", keywords=("bgp", "ospf", "sdwan", "ipsec")),
    Tool("firewall_analyzer", "Firewall Analyzer", "analyze", "offline", "1.0", "/firewall-analyzer", "firewall",
         "FortiGate (native), Palo Alto and MikroTik: policies, NAT, VPN, routing, objects and hardening findings with vendor references.",
         task="Review firewall policies, NAT and VPN", keywords=("fortigate", "palo alto", "mikrotik", "policy")),
    Tool("lb_analyzer", "Load Balancer Analyzer", "analyze", "offline", "1.0", "/load-balancer-analyzer", "balancer",
         "F5 BIG-IP: virtual server to pool map, monitors, SSL profiles and certificates, persistence, iRules, HA and hardening findings.",
         task="Review a load balancer (F5 virtual servers, pools, SSL, HA)", keywords=("f5", "big-ip", "ucs", "ltm", "gtm")),
    Tool("topology", "Topology Builder", "analyze", "offline", "0.5", "/topology", "topology",
         "Draw the network from CDP/LLDP in device captures: physical, vPC and logical IP views, link speeds, draw.io, report pack, run merge and gaps in the discovery.",
         task="Draw a network diagram from switch and router captures", keywords=("diagram", "drawio", "draw.io", "cdp", "lldp", "map", "visio", "links")),
    # Convert: one page per kind of device, the same five as Analyze. "planned"
    # must match the converter registries (tests/test_convert_domains.py checks it).
    Tool("convert_wireless", "Wireless", "convert", "offline", "", "/convert/wireless", "wireless",
         "Wireless controller configuration (Cisco 9800 / AireOS, Huawei AC, Aruba). No converter yet; Wireless Analyzer reads these files.",
         keywords=("wlc", "ssid", "ap group", "migration"), status="planned"),
    Tool("convert_switch", "Switch", "convert", "offline", "1.8", "/convert/switch", "switch",
         "Cisco, Huawei and Aruba switch configuration to Cisco, Huawei or Aruba, with target models and the TAM standard profile.",
         task="Convert a switch configuration to another vendor", keywords=("migration", "converter", "vrp", "ios", "aos")),
    Tool("convert_router", "Router", "convert", "offline", "", "/convert/router", "router",
         "Router configuration: WAN interfaces, routing protocols, NAT, IPsec and SD-WAN. No converter yet; Router Analyzer reads these files.",
         keywords=("bgp", "ospf", "nat", "ipsec", "migration"), status="planned"),
    Tool("convert_firewall", "Firewall", "convert", "offline", "1.9", "/convert/firewall", "firewall",
         "MikroTik to Palo Alto (Panorama-ready), one click or as a guided conversion checked step by step. FortiGate and Palo Alto files are analyzed, not converted.",
         task="Move a MikroTik firewall to Palo Alto", keywords=("mikrotik", "palo alto", "panorama", "migration", "wizard")),
    Tool("convert_load_balancer", "Load Balancer", "convert", "offline", "", "/convert/load-balancer", "balancer",
         "Load balancer virtual servers, pools, monitors and profiles. No converter yet; Load Balancer Analyzer reads F5 BIG-IP files.",
         keywords=("f5", "big-ip", "ucs", "migration"), status="planned"),
    Tool("lifecycle", "Device Operations", "operate", "write", "1.5", "/lifecycle/", "lifecycle",
         "Discover devices, back them up, push config or upgrade firmware, and watch every job live.",
         task="Back up, push config to or upgrade a device",
         keywords=("upgrade", "firmware", "discovery", "config push", "backup", "snapshot", "live logs", "ssh")),
    Tool("ztp", "ZTP Provisioning", "operate", "write", "1.4", "/ztp/", "console",
         "Zero-touch bootstrap for factory-default Huawei switches: DHCP, SFTP file server and per-device provisioning.",
         task="Onboard a factory-default switch without a console", keywords=("dhcp", "sftp", "esn")),
    Tool("lld_index", "LLD Index", "document", "offline", "0.1", "/lld-index", "folder",
         "Build the LLD Content Index for the LLD Generator: chapters per technology, expanded per site, device and model, tables filled from the inventory and configs, narrative from the project goals.",
         task="Prepare the LLD index", keywords=("lld", "document", "index", "low level design", "docgen", "word")),
    Tool("lld_generator", "LLD Generator", "document", "offline", "1.0", "/lld-generator", "folder",
         "Turn an LLD index into the Word LLD: master template with project placeholders, chapter tree, tables and images, Document Acceptance.",
         task="Write the LLD Word document", keywords=("lld", "word", "docx", "document generator", "master template", "generate")),
)


def grouped_tools() -> list[dict]:
    """Tools in display order, one entry per work group."""
    return [
        {"key": key, "name": name, "description": description, "tools": [t for t in TOOLS if t.group == key]}
        for key, name, description in GROUPS
    ]


def task_guide() -> list[Tool]:
    return [tool for tool in TOOLS if tool.task]


def health_modules() -> dict[str, str]:
    return {tool.key: "ready" for tool in TOOLS}
