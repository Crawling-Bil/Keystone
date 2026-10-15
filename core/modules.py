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
)

RISK_LABELS = {
    "offline": "Offline",
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
    Tool("configuration", "Configuration Studio", "convert", "offline", "1.8", "/configuration", "configuration",
         "Multi-vendor configuration conversion with automatic platform detection and mapping preview.",
         task="Convert a running configuration to another vendor", keywords=("migration", "converter")),
    Tool("lifecycle", "Lifecycle Manager", "operate", "write", "1.4", "/lifecycle/", "lifecycle",
         "Subnet discovery, firmware repository, pre-check and firmware upgrade jobs.",
         task="Stage firmware and upgrade devices", keywords=("upgrade", "firmware", "discovery")),
    Tool("config_push", "Config Push", "operate", "write", "1.4", "/lifecycle/config-push", "upload",
         "Push a prepared draft config to a discovered device over SSH, with backup before and after. No firmware, no reload.",
         task="Apply a prepared configuration to a device", keywords=("deploy", "ssh")),
    Tool("ztp", "ZTP Provisioning", "operate", "write", "1.4", "/ztp/", "console",
         "Zero-touch bootstrap for factory-default Huawei switches: DHCP, SFTP file server and per-device provisioning.",
         task="Onboard a factory-default switch without a console", keywords=("dhcp", "sftp", "esn")),
    Tool("config_backup", "Config Backup", "operate", "read", "1.4", "/lifecycle/config-backup", "folder",
         "Read-only snapshot of a configured device (hardware, config, VLANs, LLDP/STP, licensing) as a downloadable bundle.",
         task="Back up a device before a change", keywords=("snapshot", "capture")),
    Tool("live_logs", "Live Logs", "operate", "read", "1.4", "/lifecycle/live-logs", "pulse",
         "Upgrade, config push, backup and ZTP activity in real time, across the whole suite.",
         keywords=("jobs", "monitor")),
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
