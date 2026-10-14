"""Flask blueprint for the Firewall Analyzer (``/firewall-analyzer``)."""

from __future__ import annotations

from ..analyzer_core.blueprint import AnalyzerSpec, create_analyzer_blueprint
from . import forti_runtime, legacy
from .service import PLATFORMS, analyze

_ALL_VENDORS = legacy.available()

_COMMANDS = (
    ("show full-configuration", "FortiGate: every policy, object, VPN, route and system setting, including values that equal the default."),
    ("show", "FortiGate short export: only values that differ from the default (findings that depend on a default say so)."),
    ("show | grep -f ...  /  show system interface", "FortiGate: any sub-tree can be pasted; the parser reads whatever config / edit / set blocks it finds."),
    ("show configuration (PAN-OS: set format)  /  show config running", "Palo Alto: the 'set' format from 'set cli config-output-format set' + 'show', or the XML export."),
    ("set cli pager off  >  show system info  >  show config running", "Palo Alto, recommended: the CLI session saved from PuTTY/SecureCRT. The configuration (curly-brace view) plus model, serial, PAN-OS and content versions and the advanced-routing flag from 'show system info'."),
    ("/export compact  or  /export verbose", "MikroTik RouterOS: the full export (hide-sensitive is the default from RouterOS 7)."),
)


def _command_reference() -> list[dict[str, str]]:
    rows = [{"command": command, "purpose": purpose} for command, purpose in (_COMMANDS if _ALL_VENDORS else _COMMANDS[:3])]
    rows += [{"command": command, "purpose": purpose} for command, purpose in forti_runtime.COMMANDS]
    return rows


SPEC = AnalyzerSpec(
    key="firewall",
    name="Firewall Analyzer",
    url_prefix="/firewall-analyzer",
    template="analyzer_page.html",
    analyze=analyze,
    collect_prefix="collect-firewall",
    activity_module="Firewall Analyzer",
    page_context={
        "analyzer_key": "firewall",
        "analyzer_title": "Firewall Analyzer",
        "analyzer_subtitle": ("FortiGate, Palo Alto and MikroTik" if _ALL_VENDORS else "FortiGate") + " configurations - policies, NAT, VPN, routing, objects, hardening findings and an Excel export.",
        "api_prefix": "/firewall-analyzer",
        "file_hint": "FortiOS 'show full-configuration', PAN-OS set/XML export or RouterOS export (.txt, .conf, .cfg, .xml)" if _ALL_VENDORS else "FortiOS 'show full-configuration' or 'show' (.txt, .conf, .cfg, .log)",
        "accept": ".txt,.log,.cfg,.conf,.config,.xml,.rsc",
        "platforms": list(PLATFORMS),
        "empty_title": "Firewall Analyzer is ready",
        "empty_text": (
            "Upload one or more firewall configuration exports. FortiGate is read natively - including multi-VDOM files and any part of the tree - and every finding links to the vendor documentation."
            + (" Palo Alto and MikroTik are read through the shared Configuration Studio parsers." if _ALL_VENDORS else "")
        ),
        "capabilities": [
            {"title": "Policy analysis", "text": "Any-any rules, shadowed and redundant policies, internet-facing rules without inspection, risky services, unreferenced objects."},
            {"title": "NAT, VPN and routing", "text": "Virtual IPs, IP pools, IPsec phase 1/2 crypto, SSL VPN settings, BGP/OSPF neighbours, SD-WAN health checks."},
            {"title": "Management plane", "text": "Administrator trusted hosts, two-factor, management services on WAN interfaces, SNMP, logging, NTP, HA and firmware age."},
            {"title": "Secrets stay hidden", "text": "Passwords, pre-shared keys, SNMP communities, private keys and certificates are replaced at parse time - never displayed or exported."},
        ],
        "commands": _command_reference(),
        "collect_prefix": "collect-firewall",
        "no_collect_message": "No firewall collect list has been added yet. Drop a file named collect-firewall-<vendor>.txt into static/collect-scripts and it appears here automatically.",
    },
)

bp = create_analyzer_blueprint(SPEC)
