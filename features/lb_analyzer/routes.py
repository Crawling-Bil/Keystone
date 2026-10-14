"""Flask blueprint for the Load Balancer Analyzer (``/load-balancer-analyzer``)."""

from __future__ import annotations

from ..analyzer_core.blueprint import AnalyzerSpec, create_analyzer_blueprint
from . import bigip_runtime
from .service import PLATFORMS, analyze

_COMMANDS = (
    ("tmsh list", "F5 BIG-IP: the whole configuration in one command (LTM, net, sys, auth, cm). Values equal to the default are not printed."),
    ("tmsh list ltm virtual all-properties", "Every property of every virtual server, including defaults - needed to see inherited values."),
    ("tmsh list ltm profile client-ssl all-properties", "Effective TLS options and ciphers of client SSL profiles (also server-ssl)."),
    ("tmsh list sys file ssl-cert", "Certificate expiry dates and key sizes."),
    ("cat /config/bigip.conf  and  cat /config/bigip_base.conf", "The saved configuration files; paste both, or upload each as its own file."),
)


def _command_reference() -> list[dict[str, str]]:
    rows = [{"command": command, "purpose": purpose} for command, purpose in _COMMANDS]
    rows += [{"command": command, "purpose": purpose} for command, purpose in bigip_runtime.COMMANDS]
    return rows


SPEC = AnalyzerSpec(
    key="lb",
    name="Load Balancer Analyzer",
    url_prefix="/load-balancer-analyzer",
    template="analyzer_page.html",
    analyze=analyze,
    collect_prefix="collect-lb",
    activity_module="Load Balancer Analyzer",
    page_context={
        "analyzer_key": "lb",
        "analyzer_title": "Load Balancer Analyzer",
        "analyzer_subtitle": "F5 BIG-IP configurations - virtual servers, pools, monitors, SSL profiles, iRules, high availability, hardening findings and an Excel export.",
        "api_prefix": "/load-balancer-analyzer",
        "file_hint": "BIG-IP bigip.conf, bigip_base.conf, 'tmsh list' or a terminal capture (.conf, .txt, .log)",
        "accept": ".txt,.log,.cfg,.conf,.config",
        "platforms": list(PLATFORMS),
        "empty_title": "Load Balancer Analyzer is ready",
        "empty_text": (
            "Upload a BIG-IP configuration: bigip.conf, bigip_base.conf, the output of 'tmsh list', or a terminal capture that also contains 'show' commands. "
            "The analyzer maps each virtual server to its pool and members, checks monitors, SSL profiles, persistence, iRules, HA and the management plane, and links every finding to F5 documentation."
        ),
        "capabilities": [
            {"title": "Service map", "text": "Every virtual server with its default pool, members, health monitors and member state in one table."},
            {"title": "Health and delivery", "text": "Pools without monitors, web monitors without a receive string, priority-group traps, single-member and empty pools, unused and dangling objects."},
            {"title": "TLS and certificates", "text": "SSLv3 / TLS 1.0 / 1.1 and weak ciphers per SSL profile, default certificate, expiry and key size, unencrypted persistence cookie."},
            {"title": "Management plane and HA", "text": "GUI and SSH allow lists, self IP port lockdown, SNMP, NTP, syslog, password policy, LDAP, device groups, failover and config-sync."},
        ],
        "commands": _command_reference(),
        "collect_prefix": "collect-lb",
        "no_collect_message": "No load balancer collect list has been added yet. Drop a file named collect-lb-<platform>.txt into static/collect-scripts and it appears here automatically.",
    },
)

bp = create_analyzer_blueprint(SPEC)
