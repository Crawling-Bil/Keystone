"""Load Balancer Analyzer entry point (F5 BIG-IP / TMOS).

``analyze`` takes the text of a BIG-IP capture or export and returns a
``keystone.analysis/1`` result.  The input can be a prompted terminal capture
(``tmsh list ...`` plus ``show`` commands), the output of ``tmsh list`` /
``tmsh show running-config``, or ``bigip.conf`` / ``bigip_base.conf``.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Any

from ..analyzer_core.result import new_result
from . import bigip_enrich, bigip_extract, bigip_overview, bigip_rules, bigip_runtime, bigip_sections, bigip_sections_live, bigip_ucs
from .tmsh_tree import parse_tmsh

PLATFORMS: tuple[tuple[str, str], ...] = ()          # one vendor so far; the page hides the selector


_F5 = re.compile(r"^(#TMSH-VERSION:|ltm (?:virtual|pool|node|monitor|profile|rule|data-group|policy)\b|net (?:self|vlan|route|trunk)\b|sys (?:global-settings|httpd|sshd|snmp|ntp|provision)\b|cm (?:device|device-group|traffic-group)\b|auth (?:user|ldap|source)\b)", re.M)
_FORTI = re.compile(r"^(#config-version=FG|config (?:system global|firewall policy|system interface)\b)", re.M)
_CISCO_HUAWEI = re.compile(r"^(interface (?:GigabitEthernet|TenGigabitEthernet|FastEthernet|Ethernet|Vlan|XGigabitEthernet|Eth-Trunk)|router (?:bgp|ospf|eigrp)|sysname |vlan batch|spanning-tree mode)", re.M)
_PANOS = re.compile(r"^(set (?:deviceconfig|rulebase|network|zone|vsys)\b|<config\b[^>]*version=)", re.M)


def _wrong_page_hint(text: str) -> str:
    if _FORTI.search(text) or _PANOS.search(text):
        return " This looks like a firewall configuration - open the Firewall Analyzer."
    if _CISCO_HUAWEI.search(text):
        return " This looks like a Cisco or Huawei switch/router configuration - open the Router Analyzer or Switch Analyzer."
    return ""


def looks_like_bigip(text: str) -> bool:
    return bool(_F5.search(text[:3_000_000]))


def analyze(content: str, filename: str = "", platform: str = "auto", today: date | None = None) -> dict[str, Any]:
    today = today or date.today()
    runtime = bigip_runtime.gather(content)
    text = runtime["config_text"] or content
    if not looks_like_bigip(text):
        raise ValueError(
            "No F5 BIG-IP configuration was recognised. The Load Balancer Analyzer reads the stanza format of bigip.conf / bigip_base.conf, 'tmsh list' and 'tmsh show running-config' "
            "(for example 'ltm virtual /Common/name { ... }')." + _wrong_page_hint(content)
        )
    tree = parse_tmsh(text)
    if not tree.root:
        raise ValueError("No 'ltm', 'net', 'sys' or 'cm' blocks were found in the capture.")
    data = bigip_extract.extract(tree)
    bigip_enrich.enrich(tree, data, bigip_ucs.bundle_of(content), today)        # security modules, certificate details, UCS facts
    findings = bigip_rules.evaluate(tree, data, today, runtime)
    warnings: list[str] = list(tree.warnings)
    sections = bigip_sections.build_all(data, findings, warnings, today)
    sections += bigip_sections_live.live_sections(runtime)

    info = data["info"]
    hostname = info["hostname"] or runtime.get("hostname") or filename.rsplit(".", 1)[0]
    version = info["version"] or runtime.get("version", {}).get("version", "")
    platform_name = " · ".join(filter(None, ["BIG-IP", info["platform"] or info["platform_id"], f"TMOS {version}" if version else ""]))
    sync_groups = [g for g in data["device_groups"] if g["type"] == "sync-failover" and not g["system_group"]]
    result = new_result(
        "lb",
        hostname=hostname,
        vendor="F5",
        platform=platform_name,
        source_name=filename,
        title=hostname,
        subtitle=" · ".join(filter(None, [info["platform"], f"TMOS {version}" if version else "", f"{len(data['virtuals'])} virtual servers", f"HA {', '.join(g['short'] for g in sync_groups)}" if sync_groups else "standalone" if data["devices"] or data["device_groups"] else ""])),
    )
    result["sections"] = sections
    known = {s["id"] for s in sections} | {"findings", "overview", "coverage"}
    result["cards"] = [c if not c.get("section") or c["section"] in known else dict(c, section="") for c in bigip_overview.cards(data, findings, runtime, today)]
    result["info"] = bigip_overview.info(data, runtime, tree)
    result["findings"] = findings
    result["coverage"] = bigip_overview.coverage(data, tree, runtime)
    result["warnings"] = warnings + bigip_overview.notes(data, runtime)
    result["capture"] = {"commands": len(runtime["capture"].blocks) if "capture" in runtime else 0, "lines": tree.lines, "has_config": True}
    return result
