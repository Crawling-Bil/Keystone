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

from ..analyzer_core.result import card, new_result
from ..analyzer_core.vendor_hint import wrong_page_hint
from . import bigip_enrich, bigip_extract, bigip_map, bigip_overview, bigip_rules, bigip_runtime, bigip_sections, bigip_sections_live, bigip_ucs
from .tmsh_tree import parse_tmsh

PLATFORMS: tuple[tuple[str, str], ...] = ()          # one vendor so far; the page hides the selector


_F5 = re.compile(r"^(#TMSH-VERSION:|ltm (?:virtual|pool|node|monitor|profile|rule|data-group|policy)\b|net (?:self|vlan|route|trunk)\b|sys (?:global-settings|httpd|sshd|snmp|ntp|provision)\b|cm (?:device|device-group|traffic-group)\b|gtm (?:wideip|pool|server|datacenter|listener|topology)\b|auth (?:user|ldap|source)\b)", re.M)
def looks_like_bigip(text: str) -> bool:
    return bool(_F5.search(text[:3_000_000]))


def analyze(content: str, filename: str = "", platform: str = "auto", today: date | None = None) -> dict[str, Any]:
    today = today or date.today()
    live = getattr(content, "live", "")                                          # a UCS merged with the capture of the same unit (bigip_ucs.merge_same_unit)
    runtime = bigip_runtime.gather(live or content)
    text = (str(content) if live else runtime["config_text"]) or content        # the archive's configuration is complete, so it wins over the capture's own 'tmsh list'
    if not looks_like_bigip(text):
        raise ValueError(
            "No F5 BIG-IP configuration was recognised. The Load Balancer Analyzer reads the stanza format of bigip.conf / bigip_base.conf, 'tmsh list' and 'tmsh show running-config' "
            "(for example 'ltm virtual /Common/name { ... }')." + wrong_page_hint(content, "lb")
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
    dns_tabs = [x for x in sections if x["group"] == "DNS (GTM)"]
    if dns_tabs:                                                                # the DNS tab follows the LTM pools; on a DNS-only unit it is the first data tab
        rest = [x for x in sections if x["group"] != "DNS (GTM)"]
        anchor = max((i for i, x in enumerate(rest) if x["group"] == "Pools & nodes"), default=-1)
        sections = rest[:anchor + 1] + dns_tabs + rest[anchor + 1:]
    try:
        network_map = bigip_map.sections(data, runtime)
    except Exception as exc:                                                    # the map is an extra view; it must never cost the analysis
        warnings.append(f"The Visualization tab could not be built ({type(exc).__name__}: {exc}).")
        network_map = []
    if network_map:                                                            # the first tab after Overview
        sections[0:0] = network_map

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
    if network_map:
        mapped = [n for n in network_map[0]["nodes"] if n["type"] in ("virtual", "wideip")]
        down = sum(1 for n in mapped if n["status"] in ("offline", "unavailable"))
        parked = sum(1 for n in mapped if n["status"] in ("disabled", "forced down", "parent disabled"))
        live_note = "live availability" if network_map[0]["live"].get("any") else "from the configuration"
        result["cards"].append(card("Network map", len(mapped), "bad" if down else ("warn" if parked else "info"), f"{down} offline · {parked} disabled · {live_note}", bigip_map.SECTION_ID))
    result["info"] = bigip_overview.info(data, runtime, tree)
    if live:
        result["info"].append({"label": "Live state from", "value": f"{content.live_name} (merged with the UCS of the same unit)"})
    result["findings"] = findings
    result["coverage"] = bigip_overview.coverage(data, tree, runtime)
    result["warnings"] = warnings + bigip_overview.notes(data, runtime)
    result["capture"] = {"commands": len(runtime["capture"].blocks) if "capture" in runtime else 0, "lines": tree.lines, "has_config": True}
    return result
