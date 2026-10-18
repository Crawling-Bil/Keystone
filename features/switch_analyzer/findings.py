"""One findings list for a switch capture, in the shared finding model.

The Switch Analyzer produced findings in three places: the Health tab (``health.py``), the
Routing tab (``l3.py``) and the Logs tab (``logs.py``), each with its own shape, plus checks on
the capture itself (a table shorter than the device said, a serial number that disagrees between
two commands). The Findings tab shows all of them in one filterable list, like the Router Analyzer.

Each finding is ``{id, severity, category, title, object, detail, recommendation, reference}``
(``features.analyzer_core.findings``). Severity is high / medium / low / info. The rules stay
where they were written; this module only converts and adds the few checks that need nothing but
the finished result (err-disabled and inactive ports, an incomplete ARP or MAC table).
"""
from __future__ import annotations

import re
from typing import Any

from features.analyzer_core.findings import SEVERITY_RANK, finding

ERRDISABLE_DOC = "https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/69980-errdisable-recovery.html"
STP_OPTIONAL_DOC = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_optional_spanning_tree_features.html"
STP_DOC = "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-12/configuration_guide/lyr2/b_1712_lyr2_9300_cg/configuring_spanning_tree_protocol.html"

_CATEGORY = (
    ("SW-LACP", "Port-channel"), ("SW-TRK", "Port-channel"), ("SW-NX-VPC", "Port-channel"), ("SW-NX-LACP", "Port-channel"), ("SW-NX-MEM", "Device health"), ("SW-STP", "Spanning tree"), ("SW-STORM", "Spanning tree"),
    ("SW-AAA", "Management access"), ("SW-USER", "Management access"), ("SW-ENA", "Management access"), ("SW-HTTP", "Management access"),
    ("SW-SSH", "Management access"), ("SW-SNMP", "Management access"), ("SW-NTP", "Management access"), ("SW-LOG", "Management access"),
    ("SW-DHCP", "Layer-2 security"), ("SW-ENV", "Device health"), ("SW-LIC", "Device health"), ("SW-VER", "Device health"),
    ("SW-EVT", "Logs"), ("SW-IF", "Interfaces"), ("SW-CAP", "Capture"), ("SW-INV", "Inventory"),
)
_L3_SEVERITY = {"warning": "medium", "info": "info"}
_L3_TITLE = {
    "ospf_no_interfaces": "OSPF is configured but no interface runs it",
    "ospf_network_matches_nothing": "OSPF network statements match no interface",
    "ospf_all_passive": "Every OSPF interface is passive",
    "ip_routing_off": "ip routing is not enabled",
    "no_l3_found": "No Layer-3 configuration found",
}


def _category(code: str) -> str:
    for prefix, name in _CATEGORY:
        if code.startswith(prefix):
            return name
    return "Switch"


def _from_health(health: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in health.get("findings") or []:
        ref = (item.get("doc") or {}).get("url", "")
        out.append(finding(item["code"], item["severity"], _category(item["code"]), item["title"],
                           obj=item.get("where", ""), detail=item.get("text", ""), reference=ref))
    return out


def _from_l3(l3: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for item in l3.get("findings") or []:
        code = item.get("code", "l3")
        out.append(finding(f"SW-L3-{code.upper()}", _L3_SEVERITY.get(item.get("level", ""), "info"), "Routing", _L3_TITLE.get(code, code.replace("_", " ").capitalize()),
                           detail=item.get("text", "")))
    return out


def _port_state_findings(interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    err = [i for i in interfaces if "err-disabled" in str(i.get("status_detail", "")).lower()]
    if err:
        names = [i["name"] for i in err]
        out.append(finding(
            "SW-IF-001", "high", "Interfaces", f"{len(err)} port(s) are err-disabled",
            obj=", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else ""),
            detail="The switch shut these ports itself after detecting a fault (BPDU guard, port-security, loop, link-flap, UDLD or similar). They carry no traffic until recovered.",
            recommendation="Run `show interfaces status err-disabled` and the log to find the cause, fix it, then `shutdown` / `no shutdown` the port (or enable `errdisable recovery`).",
            reference=ERRDISABLE_DOC))
    inactive = [i for i in interfaces if "inactive" in str(i.get("status_detail", "")).lower()]
    if inactive:
        names = [i["name"] for i in inactive]
        out.append(finding(
            "SW-IF-002", "medium", "Interfaces", f"{len(inactive)} port(s) are inactive because their VLAN does not exist",
            obj=", ".join(names[:8]) + (f" and {len(names) - 8} more" if len(names) > 8 else ""),
            detail="An access port assigned to a VLAN that is not created on this switch stays inactive and passes no traffic.",
            recommendation="Create the VLAN, or move the port to a VLAN that exists."))
    return out


def _from_spanning_tree(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Ports ``show spanning-tree`` shows as broken (``BKN*`` with ``*TYPE_Inc`` / ``*ROOT_Inc`` / ``*LOOP_Inc`` / ``*PVID_Inc``)."""
    stp = result.get("spanning_tree") or {}
    broken = stp.get("broken") or []
    out = []
    if broken:
        names = sorted({f"{port['interface']} ({port['instance']})" for port in broken})
        reasons = sorted({port["inconsistent"] for port in broken if port["inconsistent"]})
        out.append(finding(
            "SW-STP-101", "medium", "Spanning tree", f"{len(broken)} spanning-tree port(s) are in a broken (inconsistent) state",
            obj=", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else ""),
            detail="The switch blocks these ports itself because a spanning-tree protection fired: " + ("; ".join(reasons) if reasons else "the state column shows BKN") + ". The port carries no traffic in that VLAN until the condition clears.",
            recommendation="Find the neighbour on the port (CDP / LLDP), correct the trunk / access or native-VLAN mismatch (or remove the device that sends superior BPDUs), then check `show spanning-tree inconsistentports`.",
            reference=STP_OPTIONAL_DOC))
    if stp.get("captured") and not stp.get("instances") and "No spanning tree instance" in str(stp.get("note", "")):
        out.append(finding(
            "SW-STP-102", "low", "Spanning tree", "No spanning-tree instance exists on this switch",
            detail="`show spanning-tree` reports that no instance exists, so the switch runs no spanning tree. Redundant Layer-2 links on such a switch form a loop.",
            recommendation="Confirm this is intended (single uplink, no redundant Layer-2 path); otherwise enable spanning tree (`spanning-tree mode rapid-pvst`).",
            reference=STP_DOC))
    return out


def _capture_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for name, label, code, noun in (("arp", "ARP", "SW-CAP-001", "entries"), ("mac", "MAC", "SW-CAP-002", "entries"), ("hsrp", "HSRP group", "SW-CAP-006", "groups")):
        check = (result.get("table_checks") or {}).get(name) or {}
        if check.get("captured") and check.get("reported") is not None and not check.get("complete", True):
            out.append(finding(
                code, "medium", "Capture", f"The {label} table in this capture is incomplete",
                detail=f"The device reported {check['reported']} {noun}, but only {check.get('parsed', 0)} could be read. The terminal buffer probably lost lines, so counts and searches on this tab are lower than the device's table.",
                recommendation="Capture again with `terminal length 0` (or `screen-length 0 temporary`) and a larger terminal scroll-back."))
    for text in (result.get("ospf_live") or {}).get("checks") or []:
        out.append(finding("SW-CAP-007", "low", "Capture", "OSPF commands disagree", detail=str(text)))
    for note in result.get("capture_notes") or []:
        out.append(finding("SW-CAP-003", "low", "Capture", "The capture mixes more than one device", detail=note.get("text", "")) if "different prompts" in note.get("text", "")
                   else finding("SW-CAP-004", "low", "Capture", "Some output was left out", detail=note.get("text", "")))
    warning = (result.get("detection") or {}).get("warning")
    if warning:
        out.append(finding("SW-CAP-005", "low", "Capture", "The vendor you picked disagrees with the capture", detail=str(warning)))
    for text in (result.get("serials") or {}).get("checks") or []:
        out.append(finding("SW-INV-001", "low", "Inventory", "Serial numbers disagree between commands", detail=str(text)))
    return out


def build_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    """All findings of a finished result, most severe first."""
    l3_items = _from_l3(result.get("l3") or {})
    present = (result.get("coverage") or {}).get("present")
    if present is not None and "config" not in present:
        # "No Layer-3 configuration found" is no news for a capture that has no configuration at all;
        # the Coverage tab already asks for show running-config.
        l3_items = [item for item in l3_items if item["id"] != "SW-L3-NO_L3_FOUND"]
    items = (_from_health(result.get("health") or {}) + l3_items
             + _port_state_findings(result.get("interfaces") or []) + _from_spanning_tree(result) + _capture_findings(result)
             + list((result.get("logs") or {}).get("findings") or [])
             + list((result.get("redundancy") or {}).get("findings") or []) + list((result.get("ntp") or {}).get("findings") or []) + list((result.get("stp_inconsistent") or {}).get("findings") or []) + list((result.get("fhrp") or {}).get("findings") or []) + list((result.get("ospf_live") or {}).get("findings") or []))
    seen: set[tuple[str, str, str]] = set()
    unique = []
    for item in items:
        key = (item["id"], item["object"], item["title"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    unique.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 9), f["category"], f["id"], f["object"]))
    return unique


def counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    out = {name: 0 for name in SEVERITY_RANK}
    for item in findings:
        out[item["severity"]] = out.get(item["severity"], 0) + 1
    return out
