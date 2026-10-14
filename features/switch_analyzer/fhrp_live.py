"""Live HSRP state read from the ``show hsrp`` family (Cisco NX-OS) and ``show standby brief`` (IOS / IOS XE).

``fhrp.py`` reads the *configuration* of a first-hop-redundancy group.  This module reads what the device says about the groups right now:

* ``show hsrp`` / ``show hsrp all`` (NX-OS): one block per group -- local state, priority and configured priority, preempt, hello / hold timers,
  virtual IP, the active and standby router, the authentication *type*, the virtual MAC, state changes, name.  ``show hsrp all`` also lists a
  group that is **Disabled** (a group configured without a virtual IP); ``show hsrp`` and ``show hsrp brief`` leave it out.
* ``show hsrp brief`` (NX-OS) and ``show standby brief`` (IOS / IOS XE): one row per group -- ``Interface Grp Prio P State Active Standby Group addr``.
* ``show hsrp summary`` (NX-OS): totals and packet counters.

Everything is read from the layout of a real Nexus 9000 capture (a vPC pair running 36 / 37 HSRP groups).  The IOS ``show standby brief`` row is the layout in
Cisco's IOS First Hop Redundancy Protocols Command Reference; no capture of ours has a populated one yet.

What is *not* kept: the authentication string.  NX-OS prints ``Authentication text "cisco"`` when no authentication is configured (the guideline in the NX-OS
HSRP chapter says so), so the string is compared with that default and then dropped; only ``none (default string)``, ``text`` or ``md5`` is stored.

Sources (pages opened while writing this module):

* Cisco, Cisco Nexus 9000 Series NX-OS Unicast Routing Configuration Guide 10.4(x), Configuring HSRP (defaults: priority 100, preemption off, authentication text "cisco"):
  https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide/m_configuring_hsrp.html
* Cisco, Cisco Nexus 9000 Series NX-API CLI Reference, HSRP Commands (``show hsrp``, ``show hsrp all``, ``show hsrp brief``, ``show hsrp summary``, the brief columns):
  https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/hsrp-commands
* Cisco, Cisco IOS First Hop Redundancy Protocols Command Reference, ``show standby`` (the brief columns):
  https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/command/fhp-s1.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text
from .live_state import interface_key

DOCS = {
    "hsrp": ("Cisco - Nexus 9000 NX-OS Unicast Routing Configuration Guide 10.4(x), Configuring HSRP",
             "https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/104x/unicast-routing-configuration/cisco-nexus-9000-series-nx-os-unicast-routing-configuration-guide/m_configuring_hsrp.html"),
    "show": ("Cisco - Nexus 9000 NX-API CLI Reference, HSRP Commands", "https://developer.cisco.com/docs/cisco-nexus-9000-series-nx-api-cli-reference/latest/hsrp-commands"),
    "ios": ("Cisco - IOS First Hop Redundancy Protocols Command Reference (show standby)", "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipapp_fhrp/command/fhp-s1.html"),
}

_IP = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"
_PEER = rf"(?:local|unknown|{_IP})"

PATTERN_DETAIL = (r"sh(?:ow)? hsrp(?: all| detail| active| standby| ipv4| ipv6| group \d+| interface \S+(?: \d+(?:/\d+)*)?(?: all)?)?",)
PATTERN_BRIEF = (r"sh(?:ow)? hsrp brief", r"sh(?:ow)? standby brief")
PATTERN_SUMMARY = (r"sh(?:ow)? hsrp summary",)

_HEAD = re.compile(r"^(\S+) - Group (\d+) \(HSRP-V(\d)\) \((IPv[46])\)\s*$")
_LOCAL = re.compile(r"^\s*Local state is (?P<state>[^,(]+?)\s*(?:\((?P<why>[^)]*)\))?\s*,\s*priority (?P<prio>\d+)(?: \(Cfged (?P<cfg>\d+)\))?(?P<rest>.*)$")
_TIMERS = re.compile(r"^\s*Hellotime (\d+) (m?sec), holdtime (\d+) (m?sec)")
_VIP = re.compile(rf"^\s*Virtual IP address is (\S+)(?:\s+\((\w+)\))?\s*$")
_ROUTER = re.compile(rf"^\s*(Active|Standby) router is ({_PEER})\s*(?:,\s*priority (\d+))?")
_AUTH = re.compile(r'^\s*Authentication (\w+)\b(.*)$')
_VMAC = re.compile(r"^\s*Virtual mac address is (\S+)(?:\s+\(([^)]*)\))?")
_CHANGES = re.compile(r"^\s*(\d+) state changes, last state change (\S+)")
_NAME = re.compile(r"^\s*IP redundancy name is (\S+)(?:\s+\((\w+)\))?")
_THRESHOLD = re.compile(r"^\s*Forwarding threshold\(for vPC\), lower: (\d+) upper: (\d+)")

_BRIEF_HEAD = re.compile(r"^\s*Interface\s+Grp\s+Pri(?:o)?\s+P\s+State\s+Active", re.IGNORECASE)
_BRIEF_ROW = re.compile(
    rf"^\s*(?P<if>[*#]*[A-Za-z][\w./-]*)\s+(?P<grp>[*#]*\d+)\s+(?P<prio>\d+)\s+(?:(?P<p>P)\s+)?(?P<state>[A-Za-z][\w()-]*)\s+"
    rf"(?P<active>{_PEER})\s+(?P<standby>{_PEER})\s+(?P<vip>{_IP})\s*(?:\((?P<src>conf|learn)\w*\))?\s*$")


def _blank(interface: str, group: str, family: str = "ipv4", version: str = "") -> dict[str, Any]:
    return {"interface": interface, "key": interface_key(interface), "group": group, "family": family, "version": version, "state": "", "state_detail": "",
            "priority": "", "cfg_priority": "", "preempt": "", "hello": "", "hold": "", "virtual_ip": "", "virtual_ip_source": "",
            "active": "", "active_priority": "", "standby": "", "standby_priority": "", "auth": "", "auth_default": False,
            "vmac": "", "vmac_kind": "", "changes": "", "last_change": "", "name": "", "name_source": "", "threshold": "", "sources": []}


def _state(text: str, why: str = "") -> tuple[str, str]:
    """``Initial(Interface Down)`` -> ("Initial", "interface down"); ``Disabled(Virtual IP not cfged)`` -> ("Disabled", "virtual IP not configured")."""
    word = text.strip().title() if text.strip().islower() else text.strip()
    detail = re.sub(r"(?i)\bnot cfged\b", "not configured", re.sub(r"\s+", " ", why.strip()))
    detail = " ".join(part if part.isupper() and len(part) > 1 else part.lower() for part in detail.split())
    return word, detail


def parse_detail(lines: list[str]) -> list[dict[str, Any]]:
    """``show hsrp`` / ``show hsrp all``: one dict per ``<interface> - Group <n> (HSRP-Vx) (IPvy)`` block."""
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in lines:
        found = _HEAD.match(raw.strip())
        if found:
            current = _blank(found.group(1), found.group(2), found.group(4).lower(), found.group(3))
            groups.append(current)
            continue
        if current is None:
            continue
        found = _LOCAL.match(raw)
        if found:
            current["state"], current["state_detail"] = _state(found.group("state"), found.group("why") or "")
            current["priority"] = found.group("prio")
            current["cfg_priority"] = found.group("cfg") or ""
            current["preempt"] = "on" if "may preempt" in (found.group("rest") or "") else "off"
            continue
        found = _TIMERS.match(raw)
        if found:
            current["hello"] = f"{found.group(1)} {'ms' if found.group(2) == 'msec' else 's'}"
            current["hold"] = f"{found.group(3)} {'ms' if found.group(4) == 'msec' else 's'}"
            continue
        found = _THRESHOLD.match(raw)
        if found:
            current["threshold"] = f"{found.group(1)} / {found.group(2)}"
            continue
        found = _VIP.match(raw)
        if found:
            current["virtual_ip"] = "" if found.group(1).lower() == "unknown" else found.group(1)
            current["virtual_ip_source"] = (found.group(2) or "").lower()
            continue
        found = _ROUTER.match(raw)
        if found:
            side = found.group(1).lower()
            current[side] = found.group(2)
            current[f"{side}_priority"] = found.group(3) or ""
            continue
        found = _AUTH.match(raw)
        if found:
            kind = found.group(1).lower()
            rest = found.group(2).strip()
            if kind == "text":
                # the string is compared with the NX-OS default and dropped: it may be a secret
                current["auth_default"] = rest.strip('"').lower() == "cisco"
                current["auth"] = "none (default string)" if current["auth_default"] else "text"
            elif kind == "md5":
                current["auth"] = "md5 (key chain)" if "key-chain" in rest.lower() else "md5"
            else:
                current["auth"] = kind
            continue
        found = _VMAC.match(raw)
        if found:
            current["vmac"] = found.group(1)
            current["vmac_kind"] = (found.group(2) or "").lower()
            continue
        found = _CHANGES.match(raw)
        if found:
            current["changes"] = found.group(1)
            current["last_change"] = found.group(2)
            continue
        found = _NAME.match(raw)
        if found:
            current["name"] = found.group(1)
            current["name_source"] = (found.group(2) or "").lower()
    for item in groups:
        item["sources"] = ["detail"]
    return groups


def parse_brief(lines: list[str]) -> list[dict[str, Any]]:
    """``show hsrp brief`` (NX-OS) and ``show standby brief`` (IOS): the rows below the ``Interface Grp Prio P State Active ...`` header."""
    rows: list[dict[str, Any]] = []
    seen_header = False
    for raw in lines:
        if _BRIEF_HEAD.match(raw):
            seen_header = True
            continue
        if not seen_header:
            continue
        found = _BRIEF_ROW.match(raw)
        if not found:
            continue
        interface = found.group("if").lstrip("*#")
        v6 = "*" in found.group("if") or "*" in found.group("grp") or ":" in found.group("vip")
        item = _blank(interface, found.group("grp").strip("*#"), "ipv6" if v6 else "ipv4")
        item["state"], item["state_detail"] = _state(found.group("state"))
        item["priority"] = found.group("prio")
        item["preempt"] = "on" if found.group("p") else "off"
        item["active"], item["standby"] = found.group("active"), found.group("standby")
        item["virtual_ip"] = found.group("vip")
        item["virtual_ip_source"] = {"conf": "cfged", "learn": "learnt"}.get(found.group("src") or "", "")
        item["sources"] = ["brief"]
        rows.append(item)
    return rows


_SUMMARY_FIELDS = (
    ("total_groups", re.compile(r"^\s*Total Groups:\s*(\d+)")),
    ("interfaces", re.compile(r"^\s*Total HSRP Enabled interfaces:\s*(\d+)")),
    ("tx_pass", re.compile(r"^\s*Tx - Pass:\s*(\d+)\s+Fail:\s*(\d+)")),
    ("rx_good", re.compile(r"^\s*Rx - Good:\s*(\d+)")),
    ("unknown_groups", re.compile(r"^\s*Packet for unknown groups:\s*(\d+)")),
    ("mts_rx", re.compile(r"^\s*Total MTS: Rx:\s*(\d+)")),
    ("extended_hold", re.compile(r"^\s*Extended-hold \(NSF\)\s+(\w+)")),
    ("bfd", re.compile(r"^\s*Global HSRP-BFD\s+(\w+)")),
    ("version", re.compile(r"^\s*Version::\s*V1-IPV4:\s*(\d+)\s+V2-IPV4:\s*(\d+)\s+V2-IPV6:\s*(\d+)")),
    ("states", re.compile(r"^\s*State::\s*Active:\s*(\d+)\s+Standby:\s*(\d+)\s+Listen:\s*(\d+)\s*$")),
    ("states_v6", re.compile(r"^\s*State::\s*V6-Active:\s*(\d+)\s+V6-Standby:\s*(\d+)\s+V6-Listen:\s*(\d+)")),
)


def parse_summary(lines: list[str]) -> dict[str, Any]:
    """``show hsrp summary`` -> ``{total_groups, interfaces, version: (v1, v2v4, v2v6), states: (active, standby, listen), tx_pass, tx_fail, rx_good, unknown_groups, ...}``."""
    out: dict[str, Any] = {}
    for raw in lines:
        for key, pattern in _SUMMARY_FIELDS:
            found = pattern.match(raw)
            if not found:
                continue
            if key == "tx_pass":
                out["tx_pass"], out["tx_fail"] = int(found.group(1)), int(found.group(2))
            elif key in {"version", "states", "states_v6"}:
                out[key] = tuple(int(group) for group in found.groups())
            elif key in {"extended_hold", "bfd"}:
                out[key] = found.group(1).lower()
            else:
                out[key] = int(found.group(1))
            break
    return out


def _more_complete(previous: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """The later block wins field by field; a field the later block leaves empty keeps the earlier value."""
    merged = dict(previous)
    for key, value in new.items():
        if key == "sources":
            merged["sources"] = sorted(set(previous.get("sources", [])) | set(value))
        elif value not in ("", None, False) or key not in merged:
            merged[key] = value
    return merged


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"groups": [...], "summary": {...}, "commands": [...]}`` from every ``show hsrp`` / ``show standby brief`` block of the capture.

    ``host`` limits the blocks to the ones typed at that prompt (a file that holds two devices); ``None`` reads them all."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    summary: dict[str, Any] = {}
    commands: list[str] = []

    def keep(index: int) -> bool:
        return host is None or capture_text.prompt_host(clean[index]) in (None, host)

    for index, block in capture_text.find_blocks(clean, PATTERN_DETAIL):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        rows = parse_detail(block)
        if rows:
            commands.append("detail")
        for row in rows:
            key = (row["key"], row["group"], row["family"])
            groups[key] = _more_complete(groups[key], row) if key in groups else row
    for index, block in capture_text.find_blocks(clean, PATTERN_BRIEF):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        rows = parse_brief(block)
        if rows:
            commands.append("brief")
        for row in rows:
            key = (row["key"], row["group"], row["family"])
            if key in groups:
                # the detail block is complete for its group; the brief row only fills what the detail did not print
                old = groups[key]
                for field in ("state", "priority", "preempt", "active", "standby", "virtual_ip", "virtual_ip_source"):
                    if not old.get(field) and row.get(field):
                        old[field] = row[field]
                old["sources"] = sorted(set(old.get("sources", [])) | {"brief"})
            else:
                groups[key] = row
    for index, block in capture_text.find_blocks(clean, PATTERN_SUMMARY):
        if not keep(index) or not block or re.match(r"^\s*(?:%|\^\s*$)", block[0]):
            continue
        parsed = parse_summary(block)
        if len(parsed) > len(summary):
            summary = parsed
    ordered = sorted(groups.values(), key=lambda item: _natural(item["interface"], item["group"]))
    return {"groups": ordered, "summary": summary, "commands": sorted(set(commands))}


def _natural(interface: str, group: str) -> tuple:
    parts = re.split(r"(\d+)", interface_key(interface))
    return tuple(int(part) if part.isdigit() else part for part in parts) + (int(group) if str(group).isdigit() else 0,)


def summary_rows(summary: dict[str, Any], listed: int) -> list[dict[str, str]]:
    """The ``show hsrp summary`` numbers as label / value rows, with the check against the groups the other commands listed."""
    def pair(values: tuple[int, ...], labels: tuple[str, ...]) -> str:
        return ", ".join(f"{label} {value}" for label, value in zip(labels, values))
    rows: list[dict[str, str]] = []
    if "total_groups" in summary:
        note = "" if summary["total_groups"] == listed else f" (the group blocks list {listed})"
        rows.append({"metric": "Groups", "value": f"{summary['total_groups']}{note}"})
    if "interfaces" in summary:
        rows.append({"metric": "Interfaces running HSRP", "value": str(summary["interfaces"])})
    if "version" in summary:
        rows.append({"metric": "HSRP version (groups)", "value": pair(summary["version"], ("v1 IPv4", "v2 IPv4", "v2 IPv6"))})
    if "states" in summary:
        rows.append({"metric": "State (IPv4 groups)", "value": pair(summary["states"], ("Active", "Standby", "Listen"))})
    if "states_v6" in summary and any(summary["states_v6"]):
        rows.append({"metric": "State (IPv6 groups)", "value": pair(summary["states_v6"], ("Active", "Standby", "Listen"))})
    if "tx_pass" in summary:
        rows.append({"metric": "HSRP packets sent", "value": f"{summary['tx_pass']:,} passed, {summary['tx_fail']:,} failed"})
    if "rx_good" in summary:
        rows.append({"metric": "HSRP packets received (good)", "value": f"{summary['rx_good']:,}"})
    if "unknown_groups" in summary:
        rows.append({"metric": "Packets for unknown groups", "value": f"{summary['unknown_groups']:,}"})
    if "extended_hold" in summary:
        rows.append({"metric": "Extended hold (NSF)", "value": summary["extended_hold"]})
    if "bfd" in summary:
        rows.append({"metric": "HSRP over BFD (global)", "value": summary["bfd"]})
    return rows


def peer_text(address: str, priority: str) -> str:
    """``local`` / ``unknown`` / ``172.x.x.x (priority 100)`` for the Active and Standby columns."""
    if not address:
        return "—"
    return f"{address} (priority {priority})" if priority and address not in {"local", "unknown"} else address


def _label(group: dict[str, Any]) -> str:
    return f"{group['interface']} group {group['group']}"


def _listed(groups: list[dict[str, Any]], limit: int = 6) -> str:
    names = [_label(group) for group in groups]
    return ", ".join(names[:limit]) + (f" and {len(names) - limit} more" if len(names) > limit else "")


def findings(groups: list[dict[str, Any]], summary: dict[str, Any]) -> list[dict[str, Any]]:
    """What the live HSRP state of one device says on its own.  Whether the two peers of a pair agree needs both devices (Compare Devices)."""
    from features.analyzer_core.findings import finding

    out: list[dict[str, Any]] = []
    guide = DOCS["hsrp"][1]
    for group in groups:
        if group["state"] == "Disabled":
            reason = group["state_detail"] or "no reason printed"
            out.append(finding(
                "SW-HSRP-001", "medium", "Routing", f"HSRP group is disabled ({reason})", obj=_label(group),
                detail=(f"`show hsrp all` reports this group as Disabled ({reason}). A disabled group takes no part in the election: this switch neither answers for the virtual IP nor stands by for it. "
                        "`show hsrp` and `show hsrp brief` leave such a group out, so only `show hsrp all` shows it."),
                recommendation=(f"Add the virtual IP under `hsrp {group['group']}` on {group['interface']} (`ip <virtual IP>`), the same one the peer uses, or remove the group if it is not meant to run here. "
                                "Then check on the peer that the group is Active with a Standby."), reference=guide))
    initial = [group for group in groups if group["state"] in {"Initial", "Init"}]
    if initial:
        out.append(finding(
            "SW-HSRP-002", "medium", "Routing", f"{len(initial)} HSRP group(s) are in the Initial state", obj=_listed(initial),
            detail=("A group in the Initial state cannot take part in the election, so this switch does not stand by for it. " + " ".join(
                f"{_label(group)}: {group['state_detail']}." if group["state_detail"] else f"{_label(group)}: no reason printed." for group in initial[:6])),
            recommendation=("Find out why the interface is down (`show interface <name>`; for a VLAN interface, `show vlan id <n>` and whether a port in that VLAN is up). "
                            "If the interface is not used any more, remove the HSRP group and the interface."), reference=guide))
    alone = [group for group in groups if group["state"] == "Active" and group["standby"] == "unknown"]
    if alone:
        out.append(finding(
            "SW-HSRP-003", "medium", "Routing", f"{len(alone)} HSRP group(s) are Active with no standby router", obj=_listed(alone),
            detail="`Standby router is unknown` means no other router answers for the group, so if this switch fails nobody takes over the virtual IP.",
            recommendation="On the peer, check `show hsrp all` for the same interface and group: it may be missing, Disabled or in the Initial state.", reference=guide))
    no_preempt = [group for group in groups if group["preempt"] == "off" and group["state"] not in {"Disabled"}]
    if no_preempt:
        out.append(finding(
            "SW-HSRP-004", "low", "Routing", f"{len(no_preempt)} HSRP group(s) do not preempt", obj=_listed(no_preempt),
            detail=("Without `preempt` a router with a higher priority does not take the Active role back from a lower-priority router that already holds it; "
                    "the NX-OS guide lists preemption as off by default. After a reload or a failover the roles then stay where they landed."),
            recommendation="Where the higher-priority switch is meant to be the Active one, add `preempt` (with `delay minimum` to let routing converge first) under the group.", reference=guide))
    default_auth = [group for group in groups if group["auth_default"]]
    if default_auth:
        out.append(finding(
            "SW-HSRP-005", "low", "Routing", f"{len(default_auth)} HSRP group(s) have no authentication", obj=_listed(default_auth, 4),
            detail=("The device prints the default text string (`Authentication text \"cisco\"`) for these groups, which is what NX-OS shows when no authentication is configured. "
                    "Any host on the VLAN can then send hellos for the group and take the Active role (HSRP spoofing)."),
            recommendation="Configure MD5 authentication with a key chain on every group, the same on both peers (`authentication md5 key-chain <name>`), and keep the key chain out of the capture.", reference=guide))
    plain = [group for group in groups if group["auth"] == "text"]
    if plain:
        out.append(finding(
            "SW-HSRP-006", "low", "Routing", f"{len(plain)} HSRP group(s) use plain-text authentication", obj=_listed(plain, 4),
            detail="Plain-text authentication sends the string in clear in every hello, so anyone who can capture the VLAN reads it. The string itself is not kept by this analyzer.",
            recommendation="Move to MD5 authentication with a key chain (`authentication md5 key-chain <name>`).", reference=guide))
    lowered = [group for group in groups if group["cfg_priority"] and group["priority"] and group["priority"] != group["cfg_priority"]]
    if lowered:
        out.append(finding(
            "SW-HSRP-007", "medium", "Routing", f"{len(lowered)} HSRP group(s) run with a priority different from the configured one", obj=_listed(lowered),
            detail=" ".join(f"{_label(group)}: priority {group['priority']}, configured {group['cfg_priority']}." for group in lowered[:6])
                   + " The priority in use differs from the configured one, which is what an object the group tracks does when it goes down.",
            recommendation="Check the tracking under the group (`show hsrp all`, `show track`) and the object it follows.", reference=guide))
    other = [group for group in groups if group["state"] and group["state"] not in {"Active", "Standby", "Initial", "Init", "Disabled", "Listen"}]
    if other:
        out.append(finding(
            "SW-HSRP-008", "info", "Routing", f"{len(other)} HSRP group(s) are in a transitional state", obj=_listed(other),
            detail="Speak and Learn are the states a router passes through while it joins the election; seeing them at the moment of the capture can be a router that has just started or a group that keeps changing.",
            recommendation="Run the command again a minute later; if the state does not settle on Active / Standby, read `show hsrp all` for the state-change count.", reference=guide))
    if summary.get("tx_fail"):
        out.append(finding(
            "SW-HSRP-009", "medium", "Routing", "HSRP packets failed to send",
            detail=f"`show hsrp summary` counts {summary['tx_fail']:,} HSRP packets that failed to send (against {summary.get('tx_pass', 0):,} sent).",
            recommendation="Look for interface errors or a control-plane policing drop on the interfaces that run HSRP.", reference=DOCS["show"][1]))
    return out


# --------------------------------------------------------------------------
# Pair check (Compare Devices)
# --------------------------------------------------------------------------

VERDICT_TONES = {"healthy pair": "ok", "both active": "bad", "both standby": "bad", "disabled": "bad", "initial": "warn", "only on a": "warn", "only on b": "warn",
                 "settings differ": "warn", "same priority": "warn", "not settled": "warn"}


def _pair_groups(a_groups: list[dict[str, Any]], b_groups: list[dict[str, Any]]) -> list[tuple[dict[str, Any] | None, dict[str, Any] | None]]:
    """Match the groups of two devices: same interface and group first; a routed port has a different name on each switch, so the groups that are left over meet by group number
    when that number is unique on both sides."""
    index_b = {(row["key"], row["group"], row["family"]): row for row in b_groups}
    pairs: list[tuple[dict[str, Any] | None, dict[str, Any] | None]] = []
    left_a: list[dict[str, Any]] = []
    used: set[tuple[str, str, str]] = set()
    for row in a_groups:
        key = (row["key"], row["group"], row["family"])
        if key in index_b:
            pairs.append((row, index_b[key]))
            used.add(key)
        else:
            left_a.append(row)
    left_b = [row for row in b_groups if (row["key"], row["group"], row["family"]) not in used]
    for row in list(left_a):
        same = [other for other in left_b if other["group"] == row["group"] and other["family"] == row["family"]]
        mine = [other for other in left_a if other["group"] == row["group"] and other["family"] == row["family"]]
        if len(same) == 1 and len(mine) == 1:
            pairs.append((row, same[0]))
            left_a.remove(row)
            left_b.remove(same[0])
    pairs += [(row, None) for row in left_a] + [(None, row) for row in left_b]
    pairs.sort(key=lambda pair: _natural((pair[0] or pair[1])["interface"], (pair[0] or pair[1])["group"]))
    return pairs


def pair_check(
    a_groups: list[dict[str, Any]], b_groups: list[dict[str, Any]],
    ip_a: dict[str, str] | None = None, ip_b: dict[str, str] | None = None,
) -> dict[str, Any]:
    """One row per HSRP group of two devices: the state on each side, whether the pair is a healthy Active / Standby pair, and what differs.

    Needs the live state of both devices (``show hsrp``); a capture with the configuration only has no state and gives an empty result.

    ``ip_a`` / ``ip_b`` are each device's own Layer-3 interface key -> real
    (non-virtual) IP address (``compare._l3_ip_by_key``) -- optional, so this
    still works wherever it is called without them. When given, each row
    also carries the real subnet address of each device's own interface next
    to the group's virtual IP, so a reviewer can tell the gateway's virtual
    IP from the two real device addresses that answer for it."""
    ip_a, ip_b = ip_a or {}, ip_b or {}
    if not a_groups or not b_groups:
        return {"rows": [], "counts": {}, "active_a": 0, "active_b": 0}
    rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for a, b in _pair_groups(a_groups, b_groups):
        item = a or b
        reasons: list[str] = []
        if a is None or b is None:
            verdict = "Only on B" if a is None else "Only on A"
            reasons.append("the group exists on one switch only")
        else:
            states = {a["state"], b["state"]}
            if a["state"] == "Disabled" or b["state"] == "Disabled":
                verdict = "Disabled"
                side = " and ".join(name for name, row in (("A", a), ("B", b)) if row["state"] == "Disabled")
                reasons.append(f"disabled on {side}" + (f" ({a['state_detail'] or b['state_detail']})" if (a["state_detail"] or b["state_detail"]) else ""))
            elif states == {"Active", "Standby"}:
                verdict = "Healthy pair"
            elif a["state"] == b["state"] == "Active":
                verdict = "Both Active"
                reasons.append("both switches answer for the virtual IP; they do not hear each other's hellos")
            elif a["state"] == b["state"] == "Standby":
                verdict = "Both Standby"
                reasons.append("no switch is Active")
            elif "Initial" in states or "Init" in states:
                verdict = "Initial"
                for name, row in (("A", a), ("B", b)):
                    if row["state"] in {"Initial", "Init"}:
                        reasons.append(f"{name} is Initial" + (f" ({row['state_detail']})" if row["state_detail"] else ""))
            else:
                verdict = "Not settled"
                reasons.append(f"A {a['state'] or 'unknown'}, B {b['state'] or 'unknown'}")
            differences = []
            for field, label in (("virtual_ip", "virtual IP"), ("version", "HSRP version"), ("auth", "authentication"), ("preempt", "preempt"), ("hello", "hello timer"), ("hold", "hold timer")):
                if a.get(field) and b.get(field) and a[field] != b[field]:
                    differences.append(f"{label} differs (A {a[field]}, B {b[field]})")
            if states == {"Active", "Standby"} and a["priority"] and a["priority"] == b["priority"]:
                if verdict == "Healthy pair":
                    verdict = "Same priority"
                differences.append(f"same priority {a['priority']} on both (the higher IP address wins the tie)")
            if differences and verdict in {"Healthy pair", "Same priority"}:
                verdict = "Settings differ" if any("differs" in text for text in differences) else verdict
            reasons += differences
        counts[verdict] = counts.get(verdict, 0) + 1
        name = item["interface"] if not (a and b and a["key"] != b["key"]) else f"{a['interface']} / {b['interface']}"
        rows.append({"interface": name, "group": item["group"], "a_state": (a or {}).get("state") or "—", "b_state": (b or {}).get("state") or "—",
                     "a_priority": (a or {}).get("priority") or "—", "b_priority": (b or {}).get("priority") or "—",
                     "a_preempt": (a or {}).get("preempt") or "—", "b_preempt": (b or {}).get("preempt") or "—",
                     "virtual_ip": (a or b).get("virtual_ip") or "—" if not (a and b and a.get("virtual_ip") != b.get("virtual_ip")) else f"A {a.get('virtual_ip') or '—'} / B {b.get('virtual_ip') or '—'}",
                     "a_ip": (ip_a.get(a["key"], "") if a else "") or "—", "b_ip": (ip_b.get(b["key"], "") if b else "") or "—",
                     "verdict": verdict, "reason": "; ".join(reasons) or "Active on one switch, Standby on the other, settings agree"})
    return {"rows": rows, "counts": counts, "active_a": sum(1 for a, _b in _pair_groups(a_groups, b_groups) if a and a["state"] == "Active"),
            "active_b": sum(1 for _a, b in _pair_groups(a_groups, b_groups) if b and b["state"] == "Active")}
