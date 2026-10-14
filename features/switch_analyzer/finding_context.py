"""Related detail for each finding, so the reader does not have to open the CLI to understand it.

A finding says what a rule saw ("port-channel102 went down 16 times"). This module adds what the same capture
knows about the objects involved, taken from tables the analyzer already parsed and never guessed:

* ``evidence`` - ``[{label, value}]``: the port's current state, the device on the other end (CDP / LLDP name, remote
  port, platform), the bundle it belongs to, the vPC row, the log history, the spanning-tree role.
* ``related`` - a small table with one row per port the finding names; for a port-channel one row for the bundle and
  one per member port, each with its own neighbour.
* ``meaning`` - two or three plain sentences for the rules whose title alone is not self-explanatory.

Everything is derived from ``result`` (interfaces, neighbors, port_channels, vpc_mlag, logs, spanning_tree), so a
capture that lacks a table simply produces fewer rows; a missing table is said in words (for example "no CDP / LLDP
output in this capture") instead of being shown as an empty cell.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from . import live_state

MAX_RELATED = 14
_PORT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_])(?:port-channel|portchannel|eth-trunk|ethernet|gigabitethernet|tengigabitethernet|fortygigabitethernet|hundredgige|twentyfivegige|"
    r"twogigabitethernet|fastethernet|xgigabitethernet|po|eth|gi|te|fo|hu|twe|tw|fa|ge|xge|lag|trk)\s?\d+(?:/\d+)*(?:\.\d+)?", re.IGNORECASE)

# Plain-English reading of the rules whose title does not explain itself. Only statements that follow from the rule's own evidence.
MEANING: dict[str, str] = {
    "SW-EVT-001": "The log shows this port losing link again and again: every down message is one loss of carrier, every up message one recovery. "
                  "For a port-channel, down means no member link was usable (or fewer than the configured minimum), so the member ports and the device at the other end, listed below, are where to look.",
    "SW-EVT-005": "A member of a bundle was suspended or left it. A suspended member carries no traffic and sends no LACPDUs. "
                  "It usually means its settings differ from the port-channel or from the other members, or the far end stopped answering LACP.",
    "SW-STP-001": "With no priority configured, every VLAN keeps the default bridge priority (32768 plus the VLAN number), so the root is decided by the lowest MAC address. "
                  "That can move when a switch is added or replaced. Set a lower priority on the switch that should be root and a second one on the backup root.",
    "SW-VPC-004": "A vPC is a port-channel to a device that is attached to both vPC peers. A status of down* is this switch's own view: its member links are not up, "
                  "so the traffic uses the peer-link and the other peer's links. Until this side recovers there is no second path for that device.",
    "SW-VPC-005": "Cisco prints this number in show vpc role but its pages do not say what 2 stands for (a healthy pair prints 0 in every example). "
                  "Everything else in this capture says the pair is healthy: peer adjacency formed, keep-alive alive, configuration consistent, so there is no sign of a split between the peers. "
                  "Treat it as a value to compare with the other peer, not as an outage.",
}


def compact_vlans(text: str, limit: int = 0) -> str:
    """'VLAN0848, VLAN1040-VLAN1041 VLAN2070-VLAN2073' -> '848, 1040-1041, 2070-2073' (NX-OS wraps this list without a comma).
    ``limit`` cuts at a comma, never inside a range, and adds an ellipsis. Text without VLAN names (MST instances) comes back unchanged."""
    numbers: list[int] = []
    for low, high in re.findall(r"VLAN0*(\d+)(?:\s*-\s*VLAN0*(\d+))?", text or "", re.IGNORECASE):
        numbers.extend(range(int(low), int(high or low) + 1))
    if not numbers:
        return (text or "").strip(" ,")
    parts: list[list[int]] = []
    for value in sorted(set(numbers)):
        if parts and parts[-1][1] == value - 1:
            parts[-1][1] = value
        else:
            parts.append([value, value])
    items = [str(a) if a == b else f"{a}-{b}" for a, b in parts]
    if limit and len(", ".join(items)) > limit:
        kept: list[str] = []
        for item in items:
            if len(", ".join(kept + [item])) > limit:
                break
            kept.append(item)
        return ", ".join(kept) + f" and {len(items) - len(kept)} more range(s)"
    return ", ".join(items)


def _short_state(text: str) -> str:
    """The long member state of the Interfaces tab as a few words for a table cell."""
    if text.startswith("bundled"):
        return "bundled"
    if "not listed in show lacp neighbor" in text:
        return "no LACP partner listed"
    return "configured" if text.startswith("configured as a member") else text


def vlan_phrase(text: str, limit: int = 0) -> str:
    """'VLAN(s) 848, 1040-1041' for a list of VLAN names, the text itself for anything else (MST instances)."""
    compact = compact_vlans(text, limit)
    return f"VLAN(s) {compact}" if compact[:1].isdigit() else compact


class _Index:
    def __init__(self, result: dict[str, Any]) -> None:
        key = live_state.interface_key
        self.result = result
        self.interfaces = {key(item["name"]): item for item in result.get("interfaces") or []}
        self.neighbors: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in result.get("neighbors") or []:
            self.neighbors[key(row.get("local_interface", ""))].append(row)
        present = set((result.get("coverage") or {}).get("present") or [])
        self.neighbors_captured = bool(result.get("neighbors")) or "neighbors" in present
        vpc = result.get("vpc_mlag") or {}
        self.vpc_summary = vpc.get("summary") or {}
        self.vpc_by_port = {key(row.get("port", "")): row for row in vpc.get("members") or []}
        self.flaps = {key(row.get("interface", "")): row for row in (result.get("logs") or {}).get("flaps") or []}
        self.stp_ports: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for port in (result.get("spanning_tree") or {}).get("ports") or []:
            self.stp_ports[key(port.get("interface", ""))].append(port)

    # ---- one port -------------------------------------------------------------------------------
    def state_text(self, item: dict[str, Any]) -> str:
        status, detail = str(item.get("status") or ""), str(item.get("status_detail") or "")
        return f"{status} ({detail})" if detail and detail.lower() != status.lower() else status

    def vlan_text(self, item: dict[str, Any]) -> str:
        mode, vlan, allowed = item.get("mode") or "", item.get("vlan") or "", item.get("allowed_vlans") or ""
        if mode == "trunk":
            return f"trunk, allowed {allowed}" if allowed else "trunk"
        if mode == "access" or vlan:
            return f"access VLAN {vlan}".strip() if vlan else "access"
        return mode

    def neighbour_text(self, item: dict[str, Any]) -> tuple[str, str]:
        """(device, remote port) of the CDP / LLDP neighbour on this port, or on the member ports of a bundle."""
        key = live_state.interface_key(item["name"])
        rows = list(self.neighbors.get(key, []))
        if not rows:
            for member in item.get("bundle_members") or []:
                rows.extend(self.neighbors.get(live_state.interface_key(member["port"]), []))
        if not rows:
            return "", ""
        links: dict[str, set[str]] = {}
        for row in rows:   # one link = one local port; CDP and LLDP both listing the same port count once
            links.setdefault(row.get("neighbor_id", "?"), set()).add(live_state.interface_key(row.get("local_interface", "")))
        device = ", ".join(f"{name} ({len(ports)} links)" if len(ports) > 1 else name for name, ports in links.items())
        ports = ", ".join(dict.fromkeys(str(row.get("remote_interface", "")) for row in rows if row.get("remote_interface")))
        return device, ports

    def no_neighbour_text(self) -> str:
        return ("No CDP / LLDP neighbour was reported on this port" if self.neighbors_captured
                else "No CDP / LLDP output in this capture (add show cdp neighbors detail / show lldp neighbors detail)")

    # ---- the ports a finding names -------------------------------------------------------------
    def targets(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        seen: set[str] = set()

        def add(token: str) -> None:
            item = self.interfaces.get(live_state.interface_key(token.strip()))
            if item is not None and item["name"] not in seen:
                seen.add(item["name"])
                found.append(item)
        for token in re.split(r"[,;]\s*", str(finding.get("object") or "")):
            if token.strip():
                add(token)
        for match in _PORT_TOKEN.finditer(str(finding.get("title") or "")):
            add(match.group(0))
        return found

    def related_rows(self, items: list[dict[str, Any]]) -> tuple[list[dict[str, str]], int]:
        rows: list[dict[str, str]] = []
        seen: set[str] = set()

        def add(item: dict[str, Any], role: str = "") -> None:
            if item["name"] in seen:
                return
            seen.add(item["name"])
            device, remote = self.neighbour_text(item)
            if item.get("bundle_members"):
                bundle = f"{len(item['bundle_members'])} member port(s)"
            elif item.get("bundle"):
                bundle = f"{item['bundle']} · {_short_state(item.get('bundle_state') or 'member')}"
            else:
                bundle = role
            rows.append({"interface": item["name"], "state": self.state_text(item), "bundle": bundle, "device": device, "remote": remote,
                         "vlans": self.vlan_text(item), "description": str(item.get("description") or "")})
        for item in items:
            add(item)
            for member in item.get("bundle_members") or []:
                member_item = self.interfaces.get(live_state.interface_key(member["port"]))
                if member_item is not None:
                    add(member_item)
        return rows[:MAX_RELATED], max(0, len(rows) - MAX_RELATED)

    # ---- facts of one port as label / value --------------------------------------------------------
    def port_evidence(self, item: dict[str, Any], rule: str = "") -> list[dict[str, str]]:
        key = live_state.interface_key(item["name"])
        out = [{"label": "Port now", "value": f"{item['name']}: {self.state_text(item)}" + (f", {self.vlan_text(item)}" if self.vlan_text(item) else "")}]
        device, remote = self.neighbour_text(item)
        if device:
            rows = list(self.neighbors.get(key, [])) or [row for member in item.get("bundle_members") or [] for row in self.neighbors.get(live_state.interface_key(member["port"]), [])]
            platform = next((str(row.get("platform")) for row in rows if row.get("platform")), "")
            protocol = "/".join(dict.fromkeys(str(row.get("protocol", "")) for row in rows if row.get("protocol")))
            out.append({"label": "Connected to", "value": f"{device}" + (f" on its port {remote}" if remote else "") + (f" · {protocol}" if protocol else "") + (f" · {platform}" if platform else "")})
        else:
            out.append({"label": "Connected to", "value": self.no_neighbour_text()})
        if item.get("bundle_members"):
            out.append({"label": "Member ports", "value": "; ".join(f"{m['port']}: {m['state'] or 'configured'}" for m in item["bundle_members"])})
        elif item.get("bundle"):
            mode = f" ({item['bundle_mode']})" if item.get("bundle_mode") else ""
            out.append({"label": "Port-channel", "value": f"member of {item['bundle']}{mode}" + (f": {item['bundle_state']}" if item.get("bundle_state") else "")})
        if item.get("description"):
            out.append({"label": "Description", "value": str(item["description"])})
        vpc = self.vpc_by_port.get(key)
        if vpc:
            out.append({"label": "vPC", "value": f"vPC {vpc.get('id')}: {vpc.get('status')}"
                        + (f" (traffic goes over the peer-link)" if vpc.get("via_peer_link") else "")
                        + f", consistency {vpc.get('consistency') or 'unknown'}" + (f", active VLANs {vpc['vlans']}" if vpc.get("vlans") else "")})
        flap = self.flaps.get(key)
        if flap and rule != "SW-EVT-001":        # that rule already prints the counts and the window
            out.append({"label": "Log history", "value": f"{flap.get('down', 0)} down and {flap.get('up', 0)} up messages, first {flap.get('first') or '?'}, last {flap.get('last') or '?'}"})
        ports = self.stp_ports.get(key)
        if ports:
            states: dict[str, int] = {}
            for port in ports:
                label = str(port.get("state_name") or port.get("state") or "")
                states[label] = states.get(label, 0) + 1
            out.append({"label": "Spanning tree", "value": ", ".join(f"{name} in {count} instance(s)" for name, count in states.items())})
        return out

    # ---- rule specific facts -----------------------------------------------------------------------
    def stp_evidence(self) -> list[dict[str, str]]:
        stp = self.result.get("spanning_tree") or {}
        health_stp = (self.result.get("health") or {}).get("stp") or {}
        roots = [inst for inst in stp.get("instances") or [] if inst.get("is_root")]
        out: list[dict[str, str]] = []
        if health_stp.get("root_for"):
            out.append({"label": "Root for VLANs", "value": compact_vlans(health_stp["root_for"], 420)})
        if roots:
            extras = {int(inst["bridge_priority"]) - int(inst.get("vlan") or 0) for inst in roots if inst.get("bridge_priority") is not None and inst.get("vlan")}
            if extras == {32768}:
                out.append({"label": "Bridge priority in use", "value": "32768 + VLAN number (the default; nothing is configured)"})
            elif extras:
                out.append({"label": "Bridge priority in use", "value": "base priorities " + ", ".join(str(v) for v in sorted(extras))})
            addresses = list(dict.fromkeys(str(inst.get("bridge_address")) for inst in roots if inst.get("bridge_address")))
            if addresses:
                out.append({"label": "Bridge address", "value": ", ".join(addresses[:3]) + (" …" if len(addresses) > 3 else "")})
            mode = health_stp.get("mode") or ", ".join(dict.fromkeys(str(inst.get("protocol")) for inst in roots if inst.get("protocol")))
            if mode:
                out.append({"label": "Spanning-tree mode", "value": str(mode)})
        if health_stp.get("vpc_peer_switch"):
            out.append({"label": "vPC peer-switch", "value": str(health_stp["vpc_peer_switch"])})
        return out

    def vpc_evidence(self) -> list[dict[str, str]]:
        summary = self.vpc_summary
        out: list[dict[str, str]] = []
        labels = (("domain_id", "vPC domain"), ("role", "This switch's role"), ("peer_status", "Peer status"), ("keepalive_status", "Keep-alive"),
                  ("consistency_status", "Configuration consistency"), ("auto_recovery", "Auto-recovery"))
        for key, label in labels:
            if summary.get(key):
                out.append({"label": label, "value": str(summary[key])})
        if summary.get("peer_link"):
            out.append({"label": "Peer-link", "value": f"{summary['peer_link']}: {summary.get('peer_link_status') or '?'}" + (f", VLANs {summary['peer_link_vlans']}" if summary.get("peer_link_vlans") else "")})
        return out

    def log_evidence(self) -> list[dict[str, str]]:
        logs = self.result.get("logs") or {}
        if not logs.get("captured"):
            return []
        window = f"{logs.get('first') or '?'} to {logs.get('last') or '?'}"
        duration = (logs.get("duration") or {}).get("text")
        return [{"label": "Logged by", "value": str(self.result.get("hostname") or "this switch")},
                {"label": "Log window", "value": f"{window}" + (f" ({duration})" if duration else "") + f", {logs.get('message_count', 0)} messages"}]


def attach(result: dict[str, Any]) -> None:
    """Adds ``evidence`` / ``related`` / ``meaning`` to every finding of ``result`` that has something to show."""
    index = _Index(result)
    for finding in result.get("findings") or []:
        rule = str(finding.get("id") or "")
        evidence: list[dict[str, str]] = []
        targets = index.targets(finding)
        if rule.startswith("SW-STP-001"):
            evidence += index.stp_evidence()
        elif rule.startswith(("SW-VPC-", "SW-NX-VPC-")) and not targets:
            evidence += index.vpc_evidence()
        if rule.startswith("SW-EVT-"):
            evidence += index.log_evidence()
        if len(targets) == 1:
            evidence = index.port_evidence(targets[0], rule) + evidence
        if rule.startswith("SW-VPC-004") and targets:
            evidence += index.vpc_evidence()[:4]
        if evidence:
            finding["evidence"] = evidence
        needs_table = len(targets) > 1 or (len(targets) == 1 and targets[0].get("bundle_members"))
        if needs_table:
            rows, more = index.related_rows(targets)
            if rows:
                columns = [("interface", "Port"), ("state", "State"), ("bundle", "Port-channel"), ("device", "Connected to"), ("remote", "Remote port"), ("vlans", "VLANs"), ("description", "Description")]
                columns = [(key, label) for key, label in columns if any(row.get(key) for row in rows)]
                finding["related"] = {"columns": [{"key": key, "label": label} for key, label in columns], "rows": rows, "more": more}
        if rule in MEANING and (targets or rule != "SW-EVT-001"):   # "11 more ports went down" has no single port to explain
            finding["meaning"] = MEANING[rule]
