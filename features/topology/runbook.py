"""Cutover runbook: an ordered, printable change plan written from the tables of one topology run.

Input is the same ``topology.json`` tables that "Compare two runs" reads (devices, links, hosts, findings).  Nothing is invented:

* **Impact** of a device is measured on the captured links.  The device is removed from the graph and the nodes that can no longer reach a root
  (the devices of the highest tier present: provider / router, else firewall, load balancer or core, else the next tier down) are the ones that lose service.  Nodes that were already cut off
  before the change are not counted.  An empty impact means a redundant path was proven in the captures; it is not a promise about traffic.
* **Order** is edge to core: lower tiers first, the devices with the smaller impact first, the secondary vPC peer before the primary.  It is a
  proposal; the sequence column of the CSV can be re-sorted by hand.
* **Port map** is the cabling of the run (local port, bundle, remote device and port, speed, how well the link was confirmed).  A replacement is
  patched back from it.
* **Commands** are `show` / `display` commands only, to take a baseline and to check the result.  Nothing here changes a device.  Rollback is
  physical (re-patch, previous image, saved configuration) and named step by step; no vendor rollback command is quoted.
* **After the window** the runbook sends the reader to "Compare two runs" with this run as the *before* side.

Documentation used (all opened and read; the Huawei page is listed by the Huawei search because support.huawei.com refuses automated access):
Cisco "Understand and Configure Nexus 9000 vPC with Best Practices" (vPC pair, one peer at a time), Cisco "Troubleshoot LACP on Nexus"
(bundle members after a change), Cisco "Troubleshoot STP Problems and Related Design Considerations" (a new switch must not become root),
Huawei CloudEngine S Configuration Guide (display commands), HPE Aruba Networking AOS-CX VSX architecture guide.
"""
from __future__ import annotations

import html
import re
from collections import deque
from typing import Any

from .roles import ROLE_TIER

DOC_VPC = "https://www.cisco.com/c/en/us/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html"
DOC_LACP = "https://www.cisco.com/c/en/us/support/docs/lan-switching/link-aggregation-control-protocol-lacp-8023ad/221051-troubleshoot-link-aggregation-control-pr.html"
DOC_STP = "https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/10556-16.html"
DOC_HUAWEI = "https://support.huawei.com/enterprise/en/doc/EDOC1100333463"
DOC_AOSCX = "https://developer.arubanetworks.com/aoscx/v10.04/docs/architecture-ii-dedicated-data-center-two-tier"

CHANGES = {
    "replace": "Replace the hardware",
    "upgrade": "Upgrade the software",
    "config": "Change the configuration",
}
MAX_PORT_ROWS = 200          # port-map rows per device in the plan; links.csv keeps all of them
MAX_NAMES = 8                # names listed before "and N more"

FAMILIES: dict[str, dict[str, Any]] = {
    "iosxe": {"label": "Cisco IOS / IOS XE", "docs": [("Cisco - Troubleshoot STP problems", DOC_STP), ("Cisco - Troubleshoot LACP", DOC_LACP)],
              "commands": ["show version", "show running-config", "show interfaces status", "show etherchannel summary", "show spanning-tree summary",
                           "show cdp neighbors detail", "show lldp neighbors detail", "show vlan brief", "show ip route summary", "show logging"]},
    "nxos": {"label": "Cisco NX-OS", "docs": [("Cisco - Nexus 9000 vPC best practices", DOC_VPC), ("Cisco - Troubleshoot LACP", DOC_LACP)],
             "commands": ["show version", "show running-config", "show interface status", "show port-channel summary", "show vpc", "show spanning-tree summary",
                          "show cdp neighbors detail", "show lldp neighbors detail", "show vlan brief", "show ip route summary", "show logging"]},
    "huawei": {"label": "Huawei VRP", "docs": [("Huawei - CloudEngine S configuration guide", DOC_HUAWEI)],
               "commands": ["display version", "display current-configuration", "display interface brief", "display eth-trunk", "display stp brief",
                            "display lldp neighbor brief", "display vlan", "display ip routing-table statistics", "display logbuffer"]},
    "aoscx": {"label": "Aruba AOS-CX", "docs": [("HPE Aruba Networking - AOS-CX VSX architecture", DOC_AOSCX)],
              "commands": ["show version", "show running-config", "show interface brief", "show lacp interfaces", "show spanning-tree", "show lldp neighbor-info",
                           "show vlan", "show mac-address-table", "show ip route", "show logging"]},
    "arubaos": {"label": "ArubaOS-Switch", "docs": [],
                "commands": ["show system", "show running-config", "show interfaces brief", "show trunks", "show lacp", "show spanning-tree",
                             "show lldp info remote-device", "show vlans", "show logging"]},
    "fortigate": {"label": "FortiGate", "docs": [],
                  "commands": ["get system status", "get system ha status", "show full-configuration", "get system interface physical"]},
    "paloalto": {"label": "Palo Alto PAN-OS", "docs": [],
                 "commands": ["show system info", "show high-availability state", "show interface all"]},
    "f5": {"label": "F5 BIG-IP", "docs": [],
           "commands": ["tmsh show sys version", "tmsh show sys failover", "tmsh show net trunk", "tmsh show net vlan"]},
    "generic": {"label": "Other platform", "docs": [], "commands": []},
}
_AOSCX_MODEL = re.compile(r"(?<!\d)(?:6[0-4]\d\d|8[0-9]\d\d|9300|10000)(?!\d)|aoscx|aos-cx", re.I)


class RunbookError(ValueError):
    """A request the plan cannot be written for; the message is shown to the person as it is."""


def _t(value: Any) -> str:
    return str(value if value is not None else "").strip()


def _e(value: Any) -> str:
    return html.escape(_t(value), quote=True)


def _captured(row: dict) -> bool:
    return _t(row.get("captured")).lower().startswith("yes")


def family_of(row: dict) -> str:
    vendor, model = _t(row.get("vendor")).lower(), _t(row.get("model")).lower()
    role = _t(row.get("role")).lower()
    if "cisco" in vendor:
        return "nxos" if re.search(r"\bn\d[0-9a-z]*k\b|^n\d+k|nexus|nx-os", model) or _t(row.get("vpc_domain")) else "iosxe"
    if "huawei" in vendor:
        return "huawei"
    if "aruba" in vendor or "hpe" in vendor or "hewlett" in vendor:
        return "aoscx" if _AOSCX_MODEL.search(model) else "arubaos"
    if "forti" in vendor:
        return "fortigate"
    if "palo" in vendor or "pan-os" in vendor:
        return "paloalto"
    if "f5" in vendor or role == "loadbalancer" and "big" in model:
        return "f5"
    return "generic"


def _tier(role: str) -> int:
    return ROLE_TIER.get(role or "switch", 3)


def _names(items, limit: int = MAX_NAMES) -> str:
    items = list(items)
    if not items:
        return "none"
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


# ---- the graph ------------------------------------------------------------------------------------------------------------------------------

class _Net:
    """Undirected graph of the captured links, with the reachability test that measures impact."""

    def __init__(self, devices: dict[str, dict], links: list[dict]):
        self.role = {name: (_t(row.get("role")).lower() or "switch") for name, row in devices.items()}
        self.edges: dict[str, set[str]] = {name: set() for name in devices}
        for row in links:
            a, b = _t(row.get("device_a")), _t(row.get("device_b"))
            if not a or not b or a == b or _t(row.get("kind")).lower() == "mgmt":
                continue
            for name in (a, b):
                if name not in self.edges:
                    self.edges[name] = set()
                    self.role[name] = "switch"
            self.edges[a].add(b)
            self.edges[b].add(a)
        connected = [n for n in self.edges if self.edges[n]]
        lowest = min((_tier(self.role[n]) for n in connected), default=0)
        self.roots = {n for n in connected if _tier(self.role[n]) == lowest}
        self._impact: dict[str, list[str]] = {}
        self.cut_off_before = set(self.edges) - self._reach(None)

    def _reach(self, removed: str | None) -> set[str]:
        seen = {n for n in self.roots if n != removed}
        queue = deque(seen)
        while queue:
            node = queue.popleft()
            for other in self.edges.get(node, ()):
                if other != removed and other not in seen:
                    seen.add(other)
                    queue.append(other)
        return seen

    def impact(self, name: str) -> list[str]:
        """The nodes that lose every path to a root when ``name`` is taken out (already isolated nodes are not counted)."""
        if name not in self._impact:
            self._impact[name] = self._lost(name)
        return self._impact[name]

    def _lost(self, name: str) -> list[str]:
        lost = set(self.edges) - {name} - self._reach(name) - self.cut_off_before
        return sorted(lost, key=str.lower)


# ---- text building blocks -------------------------------------------------------------------------------------------------------------------

def _impact_text(net: _Net, impact: list[str], hosts: dict[str, int], name: str) -> str:
    if not impact:
        return "No loss of reachability in the captured links: every other device keeps a path to the core."
    by_role: dict[str, int] = {}
    named = []
    for item in impact:
        role = net.role.get(item, "switch")
        if role in ("ap", "phone", "server", "host"):
            by_role[role] = by_role.get(role, 0) + 1
        else:
            named.append(item)
    parts = []
    if named:
        parts.append(_names(named))
    parts += [f"{count} {role}{'s' if count != 1 else ''}" for role, count in sorted(by_role.items())]
    macs = hosts.get(name, 0) + sum(hosts.get(item, 0) for item in impact)
    tail = f" About {macs} end-host MAC address(es) were learned on these switches." if macs else ""
    top = sorted((r for r in net.roots if r != name), key=str.lower)
    reach = f" No remaining path to {_names(top, 3)}." if top else " No other top-level device is left in the captured links."
    return f"Outage for {'; '.join(parts)}.{reach}{tail}"


def _commands(family: str) -> list[str]:
    return list(FAMILIES[family]["commands"])


def _port_map(name: str, links: list[dict]) -> list[dict]:
    rows = []
    for row in links:
        a, b = _t(row.get("device_a")), _t(row.get("device_b"))
        if _t(row.get("kind")).lower() == "mgmt" or name not in (a, b):
            continue
        mine = "a" if a == name else "b"
        other = "b" if mine == "a" else "a"
        rows.append({"port": _t(row.get(f"port_{mine}")), "bundle": _t(row.get(f"bundle_{mine}")), "peer": _t(row.get(f"device_{other}")),
                     "peer_port": _t(row.get(f"port_{other}")), "peer_bundle": _t(row.get(f"bundle_{other}")), "speed": _t(row.get(f"speed_{mine}")) or _t(row.get(f"rated_{mine}")),
                     "state": _t(row.get("state")), "port_state": _t(row.get(f"port_state_{mine}")), "kind": _t(row.get("kind")),
                     "vlan": _t(row.get("native_vlan"))})
    rows.sort(key=lambda r: _port_key(r["port"]))
    return rows


def _port_key(port: str) -> list:
    return [(0, int(x), "") if x.isdigit() else (1, 0, x.lower()) for x in re.findall(r"\d+|\D+", port)]


def _findings_for(name: str, findings: list[dict]) -> list[dict]:
    out = []
    for item in findings:
        devices = item.get("devices")
        listed = devices if isinstance(devices, list) else [d.strip() for d in _t(devices).split(",")]
        if name in listed and _t(item.get("severity")).lower() in ("high", "medium"):
            out.append(item)
    return out


# ---- the plan ---------------------------------------------------------------------------------------------------------------------------------

def _device_plan(seq: int, name: str, row: dict, family: str, net: _Net, links: list[dict], findings: list[dict], hosts: dict[str, int],
                 partner: str, change: str, rows_by_name: dict[str, dict]) -> dict[str, Any]:
    impact = net.impact(name)
    ports = _port_map(name, links)
    role = _t(row.get("role")) or "switch"
    vpc_role = _t(row.get("vpc_role"))
    stack = int(_t(row.get("stack_members")) or 1) if _t(row.get("stack_members")).isdigit() else 1
    weak = [p for p in ports if p["state"].lower() not in ("confirmed", "")]
    down = [p for p in ports if p["port_state"].lower().startswith(("down", "admin"))]
    risk: list[str] = [_impact_text(net, impact, hosts, name)]
    if partner:
        risk.append(f"vPC pair with {partner}" + (f" ({vpc_role})" if vpc_role else "") + ". Work on one peer at a time and start the second only after the first passes every post-check.")
    if stack > 1:
        risk.append(f"A stack of {stack} members: a reload or a power-off takes the whole stack. Check that every bundle has members on more than one unit before touching a member.")
    if not _t(row.get("management_ip")):
        risk.append("No management address in the capture. Use the console.")
    plan = {"seq": seq, "device": name, "role": role, "vendor": _t(row.get("vendor")), "model": _t(row.get("model")), "os": _t(row.get("os_version")),
            "mgmt": _t(row.get("management_ip")), "family": family, "impact": impact, "impact_text": _impact_text(net, impact, hosts, name),
            "partner": partner, "stack": stack, "ports": ports, "weak": weak, "down": down, "findings": _findings_for(name, findings), "risk": risk,
            "outage": bool(impact), "peers": sorted({p["peer"] for p in ports}, key=str.lower)}
    plan["steps"] = _device_steps(plan, change, rows_by_name)
    return plan


def _step(phase: str, step: str, detail: str = "", command: str = "", expect: str = "") -> dict[str, str]:
    return {"phase": phase, "step": step, "detail": detail, "command": command, "expect": expect}


def _device_steps(plan: dict[str, Any], change: str, rows_by_name: dict[str, dict]) -> list[dict[str, str]]:
    name, family = plan["device"], plan["family"]
    commands = _commands(family)
    steps: list[dict[str, str]] = []
    steps.append(_step("Before", "Confirm you can reach the device",
                       f"Management address {plan['mgmt']}." if plan["mgmt"] else "No management address in the run.",
                       expect="Login works on the network and on the console."))
    if commands:
        steps.append(_step("Before", "Take the baseline", "Save the output of every command to a file named after the device and the time.",
                           "\n".join(commands), "The files exist and are complete (no truncated tables)."))
    else:
        steps.append(_step("Before", "Take the baseline", "No command list is built in for this platform. Save the device's own equivalents of: version, configuration, interface "
                           "status, port-channels, spanning tree, neighbors, VLANs, routes, log.", expect="The files exist and are complete."))
    steps.append(_step("Before", "Back up the configuration", "Copy the running configuration to the backup location and keep a second copy off the device.",
                       expect="The backup opens and holds the full configuration."))
    if plan["partner"]:
        gate = {"nxos": "show vpc", "huawei": "display eth-trunk", "aoscx": "show lacp interfaces"}.get(family, "")
        steps.append(_step("Before", f"Check the partner {plan['partner']} is healthy", "The pair carries the traffic alone while this device is out.", gate,
                           "Peer adjacency up, consistency check passed, every port-channel up on the partner."))
    if plan["findings"]:
        steps.append(_step("Before", "Read the open findings for this device",
                           "; ".join(f"{_t(f.get('id'))} {_t(f.get('severity'))}: {_t(f.get('title'))}" for f in plan["findings"][:6])
                           + (f" and {len(plan['findings']) - 6} more" if len(plan["findings"]) > 6 else ""),
                           expect="Each one is fixed first or accepted in the change record."))
    if plan["weak"]:
        steps.append(_step("Before", "Confirm the cabling that was seen from one end only",
                           "; ".join(f"{p['port']} to {p['peer']} {p['peer_port']} ({p['state']})" for p in plan["weak"][:MAX_NAMES])
                           + (f" and {len(plan['weak']) - MAX_NAMES} more" if len(plan["weak"]) > MAX_NAMES else ""),
                           expect="Both ends are identified before a cable is moved."))
    if change == "replace":
        steps.append(_step("Change", "Label every cable at both ends", "Use the port map below. Photograph the front and the back of the unit.", expect="Every cable in the map has a label."))
        steps.append(_step("Change", "Take the old unit out", "Power it off, unplug the cables, keep the unit and its configuration unchanged for the rollback.",
                           expect="Nothing is left connected to the old unit."))
        steps.append(_step("Change", "Fit the new unit and load its configuration", "Management address, VLANs, port-channels and spanning-tree priority as before; a new switch must not "
                           "become the spanning-tree root by accident (it starts with a default priority).", expect="The new unit boots with the intended configuration."))
        shown = plan["ports"][:MAX_PORT_ROWS]
        for p in shown:
            peer = f"{p['peer']} {p['peer_port']}".strip()
            steps.append(_step("Change", f"Patch {p['port']} to {peer}", ("Member of " + p["bundle"] + ". " if p["bundle"] else "") + (f"Speed {p['speed']}." if p["speed"] else ""),
                               expect="Link up on both ends."))
        if len(plan["ports"]) > MAX_PORT_ROWS:
            steps.append(_step("Change", f"Patch the remaining {len(plan['ports']) - MAX_PORT_ROWS} port(s)", "They are listed in links.csv of the pack.", expect="Link up on both ends."))
    elif change == "upgrade":
        steps.append(_step("Change", "Load the new software image", "Copy the image to the device and verify its checksum against the vendor's release notes before it is selected.",
                           expect="The checksum matches."))
        steps.append(_step("Change", "Select the new image and reload", "Keep the previous image on the device. Write the reload time in the change record.",
                           expect="The device boots the new version."))
    else:
        steps.append(_step("Change", "Apply the configuration change", "Exactly as written in the change record; one block at a time, checking the neighbors after each.",
                           expect="The change is applied and the neighbors stay up."))
    steps.append(_step("After", "Run the baseline commands again", "Save the output next to the earlier files and compare them.", "\n".join(commands) if commands else "",
                       "Same neighbors and the same VLANs; every port in the port map is up (or was down before); every port-channel member is bundled; "
                       "no unexpected spanning-tree root change; no new error in the log."))
    if plan["partner"]:
        steps.append(_step("After", f"Gate: start {plan['partner']} only now", "Do not touch the partner until every check above passed on this device.", expect="Go / no-go written in the change record."))
    return steps


def _rollback(plan: dict[str, Any], change: str) -> list[str]:
    if change == "replace":
        return ["Power off the new unit and unplug its cables.", "Re-patch every cable to the old unit using the port map (the labels).",
                "Power on the old unit with its saved configuration and run the baseline commands again.", "Check the neighbors against the port map."]
    if change == "upgrade":
        return ["Select the previous image (still on the device) and reload.", "Run the baseline commands again and check the neighbors."]
    return ["Restore the configuration backup taken in step 'Back up the configuration'.", "Run the baseline commands again and check the neighbors."]


def build_runbook(run: dict[str, list[dict]], *, title: str = "", window: str = "", reference: str = "", change: str = "replace",
                  only: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
    """The plan for the captured devices of a run (or only ``only``).  Returns ``{"summary", "devices", "steps", "html"}`` or raises RunbookError."""
    if change not in CHANGES:
        raise RunbookError(f"Unknown change type '{_t(change)[:30]}'. Choose one of: {', '.join(CHANGES)}.")
    devices = {_t(r.get("device")): r for r in run.get("devices", []) if _t(r.get("device"))}
    links = [r for r in run.get("links", []) if isinstance(r, dict)]
    findings = [f for f in run.get("findings", []) if isinstance(f, dict)]
    captured = sorted((n for n, r in devices.items() if _captured(r)), key=str.lower)
    if not captured:
        raise RunbookError("This run has no captured device, so there is nothing to plan. Build the topology from device captures first.")
    wanted = [n.strip() for n in only if n and n.strip()]
    if wanted:
        lookup = {n.lower(): n for n in captured}
        unknown = [n for n in wanted if n.lower() not in lookup]
        if unknown:
            raise RunbookError(f"Not a captured device in this run: {_names(unknown, 5)}. Captured devices: {_names(captured, 12)}.")
        scope = sorted({lookup[n.lower()] for n in wanted}, key=str.lower)
    else:
        scope = captured
    net = _Net(devices, links)
    hosts: dict[str, int] = {}
    for h in run.get("hosts", []):
        if isinstance(h, dict) and _t(h.get("device")):
            hosts[_t(h["device"])] = hosts.get(_t(h["device"]), 0) + 1
    domains: dict[str, list[str]] = {}
    for n in captured:
        domain = _t(devices[n].get("vpc_domain"))
        if domain:
            domains.setdefault(domain, []).append(n)

    def partner_of(n: str) -> str:
        domain = _t(devices[n].get("vpc_domain"))
        return next((o for o in domains.get(domain, []) if o != n), "") if domain else ""

    def order_key(n: str):
        row = devices[n]
        secondary = 0 if "secondary" in _t(row.get("vpc_role")).lower() else 1
        return (-_tier(net.role.get(n, "switch")), len(net.impact(n)), secondary, n.lower())

    ordered = sorted(scope, key=order_key)
    plans = [_device_plan(i, n, devices[n], family_of(devices[n]), net, links, findings, hosts, partner_of(n), change, devices) for i, n in enumerate(ordered, 1)]
    skipped = sorted((n for n, r in devices.items() if not _captured(r)), key=str.lower)
    flat = _flat_steps(plans, change, reference, window, title)
    summary = {"devices": len(plans), "outage": sum(1 for p in plans if p["outage"]), "rolling": sum(1 for p in plans if not p["outage"]),
               "not_captured": len(skipped), "steps": len(flat), "change": change, "roots": sorted(net.roots, key=str.lower)}
    return {"summary": summary, "devices": [{k: p[k] for k in ("seq", "device", "role", "vendor", "model", "family", "outage", "impact_text", "partner")} for p in plans],
            "steps": flat, "html": _render(plans, summary, skipped, title=title, window=window, reference=reference, change=change, net=net)}


def _flat_steps(plans: list[dict], change: str, reference: str, window: str, title: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def add(seq: Any, device: str, phase: str, item: dict[str, str]) -> None:
        rows.append({"seq": str(len(rows) + 1), "device_order": str(seq), "device": device, "phase": phase, "step": item["step"], "detail": item["detail"],
                     "command": item["command"].replace("\n", " ; "), "expect": item["expect"], "done": "", "by": "", "time": ""})

    for item in _global_before(change, reference, window):
        add(0, "ALL", "Preparation", item)
    for plan in plans:
        for item in plan["steps"]:
            add(plan["seq"], plan["device"], item["phase"], item)
        for text in _rollback(plan, change):
            add(plan["seq"], plan["device"], "Rollback", _step("Rollback", text))
    for item in _global_after():
        add(len(plans) + 1, "ALL", "Verification", item)
    return rows


def _global_before(change: str, reference: str, window: str) -> list[dict[str, str]]:
    ref = f" Change record: {reference}." if reference else ""
    win = f" Window: {window}." if window else ""
    items = [
        _step("Preparation", "Approve the change and name the people", "Change record approved, rollback owner named, the people who use the affected devices told." + ref + win,
              expect="Approval and owner written in the change record."),
        _step("Preparation", "Use a recent run as the 'before' side", "This run is the baseline for the comparison after the window. If the captures are old, collect again and build a new run first.",
              expect="topology.json of this run is stored with the change record."),
        _step("Preparation", "Check out-of-band access", "Console or management-network access to every device in the plan, tested before the window.", expect="A login works on each."),
    ]
    if change == "replace":
        items.append(_step("Preparation", "Prepare the new units", "Staged, powered once, software at the planned version. If the new switch is another vendor, convert the old configuration in Configuration Studio "
                           "and read its round-trip check and the REVIEW lines first.", expect="Each new unit has a reviewed configuration."))
    return items


def _global_after() -> list[dict[str, str]]:
    return [
        _step("Verification", "Collect the devices again and build a new run", "Use the same collect list and the same options as the 'before' run.", expect="A new topology.json."),
        _step("Verification", "Compare the two runs", "Topology Builder, Compare two runs: before = the run this plan was written from, after = the new run.",
              expect="Only the planned differences appear (new model, serial or version for a replaced device). Every row marked 'need attention' is explained or rolled back."),
        _step("Verification", "Check the new configurations against the baseline", "Switch Analyzer, Baseline: choose the organisation standard and analyze the new captures.",
              expect="No SW-BASE finding that is not accepted in the change record."),
        _step("Verification", "Close the change", "Sign-off below, backups and captures stored with the change record.", expect="Change record closed."),
    ]


# ---- HTML ---------------------------------------------------------------------------------------------------------------------------------------

_CSS = """
body{font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;color:#1c2330;margin:24px auto;max-width:1100px;padding:0 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;border-bottom:2px solid #d7dde6;padding-bottom:4px}h3{font-size:15px;margin:18px 0 6px}
table{border-collapse:collapse;width:100%;margin:8px 0 14px}th,td{border:1px solid #c9d1dc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#eef2f7}
code,pre{font:12.5px Consolas,monospace}pre{background:#f4f6f9;border:1px solid #d7dde6;padding:8px;margin:4px 0;white-space:pre-wrap}
.meta{color:#4a5568}.risk{border-left:4px solid #b7791f;background:#fff8e6;padding:6px 10px;margin:6px 0}.risk.out{border-color:#c53030;background:#fff1f1}
.ok{border-color:#2f855a;background:#effaf3}.box{width:14px;height:14px;border:1px solid #1c2330;display:inline-block}
.device{page-break-before:always}@media print{body{margin:0;max-width:none}.device{page-break-before:always}}
""".strip()


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell if isinstance(cell, _Raw) else _e(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


class _Raw(str):
    """Markup that is already escaped."""


def _step_html(items: list[dict[str, str]]) -> str:
    rows = []
    for item in items:
        detail = _e(item["detail"])
        cmd = f"<pre>{_e(item['command'])}</pre>" if item["command"] else ""
        rows.append([_Raw('<span class="box"></span>'), _Raw(f"<strong>{_e(item['step'])}</strong><br>{detail}{cmd}"), item["expect"], "", ""])
    return _table(["Done", "Step", "Expected result", "By", "Time"], rows)


def _render(plans: list[dict], summary: dict, skipped: list[str], *, title: str, window: str, reference: str, change: str, net: _Net) -> str:
    name = title or "Cutover runbook"
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{_e(name)}</title><style>{_CSS}</style></head><body>",
           f"<h1>{_e(name)}</h1>",
           f"<p class='meta'>{_e(CHANGES[change])} · {summary['devices']} device(s) · "
           f"{summary['outage']} with an expected outage · {summary['rolling']} with a redundant path"
           + (f" · window {_e(window)}" if window else "") + (f" · change record {_e(reference)}" if reference else "") + "</p>",
           "<p class='meta'>Written from the captured links of one topology run. The impact and the order are proposals read from the captures, not a measurement of traffic. "
           "Commands are read-only (show / display); nothing in this document changes a device.</p>",
           "<h2>1. Order of work</h2>"]
    out.append(_table(["#", "Device", "Role", "Platform", "Redundancy", "Impact"],
                      [[p["seq"], p["device"], p["role"], f"{p['vendor']} {p['model']}".strip(),
                        (f"vPC with {p['partner']}" if p["partner"] else ("stack of %d" % p["stack"] if p["stack"] > 1 else "none proven")),
                        p["impact_text"]] for p in plans]))
    if skipped:
        out.append(f"<p class='meta'>Not in the plan (seen by neighbors, not captured): {_e(_names(skipped, 12))}. Collect them first if they are part of the change.</p>")
    out.append("<h2>2. Before the window</h2>" + _step_html(_global_before(change, reference, window)))
    out.append("<h2 class='device-title'>3. Device procedures</h2><p class='meta'>One section per device, in the order of the table above. Start the next device only after the one before has passed every After step.</p>")
    for plan in plans:
        klass = "risk out" if plan["outage"] else "risk ok"
        out.append(f"<div class='device'><h2>3.{plan['seq']} {_e(plan['device'])}</h2>"
                   f"<p class='meta'>{_e(plan['role'])} · {_e((plan['vendor'] + ' ' + plan['model']).strip())} · {_e(plan['os'])} · {_e(plan['mgmt'] or 'no management address')} · "
                   f"{_e(FAMILIES[plan['family']]['label'])}</p>")
        out.append(f"<div class='{klass}'>" + "<br>".join(_e(r) for r in plan["risk"]) + "</div>")
        out.append("<h3>Steps</h3>" + _step_html(plan["steps"]))
        if plan["ports"]:
            shown = plan["ports"][:MAX_PORT_ROWS]
            out.append("<h3>Port map (what is connected today)</h3>" + _table(
                ["Port", "Bundle", "Connected to", "Remote port", "Speed", "Link confirmed", "Port state"],
                [[p["port"], p["bundle"], p["peer"], (p["peer_port"] + (f" ({p['peer_bundle']})" if p["peer_bundle"] else "")).strip(), p["speed"], p["state"], p["port_state"]] for p in shown]))
            if len(plan["ports"]) > len(shown):
                out.append(f"<p class='meta'>{len(shown)} of {len(plan['ports'])} ports shown; links.csv of the pack lists all of them.</p>")
        out.append("<h3>Rollback</h3><p class='meta'>Trigger: a post-check fails and cannot be fixed within the time agreed in the change record.</p><ol>"
                   + "".join(f"<li>{_e(t)}</li>" for t in _rollback(plan, change)) + "</ol></div>")
    out.append("<h2>4. After the window</h2>" + _step_html(_global_after()))
    out.append("<h2>5. Sign-off</h2>" + _table(["Role", "Name", "Date", "Signature"], [[r, "", "", ""] for r in ("Change owner", "Network engineer", "Approver")]))
    refs: dict[str, str] = {}
    for p in plans:
        for label, url in FAMILIES[p["family"]]["docs"]:
            refs[url] = label
    if refs:
        out.append("<h2>6. References</h2><ul>" + "".join(f"<li>{_e(label)}: <a href='{_e(url)}'>{_e(url)}</a></li>" for url, label in refs.items()) + "</ul>")
    out.append("</body></html>")
    return "".join(out)
