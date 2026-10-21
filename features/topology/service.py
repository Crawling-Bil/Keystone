"""Topology Builder entry point: captures in, diagram files and tables out."""

from __future__ import annotations

import csv
import datetime as _dt
import re
import io
import json
from typing import Any

from ..switch_analyzer.service import analyze as analyze_switch
from . import hosts as hosts_module, labels, roles, split as split_module
from .drawio import to_drawio
from .extract import Device, device_from_analysis, os_from_text
from .findings import build_findings
from .graph import Graph, build, link_ratings, link_speeds
from .names import port_sort_key, speed_text
from .rollup import hide_endpoints, rollup
from .inferred import description_drift, fill_addresses_from_arp, infer_neighbors
from .iplogical import ip_page
from .labelplace import place_labels
from .routed import infer_routed
from .state import merge, state_json
from .logical import logical_pages
from .scene import build_pages
from .svg import to_svg

GROUP_MODES = (("none", "One diagram"), ("prefix1", "Group by first hostname word (BGR, JKT, DRC)"),
               ("prefix2", "Group by first two hostname words (JKT-A02)"),
               ("prefix3", "Group by first three hostname words (JKT-GD1-LT1)"))
MAX_FILES = 100


_CONFIG_COMMAND = re.compile(r"^(?:sh|sho|show)\s+run|^(?:dis|disp|display)\s+(?:cur|saved)|^show\s+startup|^show\s+configuration", re.IGNORECASE)


def capture_gap(text: str) -> str:
    """Why a terminal capture is incomplete: the first commands scrolled out of the buffer, or no configuration command was typed at all.
    Empty for a clean capture and for a file without prompts (a pasted fragment says nothing about what is missing)."""
    prompts = [(index, split_module._prompt_host(line)) for index, line in enumerate(text.splitlines()[:20000])]
    typed = [(index, found[1]) for index, found in prompts if found and found[1]]
    if len(typed) < 4:
        return ""
    if any(_CONFIG_COMMAND.match(command) for _, command in typed):
        return ""
    lead = sum(1 for line in text.splitlines()[:typed[0][0]] if line.strip())
    return ("the configuration command was not captured and the capture starts in the middle of a session (the first commands scrolled out of the terminal buffer)"
            if lead >= 5 else "the configuration command was not captured")


def read_devices(files: list[tuple[str, str]]) -> tuple[list[Device], list[dict[str, str]]]:
    devices: list[Device] = []
    skipped: list[dict[str, str]] = []
    for name, text in files:
        if not text.strip():
            skipped.append({"file": name, "reason": "The file is empty."})
            continue
        try:
            result = analyze_switch(text, filename=name)
        except Exception as exc:    # one unreadable capture must not stop the whole run
            skipped.append({"file": name, "reason": f"Could not be read: {exc.__class__.__name__}"})
            continue
        device = device_from_analysis(result, name)
        device.capture_gap = capture_gap(text)
        if not device.os_version:
            device.os_version = os_from_text(text)
        if not device.halves and not device.hostname:
            skipped.append({"file": name, "reason": "No hostname and no neighbors found - is this a device capture?"})
            continue
        devices.append(device)
    return devices, skipped


def build_topology(files: list[tuple[str, str]], group: str = "none", collapse_endpoints: bool = True,
                   show_ports: bool = True, include_hosts: bool = False, include_routed: bool = True,
                   layout: dict[str, dict[str, tuple[float, float]]] | None = None, line_style: str = "state",
                   view: str = "both", hide_mgmt: bool = True, previous: list[Device] | None = None,
                   collapse_aps: bool | None = None, exclude_endpoints: bool = False, infer_neighbors_from_arp: bool = True,
                   name: str = "", created: _dt.datetime | None = None) -> dict[str, Any]:
    """``collapse_endpoints`` folds IP phones and hosts into one node per switch; ``collapse_aps`` does the same for access points
    (default: as ``collapse_endpoints``, so older callers keep their picture).  ``exclude_endpoints`` leaves phones, hosts and servers
    out of the pictures altogether so only network devices remain."""
    devices, skipped = read_devices(files)
    replaced: list[str] = []
    if previous:
        devices, replaced = merge(previous, devices)
    graph = build(devices)
    if hide_mgmt:
        graph.hidden_kinds.add("mgmt")
    fill_addresses_from_arp(graph)
    roles.classify(graph)
    if infer_neighbors_from_arp:
        found = infer_neighbors(graph)
        graph.issues += found
        if found:
            roles.classify(graph)                  # the neighbors named by ARP / descriptions need a role too
    graph.issues += description_drift(graph)
    if include_routed:
        graph.issues += infer_routed(graph)
    fold = {"phone", "host"} if collapse_endpoints else set()
    if collapse_endpoints if collapse_aps is None else collapse_aps:
        fold.add("ap")
    if fold:
        rollup(graph, roles=fold)
    hosts_module.collect(graph, {key: node for key, node in graph.nodes.items() if node.captured})
    if include_hosts:
        hosts_module.draw(graph)
    if exclude_endpoints:
        hide_endpoints(graph)
    pages = build_pages(graph, group, layout)
    for page in pages:
        place_labels(page, graph, show_ports)
    twins = logical_pages(graph, pages)
    for page in twins:
        place_labels(page, graph, show_ports)
    ip_pages = [page for page in [ip_page(graph)] if page is not None]
    findings = build_findings(graph)
    kept = sum(page.kept for page in pages)
    shown = {"physical": pages, "logical": twins or pages, "both": pages + twins, "ip": ip_pages or pages}.get(view, pages + twins)
    settings = {"tool_version": _tool_version(), "name": name, "created": (created or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), "group": group, "view": view,
                "line_style": line_style, "exclude_endpoints": exclude_endpoints, "collapse_endpoints": collapse_endpoints,
                "collapse_aps": collapse_endpoints if collapse_aps is None else collapse_aps, "show_ports": show_ports,
                "infer_neighbors": infer_neighbors_from_arp, "include_routed": include_routed, "hide_mgmt": hide_mgmt, "include_hosts": include_hosts,
                "previous_state": bool(previous), "keep_layout": bool(layout)}
    return {
        "settings": settings, "graph": graph, "pages": pages, "logical_pages": twins, "ip_pages": ip_pages, "findings": findings, "skipped": skipped,
        "drawio": to_drawio(graph, group, show_ports, shown, line_style, title=name, created=created),
        "svgs": [{"name": page.name, "view": page.view, "svg": to_svg(page, graph, show_ports, line_style)} for page in pages + twins + ip_pages],
        "summary": {**summarize(graph, devices, findings, skipped), "layout_kept": kept, "carried": sum(1 for d in devices if d.carried),
                    "replaced": len(replaced), "behind_macs": sum(1 for h in graph.hosts if h.get("via"))},
        "replaced": replaced, "devices": devices,
    }


def summarize(graph: Graph, devices: list[Device], findings: list[dict], skipped: list[dict]) -> dict[str, Any]:
    captured = [n for n in graph.nodes.values() if n.captured]
    states = {"confirmed": 0, "single": 0, "conflict": 0, "inferred": 0}
    for link in graph.links:
        states[link.state] += 1
    routed = sum(1 for c in graph.connections if c.kind == "routed")
    return {"captured": len(captured), "seen_only": len([n for n in graph.nodes.values() if not n.captured and n.role_hint != "host"]),
            "hosts": len(graph.hosts), "routed": routed, "links": len([l for l in graph.links if l.state != "inferred"]),
            "connections": len([c for c in graph.connections if c.kind not in ("host",)]), "confirmed": states["confirmed"], "single_sided": states["single"],
            "conflicts": states["conflict"], "vpc_pairs": len(graph.vpc_pairs), "findings": len(findings), "skipped": len(skipped)}


def columns_of(rows: list[dict[str, Any]]) -> list[str]:
    """Every column that appears in any row, in first-seen order (rows of a table may differ in keys)."""
    seen: dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key)
    return list(seen)


def devices_table(graph: Graph) -> list[dict[str, Any]]:
    coverage_keys = next((list(n.coverage) for n in graph.nodes.values() if n.captured and n.coverage), [])
    rows = []
    for key, node in sorted(graph.nodes.items()):
        if node.role_hint == "host" and not node.captured and key.startswith(("HOST:", "HOSTS:")):
            continue
        rows.append({"device": node.hostname, "captured": "yes" if node.captured else "no (seen by neighbors)", "role": node.role_hint,
                     "vendor": node.vendor, "model": node.model, "os_version": node.os_version, "management_ip": node.mgmt_ip,
                     "serial": ", ".join(sorted(node.serials)), "stack_members": node.stack_members if node.captured else "",
                     "vpc_domain": node.vpc_domain, "vpc_role": node.vpc_role, "source_file": node.source,
                     "capture_run": ("previous run" if node.carried else "this run") if node.captured else "",
                     **{f"has_{k}": ("yes" if node.coverage.get(k) else "no") if node.captured else "" for k in coverage_keys},
                     "rolled_up": ", ".join(getattr(node, "rolled_up", []))})
    return rows


def links_table(graph: Graph) -> list[dict[str, Any]]:
    rows = []
    for conn in graph.connections:
        for link in conn.links:
            speed_a, speed_b = link_speeds(graph, link)
            rated_a, rated_b = link_ratings(graph, link)
            node_a, node_b = graph.nodes.get(link.a), graph.nodes.get(link.b)
            rows.append({"device_a": link.a, "port_a": link.a_port, "device_b": link.b, "port_b": link.b_port,
                         "state": link.state, "protocols": "/".join(sorted(link.protocols)), "bundle_a": conn.a_po, "bundle_b": conn.b_po,
                         "kind": conn.kind, "vpc_id": conn.vpc_id, "speed_a": speed_text(speed_a), "speed_b": speed_text(speed_b),
                         "rated_a": speed_text(rated_a), "rated_b": speed_text(rated_b),
                         "port_state_a": node_a.port_state.get(link.a_port, "") if node_a else "", "port_state_b": node_b.port_state.get(link.b_port, "") if node_b else "",
                         "duplex_a": node_a.duplex.get(link.a_port, "") if node_a else "", "duplex_b": node_b.duplex.get(link.b_port, "") if node_b else "",
                         "subnet": conn.subnet, "native_vlan": link.native_vlan, "duplex": link.duplex, "note": link.note})
    return rows


def hosts_table(graph: Graph) -> list[dict[str, Any]]:
    return [{"mac": labels_dotted(h["mac"]), "ip_address": ", ".join(h["ips"]), "vlan": h["vlan"], "device": h["device"],
             "port": h["port"], "behind": h.get("via", ""), "kind": h.get("kind", ""), "note": h["note"]}
            for h in sorted(graph.hosts, key=lambda h: (h["device"], h["port"], h["mac"]))]


def behind_table(graph: Graph) -> list[dict[str, Any]]:
    """One row per switch port that faces a device nobody captured (a UCS fabric interconnect, a hypervisor uplink, a switch not collected yet):
    how many MAC addresses live behind it, in which VLANs, and how many of them are virtual machines by MAC prefix."""
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for host in graph.hosts:
        if host.get("via"):
            groups.setdefault((host["via"], host["device"], host["port"]), []).append(host)
    rows = []
    for (via, device, port), hosts in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1], port_sort_key(item[0][2]))):
        vlans = sorted({h["vlan"] for h in hosts if h["vlan"]}, key=lambda v: int(v) if v.isdigit() else 0)
        node = graph.nodes.get(device)
        rows.append({"behind": via, "behind_role": groups[(via, device, port)][0].get("via_role") or next((n.role_hint for n in graph.nodes.values() if n.hostname == via), ""), "switch": device, "port": port,
                     "bundle_members": ", ".join(node.bundles.get(port, [])) if node else "", "mac_addresses": len(hosts),
                     "with_ip": sum(1 for h in hosts if h["ips"]), "vmware": sum(1 for h in hosts if h.get("kind") == "VMware"),
                     "hyper_v": sum(1 for h in hosts if h.get("kind") == "Hyper-V"), "vlan_count": len(vlans), "vlans": compress_vlans(vlans)})
    return rows


def compress_vlans(vlans: list[str]) -> str:
    """['2','3','4','10'] -> '2-4,10'."""
    numbers = sorted({int(v) for v in vlans if str(v).isdigit()})
    runs: list[list[int]] = []
    for number in numbers:
        if runs and number == runs[-1][-1] + 1:
            runs[-1].append(number)
        else:
            runs.append([number])
    return ",".join(str(r[0]) if len(r) == 1 else f"{r[0]}-{r[-1]}" for r in runs)


def labels_dotted(mac: str) -> str:
    return hosts_module.dotted(mac)


def to_csv(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns_of(rows), restval="", lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: _csv_safe(v) for k, v in row.items()})
    return buffer.getvalue()


def _csv_safe(value: Any) -> Any:
    """Cells that start with = + - @ are executed as formulas by Excel; a hostname or description can do that."""
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") and text.strip("-") and not text.lstrip("-").isdigit() else value


def _tool_version() -> str:
    try:
        from core.modules import TOOLS
        return next((tool.version for tool in TOOLS if tool.key == "topology"), "")
    except Exception:       # the version is a label; a missing module list must not stop a build
        return ""


def to_json(graph: Graph, findings: list[dict], devices: list[Device] | None = None, settings: dict[str, Any] | None = None) -> str:
    """The tables, readable with indentation, plus (when ``devices`` is given) the compact ``state`` block that lets a later run add to this one."""
    text = json.dumps({"devices": devices_table(graph), "links": links_table(graph), "hosts": hosts_table(graph), "behind": behind_table(graph),
                       "findings": findings, **({"build": settings} if settings else {})}, indent=2)
    if devices is None:
        return text
    return text[:-2] + ',\n  "state": ' + state_json(devices) + "\n}"
