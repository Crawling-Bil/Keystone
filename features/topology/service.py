"""Topology Builder entry point: captures in, diagram files and tables out."""

from __future__ import annotations

import copy
import csv
import datetime as _dt
import hashlib
import threading
from collections import OrderedDict
import re
import io
import json
from typing import Any

from ..analyzer_core.capture import F5_PROMPT
from ..analyzer_core.vendor_hint import identify
from ..switch_analyzer.service import analyze as analyze_switch
from . import bigipdev, fortidev, panosdev, hosts as hosts_module, l3facts, l3switch, labels, roles, split as split_module
from .drawio import to_drawio
from .extract import Device, device_from_analysis, os_from_text
from .findings import build_findings, findings_by_device
from .graph import Graph, build, link_ratings, link_speeds
from .names import port_sort_key, speed_text
from .rollup import hide_endpoints, rollup
from .f5neighbors import assume_f5_neighbors
from .panha import assume_pan_ha
from .inferred import description_drift, fill_addresses_from_arp, infer_neighbors
from .f5page import f5_pages
from .iplogical import ip_page
from .l2ips import annotate_link_ips
from .l3cloud import parse_hints
from .l3engine import build as build_l3
from .l3focus import Focus
from .l3page import l3_page, l3over2_pages
from .l3tables import overlay_sites_table, overlay_table
from .l3trace import trace_data
from .l3tables import links_table as l3_links_table, routes_table as l3_routes_table, unresolved_table as l3_unresolved_table
from .labelplace import place_labels
from .layout import auto_mode
from .routed import infer_routed
from .state import merge, state_json
from .logical import logical_pages
from .scene import build_pages
from .svg import to_svg

GROUP_MODES = (("auto", "Automatic (one page per site when the network is large)"), ("none", "One diagram"), ("prefix1", "Group by first hostname word (BGR, JKT, DRC)"),
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


def _article(label: str) -> str:
    return "an" if label[:1] in "AEIOU" or label.startswith("F5") else "a"


_CACHE: "OrderedDict[str, tuple[Device | None, dict[str, str] | None]]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
CACHE_FILES = 400           # captures kept in memory (a read device is about 50 KB, so 400 are 20 MB at most): another view or another set of sites rebuilds from the same captures without reading them again; a set of more than the old 24 captures no longer evicts itself while it is read


def _is_f5_capture(text: str) -> bool:
    """A prompted tmsh / bash session of a BIG-IP (``user@(host)(cfg-sync ...)(Active)(/Common)(tmos)#``), which has no 'ltm ...' stanza for ``identify`` to see."""
    return any(F5_PROMPT.match(line) for line in text[:300_000].splitlines()[:600])


def _read_one(name: str, text: str) -> tuple[Device | list[Device] | None, dict[str, str] | None]:
    """One capture -> a device, or the reason it is skipped.  The Switch Analyzer's full reading takes seconds per capture, so the result is kept (see ``read_devices``)."""
    if not text.strip():
        return None, {"file": name, "reason": "The file is empty."}
    found = identify(text)
    if found["kind"] == "firewall" and found["label"].startswith("Fortinet"):
        try:
            found_units = fortidev.read_units(text, name)      # one node per VDOM of a multi-VDOM chassis
            for unit in found_units:
                unit.capture_gap = ""
            return (found_units if len(found_units) > 1 else found_units[0]), None
        except Exception as exc:    # a FortiGate file this reader cannot use is reported, never fatal
            return None, {"file": name, "reason": f"A FortiGate configuration that could not be read: {exc.__class__.__name__}"}
    if found["kind"] == "firewall" and found["label"].startswith("Palo Alto"):
        try:
            found_units = panosdev.read_units(text, name)         # one node per virtual system of a multi-vsys box
            for unit in found_units:
                unit.capture_gap = ""
            return (found_units if len(found_units) > 1 else found_units[0]), None
        except Exception as exc:    # a PAN-OS file this reader cannot use is reported, never fatal
            return None, {"file": name, "reason": f"A Palo Alto PAN-OS configuration that could not be read: {exc.__class__.__name__}"}
    if found["kind"] == "lb" or _is_f5_capture(text):
        try:
            found_units = bigipdev.read_units(text, name)         # one node per vCMP guest of a vCMP host configuration
        except Exception as exc:    # a BIG-IP file this reader cannot use is reported, never fatal
            return None, {"file": name, "reason": f"An F5 BIG-IP configuration that could not be read: {exc.__class__.__name__}"}
        if len(found_units) > 1 or (found_units and found_units[0].unit):
            for unit in found_units:
                unit.capture_gap = ""
            return found_units, None
        device = found_units[0]
        if not device.l3 and not device.l3facts.get("routes") and not device.l3facts.get("fhrp"):
            return None, {"file": name, "reason": "An F5 BIG-IP file without self IPs or routes (a 'show' capture alone has none). Add the UCS archive of the unit, or 'tmsh list net self net vlan net route net trunk', to draw it."}
        device.capture_gap = ""
        return device, None
    if found["kind"] in ("firewall", "lb"):
        return None, {"file": name, "reason": f"This looks like {_article(found['label'])} {found['label']}. Topology Builder draws from switch and router captures (CDP/LLDP neighbors, ARP, MAC table); MikroTik and other load balancer files are not drawn yet (FortiGate, Palo Alto and F5 BIG-IP configurations are)."}
    try:
        facts = l3facts.read(text, name)
    except Exception:           # the L3 reader is an addition: a capture it cannot read still has its L2 facts
        facts = {}
    try:
        result = analyze_switch(text, filename=name)
    except Exception as exc:    # one unreadable capture must not stop the whole run
        if facts.get("hostname") or facts.get("interfaces") or facts.get("overlay") or facts.get("routes"):
            device = l3facts.device_from_facts(facts, name)        # a show-only router capture (SD-WAN, WAN router): no neighbors, but routes and interfaces
            device.capture_gap = capture_gap(text)
            return device, None
        return None, {"file": name, "reason": f"Could not be read: {exc.__class__.__name__}"}
    device = device_from_analysis(result, name)
    try:
        facts = l3switch.merge(facts, l3switch.facts(result))      # NX-OS / AOS-CX routes, OSPF neighbors, ARP and HSRP from the Switch Analyzer's reading
    except Exception:
        pass
    device.l3facts = facts
    if facts.get("interfaces") and not device.l3:
        device.l3 = facts["interfaces"]
    device.capture_gap = capture_gap(text)
    if not device.os_version:
        device.os_version = os_from_text(text)
    if not device.halves and not device.hostname:
        return None, {"file": name, "reason": "No hostname and no neighbors found - is this a device capture?"}
    return device, None


def _merge_f5(files: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """A UCS and the prompted capture of the same BIG-IP become one source (the archive holds the configuration, the capture the live state)."""
    if not any(getattr(text, "bundle", None) is not None for _, text in files):
        return files
    from ..lb_analyzer.bigip_ucs import merge_same_unit
    return merge_same_unit(files)


def read_devices(files: list[tuple[str, str]]) -> tuple[list[Device], list[dict[str, str]]]:
    """Every capture read into a device (copies: the build changes devices, the cache must not see that)."""
    devices: list[Device] = []
    skipped: list[dict[str, str]] = []
    for name, text in _merge_f5(files):
        key = hashlib.sha1(f"{name}\0{text}\0{getattr(text, 'live', '')}".encode("utf-8", "replace")).hexdigest()
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
            if hit is not None:
                _CACHE.move_to_end(key)
        if hit is None:
            hit = _read_one(name, text)
            with _CACHE_LOCK:
                _CACHE[key] = hit
                while len(_CACHE) > CACHE_FILES:
                    _CACHE.popitem(last=False)
        device, reason = hit
        if reason:
            skipped.append(dict(reason))
        if isinstance(device, list):
            devices.extend(copy.deepcopy(device))
        elif device is not None:
            devices.append(copy.deepcopy(device))
    return _drop_replaced_guests(devices), skipped


def _drop_replaced_guests(devices: list[Device]) -> list[Device]:
    """A vCMP guest known only from its host's configuration (name, management address, VLANs) steps aside when the guest's own capture is uploaded too."""
    own = {d.hostname for d in devices if not (d.l3facts.get("f5") or {}).get("vcmp")}
    return [d for d in devices if not ((d.l3facts.get("f5") or {}).get("vcmp") and d.hostname in own)]


def all_views_order(l3_pages: list, l3_extra: list, ip_pages: list, pages: list, twins: list, f5_pages_: list | None = None) -> list:
    """Option "All views": the pages in the order an engineer reads them - L3 over L2, L3 route view, IP view, physical view, vPC view, F5 map.
    A view that has no page (no routed data, no vPC pair, no BIG-IP) is simply absent; the list is never empty because the physical pages always exist."""
    return list(l3_pages) + list(l3_extra) + list(ip_pages) + list(pages) + list(twins) + list(f5_pages_ or [])


def build_topology(files: list[tuple[str, str]], group: str = "none", collapse_endpoints: bool = True,
                   show_ports: bool = True, include_hosts: bool = False, include_routed: bool = True,
                   layout: dict[str, dict[str, tuple[float, float]]] | None = None, line_style: str = "state",
                   view: str = "both", hide_mgmt: bool = True, previous: list[Device] | None = None,
                   collapse_aps: bool | None = None, exclude_endpoints: bool = False, infer_neighbors_from_arp: bool = True,
                   name: str = "", created: _dt.datetime | None = None, provider_hints: str = "", line_shape: str = "angled", show_link_ips: bool = True, overlay_sites: str = "captured", focus_sites: str = "", group_gateways: bool = True, group_endpoints: bool = True) -> dict[str, Any]:
    """``collapse_endpoints`` folds IP phones and hosts into one node per switch; ``collapse_aps`` does the same for access points
    (default: as ``collapse_endpoints``, so older callers keep their picture).  ``exclude_endpoints`` leaves phones, hosts and servers
    out of the pictures altogether so only network devices remain.  ``group_endpoints`` frames the end points of each switch (a box named after the
    switch); it acts only when end points are drawn one by one, that is neither excluded nor collapsed."""
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
        found = infer_neighbors(graph) + assume_f5_neighbors(graph) + assume_pan_ha(graph)
        graph.issues += found
        if found:
            roles.classify(graph)                  # the neighbors named by ARP / descriptions need a role too
    graph.issues += description_drift(graph)
    if include_routed:
        graph.issues += infer_routed(graph)
    if show_link_ips:
        annotate_link_ips(graph)
    fold = {"phone", "host"} if collapse_endpoints else set()
    if collapse_endpoints if collapse_aps is None else collapse_aps:
        fold.add("ap")
    if fold:
        rollup(graph, roles=fold)
    hosts_module.collect(graph, {key: node for key, node in graph.nodes.items() if node.captured})
    graph.hosts += getattr(graph, "f5_hosts", [])
    if include_hosts:
        hosts_module.draw(graph)
    if exclude_endpoints:
        hide_endpoints(graph)
    graph.group_endpoints = bool(group_endpoints and not exclude_endpoints and not collapse_endpoints)
    graph.group_aps = not (collapse_endpoints if collapse_aps is None else collapse_aps)         # access points drawn one by one are framed per switch, whatever the option for the other end points says
    used = auto_mode(graph) if group == "auto" else group          # the grouping that was applied
    curved = line_shape == "curved"
    pages = build_pages(graph, used, layout, curved)
    for page in pages:
        place_labels(page, graph, show_ports)
    twins = logical_pages(graph, pages)
    for page in twins:
        place_labels(page, graph, show_ports)
    ip_pages = [page for page in [ip_page(graph, curved)] if page is not None]
    f5_maps = f5_pages(graph)
    hints = {"rules": parse_hints(provider_hints)}
    focus = Focus.of(overlay_sites, focus_sites)
    want_l3 = view in ("l3route", "l3over2", "all")
    model = build_l3(graph, hints, focus, group_gateways) if want_l3 else None
    route_page = l3_page(graph, hints, curved, model, focus) if want_l3 else None
    over2_pages = l3over2_pages(graph, pages, hints, model, focus) if want_l3 else []
    route_pages = [route_page] if route_page is not None else []
    over2_first = view in ("l3over2", "all")
    l3_pages = over2_pages if over2_first else route_pages                     # the pages the tables, the trace and the draw.io file are built from
    l3_extra = route_pages if over2_first else over2_pages                     # the other L3 view: in the preview, so one build shows both
    l3_links: list[dict[str, Any]] = []
    l3_routes: list[dict[str, Any]] = []
    l3_unresolved: list[dict[str, Any]] = []
    seen_l3: set[str] = set()
    for page in l3_pages:
        fresh = [(ident, edge) for ident, edge in page.l3["all"] if ident not in seen_l3]
        seen_l3.update(ident for ident, _ in fresh)
        names = {**{k: n.hostname for k, n in graph.nodes.items()}, **{k: n.hostname for k, n in page.l3["model"].nodes.items()}}
        l3_links += l3_links_table(fresh, names, page.l3.get("under"))
        l3_routes += l3_routes_table([(i, e) for i, e in fresh if not e.members], names)
        if not l3_unresolved:
            l3_unresolved = l3_unresolved_table(page.l3["model"].unresolved, {k: n.hostname for k, n in graph.nodes.items()})
    l3_overlay = overlay_table(graph, focus) if l3_pages else []
    l3_sites = overlay_sites_table(graph, focus) if l3_pages else []
    l3_trace: dict[str, Any] = {}
    if l3_pages:
        model = l3_pages[0].l3["model"]
        l3_trace = trace_data(graph, model, {id(e): ident for page in l3_pages for ident, e in page.l3["all"]})
    findings = build_findings(graph)
    kept = sum(page.kept for page in pages)
    shown = {"physical": pages, "logical": twins or pages, "both": pages + twins, "ip": ip_pages or pages, "l3route": l3_pages or pages, "l3over2": l3_pages or pages,
             "f5map": f5_maps or pages, "all": all_views_order(l3_pages, l3_extra, ip_pages, pages, twins, f5_maps)}.get(view, pages + twins)
    settings = {"tool_version": _tool_version(), "name": name, "created": (created or _dt.datetime.now()).strftime("%Y-%m-%d %H:%M:%S"), "group": group, "group_used": used, "view": view,
                "line_style": line_style, "line_shape": line_shape, "show_link_ips": show_link_ips, "exclude_endpoints": exclude_endpoints, "collapse_endpoints": collapse_endpoints, "group_endpoints": graph.group_endpoints,
                "collapse_aps": collapse_endpoints if collapse_aps is None else collapse_aps, "show_ports": show_ports,
                "infer_neighbors": infer_neighbors_from_arp, "include_routed": include_routed, "hide_mgmt": hide_mgmt, "include_hosts": include_hosts,
                "previous_state": bool(previous), "keep_layout": bool(layout), "provider_hints": len(parse_hints(provider_hints)), "overlay_sites": focus.mode, "focus_sites": ", ".join(focus.sites), "group_gateways": group_gateways}
    return {
        "settings": settings, "graph": graph, "pages": pages, "logical_pages": twins, "ip_pages": ip_pages, "l3_pages": l3_pages, "l3_links": l3_links, "l3_routes": l3_routes, "l3_unresolved": l3_unresolved, "l3_overlay": l3_overlay, "l3_sites": l3_sites, "l3_trace": l3_trace, "findings": findings, "findings_by_device": findings_by_device(graph, findings), "skipped": skipped,
        "drawio": to_drawio(graph, used, show_ports, shown, line_style, title=name, created=created),
        "svgs": [{"name": page.name, "view": page.view, "svg": to_svg(page, graph, show_ports, line_style)} for page in (shown if view == "all" else pages + twins + ip_pages + l3_pages + l3_extra + f5_maps)],
        "l3_extra_pages": l3_extra,
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
