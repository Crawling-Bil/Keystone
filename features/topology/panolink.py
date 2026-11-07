"""A Panorama export together with the exports of the firewalls it manages.

A managed firewall's own export holds only what is local to it; the interfaces, zones, routing and IPsec a template stack pushes are in the Panorama export,
and the addresses of the interfaces are often names of Shared address objects.  When both kinds of file are uploaded, each firewall is matched to its
template stack (:mod:`features.firewall_analyzer.panorama_link`), the firewall is read as *the stack plus its own export*, and the stack's own node (drawn
from the Panorama alone) steps aside because the real units are on the picture.  A firewall that cannot be matched with confidence is drawn from its own
export, as before, and TOPO-044 says why.

Credentials never leave the Panorama or the firewall exports: the merged configuration is built with every credential leaf removed.
"""

from __future__ import annotations

import hashlib
import threading
import xml.etree.ElementTree as ET
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

_PARSED: "OrderedDict[str, Any]" = OrderedDict()
_LOCK = threading.Lock()


@dataclass
class LinkInfo:
    panoramas: dict[str, str] = field(default_factory=dict)                 # file name -> parsed key
    linked: dict[str, dict[str, Any]] = field(default_factory=dict)         # firewall file -> link facts
    unlinked: dict[str, dict[str, Any]] = field(default_factory=dict)       # managed firewall file -> why not
    linked_stacks: dict[str, set[str]] = field(default_factory=dict)        # Panorama file -> stacks that have a real unit on the picture


def _parsed(text: str):
    from ..firewall_analyzer import panorama_parse as pp
    key = hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()
    with _LOCK:
        hit = _PARSED.get(key)
        if hit is not None:
            _PARSED.move_to_end(key)
            return hit
    pano = pp.parse(text)
    with _LOCK:
        _PARSED[key] = pano
        while len(_PARSED) > 2:
            _PARSED.popitem(last=False)
    return pano


def _xml_root(text: str) -> ET.Element | None:
    head = text.lstrip()[:400]
    if not head.startswith("<"):
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    return root if root.tag == "config" and root.find("devices/entry") is not None else None


def _managed(root: ET.Element) -> bool:
    return any(True for _ in root.iter("panorama-server")) or any(n.get("ptpl") for n in root.iter())


def link_files(files: list[tuple[str, Any]]) -> tuple[list[tuple[str, Any]], LinkInfo]:
    """``files`` with each linked firewall's text replaced by its merged configuration, and what was linked."""
    from ..firewall_analyzer import panorama_effective as pe
    from ..firewall_analyzer import panorama_link as pl
    from ..firewall_analyzer import panorama_parse as pp
    info = LinkInfo()
    panoramas = {}
    for name, text in files:
        if isinstance(text, str) and "<template-stack" in text and pp.looks_like_panorama(text):
            try:
                panoramas[name] = _parsed(text)
            except ValueError:
                continue
    if not panoramas:
        return files, info
    info.panoramas = {n: n for n in panoramas}
    caches: dict[str, dict] = {}
    out: list[tuple[str, Any]] = []
    for name, text in files:
        root = _xml_root(text) if isinstance(text, str) and name not in panoramas else None
        if root is None:
            out.append((name, text))
            continue
        pano_name, found = pl.best_link(panoramas, root, caches)
        if not found.linked:
            if _managed(root):
                info.unlinked[name] = {"reason": found.reason or "no evidence ties it to a template stack", "score": found.score}
            out.append((name, text))
            continue
        merged = pe.merge_device(panoramas[pano_name], found.stack, root, [])
        if not merged:
            out.append((name, text))
            continue
        info.linked[name] = {"panorama": pano_name, "stack": found.stack, "confidence": found.confidence, "score": found.score,
                             "templates": found.templates, "shared_names": found.shared_names}
        info.linked_stacks.setdefault(pano_name, set()).add(found.stack)
        out.append((name, merged))
    return out, info


def apply(devices: list, info: LinkInfo) -> list:
    """Mark the linked firewalls and drop the stack nodes that real units replace."""
    kept = []
    for device in devices:
        facts = device.l3facts if isinstance(device.l3facts, dict) else {}
        stack = facts.get("panorama_stack")
        if stack and stack in info.linked_stacks.get(device.source, set()):
            continue
        if device.source in info.linked:
            facts["panorama_link"] = dict(info.linked[device.source])
            device.l3facts = facts
        elif device.source in info.unlinked:
            facts["panorama_link"] = dict(info.unlinked[device.source], panorama="")
            device.l3facts = facts
        kept.append(device)
    return kept


def panorama_findings(graph) -> list[dict[str, Any]]:
    """TOPO-044: which firewalls were read together with the template stack of a Panorama, and which managed firewalls could not be matched."""
    from .findings import _few, _row
    linked: list[str] = []
    stacks: dict[str, int] = {}
    unlinked: list[tuple[str, str]] = []
    medium: list[str] = []
    for node in graph.nodes.values():
        facts = (node.l3facts or {}).get("panorama_link")
        if not facts:
            continue
        if facts.get("panorama"):
            linked.append(node.hostname)
            stacks[facts["stack"]] = stacks.get(facts["stack"], 0) + 1
            if facts.get("confidence") != "high":
                medium.append(node.hostname)
        else:
            unlinked.append((node.hostname, facts.get("reason", "")))
    rows: list[dict[str, Any]] = []
    doc = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"
    if linked:
        rows.append(_row("TOPO-044", "info", f"{len(linked)} firewall(s) read together with the template stack of the Panorama that manages them",
                         f"{len(stacks)} stack(s); the interfaces, zones, routing and tunnels of the stack are part of these nodes. " + _few(sorted(linked), 6), sorted(linked),
                         "The match comes from the names of the pushed templates and of the interfaces, zones and routers both files share (the export has no serial number). "
                         "Check it" + (f" for {_few(sorted(medium), 4)}, where the evidence is thinner." if medium else " against the Panorama's managed-device list."), doc))
    if unlinked:
        rows.append(_row("TOPO-044", "low", f"{len(unlinked)} firewall(s) are managed by Panorama but could not be matched to a template stack",
                         _few(sorted(f"{h} ({r})" for h, r in unlinked), 4), sorted(h for h, _ in unlinked),
                         "These are drawn from their own export, which has no interface addresses, zones or routing of the template. Upload the Panorama export that manages them, or a full running-configuration export of the firewall.", doc))
    return rows
