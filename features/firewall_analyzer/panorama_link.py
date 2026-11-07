"""Which template stack manages a firewall: matching a device's own export to the stacks of a Panorama export.

A Panorama-managed firewall's export holds what is local to it (management, HA, local interfaces) and, unless it is a backup of the local part only, marks
what Panorama pushed.  The export does not carry the firewall's serial number, so the serial of the Panorama's managed-device list cannot be matched
directly.  What both sides do share is names: the interfaces, VLAN interfaces, zones, virtual routers, IKE gateways and tunnels the template defines, and the
names of the templates themselves (``ptpl="<template>"`` on every pushed element).  A name that appears in every stack says nothing; one that appears in a
single stack says a lot - so each shared name counts ``1 / (number of stacks that have it)``, and a template name counts much more.

The result is a *suggestion with its evidence*, never a guess: a firewall is linked only when one stack scores clearly above the others.

References: https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from . import panorama_effective as pe
from .panorama_parse import Panorama

TEMPLATE_WEIGHT = 5.0                    # a pushed element that names a template of the stack
MARGIN = 1.5                             # the best stack must score this many times the second best
MIN_SCORE = 1.0                          # and at least this much, i.e. more than one name that no other stack has

_NAME_PATHS = (
    "network/interface/ethernet/entry", "network/interface/aggregate-ethernet/entry", "network/interface/loopback/units/entry",
    "network/interface/tunnel/units/entry", "network/interface/vlan/units/entry", "network/virtual-router/entry", "network/ike/gateway/entry",
    "network/tunnel/ipsec/entry", "network/tunnel/global-protect-site-to-site/entry", "network/profiles/interface-management-profile/entry",
    "network/profiles/zone-protection-profile/entry", "network/profiles/monitor-profile/entry", "vsys/entry/zone/entry",
)


@dataclass
class Link:
    stack: str = ""                      # "" = not linked
    confidence: str = "none"             # high | medium | none
    score: float = 0.0
    runner_up: float = 0.0
    shared_names: int = 0
    templates: list[str] = field(default_factory=list)      # the stack's templates the device's pushed elements name
    reason: str = ""

    @property
    def linked(self) -> bool:
        return bool(self.stack)


def _entry(root: ET.Element) -> ET.Element | None:
    if root.tag == "entry":                          # a merged template stack is the device entry itself
        return root
    return root.find("devices/entry") if root.tag == "config" else root.find("entry")


def local_names(root: ET.Element) -> set[str]:
    device = _entry(root)
    out: set[str] = set()
    if device is None:
        return out
    for path in _NAME_PATHS:
        for node in device.findall(path):
            name = node.get("name")
            if name and not name.startswith("$"):
                out.add(f"{path.rsplit('/entry', 1)[0].split('/')[-1]}:{name}")
    return out


def pushed_templates(root: ET.Element) -> set[str]:
    return {n.get("ptpl") for n in root.iter() if n.get("ptpl")}


def stack_names(pano: Panorama, stack: str) -> set[str]:
    merged = pe.merged_template(pano, stack)
    return local_names(merged) if merged is not None else set()


def link(pano: Panorama, device_root: ET.Element, *, _cache: dict | None = None) -> Link:
    """The stack that manages the firewall whose export is ``device_root`` (or why none can be named)."""
    cache = _cache if _cache is not None else {}
    stacks = [s for s in pano.stacks.values() if any(d in pano.devices for d in s.devices)]
    if not stacks:
        return Link(reason="the Panorama has no template stack with a managed firewall")
    if "names" not in cache:
        cache["names"] = {s.name: stack_names(pano, s.name) for s in stacks}
    names = cache["names"]
    have: dict[str, int] = {}
    for stack_set in names.values():
        for n in stack_set:
            have[n] = have.get(n, 0) + 1
    mine = local_names(device_root)
    ptpl = pushed_templates(device_root)
    scores: list[tuple[float, str, int, list[str]]] = []
    for s in stacks:
        shared = mine & names[s.name]
        score = sum(1.0 / have[n] for n in shared)
        named = sorted(t for t in ptpl if t in s.templates)
        score += TEMPLATE_WEIGHT * len(named) / max(len(ptpl), 1) if ptpl else 0.0
        scores.append((score, s.name, len(shared), named))
    scores.sort(key=lambda x: (-x[0], x[1]))
    best = scores[0]
    second = scores[1][0] if len(scores) > 1 else 0.0
    if best[0] < MIN_SCORE:
        return Link(score=best[0], runner_up=second, reason="the export shares no distinctive name with any template stack")
    if len(scores) > 1 and best[0] < second * MARGIN:
        return Link(score=best[0], runner_up=second, shared_names=best[2], reason="two or more template stacks match about equally well")
    full = bool(ptpl) and set(best[3]) == ptpl
    return Link(stack=best[1], confidence="high" if (full or best[0] >= 3 * max(second, 0.5)) else "medium", score=round(best[0], 2), runner_up=round(second, 2),
                shared_names=best[2], templates=best[3], reason="")


def panorama_address(pano: Panorama) -> str:
    """The management address of the Panorama itself (what its firewalls list as ``panorama-server``)."""
    return (pano.root.findtext(".//deviceconfig/system/ip-address") or "").strip() if pano.root is not None else ""


def servers_of(device_root: ET.Element) -> set[str]:
    return {(e.text or "").strip() for tag in ("panorama-server", "panorama-server-2") for e in device_root.iter(tag) if (e.text or "").strip()}


def best_link(panoramas: dict[str, Panorama], device_root: ET.Element, caches: dict[str, dict] | None = None) -> tuple[str, Link]:
    """``(panorama name, link)`` over several Panorama exports: the one the firewall points at (its ``panorama-server``) when that is known, otherwise the
    best match, and only when it clearly beats the others."""
    caches = caches if caches is not None else {}
    servers = servers_of(device_root)
    pointed = [n for n, p in panoramas.items() if panorama_address(p) and panorama_address(p) in servers]
    pool = pointed if len(pointed) == 1 else list(panoramas)
    results = [(n, link(panoramas[n], device_root, _cache=caches.setdefault(n, {}))) for n in pool]
    linked = sorted((x for x in results if x[1].linked), key=lambda x: -x[1].score)
    if not linked:
        return (results[0] if results else ("", Link(reason="no Panorama export was given")))
    if len(linked) > 1 and linked[0][1].score < linked[1][1].score * MARGIN:
        return "", Link(score=linked[0][1].score, runner_up=linked[1][1].score, reason="more than one Panorama export matches about equally well")
    name, found = linked[0]
    if len(pointed) == 1 and found.confidence == "medium":
        found.confidence = "high"          # the firewall names this Panorama as its manager
    return name, found
