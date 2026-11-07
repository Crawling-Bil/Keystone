"""Firewall Analyzer: a Panorama export analyzed together with the exports of the firewalls it manages.

Each managed firewall is matched to its template stack (:mod:`panorama_link`) and analyzed as it really runs - the stack's interfaces, zones and routing, the
firewall's own export on top, and the rules and objects of the stack's device group in evaluation order - by the same analyzer that reads a standalone
PAN-OS firewall.  The Panorama's own report lists which uploaded firewall went with which stack and device group.

The hook is ``AnalyzerSpec.merge_sources``: it receives every upload and returns the same list, with the content of a matched firewall replaced by a
:class:`Fused` text (a ``str`` that carries what was matched).  :func:`decorate` then adds that to the result of the ordinary analysis.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any

from ..analyzer_core.findings import finding
from ..analyzer_core.result import kv_section, table_section
from . import panorama_effective as pe
from . import panorama_link as pl
from . import panorama_parse as pp

DOC_STACK = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack"
DOC_GROUPS = "https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups"


class Fused(str):
    """The text analyzed in place of an upload, with what was matched (``role`` is ``device`` or ``panorama``)."""

    role: str = ""
    info: dict[str, Any]


def _fused(text: str, role: str, info: dict[str, Any]) -> Fused:
    out = Fused(text)
    out.role, out.info = role, info
    return out


def device_group_of(pano: pp.Panorama, stack: str) -> tuple[str, list[str], list[str]]:
    """``(device group, other candidates, serials)`` for a template stack: the group most of its managed firewalls belong to."""
    st = pano.stacks.get(stack)
    serials = [s for s in (st.devices if st else []) if s in pano.devices]
    counts = Counter(pano.devices[s].device_group for s in serials if pano.devices[s].device_group)
    if not counts:
        return "", [], serials
    ranked = [g for g, _ in counts.most_common()]
    return ranked[0], ranked[1:], serials


def _pan_device(text: Any) -> ET.Element | None:
    if not isinstance(text, str) or not text.lstrip().startswith("<"):
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    return root if root.tag == "config" and root.find("devices/entry") is not None and root.find("devices/entry/template-stack") is None else None


def merge_sources(sources: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    """The hook: matched firewalls become :class:`Fused` texts, the Panorama(s) get the list of what went with them.  The list keeps the upload order."""
    panoramas: dict[int, pp.Panorama] = {}
    for i, (name, text) in enumerate(sources):
        if isinstance(text, str) and "<template-stack" in text and pp.looks_like_panorama(text):
            try:
                panoramas[i] = pp.parse(text)
            except ValueError:
                continue
    if not panoramas:
        return sources
    labels = {i: sources[i][0] if sum(1 for n, _ in sources if n == sources[i][0]) == 1 else f"{sources[i][0]} (#{i + 1})" for i in panoramas}
    by_label = {labels[i]: panoramas[i] for i in panoramas}
    caches: dict[str, dict] = {}
    rows: dict[int, list[dict[str, Any]]] = {i: [] for i in panoramas}
    unmatched: list[dict[str, Any]] = []
    out: list[tuple[str, Any]] = list(sources)
    label_to_index = {label: i for i, label in labels.items()}
    for i, (name, text) in enumerate(sources):
        if i in panoramas:
            continue
        root = _pan_device(text)
        if root is None:
            continue
        pano_label, found = pl.best_link(by_label, root, caches)
        if not found.linked:
            if pl.servers_of(root) or pl.pushed_templates(root):
                unmatched.append({"file": name, "reason": found.reason})
                out[i] = (name, _fused(text, "device", {"linked": False, "reason": found.reason}))
            continue
        pano = by_label[pano_label]
        group, others, serials = device_group_of(pano, found.stack)
        try:
            xml, eff = pe.build_standalone(pano, group, stack=found.stack, local=root, serials=serials)
        except Exception as exc:        # a firewall whose stack cannot be built is still analyzed from its own export
            reason = f"the stack could not be merged ({type(exc).__name__})"
            unmatched.append({"file": name, "reason": reason})
            out[i] = (name, _fused(text, "device", {"linked": False, "reason": reason}))
            continue
        info = {"linked": True, "panorama": pano_label, "stack": found.stack, "group": group, "other_groups": others, "confidence": found.confidence,
                "templates": found.templates, "shared_names": found.shared_names, "score": found.score, "rules": sum(len(v) for v in eff.rules.values()),
                "skipped_by_target": eff.skipped_by_target, "notes": list(eff.notes), "serials": len(serials)}
        rows[label_to_index[pano_label]].append({"file": name, "stack": found.stack, "group": group, "confidence": found.confidence})
        out[i] = (name, _fused(xml, "device", info))
    for i in panoramas:
        out[i] = (sources[i][0], _fused(sources[i][1], "panorama", {"matched": rows[i], "unmatched": unmatched, "stacks": len(panoramas[i].stacks)}))
    return out


def decorate(result: dict[str, Any], content: Any) -> dict[str, Any]:
    """Add what was matched to the result of the ordinary analysis of ``content``."""
    role = getattr(content, "role", "")
    info = getattr(content, "info", None)
    if not role or not info:
        return result
    sections = result.setdefault("sections", [])
    findings = result.setdefault("findings", [])
    warnings = result.setdefault("warnings", [])
    if role == "device":
        result["panorama_link"] = {k: v for k, v in info.items() if k != "notes"}
        if info.get("linked"):
            result["warnings"] = [w for w in warnings if "managed by Panorama" not in w]
            rows = [("Panorama export", info["panorama"]), ("Template stack", info["stack"]), ("Device group", info["group"] or "none found"),
                    ("Match", f"{info['confidence']} (score {info['score']}; {info['shared_names']} shared name(s), {len(info['templates'])} pushed template name(s))"),
                    ("Rules applied", f"{info['rules']} (rules pushed only to other firewalls of the stack: {info['skipped_by_target']} left out)")]
            sections.insert(0, kv_section("panorama_link", "Panorama management", rows, group="Panorama"))
            findings.append(finding("PANO-LINK-001", "info", "Panorama", "Analyzed as Panorama template stack + device group + the firewall's own export",
                                    obj=f"{info['stack']} / {info['group'] or 'no device group'}",
                                    detail=("The interfaces, zones and routing come from the template stack, the policy and objects from the device group, and the management settings from the "
                                            "firewall's own export. The firewall's export has no serial number, so the match is by shared names and pushed template names"
                                            + (f"; device groups of other firewalls of this stack: {', '.join(info['other_groups'])}" if info.get("other_groups") else "") + "."),
                                    recommendation="Check the stack and device group above against Device > Managed devices on the Panorama." if info["confidence"] != "high"
                                    else "Confirm against Device > Managed devices on the Panorama if the stack is shared by several device groups.",
                                    reference=DOC_STACK))
            for note in info.get("notes", [])[:6]:
                warnings.append(note)
        else:
            warnings.append(f"This firewall is managed by Panorama but could not be matched to a template stack of the uploaded Panorama ({info.get('reason') or 'no evidence'}); "
                            "it is analyzed from its own export only, which has no policy.")
    elif role == "panorama":
        matched, unmatched = info.get("matched", []), info.get("unmatched", [])
        if matched or unmatched:
            rows = [{"file": m["file"], "stack": m["stack"], "group": m["group"] or "none", "confidence": m["confidence"], "status": "analyzed with its stack and device group"} for m in matched]
            rows += [{"file": u["file"], "stack": "", "group": "", "confidence": "", "status": "not matched: " + (u["reason"] or "no evidence")} for u in unmatched]
            sections.append(table_section("pano_fused", "Managed firewalls analyzed with this Panorama",
                                          [("file", "Uploaded file", "mono"), ("stack", "Template stack"), ("group", "Device group"), ("confidence", "Match"), ("status", "Result")],
                                          rows, group="Panorama"))
            result["panorama_fusion"] = {"matched": len(matched), "unmatched": len(unmatched)}
    return result
