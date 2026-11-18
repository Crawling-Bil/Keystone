"""The changes since an earlier run, marked on the drawing.

``diff.py`` compares two runs table by table.  This module takes the same two runs (the earlier ``topology.json`` and the tables of the run being built) and marks the result on the new
diagrams, so that a change window can be reviewed on the picture instead of in a list:

* a **new device** has a green ring and a NEW tag, a device with a **changed** role, model, software, address, vPC role or captured state has an amber ring and a CHANGED tag, and a device that
  was **renamed** (the same serial number or management address under another name, ``diff.find_renames``) has an amber ring and a RENAMED tag that says the old name when the mouse rests on it;
* a **new link** (a new cable, or the new end of a re-cabled one) is lit in green, a link whose state, protocols, bundle, speed or duplex changed is lit in amber;
* a link that was in the earlier run and is **gone** between two devices that are still drawn is a red dashed line (a re-cabled link shows the old cable red and the new one green);
* devices that left the network (or were not captured again) cannot be drawn, because the new run has no place for them; a note under the picture lists them.

Nothing is drawn for a run without differences, and the marks change nothing about the layout: the diagram is the same as the one without marks, with a layer on top.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html import escape
from typing import Any

from .diff import DEVICE_FIELDS, LINK_FIELDS, _is_captured, _link_key, _link_view, _text, apply_renames, find_renames

ADDED, CHANGED, REMOVED = "#1B9E4B", "#E08A00", "#D32F2F"
NOTE_H = 64                                  # height of the band under the picture that holds the legend and the list of devices that left


@dataclass
class Marks:
    label: str = "the earlier run"
    devices: dict[str, str] = field(default_factory=dict)                       # host name -> "added" | "changed" | "renamed"
    renamed: dict[str, str] = field(default_factory=dict)                       # new host name -> the name it had in the earlier run
    gone: list[str] = field(default_factory=list)                                # host names of devices that are not in the new run
    links: dict[frozenset, str] = field(default_factory=dict)                   # {host a, host b} -> "added" | "changed"
    removed_links: list[tuple[str, str]] = field(default_factory=list)          # (host a, host b) of a link that is not in the new run

    @property
    def empty(self) -> bool:
        return not (self.devices or self.gone or self.links or self.removed_links)


def collect(before: dict[str, Any], after: dict[str, Any], label: str = "the earlier run") -> Marks:
    """``before`` and ``after`` are runs as ``diff.load_run`` returns them (``devices`` and ``links`` tables)."""
    marks = Marks(label=label)
    renames = find_renames(before.get("devices", []), after.get("devices", []))
    marks.renamed = {new: old_name for old_name, new in renames.items()}
    before = apply_renames(before, renames)
    old = {_text(r.get("device")): r for r in before.get("devices", []) if _text(r.get("device"))}
    new = {_text(r.get("device")): r for r in after.get("devices", []) if _text(r.get("device"))}
    for name, row in new.items():
        was = old.get(name)
        if was is None:
            marks.devices[name] = "added"
        elif _is_captured(was) != _is_captured(row) or any(_text(was.get(f)) != _text(row.get(f)) and (_text(was.get(f)) or f in ("vpc_domain",)) for f in DEVICE_FIELDS):
            marks.devices[name] = "changed"
        if name in marks.renamed:
            marks.devices[name] = "renamed"
    marks.gone = sorted(name for name in old if name not in new)
    before_links = {_link_key(r): _link_view(r) for r in before.get("links", [])}
    after_links = {_link_key(r): _link_view(r) for r in after.get("links", [])}
    for key, view in after_links.items():
        pair = frozenset((key[0][0], key[1][0]))
        was = before_links.get(key)
        if was is None:
            marks.links[pair] = "added"
        elif marks.links.get(pair) != "added" and (any(view[f] != was[f] for f in LINK_FIELDS) or view["first"] != was["first"] or view["second"] != was["second"]):
            marks.links[pair] = "changed"
    for key in before_links:
        if key not in after_links and key[0][0] in new and key[1][0] in new:
            marks.removed_links.append((key[0][0], key[1][0]))
    return marks


def _esc(text: Any) -> str:
    return escape(str(text), quote=True)


def layer(page, graph, marks: Marks, centre: dict[str, tuple[float, float]], node_w: float, node_h: float) -> str:
    """The SVG elements to draw on top of a diagram: rings, lit lines, red dashed lines of removed links and the note band under the picture."""
    out: list[str] = []
    host = {k: graph.nodes[k].hostname for k in page.nodes if k in graph.nodes}
    for index, conn in enumerate(page.connections):
        kind = marks.links.get(frozenset((host.get(conn.a, ""), host.get(conn.b, ""))))
        if not kind or conn.a not in centre or conn.b not in centre:
            continue
        points = " ".join(f"{x:.0f},{y:.0f}" for x, y in [centre[conn.a], *(page.routes.get(index) or []), centre[conn.b]])
        colour = ADDED if kind == "added" else CHANGED
        out.append(f'<polyline class="diff-line diff-{kind}" points="{points}" fill="none" stroke="{colour}" stroke-width="9" stroke-opacity="0.38" stroke-linecap="round" stroke-linejoin="round">'
                   f"<title>{_esc(host.get(conn.a))} - {_esc(host.get(conn.b))}: {'new link' if kind == 'added' else 'link changed'} since {_esc(marks.label)}</title></polyline>")
    by_host = {name: key for key, name in host.items()}
    joined = {frozenset((host.get(c.a, ""), host.get(c.b, ""))) for c in page.connections}
    for a, b in marks.removed_links:
        if a in by_host and b in by_host and by_host[a] in centre and by_host[b] in centre and frozenset((a, b)) not in joined:
            (x1, y1), (x2, y2) = centre[by_host[a]], centre[by_host[b]]
            out.append(f'<line class="diff-line diff-removed" x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="{REMOVED}" stroke-width="3" stroke-dasharray="9 6">'
                       f"<title>{_esc(a)} - {_esc(b)}: link no longer in the new run</title></line>")
    for key, pos in page.nodes.items():
        kind = marks.devices.get(host.get(key, ""))
        if not kind:
            continue
        colour = ADDED if kind == "added" else CHANGED
        tag = "NEW" if kind == "added" else "RENAMED" if kind == "renamed" else "CHANGED"
        was = f"<title>was {_esc(marks.renamed.get(host.get(key, ''), ''))}</title>" if kind == "renamed" else ""
        out.append(f'<g class="diff-device diff-{kind}">{was}<rect x="{pos.x - 6:.0f}" y="{pos.y - 6:.0f}" width="{node_w + 12:.0f}" height="{node_h + 12:.0f}" rx="10" fill="none" stroke="{colour}" stroke-width="4"/>'
                   f'<rect x="{pos.x - 6:.0f}" y="{pos.y - 22:.0f}" width="{9 * len(tag) + 10:.0f}" height="16" rx="3" fill="{colour}"/>'
                   f'<text x="{pos.x - 1:.0f}" y="{pos.y - 10:.0f}" font-size="11" font-weight="700" fill="#fff">{tag}</text></g>')
    return "".join(out)


def band(marks: Marks, x: float, y: float, width: float) -> str:
    """The legend and the note under the picture (``NOTE_H`` high)."""
    gone = ", ".join(marks.gone[:12]) + (f" and {len(marks.gone) - 12} more" if len(marks.gone) > 12 else "")
    parts = [f'<rect x="{x:.0f}" y="{y:.0f}" width="{width:.0f}" height="{NOTE_H - 8}" fill="#FFFFFF" stroke="#C5CED6"/>',
             f'<text x="{x + 12:.0f}" y="{y + 20:.0f}" font-size="12" font-weight="700" fill="#222">Changes since {_esc(marks.label)}</text>']
    cursor = x + 12
    for colour, text, dashed in ((ADDED, "new device / new link", False), (CHANGED, "changed device / link", False), (REMOVED, "link no longer there", True)):
        parts.append(f'<line x1="{cursor:.0f}" y1="{y + 36:.0f}" x2="{cursor + 28:.0f}" y2="{y + 36:.0f}" stroke="{colour}" stroke-width="{3 if dashed else 6}"' + (' stroke-dasharray="7 4"' if dashed else ' stroke-opacity="0.6"') + "/>"
                     f'<text x="{cursor + 34:.0f}" y="{y + 40:.0f}" font-size="11" fill="#333">{text}</text>')
        cursor += 34 + 6.2 * len(text) + 26
    if gone:
        parts.append(f'<text x="{x + 12:.0f}" y="{y + 54:.0f}" font-size="11" fill="{REMOVED}">Not in the new run: {_esc(gone)}</text>')
    return '<g class="diff-note">' + "".join(parts) + "</g>"
