"""The logical (vPC / MLAG) view: a pair of switches is one frame and a bundle that spans the pair is one line.

The physical view draws every cable. A reviewer reading a data-centre design wants "aggregation pair <-> access pair,
vPC 101, 4x10G", so this view puts a frame around each vPC pair and replaces the bundles that reach both members of a
pair by a single line. Device positions are those of the physical page, so a hand-tuned layout carries over.

Concept reference: https://www.cisco.com/c/it_it/support/docs/switches/nexus-9000-series-switches/218333-understand-and-configure-nexus-9000-vpc.html
"""

from __future__ import annotations

import copy

from .graph import Connection, Graph, Link
from .layout import NODE_H, NODE_W
from .scene import Page, PairBox, _route

FRAME_SIDE = 26          # room left and right of the two icons
FRAME_TOP = 38           # room for the frame title
FRAME_BOTTOM = 62        # room for the three label lines under the icons
VIEW_SUFFIX = " (vPC view)"


def pair_key(domain: str, a: str, b: str) -> str:
    first, second = sorted((a, b))
    return f"vpc:{domain}:{first}|{second}"


def _frames(graph: Graph, page: Page) -> dict[str, PairBox]:
    frames: dict[str, PairBox] = {}
    seen: set[frozenset] = set()
    for a, b, domain in graph.vpc_pairs:
        if frozenset((a, b)) in seen or a not in page.nodes or b not in page.nodes:
            continue
        seen.add(frozenset((a, b)))
        pa, pb = page.nodes[a], page.nodes[b]
        if abs(pa.y - pb.y) > 1:
            continue                                      # the two switches sit on different rows: no frame, physical lines
        x0, x1 = min(pa.x, pb.x) - FRAME_SIDE, max(pa.x, pb.x) + NODE_W + FRAME_SIDE
        y0, y1 = pa.y - FRAME_TOP, pa.y + NODE_H + FRAME_BOTTOM
        crowded = any(key not in (a, b) and x0 < p.x + NODE_W / 2 < x1 and y0 < p.y + NODE_H / 2 < y1 for key, p in page.nodes.items())
        if crowded:
            continue                                      # another device was dragged between the pair: keep the physical lines
        members = tuple(sorted((a, b)))
        key = pair_key(domain, a, b)
        frames[key] = PairBox(key, f"vPC domain {domain}", members, x0, y0, x1 - x0, y1 - y0)
    return frames


def _oriented(link: Link, swap: bool) -> Link:
    clone = copy.copy(link)
    clone.protocols = set(link.protocols)
    if swap:
        clone.swap()
    return clone


def _collapse(graph: Graph, page: Page, frames: dict[str, PairBox]) -> list[Connection]:
    frame_of = {member: key for key, frame in frames.items() for member in frame.members}
    groups: dict[tuple, list[Connection]] = {}
    kept: list[Connection] = []
    for conn in page.connections:
        end_a, end_b = frame_of.get(conn.a, conn.a), frame_of.get(conn.b, conn.b)
        ident = conn.vpc_id or ",".join(sorted({po for po in (conn.a_po, conn.b_po) if po}))
        touches_frame = end_a in frames or end_b in frames
        if conn.kind in ("peer-link", "rollup", "host", "routed") or end_a == end_b or not touches_frame or not ident:
            kept.append(conn)
            continue
        first, second = sorted((end_a, end_b))
        groups.setdefault((first, second, ident), []).append(conn)
    merged: list[Connection] = []
    for (first, second, ident), conns in groups.items():
        # a frame side only counts when the bundle reaches both of its switches
        complete = True
        for side, end in ((0, first), (1, second)):
            if end in frames:
                touched = {c.a if frame_of.get(c.a, c.a) == end else c.b for c in conns}
                complete = complete and touched == set(frames[end].members)
        if not complete:
            kept.extend(conns)
            continue
        links: list[Link] = []
        a_pos: set[str] = set()
        b_pos: set[str] = set()
        for conn in conns:
            forward = frame_of.get(conn.a, conn.a) == first
            links.extend(_oriented(link, not forward) for link in conn.links)
            first_po, second_po = (conn.a_po, conn.b_po) if forward else (conn.b_po, conn.a_po)
            a_pos.add(first_po)
            b_pos.add(second_po)
        vpc_id = next((c.vpc_id for c in conns if c.vpc_id), "")
        merged.append(Connection(first, second, links, "/".join(sorted(p for p in a_pos if p)), "/".join(sorted(p for p in b_pos if p)),
                                 kind="vpc", vpc_id=vpc_id, multi_chassis=True))
    return kept + merged


def logical_page(graph: Graph, page: Page) -> Page | None:
    """The logical twin of a physical page, or None when the page holds no vPC pair to collapse."""
    frames = _frames(graph, page)
    if not frames:
        return None
    clone = Page(page.name + VIEW_SUFFIX, dict(page.nodes), set(page.ghosts), list(page.boxes), [], {}, page.width, page.height, page.kept,
                 pair_boxes=frames, view="logical", curved=page.curved)
    clone.end_boxes = list(page.end_boxes)
    clone.connections = _collapse(graph, page, frames)
    if len(clone.connections) == len(page.connections):
        return None                                           # nothing collapsed: the physical page already says it all
    _route(clone)
    return clone


def logical_pages(graph: Graph, pages: list[Page]) -> list[Page]:
    return [twin for twin in (logical_page(graph, page) for page in pages) if twin is not None]
