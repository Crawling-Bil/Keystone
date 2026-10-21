"""Inline SVG preview of a page (what the browser shows before the .drawio is opened)."""

from __future__ import annotations

from . import labels
from .graph import Graph
from .layout import NODE_H, NODE_W
from .scene import ROW_H, Page, PairBox, table_columns
from .styles import line_look

_ROLE_GLYPH = {"loadbalancer": "LB", "segment": "NET", "core": "L3", "aggregation": "L3", "access": "L2", "switch": "L2", "firewall": "FW", "router": "RT", "wlc": "WLC",
               "fabric": "FI", "ap": "AP", "phone": "IP", "host": "PC", "server": "SRV", "cloud": "WAN"}


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _name(page: Page, key: str) -> str:
    frame = page.pair_boxes.get(key)
    return frame.title if frame else key


def _clip(box: PairBox, toward: tuple[float, float]) -> tuple[float, float]:
    """Where a line from the centre of a frame towards ``toward`` crosses the frame's border."""
    cx, cy = box.centre
    dx, dy = toward[0] - cx, toward[1] - cy
    if not dx and not dy:
        return cx, cy
    scale = min((box.w / 2) / abs(dx) if dx else float("inf"), (box.h / 2) / abs(dy) if dy else float("inf"))
    return cx + dx * scale, cy + dy * scale


def _origin(page: Page) -> tuple[float, float]:
    """Top-left corner of the picture: a bent line may leave the page on the left or top, and a viewBox that starts at 0 would cut it."""
    xs = [x for points in page.routes.values() for x, _ in points] + [p.x for p in page.nodes.values()] + [v[0] - 40 for v in page.label_pos.values()]
    ys = [y for points in page.routes.values() for _, y in points] + [p.y for p in page.nodes.values()] + [v[1] - 20 for v in page.label_pos.values()]
    return min(0.0, min(xs, default=0.0) - 30), min(0.0, min(ys, default=0.0) - 30)


def _tables(page: Page) -> list[str]:
    out: list[str] = []
    for table in page.tables:
        out.append(f'<g><rect x="{table.x:.0f}" y="{table.y:.0f}" width="{table.w:.0f}" height="{table.h:.0f}" fill="#fff" stroke="#9aa7b2"/>'
                   f'<rect x="{table.x:.0f}" y="{table.y:.0f}" width="{table.w:.0f}" height="22" fill="#005073"/>'
                   f'<text x="{table.x + 8:.0f}" y="{table.y + 15:.0f}" font-size="12" font-weight="700" fill="#fff">{_esc(table.title)}</text>')
        widths = table_columns(table)
        cx = table.x + 6
        for name, w in zip(table.header, widths):
            out.append(f'<text x="{cx:.0f}" y="{table.y + 37:.0f}" font-size="10" font-weight="700" fill="#555">{_esc(name)}</text>')
            cx += w
        for r, row in enumerate(table.rows):
            ry = table.y + 52 + r * ROW_H
            if r % 2:
                out.append(f'<rect x="{table.x + 1:.0f}" y="{ry - 11:.0f}" width="{table.w - 2:.0f}" height="{ROW_H}" fill="#F3F6F9"/>')
            cx = table.x + 6
            for cell, w in zip(row, widths):
                out.append(f'<text x="{cx:.0f}" y="{ry:.0f}" font-size="10" fill="#222">{_esc(cell[:int(w / 5.6)])}</text>')
                cx += w
        out.append("</g>")
    return out


def to_svg(page: Page, graph: Graph, show_ports: bool = True, line_style: str = "state") -> str:
    graph = page.graph or graph
    width, height = max(page.width + 40, 600), max(page.height + 40, 400)
    left, top = _origin(page)
    width, height = width - left, height - top
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{left:.0f} {top:.0f} {width:.0f} {height:.0f}" class="topology-svg" role="img" '
           f'aria-label="Network topology, page {_esc(page.name)}" font-family="Helvetica, Arial, sans-serif">']
    for title, x, y, w, h in page.boxes:
        out.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" fill="none" stroke="#000000" stroke-width="2"/>'
                   f'<text x="{x + 12:.0f}" y="{y + 26:.0f}" font-size="16" font-weight="700" fill="#8a5a50">{_esc(title)}</text>')
    for frame in page.pair_boxes.values():
        out.append(f'<rect x="{frame.x:.0f}" y="{frame.y:.0f}" width="{frame.w:.0f}" height="{frame.h:.0f}" rx="14" fill="#F2F8FC" stroke="#005073" '
                   f'stroke-width="2" stroke-dasharray="8 5"><title>{_esc(frame.title)}</title></rect>'
                   f'<text x="{frame.x + frame.w / 2:.0f}" y="{frame.y + 20:.0f}" font-size="12" font-weight="700" text-anchor="middle" fill="#005073">{_esc(frame.title)}</text>')
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    centre.update({k: frame.centre for k, frame in page.pair_boxes.items()})
    for index, conn in enumerate(page.connections):
        (x1, y1), (x2, y2) = centre[conn.a], centre[conn.b]
        route = page.routes.get(index) or []
        if conn.a in page.pair_boxes:                      # a line to a frame starts on its border, not at its centre
            x1, y1 = _clip(page.pair_boxes[conn.a], route[0] if route else (x2, y2))
        if conn.b in page.pair_boxes:
            x2, y2 = _clip(page.pair_boxes[conn.b], route[-1] if route else (x1, y1))
        colour, wide, dashed = line_look(graph, conn, line_style)
        dash = ' stroke-dasharray="7 5"' if dashed and conn.kind != "host" else ' stroke-dasharray="2 4"' if conn.kind == "host" else ""
        tip = "; ".join(f"{l.a_port} - {l.b_port}" for l in conn.links)
        speed = labels.speed_summary(graph, conn)
        if speed:
            tip += f" [{speed}]"
        points = " ".join(f"{px:.0f},{py:.0f}" for px, py in [(x1, y1), *route, (x2, y2)])
        out.append(f'<polyline points="{points}" fill="none" stroke="{colour}" stroke-width="{wide:g}"{dash}>'
                   f"<title>{_esc(_name(page, conn.a))} - {_esc(_name(page, conn.b))}: {_esc(tip)} ({conn.state})</title></polyline>")
        if route:                                        # place the labels along the first and last segment
            (mx, my) = route[0]
        else:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        a_text, b_text = labels.end_texts(conn)
        mid = labels.center_text(conn, graph)
        if show_ports and not (page.view == "logical" and conn.kind == "peer-link"):
            first = route[0] if route else (x2, y2)
            last = route[-1] if route else (x1, y1)
            for slot, text, (px, py), (qx, qy), t in (("a", a_text, (x1, y1), first, 0.22), ("b", b_text, (x2, y2), last, 0.22)):
                if text:
                    lx, ly = (page.label_pos[(index, slot)][:2] if (index, slot) in page.label_pos else (px + (qx - px) * t, py + (qy - py) * t))
                    out.append(f'<text x="{lx:.0f}" y="{ly + 3.5:.0f}" font-size="10" text-anchor="middle" '
                               f'paint-order="stroke" stroke="#fff" stroke-width="4" fill="#333">{_esc(text)}</text>')
        if mid:
            lx, ly = page.label_pos[(index, "mid")][:2] if (index, "mid") in page.label_pos else (mx, my)
            out.append(f'<text x="{lx:.0f}" y="{ly + 3.5:.0f}" font-size="10" font-weight="700" text-anchor="middle" '
                       f'paint-order="stroke" stroke="#fff" stroke-width="4" fill="#005073">{_esc(mid)}</text>')
    for key, pos in page.nodes.items():
        node = graph.nodes[key]
        ghost = key in page.ghosts or not node.captured
        fill, stroke = ("#E6E6E6", "#7F7F7F") if ghost else ("#FAFAFA", "#005073")
        if node.role_hint == "segment":
            fill, stroke = "#FFF6DD", "#C58F00"
            shape = f'<ellipse cx="{pos.x + NODE_W / 2:.0f}" cy="{pos.y + NODE_H / 2:.0f}" rx="{NODE_W / 2 + 10}" ry="{NODE_H / 2 - 12}" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        else:
            shape = f'<rect x="{pos.x:.0f}" y="{pos.y:.0f}" width="{NODE_W}" height="{NODE_H}" rx="6" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        out.append(f'<g><title>{_esc(node.hostname)} {_esc(node.model)} {_esc(node.mgmt_ip)}</title>' + shape +
                   f'<text x="{pos.x + NODE_W / 2:.0f}" y="{pos.y + NODE_H / 2 + 5:.0f}" font-size="15" font-weight="700" text-anchor="middle" fill="{stroke}">{_ROLE_GLYPH.get(node.role_hint, "?")}</text>')
        lines = [l for l in labels.node_lines(node) if l]
        for i, line in enumerate(lines):
            colour = ("#d90000" if node.captured and not ghost else "#7f7f7f") if i == 0 else ("#004a75" if i == 1 else "#222")
            out.append(f'<text x="{pos.x + NODE_W / 2:.0f}" y="{pos.y + NODE_H + 16 + 14 * i:.0f}" font-size="12" font-weight="700" text-anchor="middle" paint-order="stroke" stroke="#fff" stroke-width="4" stroke-linejoin="round" fill="{colour}">{_esc(line[:34])}</text>')
        out.append("</g>")
    out.extend(_tables(page))
    out.append("</svg>")
    return "".join(out)
