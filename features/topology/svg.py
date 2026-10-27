"""Inline SVG preview of a page (what the browser shows before the .drawio is opened)."""

from __future__ import annotations

from . import labels
from .graph import Graph
from .layout import NODE_H, NODE_W
from .scene import ROW_H, Page, PairBox, Shape, table_columns
from .styles import line_look

_ROLE_GLYPH = {"loadbalancer": "LB", "segment": "NET", "core": "L3", "aggregation": "L3", "access": "L2", "switch": "L2", "firewall": "FW", "router": "RT", "wlc": "WLC",
               "fabric": "FI", "ap": "AP", "phone": "IP", "host": "PC", "server": "SRV", "cloud": "WAN"}


def _rounded_path(points: list[tuple[float, float]], radius: float = 9.0) -> str:
    """An SVG path through the points with every corner rounded by up to ``radius`` px (never more than half of a run)."""
    d = f"M{points[0][0]:.0f},{points[0][1]:.0f}"
    for (px, py), (cx, cy), (nx, ny) in zip(points, points[1:], points[2:]):
        lin, lout = ((cx - px) ** 2 + (cy - py) ** 2) ** 0.5, ((nx - cx) ** 2 + (ny - cy) ** 2) ** 0.5
        r = min(radius, lin / 2, lout / 2)
        if r < 1:
            d += f" L{cx:.0f},{cy:.0f}"
            continue
        d += f" L{cx - (cx - px) / lin * r:.1f},{cy - (cy - py) / lin * r:.1f} Q{cx:.0f},{cy:.0f} {cx + (nx - cx) / lout * r:.1f},{cy + (ny - cy) / lout * r:.1f}"
    return d + f" L{points[-1][0]:.0f},{points[-1][1]:.0f}"


def _fit(text: str, chars: float) -> str:
    """The text cut to ``chars`` characters with an ellipsis (the whole name stays in the tooltip)."""
    limit = max(int(chars), 4)
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


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
    xs += [x for _, x, _, _, _ in page.end_boxes] + [shape.x for shape in page.shapes]
    ys += [y for _, _, y, _, _ in page.end_boxes] + [shape.y for shape in page.shapes]
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


def _clip_box(shape, toward: tuple[float, float]) -> tuple[float, float]:
    """Where a line from the centre of a box towards ``toward`` crosses the border of the box."""
    cx, cy = shape.x + shape.w / 2, shape.y + shape.h / 2
    dx, dy = toward[0] - cx, toward[1] - cy
    if not dx and not dy:
        return cx, cy
    scale = min((shape.w / 2) / abs(dx) if dx else float("inf"), (shape.h / 2) / abs(dy) if dy else float("inf"), 1.0)
    return cx + dx * scale, cy + dy * scale


def _f5_shapes(page: Page) -> tuple[list[str], list[str]]:
    """(lines, boxes) of the F5 map: the lines go under the devices, the boxes (pool frames first) under the lines."""
    from .f5page import style_of
    by_id = {shape.ident: shape for shape in page.shapes}
    centres: dict[str, tuple[float, float, float, float]] = {}
    for shape in page.shapes:
        centres[shape.ident] = (shape.x, shape.y, shape.w, shape.h)
    for key, pos in page.nodes.items():
        centres[f"node:{key}"] = (pos.x, pos.y, NODE_W, NODE_H)

    def centre(ident: str) -> tuple[float, float]:
        x, y, w, h = centres[ident]
        return x + w / 2, y + h / 2

    def edge_point(ident: str, toward: tuple[float, float]) -> tuple[float, float]:
        x, y, w, h = centres[ident]
        box = Shape(ident, "", x, y, w, h)
        return _clip_box(box, toward)

    lines = []
    for edge in page.shape_edges:
        if edge.a not in centres or edge.b not in centres:
            continue
        if edge.points:
            lines.append(f'<polyline points="{" ".join(f"{px:.0f},{py:.0f}" for px, py in edge.points)}" fill="none" stroke="{style_of(edge.status)[1]}" stroke-width="1.5" opacity="0.7"/>')
            continue
        (x1, y1), (x2, y2) = edge_point(edge.a, centre(edge.b)), edge_point(edge.b, centre(edge.a))
        lines.append(f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}" stroke="{style_of(edge.status)[1]}" stroke-width="1.5" opacity="0.7"/>')
    boxes = []
    for shape in sorted(page.shapes, key=lambda s: {"group": 0, "pool": 1}.get(s.kind, 2)):
        fill, border, dashed = style_of(shape.status)
        if shape.kind == "group":
            boxes.append(f'<g class="f5-group"><rect x="{shape.x:.0f}" y="{shape.y:.0f}" width="{shape.w:.0f}" height="{shape.h:.0f}" rx="6" fill="#FBFCFD" stroke="#B8C4CE" stroke-width="1.5" stroke-dasharray="6 4"/>'
                         f'<text x="{shape.x + 10:.0f}" y="{shape.y + 20:.0f}" font-size="12" font-weight="700" fill="#3E4C59">{_esc(shape.lines[0] if shape.lines else "")}</text></g>')
            continue
        dash = ' stroke-dasharray="6 4"' if dashed else ""
        tip = "\n".join(f"{k}: {v}" for k, v in shape.attrs.items() if v)
        radius = 4 if shape.kind == "node" else 8
        boxes.append(f'<g class="f5-{shape.kind}"><title>{_esc(tip)}</title><rect x="{shape.x:.0f}" y="{shape.y:.0f}" width="{shape.w:.0f}" height="{shape.h:.0f}" rx="{radius}" fill="{fill}" stroke="{border}" stroke-width="2"{dash}/>')
        rows = [r for r in shape.lines if r]
        if shape.kind == "pool":
            boxes.append(f'<text x="{shape.x + 9:.0f}" y="{shape.y + 17:.0f}" font-size="12" font-weight="700" fill="#1b1b1b">{_esc(_fit(rows[0], (shape.w - 18) / 7.4) if rows else "")}</text>')
            if len(rows) > 1:
                boxes.append(f'<text x="{shape.x + 9:.0f}" y="{shape.y + 31:.0f}" font-size="9" fill="#52606d">{_esc(_fit(rows[1], (shape.w - 18) / 5.1))}</text>')
        else:
            mid = shape.x + shape.w / 2
            size = 11 if shape.kind == "external" else 10
            limit = shape.w / 6.8
            first = shape.y + shape.h / 2 + (-2 if len(rows) > 1 else 4)
            if rows:
                boxes.append(f'<text x="{mid:.0f}" y="{first:.0f}" font-size="{size}" font-weight="700" text-anchor="middle" fill="#1b1b1b">{_esc(_fit(rows[0], limit))}</text>')
            if len(rows) > 1:
                boxes.append(f'<text x="{mid:.0f}" y="{first + 12:.0f}" font-size="9" text-anchor="middle" fill="#52606d">{_esc(_fit(rows[1], limit * 1.2))}</text>')
        boxes.append("</g>")
    return lines, boxes


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
    for title, x, y, w, h in page.end_boxes:                 # end points grouped under one switch
        out.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" rx="8" fill="#F7F9FB" stroke="#8FA0AE" stroke-width="1.5"><title>End points of {_esc(title)}</title></rect>'
                   f'<text x="{x + 10:.0f}" y="{y + 20:.0f}" font-size="12" font-weight="700" fill="#3E4C59">{_esc(title)}</text>')
    for frame in page.pair_boxes.values():
        out.append(f'<rect x="{frame.x:.0f}" y="{frame.y:.0f}" width="{frame.w:.0f}" height="{frame.h:.0f}" rx="14" fill="#F2F8FC" stroke="#005073" '
                   f'stroke-width="2" stroke-dasharray="8 5"><title>{_esc(frame.title)}</title></rect>'
                   f'<text x="{frame.x + frame.w / 2:.0f}" y="{frame.y + 20:.0f}" font-size="12" font-weight="700" text-anchor="middle" fill="#005073">{_esc(frame.title)}</text>')
    f5_lines, f5_boxes = _f5_shapes(page) if page.shapes else ([], [])
    out.extend(f5_lines)
    out.extend(f5_boxes)
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
        rounded = page.curved and index in page.comb_source        # a comb line on a curved page: straight runs with round corners
        if page.curved and len(route) > 2:                 # a sampled curve: drawn with round joins so it reads as one smooth line
            joins = ' stroke-linejoin="round" stroke-linecap="round"'
        else:
            joins = ""
        if conn.l3.get("id"):                              # L3 pages: the line explains itself in the tooltip and opens the detail panel on click
            ident = _esc(conn.l3.get("id", ""))
            out.append(f'<g class="l3-line" data-l3="{ident}" data-l3-all="{_esc(' '.join(conn.l3.get('carries', [])) or ident)}" tabindex="0" role="button" aria-label="{_esc(conn.l3.get('meaning', ''))}" style="cursor:pointer"><polyline points="{points}" fill="none" stroke="transparent" stroke-width="14"/>'
                       f'<polyline points="{points}" fill="none" stroke="{colour}" stroke-width="{wide:g}"{dash}{joins}>'
                       f"<title>{ident}: {_esc(conn.l3.get('meaning', ''))}</title></polyline></g>")
        else:
            shape = f'<path d="{_rounded_path([(x1, y1), *route, (x2, y2)])}"' if rounded else f'<polyline points="{points}"'
            end = "path" if rounded else "polyline"
            out.append(f'{shape} fill="none" stroke="{colour}" stroke-width="{wide:g}"{dash}{joins}>'
                       f"<title>{_esc(_name(page, conn.a))} - {_esc(_name(page, conn.b))}: {_esc(tip)} ({conn.state})</title></{end}>")
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
            rows = labels.wrap_centre(mid)
            top = ly + 3.5 - (len(rows) - 1) * 5.5
            out.append(f'<text x="{lx:.0f}" y="{top:.1f}" font-size="10" font-weight="700" text-anchor="middle" '
                       f'paint-order="stroke" stroke="#fff" stroke-width="4" fill="#005073">'
                       + "".join(f'<tspan x="{lx:.0f}" dy="{0 if i == 0 else 11}">{_esc(row)}</tspan>' for i, row in enumerate(rows)) + '</text>')
    for key, pos in page.nodes.items():
        node = graph.nodes[key]
        ghost = key in page.ghosts or not node.captured
        fill, stroke = ("#E6E6E6", "#7F7F7F") if ghost else ("#FAFAFA", "#005073")
        if node.role_hint == "segment":
            fill, stroke = "#FFF6DD", "#C58F00"
            shape = f'<ellipse cx="{pos.x + NODE_W / 2:.0f}" cy="{pos.y + NODE_H / 2:.0f}" rx="{NODE_W / 2 + 10}" ry="{NODE_H / 2 - 12}" fill="{fill}" stroke="{stroke}" stroke-width="3"/>'
        elif node.role_hint == "cloud":
            shape = (f'<path d="M25,52 a14,14 0 0 1 -1,-27 a18,18 0 0 1 35,-9 a17,17 0 0 1 31,9 a13,13 0 0 1 -3,27 z" transform="translate({pos.x - 22:.0f},{pos.y - 10:.0f}) scale({(NODE_W + 44) / 100:.3f},{(NODE_H + 20) / 62:.3f})" '
                     f'fill="{fill}" stroke="{stroke}" stroke-width="3" vector-effect="non-scaling-stroke"/>')
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
