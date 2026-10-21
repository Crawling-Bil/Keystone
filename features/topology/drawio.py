"""draw.io (diagrams.net) writer: uncompressed mxfile, the icon, label and line style of the reference diagrams.

Format reference: https://www.drawio.com/doc/faq/drawio-style-reference
"""

from __future__ import annotations

import datetime as _dt
import re
from xml.etree import ElementTree as ET

from . import labels
from .graph import Connection, Graph
from .layout import NODE_H, NODE_W
from .scene import Page, build_pages
from .styles import SPEED_TIERS, line_look

ICON_POINTS = ("points=[[0.015,0.015,0],[0.985,0.015,0],[0.985,0.985,0],[0.015,0.985,0],[0.25,0,0],[0.5,0,0],[0.75,0,0],"
               "[1,0.25,0],[1,0.5,0],[1,0.75,0],[0.75,1,0],[0.5,1,0],[0.25,1,0],[0,0.75,0],[0,0.5,0],[0,0.25,0]];")
LABEL_STYLE = "verticalLabelPosition=bottom;html=1;verticalAlign=top;align=center;pointerEvents=1;whiteSpace=wrap;fontSize=11;"
RECT_ICONS = {"l2_switch", "l3_switch", "firewall", "router", "wireless_lan_controller", "server", "load_balancer"}
LINE_STYLE = "edgeStyle=none;rounded=0;html=1;endArrow=none;endFill=0;"
STATE_STYLE = {
    "confirmed": "strokeColor=#1f1f1f;strokeWidth=2;",
    "single": "strokeColor=#ED7D31;strokeWidth=2;dashed=1;",
    "conflict": "strokeColor=#FF0000;strokeWidth=3;dashed=1;",
    "inferred": "strokeColor=#0070c0;strokeWidth=2;dashed=1;",
}
PEER_LINK_STYLE = "strokeColor=#0070c0;strokeWidth=4;"
ROUTED_STYLE = "strokeColor=#0070c0;strokeWidth=2;dashed=1;"
HOST_STYLE = "strokeColor=#999999;strokeWidth=1;dashed=1;dashPattern=1 3;"
END_LABEL = "edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=9;labelBackgroundColor=#ffffff;"
MID_LABEL = "edgeLabel;html=1;align=center;verticalAlign=middle;resizable=0;points=[];fontSize=10;fontStyle=1;labelBackgroundColor=#ffffff;"

ICON_FROM_ROLE = {"loadbalancer": "load_balancer", "core": "l3_switch", "aggregation": "l3_switch", "access": "l2_switch", "switch": "l2_switch",
                  "firewall": "firewall", "router": "router", "wlc": "wireless_lan_controller", "server": "server", "fabric": "l2_switch"}


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _label(node, ghost: bool) -> str:
    host, model, ip = labels.node_lines(node)
    host_colour = "#d90000" if node.captured and not ghost else "#7f7f7f"
    lines = [f'<font color="{host_colour}"><b>{_esc(host)}</b></font>']
    if model:
        lines.append(f'<font color="#004a75"><b>{_esc(model)}</b></font>')
    if ip:
        lines.append(f"<b>{_esc(ip)}</b>")
    return "<br>".join(lines)


def _node_style(node, ghost: bool) -> tuple[str, int, int]:
    role = node.role_hint
    fill, stroke = ("#FAFAFA", "#005073") if node.captured and not ghost else ("#E6E6E6", "#7F7F7F")
    if role == "cloud":
        return "shape=cloud;whiteSpace=wrap;html=1;fillColor=#ffffff;strokeColor=#333333;strokeWidth=2;fontSize=13;fontStyle=1;", 160, 75
    if role == "segment":
        return ("ellipse;whiteSpace=wrap;html=1;fillColor=#FFF6DD;strokeColor=#C58F00;strokeWidth=2;fontSize=10;fontStyle=1;"
                "verticalLabelPosition=bottom;verticalAlign=top;labelPosition=center;align=center;"), 96, 44
    if role == "ap":
        return f"shape=mxgraph.cisco19.wireless_access_point;sketch=0;{LABEL_STYLE}fillColor={'#005073' if node.captured else '#7F7F7F'};strokeColor=none;", 60, 60
    if role in ("phone", "host"):
        return f"shape=mxgraph.mscae.enterprise.workstation_client;sketch=0;{LABEL_STYLE}fillColor=#00188D;strokeColor=none;", 50, 50
    icon = ICON_FROM_ROLE.get(role, "l2_switch")
    return f"sketch=0;{ICON_POINTS}{LABEL_STYLE}aspect=fixed;shape=mxgraph.cisco19.rect;fillColor={fill};strokeColor={stroke};prIcon={icon};", NODE_W, NODE_H


def _add_node(root: ET.Element, ident: str, key: str, node, pos, ghost: bool) -> None:
    style, w, h = _node_style(node, ghost)
    obj = ET.SubElement(root, "object", {"label": _label(node, ghost), "id": ident, "hostname": node.hostname,
                                         "model": node.model, "mgmt_ip": node.mgmt_ip, "role": node.role_hint, "node_key": key,
                                         "serial": ", ".join(sorted(node.serials)), "captured": "yes" if node.captured else "no",
                                         "source_file": node.source, "vendor": node.vendor, "os_version": node.os_version})
    cell = ET.SubElement(obj, "mxCell", {"style": style, "vertex": "1", "parent": "1"})
    ET.SubElement(cell, "mxGeometry", {"x": f"{pos.x + (NODE_W - w) / 2:.0f}", "y": f"{pos.y + (NODE_H - h) / 2:.0f}",
                                       "width": str(w), "height": str(h), "as": "geometry"})


def _edge_style(graph: Graph, conn: Connection, line_style: str) -> str:
    if conn.kind == "host":
        return LINE_STYLE + HOST_STYLE
    colour, width, dashed = line_look(graph, conn, line_style)
    return LINE_STYLE + f"strokeColor={colour};strokeWidth={width:g};" + ("dashed=1;" if dashed else "")


def _add_edge(root: ET.Element, ident: str, conn: Connection, graph: Graph, ids: dict[str, str], show_ports: bool,
              waypoints: list[tuple[float, float]] | None = None, line_style: str = "state", spots: dict[str, float] | None = None) -> None:
    style = _edge_style(graph, conn, line_style)
    members = "; ".join(f"{l.a_port} <-> {l.b_port} [{l.state}]" for l in conn.links)
    obj = ET.SubElement(root, "object", {"label": "", "id": ident, "state": conn.state, "kind": conn.kind,
                                         "protocols": "/".join(sorted(conn.protocols)), "links": members,
                                         "a": conn.a, "b": conn.b, "a_bundle": conn.a_po, "b_bundle": conn.b_po,
                                         "speed": labels.speed_summary(graph, conn), "vpc_id": conn.vpc_id})
    cell = ET.SubElement(obj, "mxCell", {"style": style, "edge": "1", "parent": "1", "source": ids[conn.a], "target": ids[conn.b]})
    geometry = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
    if waypoints:
        points = ET.SubElement(geometry, "Array", {"as": "points"})
        for x, y in waypoints:
            ET.SubElement(points, "mxPoint", {"x": f"{x:.0f}", "y": f"{y:.0f}"})
    a_text, b_text = labels.end_texts(conn)
    centre = labels.center_text(conn, graph)
    extras = []
    if show_ports:
        extras += [(a_text, spots.get("a", "-0.72") if spots else "-0.72", END_LABEL), (b_text, spots.get("b", "0.72") if spots else "0.72", END_LABEL)]
    if centre:
        extras.append((centre, spots.get("mid", "0") if spots else "0", MID_LABEL))
    for n, (text, pos, lab_style) in enumerate(extras):
        if not text:
            continue
        label = ET.SubElement(root, "mxCell", {"id": f"{ident}-l{n}", "value": text, "style": lab_style, "vertex": "1",
                                               "connectable": "0", "parent": ident})
        geo = ET.SubElement(label, "mxGeometry", {"x": pos, "relative": "1", "as": "geometry"})
        ET.SubElement(geo, "mxPoint", {"as": "offset"})


def legend_rows(line_style: str, logical: bool | str) -> tuple[tuple[str, str], ...]:
    if line_style == "speed":
        rows = tuple((colour, f"{name} (rated speed)") for _, colour, _, name in SPEED_TIERS[::-1])
        rows += (("#7F7F7F", "Speed unknown"), ("#1f1f1f", "Dashed line: not confirmed from both ends"), ("#0070c0", "Blue dashed: routed /30 link"))
    else:
        rows = (("#1f1f1f", "Confirmed: both ends report the link"), ("#ED7D31", "Single-sided: only one end reports it"),
                ("#FF0000", "Conflict: the peer's table says otherwise"), ("#0070c0", "Blue thick: vPC peer-link; blue dashed: routed /30 link"))
    rows += (("#00A3A3", "Teal dashed: neighbor inferred from ARP / port description (not CDP/LLDP)"),)
    if logical == "ip":
        rows = (("#1f1f1f", "Line: two devices with addresses in the same subnet (interface and address at each end)"),
                ("#C58F00", "Yellow oval: a subnet shared by more than two devices"), ("#005073", "Tables below: every interface address of a device")
                ) + (("#00A3A3", "Teal dashed: neighbor inferred from ARP / port description"),)
    elif logical:
        rows += (("#005073", "Frame = vPC pair; one thick line = a bundle spanning both switches"),)
    return rows + (("#7F7F7F", "Grey device: seen by CDP/LLDP, not captured"),)


def _legend(root: ET.Element, x: float, y: float, line_style: str = "state", logical: bool | str = False, prefix: str = "") -> None:
    rows = legend_rows(line_style, logical)
    box = ET.SubElement(root, "mxCell", {"id": f"{prefix}legend-box", "value": "Legend", "style": "rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#BBBBBB;verticalAlign=top;align=left;spacingLeft=8;fontStyle=1;fontSize=11;", "vertex": "1", "parent": "1"})
    ET.SubElement(box, "mxGeometry", {"x": f"{x:.0f}", "y": f"{y:.0f}", "width": "300", "height": str(30 + 22 * len(rows)), "as": "geometry"})
    for i, (colour, text) in enumerate(rows):
        cell = ET.SubElement(root, "mxCell", {"id": f"{prefix}legend-{i}", "value": text, "style": f"text;html=1;align=left;verticalAlign=middle;fontSize=10;fontColor={colour};fontStyle=1;", "vertex": "1", "parent": "1"})
        ET.SubElement(cell, "mxGeometry", {"x": f"{x + 10:.0f}", "y": f"{y + 26 + 22 * i:.0f}", "width": "280", "height": "20", "as": "geometry"})


def _add_table(root: ET.Element, ident: str, table) -> None:
    """The interface table of the IP view: one text box holding an HTML table (diagrams.net renders it and it stays editable)."""
    head = "".join(f"<td><b>{_esc(name)}</b></td>" for name in table.header)
    body = "".join("<tr>" + "".join(f"<td>{_esc(str(cell))}</td>" for cell in row) + "</tr>" for row in table.rows)
    html = (f'<table cellpadding="2" cellspacing="0" border="0" width="100%" style="font-size:10px">'
            f'<tr bgcolor="#005073"><td colspan="{len(table.header)}"><font color="#ffffff"><b>{_esc(table.title)}</b></font></td></tr>'
            f'<tr bgcolor="#E8EEF3">{head}</tr>{body}</table>')
    cell = ET.SubElement(root, "mxCell", {"id": ident, "value": html, "vertex": "1", "parent": "1",
                                          "style": "text;html=1;strokeColor=#9aa7b2;fillColor=#ffffff;align=left;verticalAlign=top;whiteSpace=wrap;overflow=fill;fontSize=10;spacing=0;"})
    ET.SubElement(cell, "mxGeometry", {"x": f"{table.x:.0f}", "y": f"{table.y:.0f}", "width": f"{table.w:.0f}", "height": f"{table.h:.0f}", "as": "geometry"})


def _title_block(root: ET.Element, index: int, title: str, created: _dt.datetime) -> None:
    """Topology name (when given) and 'Topology Created at YYYY:MM:DD HH:MM:SS' above the picture; negative y keeps every device where it was."""
    y = -64.0
    if title:
        cell = ET.SubElement(root, "mxCell", {"id": f"{index}-title", "value": title, "vertex": "1", "parent": "1",
                                              "style": "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;fontSize=22;fontStyle=1;fontColor=#005073;"})
        ET.SubElement(cell, "mxGeometry", {"x": "40", "y": f"{y:.0f}", "width": "900", "height": "32", "as": "geometry"})
        y += 34
    cell = ET.SubElement(root, "mxCell", {"id": f"{index}-created", "value": "Topology Created at Date " + created.strftime("%Y:%m:%d") + " - Time " + created.strftime("%H:%M:%S"), "vertex": "1", "parent": "1",
                                          "style": "text;html=1;strokeColor=none;fillColor=none;align=left;verticalAlign=middle;whiteSpace=wrap;fontSize=12;fontColor=#52606d;"})
    ET.SubElement(cell, "mxGeometry", {"x": "40", "y": f"{y:.0f}", "width": "400", "height": "22", "as": "geometry"})


def _diagram(page: Page, graph: Graph, index: int, show_ports: bool, line_style: str = "state", title: str = "",
             created: _dt.datetime | None = None) -> ET.Element:
    graph = page.graph or graph
    diagram = ET.Element("diagram", {"id": f"page-{index}", "name": page.name})
    width, height = max(int(page.width) + 200, 1100), max(int(page.height) + 260, 850)
    model = ET.SubElement(diagram, "mxGraphModel", {"dx": "1420", "dy": "942", "grid": "1", "gridSize": "10", "guides": "1",
                                                    "tooltips": "1", "connect": "1", "arrows": "1", "fold": "1", "page": "1",
                                                    "pageScale": "1", "pageWidth": str(width), "pageHeight": str(height),
                                                    "math": "0", "shadow": "0"})
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
    _title_block(root, index, title, created or _dt.datetime.now())
    for n, (box_title, x, y, w, h) in enumerate(page.boxes):
        cell = ET.SubElement(root, "mxCell", {"id": f"{index}-box-{n}", "value": box_title,
                                              "style": "rounded=0;whiteSpace=wrap;html=1;fillColor=none;strokeColor=#000000;strokeWidth=2;verticalAlign=top;align=left;spacingLeft=12;fontStyle=1;fontSize=14;fontColor=#000000;",
                                              "vertex": "1", "parent": "1"})
        ET.SubElement(cell, "mxGeometry", {"x": f"{x:.0f}", "y": f"{y:.0f}", "width": f"{w:.0f}", "height": f"{h:.0f}", "as": "geometry"})
    ids: dict[str, str] = {}
    for n, frame in enumerate(page.pair_boxes.values()):
        ids[frame.key] = f"pb{index}-{n}"
        cell = ET.SubElement(root, "mxCell", {"id": ids[frame.key], "value": frame.title, "vertex": "1", "parent": "1",
                                              "style": "rounded=1;arcSize=6;whiteSpace=wrap;html=1;fillColor=#F2F8FC;strokeColor=#005073;strokeWidth=2;dashed=1;"
                                                       "verticalAlign=top;align=center;fontStyle=1;fontSize=11;fontColor=#005073;"})
        ET.SubElement(cell, "mxGeometry", {"x": f"{frame.x:.0f}", "y": f"{frame.y:.0f}", "width": f"{frame.w:.0f}", "height": f"{frame.h:.0f}", "as": "geometry"})
    for n, (key, pos) in enumerate(sorted(page.nodes.items(), key=lambda item: (item[1].y, item[1].x))):
        ids[key] = f"n{index}-{n}"
        _add_node(root, ids[key], key, graph.nodes[key], pos, key in page.ghosts)
    for n, conn in enumerate(page.connections):
        ports_on = show_ports and not (page.view == "logical" and conn.kind == "peer-link")   # the frame already says "peer-link"
        spots = {slot: f"{2 * share - 1:.2f}" for (i, slot), (_, _, share) in page.label_pos.items() if i == n}
        _add_edge(root, f"e{index}-{n}", conn, graph, ids, ports_on, page.routes.get(n), line_style, spots)
    for n, table in enumerate(page.tables):
        _add_table(root, f"{index}-tbl-{n}", table)
    legend_y = max([page.height] + [t.y + t.h for t in page.tables]) + 20
    _legend(root, 20, legend_y, line_style, page.view if page.view in ("ip", "logical") else False, f"{index}-")
    return diagram


def to_drawio(graph: Graph, group_mode: str = "none", show_ports: bool = True, pages: list[Page] | None = None, line_style: str = "state",
              title: str = "", created: _dt.datetime | None = None) -> str:
    pages = pages or build_pages(graph, group_mode)
    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    created = created or _dt.datetime.now()
    mxfile = ET.Element("mxfile", {"host": "Keystone Topology Builder", "modified": now, "agent": "Keystone", "version": "21.2.8", "type": "device"})
    for index, page in enumerate(pages):
        mxfile.append(_diagram(page, graph, index, show_ports, line_style, title, created))
    ET.indent(mxfile)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(mxfile, encoding="unicode")
