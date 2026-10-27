"""Line colours and widths shared by the draw.io writer and the SVG preview."""

from __future__ import annotations

from .graph import Connection, Graph, connection_speeds

STATE_COLOUR = {"confirmed": "#1f1f1f", "single": "#ED7D31", "conflict": "#FF0000", "inferred": "#0070c0"}
UNKNOWN_SPEED = ("#7F7F7F", 2)
# rated speed in Mbit/s (lower bound of the tier) -> (colour, width); the colours differ in hue so they survive a black-and-white print as widths
SPEED_TIERS = ((100000, "#C55A11", 7, "100G"), (40000, "#548235", 6, "40G"), (25000, "#7030A0", 5, "25G"),
               (10000, "#2E75B6", 4, "10G"), (1000, "#5B9BD5", 2.5, "1G"), (1, "#A6A6A6", 1.5, "100M"))


def speed_style(graph: Graph, conn: Connection) -> tuple[str, float]:
    """Colour and width of a connection when lines are styled by speed: the fastest known member decides."""
    fastest = max(connection_speeds(graph, conn), default=0)
    for floor, colour, width, _ in SPEED_TIERS:
        if fastest >= floor:
            return colour, width
    return UNKNOWN_SPEED


def line_look(graph: Graph, conn: Connection, line_style: str) -> tuple[str, float, bool]:
    """(colour, width, dashed) of one line for the chosen styling ('state' or 'speed')."""
    if conn.l3.get("role") == "under":                          # L3 over L2: a cable is thick in the colour of the L3 link it carries, thin grey otherwise
        return conn.l3["colour"], conn.l3["width"], False
    if conn.kind == "peer-link":
        if line_style == "speed":                              # blue would be mistaken for the 10G colour
            colour, width = speed_style(graph, conn)
            return colour, max(width, 4), False
        return "#0070c0", 4, False
    if conn.kind == "host":
        return "#999999", 1, True
    if conn.kind == "mgmt":
        return "#8FAADC", 1.5, True
    if conn.kind == "routed":
        return "#0070c0", 2, True
    if conn.kind == "l3r":
        from .l3page import edge_look
        return edge_look(conn)
    if conn.kind in ("l3", "l3seg"):
        return ("#3C6E47", 2.5, False) if conn.kind == "l3" else ("#C58F00", 1.5, False)
    if conn.kind == "inferred":
        return "#00A3A3", 2.5, True
    if line_style == "speed":
        colour, width = speed_style(graph, conn)
        return colour, width, conn.state != "confirmed"
    colour = STATE_COLOUR[conn.state]
    width = 6 if conn.kind == "vpc" else 4 if conn.kind in ("bundle", "parallel") and conn.state == "confirmed" else 3 if conn.state == "conflict" else 2
    return colour, width, conn.state != "confirmed"
