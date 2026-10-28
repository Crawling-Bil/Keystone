"""Text shown on nodes and connections."""

from __future__ import annotations

import re

from .graph import Connection, Graph, connection_speeds
from .names import port_sort_key, speed_text
from .roles import ROLE_LABEL


def compress_ports(ports: list[str]) -> str:
    """['Eth1/1','Eth1/2','Eth1/3','Eth1/7'] -> 'Eth1/1-3, Eth1/7'."""
    ordered = sorted({p for p in ports if p}, key=port_sort_key)
    runs: list[list[str]] = []
    for port in ordered:
        match = re.match(r"^(.*?)(\d+)$", port)
        if runs and match:
            prev = re.match(r"^(.*?)(\d+)$", runs[-1][-1])
            if prev and prev.group(1) == match.group(1) and int(match.group(2)) == int(prev.group(2)) + 1:
                runs[-1].append(port)
                continue
        runs.append([port])
    out = []
    for run in runs:
        if len(run) >= 3:
            out.append(f"{run[0]}-{re.match(r'^.*?(\d+)$', run[-1]).group(1)}")
        else:
            out.extend(run)
    return ", ".join(out)


def _short(text: str, count: int, limit: int = 30) -> str:
    """A list of ports that would run across the picture becomes "12 ports"; the full list stays in the tooltip, the tables and draw.io data."""
    return text if len(text) <= limit else f"{count} ports"


def end_texts(conn: Connection) -> tuple[str, str]:
    if conn.kind in ("rollup", "host"):
        text = _short(compress_ports([l.a_port for l in conn.links]), len(conn.links))
        return ("" if conn.kind == "rollup" and text.endswith(" ports") and len(conn.links) > 1 and text[0].isdigit() else text), ""
    if conn.kind == "sitebundle":                         # the cables of a pair of sites drawn as one line: their ports are in the tooltip and the tables
        return "", ""
    if conn.kind == "l3" and len(conn.links) > 1:      # many subnets shared by one pair: the tables list every address
        return "", ""
    if conn.kind == "l3r":
        if conn.l3.get("over2"):                              # L3 over L2: the cables carry the port names, the arc carries the addresses
            return "", ""
        return (f"{conn.links[0].a_port} {conn.ip_a}".strip(), f"{conn.links[0].b_port} {conn.ip_b}".strip())
    if conn.kind in ("l3", "l3seg"):
        link = conn.links[0]
        plen = conn.subnet.rsplit("/", 1)[-1] if "/" in conn.subnet else ""
        return (f"{link.a_port} {conn.ip_a}/{plen}".strip(), f"{link.b_port} {conn.ip_b}/{plen}".strip() if conn.ip_b else "")
    if conn.kind == "routed":
        link = conn.links[0]
        return (f"{link.a_port} {conn.ip_a}".strip() if conn.ip_a else link.a_port), (f"{link.b_port} {conn.ip_b}".strip() if conn.ip_b else link.b_port)
    a = conn.a_po or _short(compress_ports([l.a_port for l in conn.links]), len(conn.links))
    b = conn.b_po or _short(compress_ports([l.b_port for l in conn.links]), len(conn.links))
    one = conn.links[0] if len(conn.links) == 1 else None
    a_ip = conn.po_ip_a if conn.a_po else (one.a_ip if one else "")
    b_ip = conn.po_ip_b if conn.b_po else (one.b_ip if one else "")
    return (f"{a} {a_ip}" if a_ip and a else a), (f"{b} {b_ip}" if b_ip and b else b)


def speed_summary(graph: Graph, conn: Connection) -> str:
    """'10G' when every member runs at the same rated speed, '2x10G+2x1G' when they differ, '' when no member's speed is known."""
    speeds = connection_speeds(graph, conn)
    if not any(speeds):
        return ""
    if len(set(speeds)) == 1:
        return speed_text(speeds[0])
    counts: dict[int, int] = {}
    for speed in speeds:
        counts[speed] = counts.get(speed, 0) + 1
    return "+".join(f"{n}x{speed_text(s) or '?'}" for s, n in sorted(counts.items(), reverse=True))


def bundle_protocol(graph: Graph, conn: Connection) -> str:
    for node, po in ((conn.a, conn.a_po), (conn.b, conn.b_po)):
        for name in (po or "").split("/"):
            info = graph.nodes[node].bundle_info.get(name) if node in graph.nodes else None
            if info and info.get("protocol"):
                return info["protocol"]
    return ""


def center_text(conn: Connection, graph: Graph) -> str:
    if conn.kind == "l3r":
        from .l3page import centre_text
        return centre_text(conn.l3)
    parts: list[str] = []
    speed = speed_summary(graph, conn) if conn.kind in ("bundle", "parallel", "vpc", "peer-link", "sitebundle") else ""
    if conn.kind == "peer-link":
        parts.append("vPC peer-link" + (f" {len(conn.links)}x{speed}" if speed and "+" not in speed else ""))
    elif conn.kind == "rollup":
        parts.append(f"{len(conn.links)} ports")
    elif conn.kind == "vpc":
        head = f"vPC {conn.vpc_id}" if conn.vpc_id else "multi-chassis"
        count = f"{len(conn.links)}x{speed}" if speed and "+" not in speed else f"{len(conn.links)} links" + (f" ({speed})" if speed else "")
        parts.append(f"{head} · {count}")
        protocol = bundle_protocol(graph, conn)
        if protocol:
            parts.append(protocol)
    elif conn.kind == "sitebundle":
        parts.append(f"{len(conn.links)} links" + (f" · {speed}" if speed else ""))
    elif conn.kind in ("bundle", "parallel"):
        protocol = bundle_protocol(graph, conn)
        if conn.kind == "parallel":
            protocol = "not bundled"
        parts.append(f"{len(conn.links)}x{speed}" + (f" {protocol}" if protocol else ""))
    elif conn.kind == "l3" and len(conn.links) > 1:
        parts.append(f"{len(conn.links)} shared subnets")
    elif conn.kind == "inferred":
        parts.append("inferred " + "+".join(sorted(conn.protocols)) + (f", {len(conn.links)} links" if len(conn.links) > 1 else ""))
    if conn.vpc_id and conn.kind not in ("peer-link", "vpc"):
        parts.append(f"vPC {conn.vpc_id}")
    if conn.subnet and conn.kind not in ("l3seg", "inferred"):
        parts.append(conn.subnet)
    return " · ".join(parts)


def wrap_centre(text: str, width: int = 44) -> list[str]:
    """A long middle label broken at its ' · ' separators into lines of at most ``width`` characters (a part longer than that is kept whole).

    Used by the SVG preview, the draw.io file and the label placer, so the three agree on how much room the label takes."""
    lines: list[str] = []
    for part in text.split(" · "):
        if lines and len(lines[-1]) + 3 + len(part) <= width:
            lines[-1] += " · " + part
        else:
            lines.append(part)
    return lines or [text]


def node_lines(node) -> list[str]:
    """Hostname, model (+STACK), management IP - the three lines used in the reference diagrams."""
    model = " ".join(x for x in (node.model, "— STACK" if getattr(node, "stack_members", 1) > 1 else "") if x)
    if not model and node.role_hint in ROLE_LABEL and node.role_hint not in ("host", "segment"):
        model = ROLE_LABEL[node.role_hint]              # an access point that reports no model still says what it is
    return [node.hostname, model, node.mgmt_ip]
