"""The F5 map page: what a BIG-IP serves, drawn round the BIG-IP.

The Load Balancer Analyzer's *Visualization* tab is a tree (virtual server -> pool -> pool member), like Local Traffic > Network Map on the
BIG-IP itself (https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/big-ip-local-traffic-management-basics-14-0-0/01.html).
This page lays the same objects out as a network drawing, one page per BIG-IP:

* the **virtual servers** (for BIG-IP DNS: the wide IPs) are the external side, in four blocks round the BIG-IP: left, right, top-left, top-right;
* the **BIG-IP** is the box in the middle;
* below it, one frame per **pool** (a pool several virtual servers use is drawn once) with its **pool members** inside;
* below the pools, one box per **node** (member IP address), joined to the members that use it;
* tables under the picture: the VLANs with their tags, ports and self IPs, and the interfaces with state and speed - the F5's own interface / VLAN /
  self IP topology.

Colours follow the status icons of the BIG-IP Network Map (green available, blue unknown, yellow unavailable, red offline, black disabled / forced
down, grey parent disabled); a ring-like white box with a green border means "configured and monitored, no live state in the capture".  The status
is read from the configuration unless the capture holds the ``tmsh show ltm`` output (then it is the live state), and the box says which in its tooltip.
"""

from __future__ import annotations

import ipaddress
import math
from typing import Any

from .graph import Graph
from .layout import NODE_H, NODE_W, Placed
from .scene import ROW_H, Page, Shape, ShapeEdge, TableBox, table_columns

EXT_W, EXT_H = 210, 52
MEM_W, MEM_H = 180, 38
POOL_PAD, POOL_HEAD = 10, 40
POOL_W = MEM_W + 2 * POOL_PAD
NODE_BW, NODE_BH = 150, 46
GAP = 22
MARGIN = 50
SIDE_MAX = 8               # virtual servers in one left / right column; more go to the top blocks
TOP_COLS = 3
ROW_GAP = 34
TABLE_GAP = 24
SLOTS = ("L", "R", "TL", "TR")

# status -> (fill, border, dashed): the colours of the status icons of the BIG-IP Network Map
PALETTE: dict[str, tuple[str, str, bool]] = {
    "available": ("#E8F6EE", "#2E9E5B", False),
    "unverified": ("#FFFFFF", "#2E9E5B", False),
    "unknown": ("#EAF1FB", "#3B7DD8", False),
    "unavailable": ("#FFF7DB", "#D4A017", False),
    "offline": ("#FDECEC", "#D32F2F", False),
    "disabled": ("#EDEDED", "#222222", False),
    "forced down": ("#D9D9D9", "#222222", True),
    "parent disabled": ("#F5F5F5", "#8A8A8A", False),
    "": ("#F7F9FB", "#8FA0AE", False),
}
GROUP_STYLE = ("#FBFCFD", "#B8C4CE")
LEGEND = (("#2E9E5B", "Green: available (live) - white box with green border: configured and monitored, no live state in the capture"),
          ("#3B7DD8", "Blue: unknown - no health monitor, so the BIG-IP itself cannot tell"),
          ("#D4A017", "Yellow: unavailable (may recover on its own, e.g. connection limit)"),
          ("#D32F2F", "Red: offline - monitor failed, or every member is down"),
          ("#222222", "Black: disabled or forced down by a user (dashed = forced down); grey: parent (node) disabled"),
          ("#005073", "Left / right / top: virtual servers (wide IPs on BIG-IP DNS); middle: the BIG-IP; below: pools with their members, then nodes (one per member IP)"))

POOL_TYPES = ("pool", "dnspool")
MEMBER_TYPES = ("member", "dnsmember")
EXTERNAL_TYPES = ("virtual", "wideip")


def style_of(status: str) -> tuple[str, str, bool]:
    return PALETTE.get(status, PALETTE[""])


def _is_ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_address(text).version == 4
    except ValueError:
        return False


def _split(tree: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[str]]]:
    """The map tree as: external objects in order, pools by name (each once, with its members and the externals that reach it), and external -> pool names."""
    by_id = {n["id"]: n for n in tree}
    externals = [n for n in tree if n["type"] in EXTERNAL_TYPES and not n["parent"]]
    pools: dict[str, dict[str, Any]] = {}
    reach: dict[str, list[str]] = {}
    for node in tree:
        if node["type"] not in POOL_TYPES:
            continue
        pool = pools.setdefault(node["name"], {"node": node, "members": {}, "used_by": [], "orphan": False})
        parent = by_id.get(node["parent"])
        if parent is not None and parent["type"] in EXTERNAL_TYPES:
            if parent["name"] not in pool["used_by"]:
                pool["used_by"].append(parent["name"])
            reach.setdefault(parent["name"], [])
            if node["name"] not in reach[parent["name"]]:
                reach[parent["name"]].append(node["name"])
        elif parent is not None and parent["type"] == "group":
            pool["orphan"] = True
        for member in (m for m in tree if m["parent"] == node["id"] and m["type"] in MEMBER_TYPES):
            pool["members"].setdefault(member["name"], member)
    return externals, pools, reach


def _external_shape(ident: str, node: dict[str, Any], x: float, y: float) -> Shape:
    facts = node.get("facts") or {}
    kind = "Wide IP" if node["type"] == "wideip" else "Virtual server"
    attrs = {"object": kind, "name": node["name"], "status": node.get("status") or "n/a", "source": node.get("source", ""), "reason": node.get("reason", "")}
    attrs.update({k.lower().replace(" ", "_"): v for k, v in facts.items()})
    return Shape(ident, "external", x, y, EXT_W, EXT_H, [node["name"], node.get("badge") or facts.get("Destination", "")], node.get("status", ""), attrs)


def _pool_height(members: int) -> float:
    return POOL_HEAD + max(members, 1) * (MEM_H + 8) + POOL_PAD


def _vlan_table(facts: dict[str, Any]) -> TableBox | None:
    rows = []
    for row in facts.get("vlans") or []:
        rows.append([row["vlan"], str(row["tag"] or "-"), ", ".join(row["interfaces"]) or "-", ", ".join(row["self_ips"]) or "-", ", ".join(row["floating_ips"]) or "-", row["route_domain"] or "-", row["description"]])
    if not rows:
        return None
    return TableBox(f"VLANs and self IPs · {len(rows)} VLAN(s)", ["VLAN", "Tag", "Interfaces", "Self IP", "Floating IP", "Route domain", "Description"], rows)


def _interface_table(facts: dict[str, Any]) -> TableBox | None:
    trunk_of = {m: t for t, members in (facts.get("trunks") or {}).items() for m in members}
    vlans_on: dict[str, list[str]] = {}
    for row in facts.get("vlans") or []:
        for member in row["interfaces"]:
            vlans_on.setdefault(member.split(" ")[0], []).append(row["vlan"])
    rows = []
    for row in facts.get("interfaces") or []:
        port = row["name"]
        trunk = row["trunk"] or trunk_of.get(port, "")
        carried = vlans_on.get(port, []) + (vlans_on.get(trunk, []) if trunk else [])
        rows.append([port, row["status"] or "-", row["media"] or "-", trunk or "-", f"{len(carried)} VLAN(s)" if carried else "-"])
    if not rows:
        return None
    return TableBox(f"Interfaces · {len(rows)} port(s)", ["Interface", "State", "Media", "Trunk", "VLANs"], rows)


def _guest_table(facts: dict[str, Any]) -> TableBox | None:
    guest = facts.get("vcmp")
    if not guest:
        return None
    return TableBox("vCMP guest (from the configuration of its host)", ["Host", "Guest", "State", "Cores per slot", "Slots", "Management IP", "Initial image"],
                    [[guest["host"], guest["guest"], guest["state"] or "-", guest["cores_per_slot"] or "-", guest["slots"] or "-", guest["management_ip"] or "-", guest["image"] or "-"]])


def _place_tables(tables: list[TableBox], x0: float, y0: float, limit: float) -> tuple[float, float]:
    x, y, row_h, width = x0, y0, 0.0, 0.0
    for table in tables:
        table.w = max(sum(table_columns(table)) + 12, len(table.title) * 7.2 + 20)
        table.h = 52 + len(table.rows) * ROW_H + 4
        if x > x0 and x + table.w > limit:
            x, y, row_h = x0, y + row_h + TABLE_GAP, 0.0
        table.x, table.y = x, y
        x += table.w + TABLE_GAP
        row_h = max(row_h, table.h)
        width = max(width, table.x + table.w)
    return width, y + row_h


def _top_lanes(cells: list[tuple[str, int, int, Shape]], centre_x: float, y_lb: float, top_rows: int, top_cols: int) -> dict[str, list[tuple[float, float]]]:
    """The lines of the boxes in the top blocks.  A straight line from the BIG-IP to a box in the second or third row runs through the boxes of the row
    below it, so each line goes up the channel between the two blocks, along a lane in the gap under its own row and into the bottom of its box.
    Within one gap the box farthest from the middle takes the lowest lane and the outermost trunk, so no two lines cross."""
    out: dict[str, list[tuple[float, float]]] = {}
    for slot, sign in (("TL", -1), ("TR", 1)):
        mine = [c for c in cells if c[0] == slot]
        if not mine:
            continue
        # trunks, nearest the middle first: the higher the row the nearer, so its trunk never meets a lane of the rows below; in one row the box nearest the middle first
        order = sorted(mine, key=lambda c: (-c[1], c[2]))
        step = min(3.0, 15.0 / len(order))
        lane_step = min(3.0, (GAP - 6.0) / max(top_cols, 1))
        for rank, (_, row, col, shape) in enumerate(order):
            trunk = centre_x + sign * (2 + step * rank)
            lane = shape.y + shape.h + 3 + lane_step * col                    # the farther the box from the middle, the lower its lane: the verticals of the boxes nearer in never reach it
            bx = shape.x + shape.w / 2
            out[shape.ident] = [(trunk, y_lb), (trunk, lane), (bx, lane), (bx, shape.y + shape.h)]
    return out


def page_for(graph: Graph, key: str) -> Page | None:
    """The F5 map page of one captured BIG-IP node, or None when its configuration holds nothing to map (no virtual server, pool or wide IP)."""
    node = graph.nodes.get(key)
    facts = (node.l3facts or {}).get("f5") if node is not None else None
    if not facts or not (facts.get("map") or facts.get("vlans")):
        return None
    externals, pools, reach = _split(facts.get("map") or [])

    # ---------------------------------------------------------------- the pool grid (it decides the width of the page)
    top_cols = TOP_COLS if len(externals) <= 30 else 4 if len(externals) <= 70 else 5 if len(externals) <= 120 else 6      # a big unit gets wider top blocks, not a taller page
    width_top = max(2 * top_cols * (EXT_W + GAP) + 40, 2 * (EXT_W + GAP) + NODE_W + 200)
    width = max(width_top, 4 * (POOL_W + GAP) + 2 * MARGIN)
    per_row = max(2, int((width - 2 * MARGIN + GAP) // (POOL_W + GAP)))
    width = max(width, MARGIN * 2 + per_row * (POOL_W + GAP) - GAP)
    centre_x = width / 2

    # ---------------------------------------------------------------- external objects in four blocks
    slots: dict[str, list[dict[str, Any]]] = {slot: [] for slot in SLOTS}
    taken = {slot: 0 for slot in SLOTS}
    order: list[str] = []
    for i, ext in enumerate(externals):
        slot = SLOTS[i % 4]
        if slot in ("L", "R") and taken[slot] >= SIDE_MAX:
            slot = "TL" if taken["TL"] <= taken["TR"] else "TR"
        taken[slot] += 1
        slots[slot].append(ext)
        order.append(slot)
    top_rows = max(math.ceil(len(slots["TL"]) / top_cols), math.ceil(len(slots["TR"]) / top_cols))
    top_h = top_rows * (EXT_H + GAP)
    y_lb = MARGIN + top_h + 50
    shapes: list[Shape] = []
    where: dict[str, Shape] = {}

    top_cells: list[tuple[str, int, int, Shape]] = []              # (slot, row, column, shape) of the boxes in the top blocks: their lines run on lanes

    def put(ext: dict[str, Any], x: float, y: float, cell: tuple[str, int, int] | None = None) -> None:
        shape = _external_shape(f"x{len(shapes)}", ext, x, y)
        shapes.append(shape)
        where[ext["name"]] = shape
        if cell is not None:
            top_cells.append((*cell, shape))

    lb_mid = y_lb + NODE_H / 2
    side_bottom = y_lb + NODE_H
    for slot, left in (("L", True), ("R", False)):
        column = slots[slot]
        height = len(column) * (EXT_H + GAP) - GAP
        y = max(MARGIN + top_h, lb_mid - height / 2)
        x = MARGIN if left else width - MARGIN - EXT_W
        for ext in column:
            put(ext, x, y)
            y += EXT_H + GAP
        side_bottom = max(side_bottom, y - GAP)
    for slot, left in (("TL", True), ("TR", False)):
        block = slots[slot]
        for n, ext in enumerate(block):
            row, col = divmod(n, top_cols)
            # the rows nearest the BIG-IP are filled first, so a short block hugs the middle
            y = MARGIN + (top_rows - 1 - row) * (EXT_H + GAP)
            x = (centre_x - 20 - (col + 1) * (EXT_W + GAP) + GAP) if left else (centre_x + 20 + col * (EXT_W + GAP))
            put(ext, x, y, (slot, row, col))

    # ---------------------------------------------------------------- pools: frames with their members inside
    used_order = [name for ext in externals for name in reach.get(ext["name"], [])]
    pool_names = list(dict.fromkeys(used_order + [n for n in pools if n not in used_order]))
    y = max(y_lb + NODE_H + 140, side_bottom + 100)       # the room above the pools holds the header of their group frame
    pool_shapes: dict[str, Shape] = {}
    member_shapes: dict[tuple[str, str], Shape] = {}
    node_addresses: dict[str, list[Shape]] = {}
    row_y = y
    for start in range(0, len(pool_names), per_row):
        chunk = pool_names[start:start + per_row]
        row_h = max(_pool_height(len(pools[n]["members"])) for n in chunk)
        for col, name in enumerate(chunk):
            pool = pools[name]
            node_ = pool["node"]
            x = MARGIN + col * (POOL_W + GAP)
            used = pool["used_by"]
            subtitle = (node_.get("badge") or "") + (f" · used by {len(used)} virtual server(s)" if len(used) > 1 else (f" · used by {used[0]}" if used else (" · not used" if pool["orphan"] else "")))
            attrs = {"object": "GTM pool" if node_["type"] == "dnspool" else "Pool", "name": name, "status": node_.get("status") or "n/a", "source": node_.get("source", ""), "reason": node_.get("reason", ""),
                     "used_by": ", ".join(used)}
            attrs.update({k.lower().replace(" ", "_"): v for k, v in (node_.get("facts") or {}).items()})
            frame = Shape(f"p{len(shapes)}", "pool", x, row_y, POOL_W, _pool_height(len(pool["members"])), [name, subtitle.strip(" ·")], node_.get("status", ""), attrs)
            shapes.append(frame)
            pool_shapes[name] = frame
            for n, member in enumerate(pool["members"].values()):
                facts_m = member.get("facts") or {}
                mattrs = {"object": "GTM pool member" if member["type"] == "dnsmember" else "Pool member", "name": member["name"], "status": member.get("status") or "n/a", "source": member.get("source", ""),
                          "reason": member.get("reason", ""), "pool": name}
                mattrs.update({k.lower().replace(" ", "_"): v for k, v in facts_m.items()})
                box = Shape(f"m{len(shapes)}", "member", x + POOL_PAD, row_y + POOL_HEAD + n * (MEM_H + 8), MEM_W, MEM_H, [member["name"], member.get("badge", "")], member.get("status", ""), mattrs)
                shapes.append(box)
                member_shapes[(name, member["name"])] = box
                address = facts_m.get("Address", "")
                if _is_ipv4(address):
                    node_addresses.setdefault(address, []).append(box)
        row_y += row_h + ROW_GAP
    pool_end = row_y - ROW_GAP if pool_names else y

    # ---------------------------------------------------------------- nodes: one box per member address, under the pools
    node_cols = max(1, int((width - 2 * MARGIN + GAP) // (NODE_BW + GAP)))
    node_y = pool_end + 130
    node_shapes: list[Shape] = []
    for n, (address, boxes) in enumerate(node_addresses.items()):
        row, col = divmod(n, node_cols)
        node_name = next((b.attrs.get("node", "") for b in boxes if b.attrs.get("node") and b.attrs["node"] != address), "")
        states = {b.status for b in boxes}
        status = "offline" if "offline" in states and len(states) == 1 else (boxes[0].status if len(states) == 1 else "")
        attrs = {"object": "Node", "name": address, "node_name": node_name, "members": ", ".join(f"{b.attrs.get('pool', '')} {b.attrs.get('name', '')}" for b in boxes), "status": status or "n/a"}
        shape = Shape(f"n{len(shapes) + len(node_shapes)}", "node", MARGIN + col * (NODE_BW + GAP), node_y + row * (NODE_BH + GAP), NODE_BW, NODE_BH, [address, node_name], status, attrs)
        node_shapes.append(shape)
    shapes.extend(node_shapes)
    nodes_end = (node_y + math.ceil(len(node_shapes) / node_cols) * (NODE_BH + GAP) - GAP) if node_shapes else pool_end

    # ---------------------------------------------------------------- group frames and lines
    # One line per external object to the BIG-IP; the BIG-IP joins the pool group and the pool group the node group.  A line to every pool and from every
    # member to its node would cover the page (27 pools, 50 members on the sample), and the pool box already says which virtual servers use it.
    group_x, group_w = MARGIN - 14, width - 2 * MARGIN + 28
    groups: list[Shape] = []
    if pool_names:
        members_total = sum(len(pools[n]["members"]) for n in pool_names)
        groups.append(Shape("g-pools", "group", group_x, y - 40, group_w, pool_end - y + 54,
                            [f"Pools and pool members · {len(pool_names)} pool(s), {members_total} member(s)"], "", {"object": "Group", "name": "Pools"}))
    if node_shapes:
        groups.append(Shape("g-nodes", "group", group_x, node_y - 40, group_w, nodes_end - node_y + 54,
                            [f"Nodes · {len(node_shapes)} address(es) (one box per member IP address)"], "", {"object": "Group", "name": "Nodes"}))
    shapes[:0] = groups
    lane_paths = _top_lanes(top_cells, centre_x, y_lb, top_rows, top_cols)
    edges: list[ShapeEdge] = [ShapeEdge(where[ext["name"]].ident, f"node:{key}", ext.get("status", ""), lane_paths.get(where[ext["name"]].ident, [])[::-1]) for ext in externals]
    if pool_names:
        edges.append(ShapeEdge(f"node:{key}", "g-pools", ""))
    if pool_names and node_shapes:
        edges.append(ShapeEdge("g-pools", "g-nodes", ""))

    # ---------------------------------------------------------------- tables under the picture
    tables = [t for t in (_guest_table(facts), _vlan_table(facts), _interface_table(facts)) if t is not None]
    table_right, table_bottom = _place_tables(tables, MARGIN, nodes_end + 90, max(width, 1500.0))

    page = Page(name=f"F5 map · {node.hostname}", view="f5map")
    page.nodes[key] = Placed(centre_x - NODE_W / 2, y_lb, 0)
    page.shapes, page.shape_edges, page.tables = shapes, edges, tables
    page.width = max(width, table_right + MARGIN)
    page.height = max(nodes_end, table_bottom if tables else 0) + MARGIN
    return page


def f5_pages(graph: Graph) -> list[Page]:
    """One F5 map page per captured BIG-IP that has something to map, in host-name order."""
    out = []
    for key in sorted(k for k, n in graph.nodes.items() if n.captured and n.role_hint == "loadbalancer"):
        page = page_for(graph, key)
        if page is not None:
            out.append(page)
    return out
