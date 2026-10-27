"""The L3 pages: the network as the routing tables see it.

``l3_page`` turns the L3 model (l3engine) into a page the existing renderers draw.  Every edge becomes one ``Connection`` of kind
``l3r`` whose ``l3`` dict says what it stands for.  Look of a line:

* colour = VRF (``vrf_colours``), so several VRFs share one page and stay readable;
* solid = something in the captures shows it working (interface up/up, OSPF FULL, BGP Established, BFD up),
  dashed = configured only, red = something shows it broken;
* width = kind of link (overlay and tunnel thicker than a LAN segment).

The picture shows routing intent: where a device sends traffic according to its routing table and the interface state.  It is not
measured traffic.
"""

from __future__ import annotations

from typing import Any

from .graph import Connection, Graph, Link
from .l3engine import CONFIGURED, DOWN, UP, L3Edge, L3Model, build
from .l3focus import Focus
from .l3tables import sentence
from .labelplace import place_labels
from .layout import layered
from .scene import Page, _route

VIEW_L3ROUTE = "L3 - Logical and Route"
VRF_PALETTE = ("#1F6FB2", "#2E8B57", "#C2410C", "#7B3FA0", "#B8860B", "#0E8C8C", "#B03060", "#556B2F", "#8B4513", "#4169E1")
GLOBAL_COLOUR = "#3C3C3C"
OVERLAY_COLOUR = "#7B3FA0"        # the SD-WAN overlay carries every service VPN, so it has a colour of its own
TUNNEL_COLOUR = "#0E8C8C"
DOWN_COLOUR = "#D32F2F"
KIND_WIDTH = {"overlay": 4, "tunnel": 3, "p2p": 2.5, "peering": 2, "gateway": 2.5, "segment": 1.8}
KIND_TEXT = {"p2p": "direct link", "segment": "shared subnet", "tunnel": "tunnel", "overlay": "SD-WAN overlay", "peering": "routing adjacency", "gateway": "first hop"}


def vrf_colours(vrfs: list[str]) -> dict[str, str]:
    """A stable colour per VRF name (sorted); no VRF (the global table) is dark grey."""
    named = sorted({v for v in vrfs if v and v.lower() not in ("global", "default")})
    colours = {"": GLOBAL_COLOUR}
    for n, name in enumerate(named):
        colours[name] = VRF_PALETTE[n % len(VRF_PALETTE)]
    return colours


def edge_colour(l3: dict[str, Any], colours: dict[str, str]) -> str:
    if l3.get("state") == DOWN:
        return DOWN_COLOUR
    if l3.get("kind") == "overlay":
        return OVERLAY_COLOUR
    if l3.get("kind") == "tunnel" and not l3.get("vrf"):
        return TUNNEL_COLOUR
    return colours.get(l3.get("vrf", ""), colours.get("", GLOBAL_COLOUR))


def edge_look(conn: Connection) -> tuple[str, float, bool]:
    """(colour, width, dashed) of an l3r line; ``colours`` are put in the dict by the page builder so the renderers need no model."""
    l3 = conn.l3
    return l3.get("colour", GLOBAL_COLOUR), KIND_WIDTH.get(l3.get("kind", ""), 2), l3.get("state") != UP


def route_summary(routes: list[dict[str, Any]]) -> str:
    """'OSPF default + 12 prefixes' / 'static 3 prefixes' for the routes whose next hop is reached over one line."""
    parts: list[str] = []
    by_proto: dict[str, dict[str, Any]] = {}
    for route in routes:
        item = by_proto.setdefault(route.get("protocol", "") or "route", {"count": 0, "default": False})
        item["count"] += int(route.get("count") or 0)
        item["default"] = item["default"] or bool(route.get("default"))
    for proto, item in sorted(by_proto.items()):
        rest = item["count"] - (1 if item["default"] else 0)
        text = proto.upper() if len(proto) <= 4 else proto
        if item["default"]:
            text += " default" + (f" + {rest} prefixes" if rest > 0 else "")
        else:
            text += f" {item['count']} prefix" + ("" if item["count"] == 1 else "es")
        parts.append(text)
    return ", ".join(parts)


def centre_text(l3: dict[str, Any]) -> str:
    kind = l3.get("kind", "")
    bits: list[str] = []
    if l3.get("over2") and (l3.get("ip_a") or l3.get("ip_b")):
        bits.append(" - ".join(x for x in (l3.get("ip_a", ""), l3.get("ip_b", "")) if x))
    if kind == "overlay":
        up, total = l3.get("sessions", (0, 0))
        bits.append(f"SD-WAN overlay BFD {up}/{total} up" + (f" · {l3['sites']} sites not drawn" if l3.get("sites") else ""))
        if l3.get("colours"):
            bits.append(" ".join(l3["colours"][:3]) + (" ..." if len(l3["colours"]) > 3 else ""))
    elif l3.get("group"):
        bits.append((f"{l3['group']} shared subnets" if kind == "p2p" else f"{l3['group']} next hops not captured") + (f" ({l3['broken']} down)" if l3.get("broken") else ""))
        if l3.get("vrf"):
            bits.append(f"VRF {l3['vrf']}")
    else:
        if kind in ("tunnel", "peering"):
            bits.append(KIND_TEXT[kind])
        if l3.get("subnet"):
            bits.append(l3["subnet"])
        if l3.get("vrf"):
            bits.append(f"VRF {l3['vrf']}")
    if l3.get("routes"):
        bits.append(route_summary(l3["routes"]))
    return " · ".join(bits)


def to_connection(edge: L3Edge, colours: dict[str, str], ident: str = "", names: dict[str, str] | None = None, ids: dict[int, str] | None = None) -> Connection:
    link = Link(edge.a, edge.a_if, edge.b, edge.b_if, "confirmed" if edge.state == UP else "single", {"L3"}, edge.evidence[0] if edge.evidence else "")
    l3 = {"kind": edge.kind, "state": edge.state, "vrf": edge.vrf, "subnet": edge.subnet, "evidence": list(edge.evidence), "routes": list(edge.routes),
          "colours": list(edge.colours), "sessions": edge.sessions, "sites": edge.sites, "group": len(edge.members), "broken": sum(1 for m in edge.members if m.state == DOWN), "ip_a": edge.a_ip, "ip_b": edge.b_ip, "id": ident,
          "meaning": sentence(edge, (names or {}).get(edge.a, edge.a), (names or {}).get(edge.b, edge.b))}
    l3["colour"] = edge_colour(l3, colours)
    if edge.members and ids:
        l3["carries"] = [ids[id(m)] for m in edge.members if id(m) in ids]          # a click or a trace on any member highlights the grouped line
    return Connection(edge.a, edge.b, [link], kind="l3r", subnet=edge.subnet, ip_a=edge.a_ip, ip_b=edge.b_ip, l3=l3)


def edge_ids(model: L3Model) -> dict[int, str]:
    """A stable ID per edge of the model (L3-01, L3-02 ...), the same on every page and in every table."""
    ids = {id(edge): f"L3-{n:02d}" for n, edge in enumerate(model.edges, 1)}
    ids.update({id(line): line.ident for line in model.grouped})
    return ids


def l3_model_graph(graph: Graph, model: L3Model, focus: Focus | None = None) -> tuple[Graph, list[Connection]]:
    """The small graph the page is drawn from: only devices and uncaptured nodes that an edge touches (plus captured devices without any edge)."""
    colours = vrf_colours([e.vrf for e in model.edges] + [r.get("vrf", "") for e in model.edges for r in e.routes])
    names = {k: n.hostname for k, n in {**graph.nodes, **model.nodes}.items()}
    ids = edge_ids(model)
    drawn = model.drawn()
    conns = [to_connection(edge, colours, ids[id(edge)], names, ids) for edge in drawn]
    touched = {c.a for c in conns} | {c.b for c in conns}
    nodes = {k: graph.nodes[k] for k in graph.nodes if k in touched and k not in graph.hidden_nodes}
    nodes.update({k: n for k, n in model.nodes.items() if k in touched})
    narrowed = bool(focus and focus.narrowed)
    for key, node in graph.nodes.items():                  # a captured router with no edge still belongs on the page
        if node.captured and key not in nodes and key not in graph.hidden_nodes and (node.l3 or node.l3facts):
            if narrowed and node.l3facts.get("system_ip"):
                continue                                    # an SD-WAN site the typed list leaves out has nothing to show here
            nodes[key] = node
    conns = [c for c in conns if c.a in nodes and c.b in nodes]
    sub = Graph(nodes=nodes, links=[c.links[0] for c in conns], connections=conns, hidden_kinds=set())
    return sub, [c for c in conns]


def l3_page(graph: Graph, hints: dict[str, Any] | None = None, curved: bool = False, model: L3Model | None = None, focus: Focus | None = None) -> Page | None:
    """The 'L3 - Logical and Route' page, or None when no captured device owns a routed address."""
    model = model or build(graph, hints, focus)
    if not model.edges:
        return None
    sub, conns = l3_model_graph(graph, model, model.focus)
    if not conns:
        return None
    ids_of = edge_ids(model)
    clouds = {k: -1.0 for k, n in sub.nodes.items() if n.role_hint == "cloud"}            # provider clouds and gateways sit above the routers that reach them
    placed, width, height = layered(sub, list(sub.nodes), tiers=clouds)
    page = Page(VIEW_L3ROUTE, placed, set(), [], conns, {}, width, height, view="l3route", graph=sub, curved=curved)
    page.l3 = {"model": model, "edges": [(c.l3["id"], e) for c, e in zip(conns, [e for e in model.drawn() if e.a in sub.nodes and e.b in sub.nodes])],
               "all": [(ids_of[id(e)], e) for e in model.edges] + [(g.ident, g) for g in model.grouped], "names": {k: n.hostname for k, n in sub.nodes.items()}, "colours": vrf_colours([e.vrf for e in model.edges])}
    page.legend_extra = [(c, f"VRF {v}") for v, c in page.l3["colours"].items() if v] + ([(GLOBAL_COLOUR, "No VRF (global table)")] if any(not e.vrf and e.kind not in ("overlay",) for e in model.edges) else [])
    _route(page)
    place_labels(page, sub, True)
    return page


def l3over2_pages(graph: Graph, physical: list[Page], hints: dict[str, Any] | None = None, model: L3Model | None = None, focus: Focus | None = None) -> list[Page]:
    """The 'L3 over L2' pages: one per physical page that an L3 link touches."""
    from .l3over2 import l3over2_page
    model = model or build(graph, hints, focus)
    if not model.edges:
        return []
    colours = vrf_colours([e.vrf for e in model.edges] + [r.get("vrf", "") for e in model.edges for r in e.routes])
    names = {k: n.hostname for k, n in {**graph.nodes, **model.nodes}.items()}
    ids = edge_ids(model)
    pages = [p for p in (l3over2_page(graph, phys, model, colours, ids, names) for phys in physical) if p is not None]
    for page in pages:
        page.legend_extra = [(c, f"VRF {v}") for v, c in colours.items() if v]
    return pages
