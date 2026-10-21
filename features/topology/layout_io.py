"""Keep a hand-tuned layout: read node positions back from a previously exported topology.drawio."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from .layout import NODE_H, NODE_W

MAX_LAYOUT_BYTES = 30 * 1024 * 1024


def read_layout(data: bytes) -> dict[str, dict[str, tuple[float, float]]]:
    """{page name: {node key: (x, y)}} from the ``node_key`` attribute Keystone writes on every device.

    The file is parsed with ElementTree; DOCTYPE/entity declarations are refused so a crafted file cannot expand."""
    if len(data) > MAX_LAYOUT_BYTES:
        raise ValueError("The previous diagram is larger than 30 MB.")
    head = data[:4096].lower()
    if b"<!doctype" in head or b"<!entity" in data[:65536].lower():
        raise ValueError("This file contains a DOCTYPE declaration and is not read.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("The previous diagram is not a readable draw.io file (compressed pages are not supported: use File > Properties > uncheck Compressed).") from exc
    if root.tag != "mxfile":
        raise ValueError("The previous diagram is not a draw.io file.")
    pages: dict[str, dict[str, tuple[float, float]]] = {}
    for diagram in root.findall("diagram"):
        if diagram.find("mxGraphModel") is None:
            continue                                         # a compressed page: nothing to read
        positions: dict[str, tuple[float, float]] = {}
        for obj in diagram.iter("object"):
            key = obj.get("node_key")
            cell = obj.find("mxCell")
            geo = cell.find("mxGeometry") if cell is not None else None
            if not key or geo is None or cell.get("vertex") != "1":
                continue
            try:
                x, y = float(geo.get("x", "0")), float(geo.get("y", "0"))
                w, h = float(geo.get("width", NODE_W)), float(geo.get("height", NODE_H))
            except ValueError:
                continue
            positions[key] = (x - (NODE_W - w) / 2, y - (NODE_H - h) / 2)   # back to the 76 x 76 slot the layout uses
        pages[diagram.get("name", "")] = positions
    return pages
