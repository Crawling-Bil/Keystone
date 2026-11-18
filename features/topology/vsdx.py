"""A Visio drawing (.vsdx) of the diagrams: one Visio page per diagram page, a box per device, a line (with its bends) per cable, zone boxes behind them.

A .vsdx file is an Open Packaging Conventions package (a ZIP of XML parts): ``visio/document.xml`` names the pages, ``visio/pages/pages.xml`` lists them and every ``pageN.xml`` holds the shapes
of one page.  This writer produces the smallest package that holds a drawing: shapes with their position, size, fill, line and text, and a polyline for every cable.  The units are inches
(96 pixels of the diagram are one inch) and the origin is the lower left corner, so the y axis of the diagram is flipped.

A cable that runs straight between two boxes is written as a **glued connector**: a one-dimensional shape (``ObjType`` 2) whose begin and end cells refer to the ``PinX`` / ``PinY`` of the two
boxes and which is listed in ``<Connects>`` (``FromPart`` 9 for the begin and 12 for the end, ``ToPart`` 3 for the whole shape), so that it follows a box that is moved in Visio.  A cable with
bends keeps its bends as a polyline that is not glued, because a glued connector has no bends of its own and Visio would route it again; the draw.io file (``topology.drawio``) is the one to
edit.  The pages of the F5 map are not written.  The file was checked by opening it in LibreOffice (which reads Visio files) in the tests of Keystone, not in Microsoft Visio.

Microsoft: Introduction to the Visio file format (.vsdx): https://learn.microsoft.com/en-us/office/client-developer/visio/introduction-to-the-visio-file-formatvsdx
Microsoft: Connect element (glue): https://learn.microsoft.com/en-us/office/client-developer/visio/connect-element-connect_type
Microsoft: Visio file format reference: https://learn.microsoft.com/en-us/office/client-developer/visio/visio-file-format-reference
"""

from __future__ import annotations

import io
import math
import zipfile
from html import escape
from typing import Any

from . import labels
from .layout import NODE_H, NODE_W
from .styles import line_look
from .svg import _ROLE_GLYPH, zone_look

PX = 96.0                                           # pixels of the diagram per inch
NS = "http://schemas.microsoft.com/office/visio/2012/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
VISIO_REL = "http://schemas.microsoft.com/visio/2010/relationships"

CONTENT_TYPES = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                 '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
                 '<Override PartName="/visio/document.xml" ContentType="application/vnd.ms-visio.drawing.main+xml"/>'
                 '<Override PartName="/visio/pages/pages.xml" ContentType="application/vnd.ms-visio.pages+xml"/>'
                 '{pages}</Types>')
ROOT_RELS = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="{PKG_REL}"><Relationship Id="rId1" Type="{VISIO_REL}/document" Target="visio/document.xml"/></Relationships>'
DOCUMENT = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<VisioDocument xmlns="{NS}" xmlns:r="{REL}" xml:space="preserve"><DocumentSettings TopPage="0" DefaultTextStyle="0" DefaultLineStyle="0" DefaultFillStyle="0"/>'
            '<Colors/><FaceNames><FaceName ID="0" NameU="Arial" UnicodeRanges="0 0 0 0" CharSets="0 0" Panose="0 0 0 0 0 0 0 0 0 0" Flags="0"/></FaceNames>'
            '<StyleSheets><StyleSheet ID="0" NameU="No Style" Name="No Style"><Cell N="EnableLineProps" V="1"/><Cell N="EnableFillProps" V="1"/><Cell N="EnableTextProps" V="1"/>'
            '<Cell N="LineWeight" V="0.01"/><Cell N="LineColor" V="0"/><Cell N="LinePattern" V="1"/><Cell N="FillForegnd" V="1"/><Cell N="FillPattern" V="1"/></StyleSheet></StyleSheets></VisioDocument>')
DOCUMENT_RELS = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="{PKG_REL}"><Relationship Id="rId1" Type="{VISIO_REL}/pages" Target="pages/pages.xml"/></Relationships>'


def _inch(px: float) -> str:
    return f"{px / PX:.4f}"


def _cell(name: str, value: Any, formula: str = "") -> str:
    return f'<Cell N="{name}" V="{escape(str(value), quote=True)}"' + (f' F="{formula}"' if formula else "") + "/>"


class _Page:
    def __init__(self, height_px: float) -> None:
        self.height = height_px
        self.shapes: list[str] = []
        self.next_id = 1
        self.connects: list[str] = []                           # <Connect .../> elements of the glued connectors

    def reserve(self) -> int:
        number = self.next_id
        self.next_id += 1
        return number

    def y(self, px: float) -> float:
        return self.height - px                                  # Visio counts from the bottom

    def add(self, body: str, shape_id: int | None = None) -> int:
        number = shape_id if shape_id is not None else self.reserve()
        self.shapes.append(f'<Shape ID="{number}" Type="Shape" LineStyle="0" FillStyle="0" TextStyle="0">{body}</Shape>')
        return number

    def box(self, x: float, y: float, w: float, h: float, fill: str, line: str, weight_px: float, text: str = "", dashed: bool = False, rounded: float = 0.0, no_fill: bool = False,
            shape_id: int | None = None) -> int:
        cx, cy = x + w / 2, y + h / 2
        geometry = ('<Section N="Geometry" IX="0">' + _cell("NoFill", 1 if no_fill else 0) + _cell("NoLine", 0) + _rect_rows(w, h) + "</Section>")
        return self.add(_cell("PinX", _inch(cx)) + _cell("PinY", _inch(self.y(cy))) + _cell("Width", _inch(w)) + _cell("Height", _inch(h)) + _cell("LocPinX", _inch(w / 2), "Width*0.5")
                 + _cell("LocPinY", _inch(h / 2), "Height*0.5") + _cell("FillForegnd", fill) + _cell("FillPattern", 0 if no_fill else 1) + _cell("LineColor", line) + _cell("LineWeight", _inch(weight_px))
                 + _cell("LinePattern", 2 if dashed else 1) + _cell("Rounding", _inch(rounded)) + geometry + (f"<Text>{escape(text)}</Text>" if text else ""), shape_id)

    def label(self, cx: float, top: float, lines: list[str], width: float = 150.0) -> None:
        height = 14.0 * max(len(lines), 1)
        cy = top + height / 2
        self.add(_cell("PinX", _inch(cx)) + _cell("PinY", _inch(self.y(cy))) + _cell("Width", _inch(width)) + _cell("Height", _inch(height)) + _cell("LocPinX", _inch(width / 2), "Width*0.5")
                 + _cell("LocPinY", _inch(height / 2), "Height*0.5") + _cell("LinePattern", 0) + _cell("FillPattern", 0) + _cell("VerticalAlign", 0) + _cell("Char", 0)
                 + '<Section N="Geometry" IX="0">' + _cell("NoFill", 1) + _cell("NoLine", 1) + _rect_rows(width, height) + "</Section>"
                 + "<Text>" + "\n".join(escape(line) for line in lines) + "</Text>")

    def line(self, points: list[tuple[float, float]], colour: str, weight_px: float, dashed: bool) -> None:
        xs, ys = [p[0] for p in points], [p[1] for p in points]
        x0, x1, y0, y1 = min(xs), max(xs), min(ys), max(ys)
        w, h = max(x1 - x0, 0.5), max(y1 - y0, 0.5)
        rows = []
        for i, (px, py) in enumerate(points, 1):
            rows.append(f'<Row T="{"MoveTo" if i == 1 else "LineTo"}" IX="{i}">' + _cell("X", _inch(px - x0)) + _cell("Y", _inch(y1 - py)) + "</Row>")
        self.add(_cell("PinX", _inch(x0 + w / 2)) + _cell("PinY", _inch(self.y(y0 + h / 2))) + _cell("Width", _inch(w)) + _cell("Height", _inch(h)) + _cell("LocPinX", _inch(w / 2), "Width*0.5")
                 + _cell("LocPinY", _inch(h / 2), "Height*0.5") + _cell("LineColor", colour) + _cell("LineWeight", _inch(weight_px)) + _cell("LinePattern", 2 if dashed else 1) + _cell("FillPattern", 0)
                 + '<Section N="Geometry" IX="0">' + _cell("NoFill", 1) + _cell("NoLine", 0) + "".join(rows) + "</Section>")


    def glued(self, begin: tuple[float, float], end: tuple[float, float], begin_id: int, end_id: int, colour: str, weight_px: float, dashed: bool) -> None:
        """A straight connector from the centre of shape ``begin_id`` to the centre of ``end_id``, glued to both."""
        bx, by, ex, ey = _inch(begin[0]), _inch(self.y(begin[1])), _inch(end[0]), _inch(self.y(end[1]))
        dx, dy = float(ex) - float(bx), float(ey) - float(by)
        length = math.hypot(dx, dy)
        number = self.reserve()
        body = (_cell("PinX", f"{(float(bx) + float(ex)) / 2:.4f}", "GUARD((BeginX+EndX)/2)") + _cell("PinY", f"{(float(by) + float(ey)) / 2:.4f}", "GUARD((BeginY+EndY)/2)")
                + _cell("Width", f"{length:.4f}", "GUARD(SQRT((EndX-BeginX)^2+(EndY-BeginY)^2))") + _cell("Height", 0) + _cell("LocPinX", f"{length / 2:.4f}", "GUARD(Width*0.5)") + _cell("LocPinY", 0)
                + _cell("Angle", f"{math.atan2(dy, dx):.6f}", "GUARD(ATAN2(EndY-BeginY,EndX-BeginX))")
                + _cell("BeginX", bx, f"Sheet.{begin_id}!PinX") + _cell("BeginY", by, f"Sheet.{begin_id}!PinY") + _cell("EndX", ex, f"Sheet.{end_id}!PinX") + _cell("EndY", ey, f"Sheet.{end_id}!PinY")
                + _cell("ObjType", 2) + _cell("LineColor", colour) + _cell("LineWeight", _inch(weight_px)) + _cell("LinePattern", 2 if dashed else 1) + _cell("FillPattern", 0)
                + '<Section N="Geometry" IX="0">' + _cell("NoFill", 1) + _cell("NoLine", 0)
                + '<Row T="MoveTo" IX="1">' + _cell("X", 0) + _cell("Y", 0) + "</Row>" + '<Row T="LineTo" IX="2">' + _cell("X", f"{length:.4f}", "Width") + _cell("Y", 0) + "</Row></Section>")
        self.add(body, number)
        self.connects.append(f'<Connect FromSheet="{number}" FromCell="BeginX" FromPart="9" ToSheet="{begin_id}" ToCell="PinX" ToPart="3"/>')
        self.connects.append(f'<Connect FromSheet="{number}" FromCell="EndX" FromPart="12" ToSheet="{end_id}" ToCell="PinX" ToPart="3"/>')


def _rect_rows(w: float, h: float) -> str:
    corners = [(0, 0), (w, 0), (w, h), (0, h), (0, 0)]
    return "".join(f'<Row T="{"MoveTo" if i == 0 else "LineTo"}" IX="{i + 1}">' + _cell("X", _inch(x)) + _cell("Y", _inch(y)) + "</Row>" for i, (x, y) in enumerate(corners))


def _page_xml(page, graph, line_style: str) -> tuple[str, float, float]:
    graph = page.graph or graph
    width, height = max(page.width + 40, 600), max(page.height + 40, 400)
    out = _Page(height)
    for title, kind, x, y, w, h in page.zones:
        fill, border = zone_look(kind)
        out.box(x, y, w, h, fill, border, 1.5, dashed=True, rounded=14)
        out.label(x + 80, y + 4, [title], 150)
    for title, x, y, w, h in page.centers:                                   # the centre of the network: its units in one frame
        out.box(x, y, w, h, "#F2F8FC", "#005073", 2.0, dashed=True, rounded=14, no_fill=True)
        out.label(x + 110, y + 4, [title], 210)
    shape_of: dict[str, int] = {}                                            # diagram key -> Visio shape ID of its box, for the glued connectors
    for key, frame in page.pair_boxes.items():                               # a pair of switches in one frame
        shape_of[key] = out.box(frame.x, frame.y, frame.w, frame.h, "#F2F8FC", "#005073", 2.0, dashed=True, rounded=14, no_fill=True)
        out.label(frame.x + frame.w / 2, frame.y + 4, [frame.title], frame.w)
    for key in page.nodes:
        shape_of[key] = out.reserve()                                        # numbered now, drawn after the lines so that the boxes lie over them
    centre = {k: (p.x + NODE_W / 2, p.y + NODE_H / 2) for k, p in page.nodes.items()}
    centre.update({k: frame.centre for k, frame in page.pair_boxes.items()})
    for index, conn in enumerate(page.connections):
        if conn.a not in centre or conn.b not in centre:
            continue
        colour, wide, dashed = line_look(graph, conn, line_style)
        bends = page.routes.get(index) or []
        if not bends and conn.a in shape_of and conn.b in shape_of and conn.a != conn.b:
            out.glued(centre[conn.a], centre[conn.b], shape_of[conn.a], shape_of[conn.b], colour, wide, dashed)
        else:
            out.line([centre[conn.a], *bends, centre[conn.b]], colour, wide, dashed)
    for key, pos in page.nodes.items():
        node = graph.nodes[key]
        ghost = key in page.ghosts or not node.captured
        fill, stroke = ("#E6E6E6", "#7F7F7F") if ghost else ("#FAFAFA", "#005073")
        units = max(int(getattr(node, "stack_members", 1) or 1), 2 if getattr(node, "svl_domain", "") else 1)
        out.box(pos.x, pos.y, NODE_W, NODE_H, fill, stroke, 3.0, text=_ROLE_GLYPH.get(node.role_hint, "?") + (f" x{units}" if units > 1 else ""), rounded=6, shape_id=shape_of[key])
        out.label(pos.x + NODE_W / 2, pos.y + NODE_H + 4, [line for line in labels.node_lines(node) if line], 170)
    body = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<PageContents xmlns="{NS}" xmlns:r="{REL}" xml:space="preserve"><Shapes>' + "".join(out.shapes) + "</Shapes>" + (("<Connects>" + "".join(out.connects) + "</Connects>") if out.connects else "") + "</PageContents>"
    return body, width, height


def to_vsdx(pages: list, graph, line_style: str = "state", title: str = "Topology") -> bytes:
    """The .vsdx bytes for ``pages`` (the pages of a run); pages without device boxes (the F5 map) are left out."""
    drawn = [p for p in pages if p.view != "f5map" and p.nodes]
    parts: dict[str, str] = {}
    entries, overrides, rels = [], [], []
    for number, page in enumerate(drawn, 1):
        body, width, height = _page_xml(page, graph, line_style)
        parts[f"visio/pages/page{number}.xml"] = body
        overrides.append(f'<Override PartName="/visio/pages/page{number}.xml" ContentType="application/vnd.ms-visio.page+xml"/>')
        rels.append(f'<Relationship Id="rId{number}" Type="{VISIO_REL}/page" Target="page{number}.xml"/>')
        name = escape(page.name[:31], quote=True)
        entries.append(f'<Page ID="{number - 1}" NameU="{name}" Name="{name}"><PageSheet LineStyle="0" FillStyle="0" TextStyle="0">' + _cell("PageWidth", _inch(width)) + _cell("PageHeight", _inch(height))
                       + _cell("PageScale", 1) + _cell("DrawingScale", 1) + f'</PageSheet><Rel r:id="rId{number}"/></Page>')
    parts["visio/pages/pages.xml"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Pages xmlns="{NS}" xmlns:r="{REL}" xml:space="preserve">' + "".join(entries) + "</Pages>"
    parts["visio/pages/_rels/pages.xml.rels"] = f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<Relationships xmlns="{PKG_REL}">' + "".join(rels) + "</Relationships>"
    parts["visio/document.xml"] = DOCUMENT
    parts["visio/_rels/document.xml.rels"] = DOCUMENT_RELS
    parts["_rels/.rels"] = ROOT_RELS
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", CONTENT_TYPES.replace("{pages}", "".join(overrides)))
        for name in ("_rels/.rels", "visio/document.xml", "visio/_rels/document.xml.rels", "visio/pages/pages.xml", "visio/pages/_rels/pages.xml.rels"):
            archive.writestr(name, parts[name])
        for name, body in parts.items():
            if name.startswith("visio/pages/page") and name.endswith(".xml") and "pages.xml" not in name:
                archive.writestr(name, body)
    return buffer.getvalue()
