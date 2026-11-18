"""The DC / DRC demo brings its own layout: the Overview shows the HQ-DC box on the left and the DRC box on the right, and each site page is drawn tier by tier.

The layout is a plain draw.io file with a position per device; the tests read it back with the product's own reader and build the set with it.
"""

from __future__ import annotations

import re

from features.topology import demo
from features.topology.layout_io import read_layout
from features.topology.service import build_topology

BRANCHES = ("JKT", "SBY", "YOG", "MKS", "MED", "BAL")
FOLDER = demo.DEMO_DIR / "dcdrc"


def _layout() -> dict:
    return read_layout((FOLDER / "layout.drawio").read_bytes())


def _build(layout=None):
    files = [(p.name, p.read_text(encoding="utf-8")) for p in sorted(FOLDER.glob("*.txt"))]
    return build_topology(files, group="auto", collapse_endpoints=False, include_hosts=False, view="physical", group_endpoints=True, collapse_aps=False, layout=layout)


def test_the_layout_file_is_plain_and_names_only_devices_of_the_set():
    text = (FOLDER / "layout.drawio").read_text(encoding="utf-8")
    assert "<!DOCTYPE" not in text and "<!ENTITY" not in text and not re.search(r"password|secret|community", text, re.I)
    pages = _layout()
    assert set(pages) == {"Overview", "HQ-DC", "DRC", *BRANCHES}
    named = {p.stem for p in FOLDER.glob("*.txt")}
    for page, nodes in pages.items():
        for key in nodes:
            assert key in named or re.match(r"(HQ-DC|DRC|%s)-(PC|SRV|AP|PHONE)\d+$" % "|".join(BRANCHES), key), (page, key)


def test_the_two_site_pages_are_the_same_drawing_under_their_own_names():
    pages = _layout()
    hq, drc = pages["HQ-DC"], pages["DRC"]
    own = lambda page, prefix: {k[len(prefix) + 1:]: v for k, v in page.items() if k.startswith(prefix + "-")}          # noqa: E731
    assert own(hq, "HQ-DC") == own(drc, "DRC")                       # the copy sits where the original does, tier by tier
    assert {k for k in hq if not k.startswith("HQ-DC-")} == {"DRC-EDGE1", "DRC-EDGE2"}          # the far edge pair is drawn beside the near one, as a stub
    assert {k for k in drc if not k.startswith("DRC-")} == {"HQ-DC-EDGE1", "HQ-DC-EDGE2"}


def test_the_dc_zone_is_on_one_side_of_the_core_and_the_lan_zone_on_the_other():
    hq = _layout()["HQ-DC"]
    assert hq["HQ-DC-FGLAN1"][0] < hq["HQ-DC-CORE1"][0] < hq["HQ-DC-PADC1"][0]
    assert hq["HQ-DC-WANR1"][1] < hq["HQ-DC-EDGE1"][1] < hq["HQ-DC-CORE1"][1] < hq["HQ-DC-FGLAN1"][1] < hq["HQ-DC-ACC1"][1]
    for a, b in (("EDGE1", "EDGE2"), ("CORE1", "CORE2"), ("TOR1", "TOR2"), ("DS1", "DS2")):
        assert hq[f"HQ-DC-{a}"][1] == hq[f"HQ-DC-{b}"][1] and hq[f"HQ-DC-{a}"][0] < hq[f"HQ-DC-{b}"][0]


def test_building_with_the_layout_keeps_every_device_in_its_place():
    layout = _layout()
    built = _build(layout)
    pages = {p.name: p for p in built["pages"]}
    assert built["summary"]["layout_kept"] == sum(len(n) for n in layout.values())
    for name in ("HQ-DC", "DRC"):
        for key, (x, y) in layout[name].items():
            node = pages[name].nodes.get(key) or pages[name].ghosts.get(key)
            assert node is not None and (round(node.x), round(node.y)) == (round(x), round(y)), (name, key)
    assert _build()["summary"]["layout_kept"] == 0                   # without the layout the automatic arrangement stays as it was


def test_the_overview_has_the_dc_box_on_the_left_and_the_drc_box_on_the_right():
    overview = _build(_layout())["pages"][0]
    boxes = {b[0]: b for b in overview.boxes}
    assert overview.name == "Overview" and set(boxes) == {"HQ-DC", "DRC", *BRANCHES}
    dc, drc = boxes["HQ-DC"], boxes["DRC"]
    assert dc[1] < drc[1] and dc[1] + dc[3] <= drc[1]                # side by side, not overlapping
    assert abs(dc[2] - drc[2]) < 1 and abs(dc[3] - drc[3]) < 1       # the same height, on the same row
    assert all(b[2] >= dc[2] + dc[4] for k, b in boxes.items() if k in BRANCHES)          # the branches are below the two data-center sites
    centres = {k: (b[1] + b[3] / 2, b[2] + b[4] / 2) for k, b in boxes.items()}
    for key, (x, y) in _layout()["Overview"].items():
        site = "HQ-DC" if key.startswith("HQ-DC-") else "DRC" if key.startswith("DRC-") else None
        if site:
            box = boxes[site]
            assert box[1] <= x <= box[1] + box[3] and box[2] <= y <= box[2] + box[4], (key, site)
    assert centres["HQ-DC"][0] < centres["DRC"][0]
