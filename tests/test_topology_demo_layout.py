"""The multi-site demo brings the layout of its diagram (the file "Keep my layout" reads), so the head quarter page is drawn tier by tier.

The layout is a plain draw.io file with a position per device; the tests read it back with the product's own reader and build the set with it.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from features.topology import demo, routes
from features.topology.layout_io import read_layout
from features.topology.service import build_topology

SITES = ("JKT", "SBY", "YOG", "MKS", "MED", "BAL")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _captures() -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / "multisite").glob("*.txt"))]


def _layout() -> dict:
    return read_layout((demo.DEMO_DIR / "multisite" / "layout.drawio").read_bytes())


def _build(layout=None) -> dict:
    return build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="physical", group_endpoints=True, collapse_aps=False, layout=layout)


def test_only_the_multisite_set_declares_a_layout_and_serves_it(client):
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    assert sets["multisite"]["layout"] == "layout.drawio"
    assert all(sets[i]["layout"] == "" for i in ("before", "after", "edge"))
    answer = client.get("/topology/api/demo/multisite/layout.drawio")
    assert answer.status_code == 200 and answer.data.lstrip().startswith(b"<?xml") and b"<mxfile" in answer.data
    assert client.get("/topology/api/demo/before/layout.drawio").status_code == 404          # a set serves only the layout it declares
    assert demo.read_file("multisite", "../layout.drawio") is None and demo.read_file("multisite", "layout.drawio.bak") is None


def test_the_layout_file_is_a_plain_drawio_file_without_anything_but_positions():
    text = (demo.DEMO_DIR / "multisite" / "layout.drawio").read_text(encoding="utf-8")
    assert "<!DOCTYPE" not in text and "<!ENTITY" not in text and not re.search(r"password|secret|community", text, re.I)
    pages = _layout()
    assert set(pages) == {"Overview", "HQ", *SITES}
    named = {p.stem for p in (demo.DEMO_DIR / "multisite").glob("*.txt")}
    for page, nodes in pages.items():
        for key in nodes:
            assert key in named or re.match(r"(HQ|%s)-(PC|SRV|AP|PHONE)\d+$" % "|".join(SITES), key), (page, key)


def test_the_head_quarter_is_drawn_in_tiers_and_pairs_stand_side_by_side():
    hq = _layout()["HQ"]
    assert len(hq) == 28                                            # 20 captured devices and the 4 PCs and 4 servers that hang off the access switches
    row = lambda *names: {round(hq[n][1]) for n in names}           # noqa: E731
    tiers = [row("HQ-WANR1", "HQ-WANR2", "HQ-FGWAN1", "HQ-FGWAN2"), row("HQ-EDGE1", "HQ-EDGE2"), row("HQ-CORE1", "HQ-CORE2"),
             row("HQ-FGLAN1", "HQ-FGLAN2", "HQ-PADC1", "HQ-PADC2"), row("HQ-SF1", "HQ-SF2", "HQ-DS1", "HQ-DS2"), row("HQ-ACC1", "HQ-ACC2", "HQ-TOR1", "HQ-TOR2"),
             row("HQ-PC1", "HQ-PC2", "HQ-PC3", "HQ-PC4", "HQ-SRV1", "HQ-SRV2", "HQ-SRV3", "HQ-SRV4")]
    assert all(len(t) == 1 for t in tiers)                          # one row per tier
    ys = [next(iter(t)) for t in tiers]
    assert ys == sorted(ys) and len(set(ys)) == 7                   # outside on top, then edge, core, the two zones, their second tier, the end points
    for a, b in (("HQ-WANR1", "HQ-WANR2"), ("HQ-FGWAN1", "HQ-FGWAN2"), ("HQ-EDGE1", "HQ-EDGE2"), ("HQ-CORE1", "HQ-CORE2"), ("HQ-FGLAN1", "HQ-FGLAN2"),
                 ("HQ-PADC1", "HQ-PADC2"), ("HQ-SF1", "HQ-SF2"), ("HQ-DS1", "HQ-DS2"), ("HQ-ACC1", "HQ-ACC2"), ("HQ-TOR1", "HQ-TOR2")):
        assert hq[a][1] == hq[b][1] and 0 < hq[b][0] - hq[a][0] <= 520, (a, b)
    assert hq["HQ-CORE1"][0] == hq["HQ-EDGE1"][0] and hq["HQ-FGLAN1"][0] < hq["HQ-CORE1"][0] < hq["HQ-PADC1"][0]      # the LAN zone on one side of the core, the server farm on the other
    assert hq["HQ-PC1"][0] < hq["HQ-ACC1"][0] < hq["HQ-PC2"][0] and hq["HQ-SRV1"][0] < hq["HQ-TOR1"][0] < hq["HQ-SRV3"][0]


def test_building_with_the_layout_keeps_every_device_in_its_place():
    layout = _layout()
    built = _build(layout)
    pages = {p.name: p for p in built["pages"]}
    assert built["summary"]["layout_kept"] == sum(len(n) for n in layout.values())
    for key, (x, y) in layout["HQ"].items():
        assert (round(pages["HQ"].nodes[key].x), round(pages["HQ"].nodes[key].y)) == (round(x), round(y)), key
    assert not pages["HQ"].ghosts and len(pages["HQ"].nodes) == 28
    plain = _build()
    assert plain["summary"]["layout_kept"] == 0                      # without the layout the automatic arrangement stays as it was


def test_the_site_boxes_of_the_overview_hold_the_frames_of_their_end_points():
    built = _build(_layout())
    overview = built["pages"][0]
    assert overview.name == "Overview" and len(overview.boxes) == 7
    for parent, (rect, _) in ((p, f) for p, f in _frames(overview).items()):
        x0, y0, x1, y1 = rect
        holders = [b for b in overview.boxes if b[1] <= x0 and b[2] <= y0 and b[1] + b[3] >= x1 and b[2] + b[4] >= y1]
        assert holders, (parent, rect)


def _frames(page) -> dict:
    out = {}
    for name, x, y, w, h in page.end_boxes:
        out[name] = ((x, y, x + w, y + h), None)
    return out


def test_the_demo_page_scripts_hand_the_layout_over():
    base = Path(__file__).resolve().parents[1] / "static" / "js"
    demo_js = (base / "topology-demo.js").read_text(encoding="utf-8")
    page_js = (base / "topology.js").read_text(encoding="utf-8")
    assert "set.layout" in demo_js and "layout," in demo_js
    assert "d.layout" in page_js and "carrier" in page_js
