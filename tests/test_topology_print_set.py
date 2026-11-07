"""Topology Builder: the A3 print set (one sheet per diagram page), the pack that carries it and the page that offers it."""

from __future__ import annotations

import io
import zipfile

import pytest

from features.topology.report import build_print_set


SVGS = [{"name": "Overview", "view": "physical", "svg": "<svg viewBox='0 0 5000 3000'><rect/></svg>"},
        {"name": "JKT-A02", "view": "l3over2", "svg": "<svg viewBox='0 0 800 600'><rect/></svg>"},
        {"name": "IP view", "view": "ip", "svg": "<svg viewBox='0 0 100 100'></svg>"}]


def test_every_diagram_page_is_one_a3_sheet_scaled_to_fit():
    html = build_print_set(SVGS, "Lab <DC>", "2026-11-03 10:00:00")
    assert html.count("<section class='sheet'>") == 3
    assert "size:A3 landscape" in html and ".fit svg{width:100%;height:100%" in html
    assert "<h1>Overview</h1>" in html and "L3 over L2 - sheet 2 of 3" in html and "IP view - sheet 3 of 3" in html
    assert "Lab &lt;DC&gt;" in html and "<script" not in html and "http" not in html.replace("http://www.w3.org", "")


def test_a_set_without_pages_is_an_empty_document():
    assert "<section" not in build_print_set([], "x")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    from features.topology import routes

    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_the_pack_and_the_downloads_carry_the_print_set(client):
    from features.topology.demo import list_sets, read_file

    files = [(io.BytesIO(read_file("edge", f["name"])), f["name"]) for f in next(s for s in list_sets() if s["id"] == "edge")["files"]]
    body = client.post("/topology/api/build", data={"files": files, "group": "none", "name": "Lab"}, content_type="multipart/form-data").get_json()
    assert body["ok"] and "topology-print-a3.html" in [d["name"] for d in body["downloads"]]
    pack = client.get(f"/topology/api/export/{body['export_id']}/keystone-topology-pack.zip")
    assert "keystone-topology-pack/topology-print-a3.html" in zipfile.ZipFile(io.BytesIO(pack.data)).namelist()
    sheet = client.get(f"/topology/api/export/{body['export_id']}/topology-print-a3.html")
    assert sheet.status_code == 200 and b"A3 landscape" in sheet.data
