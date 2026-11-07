"""Topology history "Open again": the answer of a build is kept next to its files and shown again without building.

Synthetic captures only (the invented data-centre set of tests/topology_samples.py)."""

from __future__ import annotations

import gzip
import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import demo, history, routes  # noqa: E402

JS = Path(__file__).resolve().parents[1] / "static" / "js"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=20, TOPOLOGY_MAX_AGE_DAYS=30)
    return app.test_client()


def _build(client, set_id="before") -> dict:
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    files = [(io.BytesIO(client.get(f"/topology/api/demo/{set_id}/{f['name']}").data), f["name"]) for f in sets[set_id]["files"]]
    response = client.post("/topology/api/build", data={"files": files, "name": "Open again test"}, content_type="multipart/form-data")
    body = response.get_json()
    assert response.status_code == 200 and body["ok"]
    return body


def test_a_build_keeps_its_answer(client, tmp_path):
    body = _build(client)
    stored = tmp_path / body["export_id"] / history.RESULT_FILE
    assert stored.is_file() and stored.stat().st_size > 1000
    assert json.loads(gzip.decompress(stored.read_bytes()))["export_id"] == body["export_id"]
    assert not list(tmp_path.glob("*/*.tmp"))


def test_open_again_returns_exactly_what_the_build_returned(client):
    body = _build(client)
    again = client.get(f"/topology/api/history/{body['export_id']}/result")
    assert again.status_code == 200
    assert again.get_json() == body                      # the page renders both the same way


def test_the_list_says_which_runs_can_be_opened(client, tmp_path):
    body = _build(client)
    rows = client.get("/topology/api/history").get_json()["runs"]
    assert [r["has_result"] for r in rows] == [True]
    (tmp_path / body["export_id"] / history.RESULT_FILE).unlink()          # a run built before this was kept
    assert client.get("/topology/api/history").get_json()["runs"][0]["has_result"] is False
    gone = client.get(f"/topology/api/history/{body['export_id']}/result")
    assert gone.status_code == 404 and "Build it again" in gone.get_json()["error"]


def test_unknown_and_unsafe_ids_are_refused(client, tmp_path):
    for run_id in ("0" * 32, "not-a-run", "..", "%2e%2e", "A" * 32):
        assert client.get(f"/topology/api/history/{run_id}/result").status_code == 404
    assert history.read_result(tmp_path, "../etc") is None


def test_a_damaged_or_foreign_result_is_not_shown(client, tmp_path):
    body = _build(client)
    path = tmp_path / body["export_id"] / history.RESULT_FILE
    path.write_bytes(b"not gzip")
    assert history.read_result(tmp_path, body["export_id"]) is None
    path.write_bytes(gzip.compress(b"[1, 2]"))
    assert history.read_result(tmp_path, body["export_id"]) is None
    path.write_bytes(gzip.compress(json.dumps({"ok": True, "export_id": "f" * 32}).encode()))
    assert history.read_result(tmp_path, body["export_id"]) is None             # a result copied from another run is refused
    path.write_bytes(gzip.compress(b"{"))
    assert client.get(f"/topology/api/history/{body['export_id']}/result").status_code == 404


def test_an_oversized_result_is_not_read_back(client, tmp_path, monkeypatch):
    body = _build(client)
    monkeypatch.setattr(history, "MAX_RESULT_BYTES", 1000)
    assert history.read_result(tmp_path, body["export_id"]) is None


def test_the_result_file_is_not_a_download(client):
    body = _build(client)
    assert client.get(f"/topology/api/export/{body['export_id']}/{history.RESULT_FILE}").status_code == 404
    assert history.RESULT_FILE not in routes.EXPORT_NAMES and history.RESULT_FILE not in routes.HISTORY_FILES


def test_a_failed_write_does_not_stop_the_build(client, tmp_path, monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(history.gzip, "open", boom)
    body = _build(client)
    assert body["ok"] and not (tmp_path / body["export_id"] / history.RESULT_FILE).exists()
    assert client.get("/topology/api/history").get_json()["runs"][0]["has_result"] is False
    assert not list(tmp_path.glob("*/*.tmp"))


def test_deleting_a_run_removes_its_result(client, tmp_path):
    body = _build(client)
    assert client.delete(f"/topology/api/history/{body['export_id']}").get_json()["ok"]
    assert not (tmp_path / body["export_id"]).exists()
    assert client.get(f"/topology/api/history/{body['export_id']}/result").status_code == 404


def test_the_buttons_and_events_are_wired():
    history_js = (JS / "topology-history.js").read_text(encoding="utf-8")
    assert 'data-act="open"' in history_js and "Open again" in history_js and "run.has_result" in history_js and '"tp:open"' in history_js
    main = (JS / "topology.js").read_text(encoding="utf-8")
    assert '"tp:open"' in main and "/api/history/${encodeURIComponent(id)}/result" in main and '"tp:showview"' in main
