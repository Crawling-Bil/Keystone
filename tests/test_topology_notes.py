"""Topology history: a note per run, and the search / filter / sort controls of the panel.

Synthetic captures only (the invented data-centre set of tests/topology_samples.py)."""

from __future__ import annotations

import io
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import history, routes  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "topology-history.js").read_text(encoding="utf-8")
HTML = (ROOT / "templates" / "topology.html").read_text(encoding="utf-8")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=20, TOPOLOGY_MAX_AGE_DAYS=30)
    return app.test_client()


def _build(client, set_id="before", name="Notes test") -> str:
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    files = [(io.BytesIO(client.get(f"/topology/api/demo/{set_id}/{f['name']}").data), f["name"]) for f in sets[set_id]["files"]]
    response = client.post("/topology/api/build", data={"files": files, "name": name}, content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["export_id"]


def _note(client, run_id, text):
    return client.post(f"/topology/api/history/{run_id}/note", json={"note": text})


# ---- the note -------------------------------------------------------------------------------------------------------

def test_clean_note_keeps_three_short_lines_and_drops_control_characters():
    assert history.clean_note("  before the window \r\n\r\nafter\x00 the swap\n3\n4\n5 ") == "before the window\nafter the swap\n3"
    assert history.clean_note(None) == "" and history.clean_note("   \n \n") == ""
    assert len(history.clean_note("x" * 1000)) == history.MAX_NOTE


def test_a_note_is_saved_listed_and_removed(client, tmp_path):
    run_id = _build(client)
    assert client.get("/topology/api/history").get_json()["runs"][0]["note"] == ""
    response = _note(client, run_id, "Before the core swap")
    assert response.get_json() == {"ok": True, "note": "Before the core swap"}
    assert (tmp_path / run_id / history.NOTE_FILE).read_text(encoding="utf-8") == "Before the core swap"
    assert client.get("/topology/api/history").get_json()["runs"][0]["note"] == "Before the core swap"
    assert client.get(f"/topology/api/history/{run_id}").get_json()["run"]["note"] == "Before the core swap"
    assert _note(client, run_id, "  ").get_json() == {"ok": True, "note": ""}
    assert not (tmp_path / run_id / history.NOTE_FILE).exists()
    assert client.get("/topology/api/history").get_json()["runs"][0]["note"] == ""


def test_a_note_does_not_make_an_old_run_look_new(client, tmp_path):
    run_id = _build(client)
    folder = tmp_path / run_id
    old = time.time() - 20 * 86400
    os.utime(folder, (old, old))
    _note(client, run_id, "kept for the audit")
    assert abs(folder.stat().st_mtime - old) < 2                       # the clean-up counts age from this time
    _note(client, run_id, "")
    assert abs(folder.stat().st_mtime - old) < 2


def test_a_note_survives_pin_and_rename_and_goes_with_the_run(client, tmp_path):
    run_id = _build(client)
    _note(client, run_id, "baseline for Q4")
    client.post(f"/topology/api/history/{run_id}/pin", json={"pinned": True})
    client.post(f"/topology/api/history/{run_id}/rename", json={"name": "q4"})
    assert client.get("/topology/api/history").get_json()["runs"][0]["note"] == "baseline for Q4"
    assert client.delete(f"/topology/api/history/{run_id}").get_json()["ok"]
    assert not (tmp_path / run_id).exists()


def test_a_note_for_a_run_that_is_gone_is_a_404_and_a_bad_id_is_refused(client):
    assert _note(client, "0" * 32, "x").status_code == 404
    assert _note(client, "../../etc", "x").status_code in (404, 405)


def test_a_note_is_not_in_the_documentation_pack(client, tmp_path):
    import zipfile
    run_id = _build(client)
    _note(client, run_id, "SECRET-NOTE-MARKER")
    pack = tmp_path / run_id / "keystone-topology-pack.zip"
    with zipfile.ZipFile(pack) as z:
        assert not any(b"SECRET-NOTE-MARKER" in z.read(n) for n in z.namelist())


def test_the_note_text_is_never_read_as_markup(client, tmp_path):
    run_id = _build(client)
    assert _note(client, run_id, "<img src=x onerror=alert(1)>").get_json()["note"] == "<img src=x onerror=alert(1)>"
    assert "esc(run.note)" in JS and "${run.note}" not in JS.replace("${run.note ? ", "")        # the page escapes it on the way out


# ---- the panel --------------------------------------------------------------------------------------------------------

def test_the_panel_has_a_filter_and_a_sort_and_a_note_editor():
    for role in ("history-filter", "history-sort"):
        assert f'data-role="{role}"' in HTML
    for value in ("all", "pinned", "unpinned", "medium", "noted", "newest", "oldest", "name", "findings", "devices"):
        assert f'<option value="{value}"' in HTML and f"{value}:" in JS
    assert 'data-act="note"' in JS and 'data-act="note-form"' in JS and 'maxlength="300"' in JS


def test_the_search_looks_at_the_note_too():
    assert "${r.note || \"\"}" in JS
