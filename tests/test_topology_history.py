"""The topology history: list, details, pin, rename, delete and clear of the runs kept in exports/topology.

Synthetic data only: invented ids, device names and findings.  The folder's modified time is what the clean-up measures, so
every test that changes a run also checks that the time did not move.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import history  # noqa: E402
from features.topology.retention import prune_runs  # noqa: E402

DAY = 86400


def _document(devices: int = 3, links: int = 2, findings=(), created: str = "2026-10-30 14:05:09"):
    return {
        "devices": [{"device": f"SW{n}", "captured": "yes", "role": "switch" if n else "core", "vendor": "cisco" if n % 2 else "huawei"} for n in range(devices)],
        "links": [{"device_a": "SW0", "port_a": f"Eth1/{n}", "device_b": f"SW{n + 1}", "port_b": "Te1/1/1"} for n in range(links)],
        "hosts": [], "findings": list(findings),
        "build": {"created": created, "view": "all", "group_used": "none", "tool_version": "1.11.0", "provider_hints": 2},
    }


def _run(root: Path, number: int, age_days: float = 0.0, name: str = "", document=None, files: tuple[str, ...] = ()) -> Path:
    folder = root / f"{number:032x}"
    folder.mkdir()
    (folder / "topology.json").write_text(json.dumps(document or _document()), encoding="utf-8")
    if name:
        (folder / "_name.txt").write_text(name, encoding="utf-8")
    for extra in files:
        (folder / extra).write_bytes(b"x" * 10)
    stamp = time.time() - age_days * DAY
    os.utime(folder, (stamp, stamp))
    return folder


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    from features.topology import routes
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=20, TOPOLOGY_MAX_AGE_DAYS=30)
    return app.test_client()


# ---- list --------------------------------------------------------------------------------------------------------

def test_the_list_describes_each_run_newest_first(tmp_path, client):
    findings = [{"id": "TOP-001", "severity": "medium", "title": "Single uplink", "devices": ["SW1"]}, {"id": "TOP-002", "severity": "info", "title": "Note", "devices": []}]
    old = _run(tmp_path, 1, age_days=3, name="Lab-DC", document=_document(findings=findings))
    _run(tmp_path, 2, age_days=1, name="Lab-DC-2", document=_document(devices=5, links=4, created="2026-10-31 09:00:00"), files=("keystone-topology-pack.zip",))
    body = client.get("/topology/api/history").get_json()
    assert body["ok"] and [r["id"] for r in body["runs"]] == [f"{2:032x}", f"{1:032x}"]
    first = {r["id"]: r for r in body["runs"]}[f"{1:032x}"]
    assert first["devices"] == 3 and first["links"] == 2 and first["findings"] == 2 and first["findings_medium"] == 1
    assert first["built"] == "2026-10-30 14:05" and first["view"] == "all" and not first["pinned"] and first["size"] > 0
    assert body["keep"] == 20 and body["max_age_days"] == 30 and body["total_size"] >= first["size"]
    assert old.exists()


def test_the_summary_is_written_once_and_listing_does_not_move_the_age(tmp_path):
    folder = _run(tmp_path, 1, age_days=10)
    before = folder.stat().st_mtime
    rows = history.list_runs(tmp_path, 30)
    assert len(rows) == 1 and (folder / history.META_FILE).is_file()
    assert folder.stat().st_mtime == pytest.approx(before, abs=1)
    (folder / "topology.json").write_text("not json at all", encoding="utf-8")        # the summary is used from now on, topology.json is not read again
    assert history.list_runs(tmp_path, 30)[0]["devices"] == 3


def test_a_damaged_or_foreign_folder_is_skipped_not_fatal(tmp_path):
    _run(tmp_path, 1)
    broken = tmp_path / f"{2:032x}"
    broken.mkdir()
    (broken / "topology.json").write_text("{{{", encoding="utf-8")
    (tmp_path / "notes").mkdir()
    (tmp_path / "stray.txt").write_text("x", encoding="utf-8")
    rows = history.list_runs(tmp_path, 30)
    assert [r["id"] for r in rows] == [f"{1:032x}"]


def test_a_symbolic_link_is_ignored(tmp_path):
    real = _run(tmp_path, 1)
    link = tmp_path / f"{2:032x}"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    assert [r["id"] for r in history.list_runs(tmp_path, 30)] == [real.name]
    assert history.folder_of(tmp_path, link.name) is None


# ---- details -----------------------------------------------------------------------------------------------------

def test_details_list_the_files_that_exist_with_download_names(tmp_path, client):
    _run(tmp_path, 1, name="Lab-DC", files=("keystone-topology-pack.zip", "topology-report.html", "_trace.json"))
    detail = client.get(f"/topology/api/history/{1:032x}").get_json()["run"]
    names = [f["name"] for f in detail["files"]]
    assert "keystone-topology-pack.zip" in names and "topology-report.html" in names and "topology.json" in names and "_trace.json" not in names
    pack = next(f for f in detail["files"] if f["name"] == "keystone-topology-pack.zip")
    assert pack["filename"] == "Lab-DC-keystone-topology-pack.zip" and pack["url"] == f"/topology/api/export/{1:032x}/keystone-topology-pack.zip"
    assert detail["vendors"] == {"huawei": 2, "cisco": 1}
    assert client.get(pack["url"]).status_code == 200


def test_details_of_an_unknown_run_is_a_404(client):
    assert client.get(f"/topology/api/history/{9:032x}").status_code == 404
    assert client.get("/topology/api/history/not-a-run").status_code == 404


# ---- pin ---------------------------------------------------------------------------------------------------------

def test_a_pinned_run_survives_the_clean_up_and_is_not_counted(tmp_path, client):
    old = _run(tmp_path, 1, age_days=200)
    recent = [_run(tmp_path, n, age_days=n * 0.1) for n in range(2, 5)]
    assert client.post(f"/topology/api/history/{1:032x}/pin", json={"pinned": True}).get_json() == {"ok": True, "pinned": True}
    assert old.stat().st_mtime == pytest.approx(time.time() - 200 * DAY, abs=5)        # pinning did not make it look new
    prune_runs(tmp_path, keep=2, max_age_days=30)
    assert old.exists()
    assert sum(1 for r in recent if r.exists()) == 2                                 # two newest unpinned stay: the pin did not use a place
    client.post(f"/topology/api/history/{1:032x}/pin", json={"pinned": False})
    prune_runs(tmp_path, keep=2, max_age_days=30)
    assert not old.exists()


def test_the_number_of_pinned_runs_is_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "MAX_PINNED", 2)
    for n in (1, 2, 3):
        _run(tmp_path, n)
    assert history.set_pinned(tmp_path, f"{1:032x}", True)[0] and history.set_pinned(tmp_path, f"{2:032x}", True)[0]
    ok, message = history.set_pinned(tmp_path, f"{3:032x}", True)
    assert not ok and "At most 2" in message
    assert history.set_pinned(tmp_path, f"{1:032x}", True)[0]                        # pinning a pinned run again is fine


def test_pin_of_an_unknown_run_is_a_404(client):
    assert client.post(f"/topology/api/history/{7:032x}/pin", json={"pinned": True}).status_code == 404


# ---- rename ------------------------------------------------------------------------------------------------------

def test_rename_follows_the_name_rules_and_keeps_the_age(tmp_path, client):
    folder = _run(tmp_path, 1, age_days=12, name="old")
    stamp = folder.stat().st_mtime
    body = client.post(f"/topology/api/history/{1:032x}/rename", json={"name": "  Lab DC / Jakarta <b>1</b>  "}).get_json()
    assert body["ok"] and body["name"] == "Lab-DC-Jakarta-b1b"
    assert (folder / "_name.txt").read_text(encoding="utf-8") == "Lab-DC-Jakarta-b1b"
    assert folder.stat().st_mtime == pytest.approx(stamp, abs=1)
    assert client.post(f"/topology/api/history/{1:032x}/rename", json={"name": "x" * 200}).get_json()["name"] == "x" * 60
    assert client.post(f"/topology/api/history/{1:032x}/rename", json={}).get_json()["name"] == ""


# ---- delete and clear --------------------------------------------------------------------------------------------

def test_delete_removes_one_run_and_only_that_run(tmp_path, client):
    keep, gone = _run(tmp_path, 1), _run(tmp_path, 2)
    assert client.delete(f"/topology/api/history/{2:032x}").get_json() == {"ok": True}
    assert keep.exists() and not gone.exists()
    assert client.delete(f"/topology/api/history/{2:032x}").status_code == 404


@pytest.mark.parametrize("bad", ["not-hex", "..", "G" * 32, "a" * 31, "A" * 32])
def test_an_id_that_is_not_a_run_id_never_reaches_the_disk(tmp_path, client, bad):
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me", encoding="utf-8")
    assert client.delete(f"/topology/api/history/{bad}").status_code in (404, 405)
    assert client.post(f"/topology/api/history/{bad}/pin", json={"pinned": True}).status_code in (404, 405)
    assert client.post(f"/topology/api/history/{bad}/rename", json={"name": "x"}).status_code in (404, 405)
    assert victim.read_text(encoding="utf-8") == "keep me"


def test_clear_keeps_pinned_and_unfinished_builds(tmp_path, client):
    plain, pinned = _run(tmp_path, 1, age_days=1), _run(tmp_path, 2, age_days=1)
    history.set_pinned(tmp_path, pinned.name, True)
    unfinished = tmp_path / f"{3:032x}"
    unfinished.mkdir()
    (unfinished / "devices.csv").write_text("a", encoding="utf-8")                   # a build that has not written its summary yet
    body = client.post("/topology/api/history/clear", json={}).get_json()
    assert body == {"ok": True, "removed": 1} and not plain.exists() and pinned.exists() and unfinished.exists()
    assert client.post("/topology/api/history/clear", json={"include_pinned": True}).get_json()["removed"] == 1
    assert not pinned.exists() and unfinished.exists()


def test_a_row_says_whether_the_documentation_pack_can_be_downloaded(tmp_path, client):
    with_pack, without = _run(tmp_path, 1, files=("keystone-topology-pack.zip",)), _run(tmp_path, 2)
    rows = {r["id"]: r for r in client.get("/topology/api/history").get_json()["runs"]}
    assert rows[with_pack.name]["has_pack"] is True and rows[without.name]["has_pack"] is False
    assert client.get(f"/topology/api/export/{with_pack.name}/keystone-topology-pack.zip").status_code == 200


def test_reading_the_list_applies_the_retention_rules_even_when_nothing_was_built(tmp_path, client):
    """Keystone can stay open for weeks; the list must not show a run that the rules say is gone."""
    old, young, pinned_old = _run(tmp_path, 1, age_days=45), _run(tmp_path, 2, age_days=2), _run(tmp_path, 3, age_days=60)
    history.set_pinned(tmp_path, pinned_old.name, True)
    ids = [r["id"] for r in client.get("/topology/api/history").get_json()["runs"]]
    assert young.name in ids and pinned_old.name in ids and old.name not in ids
    assert not old.exists() and young.exists() and pinned_old.exists()


# ---- the build writes the summary; the start-up sweep leaves runs alone ------------------------------------------

def test_a_real_build_appears_in_the_history_with_its_summary(tmp_path, client):
    from topology_samples import lab_dc
    files = {"files": [(io.BytesIO(text.encode()), name) for name, text in lab_dc().items()], "group": "none", "name": "Lab DC"}
    built = client.post("/topology/api/build", data=files, content_type="multipart/form-data").get_json()
    assert built["ok"]
    assert (tmp_path / built["export_id"] / history.META_FILE).is_file()
    runs = client.get("/topology/api/history").get_json()["runs"]
    assert [r["id"] for r in runs] == [built["export_id"]] and runs[0]["name"] == "Lab-DC"
    assert runs[0]["devices"] >= 2 and runs[0]["links"] >= 1 and runs[0]["size"] > 1000
    detail = client.get(f"/topology/api/history/{built['export_id']}").get_json()["run"]
    assert {"keystone-topology-pack.zip", "topology-report.html", "topology.drawio"} <= {f["name"] for f in detail["files"]}


def test_the_start_up_sweep_does_not_touch_the_topology_runs(tmp_path):
    from app import _sweep_directory
    runs = tmp_path / "topology"
    run = runs / f"{1:032x}"
    run.mkdir(parents=True)
    (run / "_pinned").write_text("pinned", encoding="utf-8")
    other = tmp_path / "other"
    other.mkdir()
    (other / "stale.txt").write_text("x", encoding="utf-8")
    old = time.time() - 90 * DAY
    for path in (run / "_pinned", run, other / "stale.txt"):
        os.utime(path, (old, old))
    _sweep_directory(tmp_path, time.time() - 30 * DAY, skip=(runs,))
    assert (run / "_pinned").exists() and not (other / "stale.txt").exists()


# ---- the page ------------------------------------------------------------------------------------------------------

def test_the_page_offers_the_history_beside_the_name(client):
    page = client.get("/topology").get_data(as_text=True)
    assert 'data-role="history-open"' in page and "Topology history" in page and 'data-role="history-dialog"' in page
    assert "topology-history.js" in page
    assert page.index('data-role="name"') < page.index('data-role="history-open"') < page.index("Options")
    assert "newest ten" not in page and "seven days" not in page


def test_the_scripts_talk_to_each_other_through_the_events():
    base = Path(__file__).resolve().parents[1] / "static" / "js"
    history_js = (base / "topology-history.js").read_text(encoding="utf-8")
    assert "tp:compare" in history_js and "tp:runbook" in history_js and "tp:built" in history_js
    assert "tp:compare" in (base / "topology-diff.js").read_text(encoding="utf-8")
    assert "tp:runbook" in (base / "topology-runbook.js").read_text(encoding="utf-8")
    assert "tp:built" in (base / "topology.js").read_text(encoding="utf-8")


def test_the_defaults_are_twenty_runs_and_thirty_days():
    from features.topology import retention
    import app
    assert (retention.DEFAULT_KEEP, retention.DEFAULT_MAX_AGE_DAYS) == (20, 30)
    assert (app.TOPOLOGY_KEEP_RUNS, app.TOPOLOGY_MAX_AGE_DAYS) == (20, 30)


def test_only_a_run_folder_can_be_touched_even_when_another_folder_exists(tmp_path):
    other = tmp_path / "notes"
    other.mkdir()
    (other / "keep.txt").write_text("keep", encoding="utf-8")
    outside = tmp_path.parent / "outside-the-exports"
    outside.mkdir(exist_ok=True)
    for bad in ("notes", "..", "../outside-the-exports", "G" * 32, ""):
        assert history.folder_of(tmp_path, bad) is None
        assert history.delete(tmp_path, bad)[0] is False
        assert history.rename(tmp_path, bad, "x")[0] is False
        assert history.set_pinned(tmp_path, bad, True)[0] is False
    assert (other / "keep.txt").exists() and outside.exists()
    assert history.clear(tmp_path) == [] and other.exists()                  # clear only ever removes run folders
