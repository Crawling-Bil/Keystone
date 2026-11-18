"""Topology history "Download all" and "Open again all".

Synthetic data only: invented run ids, names and pack bytes.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from features.topology import history, routes  # noqa: E402

JS = Path(__file__).resolve().parents[1] / "static" / "js"
PACK = "keystone-topology-pack.zip"


def _document(created: str = "2026-10-30 14:05:09"):
    return {"devices": [{"device": "YY-SW1", "captured": "yes", "role": "core", "vendor": "cisco"}], "links": [], "hosts": [], "findings": [],
            "build": {"created": created, "view": "all", "group_used": "none", "tool_version": "3.0.0"}}


def _run(root: Path, number: int, name: str = "", pack: bytes | None = b"PACK", note: str = "", pinned: bool = False, created: str | None = None) -> Path:
    folder = root / f"{number:032x}"
    folder.mkdir()
    (folder / "topology.json").write_text(json.dumps(_document(created or f"2026-10-{number:02d} 10:00:00")), encoding="utf-8")
    if name:
        (folder / "_name.txt").write_text(name, encoding="utf-8")
    if note:
        (folder / "_note.txt").write_text(note, encoding="utf-8")
    if pinned:
        (folder / "_pinned").write_text("", encoding="utf-8")
    if pack is not None:
        (folder / PACK).write_bytes(pack)
        (folder / f"{PACK}.sha256").write_text(f"{hashlib.sha256(pack).hexdigest()}  {PACK}\n", encoding="ascii")
    stamp = time.time() - number * 60
    os.utime(folder, (stamp, stamp))
    return folder


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=40, TOPOLOGY_MAX_AGE_DAYS=30)
    return app.test_client()


def _zip(response) -> zipfile.ZipFile:
    assert response.status_code == 200 and response.mimetype == "application/zip"
    return zipfile.ZipFile(io.BytesIO(response.data))


def test_every_pack_is_in_one_zip_with_an_index(client, tmp_path):
    _run(tmp_path, 1, "Lab-A", b"AAA")
    _run(tmp_path, 2, "Lab-B", b"BBBB")
    response = client.get("/topology/api/history/download-all")
    archive = _zip(response)
    names = archive.namelist()
    packs = [n for n in names if n.endswith("/" + PACK)]
    assert len(packs) == 2 and "runs.csv" in names
    assert {archive.read(n) for n in packs} == {b"AAA", b"BBBB"}
    assert response.headers["X-Keystone-Packs"] == "2" and response.headers["X-Keystone-Skipped"] == "0"
    assert "attachment" in response.headers["Content-Disposition"] and "Keystone-topology-history-" in response.headers["Content-Disposition"]
    assert archive.testzip() is None


def test_each_run_gets_its_own_folder_named_by_date_name_and_id(client, tmp_path):
    _run(tmp_path, 1, "Lab A/../x", b"A")
    _run(tmp_path, 2, "Lab A/../x", b"B")                       # the same name twice stays apart by the id
    names = _zip(client.get("/topology/api/history/download-all")).namelist()
    folders = sorted({n.split("/")[0] for n in names if "/" in n})
    assert len(folders) == 2 and all(f not in ("", ".", "..") and f[0].isdigit() for f in folders)     # a name can never become a path step
    assert folders[0] != folders[1]
    assert all(set(f) <= set("0123456789abcdefABCDEFGHIJKLMNOPQRSTUVWXYZ-_.xyzghijklmnopqrstuvw") for f in folders)


def test_the_sha256_line_travels_with_the_pack_and_matches(client, tmp_path):
    _run(tmp_path, 1, "Lab", b"PAYLOAD")
    archive = _zip(client.get("/topology/api/history/download-all"))
    sums = [n for n in archive.namelist() if n.endswith(".sha256")]
    pack = next(n for n in archive.namelist() if n.endswith("/" + PACK))
    assert len(sums) == 1 and hashlib.sha256(archive.read(pack)).hexdigest() in archive.read(sums[0]).decode()


def test_runs_without_a_pack_are_listed_not_zipped(client, tmp_path):
    _run(tmp_path, 1, "Has-pack", b"A")
    _run(tmp_path, 2, "No-pack", None)
    response = client.get("/topology/api/history/download-all")
    archive = _zip(response)
    assert len([n for n in archive.namelist() if n.endswith("/" + PACK)]) == 1
    assert response.headers["X-Keystone-Packs"] == "1" and response.headers["X-Keystone-Skipped"] == "1"
    rows = list(csv.DictReader(io.StringIO(archive.read("runs.csv").decode("utf-8"))))
    by_name = {r["name"]: r for r in rows}
    assert by_name["Has-pack"]["in_this_zip"] == "yes" and by_name["Has-pack"]["pack_sha256"]
    assert by_name["No-pack"]["in_this_zip"] == "no pack kept" and by_name["No-pack"]["folder"] == "" and by_name["No-pack"]["pack_sha256"] == ""


def test_ids_limit_the_zip_to_the_runs_shown(client, tmp_path):
    first, second, third = (_run(tmp_path, n, f"R{n}", f"P{n}".encode()) for n in (1, 2, 3))
    response = client.get(f"/topology/api/history/download-all?ids={first.name},{third.name}")
    archive = _zip(response)
    assert {archive.read(n) for n in archive.namelist() if n.endswith("/" + PACK)} == {b"P1", b"P3"}
    assert response.headers["X-Keystone-Packs"] == "2"


def test_a_bad_id_is_refused_and_an_unknown_one_is_ignored(client, tmp_path):
    folder = _run(tmp_path, 1, "R1", b"P1")
    assert client.get("/topology/api/history/download-all?ids=../../etc/passwd").status_code == 400
    assert client.get(f"/topology/api/history/download-all?ids={folder.name},{'f' * 32}").status_code == 200
    missing = client.get(f"/topology/api/history/download-all?ids={'f' * 32}")
    assert missing.status_code == 404 and not missing.get_json()["ok"]


def test_nothing_to_download_says_so(client, tmp_path):
    assert client.get("/topology/api/history/download-all").status_code == 404           # no runs at all
    _run(tmp_path, 1, "Old", None)
    body = client.get("/topology/api/history/download-all")
    assert body.status_code == 404 and "pack" in body.get_json()["error"]


def test_the_index_cannot_run_a_formula_in_excel(client, tmp_path):
    _run(tmp_path, 1, "Lab", b"A", note="=HYPERLINK(\"http://x\")")
    archive = _zip(client.get("/topology/api/history/download-all"))
    row = next(csv.DictReader(io.StringIO(archive.read("runs.csv").decode("utf-8"))))
    assert row["note"].startswith("'=")


def test_a_symbolic_link_pack_is_not_followed(client, tmp_path):
    folder = _run(tmp_path, 1, "Lab", None)
    secret = tmp_path.parent / "outside-secret.txt"
    secret.write_bytes(b"SECRET")
    try:
        (folder / PACK).symlink_to(secret)
    except OSError:
        pytest.skip("no symbolic links here")
    response = client.get("/topology/api/history/download-all")
    assert response.status_code == 404                                                     # the only run has no real pack
    assert b"SECRET" not in response.data


def test_a_pinned_run_is_included_and_marked(client, tmp_path):
    _run(tmp_path, 1, "Keep-me", b"A", pinned=True)
    archive = _zip(client.get("/topology/api/history/download-all"))
    row = next(csv.DictReader(io.StringIO(archive.read("runs.csv").decode("utf-8"))))
    assert row["pinned"] == "yes"


def test_the_download_changes_nothing_on_disk(client, tmp_path):
    folder = _run(tmp_path, 1, "Lab", b"A")
    client.get("/topology/api/history")                          # listing writes the small _meta.json of an older run once
    before = (sorted(p.name for p in folder.iterdir()), folder.stat().st_mtime)
    client.get("/topology/api/history/download-all")
    assert (sorted(p.name for p in folder.iterdir()), folder.stat().st_mtime) == before


def test_the_buttons_and_the_new_tab_address_are_wired():
    history_js = (JS / "topology-history.js").read_text(encoding="utf-8")
    assert 'data-act="open-all"' in history_js and 'data-act="download-all"' in history_js and "/api/history/download-all" in history_js
    assert "window.open(tabUrl(run.id)" in history_js and "?open=" in history_js and "tabsOpened" in history_js
    main = (JS / "topology.js").read_text(encoding="utf-8")
    assert 'get("open")' in main and "[a-f0-9]{32}" in main and '"tp:open"' in main
    template = (JS.parent.parent / "templates" / "topology.html").read_text(encoding="utf-8")
    assert 'data-role="history-all-box"' in template


def test_two_runs_with_one_date_one_name_and_one_id_start_do_not_overwrite_each_other(client, tmp_path):
    _run(tmp_path, 1, "Same", b"ONE", created="2026-10-05 09:00:00")
    _run(tmp_path, 2, "Same", b"TWO", created="2026-10-05 09:00:00")          # ids differ only after the eighth character
    archive = _zip(client.get("/topology/api/history/download-all"))
    packs = [n for n in archive.namelist() if n.endswith("/" + PACK)]
    assert len(packs) == 2 and {archive.read(n) for n in packs} == {b"ONE", b"TWO"}
    assert len(archive.namelist()) == len(set(archive.namelist()))
