"""Audit evidence in the pack: SHA-256 manifest, capture hashes, control table, pack hash in the history.

Synthetic captures only (the invented data-centre demo sets)."""

from __future__ import annotations

import csv
import hashlib
import io
import re
import zipfile
from pathlib import Path

import pytest

from features.topology import evidence, history, routes

SRC = Path(__file__).resolve().parents[1] / "features" / "topology"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    monkeypatch.setattr(routes, "EXPORT_DIR", tmp_path)
    app = create_app()
    app.config.update(TESTING=True, TOPOLOGY_KEEP_RUNS=20, TOPOLOGY_MAX_AGE_DAYS=30)
    return app.test_client()


def _build(client, anonymize=False, set_id="before", rename=False):
    sets = {s["id"]: s for s in client.get("/topology/api/demo").get_json()["sets"]}
    names = [f["name"] for f in sets[set_id]["files"]]
    texts = {n: client.get(f"/topology/api/demo/{set_id}/{n}").data for n in names}
    if rename:                                   # the demo files are named after their devices: give them names that belong to nobody's pseudonym
        texts = {f"acmebank-capture-{i}.txt": raw for i, raw in enumerate(texts.values(), 1)}
        names = list(texts)
    data = {"files": [(io.BytesIO(texts[n]), n) for n in names], "name": "Evidence test"}
    if anonymize:
        data["anonymize"] = "1"
    body = client.post("/topology/api/build", data=data, content_type="multipart/form-data").get_json()
    assert body["ok"]
    return body, texts


def _pack(tmp_path, body, name="keystone-topology-pack.zip"):
    raw = (tmp_path / body["export_id"] / name).read_bytes()
    archive = zipfile.ZipFile(io.BytesIO(raw))
    return raw, {n.split("/", 1)[1]: archive.read(n) for n in archive.namelist()}


# ---- the pieces ---------------------------------------------------------------------------------------------------

def test_the_manifest_is_in_sha256sum_format_sorted_and_without_itself():
    text = evidence.manifest_text({"b.txt": "two", "a.txt": b"one", "MANIFEST.sha256": "ignored"})
    assert text == f"{hashlib.sha256(b'one').hexdigest()}  a.txt\n{hashlib.sha256(b'two').hexdigest()}  b.txt\n"


def test_capture_names_are_reduced_to_safe_characters_and_sorted():
    text = evidence.inputs_text([("zz.txt", "z"), ("../../etc/pass wd?.txt", "p"), ("", "e")])
    names = [line.split("  ", 1)[1] for line in text.splitlines()]
    assert names == sorted(names) and all("/" not in n and "\\" not in n and "?" not in n for n in names) and "capture" in names
    assert all(re.fullmatch(r"[0-9a-f]{64}  \S.*", line) for line in text.splitlines())


def test_every_finding_the_builder_can_raise_has_controls():
    ids = set(re.findall(r'"(TOPO-\d{3})"', "\n".join(p.read_text(encoding="utf-8") for p in SRC.glob("*.py") if p.name != "evidence.py")))
    assert ids and ids <= set(evidence.THEMES), sorted(ids - set(evidence.THEMES))
    for controls in evidence.THEMES.values():
        assert {f for f, _, _ in controls} <= {evidence.CIS, evidence.NIST, evidence.PCI, evidence.ISO} and len(controls) >= 2


def test_control_rows_start_with_the_drawing_and_follow_the_findings():
    rows = evidence.control_rows([{"id": "TOPO-035", "severity": "medium", "title": "One uplink", "devices": ["A", "B"]}, {"id": "TOPO-999", "title": "unknown"}])
    assert [r["control"] for r in rows[:4]] == ["1.2.3", "12.4", "A.8.20", "CM-2"] and rows[0]["finding"] == ""
    tagged = [r for r in rows if r["finding"] == "TOPO-035"]
    assert {r["control"] for r in tagged} == {"CP-8(2)", "A.8.14"} and tagged[0]["devices"] == "A, B"
    assert not [r for r in rows if r["finding"] == "TOPO-999"]


# ---- the pack -----------------------------------------------------------------------------------------------------

def test_the_manifest_matches_every_file_of_the_pack(client, tmp_path):
    body, _ = _build(client)
    raw, files = _pack(tmp_path, body)
    manifest = files["MANIFEST.sha256"].decode()
    listed = dict(line.split("  ", 1)[::-1] for line in manifest.splitlines())
    assert set(listed) == set(files) - {"MANIFEST.sha256"} and len(listed) >= 12
    for name, digest in listed.items():
        assert hashlib.sha256(files[name]).hexdigest() == digest, name
    assert {"audit/controls.csv", "audit/README.txt", "audit/inputs.sha256", "topology.json", "topology-report.html"} <= set(listed)


def test_a_changed_file_no_longer_matches(client, tmp_path):
    body, _ = _build(client)
    _, files = _pack(tmp_path, body)
    listed = dict(line.split("  ", 1)[::-1] for line in files["MANIFEST.sha256"].decode().splitlines())
    assert hashlib.sha256(files["topology.json"] + b" ").hexdigest() != listed["topology.json"]


def test_the_capture_hashes_are_those_of_the_uploaded_text(client, tmp_path):
    body, texts = _build(client)
    _, files = _pack(tmp_path, body)
    lines = dict(line.split("  ", 1)[::-1] for line in files["audit/inputs.sha256"].decode().splitlines())
    assert set(lines) == set(texts)
    for name, raw in texts.items():
        assert lines[name] == hashlib.sha256(raw.decode("utf-8").encode("utf-8")).hexdigest()


def test_the_control_table_lists_the_drawing_and_the_findings(client, tmp_path):
    body, _ = _build(client, set_id="after")
    _, files = _pack(tmp_path, body)
    rows = list(csv.DictReader(io.StringIO(files["audit/controls.csv"].decode("utf-8-sig"))))
    assert rows[0]["control"] == "1.2.3" and {r["framework"] for r in rows} == {evidence.CIS, evidence.NIST, evidence.PCI, evidence.ISO}
    assert any(r["finding"] == "TOPO-035" and r["control"] == "CP-8(2)" for r in rows)              # the demo's single-uplink access switch
    assert "does not assess compliance" in files["audit/README.txt"].decode()
    assert "MANIFEST.sha256" in files["README.txt"].decode() and "audit/" in files["README.txt"].decode()


def test_the_pack_hash_is_written_and_shown_in_the_history(client, tmp_path):
    body, _ = _build(client)
    raw, _ = _pack(tmp_path, body)
    digest = hashlib.sha256(raw).hexdigest()
    assert (tmp_path / body["export_id"] / "keystone-topology-pack.zip.sha256").read_text() == f"{digest}  keystone-topology-pack.zip\n"
    detail = client.get(f"/topology/api/history/{body['export_id']}").get_json()["run"]
    assert detail["pack_sha256"] == digest
    assert "keystone-topology-pack.zip.sha256" not in routes.EXPORT_NAMES
    assert client.get(f"/topology/api/export/{body['export_id']}/keystone-topology-pack.zip.sha256").status_code == 404
    assert history.pack_hash(tmp_path / ("0" * 32)) == ""


def test_a_damaged_hash_file_is_ignored(tmp_path):
    folder = tmp_path / ("1" * 32)
    folder.mkdir()
    (folder / "keystone-topology-pack.zip.sha256").write_text("not a hash  file\n")
    assert history.pack_hash(folder) == ""


def test_the_anonymized_pack_has_a_manifest_but_never_the_original_capture_names(client, tmp_path):
    body, texts = _build(client, anonymize=True, rename=True)
    _, files = _pack(tmp_path, body, "keystone-topology-pack-anonymized.zip")
    assert "MANIFEST.sha256" in files and "audit/controls.csv" in files and "audit/inputs.sha256" not in files
    listed = dict(line.split("  ", 1)[::-1] for line in files["MANIFEST.sha256"].decode().splitlines())
    for name, digest in listed.items():
        assert hashlib.sha256(files[name]).hexdigest() == digest, name
    blob = b"".join(files.values()).decode("utf-8", "replace")
    assert not [n for n in texts if n in blob]
    assert body["anonymized"]["leftovers"] == []


def test_the_history_page_shows_the_hash():
    js = (Path(__file__).resolve().parents[1] / "static" / "js" / "topology-history.js").read_text(encoding="utf-8")
    assert "d.pack_sha256" in js and "Pack SHA-256" in js
