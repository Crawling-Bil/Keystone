"""Topology Builder: the progress bar of a build.  Synthetic captures only."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import lab_dc  # noqa: E402

from features.topology import progress  # noqa: E402
from features.topology.service import build_topology  # noqa: E402


@pytest.fixture()
def client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _post(client, build_id, **fields):
    files = [(io.BytesIO(text.encode()), name) for name, text in lab_dc().items()]
    return client.post("/topology/api/build", data={"files": files, "group": "none", "progress_id": build_id, **fields}, content_type="multipart/form-data")


def test_a_finished_build_reads_100_and_done(client):
    build_id = "a1b2c3d4e5f60718"
    assert client.get(f"/topology/api/progress/{build_id}").get_json()["known"] is False      # the first poll can come before the upload ends
    assert _post(client, build_id).get_json()["ok"]
    state = client.get(f"/topology/api/progress/{build_id}").get_json()
    assert state["known"] and state["done"] and state["percent"] == 100 and state["label"] == "Done"


def test_a_refused_build_ends_as_stopped_not_as_running(client):
    build_id = "ffeeddccbbaa0011"
    response = client.post("/topology/api/build", data={"progress_id": build_id}, content_type="multipart/form-data")
    assert response.status_code == 400
    state = client.get(f"/topology/api/progress/{build_id}").get_json()
    assert state["done"] and state["label"] == "Stopped" and state["percent"] < 100


def test_the_bar_only_moves_forward_and_names_each_capture():
    build = progress.start("0011223344556677")
    seen, details = [], []
    original = progress.Tracker.set

    def spy(self, key, fraction=0.0, detail=""):
        original(self, key, fraction, detail)
        seen.append(self.build.percent)
        details.append(detail)

    progress.Tracker.set = spy
    try:
        with progress.tracking(build):
            build_topology([(name, text) for name, text in lab_dc().items()], view="all")
    finally:
        progress.Tracker.set = original
    assert seen == sorted(seen) and seen[0] < 5 and 0 < max(seen) <= 100
    assert any(d.startswith("Capture 1 of 3: ") for d in details) and any(d.startswith("Capture 3 of 3: ") for d in details)
    stages = {progress.status("0011223344556677")["label"]}
    assert stages and build.percent > 80          # the build reached the last stage it reports itself; the route adds the files


def test_a_build_with_no_listener_costs_nothing():
    progress.report("read", 0.5, "nobody listens")            # no tracker: must not raise
    assert build_topology([(n, t) for n, t in lab_dc().items()])["summary"]["captured"] == 3


def test_ids_the_page_could_not_have_made_are_ignored(client):
    assert progress.start("../x") is None and progress.start("") is None and progress.start("a" * 65) is None
    assert client.get("/topology/api/progress/short").get_json()["known"] is False


def test_the_anonymized_copy_owns_the_second_half_of_the_bar(client):
    build_id = "0f0e0d0c0b0a0908"
    seen = []
    original = progress.Tracker.set

    def spy(self, key, fraction=0.0, detail=""):
        original(self, key, fraction, detail)
        seen.append((self.lo, self.build.label))

    progress.Tracker.set = spy
    try:
        assert _post(client, build_id, anonymize="1").get_json()["ok"]
    finally:
        progress.Tracker.set = original
    assert any(lo == 0.0 for lo, _ in seen) and any(lo == 55.0 and label.startswith("Anonymized copy: ") for lo, label in seen)
    assert client.get(f"/topology/api/progress/{build_id}").get_json()["percent"] == 100


def test_the_page_carries_the_bar():
    html = Path(__file__).parent.parent.joinpath("templates", "topology.html").read_text(encoding="utf-8")
    js = Path(__file__).parent.parent.joinpath("static", "js", "topology.js").read_text(encoding="utf-8")
    assert 'data-role="progress"' in html and 'role="progressbar"' in html
    assert "/api/progress/" in js and 'body.append("progress_id"' in js
