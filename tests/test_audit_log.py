"""The Operate audit log: append-only, hash-chained, and free of secrets.  Invented hosts and values only."""
from __future__ import annotations

import json

import pytest
from flask import Flask

from core import audit_log


@pytest.fixture()
def log(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_log, "LOG_FILE", tmp_path / "audit.jsonl")
    return tmp_path / "audit.jsonl"


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_lines_are_chained_and_verify(log):
    audit_log.record("one")
    audit_log.record("two", note="x")
    audit_log.record("three")
    lines = _lines(log)
    assert lines[0]["prev"] == audit_log.GENESIS
    assert lines[1]["prev"] == audit_log._digest(log.read_text(encoding="utf-8").splitlines()[0])
    assert audit_log.verify(log) == (True, 3, None)


def test_an_edited_or_removed_line_is_found(log):
    for name in ("a", "b", "c", "d"):
        audit_log.record(name, n=name)
    text = log.read_text(encoding="utf-8").splitlines()
    log.write_text("\n".join([text[0], text[1].replace('"n":"b"', '"n":"B"'), text[2], text[3]]) + "\n", encoding="utf-8")
    assert audit_log.verify(log) == (False, 2, 3)           # the line after the edited one no longer points at it
    log.write_text("\n".join([text[0], text[2], text[3]]) + "\n", encoding="utf-8")
    assert audit_log.verify(log)[0] is False


def test_rotation_keeps_the_chain_going(log, monkeypatch):
    monkeypatch.setattr(audit_log, "MAX_BYTES", 300)
    for i in range(12):
        audit_log.record("event", n=i, filler="y" * 40)
    rotated = sorted(log.parent.glob("audit.*.jsonl"))
    assert rotated, "the file should have been renamed at the size limit"
    first_of_new = _lines(log)[0]
    last_rotated = rotated[-1].read_text(encoding="utf-8").splitlines()[-1]
    assert first_of_new["prev"] == audit_log._digest(last_rotated)
    assert all(audit_log.verify(path)[0] for path in [*rotated, log])


def test_only_state_changing_operate_requests_are_logged(log):
    assert audit_log.record_request("GET", "/lifecycle/jobs", 200, "127.0.0.1") is None
    assert audit_log.record_request("POST", "/topology/build", 200, "127.0.0.1") is None
    assert not log.exists()
    entry = audit_log.record_request("POST", "/ztp/push", 202, "127.0.0.1", form={"host": "192.0.2.10", "password": "s3cret!", "note": "n"})
    assert entry["target"] == {"host": "192.0.2.10"}
    assert entry["fields"] == ["host", "note", "password"]            # the name of the field is logged, never its value
    assert "s3cret!" not in log.read_text(encoding="utf-8")


def test_nothing_but_target_keys_is_read_from_a_json_body(log):
    audit_log.record_request("POST", "/lifecycle/api/upgrade", 200, "::1", payload={"ip": "192.0.2.7", "enable_secret": "hunter2", "devices": ["a", "b"], "config": "snmp-server community public RW"})
    text = log.read_text(encoding="utf-8")
    assert "hunter2" not in text and "snmp-server" not in text
    entry = _lines(log)[0]
    assert entry["target"] == {"ip": "192.0.2.7", "devices": "a,b"}


def test_long_values_are_cut_and_whitespace_is_collapsed(log):
    audit_log.record_request("POST", "/ztp/x", 200, "127.0.0.1", form={"host": "h" * 500 + "\n\tz"})
    assert len(_lines(log)[0]["target"]["host"]) == audit_log.VALUE_LIMIT


def test_flask_hook_logs_after_the_response_and_never_breaks_it(log):
    app = Flask(__name__)
    audit_log.register(app)

    @app.post("/ztp/start")
    def start():
        return "ok", 202

    @app.post("/other")
    def other():
        return "ok"

    client = app.test_client()
    assert client.post("/ztp/start", data={"host": "192.0.2.1", "password": "pw-value"}).status_code == 202
    assert client.post("/other", data={"host": "x"}).status_code == 200
    entries = _lines(log)
    assert len(entries) == 1 and entries[0]["status"] == 202 and entries[0]["path"] == "/ztp/start"
    assert "pw-value" not in log.read_text(encoding="utf-8")


def test_a_log_that_cannot_be_written_does_not_break_the_request(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setattr(audit_log, "LOG_FILE", blocker / "sub" / "audit.jsonl")       # the parent is a file: mkdir fails
    app = Flask(__name__)
    audit_log.register(app)

    @app.post("/lifecycle/go")
    def go():
        return "done"

    assert app.test_client().post("/lifecycle/go", data={"host": "x"}).data == b"done"
