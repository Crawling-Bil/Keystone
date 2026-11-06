"""Regression tests for the quality sweep: secret handling, response headers, identifier checks, accessibility markers.

Every secret in this file is a synthetic canary; none is a real credential.
"""
from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest

from app import create_app
from core import local_guard
from features.analyzer_core.redaction import GUESSABLE_COMMUNITIES, HIDDEN, mask_community, redact_line, redact_snmp_line

ROOT = Path(__file__).resolve().parents[1]
CANARY = "CANARYsnmp7731"


@pytest.fixture()
def client(monkeypatch):
    for name in ("NES_ALLOW_REMOTE", "NES_ALLOWED_HOSTS", "NES_AUTH_PASSWORD", "NES_DISABLE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# --- SNMP community names and keys -----------------------------------------------------------------------------------

def test_mask_community_shows_defaults_and_hides_everything_else():
    assert mask_community("public") == "public"
    assert mask_community('"Private"') == "Private"
    masked = mask_community(CANARY)
    assert CANARY not in masked and HIDDEN in masked and str(len(CANARY)) in masked


@pytest.mark.parametrize("line", [
    f"snmp-server community {CANARY} RO",
    f"snmp-agent community read {CANARY}",
    f"snmp-agent community write cipher {CANARY}",
    f"snmp-agent community read irreversible-cipher {CANARY}",
    f"snmp-server host 10.1.1.5 version 2c {CANARY}",
    f"snmp-server host 10.1.1.5 traps version 2c {CANARY} config",
    f"snmp-server host 10.1.1.5 {CANARY}",
    f"snmp-server user u g v3 auth sha {CANARY} priv aes 128 {CANARY}",
])
def test_snmp_lines_never_keep_a_secret(line):
    assert CANARY not in redact_snmp_line(line)
    assert CANARY not in redact_line(line)


def test_huawei_read_write_keyword_is_kept():
    assert redact_snmp_line(f"snmp-agent community read cipher {CANARY}") == f"snmp-agent community read cipher {HIDDEN}"
    assert redact_snmp_line(f"snmp-agent community write {CANARY}") == f"snmp-agent community write {HIDDEN}"


def test_default_community_stays_readable_in_the_line():
    assert redact_snmp_line("snmp-server community public RO") == "snmp-server community public RO"
    # a cipher text is never a default name even when it looks like one
    assert "abc" not in redact_snmp_line("snmp-agent community read cipher abc")
    assert {"public", "private"} <= GUESSABLE_COMMUNITIES


def _switch_response(client, text):
    reply = client.post("/switch-analyzer/api/analyze", data={"config_file": (io.BytesIO(text.encode()), "cap.txt")}, content_type="multipart/form-data")
    assert reply.status_code == 200
    return reply


def test_switch_analyzer_response_has_no_snmp_community(client):
    config = f"hostname SW-CAN\nsnmp-server community {CANARY} RO\nsnmp-server community public RO\nsnmp-server host 10.1.1.5 version 2c {CANARY}\nend\n"
    reply = _switch_response(client, config)
    assert CANARY not in reply.get_data(as_text=True)
    snmp = json.loads(reply.get_data(as_text=True))["result"]["snmp"]
    shown = snmp.get("summary", {}).get("communities", [])
    assert "public" in shown and any(HIDDEN in item for item in shown)


# --- response headers ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/switch-analyzer/", "/topology", "/static/css/app.css", "/static/js/switch_analyzer.js"])
def test_security_headers_on_pages_and_static_files(client, path):
    reply = client.get(path)
    assert reply.status_code == 200
    policy = reply.headers["Content-Security-Policy"]
    assert "default-src 'self'" in policy and "object-src 'none'" in policy and "frame-ancestors 'none'" in policy
    assert "connect-src 'self'" in policy
    assert reply.headers["X-Content-Type-Options"] == "nosniff"
    assert reply.headers["X-Frame-Options"] == "DENY"
    assert reply.headers["Referrer-Policy"] == "no-referrer"


def test_security_headers_on_a_refused_request(client):
    reply = client.get("/", headers={"Host": "evil.example"})
    assert reply.status_code >= 400
    assert reply.headers.get("X-Content-Type-Options") == "nosniff"


def test_csp_allows_no_remote_script_or_frame():
    policy = local_guard.SECURITY_HEADERS["Content-Security-Policy"]
    script_src = re.search(r"script-src ([^;]+)", policy).group(1)
    assert "http:" not in script_src and "https:" not in script_src and "*" not in script_src
    assert "frame-ancestors 'none'" in policy


# --- identifiers: a trailing newline must not pass `^[a-f0-9]{32}$` ----------------------------------------------------------

def test_identifier_patterns_reject_a_trailing_newline():
    from features.topology import progress, routes
    good = "a" * 32
    assert routes.SAFE_IDENTIFIER.fullmatch(good)
    assert not routes.SAFE_IDENTIFIER.fullmatch(good + "\n")
    assert not progress.ID_RE.fullmatch(good + "\n")


def test_no_identifier_check_uses_match_with_dollar_anchor():
    """`re.match(r'^...$')` accepts a trailing newline; every `_ID`/`SAFE_*` pattern in the web layer is used with fullmatch."""
    offenders = []
    for path in list((ROOT / "features").rglob("*.py")) + list((ROOT / "core").rglob("*.py")):
        if "lld" in path.as_posix() or "docgen" in path.as_posix():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if re.search(r"\b(?:SAFE_[A-Z_]*|ID_RE|_TOKEN_RE|SAFE_IDENTIFIER)\.match\(", line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert offenders == []


# --- accessibility markers that axe flagged and are cheap to keep ----------------------------------------------------------

def test_hardware_tree_is_not_declared_a_tree_widget():
    source = (ROOT / "templates" / "_hardware_catalog.html").read_text(encoding="utf-8")
    assert 'role="tree"' not in source


def test_configuration_page_has_no_h3_before_an_h2():
    source = (ROOT / "templates" / "configuration.html").read_text(encoding="utf-8")
    assert "<h3>Conversion Settings</h3>" not in source
    assert "<aside" not in source.split("convert-panel")[0][-200:]


def test_primary_button_text_uses_the_contrast_token():
    css = (ROOT / "static" / "css" / "app.css").read_text(encoding="utf-8")
    block = re.search(r"\.primary-button\s*\{[^}]*\}", css)
    assert block and "var(--on-accent)" in block.group(0)


# --- the Topology Builder reads whole configurations: no credential may reach its answer, its pack or its Excel file ----------

def test_topology_build_and_pack_carry_no_credential(client):
    import zipfile
    secrets = {"snmp": "CANARYsnmp7731", "pw": "CANARYpw5521", "psk": "CANARYpsk4412", "tac": "CANARYtac6620", "hash": "CANARYhash0071", "v3": "CANARYv3key8841"}
    capture = (
        "SW-CAN# show running-config\nhostname SW-CAN\n"
        f"snmp-server community {secrets['snmp']} RO\nsnmp-server user u g v3 auth sha {secrets['v3']} priv aes 128 {secrets['v3']}\n"
        f"username bob password 7 {secrets['pw']}\nenable secret 9 {secrets['hash']}\n"
        f"tacacs-server host 10.1.1.1 key {secrets['tac']}\ncrypto isakmp key {secrets['psk']} address 203.0.113.9\n"
        "interface GigabitEthernet1/0/1\n switchport mode access\nline vty 0 4\n"
        f" password {secrets['pw']}\nend\n"
        "SW-CAN# show cdp neighbors detail\n-------------------------\nDevice ID: PEER1\nEntry address(es):\n  IP address: 10.0.0.2\n"
        "Platform: cisco WS-C3850,  Capabilities: Switch IGMP\nInterface: GigabitEthernet1/0/1,  Port ID (outgoing port): GigabitEthernet1/0/2\n"
    )
    reply = client.post("/topology/api/build", data={"files": (io.BytesIO(capture.encode()), "SW-CAN.txt")}, content_type="multipart/form-data")
    assert reply.status_code == 200
    body = reply.get_json()
    blobs = [reply.get_data(as_text=True)]
    for download in body["downloads"]:
        name = download["name"] if isinstance(download, dict) else str(download)
        data = client.get(f"/topology/api/export/{body['export_id']}/{name}").get_data()
        if name.endswith((".zip", ".xlsx")):
            archive = zipfile.ZipFile(io.BytesIO(data))
            for member in archive.namelist():
                raw = archive.read(member)
                if member.endswith(".xlsx"):
                    inner = zipfile.ZipFile(io.BytesIO(raw))
                    raw = b" ".join(inner.read(part) for part in inner.namelist())
                blobs.append(raw.decode("utf-8", "ignore"))
        else:
            blobs.append(data.decode("utf-8", "ignore"))
    everything = "\n".join(blobs)
    assert [name for name, value in secrets.items() if value in everything] == []
