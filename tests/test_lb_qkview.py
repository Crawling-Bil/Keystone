"""A QKView (the F5 diagnostic archive) has the same ``config/`` files as a UCS plus a lot of diagnostic data that can hold secrets.

The archive here is built in memory from invented data: a fake private key, a fake shadow file and a fake log line carry marker strings, and none of them
may appear anywhere in the result.
"""

from __future__ import annotations

import io
import json
import tarfile
from datetime import date

import pytest

from features.lb_analyzer import bigip_ucs, service, ucs_reader

TODAY = date(2026, 11, 1)
SECRET_KEY = "QKVIEW-FAKE-PRIVATE-KEY-MATERIAL"
SECRET_SHADOW = "QKVIEW-FAKE-SHADOW-HASH"
SECRET_LOG = "QKVIEW-FAKE-LOG-PASSWORD"
SECRET_REG = "QKVIEW-FAKE-REGISTRATION-KEY"

BIGIP_CONF = """#TMSH-VERSION: 15.1.5
ltm pool /Common/pool_a {
    members {
        /Common/192.0.2.11:80 {
            address 192.0.2.11
        }
    }
    monitor /Common/http
}
ltm virtual /Common/vs_a {
    destination /Common/192.0.2.10:80
    ip-protocol tcp
    pool /Common/pool_a
}
"""
BASE_CONF = """sys global-settings {
    hostname qk1.example.test
}
"""


def _archive(extra: dict[str, bytes] | None = None, markers: bool = True) -> bytes:
    members = {
        "config/bigip.conf": BIGIP_CONF.encode(),
        "config/bigip_base.conf": BASE_CONF.encode(),
        "VERSION.LTM": b"Product: BIG-IP\nVersion: 15.1.5\nBuild: 0.0.10\nEdition: Final\nDate: Fri Dec 10 13:48:13 PST 2021\n",
        "PLATFORM": b"platform=C119\nfamily=0xF8000000\n",
        "config/ssl/ssl.key/site.key": f"-----BEGIN RSA PRIVATE KEY-----\n{SECRET_KEY}\n-----END RSA PRIVATE KEY-----\n".encode(),
        "etc/shadow": f"root:{SECRET_SHADOW}:19000::::::\n".encode(),
        "var/log/ltm": f"Nov  1 10:00:00 qk1 notice mcpd: password={SECRET_LOG}\n".encode(),
        "config/RegKey.license": SECRET_REG.encode(),
        "var/core/core.1": b"\x7fELF" + SECRET_KEY.encode(),
        "mcp_module.xml": f"<mcp><secret>{SECRET_KEY}</secret></mcp>".encode(),
    }
    if markers:
        members["manifest.xml"] = b"<manifest></manifest>"
        members["qkview_run.data"] = b"x"
    members.update(extra or {})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo("./" + name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _read(data: bytes, name: str = "support.qkview"):
    return bigip_ucs.read_upload(name, io.BytesIO(data))


def test_a_qkview_is_recognised_and_labelled():
    text = _read(_archive())
    bundle = bigip_ucs.bundle_of(text)
    assert bundle.kind == "QKView"
    assert bundle.version["Version"] == "15.1.5" and bundle.platform["platform"] == "C119"
    assert set(bundle.files) == {"config/bigip.conf", "config/bigip_base.conf"}


def test_an_archive_without_the_qkview_markers_stays_a_ucs():
    assert bigip_ucs.bundle_of(_read(_archive(markers=False), "backup.ucs")).kind == "UCS"


def test_secrets_never_reach_the_result():
    text = _read(_archive())
    bundle = bigip_ucs.bundle_of(text)
    assert bundle.omitted.get("private keys / password files", 0) >= 3        # ssl.key, shadow, RegKey.license
    result = service.analyze(text, "support.qkview", today=TODAY)
    blob = json.dumps(result, default=str) + str(text)
    for marker in (SECRET_KEY, SECRET_SHADOW, SECRET_LOG, SECRET_REG):
        assert marker not in blob


def test_the_result_names_the_archive_kind_and_maps_the_pool():
    result = service.analyze(_read(_archive()), "support.qkview", today=TODAY)
    assert result["hostname"].startswith("qk1")
    rows = {c["command"]: c for c in result["coverage"]}
    assert rows["QKView archive (.qkview)"]["status"] == "analyzed"
    archive = next(s for s in result["sections"] if s["id"] == "ucs_archive")
    assert archive["title"] == "QKView archive"
    assert any("pool_a" in json.dumps(s, default=str) for s in result["sections"])


def test_a_qkview_without_configuration_is_refused_with_a_message():
    data = _archive()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as src, tarfile.open(fileobj=buffer, mode="w:gz") as dst:
        for member in src:
            if "config/bigip" not in member.name:
                dst.addfile(member, src.extractfile(member))
    with pytest.raises(ucs_reader.UcsError):
        _read(buffer.getvalue())


def test_the_topology_upload_accepts_a_qkview():
    from features.topology import ingest
    captures = ingest.to_captures([("support.qkview", _archive())], 10)
    assert len(captures) == 1 and bigip_ucs.bundle_of(captures[0][1]).kind == "QKView"
