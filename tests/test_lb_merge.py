"""One analysis from a UCS and the prompted capture of the same unit (matched by hostname). Synthetic data only."""

from __future__ import annotations

import io
from datetime import date
from pathlib import Path

import pytest
from flask import Flask

from features.lb_analyzer import bigip_ucs, service
from features.lb_analyzer.routes import bp
from tests.test_lb_gtm_ucs import BASE, FILES, LTM, _tar

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "loadbalancer" / "bigip_capture_dns_synthetic.txt"
HOST_STANZA = "sys global-settings {\n    hostname dns-hq-01.example.test\n}\n"


def _ucs(host_stanza: str = HOST_STANZA) -> bigip_ucs.UcsText:
    members = dict(FILES, **{"config/bigip_base.conf": host_stanza + BASE})
    return bigip_ucs.read_upload("unit.ucs", io.BytesIO(_tar(members)))


def _capture() -> str:
    return FIXTURE.read_text(encoding="utf-8")


def test_hostnames_come_from_the_config_stanza_and_from_both_prompt_styles():
    assert bigip_ucs.unit_hostname("sys global-settings {\n    hostname Dns-HQ-01.example.test\n}\n") == "dns-hq-01"
    assert bigip_ucs.unit_hostname("[admin@dns-hq-01:Active:In Sync] ~ # tmsh show sys version\n") == "dns-hq-01"
    assert bigip_ucs.unit_hostname("root@(dns-hq-01)(cfg-sync In Sync)(Active)(/Common)(tmos)# show sys version\n") == "dns-hq-01"
    assert bigip_ucs.unit_hostname("ltm node /Common/n { address 1.1.1.1 }\n") == ""


def test_a_ucs_and_the_capture_of_the_same_unit_become_one_source():
    merged = bigip_ucs.merge_same_unit([("unit.ucs", _ucs()), ("capture.txt", _capture())])
    assert len(merged) == 1
    name, content = merged[0]
    assert name == "unit.ucs + capture.txt" and content.live_name == "capture.txt" and content.bundle is not None


def test_other_hostnames_plain_config_and_a_second_archive_stay_separate():
    ucs = _ucs()
    other = _capture().replace("dns-hq-01", "dns-dr-02")
    assert len(bigip_ucs.merge_same_unit([("unit.ucs", ucs), ("other.txt", other)])) == 2
    plain_conf = HOST_STANZA + LTM                                     # a bigip.conf of the same host is not a prompted capture
    assert len(bigip_ucs.merge_same_unit([("unit.ucs", ucs), ("bigip.conf", plain_conf)])) == 2
    assert len(bigip_ucs.merge_same_unit([("a.txt", _capture()), ("b.txt", _capture())])) == 2     # no archive: nothing to merge
    assert len(bigip_ucs.merge_same_unit([("a.ucs", _ucs()), ("b.ucs", _ucs()), ("c.txt", _capture())])) == 3     # two archives claim the host: ambiguous


@pytest.fixture(scope="module")
def merged_result():
    (name, content), = bigip_ucs.merge_same_unit([("unit.ucs", _ucs()), ("capture.txt", _capture())])
    return service.analyze(content, name, today=date(2026, 10, 23))


def test_the_archive_supplies_the_configuration_and_the_capture_the_live_state(merged_result):
    sections = {s["id"]: s for s in merged_result["sections"]}
    wideips = {r["name"] for r in sections["gtm_wideips"]["rows"]}
    assert {"on.example.test", "off.example.test"} <= wideips                       # only in the UCS, not in the capture
    assert "gtm_wideips_live" in sections or "gtm_servers_live" in sections           # only in the capture
    assert {"label": "Live state from", "value": "capture.txt (merged with the UCS of the same unit)"} in merged_result["info"]
    assert merged_result["capture"]["commands"] > 0


def test_the_upload_route_returns_one_result_for_the_pair():
    app = Flask("t", template_folder="templates")
    app.register_blueprint(bp)
    app.context_processor(lambda: {"app_version": "t"})
    ucs_bytes = _tar(dict(FILES, **{"config/bigip_base.conf": HOST_STANZA + BASE}))
    data = {"config_files": [(io.BytesIO(ucs_bytes), "unit.ucs"), (io.BytesIO(_capture().encode()), "capture.txt")]}
    body = app.test_client().post("/load-balancer-analyzer/api/analyze", data=data, content_type="multipart/form-data").get_json()
    assert body["ok"] and len(body["results"]) == 1 and body["results"][0]["source_name"] == "unit.ucs + capture.txt"
