"""Regression snapshots: the output of the converter, the Switch Analyzer, the Topology Builder and the cutover runbook for synthetic samples.

Every input here is invented (documentation addresses, made-up names).  A snapshot shows what a person would see; when one changes, read the
diff: it is either the intended improvement (accept it, see snapshot_util.py) or a regression.
"""
from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from snapshot_util import assert_snapshot  # noqa: E402
from test_convert_roundtrip import ARUBA_OS_S, CISCO  # noqa: E402
from test_switch_baseline import ARUBA_OK, CISCO_OK, HUAWEI_OK  # noqa: E402
from topology_samples import lab_dc  # noqa: E402

from features.configuration_studio import service  # noqa: E402
from features.switch_analyzer.service import analyze  # noqa: E402
from features.topology.diff import compare_runs, load_run  # noqa: E402
from features.topology.ingest import to_captures  # noqa: E402
from features.topology.runbook import build_runbook  # noqa: E402
from features.topology.service import build_topology, to_json  # noqa: E402

CREATED = datetime.datetime(2026, 11, 1, 9, 0, 0)


# ---- converter ----------------------------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,source,target,profile", [
    ("convert-cisco-to-huawei", CISCO, "Huawei", None),
    ("convert-cisco-to-huawei-tam", CISCO, "Huawei", "tam_standard"),
    ("convert-cisco-to-aruba", CISCO, "Aruba", None),
    ("convert-arubaos-to-huawei", ARUBA_OS_S, "Huawei", None),
])
def test_converter_output(tmp_path, name, source, target, profile):
    path = tmp_path / "lab.txt"
    path.write_text(source, encoding="utf-8")
    options = {"target_vendor": target}
    if profile:
        options["profile_key"] = profile
    result = service.convert_file(path, **options)
    # a snapshot is read in reviews and copied around: community strings are masked
    lines = [re.sub(r"^(snmp-agent community (?:read|write)(?: cipher| simple)? )\S+", r"\1<hidden>", line) for line in result["output_text"].splitlines()]
    assert_snapshot(name, {"output": lines, "confidence": result["confidence"], "review_count": result["review_count"],
                           "source_vendor": result["source_vendor"], "roundtrip": result["roundtrip"]})


# ---- Switch Analyzer ----------------------------------------------------------------------------------------------------------------------

def _findings(result):
    return [{"id": f["id"], "severity": f["severity"], "title": f["title"], "object": f["object"]} for f in result["findings"]]


@pytest.mark.parametrize("name,text,vendor,baseline", [
    ("analyze-cisco", CISCO_OK, "Cisco", ""), ("analyze-cisco-baseline", CISCO, "Cisco", "tam_standard"),
    ("analyze-huawei-baseline", HUAWEI_OK.replace("stp mode vbst", "stp mode rstp") + "dns server 192.0.2.53\n", "Huawei", "tam_standard"),
    ("analyze-aruba-baseline", ARUBA_OK, "Aruba", "tam_standard"),
])
def test_switch_analyzer_output(name, text, vendor, baseline):
    result = analyze(text, vendor=vendor, baseline=baseline)
    snapshot = {"vendor": result["vendor"], "hostname": result["hostname"], "cards": result["cards"], "findings": _findings(result)}
    if baseline:
        snapshot["baseline"] = {key: value for key, value in result["baseline"].items() if key != "findings"}
    assert_snapshot(name, snapshot)


# ---- Topology Builder, runbook, comparison ------------------------------------------------------------------------------------------------

def _lab_run(drop: str = "") -> dict:
    captures = [(name, text.encode()) for name, text in lab_dc().items() if not (drop and drop in name)]
    built = build_topology(to_captures(captures, 100), name="lab", created=CREATED)
    return load_run(to_json(built["graph"], built["findings"], built["devices"], built["settings"]).encode())


def test_topology_tables():
    run = _lab_run()
    assert_snapshot("topology-lab-dc", {
        "devices": [{k: r.get(k) for k in ("device", "captured", "role", "vendor", "model", "os_version", "management_ip", "stack_members", "vpc_domain", "vpc_role")} for r in run["devices"]],
        "links": [{k: r.get(k) for k in ("device_a", "port_a", "device_b", "port_b", "state", "kind", "bundle_a", "bundle_b", "vpc_id", "speed_a", "speed_b")} for r in run["links"]],
        "findings": [{k: f.get(k) for k in ("id", "severity", "title", "devices")} for f in run["findings"]]})


def test_runbook_for_the_lab():
    result = build_runbook(_lab_run(), title="Lab cutover", window="Sat 22:00-02:00", reference="CHG0001")
    assert_snapshot("runbook-lab-dc", {"summary": result["summary"], "devices": result["devices"],
                                       "steps": [{k: s[k] for k in ("seq", "device", "phase", "step", "detail", "command", "expect")} for s in result["steps"]]})


def test_comparison_when_a_device_capture_is_missing():
    result = compare_runs(_lab_run(), _lab_run(drop="ACC1"))
    assert_snapshot("compare-lab-dc-without-acc1", {"summary": result["summary"], "rows": result["rows"]})
