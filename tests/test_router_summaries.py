"""Router Analyzer: ``show arp summary``, ``show ip route summary`` (per VRF), ``show ipv6 route summary``, the VRF filter buttons
and the Duration next to the log Window."""
from __future__ import annotations

from pathlib import Path

import pytest

from features.analyzer_core.result import section_by_id, validate_result
from features.router_analyzer.service import analyze

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "router"


@pytest.fixture(scope="module")
def result():
    return analyze((FIXTURES / "synthetic_summary_counters.txt").read_text(encoding="utf-8"), "lab-r1.txt")


def test_result_stays_valid(result):
    assert validate_result(result) == []


def test_arp_summary_counts(result):
    section = section_by_id(result, "arp_summary")
    pairs = {item["label"]: item["value"] for item in section["pairs"]}
    assert pairs["Entries in the ARP table"] == "248"
    assert pairs["Incomplete entries"] == "178"
    assert any(value == "186" for value in pairs.values())


def test_route_counters_have_one_row_per_source_and_vrf(result):
    section = section_by_id(result, "route_counters")
    vrfs = {row["vrf"] for row in section["rows"]}
    assert vrfs == {"global", "1"}
    connected = next(row for row in section["rows"] if row["vrf"] == "global" and row["source"] == "connected")
    assert connected["routes"] == 66
    bgp = next(row for row in section["rows"] if row["vrf"] == "global" and row["source"].startswith("bgp"))
    assert bgp["routes"] == 1 and "External: 1" in bgp["detail"]
    omp = next(row for row in section["rows"] if row["vrf"] == "1" and row["source"] == "omp")
    assert omp["routes"] == 12


def test_vrf_buttons_are_declared_on_the_tables_that_carry_a_vrf_column(result):
    section = section_by_id(result, "route_counters")
    assert section["facets"] == [{"key": "vrf", "label": "VRF", "prefix": "vrf ", "order": ["global"]}]   # "vrf global" is the first button


def test_ipv6_route_summary(result):
    section = section_by_id(result, "route_counters_v6")
    local = next(row for row in section["rows"] if row["source"] == "local")
    assert local["routes"] == 1 and local["overhead"] == 192
    assert any(row["detail"] == "overlay: 0" for row in section["rows"])


def test_the_three_summaries_are_analyzed_in_coverage(result):
    status = {row["command"]: row["status"] for row in result["coverage"]}
    for command in ("show ip route summary", "show ip route vrf 1 summary", "show ipv6 route summary", "show arp summary"):
        assert status[command] == "analyzed", command


def test_log_duration_is_next_to_the_window():
    text = (FIXTURES / "c8300_iosxe_ospf_log_masked.txt").read_text(encoding="utf-8")
    section = section_by_id(analyze(text, "c8300.txt"), "log_summary")
    keys = [item["label"] for item in section["pairs"]]
    assert "Window" in keys and "Duration" in keys
    assert keys.index("Duration") == keys.index("Window") + 1
