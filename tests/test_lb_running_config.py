"""'show running-config' prints /Common objects without the /Common/ prefix.  The parser must still resolve references.

The fixture is synthetic; it mirrors the layout seen in a trainer-lab capture without any of its data.
"""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path

import pytest

from features.lb_analyzer import service
from features.lb_analyzer.tmsh_tree import parse_tmsh

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "loadbalancer" / "bigip_running_config_bare_synthetic.txt"
TODAY = date(2026, 10, 18)


@pytest.fixture(scope="module")
def result():
    return service.analyze(FIXTURE.read_text(encoding="utf-8"), "running.txt", today=TODAY)


def _ids(result: dict) -> Counter:
    return Counter(f["id"] for f in result["findings"])


def _objects(result: dict, rule_id: str) -> str:
    return " ".join(f["object"] + " " + f["detail"] for f in result["findings"] if f["id"] == rule_id)


def test_bare_names_become_absolute():
    tree = parse_tmsh("ltm pool POOL-A {\n members { 10.0.0.1:80 { address 10.0.0.1 } }\n}\nsys global-settings {\n hostname lab\n}\nltm virtual V {\n pool POOL-A\n}\n")
    heads = {" ".join(n.tokens) for n in tree.root}
    assert "ltm pool /Common/POOL-A" in heads
    assert "ltm virtual /Common/V" in heads
    assert "sys global-settings" in heads                       # singleton: no name to qualify


def test_already_absolute_and_other_partitions_stay_untouched():
    tree = parse_tmsh("ltm pool /Common/P { }\nltm pool /Part/Q { }\n")
    assert {" ".join(n.tokens) for n in tree.root} == {"ltm pool /Common/P", "ltm pool /Part/Q"}


def test_references_resolve(result):
    assert "LB-REF-001" not in _ids(result), _objects(result, "LB-REF-001")


def test_dns_listener_virtual_is_not_flagged_without_pool(result):
    assert "DC-LISTENER-1" not in _objects(result, "LB-VS-001")


def test_system_shipped_profiles_are_not_unused(result):
    text = _objects(result, "LB-OBJ-004")
    assert "HTTP-CUSTOM-UNUSED" in text
    assert "georedundancy" not in text
    assert "do-not-remove-without-replacement" not in text


def test_map_and_dns_tree_are_populated(result):
    section = next(s for s in result["sections"] if s["kind"] == "map")
    kinds = Counter(n["type"] for n in section["nodes"])
    assert kinds["virtual"] == 3 and kinds["pool"] == 2 and kinds["member"] == 3
    assert kinds["wideip"] == 1 and kinds["dnspool"] == 1 and kinds["dnsmember"] == 1
