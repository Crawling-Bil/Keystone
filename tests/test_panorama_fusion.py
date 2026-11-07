"""Firewall Analyzer: a Panorama and the firewalls it manages analyzed together.  Invented names and CANARY credentials only."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from features.firewall_analyzer import panorama_fusion as pf
from features.firewall_analyzer import service

FIX = Path(__file__).parent / "fixtures" / "panorama"
PANO = (FIX / "synthetic_panorama.xml").read_text(encoding="utf-8")
FW = (FIX / "synthetic_managed_fw.xml").read_text(encoding="utf-8")
BARE = ('<config version="11.2.0"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>FW-SYN-X</hostname>'
        '<panorama><local-panorama><panorama-server>192.0.2.200</panorama-server></local-panorama></panorama></system></deviceconfig></entry></devices></config>')


def analyzed(sources):
    merged = pf.merge_sources(sources)
    return {name: service.analyze(text, filename=name, platform="auto") for name, text in merged}, dict(merged)


def test_a_matched_firewall_is_analyzed_with_its_stack_and_device_group():
    results, merged = analyzed([("Panorama-Syn", PANO), ("FW-SYN-DC1.xml", FW)])
    fw = results["FW-SYN-DC1.xml"]
    link = fw["panorama_link"]
    assert link["linked"] and link["stack"] == "STK-A" and link["group"] == "DG-PARENT" and link["confidence"] == "high"
    assert link["rules"] >= 2
    assert fw["sections"][0]["id"] == "panorama_link"
    assert any(f["id"] == "PANO-LINK-001" for f in fw["findings"])
    assert not any("managed by Panorama" in w for w in fw["warnings"])         # the policy is here now, so the "not included" warning goes
    assert fw["hostname"] == "FW-SYN-DC1"
    assert "CANARY" not in repr(fw) and "CANARY" not in str(merged["FW-SYN-DC1.xml"])


def test_the_policy_of_the_device_group_is_part_of_the_firewalls_analysis():
    results, _ = analyzed([("Panorama-Syn", PANO), ("FW-SYN-DC1.xml", FW)])
    rules = next(s for s in results["FW-SYN-DC1.xml"]["sections"] if s["id"] == "security_rules")
    assert len(rules["rows"]) >= 2
    interfaces = next(s for s in results["FW-SYN-DC1.xml"]["sections"] if s["id"] == "interfaces")
    assert len(interfaces["rows"]) >= 2                                         # template ports plus the firewall's own VLAN interface


def test_the_panorama_report_lists_what_went_with_it():
    results, _ = analyzed([("Panorama-Syn", PANO), ("FW-SYN-DC1.xml", FW), ("FW-SYN-X.xml", BARE)])
    table = next(s for s in results["Panorama-Syn"]["sections"] if s["id"] == "pano_fused")
    status = {r["file"]: r["status"] for r in table["rows"]}
    assert status["FW-SYN-DC1.xml"].startswith("analyzed") and status["FW-SYN-X.xml"].startswith("not matched")
    assert results["Panorama-Syn"]["panorama_fusion"] == {"matched": 1, "unmatched": 1}


def test_a_managed_firewall_that_cannot_be_matched_is_analyzed_alone_and_says_so():
    results, _ = analyzed([("Panorama-Syn", PANO), ("FW-SYN-X.xml", BARE)])
    fw = results["FW-SYN-X.xml"]
    assert "panorama_link" in fw and not fw["panorama_link"]["linked"]
    assert any("could not be matched" in w for w in fw["warnings"])


def test_nothing_changes_without_a_panorama_or_without_a_managed_firewall():
    sources = [("FW-SYN-DC1.xml", FW), ("notes.txt", "hostname x\n")]
    assert pf.merge_sources(sources) is sources
    results, _ = analyzed([("Panorama-Syn", PANO)])
    assert "pano_fused" not in {s["id"] for s in results["Panorama-Syn"]["sections"]}
    assert "panorama_fusion" not in results["Panorama-Syn"]
    plain, _ = analyzed([("Panorama-Syn", PANO), ("local.xml", '<config version="11.2.0"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>solo</hostname></system></deviceconfig></entry></devices></config>')])
    assert "panorama_link" not in plain["local.xml"]


def test_non_xml_and_duplicate_names_are_handled():
    merged = pf.merge_sources([("a.xml", PANO), ("a.xml", FW), ("set.txt", "set deviceconfig system hostname x\n"), ("bad.xml", "<config><unclosed>")])
    assert [n for n, _ in merged] == ["a.xml", "a.xml", "set.txt", "bad.xml"]
    assert getattr(merged[0][1], "role", "") == "panorama" and getattr(merged[1][1], "role", "") == "device"
    assert getattr(merged[2][1], "role", "") == "" and getattr(merged[3][1], "role", "") == ""


def test_rules_pushed_only_to_other_firewalls_are_left_out():
    from features.firewall_analyzer import panorama_effective as pe
    from features.firewall_analyzer import panorama_parse as pp
    pano = pp.parse(PANO)
    everything, _ = pe.effective_rules(pano, "DG-CHILD")
    one_stack, skipped = pe.effective_rules(pano, "DG-CHILD", serials=["007000000003"])
    assert sum(map(len, one_stack.values())) + skipped == sum(map(len, everything.values()))


def test_the_route_takes_a_panorama_with_more_than_sixteen_firewalls():
    from app import create_app
    client = create_app().test_client()
    files = [(io.BytesIO(PANO.encode()), "Panorama-Syn")] + [(io.BytesIO(FW.replace("FW-SYN-DC1", f"FW-SYN-{i:02d}").encode()), f"fw{i:02d}.xml") for i in range(20)]
    reply = client.post("/firewall-analyzer/api/analyze", data={"config_files": files, "platform": "auto"}, content_type="multipart/form-data")
    assert reply.status_code == 200, reply.data[:200]
    body = reply.get_json()
    assert body["ok"] and len(body["results"]) == 21 and not body["errors"]
    assert sum(1 for r in body["results"] if r.get("panorama_link", {}).get("linked")) == 20
    too_many = client.post("/firewall-analyzer/api/analyze", data={"config_files": [(io.BytesIO(b"<config/>"), f"x{i}.xml") for i in range(61)]}, content_type="multipart/form-data")
    assert too_many.status_code == 400 and "At most 60" in too_many.get_json()["error"]
    export = client.post("/firewall-analyzer/api/export", json={"results": body["results"][:3]})
    assert export.status_code == 200 and export.get_json()["ok"]
