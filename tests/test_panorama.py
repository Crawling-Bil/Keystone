"""Panorama support: parser, effective configuration, analyzer, Convert (flatten and FortiGate), Topology, routes.

Everything runs on ``tests/fixtures/panorama/synthetic_panorama.xml`` (invented names, documentation addresses, CANARY credentials); no real export is
used.  The CANARY strings must never reach an analyzer result, a converter output, the source pane or a topology build.
"""

from __future__ import annotations

import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from features.configuration_studio import service as convert_service
from features.configuration_studio.converter_engine.fwconvert import panorama as pano_conv
from features.configuration_studio.converter_engine.parsers.firewall.paloalto_xml import PaloAltoXmlConfigParser
from features.firewall_analyzer import panorama_effective as pe
from features.firewall_analyzer import panorama_parse as pp
from features.firewall_analyzer import service as fw_service
from features.topology import service as topo_service

FIXTURE = Path(__file__).parent / "fixtures" / "panorama" / "synthetic_panorama.xml"
TEXT = FIXTURE.read_text(encoding="utf-8")
CANARIES = ("CANARYphash", "CANARYsnmpcommunity77", "CANARYwmipassword88")


@pytest.fixture(scope="module")
def pano() -> pp.Panorama:
    return pp.parse(TEXT)


# ------------------------------------------------------------------------------------------------ parser
def test_detection_is_specific_to_panorama():
    assert pp.looks_like_panorama(TEXT)
    firewall = '<?xml version="1.0"?><config version="10.1.0"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'
    assert not pp.looks_like_panorama(firewall)
    assert not pp.looks_like_panorama("config system global\nend\n")
    with pytest.raises(ValueError, match="not a Panorama"):
        pp.parse(firewall)


def test_structure_is_read(pano):
    assert set(pano.groups) == {"DG-PARENT", "DG-CHILD", "DG-LONELY"}
    assert pano.version == "11.2.0"
    assert pano.hierarchy_known and pano.groups["DG-CHILD"].parent == "DG-PARENT" and pano.groups["DG-PARENT"].parent == "shared"
    assert [s.name for s in pano.chain("DG-CHILD")] == ["shared", "DG-PARENT", "DG-CHILD"]
    assert pano.depth("DG-CHILD") == 2
    assert pano.stacks["STK-A"].templates == ["TPL-DC", "TPL-BASE"]
    assert set(pano.devices) == {"007000000001", "007000000002", "007000000003", "007000000009"}
    assert pano.devices["007000000002"].device_group == "DG-CHILD" and pano.devices["007000000002"].stack == "STK-A"
    assert pano.devices["007000000009"].device_group == "" and pano.devices["007000000009"].stack == ""


def test_missing_hierarchy_is_flat_and_says_so():
    flat = TEXT.replace("<parent-dg>DG-PARENT</parent-dg>", "")
    pano = pp.parse(flat)
    assert not pano.hierarchy_known and pano.groups["DG-CHILD"].parent == "shared"
    assert any("hierarchy" in w for w in pano.warnings)
    result = fw_service.analyze(flat, "demo.xml")
    assert any(f["id"] == "PANO-HIER-002" for f in result["findings"])


def test_rule_targets(pano):
    rule = next(r for r in pano.groups["DG-CHILD"].all_rules() if r.name == "C-targeted")
    assert rule.target.restricted and rule.target.devices == ["007000000002", "009999999999"]
    assert rule.target.applies("007000000002") and not rule.target.applies("007000000003")
    plain = next(r for r in pano.groups["DG-CHILD"].all_rules() if r.name == "C-block-p2p")
    assert not plain.target.restricted and plain.target.applies("anything")


def test_secrets_are_removed_by_name():
    root = ET.fromstring("<a><wmi-password>x1y2z3w4</wmi-password><password-history-count>3</password-history-count><pre-shared-key>abcdef12</pre-shared-key>"
                         "<x><community>v2cstring</community><manager>192.0.2.9</manager></x><bgp><community>65000:1</community></bgp></a>")
    assert pp.strip_secrets(root) == 3
    assert root.find("password-history-count") is not None and root.find("bgp/community") is not None
    assert root.find("wmi-password") is None and root.find("pre-shared-key") is None and root.find("x/community") is None


# ------------------------------------------------------------------------------------------------ effective configuration
def test_rule_order_is_the_evaluation_order(pano):
    eff = pe.effective(pano, "DG-CHILD")
    names = [r.name for r in eff.rules["security"]]
    assert names[0] == "P-allow-all-apps"                        # the parent's pre-rule is evaluated first
    assert names.index("C-block-p2p") < names.index("P-any-any") < names.index("shared-post-deny")    # child pre, then post: parent before shared
    assert names[-1] == "shared-post-deny"


def test_target_filters_rules_per_firewall(pano):
    hit = pe.effective(pano, "DG-CHILD", "007000000002")
    miss = pe.effective(pano, "DG-CHILD", "007000000003")
    assert "C-targeted" in [r.name for r in hit.rules["security"]] and hit.skipped_by_target == 0
    assert "C-targeted" not in [r.name for r in miss.rules["security"]] and miss.skipped_by_target == 1


def test_lower_level_object_wins(pano):
    eff = pe.effective(pano, "DG-CHILD")
    element, scope = eff.objects["address"]["sh-web"]
    assert scope == "DG-CHILD" and pp.text(element, "ip-netmask") == "10.99.0.10/32"
    assert ("address", "sh-web", "shared", "DG-CHILD") in eff.hidden
    assert pe.effective(pano, "DG-PARENT").objects["address"]["sh-web"][1] == "shared"


def test_template_priority_and_variables(pano):
    merged = pe.merged_template(pano, "STK-A", serial="007000000001")
    assert merged is not None
    ip = lambda name: [e.get("name") for e in merged.findall(f"network/interface/ethernet/entry[@name='{name}']/layer3/ip/entry")]
    assert ip("ethernet1/2") == ["10.20.0.1/24"]                 # TPL-DC is first in the stack, so it wins over TPL-BASE
    assert ip("ethernet1/1") == ["192.0.2.2/30"]                 # $wan_ip is filled from the template variable
    for canary in CANARIES:
        assert canary not in ET.tostring(merged, encoding="unicode")


def test_standalone_xml_is_an_ordinary_firewall(pano):
    xml, eff = pe.build_standalone(pano, "DG-CHILD", "007000000002")
    config = PaloAltoXmlConfigParser().parse_text(xml)
    assert len(config.security_rules) == 9 and len(config.nat_rules) == 1
    assert {z.name for z in config.zones} == {"trust", "untrust"}
    assert {a.name for a in config.address_objects} >= {"sh-web", "parent-net", "sh-dns"}
    assert not pp.looks_like_panorama(xml)
    for canary in CANARIES:
        assert canary not in xml


# ------------------------------------------------------------------------------------------------ analyzer
def test_analyzer_is_chosen_for_panorama_only():
    result = fw_service.analyze(TEXT, "demo.xml")
    assert result["platform"].startswith("Panorama")
    assert result["analyzer"] == "firewall"
    ids = {s["id"] for s in result["sections"]}
    assert {"pano_groups", "pano_devices", "pano_templates", "pano_stacks", "pano_security", "pano_objects", "pano_unused"} <= ids


EXPECTED_FINDINGS = {
    "PANO-POL-001": "P-any-any", "PANO-POL-002": "C-app-any-no-profile", "PANO-POL-003": "P-allow-all-apps", "PANO-POL-004": "C-no-profile", "PANO-POL-005": "C-no-profile",
    "PANO-POL-008": "C-block-p2p", "PANO-OBJ-001": "C-needs-sibling", "PANO-OBJ-002": "DG-CHILD", "PANO-OBJ-003": "shared", "PANO-OBJ-006": "DG-CHILD",
    "PANO-HIER-001": "DG-CHILD", "PANO-HIER-003": "DG-LONELY", "PANO-HIER-004": "007000000009", "PANO-HIER-005": "007000000009", "PANO-HIER-006": "TPL-ORPHAN",
    "PANO-HIER-007": "TPL-MISSING", "PANO-HIER-008": "STK-EMPTY", "PANO-MGT-001": "mgt-config/users", "PANO-MGT-005": "mgt-config/password-complexity",
    "PANO-TPL-001": "STK-A", "PANO-TPL-002": "STK-A", "PANO-TPL-003": "STK-A", "PANO-TPL-004": "mgmt-open",
}


@pytest.mark.parametrize("rule_id,needle", sorted(EXPECTED_FINDINGS.items()))
def test_each_finding_fires_on_its_object(rule_id, needle):
    findings = [f for f in fw_service.analyze(TEXT, "demo.xml")["findings"] if f["id"] == rule_id]
    assert findings, rule_id
    assert any(needle in f["object"] for f in findings), (rule_id, [f["object"] for f in findings])
    for f in findings:
        assert f["reference"].startswith("https://docs.paloaltonetworks.com/"), f


def test_predefined_edl_and_clean_rules_are_not_flagged():
    findings = fw_service.analyze(TEXT, "demo.xml")["findings"]
    assert not any("C-edl-block" in f["object"] for f in findings if f["id"] == "PANO-OBJ-001")       # panw-known-ip-list is built in
    assert not any("C-targeted" in f["object"] for f in findings if f["id"] in ("PANO-POL-001", "PANO-POL-002", "PANO-POL-004"))


def test_shadow_and_redundancy_use_effective_order(pano):
    from features.firewall_analyzer import panorama_rules
    findings, notes = panorama_rules.shadow_findings(pano)
    shadowed = {f["object"].split(" [")[0] for f in findings if f["id"] == "PANO-POL-008"}
    assert {"C-block-p2p", "shared-post-deny"} <= shadowed
    assert not notes


def test_result_validates_and_exports():
    from features.analyzer_core.result import validate_result
    result = fw_service.analyze(TEXT, "demo.xml")
    assert validate_result(result) == []
    dumped = json.dumps(result, default=str)
    for canary in CANARIES:
        assert canary not in dumped


# ------------------------------------------------------------------------------------------------ converter
def _convert(tmp_path, target, scope="", name="demo-panorama.xml"):
    path = tmp_path / name
    path.write_text(TEXT, encoding="utf-8")
    return convert_service.convert_file(path, source_vendor="Auto Detect", source_device_type="Auto Detect", target_vendor=target, domain="firewall", vdom=scope)


def test_flatten_to_panos(tmp_path):
    result = _convert(tmp_path, "Palo Alto", "DG-CHILD:007000000002")
    assert result["panorama"]["group"] == "DG-CHILD" and result["panorama"]["serial"] == "007000000002" and result["panorama"]["stack"] == "STK-A"
    assert result["download_name"].endswith("_PAN-OS_flattened.xml")
    config = PaloAltoXmlConfigParser().parse_text(result["output_text"])
    assert len(config.security_rules) == 9
    assert not pp.looks_like_panorama(result["output_text"])
    rows = result["fwconvert"]["rows"]
    assert any(r["kind"] == "credentials" for r in rows)
    for canary in CANARIES:
        assert canary not in result["output_text"] and canary not in result["source_text"] and canary not in json.dumps(result["fwconvert"])


def test_panorama_to_fortigate(tmp_path):
    result = _convert(tmp_path, "FortiGate", "DG-CHILD")
    assert result["target_vendor"] == "FortiGate" and result["panorama"]["group"] == "DG-CHILD"
    assert "config firewall policy" in result["output_text"]
    for canary in CANARIES:
        assert canary not in result["output_text"] and canary not in result["source_text"]


def test_scope_errors_name_the_choices(tmp_path):
    with pytest.raises(ValueError, match="3 device groups") as exc:
        _convert(tmp_path, "FortiGate", "")
    assert "DG-CHILD" in str(exc.value) and "name:serial" not in str(exc.value) or "serial number" in str(exc.value)
    with pytest.raises(ValueError, match="not in this Panorama export"):
        _convert(tmp_path, "FortiGate", "NOPE")
    with pytest.raises(ValueError, match="not a member"):
        _convert(tmp_path, "FortiGate", "DG-CHILD:007000000001")


def test_scopes_listing():
    scopes = pano_conv.scopes(TEXT)
    child = next(s for s in scopes if s["group"] == "DG-CHILD")
    assert child["parent"] == "DG-PARENT" and [f["serial"] for f in child["firewalls"]] == ["007000000002", "007000000003"]


def test_static_route_to_address_object_is_resolved():
    """A PAN-OS static route may name an address object as destination or next hop; the FortiGate converter used to abort on it."""
    import importlib
    fw = importlib.import_module("features.configuration_studio.converter_engine.fwconvert.convert")
    xml = ('<config version="10.1.0"><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="192.0.2.2/24"/></ip></layer3></entry></ethernet></interface><virtual-router><entry name="vr"><routing-table><ip><static-route>'
           '<entry name="r1"><destination>NET-A</destination><nexthop><ip-address>GW-A</ip-address></nexthop><interface>ethernet1/1</interface></entry>'
           '<entry name="r2"><destination>NET-MISSING</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop></entry>'
           '</static-route></ip></routing-table></entry></virtual-router></network><vsys><entry name="vsys1"><address>'
           '<entry name="NET-A"><ip-netmask>198.51.100.0/24</ip-netmask></entry><entry name="GW-A"><ip-netmask>192.0.2.1/32</ip-netmask></entry>'
           '</address></entry></vsys></entry></devices></config>')
    result = fw.convert(xml, "panos", "fortigate")
    assert result.ok, result.error
    assert "set dst 198.51.100.0 255.255.255.0" in result.output and "set gateway 192.0.2.1" in result.output
    assert any(i.name == "r1" and i.status == "approximated" for i in result.report.items)
    assert any(i.name == "r2" and i.status == "not_converted" for i in result.report.items)


# ------------------------------------------------------------------------------------------------ routes
def test_convert_routes_accept_panorama(tmp_path):
    from app import create_app
    client = create_app().test_client()
    data = TEXT.encode()

    found = client.post("/configuration/api/panorama-scopes", data={"config_file": (io.BytesIO(data), "Panorama-Site-30_10_2026")}, content_type="multipart/form-data").get_json()
    assert found["ok"] and found["panorama"] and {g["group"] for g in found["groups"]} == {"DG-PARENT", "DG-CHILD", "DG-LONELY"}
    other = client.post("/configuration/api/panorama-scopes", data={"config_file": (io.BytesIO(b"hostname x\n"), "x.txt")}, content_type="multipart/form-data").get_json()
    assert other == {"ok": True, "panorama": False}

    for filename in ("Panorama-Site-30_10_2026", "panorama.xml"):         # no extension, and .xml
        reply = client.post("/configuration/api/convert", data={"config_file": (io.BytesIO(data), filename), "domain": "firewall", "target_vendor": "FortiGate", "vdom": "DG-PARENT"},
                            content_type="multipart/form-data").get_json()
        assert reply["ok"], reply
        assert reply["result"]["panorama"]["group"] == "DG-PARENT"
    bad = client.post("/configuration/api/convert", data={"config_file": (io.BytesIO(data), "notes.exe"), "domain": "firewall", "target_vendor": "FortiGate"},
                      content_type="multipart/form-data")
    assert bad.status_code == 400


def test_analyzer_route_and_export():
    from app import create_app
    client = create_app().test_client()
    reply = client.post("/firewall-analyzer/api/analyze", data={"config_files": (io.BytesIO(TEXT.encode()), "Panorama-Site-30_10_2026")}, content_type="multipart/form-data").get_json()
    assert reply["ok"] and reply["results"][0]["platform"].startswith("Panorama")
    export = client.post("/firewall-analyzer/api/export", json={"results": reply["results"]}).get_json()
    assert export["ok"]


# ------------------------------------------------------------------------------------------------ topology
def test_topology_draws_one_firewall_per_stack_with_managed_units():
    device, error = topo_service._read_one("panorama.xml", TEXT)
    assert error is None
    devices = device if isinstance(device, list) else [device]
    assert sorted(d.hostname for d in devices) == ["STK-A", "STK-B"]            # STK-EMPTY has no firewall
    stack_a = next(d for d in devices if d.hostname == "STK-A")
    assert stack_a.role_hint == "firewall" and "2 managed units" in stack_a.model
    assert {row["ip"] for row in stack_a.l3} >= {"192.0.2.2", "10.20.0.1"}
    assert stack_a.descriptions.get("Eth1/1") == "DEMO-ISP-1 - Gi0/1"      # the cable hint in the interface comment survives


def test_topology_build_and_no_credentials():
    built = topo_service.build_topology([("panorama.xml", TEXT)])
    assert built["graph"].nodes
    dumped = json.dumps(built, default=str)
    for canary in CANARIES:
        assert canary not in dumped
    assert not re.search(r"CANARY", dumped)
