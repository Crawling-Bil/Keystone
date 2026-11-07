"""A Panorama export together with the exports of the firewalls it manages: address-object names, matching a firewall to its template stack, the merged
configuration and the Topology Builder.  Invented names and CANARY credentials only (``tests/fixtures/panorama``)."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from features.firewall_analyzer import panorama_effective as pe
from features.firewall_analyzer import panorama_link as pl
from features.firewall_analyzer import panorama_parse as pp

FIX = Path(__file__).parent / "fixtures" / "panorama"
PANO_TEXT = (FIX / "synthetic_panorama.xml").read_text(encoding="utf-8")
FW_TEXT = (FIX / "synthetic_managed_fw.xml").read_text(encoding="utf-8")
OWN = "<deviceconfig><system><ip-address>192.0.2.200</ip-address></system></deviceconfig>"


def panorama_with_own_ip(ip: str = "192.0.2.200") -> str:
    return PANO_TEXT.replace('<config version="11.2.0" urldb="paloaltonetworks">', f'<config version="11.2.0" urldb="paloaltonetworks">{OWN.replace("192.0.2.200", ip)}', 1)


def test_interface_address_object_is_resolved_from_shared():
    text = PANO_TEXT.replace('<entry name="10.20.0.1/24"/>', '<entry name="sh-dns"/><entry name="no-such-object"/>')
    pano = pp.parse(text)
    notes: list[str] = []
    merged = pe.merged_template(pano, "STK-A", notes)
    names = [e.get("name") for e in merged.findall(".//network/interface/ethernet/entry[@name='ethernet1/2']/layer3/ip/entry")]
    assert "10.1.1.53/32" in names and "no-such-object" in names
    resolved = merged.find(".//ip/entry[@name='10.1.1.53/32']")
    assert resolved.get("src-object") == "sh-dns"                         # the object's name stays readable
    assert any("replaced by the value of the Shared object" in n for n in notes)
    assert any("no-such-object" in n and "not objects of the Shared location" in n for n in notes)


def test_resolution_covers_routes_and_ike_peers():
    root = ET.fromstring('<entry name="localhost.localdomain"><network><virtual-router><entry name="vr"><routing-table><ip><static-route>'
                         '<entry name="r"><destination>NET-A</destination><nexthop><ip-address>GW-A</ip-address></nexthop></entry>'
                         '<entry name="lit"><destination>10.0.0.0/8</destination><nexthop><ip-address>192.0.2.1</ip-address></nexthop></entry>'
                         '</static-route></ip></routing-table></entry></virtual-router>'
                         '<ike><gateway><entry name="g"><peer-address><ip>PEER</ip></peer-address><local-address><ip>10.9.9.9</ip></local-address></entry></gateway></ike></network></entry>')
    done, missing = pe.resolve_address_names(root, {"NET-A": "198.51.100.0/24", "GW-A": "192.0.2.1/32", "PEER": "203.0.113.5/32"})
    assert (done, missing) == (3, [])
    assert root.findtext(".//entry[@name='r']/destination") == "198.51.100.0/24"
    assert root.findtext(".//entry[@name='r']/nexthop/ip-address") == "192.0.2.1"       # /32 dropped where a host address is wanted
    assert root.findtext(".//peer-address/ip") == "203.0.113.5"


def test_firewall_is_linked_by_its_pushed_template():
    pano = pp.parse(PANO_TEXT)
    found = pl.link(pano, ET.fromstring(FW_TEXT))
    assert found.stack == "STK-A" and found.confidence == "high" and found.templates == ["TPL-DC"]


def test_firewall_with_no_evidence_is_not_linked():
    pano = pp.parse(PANO_TEXT)
    bare = ET.fromstring('<config><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>x</hostname></system></deviceconfig></entry></devices></config>')
    found = pl.link(pano, bare)
    assert not found.linked and "no distinctive name" in found.reason
    base_only = ET.fromstring('<config><devices><entry name="localhost.localdomain"><network><interface><ethernet><entry name="ethernet1/1" ptpl="TPL-BASE"/></ethernet></interface></network></entry></devices></config>')
    both = pl.link(pano, base_only)                                       # TPL-BASE is in STK-A and STK-B: equally good, so no guess
    assert not both.linked and "about equally" in both.reason


def test_panorama_the_firewall_points_at_decides_between_two_exports():
    one, other = pp.parse(panorama_with_own_ip("192.0.2.200")), pp.parse(panorama_with_own_ip("192.0.2.201"))
    root = ET.fromstring(FW_TEXT)                                         # its panorama-server is .200
    name, found = pl.best_link({"first": one, "second": other}, root)
    assert name == "first" and found.stack == "STK-A"
    tie_name, tie = pl.best_link({"a": pp.parse(PANO_TEXT), "b": pp.parse(PANO_TEXT)}, root)       # neither names itself: identical exports cannot be told apart
    assert tie_name == "" and not tie.linked and "more than one Panorama" in tie.reason


def test_merged_configuration_keeps_what_panorama_pushed_and_what_is_local():
    pano = pp.parse(PANO_TEXT)
    xml = pe.merge_device(pano, "STK-A", ET.fromstring(FW_TEXT), [])
    assert "CANARY" not in xml                                           # neither the template's nor the firewall's credentials
    cfg = ET.fromstring(xml)
    eth2 = cfg.find(".//network/interface/ethernet/entry[@name='ethernet1/2']")
    assert eth2.find("layer3/ip/entry").get("name") == "10.20.0.1/24"     # the template's address stays; the local entry only added a comment
    assert eth2.findtext("comment") == "pushed port"
    assert {z.get("name") for z in cfg.findall(".//vsys/entry/zone/entry")} == {"trust", "untrust"}      # the local empty <zone/> did not wipe them
    svi = cfg.find(".//network/interface/vlan/units/entry[@name='vlan.100']/ip/entry")
    assert svi.get("name") == "10.1.1.53/32" and svi.get("src-object") == "sh-dns"
    assert cfg.findtext(".//deviceconfig/system/hostname") == "FW-SYN-DC1"


def test_local_address_list_replaces_the_pushed_one():
    base = ET.fromstring("<e><network><interface><ethernet><entry name='e1'><layer3><ip><entry name='10.0.0.1/24'/></ip></layer3></entry></ethernet></interface></network></e>")
    local = ET.fromstring("<e><network><interface><ethernet><entry name='e1'><layer3><ip><entry name='10.0.0.9/24'/></ip></layer3></entry></ethernet></interface></network></e>")
    pe.overlay_local(base, local)
    assert [e.get("name") for e in base.findall(".//ip/entry")] == ["10.0.0.9/24"]


# ---------------------------------------------------------------------------------------------- topology
def test_topology_reads_the_firewall_with_its_stack_and_drops_the_stack_node():
    from features.topology import service
    files = [("Panorama-Syn", PANO_TEXT), ("FW-SYN-DC1.xml", FW_TEXT)]
    devices, skipped = service.read_devices(files)
    assert not skipped
    sources = [d.source for d in devices]
    assert sources.count("FW-SYN-DC1.xml") == 1
    fw = next(d for d in devices if d.source == "FW-SYN-DC1.xml")
    addresses = {row["ip"] for row in fw.l3}
    assert {"10.20.0.1", "10.1.1.53"} <= addresses                        # a template address and the resolved local SVI
    assert fw.l3facts["panorama_link"]["stack"] == "STK-A"
    assert not any(d.l3facts.get("panorama_stack") == "STK-A" for d in devices)           # STK-A is drawn by its real unit now
    assert any(d.l3facts.get("panorama_stack") == "STK-B" for d in devices)               # a stack without an uploaded unit stays on the picture


def test_topology_without_panorama_is_unchanged():
    from features.topology import service
    devices, _ = service.read_devices([("FW-SYN-DC1.xml", FW_TEXT)])
    assert len(devices) == 1 and "panorama_link" not in devices[0].l3facts


def test_topology_finding_names_linked_and_unlinked_firewalls():
    from features.topology import service
    unmatched = FW_TEXT.replace(' ptpl="TPL-DC"', "").replace("FW-SYN-DC1", "FW-SYN-X").replace("sh-dns", "10.77.0.1/24")
    result = service.build_topology([("Panorama-Syn", PANO_TEXT), ("FW-SYN-DC1.xml", FW_TEXT), ("FW-SYN-X.xml", unmatched)])
    rows = [f for f in result["findings"] if f["id"] == "TOPO-044"]
    severities = {f["severity"] for f in rows}
    assert severities == {"info", "low"}
    info = next(f for f in rows if f["severity"] == "info")
    assert "FW-SYN-DC1" in info["devices"]
    low = next(f for f in rows if f["severity"] == "low")
    assert "FW-SYN-X" in low["devices"]
    assert "CANARY" not in repr(result["findings"])


def test_topology_json_has_no_credentials():
    from features.topology import service
    result = service.build_topology([("Panorama-Syn", PANO_TEXT), ("FW-SYN-DC1.xml", FW_TEXT)])
    assert "CANARY" not in repr(result["findings"]) and "CANARY" not in result["drawio"]


# ---------------------------------------------------------------------------------------------- analyzer of the firewall's own export
def test_analyzer_says_when_interface_addresses_are_names_of_unknown_objects():
    from features.firewall_analyzer import service
    result = service.analyze(FW_TEXT, "fw.xml", "paloalto")
    row = next(f for f in result["findings"] if f["id"] == "PAN-NET-001")
    assert row["severity"] == "info" and "1 interface address" in row["title"] and "Panorama" in row["detail"]
    assert "CANARY" not in repr(result)
    defined = FW_TEXT.replace("<shared/>", '<shared><address><entry name="sh-dns"><ip-netmask>10.1.1.53/32</ip-netmask></entry></address></shared>')
    assert not [f for f in service.analyze(defined, "fw.xml", "paloalto")["findings"] if f["id"] == "PAN-NET-001"]


def test_snmpv3_keys_are_credentials():
    root = ET.fromstring("<e><snmp><v3><users><entry name='u'><authpwd>CANARYauthkey1234567890abcdefghijklmnopqrstuvwx</authpwd><privpwd>CANARYprivkey1234567890abcdefghijklmnopqrstuvwx</privpwd>"
                         "<authproto>SHA</authproto></entry></users></v3></snmp></e>")
    assert pp.strip_secrets(root) == 2
    assert root.find(".//authproto") is not None and "CANARY" not in ET.tostring(root, encoding="unicode")
