"""Cisco StackWise Virtual is read from the configuration, labelled as such, and checked for dual-active detection (TOPO-057).  Invented names and ports.

Cisco, Troubleshoot SVL on Catalyst 9000 Switch: https://www.cisco.com/c/en/us/support/docs/switches/catalyst-9500-series-switches/216537-troubleshoot-svl-on-catalyst-9000-switch.html
"""

from __future__ import annotations

from features.topology import findings, stackwise
from features.topology.extract import Device
from features.topology.graph import Graph

SVL = """\
hostname LAB-CORE
!
stackwise-virtual
 domain 7
!
interface HundredGigE1/0/51
 stackwise-virtual link 1
!
interface HundredGigE1/0/52
 stackwise-virtual link 1
!
interface HundredGigE2/0/51
 stackwise-virtual link 1
!
interface HundredGigE2/0/52
 stackwise-virtual link 1
!
interface TwentyFiveGigE1/0/48
 stackwise-virtual dual-active-detection
!
interface TwentyFiveGigE2/0/48
 stackwise-virtual dual-active-detection
!
interface TwentyFiveGigE1/0/1
 description not an svl port
!
"""


def test_the_domain_the_svl_cables_and_the_dad_ports_are_read():
    got = stackwise.read(SVL)
    assert got["domain"] == "7"
    assert got["links"] == {"Hu1/0/51": "1", "Hu1/0/52": "1", "Hu2/0/51": "1", "Hu2/0/52": "1"}
    assert got["dad"] == ["Twe1/0/48", "Twe2/0/48"]


def test_a_configuration_that_holds_the_same_lines_twice_lists_each_port_once():
    assert stackwise.read(SVL + SVL)["dad"] == ["Twe1/0/48", "Twe2/0/48"]


def test_a_box_without_stackwise_virtual_reads_empty():
    assert stackwise.read("hostname X\ninterface Gi1/0/1\n description stackwise-virtual in a text\n") == {"domain": "", "links": {}, "dad": []}
    assert stackwise.read("") == {"domain": "", "links": {}, "dad": []}


def test_crlf_text_reads_the_same():
    assert stackwise.read(SVL.replace("\n", "\r\n")) == stackwise.read(SVL)


def _device(links, dad, domain="7"):
    return Device(key="LAB-CORE", hostname="LAB-CORE", captured=True, model="C9500-48Y4C", stack_members=2, svl_domain=domain, svl_links=dict(links), svl_dad=list(dad))


def _rows(device):
    return [r for r in findings._stackwise_findings(Graph(nodes={device.key: device}, links=[], connections=[], hidden_kinds=set())) if r["id"] == "TOPO-057"]


def test_a_protected_pair_has_no_finding():
    got = stackwise.read(SVL)
    assert _rows(_device(got["links"], got["dad"])) == []


def test_no_dual_active_detection_is_a_medium_finding_with_the_cisco_link():
    got = stackwise.read(SVL)
    rows = _rows(_device(got["links"], []))
    assert len(rows) == 1 and rows[0]["severity"] == "medium" and "no dual-active-detection" in rows[0]["detail"]
    assert rows[0]["reference"] == findings.DOC_SVL and "216537" in findings.DOC_SVL


def test_dad_on_one_chassis_and_one_svl_cable_per_chassis_are_low():
    rows = _rows(_device({"Hu1/0/51": "1", "Hu2/0/51": "1"}, ["Twe1/0/48"]))
    assert len(rows) == 1 and rows[0]["severity"] == "low"
    assert "1 chassis only" in rows[0]["detail"] and "single StackWise Virtual Link" in rows[0]["detail"]


def test_a_plain_stack_is_not_judged():
    assert _rows(Device(key="S", hostname="S", captured=True, stack_members=3)) == []


def test_the_node_says_svl_domain_not_stack():
    from features.topology import labels
    node = _device({}, [])
    assert "SVL DOMAIN 7" in node.label_lines[1] and "STACK" not in node.label_lines[1]
    assert labels.node_lines(node)[1] == "C9500-48Y4C — SVL DOMAIN 7"
    plain = Device(key="S", hostname="S", captured=True, model="C9300-48P", stack_members=3)
    assert labels.node_lines(plain)[1] == "C9300-48P — STACK" and plain.label_lines[1] == "C9300-48P STACK"


def test_a_whole_run_reads_the_svl_and_reports_it():
    from features.topology.service import build_topology
    result = build_topology([("core.txt", SVL.replace("!\ninterface TwentyFiveGigE2/0/48\n stackwise-virtual dual-active-detection\n", "") + "\nshow switch\n")])
    node = result["graph"].nodes["LAB-CORE"]
    assert node.svl_domain == "7" and len(node.svl_links) == 4
