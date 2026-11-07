"""The same device uploaded twice is drawn once: a PAN-OS or FortiGate export has no serial number, so identical hostname and addresses prove it.
Invented devices and documentation addresses."""

from __future__ import annotations

from features.topology.extract import Device
from features.topology.findings import build_findings
from features.topology.graph import Graph, _unique_keys


def _device(source: str, ips: set[str], serials: set[str] | None = None, mgmt: str = "192.0.2.10", model: str = "PA-440") -> Device:
    return Device(key="", hostname="FW01", source=source, vendor="paloalto", model=model, mgmt_ip=mgmt, ips=set(ips), serials=set(serials or ()))


def _nodes(*devices: Device) -> tuple[Graph, list[str]]:
    graph = Graph()
    _unique_keys(list(devices), graph)
    return graph, sorted(graph.nodes)


def test_a_copy_under_another_file_name_is_one_device():
    graph, nodes = _nodes(_device("running-config.xml", {"192.0.2.10", "198.51.100.1"}), _device("copy-of-running-config.xml", {"192.0.2.10", "198.51.100.1"}))
    assert nodes == ["FW01"]
    assert [i["type"] for i in graph.issues] == ["duplicate-capture"] and graph.issues[0]["proof"] == "hostname and addresses"


def test_the_duplicate_is_reported_as_a_low_finding_naming_both_files():
    graph, _ = _nodes(_device("a.xml", {"192.0.2.10"}), _device("b.xml", {"192.0.2.10"}))
    rows = [r for r in build_findings(graph) if r["id"] == "TOPO-003"]
    assert len(rows) == 1 and rows[0]["severity"] == "low" and "a.xml" in rows[0]["detail"] and "b.xml" in rows[0]["detail"] and "same hostname and addresses" in rows[0]["detail"]


def test_a_cloned_configuration_with_its_own_address_stays_a_second_device():
    graph, nodes = _nodes(_device("a.xml", {"192.0.2.10", "198.51.100.1"}), _device("b.xml", {"192.0.2.10", "198.51.100.1", "203.0.113.7"}))
    assert nodes == ["FW01", "FW01#2"] and graph.issues[0]["type"] == "same-hostname"


def test_another_management_address_or_model_is_another_device():
    _, nodes = _nodes(_device("a.xml", {"192.0.2.10"}), _device("b.xml", {"192.0.2.10"}, mgmt="192.0.2.11"))
    assert nodes == ["FW01", "FW01#2"]
    _, nodes = _nodes(_device("a.xml", {"192.0.2.10"}), _device("b.xml", {"192.0.2.10"}, model="PA-460"))
    assert nodes == ["FW01", "FW01#2"]


def test_without_any_address_nothing_is_assumed():
    _, nodes = _nodes(_device("a.xml", set()), _device("b.xml", set()))
    assert nodes == ["FW01", "FW01#2"]


def test_a_serial_number_on_one_side_only_does_not_prove_anything():
    _, nodes = _nodes(_device("a.xml", {"192.0.2.10"}, serials={"SN1"}), _device("b.xml", {"192.0.2.10"}))
    assert nodes == ["FW01", "FW01#2"]


def test_the_same_serial_is_still_a_duplicate():
    graph, nodes = _nodes(_device("a.xml", {"192.0.2.10"}, serials={"SN1"}), _device("b.xml", {"192.0.2.99"}, serials={"SN1"}))
    assert nodes == ["FW01"] and graph.issues[0]["proof"] == "serial number"
