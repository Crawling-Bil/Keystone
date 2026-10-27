"""A MikroTik file in the Topology Builder upload is skipped with a clear reason, not read as a switch (FortiGate configurations are drawn since v0.6, Palo Alto since v0.7). Synthetic fixtures."""

from __future__ import annotations

from pathlib import Path

from features.topology.service import read_devices

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read(rel: str):
    return read_devices([(Path(rel).name, (FIXTURES / rel).read_text(encoding="utf-8"))])


def test_mikrotik_files_are_skipped_with_a_reason():
    devices, skipped = _read("firewall/mikrotik_routeros6_synthetic.rsc")
    assert devices == [] and len(skipped) == 1
    assert "MikroTik" in skipped[0]["reason"] and "not drawn yet" in skipped[0]["reason"]


def test_a_palo_alto_file_is_drawn_as_a_firewall():
    devices, skipped = _read("firewall/panos_cli_network_synthetic.txt")
    assert skipped == [] and len(devices) == 1 and devices[0].role_hint == "firewall" and devices[0].vendor == "Palo Alto Networks"


def test_fortigate_configuration_is_drawn_as_a_firewall():
    devices, skipped = _read("firewall/fortigate_synthetic_7.2.conf")
    assert skipped == [] and len(devices) == 1
    assert devices[0].role_hint == "firewall" and devices[0].vendor == "Fortinet" and devices[0].l3


def test_f5_capture_is_drawn_as_a_load_balancer_not_read_as_a_switch():
    devices, skipped = _read("loadbalancer/bigip_capture_synthetic.txt")
    assert skipped == [] and len(devices) == 1
    assert devices[0].role_hint == "loadbalancer" and devices[0].vendor == "F5" and devices[0].l3


def test_an_f5_file_without_self_ips_is_skipped_with_the_fix():
    devices, skipped = read_devices([("pools.conf", "ltm pool /Common/p1 {\n    members {\n        /Common/10.0.0.1:80 {\n            address 10.0.0.1\n        }\n    }\n}\n")])
    assert devices == [] and "net self" in skipped[0]["reason"] and "UCS" in skipped[0]["reason"]


def test_a_switch_capture_next_to_a_skipped_firewall_file_still_works():
    switch = "hostname SW1\n!\ninterface GigabitEthernet1/0/1\n description to SW2\n!\n"
    devices, skipped = read_devices([("sw1.txt", switch), ("fw.rsc", (FIXTURES / "firewall/mikrotik_routeros6_synthetic.rsc").read_text(encoding="utf-8"))])
    assert [d.hostname for d in devices] == ["SW1"] and [s["file"] for s in skipped] == ["fw.rsc"]
