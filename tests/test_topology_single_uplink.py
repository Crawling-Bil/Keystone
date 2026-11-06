"""TOPO-035: an access switch that reaches the core or distribution layer through one device only, while the picture holds a second one.

Synthetic captures only (invented names and addresses; layouts follow what NX-OS and IOS XE print)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import iosxe_capture, nxos_capture  # noqa: E402

from features.topology import service  # noqa: E402

CORE_IPS = {"LAB-CORE1": "10.97.0.1", "LAB-CORE2": "10.97.0.2"}
SERIALS = {"LAB-CORE1": "FDO97000001", "LAB-CORE2": "FDO97000002"}
CORE_PLATFORM = "N9K-C93180YC-FX3"


def network(uplinks: dict[str, list[str]], cores=("LAB-CORE1", "LAB-CORE2"), down: dict[str, list[str]] | None = None) -> dict[str, str]:
    """uplinks: access switch -> the cores it is cabled to (one cable each).  ``down``: access switch -> cores whose uplink port the switch lists as down."""
    files: dict[str, str] = {}
    port = {c: 0 for c in cores}
    core_cdp: dict[str, list[tuple]] = {c: [] for c in cores}
    for number, (acc, targets) in enumerate(sorted(uplinks.items()), start=1):
        serial, ip = f"FOC9700000{number}", f"10.97.0.{20 + number}"
        cdp = []
        for index, core in enumerate(targets):
            port[core] += 1
            local = f"GigabitEthernet1/0/{47 + index}"
            cdp.append((f"{core}.lab.example({SERIALS[core]})", CORE_IPS[core], CORE_PLATFORM, local, f"Ethernet1/{port[core]}"))
            core_cdp[core].append((f"{acc}.lab.example({serial})", ip, "C9300L-48P-4X", f"Ethernet1/{port[core]}", local))
        extra = ""
        if down and down.get(acc):
            rows = "".join(f"Gi1/0/{47 + targets.index(core)}  uplink  notconnect  1  auto  auto  10/100/1000BaseTX\n" for core in down[acc])
            extra = f"{acc}#show interfaces status\nPort      Name   Status       Vlan  Duplex Speed Type\n{rows}"
        files[f"{acc}.txt"] = iosxe_capture(acc, serial, ip, cdp=cdp, extra=extra)
    for core in cores:
        files[f"{core}.txt"] = nxos_capture(core, SERIALS[core], CORE_IPS[core], cdp=core_cdp[core], model=CORE_PLATFORM)
    return files


def finding(files: dict[str, str], devices=None):
    result = service.build_topology(list(files.items()), group="none", devices=devices)
    return [f for f in result["findings"] if f["id"] == "TOPO-035"], result


def test_dual_homed_access_switches_are_fine():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1", "LAB-CORE2"]}))
    assert rows == []


def test_a_single_homed_access_switch_is_named_and_the_dual_homed_one_is_not():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1"]}))
    assert len(rows) == 1
    row = rows[0]
    assert row["severity"] == "medium" and "1 access switch" in row["title"]
    assert "LAB-ACC2: only LAB-CORE1 (1 port)" in row["detail"] and "LAB-ACC1" not in row["detail"]
    assert set(row["devices"]) == {"LAB-ACC2", "LAB-CORE1"}
    assert row["reference"].startswith("https://www.cisco.com/")


def test_two_cables_to_the_same_single_core_are_still_a_single_point_of_failure():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1", "LAB-CORE1"]}))
    assert len(rows) == 1 and "LAB-ACC2: only LAB-CORE1 (2 ports)" in rows[0]["detail"]


def test_no_finding_when_the_picture_holds_only_one_core():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1"], "LAB-ACC2": ["LAB-CORE1"]}, cores=("LAB-CORE1",)))
    assert rows == []


def test_a_stack_with_two_ports_counts_as_redundant():
    files = network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1", "LAB-CORE1"]})
    devices, _ = service.read_devices(list(files.items()))
    for device in devices:
        if device.hostname == "LAB-CORE1":
            device.stack_members = 2
    rows, _ = finding(files, devices=devices)
    assert rows == []
    for device in devices:
        if device.hostname == "LAB-CORE1":
            device.stack_members = 1
    assert len(finding(files, devices=devices)[0]) == 1


def test_an_uplink_port_that_is_down_is_no_path():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1", "LAB-CORE2"]}, down={"LAB-ACC2": ["LAB-CORE2"]}))
    assert len(rows) == 1 and "LAB-ACC2: only LAB-CORE1" in rows[0]["detail"]


def test_the_finding_is_part_of_the_demo_change_window_story():
    from features.topology import demo
    for set_id, expected in (("before", 0), ("after", 1)):
        files = [(f["name"], demo.read_file(set_id, f["name"]).decode()) for item in demo.list_sets() if item["id"] == set_id for f in item["files"]]
        result = service.build_topology(files, group="none")
        rows = [f for f in result["findings"] if f["id"] == "TOPO-035"]
        assert len(rows) == expected, set_id
        if rows:
            assert "DC1-ACC3: only DC1-CORE1" in rows[0]["detail"]


def test_a_switch_with_no_live_uplink_at_all_is_not_reported_here():
    rows, _ = finding(network({"LAB-ACC1": ["LAB-CORE1", "LAB-CORE2"], "LAB-ACC2": ["LAB-CORE1", "LAB-CORE2"]}, down={"LAB-ACC2": ["LAB-CORE1", "LAB-CORE2"]}))
    assert rows == []
