"""A router capture with show output only (no CDP/LLDP) becomes a device with L3 facts. Masked router fixtures."""

from __future__ import annotations

from pathlib import Path

from features.topology import l3facts
from features.topology.service import read_devices

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "router"


def _text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


def test_sdwan_overlay_capture_becomes_a_device_with_bfd_sessions():
    devices, skipped = read_devices([("cedge.txt", _text("cedge_sdwan_overlay_masked.txt"))])
    assert [s for s in skipped if "Could not be read" in s["reason"]] == []
    assert len(devices) == 1
    device = devices[0]
    assert device.role_hint == "router" and device.l3facts["overlay"]
    first = device.l3facts["overlay"][0]
    assert first["system_ip"] and first["state"] in ("up", "down")


def test_facts_have_the_expected_shape_for_every_router_fixture():
    for path in sorted(FIXTURES.glob("*_masked.txt")):
        facts = l3facts.read(path.read_text(encoding="utf-8", errors="replace"), path.name)
        if not facts:
            continue
        for key in ("interfaces", "routes", "neighbors", "overlay", "tunnels", "state", "arp"):
            assert key in facts, (path.name, key)
        for route in facts["routes"]:
            assert route["count"] >= 1 and "next_hop" in route


def test_text_that_is_not_a_router_capture_gives_no_facts():
    assert not l3facts.read("hello world\nnothing to see\n", "x.txt")


def test_l3_facts_survive_a_saved_run():
    from features.topology.state import device_from_state, device_to_state
    import json
    devices, _ = read_devices([("cedge.txt", _text("cedge_sdwan_overlay_masked.txt"))])
    saved = json.loads(json.dumps(device_to_state(devices[0])))
    again = device_from_state(saved)
    assert again.l3facts["overlay"] == devices[0].l3facts["overlay"] and again.l3facts.get("system_ip") == devices[0].l3facts.get("system_ip")
