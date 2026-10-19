"""Convert Switch: port mapping for the legacy Catalyst / Aruba 2540 sources seen in the TAM captures.

Real behaviour behind these tests (TTC cutover captures and staging log): a 2960 with 48 FastEthernet ports and two Gigabit uplinks produced two
``interface GE1/0/1`` blocks (Fa0/1 and Gi0/1), a 1G optic in a 10GE cage needs ``device transceiver 1000BASE-X``, in a 25GE cage also
``port mode GE``, and ``undo poe enable`` belongs on copper access ports only.  The configurations here are synthetic (invented host names, RFC 5737 addresses).
"""
from __future__ import annotations

import collections
import re
from pathlib import Path

import pytest

from app import create_app
from features.configuration_studio.converter_engine.engine import MigrationEngine
from features.configuration_studio.converter_engine.hardware import catalog
from features.configuration_studio.converter_engine.translators.switch.huawei import HuaweiSwitchTranslator
from features.configuration_studio.converter_engine.hardware.interface_map import build_interface_map
from features.configuration_studio.service import convert_file

FIXTURES = Path(__file__).parent / "fixtures" / "switch"


def _convert(name: str, model: str | None = None) -> str:
    return convert_file(FIXTURES / name, target_vendor="Huawei", domain="switch", target_model=model)["output_text"]


def _headers(text: str) -> list[str]:
    return re.findall(r"^interface (\S+)$", text, re.MULTILINE)


def _block(text: str, name: str) -> str:
    match = re.search(rf"^interface {re.escape(name)}\n((?: .*\n)+)", text, re.MULTILINE)
    assert match, name
    return match.group(1)


def test_the_five_legacy_models_are_detected_from_their_own_capture():
    for name, key in (("cisco_2960_48tc_synthetic.txt", "WS-C2960-48TC-L"), ("cisco_3650_24ts_synthetic.txt", "WS-C3650-24TS"),
                      ("cisco_3560x_personality_synthetic.txt", "WS-C3560X-24P")):
        model, _others = catalog.detect_model((FIXTURES / name).read_text(encoding="utf-8"))
        assert model and model.key == key, name


def test_an_aruba_switch_is_not_taken_for_the_catalyst_in_its_neighbour_table():
    text = (FIXTURES / "aruba_2540_neighbour_synthetic.txt").read_text(encoding="utf-8")
    assert catalog.detect_model(text, "switch", "Aruba")[0].key == "JL356A"
    # the vendor filter is what protects it: unfiltered, the many neighbour lines outweigh the banner
    assert catalog.detect_model(text)[0].key == "WS-C3650-24TS"


def test_fastethernet_and_gigabit_uplinks_never_share_a_huawei_port():
    out = _convert("cisco_2960_48tc_synthetic.txt", "S5735-S48T4XE-V2")
    headers = _headers(out)
    assert [name for name, count in collections.Counter(headers).items() if count > 1] == []
    assert "interface GE1/0/1" in out and "interface 10GE1/0/1" in out and "interface 10GE1/0/2" in out
    assert "description LAB-PC-1" in _block(out, "GE1/0/1")
    assert "description LAB-CORE-A" in _block(out, "10GE1/0/1") and "port link-type trunk" in _block(out, "10GE1/0/1")


def test_without_a_target_model_an_uplink_still_gets_an_uplink_name():
    cisco = catalog.get_model("WS-C2960-48TC-L")
    result = build_interface_map([("GigabitEthernet0/1", True), ("FastEthernet0/1", True)], source_model=cisco, target_vendor="Huawei")
    by = {row["source"]: row for row in result["rows"]}
    assert by["FastEthernet0/1"]["target"] == "GE1/0/1"
    assert by["GigabitEthernet0/1"]["target"] == "10GE1/0/1"


def test_a_fastethernet_port_on_a_gigabit_copper_port_is_not_a_review_item():
    cisco = catalog.get_model("WS-C2960-48TC-L")
    result = build_interface_map([("FastEthernet0/1", True)], source_model=cisco, target_vendor="Huawei", target_model="S5735-S48T4XE-V2")
    row = next(item for item in result["rows"] if item["source"] == "FastEthernet0/1")
    assert row["status"] == "ok" and row["target"] == "GE1/0/1"


def test_a_dual_purpose_uplink_is_reviewed_but_gets_no_optic_command():
    out = _convert("cisco_2960_48tc_synthetic.txt", "S5735-S48T4XE-V2")
    assert "device transceiver" not in out        # the source port may be copper: nothing proves a 1000BASE-X optic
    assert "REVIEW-INTERFACE-MAPPING" in _block(out, "10GE1/0/1")


def test_a_1g_sfp_uplink_in_a_10ge_cage_gets_the_1000basex_optic_type_only():
    out = _convert("cisco_3650_24ts_synthetic.txt", "S5735-S24P4XE-V2")
    block = _block(out, "10GE1/0/1")
    assert " device transceiver 1000BASE-X" in block
    assert "port mode GE" not in out
    assert "device transceiver" in _block(out, "10GE1/0/2")                                  # shutdown but configured
    assert "device transceiver" not in _block(out, "10GE1/0/3")                               # an empty spare cage is not given an optic type


def test_a_1g_sfp_uplink_in_a_25ge_cage_also_gets_port_mode_ge_and_a_bank_warning():
    out = _convert("cisco_3650_24ts_synthetic.txt", "S5755-H24T4Y2CZ")
    block = _block(out, "25GE1/0/1")
    assert block.index(" device transceiver 1000BASE-X") < block.index(" port mode GE")
    assert "REVIEW-PORT-MODE" in block and "WHOLE 25GE bank" in block
    assert "port mode GE" not in _block(out, "25GE1/0/3")


def test_two_speed_stanzas_of_one_module_cage_become_one_interface_block():
    out = _convert("cisco_3560x_personality_synthetic.txt", "S5735-S24P4XE-V2")
    assert [name for name, count in collections.Counter(_headers(out)).items() if count > 1] == []
    block = _block(out, "10GE1/0/1")
    assert "REVIEW-PORT-PERSONALITY" in block and "TenGigabitEthernet1/1" in block and "description LAB-UPLINK" in block
    assert "port link-type trunk" in block


def test_undo_poe_enable_is_for_copper_access_ports_only():
    translator = HuaweiSwitchTranslator()
    translator._port_map = {}
    assert translator._is_poe_port_name("GE1/0/3", "FastEthernet0/3") is True
    assert translator._is_poe_port_name("MultiGE1/0/2", "GigabitEthernet1/0/2") is True
    for name in ("Vlanif1", "Eth-Trunk1", "10GE1/0/1", "25GE1/0/2", "LoopBack0", "MEth0/0/0"):
        assert translator._is_poe_port_name(name, name) is False, name
    translator._port_map = {"GigabitEthernet1/1/1": {"role": "uplink", "target": "GE1/0/25"}}
    assert translator._is_poe_port_name("GE1/0/25", "GigabitEthernet1/1/1") is False


def test_the_inventory_model_is_used_for_the_port_map_when_no_target_was_chosen():
    engine = MigrationEngine()

    class Config:
        hostname = "SW-LAB-2960"

    engine.inventory.devices = {"sw-lab-2960": {"OldHostname": "SW-LAB-2960", "HuaweiModel": "CloudEngine S5735-S48T4XE-V2"}}
    assert engine._inventory_target_model(Config, "Huawei") == "S5735-S48T4XE-V2"
    assert engine._inventory_target_model(Config, "Aruba") is None
    engine.inventory.devices = {"sw-lab-2960": {"OldHostname": "SW-LAB-2960", "HuaweiModel": "CloudEngine S9999-NOT-IN-CATALOG"}}
    assert engine._inventory_target_model(Config, "Huawei") is None


def test_the_management_port_is_bound_to_the_built_in_management_vpn_instance():
    out = _convert("cisco_3650_24ts_synthetic.txt", "S5735-S24P4XE-V2")
    block = _block(out, "MEth0/0/0")
    assert " ip binding vpn-instance management" in block and "Mgmt-vrf" in block.split("REVIEW-MGMT-VRF")[1]
    assert "ip binding vpn-instance Mgmt-vrf" not in out


# ----------------------------------------------------------------------------------------------------------------------------------------
# Lexus: two standalone Catalyst 2960 24TC switches merged into one S5735-S24T4XE-V2 stack
# ----------------------------------------------------------------------------------------------------------------------------------------


def _convert_stack(name: str, member: int, members: int = 2, model: str | None = "S5735-S24T4XE-V2") -> dict:
    return convert_file(FIXTURES / name, target_vendor="Huawei", domain="switch", target_model=model, stack_member=member, stack_members=members)


def test_the_24tc_models_are_detected_and_their_gigabit_uplinks_are_not_the_fast_ethernet_ports():
    for name, key in (("cisco_2960_24tc_synthetic.txt", "WS-C2960-24TC-L"), ("cisco_2960plus_24tc_synthetic.txt", "WS-C2960+24TC-L")):
        model, _ = catalog.detect_model((FIXTURES / name).read_text(encoding="utf-8"))
        assert model and model.key == key, name
        text = _convert(name)
        headers = _headers(text)
        assert len(headers) == len(set(headers)), collections.Counter(headers).most_common(2)
        assert "10GE1/0/1" in headers and "10GE1/0/2" in headers                      # Gi0/1 and Gi0/2 are uplinks, not access ports 1 and 2
        assert "port default vlan 21" in _block(text, "10GE1/0/1") and "LAB-FW-B" in _block(text, "10GE1/0/1")


def test_an_unknown_fast_ethernet_model_does_not_merge_gi0_1_into_fa0_1():
    """Real 2960-24TC-L files lost their Gi0/1-2 configuration (the firewall uplinks) this way when the model was not in the catalog."""
    for model in (None, "S5735-S24T4XE-V2"):
        text = _convert("cisco_fe_gi_unknown_model_synthetic.txt", model)
        headers = _headers(text)
        assert len(headers) == len(set(headers)), (model, headers)
        assert "LAB-ISP-A" in _block(text, "GE1/0/1") and "LAB-FW-B" in _block(text, "10GE1/0/1")
        assert "LAB-ISP-B" in _block(text, "10GE1/0/2")
        assert "REVIEW-PORT-PERSONALITY" not in text


def test_a_second_stack_member_is_numbered_from_its_member_and_keeps_the_stack_ports_free():
    result = _convert_stack("cisco_2960_24tc_synthetic.txt", 2)
    text = result["output_text"]
    headers = _headers(text)
    assert {"GE2/0/1", "GE2/0/2", "GE2/0/23", "10GE2/0/1", "10GE2/0/2"} <= set(headers)
    assert not [h for h in headers if re.match(r"^(?:10)?GE1/0/", h)]                 # nothing lands on member 1
    assert "LAB-ISP-A" in _block(text, "GE2/0/1") and "LAB-FW-B" in _block(text, "10GE2/0/1")
    for port in ("GE2/0/21", "GE2/0/22"):
        block = _block(text, port)
        assert "REVIEW-STACK-PORT" in block and "port link-type" not in block and "shutdown" not in block
    assert "#    stack member 1 priority 100" in text and "#    stack member 1 renumber 2" in text
    assert "#   interface stack-port 2/1" in text and "#    port member-group interface GE 2/0/21" in text          # V600R025C00 syntax
    assert "port interface GE2/0/21 enable" not in text
    assert result["stack"] == {"member": 2, "members": 2}


def test_the_first_member_uses_priority_200_and_a_single_switch_gets_no_stack_header():
    first = _convert_stack("cisco_2960_24tc_synthetic.txt", 1)["output_text"]
    assert "#    stack member 1 priority 200" in first and "REVIEW-STACK-PORT" in _block(first, "GE1/0/22")
    single = _convert("cisco_2960_24tc_synthetic.txt", "S5735-S24T4XE-V2")
    assert "REVIEW-STACK-MEMBER" not in single and "REVIEW-STACK-PORT" not in single
    assert "GE1/0/21" in _headers(single) and "REVIEW-STACK-PORT" not in _block(single, "GE1/0/21")


def test_links_to_a_sibling_switch_are_flagged_so_they_are_not_carried_into_the_stack():
    text = _convert_stack("cisco_2960_24tc_synthetic.txt", 1)["output_text"]
    for name in ("Eth-Trunk1", "GE1/0/23"):
        assert "REVIEW-STACK-LINK: the description names SW-LAB-PEER-2960" in _block(text, name), name
    assert "REVIEW-STACK-LINK" not in _block(text, "GE1/0/1")
    alone = _convert("cisco_2960_24tc_synthetic.txt", "S5735-S24T4XE-V2")
    assert "REVIEW-STACK-LINK" not in alone


def test_the_stack_ports_come_from_the_catalog_only_for_a_model_whose_stack_ports_are_confirmed():
    assert catalog.get_model("S5735-S24T4XE-V2").stack_ports == ("GE{m}/0/21", "GE{m}/0/22")
    assert catalog.get_model("S5735-S48T4XE-V2").stack_ports == ()                    # not read from a capture: nothing is claimed
    text = _convert_stack("cisco_2960_24tc_synthetic.txt", 2, model="S5735-S48T4XE-V2")["output_text"]
    assert "REVIEW-STACK-PORT" not in text


def test_a_console_line_keeps_its_authentication_when_privilege_level_comes_first():
    """`line con 0` / `privilege level 15` / `logging synchronous` / `login authentication CONSOLE`: the privilege line used to end the block."""
    text = _convert("cisco_2960_24tc_synthetic.txt")
    console = text[text.index("user-interface con 0"):text.index("user-interface vty")]
    assert " authentication-mode aaa" in console and "REVIEW-LINE-PRIVILEGE" in console
    assert "# CISCO: login authentication CONSOLE" not in text


def test_a_self_signed_certificate_chain_is_one_line_not_a_hex_dump():
    text = _convert("cisco_2960_24tc_synthetic.txt")
    assert "certificate body not copied" in text
    assert "3082024D" not in text and "# CISCO: quit" not in text


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def test_the_switch_page_and_convert_api_take_the_stack_member(client):
    page = client.get("/convert/switch").get_data(as_text=True)
    assert 'name="stack_member"' in page and 'name="stack_members"' in page
    assert 'name="stack_member"' not in client.get("/convert/firewall").get_data(as_text=True)
    with (FIXTURES / "cisco_2960_24tc_synthetic.txt").open("rb") as handle:
        response = client.post(
            "/configuration/api/convert",
            data={"config_file": (handle, "sw.txt"), "target_vendor": "Huawei", "target_model": "S5735-S24T4XE-V2", "domain": "switch",
                  "stack_member": "2", "stack_members": "2"},
            content_type="multipart/form-data",
        )
    payload = response.get_json()
    assert payload["ok"], payload
    assert payload["result"]["stack"] == {"member": 2, "members": 2}
    assert "interface GE2/0/1\n" in payload["result"]["output_text"]


def test_a_neighbour_platform_line_does_not_name_the_source_model():
    """`show cdp neighbors detail` ends the 3750 capture with the platform of its 2960-X neighbour; the 3750 itself is not in the catalog."""
    text = "hostname SW-LAB-3750\nswitch 1 provision ws-c3750g-24t\n\nDevice ID: SW-LAB-NEIGHBOUR\nPlatform: cisco WS-C2960X-24TS-L,  Capabilities: Switch IGMP\n"
    model, _ = catalog.detect_model(text, "switch", "Cisco")
    assert model is None
    model, _ = catalog.detect_model(text + "cisco WS-C2960X-24TS-L (APM86XXX) processor\n", "switch", "Cisco")
    assert model and model.key == "WS-C2960X-24TS-L"
