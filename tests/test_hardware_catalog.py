"""Hardware catalog and interface map for Convert Switch / Convert Router.

Fixtures are synthetic: invented hostnames and documentation addresses, real Cisco/HPE product IDs (they are what the detector reads).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from app import create_app
from features.configuration_studio.converter_engine.hardware.catalog import (
    ALL_MODELS,
    detect_model,
    get_model,
    target_models,
)
from features.configuration_studio.converter_engine.hardware.interface_map import build_interface_map, parse_name
from features.configuration_studio.converter_engine.hardware.routers import ROUTER_MODELS
from features.configuration_studio.converter_engine.hardware.switches import SWITCH_MODELS
from features.configuration_studio.service import available_target_models, convert_file

FIXTURES = Path(__file__).parent / "fixtures" / "switch"
NM8X = FIXTURES / "c9300_48p_nm8x_synthetic.txt"
NM4M = FIXTURES / "c9300_48t_nm4m_synthetic.txt"
ARUBA = FIXTURES / "aruba_6200f_vsf_synthetic.txt"

SWITCH_KEYS = {
    "C9300X-24Y", "C9300X-48TX", "C9300-48P", "C9300-48T", "C9200L-24P-4X", "C9200L-48P-4X", "C9300L-48P-4X", "C9300L-48T-4X", "C9500-48Y4C",
    "N9K-C93108TC-EX", "N9K-C93108TC-FX", "N9K-C93108TC-FX3", "JL724B",
    "S5735-L8T4X-QA-V2", "S5735-S24T4XE-V2", "S5735-S24P4XE-V2", "S5735-S48T4XE-V2", "S5755-H24T4Y2CZ", "S5755-H48UM4Y2CZ",
}
HUAWEI_KEYS = ("S5735-L8T4X-QA-V2", "S5735-S24T4XE-V2", "S5735-S24P4XE-V2", "S5735-S48T4XE-V2", "S5755-H24T4Y2CZ", "S5755-H48UM4Y2CZ")
ROUTER_KEYS = {"C8200-1N-4T", "C8200L-1N-4T", "C8300-1N1S-6T", "ISR4431/K9", "ISR4331/K9", "ASR1002-X", "CISCO3825"}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("NES_DISABLE_AUTH", "1")
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _convert(path, vendor, model):
    return convert_file(path, target_vendor=vendor, target_model=model, domain="switch")


def _row(result, source):
    return next(r for r in result["interface_map"]["rows"] if r["source"] == source)


# ------------------------------------------------------------------------------------------------- catalog
def test_catalog_holds_every_sample_switch_and_router():
    assert {m.key for m in SWITCH_MODELS} == SWITCH_KEYS
    assert {m.key for m in ROUTER_MODELS} == ROUTER_KEYS
    assert len({m.key for m in ALL_MODELS}) == len(ALL_MODELS)


def test_every_model_links_to_a_vendor_document():
    for model in ALL_MODELS:
        assert model.doc_url.startswith(("https://www.cisco.com/", "https://www.hpe.com/", "https://e.huawei.com/")), model.key
        assert model.doc_title, model.key
        assert model.groups, model.key


def test_port_counts_match_the_data_sheets():
    def count(key, role):
        return sum(g.count for g in get_model(key).groups if g.role == role)

    assert count("C9300-48P", "access") == 48
    assert count("C9300X-24Y", "access") == 24
    assert count("C9200L-24P-4X", "uplink") == 4
    assert count("N9K-C93108TC-FX3", "access") == 48 and count("N9K-C93108TC-FX3", "uplink") == 6
    assert count("JL724B", "access") == 24 and count("JL724B", "uplink") == 4
    assert count("C8300-1N1S-6T", "onboard") == 6
    assert count("ISR4331/K9", "onboard") == 3


def test_nexus_fx_is_not_mistaken_for_fx3():
    fx, _ = detect_model("PID: N9K-C93108TC-FX       , VID: V01", "switch")
    fx3, _ = detect_model("PID: N9K-C93108TC-FX3      , VID: V01", "switch")
    assert fx.key == "N9K-C93108TC-FX" and fx3.key == "N9K-C93108TC-FX3"


def test_a_neighbour_table_does_not_outvote_the_chassis_pid():
    text = "Platform: C9300X-24Y\n" * 2 + "PID: C9200L-24P-4X , VID: V01\n"
    best, _ = detect_model(text, "switch")
    assert best.key == "C9200L-24P-4X"


def test_target_choices_name_the_uplink_module():
    cisco = {m["model"] for m in target_models("Cisco")}
    assert "C9300-48P+C9300-NM-8X" in cisco and "C9200L-24P-4X" in cisco
    assert not any(k.startswith("N9K") for k in cisco), "NX-OS syntax is not generated, so Nexus is not a target"
    assert [m["model"] for m in target_models("Aruba")] == ["JL724B"]
    assert available_target_models("Cisco") == target_models("Cisco")
    assert any(m["model"] == "S5735-S48T4XE-V2" for m in available_target_models("Huawei"))


def test_parse_name_ignores_logical_interfaces():
    assert parse_name("Vlan10") is None and parse_name("Port-channel3") is None and parse_name("Gi1/0/1.100") is None
    assert parse_name("Te1/1/3")["keyword"] == "TenGigabitEthernet"
    assert parse_name("mgmt0")["keyword"] == "mgmt"


# ------------------------------------------------------------------------------------------ interface map
def test_uplink_module_ports_are_numbered_from_the_target_model():
    result = _convert(NM8X, "Huawei", "S5735-S48T4XE-V2")
    assert result["interface_map"]["source_model"] == "C9300-48P"
    assert result["interface_map"]["source_modules"] == ["C9300-NM-8X"]
    assert _row(result, "TenGigabitEthernet1/1/1")["target"] == "10GE1/0/1"
    assert _row(result, "TenGigabitEthernet1/1/3")["target"] == "10GE1/0/3"
    assert _row(result, "GigabitEthernet1/0/48")["target"] == "GE1/0/48"
    assert _row(result, "GigabitEthernet0/0")["target"] == "MEth0/0/0"
    assert "interface 10GE1/0/3" in result["output_text"]


def test_a_port_the_target_does_not_have_is_flagged_not_hidden():
    result = _convert(NM8X, "Huawei", "S5735-S48T4XE-V2")
    row = _row(result, "TenGigabitEthernet1/1/8")
    assert row["status"] == "missing"
    assert "only 4x 10G" in row["note"]
    assert "only 4x 10G" in result["output_text"], "the converted config carries the same warning"


def test_without_a_target_model_uplinks_are_still_flagged_for_review():
    result = _convert(NM8X, "Huawei", None)
    row = _row(result, "TenGigabitEthernet1/1/3")
    assert row["target"] == "10GE1/0/3" and row["status"] == "review"
    assert "Target Model not chosen" in row["note"]


def test_the_25g_target_numbers_uplinks_by_its_own_speed():
    result = _convert(NM8X, "Huawei", "S5755-H24T4Y2CZ")
    row = _row(result, "TenGigabitEthernet1/1/2")
    assert row["target"] == "25GE1/0/2" and row["status"] == "review"
    assert "10G -> 25G" in row["note"]


def test_module_slot_personality_stanzas_are_reported_but_not_mapped():
    result = _convert(NM4M, "Huawei", "S5735-S24T4XE-V2")
    stanza = _row(result, "TenGigabitEthernet1/1/5")
    assert stanza["status"] == "stanza" and stanza["target"] == ""
    assert result["interface_map"]["source_modules"] == ["C9300-NM-4M"]
    port = _row(result, "GigabitEthernet1/1/2")
    assert port["target"] == "10GE1/0/2" and port["status"] == "review"
    assert "SFP+" in port["note"], "an RJ45 mGig port landing on an SFP+ cage needs a transceiver"


def test_aruba_target_uses_member_slash_one_slash_port():
    result = _convert(NM8X, "Aruba", "JL724B")
    assert _row(result, "GigabitEthernet1/0/2")["target"] == "1/1/2"
    assert _row(result, "TenGigabitEthernet1/1/1")["target"] == "1/1/25"
    mgmt = _row(result, "GigabitEthernet0/0")
    assert mgmt["status"] == "missing" and "management" in mgmt["note"]
    assert "interface 1/1/25" in result["output_text"]


def test_aruba_source_with_vsf_members_maps_to_a_catalyst_module():
    result = _convert(ARUBA, "Cisco", "C9300-48P+C9300-NM-8X")
    assert result["interface_map"]["source_model"] == "JL724B"
    assert result["interface_map"]["members"] == [1, 2]
    assert _row(result, "1/1/25")["target"] == "TenGigabitEthernet1/1/1"
    assert _row(result, "2/1/26")["target"] == "TenGigabitEthernet2/1/2"
    assert "interface TenGigabitEthernet2/1/2" in result["output_text"]


def test_same_vendor_conversion_without_a_target_model_keeps_the_names():
    result = _convert(NM8X, "Cisco", None)
    assert _row(result, "TenGigabitEthernet1/1/3")["target"] == "TenGigabitEthernet1/1/3"
    assert "interface TenGigabitEthernet1/1/3" in result["output_text"]


def test_stack_member_beyond_the_target_limit_is_flagged():
    names = [("GigabitEthernet9/0/1", True)]
    result = build_interface_map(names, source_model=get_model("C9300-48P"), target_vendor="Cisco", target_model="C9200L-24P-4X")
    row = next(r for r in result["rows"] if r["source"] == "GigabitEthernet9/0/1")
    assert row["status"] == "missing"
    assert "8-member limit" in row["note"]


def test_every_source_port_of_the_model_is_listed_once_per_member():
    result = build_interface_map(
        [("GigabitEthernet1/0/1", True), ("GigabitEthernet2/0/1", True)],
        source_model=get_model("C9200L-24P-4X"), target_vendor="Huawei", target_model="S5735-S24T4XE-V2",
    )
    assert result["members"] == [1, 2]
    sources = [r["source"] for r in result["rows"]]
    assert len(sources) == len(set(sources)) == 2 * (24 + 4) + 1  # two members + one management port


def test_unknown_source_model_still_gets_a_name_based_map():
    result = build_interface_map(
        [("TenGigabitEthernet1/1/3", True), ("Ethernet1/7", True)],
        source_text="", target_vendor="Huawei", target_model=None,
    )
    assert result["source_model"] == ""
    by = {r["source"]: r for r in result["rows"]}
    assert by["TenGigabitEthernet1/1/3"]["target"] == "10GE1/0/3"
    assert by["Ethernet1/7"]["status"] == "review" and "speed" in by["Ethernet1/7"]["note"]


# ----------------------------------------------------------------------------------------------- web pages
def test_switch_page_lists_every_switch_and_the_new_targets(client):
    html = client.get("/convert/switch").get_data(as_text=True)
    for key in SWITCH_KEYS:
        assert f'data-model="{key}"' in html, key
    assert 'id="interface-map-panel"' in html
    for url in ("catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html", "nexus-9000-series-switches/datasheet-c78-744052.html"):
        assert url in html
    assert "C9300-48P+C9300-NM-8X" in html  # embedded in the target-models-by-vendor JSON


def test_router_page_has_the_model_dropdown_and_catalog_but_cannot_convert(client):
    html = client.get("/convert/router").get_data(as_text=True)
    assert '<fieldset class="cv-fieldset" disabled>' in html
    assert "Not available yet" in html
    for key in ROUTER_KEYS:
        assert f'data-model="{key}"' in html, key
        assert f'<option value="{key}">' in html, key
    assert "SPA-8X1GE-V2" in html and "HWIC-4ESW" in html
    assert "js/configuration.js" not in html


def test_convert_api_returns_the_interface_map(client):
    with NM8X.open("rb") as handle:
        response = client.post(
            "/configuration/api/convert",
            data={"config_file": (handle, "sw.txt"), "target_vendor": "Huawei", "target_model": "S5735-S48T4XE-V2", "domain": "switch"},
            content_type="multipart/form-data",
        )
    payload = response.get_json()
    assert payload["ok"], payload
    mapped = payload["result"]["interface_map"]
    assert mapped["counts"]["missing"] >= 1 and mapped["port_check"] is True


def test_ojk_models_detect_and_expose_their_real_port_names():
    """C9300L fixed uplinks are Te<m>/1/<n>; the C9500-48Y4C is TwentyFiveGigE<m>/0/1-48 plus HundredGigE<m>/0/49-52 (names read from the OJK captures)."""
    l48p = get_model("C9300L-48P-4X")
    assert [g.name(2, 4) for g in l48p.groups if g.role == "uplink"] == ["TenGigabitEthernet2/1/4"]
    assert l48p.max_members == 8
    y4c = get_model("C9500-48Y4C")
    names = {g.name(1, g.first) for g in y4c.groups}
    assert {"TwentyFiveGigE1/0/1", "HundredGigE1/0/49"} <= names
    assert y4c.max_members is None   # the data sheet gives no StackWise Virtual limit, so none is invented
    assert detect_model("Model Number : C9500-48Y4C\n")[0].key == "C9500-48Y4C"
    assert detect_model("PID: C9300L-48T-4X , VID: V01")[0].key == "C9300L-48T-4X"


# ------------------------------------------------------------------------------------------------- Huawei catalog
def test_huawei_models_match_the_data_sheets():
    expected = {  # key: (GE/Multi-GE access ports, 10G uplinks, 25G uplinks, 100G uplinks, stack limit)
        "S5735-L8T4X-QA-V2": (8, 4, 0, 0, None),
        "S5735-S24T4XE-V2": (24, 4, 0, 0, 9),
        "S5735-S24P4XE-V2": (24, 4, 0, 0, 9),
        "S5735-S48T4XE-V2": (48, 4, 0, 0, 9),
        "S5755-H24T4Y2CZ": (24, 0, 4, 2, 9),
        "S5755-H48UM4Y2CZ": (48, 0, 4, 2, 9),
    }
    for key, (access, g10, g25, g100, stack) in expected.items():
        model = get_model(key)
        assert model.vendor == "Huawei" and model.os_name == "VRP" and model.target_ok, key
        assert model.doc_url.startswith("https://e.huawei.com/"), key
        count = lambda speed, role: sum(g.count for g in model.groups if g.role == role and g.speed == speed)  # noqa: E731
        assert count("1G", "access") + count("mGig", "access") == access, key
        assert (count("10G", "uplink"), count("25G", "uplink"), count("100G", "uplink")) == (g10, g25, g100), key
        assert model.max_members == stack, key


def test_huawei_port_names_and_poe():
    s24p = get_model("S5735-S24P4XE-V2")
    assert s24p.groups[0].poe == "PoE+" and get_model("S5735-S24T4XE-V2").groups[0].poe == ""
    um = get_model("S5755-H48UM4Y2CZ")
    assert um.groups[0].name(2, 7) == "MultiGE2/0/7" and um.groups[0].speed == "mGig" and um.groups[0].poe.startswith("PoE++")
    assert [g.name(1, 2) for g in get_model("S5755-H24T4Y2CZ").groups if g.role == "uplink"] == ["25GE1/0/2", "100GE1/0/2"]
    assert get_model("S5735-S48T4XE-V2").groups[1].name(1, 4) == "10GE1/0/4"
    assert [g.name(1, 0) for g in get_model("S5735-S48T4XE-V2").groups if g.role == "mgmt"] == ["MEth0/0/0"]


def test_huawei_dropdown_comes_from_the_catalog():
    models = available_target_models("Huawei")
    assert tuple(m["model"] for m in models) == HUAWEI_KEYS
    assert models == target_models("Huawei")
    assert all(get_model(m["model"]).label == m["label"] for m in models)


def test_huawei_model_is_detected_in_display_version_text():
    text = "HUAWEI S5735-S48T4XE-V2 Switch\nVRP (R) software, Version 5.170 (S5735 V200R021C00SPC100)\n"
    best, others = detect_model(text, "switch")
    assert best.key == "S5735-S48T4XE-V2" and others == []
    assert detect_model("S5735-S24T4XE-V2 Switch", "switch")[0].key == "S5735-S24T4XE-V2"  # no prefix clash with ...S24P4XE


def test_huawei_names_parse_both_spellings():
    assert parse_name("10GE1/0/1")["keyword"] == "10GE" and parse_name("10GE1/0/1")["nums"] == (1, 0, 1)
    assert parse_name("25GE1/0/4")["nums"] == (1, 0, 4) and parse_name("MultiGE1/0/48")["keyword"] == "MultiGE"
    assert parse_name("XGigabitEthernet0/0/2")["keyword"] == "XGigabitEthernet" and parse_name("MEth0/0/0")["keyword"] == "MEth"
    assert parse_name("Eth-Trunk1") is None and parse_name("Vlanif10") is None


def test_huawei_source_ports_map_onto_a_cisco_target():
    names = [("GE1/0/1", True), ("GE1/0/24", True), ("10GE1/0/1", True), ("10GE1/0/4", True), ("GE2/0/3", True), ("MEth0/0/0", True)]
    result = build_interface_map(
        names, source_text="HUAWEI S5735-S24T4XE-V2 Switch", target_vendor="Cisco", target_model="C9200L-24P-4X",
    )
    assert result["source_model"] == "S5735-S24T4XE-V2" and result["members"] == [1, 2]
    by = {r["source"]: r for r in result["rows"]}
    assert by["GE1/0/24"]["target"] == "GigabitEthernet1/0/24" and by["GE1/0/24"]["status"] == "ok"
    assert by["GE2/0/3"]["target"] == "GigabitEthernet2/0/3"
    assert by["10GE1/0/4"]["target"] == "TenGigabitEthernet1/1/4" and by["10GE1/0/4"]["status"] == "ok"
    assert by["MEth0/0/0"]["target"] == "GigabitEthernet0/0"
    assert len([r for r in result["rows"] if r["role"] == "access" and r["member"] == 1]) == 24  # unused ports are listed too


def test_legacy_gigabitethernet_names_on_a_huawei_source_are_recognised():
    result = build_interface_map(
        [("GigabitEthernet0/0/5", True), ("XGigabitEthernet0/0/1", True)],
        source_text="S5735-S24T4XE-V2", target_vendor="Aruba", target_model="JL724B",
    )
    by = {r["source"]: r for r in result["rows"]}
    assert by["GigabitEthernet0/0/5"]["target"] == "1/1/5" and by["XGigabitEthernet0/0/1"]["target"] == "1/1/25"


def test_cisco_ports_map_onto_the_multi_gige_target_without_noise():
    result = build_interface_map(
        [("GigabitEthernet1/0/10", True), ("TenGigabitEthernet1/1/2", True)],
        source_model=get_model("C9200L-48P-4X"), target_vendor="Huawei", target_model="S5755-H48UM4Y2CZ",
    )
    by = {r["source"]: r for r in result["rows"]}
    assert by["GigabitEthernet1/0/10"]["target"] == "MultiGE1/0/10" and by["GigabitEthernet1/0/10"]["status"] == "ok"
    assert by["TenGigabitEthernet1/1/2"]["target"] == "25GE1/0/2" and by["TenGigabitEthernet1/1/2"]["status"] == "review"


def test_a_converted_config_uses_multige_names_on_the_multi_gige_target():
    result = _convert(NM8X, "Huawei", "S5755-H48UM4Y2CZ")
    assert _row(result, "GigabitEthernet1/0/48")["target"] == "MultiGE1/0/48"
    assert "interface MultiGE1/0/48" in result["output_text"]
    assert "interface GE1/0/48\n" not in result["output_text"]
    assert _row(result, "TenGigabitEthernet1/1/8")["status"] == "missing"  # only 4 SFP28 cages


def test_ports_beyond_the_target_are_flagged_on_the_24_port_models():
    result = _convert(NM8X, "Huawei", "S5735-S24T4XE-V2")
    row = _row(result, "GigabitEthernet1/0/48")
    assert row["status"] == "missing" and "only 24x 1G" in row["note"]
