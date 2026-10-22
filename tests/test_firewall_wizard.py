"""Guided firewall conversion (MikroTik RouterOS -> Palo Alto PAN-OS).

Covers the three layers the wizard relies on:

* the translator emits PAN-OS CLI paths that match the configuration XML
  (network ike gateway / crypto-profiles, proxy-id under auto-key) and
  binds every IKE gateway to a local interface;
* pan_validator finds every unresolved reference and the commit blockers
  visible without a firewall;
* the wizard keeps a port swap consistent everywhere, gates each step on
  the errors of the steps before it, and refuses export until all pass.

All configurations are synthetic.
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path

import pytest

from features.configuration_studio.converter_engine.engine import MigrationEngine
from features.configuration_studio.converter_engine.wizard import firewall_wizard as fw
from features.configuration_studio.converter_engine.wizard.pan_validator import validate

BRANCH_RSC = """
/system identity
set name=BRANCH-01
/interface ethernet
set [ find default-name=ether1 ] comment="LAN switch"
set [ find default-name=ether2 ] comment="ISP uplink"
set [ find default-name=ether3 ] comment="spare"
/interface bridge
add name=br-lan
/interface bridge port
add bridge=br-lan interface=ether1
/interface list
add name=WAN
/interface list member
add interface=ether2 list=WAN
/ip address
add address=192.168.10.1/24 interface=br-lan
add address=203.0.113.6/29 interface=ether2
/ip route
add gateway=203.0.113.1
/ip firewall address-list
add address=192.168.10.0/24 list=lan-net
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether2 comment=hide
/ip firewall filter
add action=accept chain=forward in-interface=ether1 out-interface-list=WAN comment=lan-out
/ip ipsec profile
add dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256 name=ike-prof lifetime=1d
/ip ipsec proposal
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc name=esp-prop pfs-group=modp2048 lifetime=1h
/ip ipsec peer
add address=198.51.100.50/32 exchange-mode=ike2 local-address=203.0.113.6 name=hq profile=ike-prof
/ip ipsec policy
add dst-address=10.50.0.0/24 peer=hq proposal=esp-prop src-address=192.168.10.0/24 tunnel=yes comment=to-hq
"""


@pytest.fixture()
def parsed():
    engine = MigrationEngine()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "branch.rsc"
        path.write_text(BRANCH_RSC, encoding="utf-8")
        config = engine.parse(filename=path, source_vendor="Mikrotik", source_device_type="Firewall")
    translator = engine.get_translator(vendor="Palo Alto", device_type="Firewall")
    return config, translator


def _lines(config, translator, mapping=None, model=None):
    return [str(x) for x in translator.translate(config, mapping=mapping or {"interfaces": {}}, target_model=model)]


# ------------------------------------------------------------------ translator syntax

def test_ike_and_ipsec_use_the_pan_os_configuration_paths(parsed):
    config, translator = parsed
    text = "\n".join(_lines(config, translator))
    assert "set network ike crypto-profiles ike-crypto-profiles ike-prof encryption aes-256-cbc" in text
    assert "set network ike crypto-profiles ike-crypto-profiles ike-prof lifetime days 1" in text
    assert "set network ike crypto-profiles ipsec-crypto-profiles esp-prop esp encryption aes-256-cbc" in text
    assert "set network ike crypto-profiles ipsec-crypto-profiles esp-prop lifetime hours 1" in text
    assert "set network ike gateway hq protocol version ikev2" in text
    assert "set network tunnel ipsec to-hq auto-key ike-gateway hq" in text
    assert "set network tunnel ipsec to-hq auto-key proxy-id proxy1 local 192.168.10.0/24" in text
    for old in ("network ike-gateway", "network ike-crypto-profile", "network ipsec-crypto-profile", "lifetime-seconds"):
        assert old not in text
    assert "ipsec to-hq proxy-id" not in text


def test_ike_gateway_binds_to_the_interface_that_owns_the_local_address(parsed):
    config, translator = parsed
    text = "\n".join(_lines(config, translator))
    assert "set network ike gateway hq local-address interface ethernet1/2" in text
    assert "set network ike gateway hq local-address ip 203.0.113.6/29" in text
    assert "peer-address ip 198.51.100.50\n" in text + "\n"


def test_ike_gateway_follows_the_target_port_of_a_swap(parsed):
    config, translator = parsed
    mapping = {"interfaces": {"ether2": {"pan_interface": "ethernet1/1"}, "ether1": {"pan_interface": "ethernet1/2"}}}
    text = "\n".join(_lines(config, translator, mapping))
    assert "set network ike gateway hq local-address interface ethernet1/1" in text


def test_negated_nat_address_is_never_written_into_the_rule():
    from features.configuration_studio.converter_engine.models.firewall import FirewallConfig, Interface, NatRule
    from features.configuration_studio.converter_engine.translators.firewall.paloalto import PaloAltoFirewallTranslator

    config = FirewallConfig(hostname="x")
    config.interfaces.append(Interface(name="ether1", interface_type="ethernet", default_name="ether1"))
    config.nat_rules.append(NatRule(chain="dstnat", action="dst-nat", dst_address="!10.0.0.0/8",
                                    to_addresses="10.9.9.10", protocol="tcp", dst_port="443", comment="web"))
    text = "\n".join(PaloAltoFirewallTranslator().translate(config))
    assert "!10.0.0.0/8" not in "\n".join(l for l in text.splitlines() if l.startswith("set "))


def test_the_set_parser_reads_both_ike_syntaxes():
    from features.configuration_studio.converter_engine.parsers.firewall.paloalto import PaloAltoFirewallParser

    new = """set network ike crypto-profiles ike-crypto-profiles P encryption [ aes-256-cbc aes-128-cbc ]
set network ike crypto-profiles ike-crypto-profiles P lifetime hours 8
set network ike gateway G protocol ikev2 ike-crypto-profile P
set network ike gateway G protocol version ikev2
set network ike gateway G local-address interface ethernet1/1
set network ike gateway G peer-address ip 198.51.100.1
set network tunnel ipsec T auto-key ike-gateway G
set network tunnel ipsec T auto-key proxy-id p1 local 10.0.0.0/24
"""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "pan.txt"
        path.write_text(new, encoding="utf-8")
        config = PaloAltoFirewallParser().parse_file(str(path))
    assert config.ike_crypto_profiles[0].encryption == "aes-256-cbc"
    assert config.ike_crypto_profiles[0].lifetime_seconds == 8 * 3600
    gateway = config.ike_gateways[0]
    assert (gateway.ike_crypto_profile, gateway.version, gateway.local_interface) == ("P", "ikev2", "ethernet1/1")
    assert config.ipsec_tunnels[0].proxy_id_local == "10.0.0.0/24"
    assert not config.unhandled_commands


# ------------------------------------------------------------------ validator

def _codes(lines, ports=None):
    return {issue.code for issue in validate(lines, ports)}


def test_validator_reports_unresolved_references():
    lines = [
        "set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24",
        "set zone LAN network layer3 [ ethernet1/1 ethernet1/9 ]",
        "set address-group G static [ missing ]",
        "set rulebase security rules r1 from [ LAN ]",
        "set rulebase security rules r1 to [ WAN ]",
        "set rulebase security rules r1 source [ nope ]",
        "set rulebase security rules r1 destination [ any ]",
        "set rulebase security rules r1 service [ svc-x ]",
        "set rulebase security rules r1 action allow",
        "set network tunnel ipsec T auto-key ike-gateway GW",
    ]
    codes = _codes(lines)
    assert {"REF-INTERFACE", "REF-ADDRESS", "REF-ZONE", "REF-SERVICE", "REF-GATEWAY", "VPN-TUN-IF"} <= codes


def test_validator_catches_commit_blockers():
    lines = [
        "set network interface ethernet ethernet1/1 layer3 ip 10.0.0.1/24",
        "set network interface ethernet ethernet1/2 layer3 ip 10.0.0.2/25",
        "set network interface ethernet ethernet1/12 layer3 ip 172.16.0.1/24",
        "set zone A network layer3 [ ethernet1/1 ]",
        "set zone B network layer3 [ ethernet1/1 ethernet1/2 ]",
        "set network ike crypto-profiles ike-crypto-profiles P encryption aes-256",
        "set network ike gateway G protocol ikev2 ike-crypto-profile P",
        "set rulebase nat rules n from [ A ]",
        "set rulebase nat rules n to [ A B ]",
        "set rulebase nat rules n source [ any ]",
        "set rulebase nat rules n destination [ !10.0.0.0/8 ]",
    ]
    codes = _codes(lines, ports=7)
    assert {"IF-OVERLAP", "ZONE-DUP-IF", "IF-PORT-MISSING", "VPN-ALGO", "VPN-GW-LOCAL", "NAT-TO-MULTI", "NAT-NEGATE"} <= codes


def test_validator_is_clean_on_a_consistent_config(parsed):
    config, translator = parsed
    mapping = {"interfaces": {}, "ipsec_tunnels": {"to-hq": {"zone": "VPN", "tunnel_unit": 1}}}
    errors = [i for i in validate(_lines(config, translator, mapping), 7) if i.severity == "error"]
    assert errors == []


# ------------------------------------------------------------------ wizard

def _evaluate(config, translator, changes=None, model="PA-505"):
    state = fw.initial_state(config, translator, model)
    state = fw.merge_state(state, changes or {})
    return fw.evaluate(config, translator, state)


def _step(result, key):
    return next(s for s in result["steps"] if s["key"] == key)


def test_roles_are_detected_from_the_source(parsed):
    config, translator = parsed
    facts = fw.describe_source(config)
    assert facts["ether2"]["role"] == "inet"
    assert facts["ether1"]["role"] == "lan"
    assert facts["ether3"]["used"] is False


def test_swapping_lan_and_inet_ports_keeps_every_reference_consistent(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {
        "interfaces": {"ether1": {"pan_interface": "ethernet1/2"}, "ether2": {"pan_interface": "ethernet1/1"}},
        "ipsec_tunnels": {"to-hq": {"zone": "VPN"}},
    })
    text = result["output_text"]
    assert "set network vlan br-lan interface [ ethernet1/2 ]" in text
    assert "set network interface ethernet ethernet1/1 layer3 ip 203.0.113.6/29" in text
    assert "interface-address interface ethernet1/1" in text
    assert "local-address interface ethernet1/1" in text
    assert all(s["counts"]["error"] == 0 for s in result["steps"])
    assert any(i["code"] == "MAP-RENUMBER" for i in _step(result, "interfaces")["issues"])


def test_two_sources_on_one_port_and_an_unmapped_used_port_are_errors(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {"interfaces": {"ether3": {"pan_interface": "ethernet1/2"}}})
    assert "MAP-DUP" in {i["code"] for i in _step(result, "interfaces")["issues"]}
    result = _evaluate(config, translator, {"interfaces": {"ether2": {"pan_interface": ""}}})
    assert "MAP-UNMAPPED" in {i["code"] for i in _step(result, "interfaces")["issues"]}


def test_a_port_the_model_lacks_blocks_the_interfaces_step(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {"interfaces": {"ether2": {"pan_interface": "ethernet1/8"}}})
    interfaces = _step(result, "interfaces")
    assert interfaces["status"] == "error"
    assert not _step(result, "zones")["reachable"]


def test_renamed_zones_follow_into_rules_written_on_bridge_ports_and_interface_lists(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {
        "interfaces": {"br-lan": {"zone": "LAN"}, "ether2": {"zone": "INTERNET"}},
        "ipsec_tunnels": {"to-hq": {"zone": "VPN"}},
    })
    text = result["output_text"]
    assert "set rulebase security rules lan-out from [ LAN ]" in text
    assert "set rulebase security rules lan-out to [ INTERNET ]" in text
    assert _step(result, "policy")["counts"]["error"] == 0


def test_steps_open_in_order_and_export_needs_every_step(parsed):
    config, translator = parsed
    result = _evaluate(config, translator)
    vpn = _step(result, "vpn")
    assert vpn["status"] == "error"  # tunnel has no zone yet
    assert not result["ready"]
    later = result["steps"][result["steps"].index(vpn) + 1:]
    assert all(not s["reachable"] for s in later)


# ------------------------------------------------------------------ API

@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app import create_app
    from features.configuration_studio import routes

    monkeypatch.setattr(routes, "WIZARD_DIR", tmp_path / "wizard")
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _start(client, text=BRANCH_RSC, model="PA-505"):
    return client.post(
        "/configuration/api/wizard/start",
        data={"config_file": (io.BytesIO(text.encode()), "branch.rsc"), "target_model": model},
        content_type="multipart/form-data",
    )


def test_api_refuses_export_until_every_step_passes(client):
    response = _start(client)
    assert response.status_code == 200
    result = response.get_json()["result"]
    token = result["token"]
    assert client.get(f"/configuration/api/wizard/{token}/download").status_code == 400

    state = result["state"]
    state["ipsec_tunnels"]["to-hq"]["zone"] = "VPN"
    result = client.post(f"/configuration/api/wizard/{token}/validate", json={"state": state}).get_json()["result"]
    state["acknowledged"] = [i["key"] for s in result["steps"] for i in s["issues"] if i["severity"] == "warning"]
    result = client.post(f"/configuration/api/wizard/{token}/validate", json={"state": state}).get_json()["result"]
    assert result["ready"] is True

    download = client.get(f"/configuration/api/wizard/{token}/download?rev={result['revision']}")
    assert download.status_code == 200
    body = download.get_data(as_text=True)
    assert body.startswith("# Generated by Keystone guided conversion")
    assert "validate full" in body


def test_api_rejects_unknown_sessions_and_non_mikrotik_sources(client):
    assert client.post("/configuration/api/wizard/nothex/validate", json={}).status_code == 400
    response = _start(client, text="set deviceconfig system hostname PA\nset network interface ethernet ethernet1/1 layer3\n")
    assert response.status_code == 400
    assert "MikroTik" in response.get_json()["error"]


def test_only_the_firewall_page_offers_the_guided_conversion(client):
    assert 'id="wizard-start-button"' in client.get("/convert/firewall").get_data(as_text=True)
    assert 'id="wizard-start-button"' not in client.get("/convert/switch").get_data(as_text=True)


def test_a_rule_on_an_interface_list_uses_every_member_zone(parsed):
    config, translator = parsed
    from features.configuration_studio.converter_engine.models.firewall import InterfaceListMember

    config.interface_list_members.append(InterfaceListMember(list_name="WAN", interface="ether3"))
    mapping = {"interfaces": {"ether2": {"zone": "ISP-A"}, "ether3": {"pan_interface": "ethernet1/3", "zone": "ISP-B"}}}
    text = "\n".join(_lines(config, translator, mapping))
    assert "set rulebase security rules lan-out to [ ISP-A ISP-B ]" in text


# ------------------------------------------------------------------ VLAN, bridge, disabled ports

VLAN_RSC = """
/interface ethernet
set [ find default-name=ether1 ] comment=WAN
set [ find default-name=ether2 ] comment=LAN-1
set [ find default-name=ether3 ] comment=LAN-2
set [ find default-name=ether4 ] comment=DMZ-trunk
set [ find default-name=ether5 ] disabled=yes comment=spare
/interface bridge
add name=br-lan
/interface bridge port
add bridge=br-lan interface=ether2
add bridge=br-lan interface=ether3
/interface vlan
add interface=br-lan name=vlan20-guest vlan-id=20
add interface=ether4 name=vlan30-dmz vlan-id=30
/ip address
add address=203.0.113.6/29 interface=ether1
add address=192.168.10.1/24 interface=br-lan
add address=192.168.20.1/24 interface=vlan20-guest
add address=172.16.30.1/24 interface=vlan30-dmz
add address=10.5.5.1/24 interface=ether5
"""


@pytest.fixture()
def vlan_parsed():
    engine = MigrationEngine()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "vlan.rsc"
        path.write_text(VLAN_RSC, encoding="utf-8")
        config = engine.parse(filename=path, source_vendor="Mikrotik", source_device_type="Firewall")
    return config, engine.get_translator(vendor="Palo Alto", device_type="Firewall")


def test_vlan_on_a_bridge_uses_tagged_layer2_subinterfaces(vlan_parsed):
    config, translator = vlan_parsed
    result = _evaluate(config, translator, model="PA-1410")
    text = result["output_text"]
    assert "set network interface ethernet ethernet1/2 layer2 units ethernet1/2.20 tag 20" in text
    assert "set network vlan vlan20-guest interface [ ethernet1/2.20 ethernet1/3.20 ]" in text
    assert "set network vlan vlan20-guest interface [ ethernet1/2 " not in text
    assert "set network interface ethernet ethernet1/4 layer3 units ethernet1/4.30 tag 30" in text
    assert all(s["counts"]["error"] == 0 for s in result["steps"][:3])


def test_vlan_as_subinterface_on_a_bridge_port_conflicts_and_needs_a_parent(vlan_parsed):
    config, translator = vlan_parsed
    result = _evaluate(config, translator, {"interfaces": {"vlan20-guest": {"mode": "subinterface"}}}, model="PA-1410")
    assert "MAP-VLAN-PARENT" in {i["code"] for i in _step(result, "interfaces")["issues"]}
    result = _evaluate(config, translator, {"interfaces": {"vlan20-guest": {"mode": "subinterface", "parent_port": "ethernet1/2"}}},
                       model="PA-1410")
    assert "IF-MODE" in {i["code"] for i in _step(result, "interfaces")["issues"]}


def test_vlan_tag_unit_and_duplicate_checks(vlan_parsed):
    config, translator = vlan_parsed
    codes = lambda changes: {i["code"] for i in _step(_evaluate(config, translator, changes, model="PA-1410"), "interfaces")["issues"]}
    assert "MAP-VLAN-TAG" in codes({"interfaces": {"vlan30-dmz": {"tag": "5000"}}})
    assert "MAP-VLAN-UNIT" in codes({"interfaces": {"br-lan": {"unit": "20"}}})
    assert "MAP-BRIDGE-ROUTED" in codes({"interfaces": {"br-lan": {"mode": "routed"}}})


def test_vlan_tag_and_unit_overrides_reach_the_output(vlan_parsed):
    config, translator = vlan_parsed
    result = _evaluate(config, translator, {"interfaces": {"vlan30-dmz": {"tag": "130"}, "vlan20-guest": {"unit": "200"},
                                                           "br-lan": {"unit": "10"}}}, model="PA-1410")
    text = result["output_text"]
    assert "ethernet1/4.130 tag 130" in text
    assert "set network vlan vlan20-guest vlan-interface vlan.200" in text
    assert "set network interface vlan units vlan.10 ip 192.168.10.1/24" in text


def test_disabled_port_is_shown_and_written_link_down(vlan_parsed):
    config, translator = vlan_parsed
    facts = fw.describe_source(config)
    assert facts["ether5"]["disabled"] is True and facts["ether5"]["used"] is False
    # Disabled and unused: unmapped by default, so nothing is written for it.
    text = _evaluate(config, translator, model="PA-1410")["output_text"]
    assert "ethernet1/5" not in "\n".join(l for l in text.splitlines() if l.startswith("set "))
    # Mapped on purpose: it is converted but stays down.
    text = _evaluate(config, translator, {"interfaces": {"ether5": {"pan_interface": "ethernet1/5"}}}, model="PA-1410")["output_text"]
    assert "set network interface ethernet ethernet1/5 link-state down" in text


def test_synthetic_vlan_numbers_are_stable_across_runs(vlan_parsed):
    config, translator = vlan_parsed
    first = _evaluate(config, translator, model="PA-1410")["output_text"]
    second = _evaluate(config, translator, model="PA-1410")["output_text"]
    assert first == second


def test_an_enabled_unused_port_starts_unmapped_and_writes_nothing(parsed):
    config, translator = parsed
    state = fw.initial_state(config, translator, "PA-505")
    assert state["interfaces"]["ether3"]["pan_interface"] == ""
    result = fw.evaluate(config, translator, state)
    set_lines = [l for l in result["output_text"].splitlines() if l.startswith("set ")]
    assert not any("ethernet1/3" in l or "ether3" in l for l in set_lines)
    assert not any(i["code"] == "MAP-UNMAPPED" for i in _step(result, "interfaces")["issues"])


def test_unmapping_a_used_port_is_still_an_error(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {"interfaces": {"ether1": {"pan_interface": ""}}})  # bridge member
    assert "MAP-UNMAPPED" in {i["code"] for i in _step(result, "interfaces")["issues"]}



# ------------------------------------------------------------------ regressions from the debugging pass

def test_download_refuses_a_revision_that_was_not_the_last_check(client):
    result = _start(client).get_json()["result"]
    token, state = result["token"], result["state"]
    state["ipsec_tunnels"]["to-hq"]["zone"] = "VPN"
    result = client.post(f"/configuration/api/wizard/{token}/validate", json={"state": state}).get_json()["result"]
    state["acknowledged"] = [i["key"] for s in result["steps"] for i in s["issues"] if i["severity"] == "warning"]
    ready = client.post(f"/configuration/api/wizard/{token}/validate", json={"state": state}).get_json()["result"]
    assert ready["ready"]
    old_revision = ready["revision"]
    # an edit that was checked afterwards changes the revision ...
    state["interfaces"]["ether2"]["zone"] = "INTERNET"
    newer = client.post(f"/configuration/api/wizard/{token}/validate", json={"state": state}).get_json()["result"]
    assert newer["revision"] != old_revision
    # ... so a page still holding the old one cannot download, and neither can a missing one
    assert client.get(f"/configuration/api/wizard/{token}/download?rev={old_revision}").status_code == 400
    assert client.get(f"/configuration/api/wizard/{token}/download").status_code == 400


def test_a_port_in_a_slot_the_model_lacks_is_an_error(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {"interfaces": {"ether2": {"pan_interface": "ethernet2/1"}}})
    assert "MAP-PORT-MISSING" in {i["code"] for i in _step(result, "interfaces")["issues"]}
    assert "IF-PORT-MISSING" in {i.code for i in validate(["set network interface ethernet ethernet2/1 layer3"], 7)}


def test_two_tunnels_cannot_share_a_tunnel_unit_and_units_must_be_numbers():
    engine = MigrationEngine()
    text = BRANCH_RSC + ("/ip ipsec policy\nadd dst-address=10.60.0.0/24 peer=hq proposal=esp-prop "
                         "src-address=192.168.10.0/24 tunnel=yes comment=to-dr\n")
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "two.rsc"
        path.write_text(text, encoding="utf-8")
        config = engine.parse(filename=path, source_vendor="Mikrotik", source_device_type="Firewall")
    translator = engine.get_translator(vendor="Palo Alto", device_type="Firewall")
    codes = {i["code"] for i in _step(_evaluate(config, translator, {"ipsec_tunnels": {
        "to-hq": {"zone": "VPN", "tunnel_unit": 1}, "to-dr": {"zone": "VPN", "tunnel_unit": 1}}}), "vpn")["issues"]}
    assert {"MAP-TUNNEL-DUP", "VPN-TUN-DUP"} <= codes
    codes = {i["code"] for i in _step(_evaluate(config, translator, {"ipsec_tunnels": {
        "to-hq": {"zone": "VPN", "tunnel_unit": "abc"}, "to-dr": {"zone": "VPN", "tunnel_unit": 2}}}), "vpn")["issues"]}
    assert "MAP-TUNNEL-UNIT" in codes


def test_ike_gateway_keeps_its_local_interface_when_the_wan_is_an_sdwan_link(parsed):
    config, translator = parsed
    result = _evaluate(config, translator, {"sdwan": {"enabled": True}, "interfaces": {"ether2": {"sdwan_link_type": "fiber"}},
                                            "ipsec_tunnels": {"to-hq": {"zone": "VPN"}}})
    assert "local-address interface ethernet1/2" in result["output_text"]
    assert "VPN-GW-LOCAL" not in {i["code"] for i in _step(result, "vpn")["issues"]}


def test_a_wan_subinterface_can_be_picked_as_the_ike_local_interface():
    engine = MigrationEngine()
    text = """
/interface ethernet
set [ find default-name=ether1 ] comment=uplink
set [ find default-name=ether2 ] comment=LAN
/interface vlan
add interface=ether1 name=wan-vlan vlan-id=100
/ip address
add address=203.0.113.6/29 interface=wan-vlan
add address=192.168.1.1/24 interface=ether2
/ip ipsec peer
add address=198.51.100.50/32 exchange-mode=ike2 name=hq
/ip ipsec policy
add dst-address=10.50.0.0/24 peer=hq src-address=192.168.1.0/24 tunnel=yes comment=t1
"""
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "wan.rsc"
        path.write_text(text, encoding="utf-8")
        config = engine.parse(filename=path, source_vendor="Mikrotik", source_device_type="Firewall")
    translator = engine.get_translator(vendor="Palo Alto", device_type="Firewall")
    result = _evaluate(config, translator, {"ipsec_tunnels": {"t1": {"zone": "VPN"}}})
    assert "ethernet1/1.100" in result["options"]["gateway_interfaces"]
    result = _evaluate(config, translator, {"ipsec_tunnels": {"t1": {"zone": "VPN"}},
                                            "ipsec_gateways": {"hq": {"local_interface": "ethernet1/1.100"}}})
    assert "local-address interface ethernet1/1.100" in result["output_text"]
    assert _step(result, "vpn")["counts"]["error"] == 0


def test_an_active_session_is_not_expired_by_its_start_time(tmp_path):
    import os
    import time
    from features.configuration_studio import wizard_service

    source = tmp_path / "in.rsc"
    source.write_text(BRANCH_RSC, encoding="utf-8")
    root = tmp_path / "wizard"
    token = wizard_service.start(root, source)["token"]
    stale = time.time() - 2 * wizard_service.SESSION_TTL_SECONDS
    os.utime(root / token, (stale, stale))
    wizard_service.validate(root, token, {})          # still in use
    wizard_service.start(root, source)                # runs the cleanup
    assert (root / token).is_dir()
