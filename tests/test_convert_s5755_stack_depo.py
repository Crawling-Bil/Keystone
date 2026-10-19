"""Convert Switch and Switch Analyzer: Catalyst 3650 stacks to S5755-H24T4Y2CZ stacks (TAM Depo captures).

Real behaviour behind these tests (four deployed S5755-H24T4Y2CZ two-member ring stacks, V600R025C00): the stack links are 25GE<m>/0/3 and
25GE<m>/0/4 at 10G, each carries ``device transceiver 10GBASE-COPPER``, the stack is built with ``interface stack-port <m>/<n>`` and
``port member-group interface <port>``, NetStream exports with ``netstream export ip host <ip> <port> dscp <n>``, and NTP / syslog source the
SVI the Catalyst named.  The configurations here are synthetic (invented host names, RFC 5737 / 5198 documentation addresses); no customer capture is a fixture.
"""
from __future__ import annotations

from pathlib import Path

from features.configuration_studio.converter_engine.hardware import catalog
from features.configuration_studio.service import convert_file
from features.switch_analyzer import service

FIXTURES = Path(__file__).parent / "fixtures" / "switch"


def _out(model: str = "S5755-H24T4Y2CZ", **options) -> str:
    return convert_file(FIXTURES / "cisco_3650_stack_netflow_synthetic.txt", target_vendor="Huawei", domain="switch", target_model=model, **options)["output_text"]


def test_catalog_knows_the_stack_ports_of_the_s5755():
    model = catalog.get_model("S5755-H24T4Y2CZ")
    assert model.stack_ports == ("25GE{m}/0/3", "25GE{m}/0/4")
    assert model.stack_transceiver == "10GBASE-COPPER" and model.stack_shares_bank


def test_a_two_member_source_stack_reserves_the_stack_ports_on_every_member():
    text = _out()
    for port in ("25GE1/0/3", "25GE1/0/4", "25GE2/0/3", "25GE2/0/4"):
        block = text.split(f"interface {port}\n", 1)[1].split("\ninterface ", 1)[0]
        assert "device transceiver 10GBASE-COPPER" in block
        assert "port link-type" not in block and "shutdown" not in block.replace("# ", "")


def test_the_stack_template_uses_the_v600r025c00_member_group_syntax():
    text = _out()
    assert "#   interface stack-port 1/1" in text and "#    port member-group interface 25GE 1/0/3" in text
    assert "#    port member-group interface 25GE 2/0/4" in text
    assert "#    stack member 1 priority 200" in text and "#    stack member 1 priority 100" in text
    assert "port interface 25GE" not in text


def test_the_25ge_bank_is_not_forced_to_gigabit_next_to_the_10g_stack_links():
    text = _out()
    assert " port mode GE" not in text
    assert " # port mode 10GE-GE" in text
    assert text.count("REVIEW-PORT-MODE-BANK") == 1  # once per member bank that has an optic (only member 1 has one here)


def test_netstream_is_converted_for_the_s5755_and_dropped_for_the_s5735():
    text = _out()
    assert "netstream export ip host 198.51.100.50 9996 dscp 0" in text
    assert "netstream export ip source 198.51.100.200" in text
    assert " netstream inbound ip" in text
    other = _out("S5735-S24P4XE-V2")
    assert "netstream export" not in other and "netstream inbound" not in other and "REVIEW-NETSTREAM" in other


def test_ntp_and_loghost_source_the_vlanif_the_catalyst_named():
    text = _out(profile_key="tam_standard")
    assert "ntp server source-interface Vlanif200" in text
    assert "info-center loghost source Vlanif50" in text
    assert "Vlanif-mgmt" not in text


def test_clock_timezone_uses_the_huawei_syntax():
    assert "clock timezone GMT add 07:00:00" in _out()


_HUAWEI = """sysname LAB-S5755
#
interface Vlanif200
 ip address 198.51.100.200 255.255.255.0
#
interface Vlanif50
 ip address 203.0.113.1 255.255.255.252
#
ntp server source-interface Vlanif200
info-center loghost source Vlanif99
netstream export ip host 198.51.100.50 9996 dscp 0
netstream export ip source 198.51.100.77
netstream timeout ip active 1
#
return
"""


def test_the_analyzer_flags_a_netstream_source_the_switch_does_not_own():
    ids = {finding["id"]: finding for finding in service.analyze(_HUAWEI, filename="lab.txt")["findings"]}
    assert "SW-NSF-001" in ids and "198.51.100.77" in ids["SW-NSF-001"]["detail"]
    assert "SW-NSF-002" in ids and "1 second" in ids["SW-NSF-002"]["title"]
    assert "SW-SRC-001" in ids and "Vlanif99" in ids["SW-SRC-001"]["title"]


def test_the_analyzer_stays_quiet_when_the_sources_are_local():
    text = _HUAWEI.replace("198.51.100.77", "198.51.100.200").replace("Vlanif99", "Vlanif50").replace("active 1", "active 60")
    ids = {finding["id"] for finding in service.analyze(text, filename="lab.txt")["findings"]}
    assert not ids & {"SW-NSF-001", "SW-NSF-002", "SW-SRC-001"}
