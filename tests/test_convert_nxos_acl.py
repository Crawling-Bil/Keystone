"""Configuration Studio: a Nexus 9000 running-config (sequence-numbered ACLs, object-groups, RBAC roles, vlan lists, VRF routes).

The fixture is synthetic: invented names, RFC 5737 / RFC 1918 addresses, password hashes of repeated digits.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from features.configuration_studio.converter_engine.parsers.switch import nxos_acl
from features.configuration_studio.converter_engine.translators.switch import acl_common
from features.configuration_studio.service import convert_file

NXOS = Path(__file__).parent / "fixtures" / "switch" / "nxos_acl_synthetic.txt"


def _out(vendor: str, model: str | None = None) -> str:
    return convert_file(NXOS, target_vendor=vendor, target_model=model, domain="switch")["output_text"]


def _section(text: str, header: str) -> list[str]:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == header)
    end = start + 1
    while end < len(lines) and lines[end].strip() not in ("#", "!"):
        end += 1
    return [line.strip() for line in lines[start + 1:end]]


# ------------------------------------------------------------------------------------------------- grammar
def test_nxos_acl_entry_is_flattened_to_ios_lines():
    groups = nxos_acl.collect_groups(NXOS.read_text().splitlines())
    assert groups[("address", "GSVR-DNS")] == ["host 192.0.2.53", "host 192.0.2.54"]
    assert groups[("port", "GPORT-WEB")] == ["eq 80", "eq 443", "range 8080 8090"]
    lines, notes = nxos_acl.expand_entry("60 permit tcp addrgroup GNET-USERS addrgroup GSVR-DNS portgroup GPORT-WEB", groups)
    assert len(lines) == 2 * 2 * 3 and "expanded to 12 rules" in notes[0]    # 2 sources x 2 destinations x 3 port entries
    assert lines[0] == "permit tcp 198.51.100.0 0.0.0.255 host 192.0.2.53 eq 80"
    assert nxos_acl.expand_entry("20 permit icmp any 192.0.2.240/29", groups)[0] == ["permit icmp any 192.0.2.240 0.0.0.7"]
    assert nxos_acl.expand_entry("10 permit ip host 192.0.2.7 any", groups)[0] == ["permit ip host 192.0.2.7 any"]
    assert nxos_acl.expand_entry("10 permit ip 192.0.2.7/32 0.0.0.0/0", groups)[0] == ["permit ip host 192.0.2.7 any"]
    assert nxos_acl.expand_entry("5 remark WEB", groups)[0] == ["remark WEB"]


def test_unknown_group_or_oversized_expansion_is_kept_verbatim_for_review():
    lines, notes = nxos_acl.expand_entry("10 permit ip any addrgroup NOPE", {})
    assert lines == ["permit ip any addrgroup NOPE"] and notes
    big = {("address", "A"): [f"host 192.0.2.{n}" for n in range(1, 41)], ("port", "P"): [f"eq {n}" for n in range(1000, 1020)]}
    lines, notes = nxos_acl.expand_entry("10 permit tcp addrgroup A addrgroup A portgroup P", big)   # 40 x 40 x 20 = 32000
    assert lines == ["permit tcp addrgroup A addrgroup A portgroup P"] and "expands to 32000" in notes[0]


@pytest.mark.parametrize("wildcard,length", [("0.0.0.0", 32), ("0.0.0.255", 24), ("0.0.0.7", 29), ("255.255.255.255", 0), ("0.0.0.254", None), ("0.255.0.255", None)])
def test_wildcard_to_prefix_only_accepts_contiguous_masks(wildcard, length):
    assert acl_common.wildcard_to_prefix(wildcard) == length


# ------------------------------------------------------------------------------------------------- Huawei
def test_huawei_acl_rules_are_real_rules():
    out = _out("Huawei", "S5735-S48T4XE-V2")
    rules = _section(out, "acl name APP-ACL advanced")
    assert "rule 5 permit icmp source any destination 192.0.2.240 0.0.0.7" in rules
    assert "rule 10 permit udp source any destination any destination-port eq 123" in rules      # service name "ntp" written as the number
    assert "rule 15 permit tcp source any destination any destination-port eq 53" in rules
    assert "rule 20 permit tcp source 198.51.100.0 0.0.0.255 destination 192.0.2.53 0 destination-port eq 80" in rules
    assert "rule 30 permit tcp source 198.51.100.0 0.0.0.255 destination 192.0.2.53 0 destination-port range 8080 8090" in rules
    assert "rule 80 permit udp source any source-port eq 123 destination any" in rules            # source port
    assert sum(1 for line in rules if line.startswith("rule ") and "REVIEW" not in line) >= 17
    edge = _section(out, "acl name EDGE-ACL advanced")
    assert "rule 10 permit tcp source 192.0.2.7 0 source-port gt 1023 destination any" in edge
    assert "# remark STARTER" in rules                                                          # a remark is a comment, not a review item
    assert not any("REVIEW-ACL:" in line for line in out.splitlines())
    assert "if-match acl APP-ACL" in out and "traffic-policy APP-ACL inbound" in out            # the SVI binding is still produced


def test_huawei_log_keeps_the_deny_rule_and_flags_logging():
    rules = _section(_out("Huawei", "S5735-S48T4XE-V2"), "acl name APP-ACL advanced")
    index = next(i for i, line in enumerate(rules) if line.startswith("rule 90 deny ip"))
    assert rules[index] == "rule 90 deny ip source any destination any"       # the filter is never lost
    assert rules[index + 1].startswith("# REVIEW-ACL-LOG: rule 90")


def test_huawei_nxos_roles_become_privilege_levels():
    users = _section(_out("Huawei", "S5735-S48T4XE-V2"), "aaa")
    assert users[0] == "local-user admin privilege level 3"                   # network-admin -> Management
    assert "local-user viewer privilege level 1" in users                      # network-operator -> Monitor
    assert "local-user auditor privilege level 0" in users                     # custom role: fail-safe, never guessed upward
    assert any(line.startswith("# REVIEW-USER-ROLE: auditor") for line in users)
    assert not any("role network" in line and "REVIEW-PASSWORD-HASH" in line for line in users)  # the role is not part of the hash
    assert not any("lifetime 99999" in line for line in users)                 # factory password-aging default is dropped
    assert any("lifetime 60" in line for line in users)                        # a chosen lifetime is kept for review


def test_huawei_vlan_list_noise_and_vrf_route():
    out = _out("Huawei", "S5735-S48T4XE-V2")
    assert "vlan batch 2 3 4 5 10 20 21 22" in out                             # the range line creates VLANs 2-5 and 20-22 (they have no own block)
    assert "ip route-static vpn-instance management 0.0.0.0 0.0.0.0 192.0.2.1" in out
    assert "ip route-static 0.0.0.0 0.0.0.0 192.0.2.1" not in out             # a management-VRF route must not land in the global table
    for noise in ("# CISCO: feature", "# CISCO: vdc", "# CISCO: limit-resource", "# CISCO: !Command", "REVIEW-CISCO: switchport", "REVIEW-CISCO: hsrp version 2"):
        assert noise not in out
    assert "REVIEW-CISCO: no ip redirects" in out                              # a hardening setting is still reported


# ------------------------------------------------------------------------------------------------- Aruba / Cisco
def test_aruba_acl_uses_aos_cx_syntax():
    out = _out("Aruba")
    lines = [line.strip() for line in out.splitlines()]
    start = lines.index("access-list ip APP-ACL")
    acl = lines[start + 1:start + 24]
    assert "10 permit icmp any 192.0.2.240/29" in acl
    assert "20 permit udp any any eq 123" in acl
    assert "40 permit tcp 198.51.100.0/24 192.0.2.53/32 eq 80" in acl
    assert "10 comment STARTER" in acl and "40 comment WEB" in acl
    assert "160 permit udp any eq 123 any" in acl
    assert "! REVIEW-ACL: permit ip 10.1.1.0 0.0.0.254 any" in lines          # non-contiguous wildcard: no prefix form, not guessed
    assert "170 deny any any any log" in acl
    assert "apply access-list ip APP-ACL in" in lines
    assert "access-list ip EDGE-ACL" in lines and "20 permit tcp 192.0.2.7/32 gt 1023 any" in lines
    assert "vlan trunk allowed all" in lines and "vlan trunk allowed 10,20" in lines   # a trunk without a list carries every VLAN
    assert "ip route 0.0.0.0/0 192.0.2.1 vrf mgmt" in lines
    assert not any(line.startswith("! REVIEW-UNSUPPORTED: switchport") or "hsrp version 2" in line for line in lines)
    assert not any(line.startswith("! REVIEW-UNSUPPORTED: version ") for line in lines)


def test_cisco_target_keeps_the_vrf_of_a_route():
    assert "ip route vrf management 0.0.0.0 0.0.0.0 192.0.2.1" in _out("Cisco")


# ------------------------------------------------------------------------------------------------- vPC -> VSX / M-LAG
def test_aruba_vpc_domain_becomes_a_vsx_block():
    lines = [line.strip() for line in _out("Aruba").splitlines()]
    start = lines.index("vsx")
    block = lines[start:start + 14]
    assert "inter-switch-link lag 240" in block                      # the port-channel that carried 'vpc peer-link'
    assert "role primary" in block                                    # role priority 10 < 32667: lower wins on NX-OS
    assert "keepalive peer 192.0.2.2 source 192.0.2.1 vrf mgmt" in block   # NX-OS 'management' VRF is AOS-CX 'mgmt'
    assert "linkup-delay-timer 150" in block
    assert any(line.startswith("! REVIEW-VSX-SYSTEM-MAC") for line in block)
    assert any(line.startswith("! REVIEW-VSX-PEER-SWITCH") for line in block)
    assert any("REVIEW-VSX-UNMAPPED" in line and "peer-gateway" in line for line in block)


def test_aruba_vpc_member_port_channels_are_multi_chassis_lags():
    lines = [line.strip() for line in _out("Aruba").splitlines()]
    assert "interface lag 101 multi-chassis" in lines and "interface lag 102 multi-chassis" in lines
    assert "interface lag 240" in lines                               # the ISL itself is an ordinary LAG
    assert not any(line.startswith("interface lag 240 multi-chassis") for line in lines)


def test_aruba_management_vrf_uses_the_builtin_mgmt_vrf():
    out = _out("Aruba")
    assert "REVIEW-UNSUPPORTED: vrf context management" not in out
    assert "vrf attach management" not in out and "vrf mgmt" in out


def test_aruba_hsrp_review_carries_the_source_timers_and_preempt():
    out = _out("Aruba")
    assert "REVIEW-HSRP->VRRP: Cisco HSRP group mapped to VRRP VRID 10 (source: hello 1s / hold 3s, preempt on)" in out


def test_huawei_mlag_priority_follows_the_source_vpc_role():
    from features.configuration_studio.converter_engine.translators.switch.vpc_common import vpc_role

    assert vpc_role(10) == "primary" and vpc_role(40000) == "secondary"
    assert vpc_role(32667) is None and vpc_role(None) is None        # the NX-OS default carries no intent
    section = _section(_out("Huawei"), "dfs-group 240")
    assert "priority 150" in section                                  # Huawei elects the HIGHER value as master
    assert not any("#variable input" in line for line in section)
    assert any("REVIEW-MLAG-PRIORITY" in line and "inverted" in line for line in section)


def test_huawei_mlag_priority_keeps_a_marked_placeholder_without_a_source_role(tmp_path):
    text = NXOS.read_text(encoding="utf-8").replace("  role priority 10\n", "")
    path = tmp_path / "SW-LAB-AGG2.txt"
    path.write_text(text, encoding="utf-8")
    out = convert_file(path, target_vendor="Huawei", target_model=None, domain="switch")["output_text"]
    assert "#variable input" in out and "no primary/secondary intent" in out
