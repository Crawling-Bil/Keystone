"""Small, hand-written FortiGate inputs for corners of ``forti_read`` that the golden files do not reach (found by mutation testing)."""
from __future__ import annotations

from features.configuration_studio.converter_engine.fwconvert import convert
from features.configuration_studio.converter_engine.fwconvert.forti_read import cidr

HEAD = 'config system global\n    set hostname "T"\nend\n'
IFACES = ('config system interface\n    edit "port1"\n        set vdom "root"\n        set ip 192.0.2.1 255.255.255.0\n        set type physical\n    next\n'
          '    edit "port2"\n        set vdom "root"\n        set ip 10.0.0.1 255.255.255.0\n        set type physical\n    next\nend\n')


def run(body: str, ifaces: str = IFACES, **kw):
    result = convert(HEAD + ifaces + body, "fortigate", "panos", **kw)
    assert result.ok, result.error
    return result


def rows(result, layer: str | None = None):
    """The report items (``layer``, ``kind``, ``name``, ``status``, ``message``) of one layer."""
    return [i for i in result.report.items if layer is None or i.layer == layer]


def test_cidr_single_word_and_masks():
    assert cidr("10.1.1.5") == "10.1.1.5/32"
    assert cidr("10.1.1.5/24") == "10.1.1.5/24"
    assert cidr("10.1.1.0 255.255.255.0") == "10.1.1.0/24"
    assert cidr("") == "" and cidr("10.1.1.0 255.0.255.0") == ""


def test_ssl_and_management_interfaces_are_not_data_plane_ports():
    extra = IFACES[:-4] + '    edit "ssl.vdom1"\n        set vdom "root"\n        set type tunnel\n    next\n    edit "mgmt"\n        set vdom "root"\n        set ip 192.168.1.99 255.255.255.0\n    next\nend\n'
    result = run("", extra)
    names = {p.name for p in result.model.ports}
    assert "ssl.vdom1" not in names and "mgmt" not in names and "port1" in names
    assert any(r.name == "ssl.vdom1" and r.status == "not_converted" for r in rows(result, "interfaces"))


def test_mtu_is_read_only_when_override_is_enabled():
    ifaces = IFACES[:-4] + '    edit "port3"\n        set vdom "root"\n        set ip 10.3.0.1 255.255.255.0\n        set mtu-override enable\n        set mtu 1400\n    next\n' \
                           '    edit "port4"\n        set vdom "root"\n        set ip 10.4.0.1 255.255.255.0\n        set mtu 1300\n    next\nend\n'
    ports = {p.name: p for p in run("", ifaces).model.ports}
    assert ports["port3"].mtu == 1400 and ports["port4"].mtu is None


def test_zero_address_with_a_host_mask_is_not_widened_to_any():
    body = 'config firewall address\n    edit "host0"\n        set subnet 0.0.0.0 255.255.255.255\n    next\n    edit "nosub"\n    next\nend\n'
    values = {a.name: a.value for a in run(body).model.addresses}
    assert values["host0"] == "0.0.0.0/32" and values["nosub"] == "0.0.0.0/0"


def test_address_group_exclude_is_kept_only_when_enabled():
    body = ('config firewall address\n    edit "a1"\n        set subnet 10.1.0.0 255.255.0.0\n    next\n    edit "a2"\n        set subnet 10.1.1.0 255.255.255.0\n    next\nend\n'
            'config firewall addrgrp\n    edit "g-on"\n        set member "a1"\n        set exclude enable\n        set exclude-member "a2"\n    next\n'
            '    edit "g-off"\n        set member "a1"\n        set exclude disable\n        set exclude-member "a2"\n    next\nend\n')
    result = run(body)
    groups = {g.name: g for g in result.model.address_groups}
    assert groups["g-on"].exclude == ["a2"] and groups["g-off"].exclude == []
    reviewed = {r.name for r in rows(result, "objects") if r.status == "review"}
    assert "g-on" in reviewed and "g-off" not in reviewed


def test_custom_icmp_and_ip_services_keep_their_own_protocol():
    body = ('config firewall service custom\n    edit "ping-echo"\n        set protocol ICMP\n        set icmptype 8\n    next\n'
            '    edit "gre-ip"\n        set protocol IP\n        set protocol-number 47\n    next\nend\n')
    services = {s.name: s for s in run(body).model.services}
    assert [(e.protocol, e.icmp_type) for e in services["ping-echo"].entries] == [("icmp", "8")]
    assert [(e.protocol, e.ip_protocol) for e in services["gre-ip"].entries] == [("ip", "47")]


def test_predefined_service_used_by_a_policy_is_a_builtin_service():
    body = ('config firewall policy\n    edit 1\n        set name "web"\n        set srcintf "port2"\n        set dstintf "port1"\n        set srcaddr "all"\n        set dstaddr "all"\n'
            '        set action accept\n        set schedule "always"\n        set service "HTTP"\n    next\nend\n')
    services = {s.name: s for s in run(body).model.services}
    assert services["HTTP"].builtin is True and services["HTTP"].entries[0].protocol == "tcp"


def _policy(extra: str) -> str:
    return ('config firewall policy\n    edit 1\n        set name "p1"\n        set srcintf "port2"\n        set dstintf "port1"\n        set srcaddr "all"\n        set dstaddr "all"\n'
            f'        set action accept\n        set schedule "always"\n        set service "ALL"\n{extra}    next\nend\n')


def test_internet_service_destination_becomes_any_but_a_source_one_keeps_the_address():
    body = ('config firewall address\n    edit "dst1"\n        set subnet 10.9.0.0 255.255.0.0\n    next\nend\n')
    dst = _policy('        set internet-service enable\n').replace('set dstaddr "all"', 'set dstaddr "dst1"')
    src = _policy('        set internet-service-src enable\n').replace('set dstaddr "all"', 'set dstaddr "dst1"')
    on = run(body + dst).model.policies[0]
    assert on.dst_addrs == ["any"] and on.widened
    src_policy = run(body + src).model.policies[0]
    assert src_policy.dst_addrs == ["dst1"] and src_policy.widened


def test_policy_nat_flag_and_the_nat_rule_it_makes():
    result = run(_policy('        set nat enable\n'))
    assert result.model.policies[0].nat_source is True
    assert [n.origin for n in result.model.nat_rules] == ["policy"]
    assert run(_policy("")).model.policies[0].nat_source is False


def test_central_snat_protocol_or_port_match_is_reported():
    base = ('config system settings\n    set central-nat enable\nend\nconfig firewall central-snat-map\n    edit 1\n        set orig-addr "all"\n        set srcintf "port2"\n'
            '        set dst-addr "all"\n        set dstintf "port1"\n{extra}    next\nend\n')
    def reviews(extra):
        return [r for r in rows(run(base.format(extra=extra)), "nat") if "protocol and port" in r.message]
    assert reviews('        set protocol 6\n')
    assert reviews('        set orig-port 8080\n')
    assert not reviews("")


def test_vpn_dynamic_peer_is_dialup_and_the_key_is_never_carried():
    body = ('config vpn ipsec phase1-interface\n    edit "dial"\n        set interface "port1"\n        set type dynamic\n        set proposal aes256-sha256\n        set dhgrp 14\n'
            '        set psksecret ENC AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n    next\n    edit "site"\n        set interface "port1"\n        set proposal aes256-sha256\n        set dhgrp 14\n'
            '        set remote-gw 198.51.100.2\n    next\nend\n')
    result = run(body)
    tunnels = {t.name: t for t in result.model.tunnels}
    assert tunnels["dial"].dialup is True and tunnels["site"].dialup is False
    assert "AAAAAAAA" not in result.output
