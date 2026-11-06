"""Topology Builder: an F5 capture made of ``show`` commands alone (no UCS, no ``tmsh list``) still draws the unit.

It used to be skipped ("a 'show' capture alone has none"), so only a UCS or a ``tmsh list`` capture gave an F5 node.  A show capture holds the ports
(``show net interface``), the hosts and VLAN names (``show net arp``) and the virtual servers; it does not hold self IPs, subnets or routes, and the
run says so (TOPO-024) instead of guessing them.  All names and addresses below are invented.
"""
from __future__ import annotations

import pytest

from features.topology import service
from features.topology.bigipdev import _arp_vlan_rows

PROMPT = "ops@(LTM-A)(cfg-sync In Sync)(Active)(/Common)(tmos)# "

SHOW_ONLY = f"""
{PROMPT}show ltm virtual

------------------------------------------------------------------
Ltm::Virtual Server: VS_Shop_HTTPS
------------------------------------------------------------------
Status
  Availability     : available
  State            : enabled
  Reason           : The virtual server is available
  CMP              : enabled
  Destination      : 192.0.2.10:443

{PROMPT}show ltm virtual field-fmt
ltm virtual VS_Shop_HTTPS {{
    clientside.cur-conns 12
    cmp-enabled enabled
    destination 192.0.2.10:443
    enabled
    ip-protocol tcp
    status.availability-state available
    status.enabled-state enabled
    status.status-reason The virtual server is available
}}

{PROMPT}show net interface

-------------------------------------------------------------------
Net::Interface
Name  Status    Bits    Bits   Pkts    Pkts  Drops  Errs      Media
                  In     Out     In     Out
-------------------------------------------------------------------
1.1       up  343.0T  324.3T  44.8G   20.5G      0     0   1000T-FD
1.2   uninit       0       0      0       0      0     0       none
mgmt      up    1.4T   13.4T   2.0G  611.6M      0     0   100TX-FD

{PROMPT}show net lldp-neighbors
{PROMPT}show net arp

------------------------------------------------------------------------------------------------------
Net::Arp
Name             Address          HWaddress          Vlan                      Expire-in-sec  Status
------------------------------------------------------------------------------------------------------
192.0.2.1        192.0.2.1        00:00:0c:07:ac:01  /Common/WEB_VIP           78             resolved
192.0.2.7        192.0.2.7        02:00:00:00:00:07  /Common/WEB_VIP           233            resolved
198.51.100.6     198.51.100.6     02:00:00:00:00:06  /Common/WEB_REAL          275            resolved
198.51.100.7     198.51.100.7     incomplete         /Common/WEB_REAL          0              unknown
{PROMPT}
"""

NOTHING = f"""
{PROMPT}show sys version
Sys::Version
Main Package
  Product     BIG-IP
{PROMPT}
"""


def _read(text, name="show-ltm-a.txt"):
    return service._read_one(name, text)


def test_a_show_only_capture_gives_a_device():
    device, skipped = _read(SHOW_ONLY)
    assert skipped is None and device is not None
    assert device.hostname == "LTM-A" and device.vendor == "F5" and device.role_hint == "loadbalancer"
    assert device.capture_gap == service.SHOW_ONLY_GAP
    assert len(device.arp_table) == 3                      # the incomplete entry is not a neighbour
    facts = device.l3facts["f5"]
    assert [row["name"] for row in facts["interfaces"]] == ["1.1", "1.2"]      # the management port is not a data port
    assert facts["map"] and facts["map"][0]["name"] == "VS_Shop_HTTPS"


def test_the_vlans_come_from_the_arp_table_with_the_hsrp_gateway():
    device, _ = _read(SHOW_ONLY)
    rows = {row["vlan"]: row for row in device.l3facts["f5"]["vlans"]}
    assert set(rows) == {"WEB_VIP", "WEB_REAL"}
    assert rows["WEB_VIP"]["description"] == "ARP: 2 host(s); gw 192.0.2.1 (HSRP 1)"
    assert rows["WEB_REAL"]["description"] == "ARP: 1 host(s), 1 incomplete"
    for row in rows.values():                              # nothing a show capture cannot know is invented
        assert row["tag"] == "" and row["interfaces"] == [] and row["self_ips"] == [] and row["floating_ips"] == []


@pytest.mark.parametrize("mac,expected", [("00:00:0c:07:ac:0a", "HSRP 10"), ("00:00:5e:00:01:05", "VRRP 5"), ("02:00:00:00:00:01", None)])
def test_gateway_hint_comes_from_the_virtual_mac_only(mac, expected):
    row = _arp_vlan_rows([{"address": "10.0.0.1", "mac": mac, "vlan": "/Common/V"}])[0]
    assert (expected in row["description"]) if expected else ("gw" not in row["description"])


def test_a_run_with_it_draws_the_f5_map_and_reports_the_gap():
    result = service.build_topology([("show-ltm-a.txt", SHOW_ONLY)], view="all")
    assert result["skipped"] == [] and result["summary"]["captured"] == 1
    assert [s["name"] for s in result["svgs"] if s["view"] == "f5map"] == ["F5 map · LTM-A"]
    gap = [f for f in result["findings"] if f["id"] == "TOPO-024"]
    assert len(gap) == 1 and "show output only" in str(gap[0])
    assert "Collect the configuration" in str(gap[0]) and "scrollback" not in str(gap[0])


def test_a_prompted_file_without_usable_show_output_is_still_skipped():
    device, skipped = _read(NOTHING)
    assert device is None
    assert "show net arp" in skipped["reason"] and "net self" in skipped["reason"]


def test_a_full_configuration_has_no_gap():
    from pathlib import Path
    text = (Path(__file__).parent / "fixtures" / "loadbalancer" / "bigip_capture_synthetic.txt").read_text(encoding="utf-8")
    device, skipped = _read(text, "lb.txt")
    assert skipped is None and device.capture_gap == ""


def test_dns_only_show_capture_draws_the_wide_ip_map():
    """A BIG-IP DNS unit's ``show gtm`` capture has no ``gtm wideip`` stanza: the Topology Builder used to draw an empty F5 map for it."""
    from pathlib import Path

    from features.topology import bigipdev

    fixture = Path(__file__).resolve().parent / "fixtures" / "loadbalancer" / "bigip_capture_dns_synthetic.txt"
    unit = bigipdev.read_units(fixture.read_text(encoding="utf-8"), fixture.name)[0]
    facts = unit.l3facts["f5"]
    assert facts["gtm"] is True
    assert len(facts["map"]) > 0
