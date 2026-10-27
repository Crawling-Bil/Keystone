"""An F5 BIG-IP as a Topology Builder device: self IPs, floating self IPs, route domains, trunks, routes, UCS upload and a merged capture.

Every name and address here is invented (documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""

from __future__ import annotations

import io
import tarfile

import pytest

from features.topology import bigipdev, ingest, service

BASE = """#TMSH-VERSION: 17.1.3
sys global-settings {
    hostname {host}.lab.test
}
net vlan /Common/client {
    interfaces {
        1.1 {
            tagged
        }
    }
    tag 100
}
net vlan /Common/server {
    interfaces {
        trk1 { }
    }
    tag 200
}
net vlan /Common/dmz {
    interfaces {
        1.3 { }
    }
    tag 300
}
net trunk /Common/trk1 {
    interfaces {
        1.2
        1.4
    }
    lacp enabled
}
net route-domain /Common/rd_dmz {
    id 2
    vlans {
        /Common/dmz
    }
}
net self /Common/self_client {
    address {client_ip}/24
    allow-service none
    traffic-group /Common/traffic-group-local-only
    vlan /Common/client
}
net self /Common/float_client {
    address 192.0.2.1/24
    floating enabled
    traffic-group /Common/traffic-group-1
    vlan /Common/client
}
net self /Common/self_server {
    address {server_ip}/24
    traffic-group /Common/traffic-group-local-only
    vlan /Common/server
}
net self /Common/self_dmz {
    address 203.0.113.{dmz}%2/28
    traffic-group /Common/traffic-group-local-only
    vlan /Common/dmz
}
net route /Common/default {
    gw 192.0.2.254
    network default
}
net route /Common/to_dmz {
    gw 203.0.113.14%2
    network 10.99.0.0%2/16
}
"""


def _config(host="lab-lb1", client_ip="192.0.2.2", server_ip="198.51.100.2", dmz="2") -> str:
    return BASE.replace("{host}", host).replace("{client_ip}", client_ip).replace("{server_ip}", server_ip).replace("{dmz}", dmz)


SHOW = """ops@(lab-lb1)(cfg-sync In Sync)(Active)(/Common)(tmos)# show net interface

-------------------------------------------------------------------
Net::Interface
Name  Status    Bits    Bits   Pkts    Pkts  Drops  Errs      Media
                  In     Out     In     Out
-------------------------------------------------------------------
1.1       up  343.0T  324.3T  44.8G   20.5G      0     0   1000T-FD
1.2       up    4.5T    2.7T   2.5G    1.1G      0     0  10000T-FD
1.3   uninit       0       0      0       0      0     0       none
1.4       up    2.0T    2.0T   2.0G    2.1G      0     0  10000T-FD
mgmt      up    1.4T   13.4T   2.0G  611.6M      0     0   100TX-FD

ops@(lab-lb1)(cfg-sync In Sync)(Active)(/Common)(tmos)# show net arp

------------------------------------------------------------------------------------------------------
Net::Arp
Name             Address          HWaddress          Vlan                      Expire-in-sec  Status
------------------------------------------------------------------------------------------------------
192.0.2.254      192.0.2.254      00:00:5e:00:53:01  /Common/client            297            resolved
192.0.2.77       192.0.2.77       incomplete         /Common/client            0              unknown

ops@(lab-lb1)(cfg-sync In Sync)(Active)(/Common)(tmos)# show cm failover-status

CM::Failover Status
Color    green
Status   ACTIVE
Summary  1/1 active
"""


def _ucs(config: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in {"config/bigip.conf": config.encode(), "config/bigip_base.conf": config.encode(), "config/ucs_version": b"BIG-IP 17.1.3\n"}.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_self_ips_floating_ips_route_domains_trunks_and_routes():
    device = bigipdev.read(_config(), "lab-lb1.conf")
    assert (device.hostname, device.vendor, device.role_hint, device.os_version) == ("LAB-LB1", "F5", "loadbalancer", "TMOS 17.1.3")
    rows = {r["name"]: r for r in device.l3}
    assert set(rows) == {"self_client", "self_server", "self_dmz"}                     # the floating self IP is not an interface of this unit
    assert (rows["self_client"]["ip"], rows["self_client"]["prefix_len"], rows["self_client"]["vrf"], rows["self_client"]["vlan_id"], rows["self_client"]["parent"]) == ("192.0.2.2", 24, "global", 100, "1.1")
    assert rows["self_server"]["parent"] == "trk1" and rows["self_dmz"]["vrf"] == "rd_dmz" and rows["self_dmz"]["ip"] == "203.0.113.2" and rows["self_dmz"]["prefix_len"] == 28
    fhrp = device.l3facts["fhrp"]
    assert [(g["virtual_ip"], g["interface"], g["group"]) for g in fhrp] == [("192.0.2.1", "client", "traffic-group-1")]
    assert device.bundles == {"trk1": ["1.2", "1.4"]} and device.bundle_of["1.2"] == "trk1" and device.bundle_info["trk1"]["protocol"] == "LACP"
    routes = {(r["vrf"], r["next_hop"]): r for r in device.l3facts["routes"]}
    assert routes[("global", "192.0.2.254")]["default"] is True
    assert routes[("rd_dmz", "203.0.113.14")]["prefixes"] == ["10.99.0.0/16"]           # the %2 route-domain suffix is not part of the prefix


def test_show_capture_adds_port_state_speed_and_arp():
    device = bigipdev.read(_config() + "\n" + SHOW, "lab-lb1.txt")
    assert device.port_state["1.1"] == "up" and device.port_state["1.3"] == "down" and "mgmt" not in device.port_state
    assert device.actual_speeds["1.2"] == 10000 and device.duplex["1.2"] == "full"
    assert [r["ip_address"] for r in device.arp_table] == ["192.0.2.254"]               # an incomplete entry is not evidence of a neighbor
    assert device.l3facts["ha"] == "active"
    assert {r["name"] for r in device.l3 if r["status"] == "up"} == {"self_client", "self_server"}


def test_a_ucs_upload_is_read_and_merged_with_the_capture_of_the_same_unit():
    files = ingest.to_captures([("lab-lb1.ucs", _ucs(_config())), ("show.txt", SHOW.encode())], 10)
    assert files[0][0] == "lab-lb1.ucs" and getattr(files[0][1], "bundle", None) is not None
    devices, skipped = service.read_devices(files)
    assert skipped == [] and len(devices) == 1                                         # one unit: the capture was folded into the archive
    assert devices[0].port_state["1.2"] == "up" and len(devices[0].arp_table) == 1


def test_a_show_capture_alone_is_skipped_with_a_reason_that_names_the_fix():
    devices, skipped = service.read_devices([("show.txt", SHOW)])
    assert devices == [] and "UCS" in skipped[0]["reason"] and "net self" in skipped[0]["reason"]


def test_a_pair_shares_the_floating_address_and_the_page_is_drawn():
    one = _config("lab-lb1", "192.0.2.2", "198.51.100.2")
    two = _config("lab-lb2", "192.0.2.3", "198.51.100.3", "3")
    result = service.build_topology([("lb1.conf", one), ("lb2.conf", two)], view="l3route")
    assert result["summary"]["captured"] == 2 and result["skipped"] == []
    direct = {row["subnet"]: row for row in result["l3_links"] if row["kind"] == "Direct routed link"}
    assert {"192.0.2.0/24", "198.51.100.0/24"} <= set(direct)                          # the two units face each other on their client and server VLANs
    assert direct["192.0.2.0/24"]["address_a"] == "192.0.2.2" and direct["192.0.2.0/24"]["address_b"] == "192.0.2.3"
    assert "192.0.2.1" not in " ".join(row["meaning"] for row in direct.values())     # the floating address is not a unit's own address


def test_a_corrupt_archive_is_a_readable_error():
    with pytest.raises(ingest.IngestError):
        ingest.to_captures([("broken.ucs", b"Salted__" + b"\x00" * 64)], 10)


def test_a_router_whose_next_hop_is_the_floating_address_reaches_the_pair():
    from features.topology.extract import Device
    from features.topology.graph import Graph
    from features.topology.l3engine import build
    units = [bigipdev.read(_config("lab-lb1", "192.0.2.2"), "a.conf"), bigipdev.read(_config("lab-lb2", "192.0.2.3"), "b.conf")]
    for unit, key in zip(units, ("LAB-LB1", "LAB-LB2")):
        unit.key = key
    router = Device(key="R1", hostname="R1", role_hint="router", mgmt_ip="192.0.2.254",
                    l3=[{"name": "Gi0/0", "ip": "192.0.2.254", "prefix_len": 24, "vrf": "global", "kind": "routed", "shutdown": False, "description": "", "status": "up/up", "secondary": []}])
    router.l3facts = {"routes": [{"vrf": "global", "protocol": "static", "next_hop": "192.0.2.1", "interface": "", "count": 1, "prefixes": ["10.50.0.0/16"], "default": False}],
                      "neighbors": [], "overlay": [], "tunnels": [], "state": {}}
    model = build(Graph(nodes={n.key: n for n in units + [router]}))
    text = " ".join(" ".join(e.evidence) for e in model.edges)
    assert "virtual address" in text and "192.0.2.1" in text
    assert not [u for u in model.unresolved if u.get("address") == "192.0.2.1"]


def test_a_bigip_is_not_asked_for_cdp_or_lldp_commands():
    result = service.build_topology([("lb1.conf", _config())], view="l3route")
    gap = [f for f in result["findings"] if f["id"] == "TOPO-013"]
    assert not [f for f in gap if "LAB-LB1" in f["detail"]]
    note = [f for f in result["findings"] if f["id"] == "TOPO-008" and f["devices"] == ["LAB-LB1"]]
    assert note and note[0]["severity"] == "info" and "BIG-IP" in note[0]["recommendation"]
