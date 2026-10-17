"""FortiGate areas added from the real-world backups: proxy policies, URL filter lists, threat feeds, DNS server, virtual wire.

Synthetic: documentation address space (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and invented names.
"""

from __future__ import annotations

from features.analyzer_core.result import validate_result
from features.firewall_analyzer import service

CONFIG = """\
#config-version=FGT201F-7.2.10-FW-build1706-250108:opmode=0:vdom=0:user=admin
config system global
    set hostname "LAB-FGT-01"
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.248
        set allowaccess ping
        set role wan
    next
    edit "lan"
        set vdom "root"
        set ip 192.0.2.1 255.255.255.0
        set role lan
    next
end
config system dns-server
    edit "wan1"
    next
    edit "lan"
        set mode forward-only
    next
end
config system dns-database
    edit "corp"
        set domain "corp.example"
        set authoritative disable
        set forwarder "192.0.2.53"
    next
end
config system external-resource
    edit "feed-http"
        set type domain
        set resource "http://198.51.100.9/domains.txt"
    next
    edit "feed-https"
        set type address
        set resource "https://198.51.100.9/ip.txt"
    next
end
config system virtual-wire-pair
    edit "vwp1"
        set member "port3" "port4"
        set wildcard-vlan enable
    next
end
config webfilter urlfilter
    edit 1
        set name "lab-list"
        config entries
            edit 1
                set url "*"
                set type wildcard
                set action exempt
            next
            edit 2
                set url "www.example.com"
                set action block
            next
        end
    next
end
config firewall proxy-policy
    edit 1
        set name "open-proxy"
        set proxy explicit-web
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "webproxy"
        set action accept
        set schedule "always"
    next
    edit 2
        set name "lan-to-any"
        set proxy explicit-web
        set srcaddr "lan-net"
        set dstaddr "all"
        set service "webproxy"
        set action accept
        set schedule "always"
    next
    edit 3
        set name "empty"
        set proxy explicit-web
        set srcaddr "lan-net"
        set action accept
        set schedule "always"
    next
    edit 4
        set name "off"
        set proxy explicit-web
        set srcaddr "all"
        set dstaddr "all"
        set service "webproxy"
        set action accept
        set status disable
        set schedule "always"
    next
end
config firewall address
    edit "lan-net"
        set subnet 192.0.2.0 255.255.255.0
    next
end
"""


def _result():
    return service.analyze(CONFIG, "lab.conf", "fortigate")


def _ids(result):
    return {f["id"]: f for f in result["findings"]}


def test_result_is_valid_and_sections_are_present():
    result = _result()
    assert validate_result(result) == []
    ids = {s["id"] for s in result["sections"]}
    assert {"proxy_policies", "urlfilters", "external_resources", "dns_service", "l2_topology"} <= ids


def test_proxy_policy_findings_by_severity():
    findings = [f for f in _result()["findings"] if f["id"].startswith("FGT-PXY")]
    by_id = {}
    for f in findings:
        by_id.setdefault(f["id"], []).append(f)
    assert len(by_id["FGT-PXY-001"]) == 1 and "open-proxy" in by_id["FGT-PXY-001"][0]["object"]
    assert by_id["FGT-PXY-001"][0]["severity"] == "high"
    assert by_id["FGT-PXY-002"][0]["severity"] == "medium" and "lan-to-any" in by_id["FGT-PXY-002"][0]["object"]
    assert by_id["FGT-PXY-004"][0]["severity"] == "low" and "empty" in by_id["FGT-PXY-004"][0]["object"]


def test_disabled_proxy_policy_is_listed_but_not_a_finding():
    result = _result()
    rows = next(s for s in result["sections"] if s["id"] == "proxy_policies")["rows"]
    assert {r["name"] for r in rows} == {"open-proxy", "lan-to-any", "empty", "off"}
    assert not any("'off'" in f["object"] or f["object"].endswith(" off") for f in result["findings"] if f["id"].startswith("FGT-PXY"))


def test_catch_all_url_exemption_is_high():
    f = _ids(_result())["FGT-URL-001"]
    assert f["severity"] == "high" and "exempt" in f["title"]


def test_plain_http_threat_feed_only_flags_the_http_one():
    feeds = [f for f in _result()["findings"] if f["id"] == "FGT-EXT-001"]
    assert len(feeds) == 1 and "feed-http" in feeds[0]["title"]


def test_recursive_dns_on_wan_interface_but_not_on_forward_only_lan():
    dns = [f for f in _result()["findings"] if f["id"] == "FGT-DNS-001"]
    assert len(dns) == 1 and "wan1" in dns[0]["title"]


def test_wildcard_vlan_virtual_wire_pair():
    assert "FGT-VWP-001" in _ids(_result())


def test_every_new_finding_has_a_fortinet_documentation_link():
    for f in _result()["findings"]:
        if f["id"].startswith(("FGT-PXY", "FGT-URL", "FGT-EXT", "FGT-DNS", "FGT-VWP")):
            assert f["reference"].startswith("https://docs.fortinet.com/"), f["id"]


def test_config_without_these_areas_adds_nothing():
    plain = "config system global\n    set hostname \"X\"\nend\nconfig system interface\n    edit \"lan\"\n        set ip 192.0.2.1 255.255.255.0\n    next\nend\n"
    result = service.analyze(plain, "plain.conf", "fortigate")
    assert not {"proxy_policies", "urlfilters", "external_resources", "dns_service", "l2_topology"} & {s["id"] for s in result["sections"]}
    assert not any(f["id"].startswith(("FGT-PXY", "FGT-URL", "FGT-EXT", "FGT-DNS", "FGT-VWP")) for f in result["findings"])
