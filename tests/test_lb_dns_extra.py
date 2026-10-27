"""GTM topology records, regions and the 'ltm dns' objects (DNS Express zones, name servers, resolvers). Synthetic text from the documented tmsh syntax."""

from __future__ import annotations

from datetime import date

from features.lb_analyzer import service

CONF = """#TMSH-VERSION: 17.1.3
gtm datacenter /Common/dc_a { }
gtm server /Common/srv_a {
    datacenter /Common/dc_a
    product bigip
}
gtm region /Common/Asia {
    region-members {
        country JP { }
        subnet 10.20.0.0/16 { }
        not country CN { }
    }
}
gtm topology ldns: region /Common/Asia server: datacenter /Common/dc_a {
    score 200
}
gtm topology ldns: subnet 10.0.0.0/8 server: datacenter /Common/dc_missing {
    score 50
}
gtm topology ldns: region /Common/Nowhere server: datacenter /Common/dc_a {
    description "typo"
}
ltm dns zone /Common/example.test {
    dns-express-server /Common/ns_master
    response-policy yes
    transfer-clients { /Common/ns_secondary }
}
ltm dns zone /Common/orphan.test {
}
ltm dns zone /Common/lost.test {
    dns-express-server /Common/ns_gone
}
ltm dns nameserver /Common/ns_master {
    address 192.0.2.53
    tsig-key /Common/key1
}
net dns-resolver /Common/res1 {
    forward-zones {
        . {
            nameservers {
                192.0.2.1:53 { }
            }
        }
        empty.test { }
    }
    use-ipv6 no
}
"""


def _run(text: str = CONF) -> dict:
    return service.analyze(text, "dns.conf", today=date(2026, 10, 23))


def _section(result: dict, sid: str) -> dict:
    return next(s for s in result["sections"] if s["id"] == sid)


def _ids(result: dict) -> list[str]:
    return [f["id"] for f in result["findings"]]


def test_topology_records_are_split_into_ldns_and_answer_side():
    rows = _section(_run(), "gtm_topology")["rows"]
    assert len(rows) == 3
    first = rows[0]
    assert first["ldns"] == "region /Common/Asia" and first["server"] == "datacenter /Common/dc_a" and first["score"] == "200"
    assert rows[2]["score"] == "1" and rows[2]["description"] == "typo"          # documented default score is 1


def test_regions_list_members_including_negated_ones():
    rows = _section(_run(), "gtm_regions")["rows"]
    assert rows[0]["name"] == "/Common/Asia" and rows[0]["members"] == ["country JP", "subnet 10.20.0.0/16", "not country CN"]


def test_topology_records_with_unknown_region_or_datacenter_are_findings():
    res = _run()
    hits = [f for f in res["findings"] if f["id"] == "LB-GTM-014"]
    titles = sorted(f["title"] for f in hits)
    assert titles == ["Topology record refers to an unknown data center", "Topology record refers to an unknown region"]


def test_dns_express_zones_nameservers_and_resolvers_have_tabs():
    res = _run()
    zones = {r["name"]: r for r in _section(res, "dns_zones")["rows"]}
    assert zones["example.test"]["server"] == "ns_master" and zones["example.test"]["policy"] == "yes" and zones["example.test"]["clients"] == ["ns_secondary"]
    assert zones["orphan.test"]["server"] == "(none)" and zones["orphan.test"]["notify"] == "consume"
    ns = _section(res, "dns_nameservers")["rows"][0]
    assert ns["address"] == "192.0.2.53" and ns["port"] == "53" and ns["tsig"] == "key1"
    resolver = _section(res, "dns_resolvers")["rows"][0]
    assert resolver["forward"][0] == ". -> 192.0.2.1:53" and resolver["transports"] == "IPv4/TCP/UDP"


def test_dns_findings_for_zones_without_a_usable_server_and_empty_forward_zones():
    ids = _ids(_run())
    assert ids.count("LB-DNS-001") == 2          # orphan.test (no server) and lost.test (unknown name server)
    assert ids.count("LB-DNS-002") == 1


def test_an_ltm_only_capture_gets_none_of_these_tabs():
    res = _run("ltm node /Common/n1 {\n    address 192.0.2.10\n}\ngtm global-settings metrics {\n}\n")
    assert not [s for s in res["sections"] if s["id"].startswith(("gtm_", "dns_"))]
    assert not [i for i in _ids(res) if i.startswith(("LB-GTM", "LB-DNS"))]


def test_failover_address_keyword_management_ip_shows_the_address():
    text = "cm device /Common/a.example.test {\n    hostname a.example.test\n    management-ip 192.0.2.10\n    unicast-address {\n        {\n            ip management-ip\n            port 1026\n        }\n    }\n}\n"
    res = service.analyze(text, "a.conf", today=date(2026, 10, 23))
    row = next(s for s in res["sections"] if s["id"] == "devices")["rows"][0]
    assert row["unicast"] == ["192.0.2.10:1026"]
