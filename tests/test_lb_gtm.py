"""BIG-IP DNS (GTM) parsing, findings and tab.  Synthetic configuration written from the documented TMSH syntax."""

from __future__ import annotations

import unittest
from datetime import date

from features.lb_analyzer import service

CONF = """#TMSH-VERSION: 15.1.8
ltm virtual /Common/vs_dns {
    destination /Common/10.9.9.9:53
    ip-protocol udp
    profiles { /Common/dns { } /Common/udp { } }
}
gtm datacenter /Common/dc1 { }
gtm datacenter /Common/dc_empty { }
gtm server /Common/bigip1 {
    datacenter /Common/dc1
    devices { bigip1 { addresses { 10.0.0.1 { } } } }
    monitor /Common/bigip
    product redundant-bigip
    virtual-servers { vs_web { destination 10.1.1.1:80 } }
}
gtm server /Common/lb3rd {
    datacenter /Common/dc1
    product generic-host
    addresses { 10.5.5.5 { } }
    virtual-servers { web { destination 10.5.5.6:80 } }
}
gtm server /Common/lost {
    datacenter /Common/dc_missing
    product bigip
    monitor /Common/bigip
}
gtm pool a /Common/pool_ok {
    load-balancing-mode topology
    members { /Common/bigip1:vs_web { member-order 0 } }
    monitor /Common/http
}
gtm pool a /Common/pool_bad {
    verify-member-availability disabled
    members { /Common/ghost:vs1 { } /Common/bigip1:nope { } }
}
gtm pool a /Common/pool_empty { }
gtm pool a /Common/pool_unused {
    members { /Common/lb3rd:web { } }
}
gtm wideip a /Common/www.example.com {
    pool-lb-mode topology
    pools { /Common/pool_ok { order 0 } /Common/pool_bad { order 1 } /Common/pool_missing { order 2 } }
    last-resort-pool a /Common/pool_empty
}
gtm wideip a /Common/nopool.example.com { }
gtm wideip a /Common/off.example.com {
    disabled
}
"""


class GtmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(CONF, "gtm.conf", today=date(2026, 10, 14))
        cls.ids = {}
        for f in cls.result["findings"]:
            cls.ids.setdefault(f["id"], []).append(f)

    def table(self, sid):
        return next(s for s in self.result["sections"] if s["id"] == sid)

    def test_tabs(self):
        self.assertEqual({s["group"] for s in self.result["sections"] if s["id"].startswith("gtm_")}, {"DNS (GTM)"})
        wide = {r["name"]: r for r in self.table("gtm_wideips")["rows"]}
        self.assertEqual(set(wide), {"www.example.com", "nopool.example.com", "off.example.com"})
        self.assertEqual(wide["off.example.com"]["state"], "disabled")
        self.assertEqual(wide["www.example.com"]["last"], "pool_empty")
        pools = {r["name"]: r for r in self.table("gtm_pools")["rows"]}
        self.assertEqual(pools["pool_ok"]["wideips"], ["www.example.com"])
        self.assertEqual(pools["pool_empty"]["wideips"], ["www.example.com"])       # last-resort use counts as use
        self.assertEqual(pools["pool_unused"]["wideips"], ["(unused)"])
        servers = {r["name"]: r for r in self.table("gtm_servers")["rows"]}
        self.assertEqual(servers["bigip1"]["addresses"], ["10.0.0.1"])
        self.assertEqual(servers["bigip1"]["vs"], 1)

    def test_findings(self):
        self.assertEqual([f["object"] for f in self.ids["LB-GTM-001"]], ["gtm wideip a /Common/nopool.example.com"])    # disabled wide IP is silent
        self.assertIn("pool_missing", self.ids["LB-GTM-002"][0]["detail"])
        self.assertEqual([f["object"] for f in self.ids["LB-GTM-003"]], ["gtm pool a /Common/pool_empty"])
        details = " ".join(f["detail"] for f in self.ids["LB-GTM-004"])
        self.assertIn("/Common/ghost", details)
        self.assertIn("nope", details)
        self.assertTrue(self.ids["LB-GTM-005"])                                       # topology mode, no topology record
        self.assertEqual([f["object"] for f in self.ids["LB-GTM-006"]], ["gtm pool a /Common/pool_bad"])
        self.assertEqual([f["object"] for f in self.ids["LB-GTM-007"]], ["gtm server /Common/lb3rd"])               # generic host, nothing monitors it
        self.assertIn("pool_unused", self.ids["LB-GTM-008"][0]["object"])
        self.assertIn("dc_missing", self.ids["LB-GTM-009"][0]["detail"])
        self.assertIn("dc_empty", self.ids["LB-GTM-010"][0]["object"])
        self.assertNotIn("LB-GTM-011", self.ids)                                      # a DNS-profile virtual server answers queries
        for items in self.ids.values():
            for f in items:
                if f["id"].startswith("LB-GTM"):
                    self.assertTrue(f["reference"].startswith("https://clouddocs.f5.com/cli/tmsh-reference/"))

    def test_third_party_server_with_monitor_is_quiet(self):
        text = CONF.replace("    product generic-host\n", "    product generic-host\n    monitor /Common/gateway_icmp\n")
        ids = {f["id"] for f in service.analyze(text, "gtm.conf", today=date(2026, 10, 14))["findings"]}
        self.assertNotIn("LB-GTM-007", ids)

    def test_no_listener_finding(self):
        text = CONF.replace("    profiles { /Common/dns { } /Common/udp { } }", "    profiles { /Common/udp { } }")
        ids = {f["id"] for f in service.analyze(text, "gtm.conf", today=date(2026, 10, 14))["findings"]}
        self.assertIn("LB-GTM-011", ids)

    def test_ltm_only_has_no_gtm_tab(self):
        text = "ltm node /Common/10.0.0.1 { address 10.0.0.1 }\nltm pool /Common/p { members { /Common/10.0.0.1:80 { address 10.0.0.1 } } }\n"
        result = service.analyze(text, "ltm.conf", today=date(2026, 10, 14))
        self.assertFalse([s for s in result["sections"] if s["id"].startswith("gtm_")])
        self.assertFalse([f for f in result["findings"] if f["id"].startswith("LB-GTM")])

    def test_inventory_names_typed_objects(self):
        inv = {r["type"]: r for r in self.table("inventory")["rows"]}
        self.assertEqual(inv["gtm wideip"]["status"], "analyzed")
        self.assertIn("www.example.com", inv["gtm wideip"]["objects"])


if __name__ == "__main__":
    unittest.main()
