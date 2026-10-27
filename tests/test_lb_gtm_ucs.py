"""BIG-IP DNS (GTM) objects inside a UCS: ``config/bigip_gtm.conf``, partition files, data centers, virtual servers and the LTM cross-check.

Synthetic archives built in memory; written from the documented TMSH syntax (clouddocs.f5.com, gtm_* pages).
"""

from __future__ import annotations

import io
import tarfile
import unittest
from datetime import date

from features.lb_analyzer import bigip_ucs, service, ucs_history, ucs_reader

LTM = """#TMSH-VERSION: 15.1.8
ltm virtual /Common/vs_web_on {
    destination /Common/10.1.1.1:443
    ip-protocol tcp
}
ltm virtual /Common/vs_web_off {
    destination /Common/10.1.1.2:80
    disabled
    ip-protocol tcp
}
"""

BASE = """cm device /Common/dns1.example.test {
    hostname dns1.example.test
    self-device true
}
cm device /Common/dns2.example.test {
    hostname dns2.example.test
}
"""

GTM = """gtm datacenter /Common/dc_a {
    location Site-A
}
gtm datacenter /Common/dc_b { }
gtm server /Common/GTM {
    datacenter /Common/dc_a
    devices { dns1 { addresses { 10.0.0.1 { } } } }
    monitor /Common/bigip
    prober-preference inside-datacenter
    product bigip
    virtual-server-discovery enabled
    virtual-servers {
        /Common/vs_web_on { destination 10.1.1.1:443 }
        /Common/vs_web_off { destination 10.1.1.2:80 }
        /Common/vs_remote { destination 192.0.2.9:443 }
    }
}
gtm pool a /Common/pool_on { members { /Common/GTM:/Common/vs_web_on { member-order 0 } } }
gtm pool a /Common/pool_off { members { /Common/GTM:/Common/vs_web_off { member-order 0 } } }
gtm wideip a /Common/on.example.test { pools { /Common/pool_on { order 0 } } }
gtm wideip a /Common/off.example.test { pools { /Common/pool_off { order 0 } } }
"""

PARTITION = """gtm wideip a /Tenant/tenant.example.test { pools { /Common/pool_on { order 0 } } }
"""


def _tar(members: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _analyze(members: dict[str, str]):
    content = bigip_ucs.read_upload("dns.ucs", io.BytesIO(_tar(members)))
    return service.analyze(content, "dns.ucs", today=date(2026, 10, 23))


FILES = {"config/bigip.conf": LTM, "config/bigip_base.conf": BASE, "config/bigip_gtm.conf": GTM, "config/partitions/Tenant/bigip_gtm.conf": PARTITION}


class GtmUcsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = _analyze(FILES)
        cls.ids = {}
        for f in cls.result["findings"]:
            cls.ids.setdefault(f["id"], []).append(f)

    def table(self, sid):
        return next(s for s in self.result["sections"] if s["id"] == sid)

    def test_reader_keeps_gtm_and_partition_files(self):
        bundle = ucs_reader.read_ucs(io.BytesIO(_tar(FILES)))
        for needle in ("ltm virtual /Common/vs_web_on", "gtm wideip a /Common/on.example.test", "gtm wideip a /Tenant/tenant.example.test", "cm device /Common/dns1.example.test"):
            self.assertIn(needle, bundle.text)

    def test_wide_ips_of_the_gtm_file_and_the_partition_are_listed(self):
        names = {r["name"] for r in self.table("gtm_wideips")["rows"]}
        self.assertEqual(names, {"on.example.test", "off.example.test", "/Tenant/tenant.example.test"})

    def test_data_centers_and_servers(self):
        dcs = {r["name"]: r for r in self.table("gtm_datacenters")["rows"]}
        self.assertEqual(dcs["dc_a"]["location"], "Site-A")
        self.assertEqual(dcs["dc_a"]["servers"], ["GTM"])
        self.assertEqual(dcs["dc_b"]["servers"], ["(none)"])
        server = self.table("gtm_servers")["rows"][0]
        self.assertEqual((server["discovery"], server["prober"], server["vs"]), ("enabled", "inside-datacenter", 3))

    def test_virtual_servers_are_matched_with_ltm_virtual_servers(self):
        rows = {r["name"]: r for r in self.table("gtm_virtuals")["rows"]}
        self.assertEqual(rows["vs_web_on"]["address"], "10.1.1.1:443")
        self.assertEqual((rows["vs_web_on"]["ltm"], rows["vs_web_on"]["ltm_state"]), ("vs_web_on", "enabled"))
        self.assertEqual(rows["vs_web_off"]["ltm_state"], "disabled")
        self.assertEqual((rows["vs_remote"]["ltm"], rows["vs_remote"]["ltm_state"]), ("(not on this unit)", "-"))

    def test_member_on_a_disabled_ltm_virtual_server_is_reported_once(self):
        found = self.ids["LB-GTM-012"]
        self.assertEqual([f["object"] for f in found], ["gtm pool a /Common/pool_off"])
        self.assertTrue(found[0]["reference"].startswith("https://clouddocs.f5.com/cli/tmsh-reference/"))

    def test_visualization_member_follows_the_ltm_virtual_server_of_the_same_unit(self):
        nodes = next(s for s in self.result["sections"] if s["id"] == "network_map")["nodes"]
        members = {n["name"]: n for n in nodes if n["type"] == "dnsmember"}
        on, off = members["GTM:vs_web_on"], members["GTM:vs_web_off"]
        self.assertEqual(on["status"], "unverified")                                    # monitored by the 'bigip' monitor, no live state
        self.assertEqual(off["status"], "parent disabled")
        self.assertIn("disabled", off["reason"])
        self.assertIn({"label": "LTM virtual server (same unit)", "value": "vs_web_on (enabled), 10.1.1.1:443"}, on["detail"])

    def test_synchronization_off_with_two_devices(self):
        self.assertEqual([f["object"] for f in self.ids["LB-GTM-013"]], ["gtm global-settings general"])
        self.assertEqual(self.table("gtm_settings")["rows"], [])
        on = dict(FILES, **{"config/bigip_gtm.conf": GTM + "gtm global-settings general {\n    synchronization yes\n}\n"})
        result = _analyze(on)
        self.assertNotIn("LB-GTM-013", {f["id"] for f in result["findings"]})
        rows = next(s for s in result["sections"] if s["id"] == "gtm_settings")["rows"]
        self.assertEqual([(r["group"], r["option"], r["value"]) for r in rows], [("general", "synchronization", "yes")])

    def test_ltm_only_unit_with_default_gtm_stanzas_gets_no_dns_tabs(self):
        only = {"config/bigip.conf": LTM, "config/bigip_base.conf": BASE, "config/bigip_gtm.conf": "gtm global-settings metrics {\n    metrics-collection-protocols { icmp }\n}\n"}
        result = _analyze(only)
        self.assertFalse([s for s in result["sections"] if s["id"].startswith("gtm_")])
        self.assertFalse([f for f in result["findings"] if f["id"].startswith("LB-GTM")])

    def test_config_save_history_includes_the_gtm_file(self):
        self.assertTrue(ucs_history.PATCH_PATH.match("config/.diffVersions/config/bigip_gtm.conf/7.patch"))
        self.assertFalse(ucs_history.PATCH_PATH.match("config/.diffVersions/config/BigDB.dat/7.patch"))


if __name__ == "__main__":
    unittest.main()
