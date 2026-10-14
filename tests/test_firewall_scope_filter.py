"""The VDOM / vsys scope filter: every table with a scope column gets a shared filter, Palo Alto objects carry the
virtual system they were read from (also when two vsys define the same name), and the client script supports it."""

from __future__ import annotations

import unittest
from pathlib import Path

from features.firewall_analyzer import scope, service

ROOT = Path(__file__).resolve().parent.parent

PAN_MULTI_VSYS = """<?xml version="1.0"?>
<config version="10.2.0"><devices><entry name="localhost.localdomain">
<network>
 <interface><ethernet>
  <entry name="ethernet1/1"><layer3><ip><entry name="10.1.0.1/24"/></ip></layer3></entry>
  <entry name="ethernet1/2"><layer3><ip><entry name="10.2.0.1/24"/></ip></layer3></entry>
  <entry name="ethernet1/9"><layer3><ip><entry name="192.168.9.1/24"/></ip></layer3></entry>
 </ethernet></interface>
 <virtual-router><entry name="vr-a"><interface><member>ethernet1/1</member></interface>
  <routing-table><ip><static-route><entry name="def"><destination>0.0.0.0/0</destination><nexthop><ip-address>10.1.0.254</ip-address></nexthop></entry></static-route></ip></routing-table></entry></virtual-router>
</network>
<vsys>
 <entry name="vsys1"><import><network><interface><member>ethernet1/1</member></interface><virtual-router><member>vr-a</member></virtual-router></network></import>
  <zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
  <address><entry name="Web"><ip-netmask>10.1.1.10/32</ip-netmask></entry></address>
  <rulebase><security><rules><entry name="allow-web"><from><member>trust</member></from><to><member>trust</member></to><source><member>any</member></source><destination><member>Web</member></destination>
   <service><member>application-default</member></service><application><member>web-browsing</member></application><action>allow</action></entry></rules></security></rulebase></entry>
 <entry name="vsys2"><import><network><interface><member>ethernet1/2</member></interface></network></import>
  <zone><entry name="dmz"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone>
  <address><entry name="Web"><ip-netmask>10.2.1.10/32</ip-netmask></entry></address>
  <rulebase><security><rules><entry name="allow-web"><from><member>dmz</member></from><to><member>dmz</member></to><source><member>any</member></source><destination><member>Web</member></destination>
   <service><member>application-default</member></service><application><member>ssl</member></application><action>allow</action></entry></rules></security></rulebase></entry>
</vsys></entry></devices>
<shared><address><entry name="Shared-DNS"><ip-netmask>8.8.8.8/32</ip-netmask></entry></address></shared></config>
"""


def section(result, sid):
    return next(s for s in result["sections"] if s["id"] == sid)


class ScopeHelperTests(unittest.TestCase):
    def test_only_tables_with_the_column_get_the_filter(self):
        sections = [{"kind": "table", "columns": [{"key": "vdom"}], "facets": []}, {"kind": "table", "columns": [{"key": "name"}]}, {"kind": "kv"}]
        self.assertEqual(scope.apply(sections, "vdom", "VDOM"), 1)
        self.assertEqual(sections[0]["facets"], [{"key": "vdom", "label": "VDOM", "shared": True}])
        self.assertNotIn("facets", sections[1])
        self.assertEqual(scope.apply(sections, "vdom", "VDOM"), 0, "applying twice must not duplicate the filter")


class PaloAltoVsysTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(PAN_MULTI_VSYS, "pa.xml")

    def test_rules_zones_and_same_named_objects_keep_their_vsys(self):
        rules = section(self.result, "security_rules")
        self.assertEqual(sorted((r["name"], r["vsys"]) for r in rules["rows"]), [("allow-web", "vsys1"), ("allow-web", "vsys2")])
        zones = {r["name"]: r["vsys"] for r in section(self.result, "zones")["rows"]}
        self.assertEqual(zones, {"trust": "vsys1", "dmz": "vsys2"})
        addresses = sorted((r["name"], r["vsys"]) for r in section(self.result, "address_objects")["rows"])
        self.assertEqual(addresses, [("Shared-DNS", "shared"), ("Web", "vsys1"), ("Web", "vsys2")], "the second vsys' 'Web' must not be dropped as a duplicate")

    def test_interfaces_follow_the_vsys_import_list(self):
        owner = {r["name"]: r["vsys"] for r in section(self.result, "interfaces")["rows"]}
        self.assertEqual(owner["ethernet1/1"], "vsys1")
        self.assertEqual(owner["ethernet1/2"], "vsys2")
        self.assertEqual(owner["ethernet1/9"], "(none)")
        self.assertEqual({r["virtual_router"]: r["vsys"] for r in section(self.result, "static_routes")["rows"]}, {"vr-a": "vsys1"})

    def test_scope_filter_is_attached(self):
        for sid in ("interfaces", "zones", "security_rules", "address_objects", "static_routes"):
            self.assertEqual(section(self.result, sid)["facets"][0], {"key": "vsys", "label": "vsys", "shared": True}, sid)

    def test_single_vsys_has_no_vsys_column(self):
        single = PAN_MULTI_VSYS.replace('<entry name="vsys2">', '<entry name="vsys2-removed" ignore="1">', 1)
        one = single.split('<entry name="vsys2-removed"')[0] + "</entry></vsys></entry></devices></config>"
        result = service.analyze(one, "pa1.xml")
        self.assertNotIn("vsys", [c["key"] for c in section(result, "security_rules")["columns"]])


class ClientScriptTests(unittest.TestCase):
    def test_script_supports_shared_filters(self):
        js = (ROOT / "static/js/analyzer_kit.js").read_text(encoding="utf-8")
        for needle in ("def.shared", "function scopeBar", "function repaintScope", "__shared"):
            self.assertIn(needle, js)


if __name__ == "__main__":
    unittest.main()
