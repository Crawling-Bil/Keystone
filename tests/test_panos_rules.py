"""Palo Alto rulebase checks that compare rules and objects with each other (shadowing, unused objects, zones, any-application)."""

from __future__ import annotations

import unittest

from features.firewall_analyzer import panos_rules, service


def rule(name, vsys="vsys1", frm=("trust",), to=("untrust",), src=("any",), dst=("any",), app=("any",), svc=("application-default",), action="allow", disabled=False):
    return {"name": name, "vsys": vsys, "from_zone": list(frm), "to_zone": list(to), "source": list(src), "destination": list(dst), "application": list(app), "service": list(svc),
            "action": action, "disabled": disabled, "category": [], "source_user": []}


def dashboard(rules, **extra):
    base = {"security_rules": rules, "zones": [{"name": "trust", "vsys": "vsys1", "interfaces": ["e1"]}, {"name": "untrust", "vsys": "vsys1", "interfaces": ["e2"]}],
            "nat_rules": [], "pbf_rules": [], "address_objects": [], "service_objects": []}
    base.update(extra)
    return base


def ids(findings):
    return sorted(f["id"] for f in findings)


class RulebaseTests(unittest.TestCase):
    def test_no_rulebase_means_no_findings(self):
        self.assertEqual(panos_rules.evaluate(dashboard([])), [])

    def test_shadowed_by_wider_rule_with_other_action(self):
        found = panos_rules.evaluate(dashboard([rule("allow-all", app=("any",)), rule("deny-ssh", app=("ssh",), action="deny")]))
        shadow = [f for f in found if f["id"] == "PAN-POL-001"]
        self.assertEqual(len(shadow), 1)
        self.assertEqual(shadow[0]["severity"], "medium")
        self.assertIn("deny-ssh", shadow[0]["object"])

    def test_same_action_is_only_redundant(self):
        found = panos_rules.evaluate(dashboard([rule("a"), rule("b", app=("web-browsing",))]))
        self.assertEqual([f["severity"] for f in found if f["id"] == "PAN-POL-001"], ["low"])

    def test_narrower_rule_first_is_not_shadowing(self):
        self.assertNotIn("PAN-POL-001", ids(panos_rules.evaluate(dashboard([rule("specific", app=("ssh",), action="deny"), rule("broad")]))))

    def test_rules_of_different_vsys_never_shadow_each_other(self):
        self.assertNotIn("PAN-POL-001", ids(panos_rules.evaluate(dashboard([rule("a", vsys="vsys1"), rule("b", vsys="vsys2", action="deny")]))))

    def test_disabled_rules_do_not_shadow_and_are_summarised(self):
        found = panos_rules.evaluate(dashboard([rule("off", disabled=True), rule("on", action="deny")]))
        self.assertEqual(ids(found), ["PAN-POL-002"])

    def test_any_application_from_untrusted_zone(self):
        found = panos_rules.evaluate(dashboard([rule("in", frm=("untrust",), to=("trust",), app=("any",), svc=("tcp-443",), src=("any",))]))
        self.assertIn("PAN-POL-003", ids(found))

    def test_undefined_zone(self):
        found = panos_rules.evaluate(dashboard([rule("bad", frm=("dmz",))]))
        self.assertEqual([f["id"] for f in found if f["id"] == "PAN-POL-004"], ["PAN-POL-004"])

    def test_zone_check_is_silent_without_local_zones(self):
        self.assertNotIn("PAN-POL-004", ids(panos_rules.evaluate(dashboard([rule("x", frm=("dmz",))], zones=[]))))

    def test_unused_objects(self):
        objs = [{"name": f"host{i}", "vsys": "vsys1", "members": ["ip-netmask:10.0.0.%d" % i]} for i in range(4)]
        found = panos_rules.evaluate(dashboard([rule("r", src=("host0",))], address_objects=objs))
        unused = [f for f in found if f["id"] == "PAN-OBJ-001"]
        self.assertEqual(len(unused), 1)
        self.assertIn("host1", unused[0]["detail"])
        self.assertNotIn("host0", unused[0]["detail"])

    def test_shared_object_used_in_any_vsys_is_used(self):
        objs = [{"name": f"s{i}", "vsys": "shared", "members": ["ip-netmask:10.9.0.%d" % i]} for i in range(3)]
        found = panos_rules.evaluate(dashboard([rule("r", vsys="vsys2", src=("s0", "s1", "s2"))], address_objects=objs))
        self.assertNotIn("PAN-OBJ-001", ids(found))


class EndToEnd(unittest.TestCase):
    def test_rules_run_inside_the_analyzer(self):
        from tests.test_firewall_scope_filter import PAN_MULTI_VSYS
        result = service.analyze(PAN_MULTI_VSYS, "pa.xml")
        self.assertNotIn("PAN-POL-001", [f["id"] for f in result["findings"]], "same-named rules in two vsys must not shadow each other")
        self.assertTrue(any("vsys filter" in w for w in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
