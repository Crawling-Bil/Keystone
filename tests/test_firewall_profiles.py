"""FortiGate security-profile content: SSL inspection depth, IPS/antivirus/web-filter effect, and which policies use each."""

from __future__ import annotations

import unittest
from datetime import date

from features.firewall_analyzer import service

CONFIG = """#config-version=FGT60F-7.4.3-FW-build2573-231130:opmode=0:vdom=0:user=admin
config system global
    set hostname "T1"
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.252
        set role wan
    next
    edit "lan"
        set vdom "root"
        set ip 10.0.0.1 255.255.255.0
        set role lan
    next
end
config ips sensor
    edit "monitor-only"
        config entries
            edit 1
                set action pass
                set severity high critical
            next
        end
    next
    edit "enforcing"
        config entries
            edit 1
                set action block
                set severity high critical
            next
        end
    next
end
config antivirus profile
    edit "av-monitor"
        config http
            set av-scan monitor
        end
    next
    edit "av-block"
        config http
            set av-scan block
        end
    next
end
config webfilter profile
    edit "wf-none"
        config ftgd-wf
            config filters
                edit 1
                    set category 2
                    set action monitor
                next
            end
        end
    next
end
config firewall ssl-ssh-profile
    edit "my-deep"
        config https
            set status deep-inspection
            set unsupported-ssl-version allow
        end
    next
end
config firewall policy
    edit 1
        set name "cert-only"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ssl-ssh-profile "certificate-inspection"
        set av-profile "av-block"
        set ips-sensor "enforcing"
        set nat enable
    next
    edit 2
        set name "deep-ok"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set utm-status enable
        set ssl-ssh-profile "my-deep"
        set av-profile "av-monitor"
        set ips-sensor "monitor-only"
        set webfilter-profile "wf-none"
        set nat enable
    next
end
"""


class ProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(CONFIG, "t.conf", today=date(2026, 10, 14))
        cls.findings = {(f["id"], f["object"]): f for f in cls.result["findings"]}
        cls.rows = {(r["kind"], r["name"]): r for r in next(s for s in cls.result["sections"] if s["id"] == "profile_detail")["rows"]}

    def ids(self, prefix="FGT-UTM"):
        return sorted(f["id"] for f in self.result["findings"] if f["id"].startswith(prefix))

    def test_effect_of_each_profile_is_read_from_the_profile(self):
        self.assertEqual(self.rows[("IPS sensor", "monitor-only")]["mode"], "monitor only")
        self.assertEqual(self.rows[("IPS sensor", "enforcing")]["mode"], "blocks")
        self.assertEqual(self.rows[("Antivirus", "av-monitor")]["mode"], "monitor only")
        self.assertEqual(self.rows[("Antivirus", "av-block")]["mode"], "blocks")
        self.assertEqual(self.rows[("Web filter", "wf-none")]["mode"], "monitor only")
        self.assertEqual(self.rows[("SSL/SSH inspection", "my-deep")]["mode"], "deep inspection")

    def test_usage_counts_policies(self):
        self.assertEqual(self.rows[("IPS sensor", "monitor-only")]["used_by"], 1)
        self.assertEqual(self.rows[("Antivirus", "av-block")]["policies"], ["#1"])

    def test_findings(self):
        self.assertEqual(self.ids(), ["FGT-UTM-001", "FGT-UTM-002", "FGT-UTM-003", "FGT-UTM-004", "FGT-UTM-005"])

    def test_certificate_inspection_flag_names_only_the_policy_that_needs_it(self):
        finding = next(f for f in self.result["findings"] if f["id"] == "FGT-UTM-001")
        self.assertIn("#1", finding["detail"])
        self.assertNotIn("#2", finding["detail"], "policy 2 uses deep inspection")

    def test_unused_profiles_do_not_raise_findings(self):
        config = CONFIG.replace('set av-profile "av-monitor"', "").replace('set ips-sensor "monitor-only"', "").replace('set webfilter-profile "wf-none"', "")
        ids = sorted(f["id"] for f in service.analyze(config, "t.conf")["findings"] if f["id"].startswith("FGT-UTM"))
        self.assertEqual(ids, ["FGT-UTM-001", "FGT-UTM-005"])


if __name__ == "__main__":
    unittest.main()
