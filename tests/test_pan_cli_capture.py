"""PAN-OS CLI capture ('show config running' in the curly-brace view + 'show system info'), routing engines, runtime findings.

The capture below is synthetic but follows the real layout: entries are bare blocks, rules print as 'name uuid { }', a one-member
list is a plain value, longer lists use [ ], and strings with ';' or '#' are quoted.
"""

from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

from features.configuration_studio.converter_engine.parsers.firewall import paloalto_curly
from features.firewall_analyzer import legacy, panos_routing, panos_runtime, service

CAPTURE = """Last login: Wed Oct  7 12:17:15 2026 from 10.0.0.9

admin@FW1> set cli pager off
admin@FW1> show system info

hostname: FW1
ip-address: 10.0.0.1
model: PA-440
serial: 0123456789
sw-version: 11.1.4-h2
uptime: 0 days, 0:05:58
app-version: 8900-1234
av-version: 0
threat-version: 0
wildfire-version: 0
url-db: paloaltonetworks
url-filtering-version: 0000.00.00.000
multi-vsys: off
advanced-routing: on
device-certificate-status: None

admin@FW1> show config running

config {
  mgt-config {
    users {
      admin {
        phash $5$abc$def;
        permissions {
          role-based {
            superuser yes;
          }
        }
      }
    }
  }
  shared {
    application;
    service;
  }
  devices {
    localhost.localdomain {
      network {
        interface {
          ethernet {
            ethernet1/1 {
              layer3 {
                ip {
                  192.0.2.2/30;
                }
              }
              comment "WAN #1; primary";
            }
            ethernet1/2 {
              layer3 {
                ip {
                  10.0.0.1/24;
                }
              }
            }
          }
        }
        virtual-router {
          default {
            interface [ ethernet1/1 ethernet1/2];
            routing-table {
              ip {
                static-route {
                  DEF-A {
                    destination 0.0.0.0/0;
                    interface ethernet1/1;
                    nexthop {
                      ip-address 192.0.2.1;
                    }
                    metric 10;
                    path-monitor {
                      enable yes;
                      monitor-destinations {
                        PM1 {
                          destination 8.8.8.8;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        logical-router {
          default {
            vrf {
              default {
                interface [ ethernet1/1 ethernet1/2];
                routing-table {
                  ip {
                    static-route {
                      DEF-A {
                        destination 0.0.0.0/0;
                        interface ethernet1/1;
                        nexthop {
                          ip-address 192.0.2.1;
                        }
                        metric 10;
                      }
                      DEF-B {
                        destination 0.0.0.0/0;
                        interface ethernet1/2;
                        nexthop {
                          ip-address 10.0.0.254;
                        }
                        metric 20;
                        path-monitor {
                          enable yes;
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      deviceconfig {
        system {
          hostname FW1;
          panorama {
            local-panorama {
              panorama-server 10.9.9.9;
            }
          }
        }
      }
      vsys {
        vsys1 {
          zone {
            trust {
              network {
                layer3 ethernet1/2;
              }
            }
            untrust {
              network {
                layer3 [ ethernet1/1 ];
              }
            }
          }
          address {
            H1 {
              ip-netmask 10.0.0.5/32;
              description "web; server #1";
            }
          }
          profile-group {
            GRP {
              virus AV1;
              spyware SP;
            }
          }
          profiles {
            spyware {
              SP {
                rules {
                  R1 {
                    threat-name any;
                  }
                }
              }
            }
          }
          rulebase {
            security {
              rules {
                Allow-Web 11111111-2222-3333-4444-555555555555 {
                  from trust;
                  to untrust;
                  source [ H1 trust-net];
                  destination any;
                  application web-browsing;
                  service application-default;
                  action allow;
                  profile-setting {
                    group GRP;
                  }
                }
                "Block Bad" aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee {
                  from any;
                  to any;
                  source any;
                  destination any;
                  application any;
                  service any;
                  action deny;
                }
              }
            }
          }
        }
      }
    }
  }
}
"""


class CurlyConverterTest(unittest.TestCase):
    def test_detection_and_structure(self):
        self.assertTrue(paloalto_curly.looks_like_curly(CAPTURE))
        self.assertFalse(paloalto_curly.looks_like_curly("<config version='10.2.0'><devices/></config>"))
        self.assertFalse(paloalto_curly.looks_like_curly("set deviceconfig system hostname X\n"))
        cap = paloalto_curly.convert(CAPTURE)
        root = ET.fromstring(cap.xml)
        self.assertEqual(root.get("version"), "11.1.0")
        self.assertEqual(cap.prompt_host, "FW1")
        rules = root.findall("devices/entry/vsys/entry/rulebase/security/rules/entry")
        self.assertEqual([(r.get("name"), r.get("uuid")) for r in rules], [("Allow-Web", "11111111-2222-3333-4444-555555555555"), ("Block Bad", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")])
        self.assertEqual([m.text for m in rules[0].findall("source/member")], ["H1", "trust-net"])
        self.assertEqual(rules[0].findtext("from"), "trust")                       # a one-member list stays a plain value
        self.assertEqual(root.find("devices/entry/network/interface/ethernet/entry[@name='ethernet1/1']").findtext("comment"), "WAN #1; primary")
        self.assertIsNotNone(root.find("devices/entry/network/interface/ethernet/entry/layer3/ip/entry[@name='10.0.0.1/24']"))
        self.assertEqual(cap.system_info["sw-version"], "11.1.4-h2")

    def test_windows_line_endings_and_pager_noise(self):
        noisy = CAPTURE.replace("\n", "\r\n").replace("show system info", "show system info\x1b[K")
        self.assertEqual(paloalto_curly.convert(noisy).xml, paloalto_curly.convert(CAPTURE).xml)

    def test_unknown_collection_is_left_alone_not_misread(self):
        cap = paloalto_curly.convert("config {\n  devices {\n    localhost.localdomain {\n      made-up {\n        thing {\n          x 1;\n        }\n      }\n    }\n  }\n}\n")
        root = ET.fromstring(cap.xml)
        self.assertIsNotNone(root.find("devices/entry/made-up/thing/x"))


class CaptureAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = service.analyze(CAPTURE, "fw1.log")
        cls.ids = {f["id"]: f for f in cls.result["findings"]}
        cls.sections = {s["id"]: s for s in cls.result["sections"]}

    def test_detected_without_a_platform_choice(self):
        self.assertEqual(service.detect_vendor(CAPTURE), "paloalto")
        self.assertEqual(self.result["hostname"], "FW1")
        self.assertIn("CLI capture", self.result["subtitle"])

    def test_policy_read_from_the_capture(self):
        rows = {r["name"]: r for r in self.sections["security_rules"]["rows"]}
        self.assertEqual(set(rows), {"Allow-Web", "Block Bad"})
        self.assertEqual(rows["Allow-Web"]["from_zone"], ["trust"])
        self.assertEqual(rows["Allow-Web"]["application"], ["web-browsing"])
        self.assertEqual([z["name"] for z in self.sections["zones"]["rows"]], ["trust", "untrust"])
        self.assertEqual({r["name"] for r in self.sections["address_objects"]["rows"]}, {"H1"})
        self.assertEqual(self.sections["interfaces"]["rows"][0]["comment"], "WAN #1; primary")

    def test_runtime_identity(self):
        info = {i["label"]: i["value"] for i in self.result["info"]}
        self.assertEqual((info["Model"], info["Serial"], info["PAN-OS version"]), ("PA-440", "0123456789", "11.1.4-h2"))
        pairs = {p["label"]: p["value"] for p in self.sections["runtime_identity"]["pairs"]}
        self.assertEqual(pairs["Threat content"], "0")
        self.assertIn("PAN-RT-001", self.ids)                                       # profile group on a unit with no threat content
        self.assertEqual(self.ids["PAN-RT-001"]["severity"], "medium")
        self.assertNotIn("PAN-RT-002", self.ids)                                    # no URL filtering profile in this capture
        self.assertIn("PAN-RT-003", self.ids)

    def test_profile_group_is_resolved(self):
        rows = {r["name"]: r for r in self.sections["profile_groups"]["rows"]}
        self.assertEqual(rows["GRP"]["virus"], "AV1")
        self.assertEqual(rows["GRP"]["used_by"], ["Allow-Web"])
        rule = {r["name"]: r for r in self.sections["security_rules"]["rows"]}["Allow-Web"]
        self.assertEqual(rule["profile"], ["group GRP (Antivirus, Anti-Spyware)"])
        self.assertNotIn("FW-POL-004", {f["id"] for f in self.result["findings"] if f["object"] == "rule Allow-Web"})   # it has a group, so it is not 'unprofiled'
        gap = self.ids["FW-POL-007"]
        self.assertEqual(gap["severity"], "medium")                                 # trust -> untrust is Internet-bound
        self.assertIn("WildFire Analysis", gap["title"])
        self.assertNotIn("Antivirus", gap["title"])

    def test_routing_engines(self):
        routes = {(r["name"], r["engine"]): r for r in self.sections["static_routes"]["rows"]}
        self.assertEqual(routes[("DEF-A", "advanced")]["active"], "yes")
        self.assertEqual(routes[("DEF-A", "classic")]["active"], "no")              # advanced-routing: on
        self.assertEqual(routes[("DEF-B", "advanced")]["detect"], "path monitor")
        self.assertEqual(routes[("DEF-A", "advanced")]["interface"], "ethernet1/1")
        self.assertIn("PAN-RT-004", self.ids)
        primary = self.ids["PAN-RT-005"]
        self.assertIn("DEF-A", primary["object"])
        self.assertIn("probably dropped", primary["detail"])                        # the inactive copy still has path monitoring
        self.assertIn("PAN-RT-006", self.ids)

    def test_panorama_notice_with_local_rules(self):
        notice = next(w for w in self.result["warnings"] if "Panorama" in w)
        self.assertIn("2 security", notice)
        self.assertNotIn("not included in this device's own", notice)

    def test_catch_all_deny_is_not_a_finding(self):
        self.assertNotIn("PAN-POL-005", self.ids)                                   # the deny is last, it hides nothing


class RoutingUnitTest(unittest.TestCase):
    @staticmethod
    def dashboard(classic=(), advanced=()):
        routes = [dict(r, engine="virtual-router", virtual_router="default") for r in classic] + [dict(r, engine="logical-router", virtual_router="default") for r in advanced]
        return {"static_routes": routes, "routing_protocols": [{"engine": r["engine"], "virtual_router": "default"} for r in routes[:1]] + ([{"engine": "logical-router", "virtual_router": "default"}] if classic and advanced else [])}

    def test_unknown_when_both_engines_and_no_show_output(self):
        d = self.dashboard([{"name": "A", "destination": "0.0.0.0/0"}], [{"name": "A", "destination": "0.0.0.0/0"}])
        panos_routing.annotate(d, None)
        self.assertEqual({r["active"] for r in d["static_routes"]}, {"unknown"})
        self.assertEqual(panos_routing.evaluate(d, None)[0]["id"], "PAN-RT-004")

    def test_single_engine_is_active_and_quiet(self):
        d = self.dashboard(classic=[{"name": "A", "destination": "0.0.0.0/0", "metric": 10}])
        panos_routing.annotate(d, None)
        self.assertEqual(d["static_routes"][0]["active"], "yes")
        self.assertEqual(panos_routing.evaluate(d, None), [])

    def test_two_defaults_both_monitored_is_quiet(self):
        d = self.dashboard(advanced=[{"name": "A", "destination": "0.0.0.0/0", "metric": 10, "path_monitor": True}, {"name": "B", "destination": "0.0.0.0/0", "metric": 20}])
        panos_routing.annotate(d, True)
        self.assertEqual([f["id"] for f in panos_routing.evaluate(d, True)], [])

    def test_secondary_without_monitoring_is_not_flagged(self):
        d = self.dashboard(advanced=[{"name": "A", "destination": "0.0.0.0/0", "metric": 10, "bfd": True}, {"name": "B", "destination": "0.0.0.0/0", "metric": 20}])
        panos_routing.annotate(d, True)
        self.assertEqual(panos_routing.evaluate(d, True), [])

    def test_advanced_flag_parsing(self):
        self.assertIs(panos_runtime.advanced_routing({"advanced-routing": "on"}), True)
        self.assertIs(panos_runtime.advanced_routing({"advanced-routing": "off"}), False)
        self.assertIsNone(panos_runtime.advanced_routing({}))


class XmlParserTest(unittest.TestCase):
    XML = """<config version="11.1.0"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>X</hostname><panorama><local-panorama><panorama-server>10.9.9.9</panorama-server></local-panorama></panorama></system></deviceconfig>
    <vsys><entry name="vsys1">{body}</entry></vsys></entry></devices></config>"""
    RULES = "<zone><entry name='a'><network><layer3><member>e1</member></layer3></network></entry></zone><rulebase><security><rules><entry name='r1'><from><member>a</member></from><to><member>a</member></to><source><member>any</member></source><destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>allow</action></entry></rules></security></rulebase>"

    def test_panorama_notice_wording_depends_on_local_policy(self):
        with_rules = legacy.analyze(self.XML.format(body=self.RULES), "x.xml", "Palo Alto")["warnings"]
        without = legacy.analyze(self.XML.format(body="<zone/>"), "x.xml", "Palo Alto")["warnings"]
        self.assertTrue(any("1 security" in w for w in with_rules))
        self.assertTrue(any("not included in this device's own" in w for w in without))

    def test_no_rules_gives_one_note_not_a_finding_per_zone(self):
        body = "<zone><entry name='a'><network><layer3><member>e1</member></layer3></network></entry><entry name='b'><network><layer3><member>e2</member></layer3></network></entry></zone>"
        ids = [f["id"] for f in legacy.analyze(self.XML.format(body=body), "x.xml", "Palo Alto")["findings"]]
        self.assertNotIn("FW-POL-002", ids)
        self.assertIn("FW-POL-006", ids)


if __name__ == "__main__":
    unittest.main()
