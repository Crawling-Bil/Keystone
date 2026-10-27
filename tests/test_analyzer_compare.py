"""Compare two analysis results (backup vs backup, HA peer vs peer) through the shared result schema."""

from __future__ import annotations

import io
import unittest
from datetime import date

from flask import Flask

from features.analyzer_core.compare import compare_results
from features.analyzer_core.result import kv_section, new_result, table_section, validate_result
from features.firewall_analyzer import service
from features.firewall_analyzer.routes import bp
from tests.test_firewall_profiles import CONFIG


def result(rows, host="A", findings=(), pairs=(("Version", "1.0"),), info=()):
    out = new_result("firewall", hostname=host, source_name=f"{host}.txt", platform="TestOS")
    out["sections"] = [table_section("objs", "Objects", [("name", "Name", "mono"), ("vdom", "VDOM"), ("members", "Members", "list"), ("note", "Note")], rows, group="Policies"),
                       kv_section("sys", "System", list(pairs), group="System")]
    out["findings"] = list(findings)
    out["info"] = [{"label": k, "value": v} for k, v in info]
    return out


def row(name, vdom="root", members=("a", "b"), note=""):
    return {"name": name, "vdom": vdom, "members": list(members), "note": note}


class CompareTests(unittest.TestCase):
    def changes(self, before, after):
        out = compare_results(before, after)
        self.assertEqual(validate_result(out), [])
        return out, [r for r in next(s for s in out["sections"] if s["id"] == "compare_changes")["rows"]]

    def test_identical_results_have_no_changes(self):
        out, rows = self.changes(result([row("x")]), result([row("x")], host="B"))
        self.assertEqual(rows, [])
        self.assertEqual(out["cards"][2]["value"], 0)

    def test_added_removed_changed(self):
        out, rows = self.changes(result([row("keep", note="old"), row("gone")]), result([row("keep", note="new"), row("fresh")], host="B"))
        got = {(r["change"], r["object"], r["field"]) for r in rows if r["section"] == "Objects"}
        self.assertEqual(got, {("changed", "root / keep", "Note"), ("removed", "root / gone", "(row)"), ("added", "root / fresh", "(row)")})
        changed = next(r for r in rows if r["change"] == "changed")
        self.assertEqual((changed["before"], changed["after"]), ("old", "new"))

    def test_member_order_is_not_a_change(self):
        _, rows = self.changes(result([row("x", members=("a", "b"))]), result([row("x", members=("b", "a"))], host="B"))
        self.assertEqual(rows, [])

    def test_scope_is_part_of_the_key(self):
        _, rows = self.changes(result([row("web", vdom="root"), row("web", vdom="dmz")]), result([row("web", vdom="root"), row("web", vdom="dmz", note="x")], host="B"))
        self.assertEqual([r["object"] for r in rows], ["dmz / web"])

    def test_duplicate_first_column_falls_back_to_more_columns(self):
        before = result([row("dup", members=("1",), note="p"), row("dup", members=("2",), note="q")])
        after = result([row("dup", members=("1",), note="p"), row("dup", members=("2",), note="CHANGED")], host="B")
        _, rows = self.changes(before, after)
        self.assertEqual(len(rows), 1)

    def test_key_value_sections(self):
        _, rows = self.changes(result([], pairs=(("Version", "1.0"), ("Mode", "ha"))), result([], host="B", pairs=(("Version", "2.0"), ("Mode", "ha"), ("New", "y"))))
        self.assertEqual({(r["object"], r["change"]) for r in rows}, {("Version", "changed"), ("New", "added")})

    def test_findings_new_and_resolved(self):
        f = lambda i, o, sev="high": {"id": i, "severity": sev, "category": "c", "title": f"t {i}", "object": o, "detail": "", "recommendation": "", "reference": ""}
        out = compare_results(result([], findings=[f("R1", "a"), f("R2", "b")]), result([], host="B", findings=[f("R2", "b"), f("R3", "c")]))
        titles = sorted(x["title"] for x in out["findings"])
        self.assertEqual(titles, ["New: t R3", "Resolved: t R1"])
        self.assertEqual({c["label"]: c["value"] for c in out["cards"]}["New findings"], 1)
        self.assertEqual(next(c for c in out["cards"] if c["label"] == "New findings")["tone"], "bad")

    def test_change_history_is_left_out_between_ha_peers_but_kept_for_one_device(self):
        def with_log(host, line):
            out = result([row("x")], host=host)
            out["sections"].append(table_section("change_log", "Configuration saves", [("when", "When", "mono"), ("what", "What")], [{"when": line, "what": "save"}], group="Change history"))
            return out
        peers = compare_results(with_log("A", "2026-10-01"), with_log("B", "2026-10-02"))
        self.assertEqual([r for r in next(s for s in peers["sections"] if s["id"] == "compare_changes")["rows"]], [])
        self.assertTrue(any("change-history" in w for w in peers["warnings"]))
        same = compare_results(with_log("A", "2026-10-01"), with_log("A", "2026-10-02"))
        self.assertTrue([r for r in next(s for s in same["sections"] if s["id"] == "compare_changes")["rows"]])
        self.assertFalse(same["warnings"])

    def test_a_comparison_is_never_compared_again(self):
        flask = Flask("t", template_folder="templates")
        flask.register_blueprint(bp)
        flask.context_processor(lambda: {"app_version": "t"})
        client = flask.test_client()
        done = compare_results(result([]), result([], host="B"))
        bad = client.post("/firewall-analyzer/api/compare", json={"before": done, "after": result([])})
        self.assertEqual(bad.status_code, 400)


class FirewallBackupDrift(unittest.TestCase):
    def test_policy_change_between_two_real_analyses(self):
        older = CONFIG.replace('set av-profile "av-monitor"', "")          # the monitor-only antivirus profile was not attached yet
        before, after = service.analyze(older, "old.conf", today=date(2026, 10, 14)), service.analyze(CONFIG, "new.conf", today=date(2026, 10, 14))
        out = compare_results(before, after)
        self.assertEqual(validate_result(out), [])
        rows = next(s for s in out["sections"] if s["id"] == "compare_changes")["rows"]
        self.assertTrue(any(r["change"] == "changed" for r in rows))
        self.assertIn("New: Antivirus profile does not block", [f["title"] for f in out["findings"]])

    def test_http_round_trip_and_export(self):
        flask = Flask("t", template_folder="templates", static_folder="static")
        flask.register_blueprint(bp)
        flask.context_processor(lambda: {"app_version": "t"})
        client = flask.test_client()
        files = [(io.BytesIO(CONFIG.encode()), "a.conf"), (io.BytesIO(CONFIG.replace("monitor-only", "mon-renamed").encode()), "b.conf")]
        analyzed = client.post("/firewall-analyzer/api/analyze", data={"config_files": files}, content_type="multipart/form-data").get_json()
        self.assertTrue(analyzed["ok"])
        a, b = analyzed["results"]
        cmp = client.post("/firewall-analyzer/api/compare", json={"before": a, "after": b}).get_json()
        self.assertTrue(cmp["ok"])
        self.assertTrue(cmp["result"]["comparison"])
        export = client.post("/firewall-analyzer/api/export", json={"results": [a, b, cmp["result"]]})
        self.assertEqual(export.status_code, 200, export.get_data(as_text=True)[:200])


if __name__ == "__main__":
    unittest.main()
