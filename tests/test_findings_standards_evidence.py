"""Optional ``standards`` and ``evidence`` on a finding: absent when unused (nothing existing changes), carried into the Findings sheet when used."""
from __future__ import annotations

from openpyxl import load_workbook

from features.analyzer_core.export import export_results
from features.analyzer_core.findings import cap_per_rule, finding


def test_plain_finding_has_exactly_the_old_keys():
    item = finding("X-1", "low", "Cat", "Title")
    assert set(item) == {"id", "severity", "category", "title", "object", "detail", "recommendation", "reference"}


def test_standards_and_evidence_are_stored_clean():
    item = finding("X-1", "high", "Cat", "Title", standards=["NIST SP 800-53 Rev. 5 AC-6", "  ", "PCI DSS v4.0 1.3.1"], evidence="snmp-server community public RW")
    assert item["standards"] == ["NIST SP 800-53 Rev. 5 AC-6", "PCI DSS v4.0 1.3.1"]
    assert item["evidence"] == "snmp-server community public RW"
    assert finding("X-2", "low", "Cat", "T", standards="CIS 1.1")["standards"] == ["CIS 1.1"]            # a bare string is one control, not letters


def test_cap_per_rule_summary_line_stays_valid():
    items = [finding("R", "low", "C", "t", obj=str(i), standards=["S"]) for i in range(30)]
    capped = cap_per_rule(items, limit=5)
    assert len(capped) == 6 and "standards" not in capped[-1]


def _sheet(tmp_path, findings):
    result = {"hostname": "sw1", "findings": findings, "info": [], "sections": []}
    path = export_results([result], tmp_path / "out.xlsx")
    return load_workbook(path)


def test_findings_sheet_adds_audit_columns_only_when_used(tmp_path):
    plain = _sheet(tmp_path, [finding("X-1", "low", "Cat", "Title")])
    used = _sheet(tmp_path, [finding("X-1", "low", "Cat", "Title", standards=["CIS 1.1"], evidence="line")])
    for book, expect in ((plain, False), (used, True)):
        ws = book["Findings"]
        headers = [c.value for c in ws[1]]
        assert (("Standards" in headers) and ("Evidence" in headers)) is expect
        if expect:
            assert [c.value for c in ws[2]][-2:] == ["CIS 1.1", "line"]
