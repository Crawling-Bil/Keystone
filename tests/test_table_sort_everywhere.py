"""Click-to-sort on every analyzer result table: the Switch Analyzer page (its firewall pane and the L3, health, routing and sizing tables, not only the
CDP/LLDP table), and the shared table of the Router, Firewall and Load Balancer analyzers (empty cells last, whichever way, and a hint on every header)."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWITCH_JS = (ROOT / "static" / "js" / "switch_analyzer.js").read_text(encoding="utf-8")
KIT_JS = (ROOT / "static" / "js" / "analyzer_kit.js").read_text(encoding="utf-8")


def _body(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    return source[start:source.index("\n  }\n", start)]


def test_the_plain_result_tables_of_the_switch_page_are_sortable_tables():
    body = _body(SWITCH_JS, "renderTable")
    assert "renderFilterable(id, columns, rows" in body and 'startsWith("switch-compare-")' in body
    assert "cap: Infinity" in body                                      # nothing is cut to 500 rows that was shown in full before


def test_the_row_cap_can_be_set_per_table():
    assert "cap: options.cap ?? ROW_CAP" in SWITCH_JS


def test_the_paired_compare_tables_are_not_sortable():
    assert 'sortable: options.sortable ?? !id.startsWith("switch-compare-")' in SWITCH_JS


def test_the_firewall_pane_cdp_lldp_table_goes_through_the_sortable_path():
    assert 'renderTable("firewall-cdp-lldp-table"' in SWITCH_JS         # renderTable is the sortable path now


def test_the_shared_analyzer_table_puts_empty_cells_last_in_both_directions():
    assert "function isBlankValue(" in KIT_JS
    sort = _body(KIT_JS, "sortedBy")                                     # one rule for the tables, the findings list and the Excel export
    assert "isBlankValue(a[key])" in sort and "blankA === blankB ? 0" in sort
    assert re.search(r"return dir \* compareValues\(a\[key\], b\[key\]\)", sort)
    assert "sortedBy(list, local.sortKey, local.sortDir)" in KIT_JS      # the table view uses it


def test_the_findings_list_the_lb_summary_and_the_wizard_tables_sort_too():
    assert "FINDING_SORTS" in KIT_JS and "sortFindings(shown, f)" in KIT_JS
    assert 'aria-label": "Sort findings by"' in KIT_JS
    assert "const sortHead = (key, label, lead)" in KIT_JS               # the Load Balancer summary table
    wizard = (ROOT / "static" / "js" / "firewall_wizard.js").read_text(encoding="utf-8")
    assert "function makeSortable(" in wizard and "makeSortable(stepKey);" in wizard


def test_the_excel_export_follows_the_sorted_order():
    assert "orderedResults()" in KIT_JS and "an-export-order" in KIT_JS
    assert "this.state.exportShown === false ? this.state.results : this.orderedResults()" in KIT_JS


def test_every_header_of_the_shared_table_says_what_a_click_does():
    assert 'title: `Sort by ${col.label}`' in KIT_JS and '"aria-sort"' in KIT_JS


def test_the_router_firewall_and_lb_analyzers_use_the_shared_table():
    for package in ("router_analyzer", "firewall_analyzer", "lb_analyzer"):
        assert 'template="analyzer_page.html"' in (ROOT / "features" / package / "routes.py").read_text(encoding="utf-8")


def test_the_workbook_lists_findings_and_rows_in_the_order_it_is_given(tmp_path):
    """The browser sends the results sorted as the person sees them; the workbook must not put them back in the order of the analysis."""
    import openpyxl

    from features.analyzer_core.export import export_results
    from features.lb_analyzer import service

    text = (ROOT / "tests" / "fixtures" / "loadbalancer" / "bigip_capture_synthetic.txt").read_text(encoding="utf-8")
    result = service.analyze(text, "cap.txt")
    result["findings"] = sorted(result["findings"], key=lambda item: item["title"], reverse=True)
    path = export_results([result], tmp_path / "ordered.xlsx")
    sheet = openpyxl.load_workbook(path)["Findings"]
    heads = [cell.value for cell in sheet[1]]
    titles = [sheet.cell(row=index, column=heads.index("Title") + 1).value for index in range(2, sheet.max_row + 1)]
    assert titles == [item["title"] for item in result["findings"]]
