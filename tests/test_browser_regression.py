"""Real-browser regression tests: the pages are opened in Chromium (Playwright), a capture is uploaded and the controls a person uses are clicked.

The Python tests pin what the server answers; these pin what the person sees: a table that sorts when its heading is clicked, empty cells that stay last, the Findings
sort, the Load Balancer summary, the guided firewall conversion tables, the Excel export that follows the order on screen, and a page that raises no script error.

Skipped when Playwright or its Chromium is not installed (``pip install playwright`` and ``playwright install chromium``).  Every capture is invented:
the files under tests/fixtures or the short text below, documentation addresses only.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

playwright_api = pytest.importorskip("playwright.sync_api")

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"

# A short MikroTik export for the guided conversion (documentation addresses).
BRANCH_RSC = """\
/system identity
set name=BRANCH-01
/interface ethernet
set [ find default-name=ether1 ] comment="LAN switch"
set [ find default-name=ether2 ] comment="ISP uplink"
set [ find default-name=ether3 ] comment="spare"
/interface bridge
add name=br-lan
/interface bridge port
add bridge=br-lan interface=ether1
/interface list
add name=WAN
/interface list member
add interface=ether2 list=WAN
/ip address
add address=192.168.10.1/24 interface=br-lan
add address=203.0.113.6/29 interface=ether2
/ip route
add gateway=203.0.113.1
/ip firewall address-list
add address=192.168.10.0/24 list=lan-net
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether2 comment=hide
/ip firewall filter
add action=accept chain=forward in-interface=ether1 out-interface-list=WAN comment=lan-out
/ip ipsec profile
add dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256 name=ike-prof lifetime=1d
/ip ipsec proposal
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc name=esp-prop pfs-group=modp2048 lifetime=1h
/ip ipsec peer
add address=198.51.100.50/32 exchange-mode=ike2 local-address=203.0.113.6 name=hq profile=ike-prof
/ip ipsec policy
add dst-address=10.50.0.0/24 peer=hq proposal=esp-prop src-address=192.168.10.0/24 tunnel=yes comment=to-hq
"""


@pytest.fixture(scope="module")
def base_url():
    from werkzeug.serving import make_server

    from app import create_app

    server = make_server("127.0.0.1", 0, create_app(), threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def browser():
    with playwright_api.sync_playwright() as p:
        try:
            chromium = p.chromium.launch()
        except Exception as error:                                   # noqa: BLE001 - the browser binary is not installed
            pytest.skip(f"Chromium is not available: {error}")
        yield chromium
        chromium.close()


@pytest.fixture()
def page(browser):
    context = browser.new_context(viewport={"width": 1500, "height": 1000}, accept_downloads=True)
    page = context.new_page()
    page.errors = []                                                 # script errors and console errors of this page
    page.on("pageerror", lambda error: page.errors.append(str(error)))
    page.on("console", lambda message: message.type == "error" and page.errors.append(message.text))
    yield page
    context.close()


def _analyze(page, base_url, path, fixture):
    page.goto(f"{base_url}{path}")
    page.set_input_files('[data-role="file-input"]', str(fixture))
    page.click('[data-role="analyze"]')
    page.wait_for_selector('[data-role="result"]:not(.hidden) .an-tabs', timeout=30000)


def _tab(page, label):
    page.click(f'.an-tabs button:has-text("{label}")')


def _column(page, selector, index):
    return page.eval_on_selector_all(f"{selector} tbody tr td:nth-child({index})", "cells => cells.map(cell => cell.textContent.trim())")


# ---------------------------------------------------------------- every page opens

def test_every_page_in_the_menu_opens_without_a_script_error(page, base_url):
    page.goto(base_url)
    links = sorted(set(page.eval_on_selector_all("#suite-sidebar a.suite-nav-item", "links => links.map(link => link.getAttribute('href'))")))
    assert len(links) >= 8
    for href in links:
        if not href.startswith("/"):
            continue
        response = page.goto(f"{base_url}{href}")
        assert response is not None and response.status < 400, href
        page.wait_for_load_state("networkidle")
    assert page.errors == []


# ---------------------------------------------------------------- the shared analyzer kit (Router, Firewall, Load Balancer)

def test_findings_sort_by_category_and_reverse(page, base_url):
    _analyze(page, base_url, "/load-balancer-analyzer", FIXTURES / "loadbalancer" / "bigip_capture_synthetic.txt")
    _tab(page, "Findings")
    categories = lambda: page.eval_on_selector_all(".an-finding-list .an-finding .an-finding-head .an-chip", "chips => chips.map(chip => chip.textContent)")
    unsorted = categories()
    assert len(set(unsorted)) > 2
    page.select_option('select[aria-label="Sort findings by"]', "category")
    ascending = categories()
    assert ascending == sorted(ascending, key=str.casefold) and ascending[0] != unsorted[0]
    page.click('button[aria-label="Reverse the sort order"]')
    descending = categories()
    assert descending == sorted(descending, key=str.casefold, reverse=True)
    page.select_option('select[aria-label="Sort findings by"]', "")
    assert categories() == unsorted                                  # the default order comes back
    assert page.errors == []


def test_findings_sort_by_severity_puts_the_most_severe_first_and_back(page, base_url):
    _analyze(page, base_url, "/load-balancer-analyzer", FIXTURES / "loadbalancer" / "bigip_synthetic_weak.conf")
    _tab(page, "Findings")
    page.select_option('select[aria-label="Sort findings by"]', "severity")
    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    levels = lambda: [rank[text] for text in page.eval_on_selector_all(".an-finding-list .an-finding .an-finding-head .an-pill", "pills => pills.map(pill => pill.textContent)")]
    assert levels() == sorted(levels())
    page.click('button[aria-label="Reverse the sort order"]')
    assert levels() == sorted(levels(), reverse=True)


def test_the_load_balancer_summary_sorts_by_any_heading_and_goes_back(page, base_url):
    _analyze(page, base_url, "/load-balancer-analyzer", FIXTURES / "loadbalancer" / "bigip_capture_synthetic.txt")
    _tab(page, "Visualization")
    page.click("details.an-map-summary summary")
    names = lambda: page.eval_on_selector_all(".an-map-summary-table tbody tr th", "cells => cells.map(cell => cell.textContent.trim())")
    totals = lambda: [int(text) for text in _column(page, ".an-map-summary-table", _heads(page))]          # the last column is the total
    original = names()
    assert len(original) >= 3
    total = ".an-map-summary-table thead th:last-child button"
    page.click(total)
    assert totals() == sorted(totals())
    page.click(total)
    assert totals() == sorted(totals(), reverse=True)
    page.click(total)
    assert names() == original                                       # a third click is the order of the map again
    assert page.get_attribute(".an-map-summary-table thead th:last-child", "aria-sort") == "none"
    page.click(".an-map-summary-table thead th:first-child button")
    assert names() == sorted(original, key=str.casefold)
    for _ in range(2):                                               # a status column: a dash (no object of that kind) stays last, up and down
        page.click(".an-map-summary-table thead th:nth-child(5) button")
        cells = _column(page, ".an-map-summary-table", 5)
        assert "\u2013" in cells and cells == sorted(cells, key=lambda text: text == "\u2013"), cells
    assert page.errors == []


def _heads(page) -> int:
    return page.eval_on_selector_all(".an-map-summary-table thead th", "heads => heads.length")


def test_a_router_table_sorts_with_empty_cells_last_in_both_directions(page, base_url):
    _analyze(page, base_url, "/router-analyzer", FIXTURES / "router" / "synthetic_bad_ios_router.txt")
    tabs = page.eval_on_selector_all(".an-tabs button", "buttons => buttons.map(button => button.textContent.trim())")
    checked = 0
    for label in tabs:
        if label.startswith(("Overview", "Findings", "Coverage", "Collect")):
            continue
        _tab(page, label)
        for table in page.query_selector_all(".an-table"):
            heads = table.query_selector_all("thead th button.an-sort")
            rows = table.query_selector_all("tbody tr")
            if len(rows) < 3 or not heads:
                continue
            for index in range(len(heads)):
                table.query_selector_all("thead th button.an-sort")[index].click()
                cells = [row.query_selector_all("td")[index].inner_text().strip() for row in table.query_selector_all("tbody tr")]
                blanks = [cell in ("", "-", "—") for cell in cells]
                assert blanks == sorted(blanks), (label, index, cells)          # blanks, if any, all at the end
                table.query_selector_all("thead th button.an-sort")[index].click()
                cells = [row.query_selector_all("td")[index].inner_text().strip() for row in table.query_selector_all("tbody tr")]
                blanks = [cell in ("", "-", "—") for cell in cells]
                assert blanks == sorted(blanks), (label, index, cells)
                checked += 1
            break
    assert checked >= 3
    assert page.errors == []


def test_the_excel_export_keeps_the_order_on_screen_unless_switched_off(page, base_url):
    _analyze(page, base_url, "/load-balancer-analyzer", FIXTURES / "loadbalancer" / "bigip_capture_synthetic.txt")
    _tab(page, "Findings")
    page.select_option('select[aria-label="Sort findings by"]', "title")
    page.click('button[aria-label="Reverse the sort order"]')
    shown = page.eval_on_selector_all(".an-finding-list .an-finding h4", "titles => titles.map(title => title.textContent)")

    def posted() -> list[str]:
        with page.expect_request("**/api/export") as request:
            page.click(".an-toolbar .an-btn.primary")
        return [item["title"] for item in json.loads(request.value.post_data)["results"][0]["findings"]]

    assert posted() == shown                                         # the whole list in the sorted order, not only what the filter shows
    page.uncheck(".an-export-order input")
    default = posted()
    assert default != shown and sorted(default) == sorted(shown)     # off: the order of the analysis
    assert page.errors == []


def test_the_excel_export_keeps_the_sorted_order_of_a_table(page, base_url):
    _analyze(page, base_url, "/router-analyzer", FIXTURES / "router" / "synthetic_bad_ios_router.txt")
    sorted_tables = 0
    for label in page.eval_on_selector_all(".an-tabs button", "buttons => buttons.map(button => button.textContent.trim())"):
        if label.startswith(("Overview", "Findings", "Coverage", "Collect")):
            continue
        _tab(page, label)
        for table in page.query_selector_all("section.an-section"):
            heads = table.query_selector_all("thead th button.an-sort")
            if len(table.query_selector_all("tbody tr")) < 3 or not heads:
                continue
            section_id = table.get_attribute("data-section-id")
            for _ in range(2):                                        # descending on the first column (the heading is drawn again after every click)
                table.query_selector_all("thead th button.an-sort")[0].click()
            shown = [row.query_selector_all("td")[0].inner_text().strip() for row in table.query_selector_all("tbody tr")]
            with page.expect_request("**/api/export") as request:
                page.click(".an-toolbar .an-btn.primary")
            section = next(item for item in json.loads(request.value.post_data)["results"][0]["sections"] if item["id"] == section_id)
            first_key = section["columns"][0]["key"]
            posted = [str(row[first_key]).strip() for row in section["rows"]][: len(shown)]
            assert [text for text in posted if text] == [text for text in shown if text and text not in ("-", "—")], section_id
            sorted_tables += 1
            break
        if sorted_tables:
            break
    assert sorted_tables == 1
    assert page.errors == []


# ---------------------------------------------------------------- the Switch Analyzer page

def test_the_switch_neighbour_table_sorts_and_keeps_its_filter(page, base_url):
    page.goto(f"{base_url}/switch-analyzer")
    page.set_input_files("#switch-config-file", str(FIXTURES / "switch" / "browser_cdp_lab_synthetic.txt"))
    page.click("#switch-analyze-button")
    page.wait_for_selector("#switch-result:not(.hidden)", timeout=30000)
    page.click('#switch-tabs button[data-tab="neighbors"]')
    column = lambda index: _column(page, "#switch-neighbor-table", index)
    names = column(2)
    assert len(names) >= 3
    page.click("#switch-neighbor-table thead th:nth-child(2) button")
    assert column(2) == sorted(names, key=str.casefold)
    page.click("#switch-neighbor-table thead th:nth-child(2) button")
    assert column(2) == sorted(names, key=str.casefold, reverse=True)
    page.fill('[data-table-search="switch-neighbor-table"]', names[0])
    assert column(2) and all(names[0].lower() in cell.lower() for cell in column(2))
    assert page.errors == []


# ---------------------------------------------------------------- guided firewall conversion

def test_the_wizard_tables_sort_by_a_click_and_keep_the_rows_editable(page, base_url):
    page.goto(f"{base_url}/convert/firewall")
    page.select_option("#target-vendor", "Palo Alto")
    page.fill("#config-text", BRANCH_RSC)
    page.click("#wizard-start-button")
    page.wait_for_selector("#wizard-result:not(.hidden) #wizard-editor select", timeout=30000)
    page.select_option("#wizard-editor select", "PA-505")
    page.click("#wizard-next")
    page.wait_for_selector("#wizard-editor table", timeout=30000)
    table = page.locator("#wizard-editor table").first                # the port table; the VLAN / bridge table below it is a second table
    first = lambda: [text.strip() for text in table.locator("tbody tr td:first-child strong").all_inner_texts()]
    original = first()
    assert len(original) >= 3
    head = table.locator("thead th").nth(0)
    page.locator("#wizard-editor table").first.locator("thead th").nth(0).locator("button").click()
    assert first() == sorted(original, key=str.casefold)
    head.locator("button").click()
    assert first() == sorted(original, key=str.casefold, reverse=True)
    # a row that moved still carries its controls: pick a target port in the first row and the state follows
    table.locator("tbody tr").first.locator("select").select_option(index=1)
    assert page.inner_text("#wizard-step-status") == "Changed, not checked yet"
    head.locator("button").click()
    assert first() == original                                      # a third click: the order of the export
    assert head.get_attribute("aria-sort") == "none"
    assert page.errors == []
