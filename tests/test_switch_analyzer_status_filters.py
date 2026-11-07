"""Switch Analyzer, single device: the Transceivers and Port-Channel tabs have the same search box, count and filter buttons (by status) as Interfaces, Trunks and PoE.

The behaviour itself was checked in a real browser (chips, counts, a chip together with a search); these tests keep the wiring from being lost: the page has the containers
the script fills, and the script renders both tables through the filterable-table code with a chip function."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "templates" / "switch_analyzer.html").read_text(encoding="utf-8")
SCRIPT = (ROOT / "static" / "js" / "switch_analyzer.js").read_text(encoding="utf-8")


def _tab(tab_id: str) -> str:
    start = PAGE.index(f'id="switch-tab-{tab_id}"')
    return PAGE[start:PAGE.index('<div class="tab-content"', start + 1)]


def test_each_tab_has_a_search_box_a_count_and_a_row_of_filter_buttons_for_its_table():
    for tab_id, table in (("transceivers", "switch-transceiver-table"), ("portchannels", "switch-portchannel-table")):
        html = _tab(tab_id)
        assert f'data-table-search="{table}"' in html and f'data-table-count="{table}"' in html
        assert f'class="filter-chips" data-chips-for="{table}"' in html and "by status" in html


def test_the_script_renders_both_tables_as_filterable_tables_with_a_status_chip():
    transceivers = re.search(r'renderFilterable\("switch-transceiver-table".*?\}\);', SCRIPT, re.S)
    port_channels = re.search(r'renderFilterable\("switch-portchannel-table".*?\}\);', SCRIPT, re.S)
    assert transceivers and "chip:" in transceivers.group(0) and "TRANSCEIVER_CHIP_ORDER" in transceivers.group(0)
    assert port_channels and "chip: portChannelState" in port_channels.group(0) and "PORTCHANNEL_CHIP_ORDER" in port_channels.group(0)


def test_the_compare_tab_keeps_its_plain_tables():
    assert 'renderTable("switch-compare-transceivers-a"' in SCRIPT and 'renderTable("switch-compare-portchannels-a"' in SCRIPT


def test_the_new_chip_words_have_a_colour_and_an_order():
    tone = SCRIPT[SCRIPT.index("const STATUS_TONE"):SCRIPT.index("const toneOf")]
    assert '"degraded": "warn"' in tone and '"not in use": "warn"' in tone
    assert 'PORTCHANNEL_CHIP_ORDER = ["up", "degraded", "down", "not in use", "unknown"]' in SCRIPT
    assert 'TRANSCEIVER_CHIP_ORDER = ["up", "down", "admin down", "unknown"]' in SCRIPT
