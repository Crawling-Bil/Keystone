"""Topology Builder: automatic grouping by site ("Automatic" option). Synthetic captures only."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_samples import nxos_capture  # noqa: E402

from features.topology.layout import auto_mode  # noqa: E402
from features.topology.report import settings_text  # noqa: E402
from features.topology.service import GROUP_MODES, build_topology  # noqa: E402
from tests.test_topology_v05 import _graph_of  # noqa: E402


def _sites(sites: list[str], per_site: int) -> list[str]:
    return [f"{site}-SW{i}" for site in sites for i in range(1, per_site + 1)]


def test_a_small_network_stays_on_one_diagram():
    assert auto_mode(_graph_of(_sites(["JKT", "BGR", "SBY"], 5), [])) == "none"


def test_a_large_network_is_split_by_the_first_hostname_word():
    assert auto_mode(_graph_of(_sites(["JKT", "BGR", "SBY", "MDN", "BDG", "SMG"], 6), [])) == "prefix1"


def test_role_first_hostnames_use_the_second_word_when_the_first_gives_one_site():
    names = [f"SW-{site}-{i}" for site in ("JKT", "BGR", "SBY", "MDN") for i in range(1, 9)]
    assert auto_mode(_graph_of(names, [])) == "prefix2"


def test_no_readable_split_keeps_the_diagram_whole():
    assert auto_mode(_graph_of([f"DEVICE{i}" for i in range(1, 41)], [])) == "none"       # every name is its own group: no site holds two devices
    assert auto_mode(_graph_of([f"KCU-SW{i}" for i in range(1, 41)], [])) == "none"       # one site only


def test_automatic_is_the_first_choice_of_the_page():
    assert GROUP_MODES[0][0] == "auto"


def _site_files(sites: int, per_site: int) -> list[tuple[str, str]]:
    files = []
    serial = 100
    for s in range(1, sites + 1):
        for i in range(1, per_site + 1):
            host = f"S{s:02d}-SW{i}"
            cdp = []
            if i > 1:
                cdp.append((f"S{s:02d}-SW{i - 1}", f"10.{s}.0.{i - 1}", "N9K-C93180YC-FX3", "Eth1/1", "Eth1/2"))
            if i < per_site:
                cdp.append((f"S{s:02d}-SW{i + 1}", f"10.{s}.0.{i + 1}", "N9K-C93180YC-FX3", "Eth1/2", "Eth1/1"))
            serial += 1
            files.append((f"{host}.txt", nxos_capture(host, f"FDO{serial:08d}", f"10.{s}.0.{i}", cdp)))
    return files


def test_build_with_automatic_makes_an_overview_and_one_page_per_site():
    result = build_topology(_site_files(8, 4), group="auto")
    assert result["settings"]["group"] == "auto" and result["settings"]["group_used"] == "prefix1"
    names = [page.name for page in result["pages"]]
    assert names[0] == "Overview" and len(names) == 9
    assert names[1:] == [f"S{n:02d}" for n in range(1, 9)]
    graph = result["graph"]
    for page in result["pages"][1:]:
        assert sorted(graph.nodes[key].hostname for key in page.nodes) == [f"{page.name}-SW{i}" for i in range(1, 5)]


def test_build_with_automatic_on_a_small_network_makes_one_page():
    result = build_topology(_site_files(2, 3), group="auto")
    assert result["settings"]["group_used"] == "none"
    assert [page.name for page in result["pages"]] == ["Overview"]


def test_run_settings_name_the_grouping_that_automatic_applied():
    result = build_topology(_site_files(8, 4), group="auto", name="Lab")
    text = settings_text(result["settings"])
    assert "Grouping: Automatic" in text and "Grouping applied by Automatic: Group by first hostname word" in text
    plain = settings_text(build_topology(_site_files(2, 3), group="none")["settings"])
    assert "Grouping applied by Automatic" not in plain
