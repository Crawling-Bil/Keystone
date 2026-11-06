"""Topology Builder: the layout score (``features/topology/layoutscore.py``) and its use as a guard on the demo sets (invented captures)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from features.topology import demo, layoutscore, service
from features.topology.layoutscore import crosses, runs_through, score_page, score_pages


def _page(positions: dict[str, tuple[float, float]], pairs: list[tuple[str, str]], name: str = "P", routes: dict | None = None):
    nodes = {k: SimpleNamespace(x=x, y=y) for k, (x, y) in positions.items()}
    return SimpleNamespace(name=name, nodes=nodes, connections=[SimpleNamespace(a=a, b=b) for a, b in pairs], routes=routes or {})


def test_two_lines_that_cross_are_counted_and_lines_that_meet_at_a_device_are_not():
    assert crosses((0, 0, 10, 10), (0, 10, 10, 0))
    assert not crosses((0, 0, 10, 10), (10, 10, 20, 0))             # they meet at an end
    assert not crosses((0, 0, 10, 0), (0, 5, 10, 5))                # parallel
    page = _page({"A": (0, 0), "B": (400, 400), "C": (0, 400), "D": (400, 0), "E": (0, 800)}, [("A", "B"), ("C", "D"), ("A", "E")])
    assert score_page(page)["crossings"] == 1                       # A-B x C-D; A-E shares A with A-B and is far from C-D


def test_a_line_through_the_icon_of_a_third_device_is_counted():
    assert runs_through((0, 0, 100, 0), (40, -10, 60, 10)) and not runs_through((0, 0, 100, 0), (40, 5, 60, 25))
    through = _page({"A": (0, 0), "B": (600, 0), "M": (300, 0)}, [("A", "B")])
    beside = _page({"A": (0, 0), "B": (600, 0), "M": (300, 200)}, [("A", "B")])
    assert score_page(through)["through"] == 1 and score_page(beside)["through"] == 0


def test_the_cost_rises_with_every_part_and_the_rows_name_the_page():
    page = _page({"A": (0, 0), "B": (2000, 0)}, [("A", "B")], name="Floor 2")
    row = score_pages([page])[0]
    assert row["page"] == "Floor 2" and row["devices"] == 2 and row["length"] == 2000 and row["cost"] == 2.0


def test_a_cable_to_a_device_that_is_not_on_the_page_is_skipped():
    assert score_page(_page({"A": (0, 0)}, [("A", "GHOST")]))["length"] == 0


def test_a_routed_line_is_scored_on_its_bent_path_not_on_the_straight_segment():
    # A-B would run straight through M; the layout routed it over (300, 200), a bend below M
    positions = {"A": (0, 0), "B": (600, 0), "M": (300, 0)}
    straight = _page(positions, [("A", "B")])
    bent = _page(positions, [("A", "B")], routes={0: [(338.0, 300.0)]})
    assert score_page(straight)["through"] == 1 and score_page(bent)["through"] == 0
    assert score_page(bent)["length"] > score_page(straight)["length"]                      # the way around is longer


def test_the_length_of_a_bent_line_is_the_sum_of_its_legs():
    page = _page({"A": (0, 0), "B": (300, 400)}, [("A", "B")], routes={0: [(38.0, 438.0)]})       # centres (38, 38) -> (38, 438) -> (338, 438)
    assert score_page(page)["length"] == 400 + 300


def test_two_lines_cross_where_their_bent_paths_cross_and_not_where_the_straight_segments_would():
    positions = {"A": (0, 0), "B": (400, 400), "C": (0, 400), "D": (400, 0)}
    straight = _page(positions, [("A", "B"), ("C", "D")])
    assert score_page(straight)["crossings"] == 1
    # C-D leaves downwards and comes back round the outside: it no longer meets A-B
    around = _page(positions, [("A", "B"), ("C", "D")], routes={1: [(38.0, 900.0), (900.0, 900.0), (900.0, 38.0)]})
    assert score_page(around)["crossings"] == 0
    # a bend that makes a line cross another one is counted too
    meets = _page({"A": (0, 0), "B": (400, 0), "C": (0, 200), "D": (400, 200)}, [("A", "B"), ("C", "D")], routes={1: [(200.0, -300.0)]})
    assert score_page(straight)["crossings"] == 1 and score_page(meets)["crossings"] == 2          # up to the bend and back down: it crosses A-B twice


def test_a_line_without_a_route_keeps_its_straight_segment_when_others_are_routed():
    page = _page({"A": (0, 0), "B": (600, 0), "M": (300, 0), "C": (0, 500), "D": (600, 500)}, [("A", "B"), ("C", "D")], routes={1: [(300.0, 800.0)]})
    assert score_page(page)["through"] == 1                                                 # A-B has no route: still through M


# the guard: a layout rule must not make the demo sets worse than they are today (small room for the pages that move by one line); counted on the lines as they are drawn
BUDGET = {"before": (7, 1), "edge": (2, 1), "multisite": (36, 1)}


@pytest.mark.parametrize("set_id", ["before", "edge", "multisite"])
def test_the_demo_sets_keep_their_crossings_and_lines_through_icons_within_budget(set_id):
    names = [f["name"] for f in next(s for s in demo.list_sets() if s["id"] == set_id)["files"]]
    files = [(name, demo.read_file(set_id, name).decode("utf-8")) for name in names]
    result = service.build_topology(files, group="auto", view="physical")
    rows = score_pages(result["pages"])
    crossings, through = BUDGET[set_id]
    assert sum(r["crossings"] for r in rows) <= crossings
    assert sum(r["through"] for r in rows) <= through
    assert result["settings"]["layout_check"] == rows


def test_the_run_settings_text_carries_the_layout_check():
    from features.topology.report import settings_text

    text = settings_text({"layout_check": [{"page": "Overview", "devices": 3, "crossings": 2, "through": 1, "length": 1234}]})
    assert "Overview: 3 devices, 2 crossings, 1 lines through another icon, 1,234 px of line" in text and "Total: 2 crossings" in text


def test_a_very_large_page_is_scored_on_its_first_lines(monkeypatch):
    monkeypatch.setattr(layoutscore, "MAX_LINES", 1)
    page = _page({"A": (0, 0), "B": (100, 0), "C": (0, 500), "D": (100, 500)}, [("A", "B"), ("C", "D")])
    assert score_page(page)["length"] == 100
