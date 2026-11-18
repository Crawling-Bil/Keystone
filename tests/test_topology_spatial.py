"""The uniform grid behind the topology engine's "what lies under this line or label" questions must answer EXACTLY what the plain loops answered.

Every test here draws random rectangles and segments (fixed seeds, invented numbers) and compares the grid-backed function with a plain
reference loop written out in the test.  A speed-budget test at the end keeps the quadratic behaviour from coming back.
"""
from __future__ import annotations

import random
import time
import types

import pytest

from features.topology import labelplace, scene
from features.topology.spatial import MIN_BOXES, BoxGrid, near

SEEDS = range(12)


def _overlaps(b, left, top, right, bottom) -> bool:
    return b[0] < right and b[2] > left and b[1] < bottom and b[3] > top


def _boxes(rng: random.Random, n: int, span: float = 2400.0) -> list[tuple[float, float, float, float]]:
    out = []
    for _ in range(n):
        x, y = rng.uniform(-300, span), rng.uniform(-300, span)
        w, h = rng.choice((0.0, 1.0, 20.0, 74.0, 130.0, 500.0)) * rng.random(), rng.choice((0.0, 12.0, 60.0, 90.0, 400.0)) * rng.random()
        out.append((x, y, x + w, y + h))
    return out


@pytest.mark.parametrize("seed", SEEDS)
def test_boxgrid_overlapping_matches_plain_scan_in_order(seed):
    rng = random.Random(seed)
    boxes = _boxes(rng, rng.choice((1, 5, 30, 200)))
    grid = BoxGrid(boxes)
    for _ in range(150):
        l, t = rng.uniform(-400, 2600), rng.uniform(-400, 2600)
        r, b = l + rng.choice((0.0, 5.0, 80.0, 300.0, 4000.0)) * rng.random(), t + rng.choice((0.0, 5.0, 80.0, 300.0, 4000.0)) * rng.random()
        assert grid.overlapping(l, t, r, b) == [x for x in boxes if _overlaps(x, l, t, r, b)]
        assert grid.count((l, t, r, b)) == sum(1 for x in boxes if _overlaps(x, l, t, r, b))


def test_boxgrid_edges_that_only_touch_do_not_count():
    far = [(5000.0 + 200 * i, 5000.0, 5100.0 + 200 * i, 5100.0) for i in range(40)]          # enough boxes that a small query goes through the cells, not the direct scan
    grid = BoxGrid([(0.0, 0.0, 100.0, 100.0), *far])
    assert grid.overlapping(100.0, 0.0, 200.0, 100.0) == []          # touching on the right edge
    assert grid.overlapping(0.0, 100.0, 100.0, 200.0) == []          # touching on the bottom edge
    assert grid.overlapping(-100.0, 0.0, 0.0, 100.0) == []           # touching on the left edge
    assert grid.overlapping(0.0, -100.0, 100.0, 0.0) == []           # touching on the top edge
    assert grid.overlapping(99.9, 99.9, 200.0, 200.0) == [(0.0, 0.0, 100.0, 100.0)]


def test_boxgrid_grows_box_by_box_and_keeps_inverted_boxes():
    grid = BoxGrid()
    seen: list = []
    rng = random.Random(7)
    for box in _boxes(rng, 40):
        grid.add(box)
        seen.append(box)
        assert grid.overlapping(-1e4, -1e4, 1e4, 1e4) == seen
    inverted = (500.0, 500.0, 450.0, 430.0)                          # x1 < x0 and y1 < y0: the plain loop never matches it, and neither does the grid
    both = BoxGrid([inverted])
    assert both.overlapping(440.0, 420.0, 510.0, 510.0) == [x for x in [inverted] if _overlaps(x, 440.0, 420.0, 510.0, 510.0)]


@pytest.mark.parametrize("seed", SEEDS)
def test_near_matches_plain_scan_for_small_and_large_lists(seed):
    rng = random.Random(100 + seed)
    for n in (0, 3, MIN_BOXES - 1, MIN_BOXES, MIN_BOXES + 1, 150):
        boxes = _boxes(rng, n)
        for _ in range(60):
            l, t = rng.uniform(-300, 2500), rng.uniform(-300, 2500)
            r, b = l + rng.random() * 600, t + rng.random() * 600
            assert near(boxes, l, t, r, b) == [x for x in boxes if _overlaps(x, l, t, r, b)]


def test_near_notices_a_list_that_was_changed_after_the_grid_was_built():
    boxes = _boxes(random.Random(3), 60)
    assert near(boxes, 0, 0, 3000, 3000) == [x for x in boxes if _overlaps(x, 0, 0, 3000, 3000)]
    boxes.append((10.0, 10.0, 50.0, 50.0))
    assert near(boxes, 0, 0, 60, 60) == [x for x in boxes if _overlaps(x, 0, 0, 60, 60)]
    boxes[0] = (11.0, 11.0, 40.0, 40.0)
    assert near(boxes, 0, 0, 60, 60) == [x for x in boxes if _overlaps(x, 0, 0, 60, 60)]
    other = _boxes(random.Random(4), 60)                             # a different list is never answered from the first list's grid
    assert near(other, 0, 0, 3000, 3000) == [x for x in other if _overlaps(x, 0, 0, 3000, 3000)]


def _steps(p, q):
    return max(int(max(abs(q[0] - p[0]), abs(q[1] - p[1])) // 12), 2)


def _hits_plain(p, q, obstacles) -> bool:
    for i in range(1, _steps(p, q)):
        x, y = p[0] + (q[0] - p[0]) * i / _steps(p, q), p[1] + (q[1] - p[1]) * i / _steps(p, q)
        if any(x0 < x < x1 and y0 < y < y1 for x0, y0, x1, y1 in obstacles):
            return True
    return False


def _hit_boxes_plain(p, q, obstacles):
    hit = set()
    for i in range(1, _steps(p, q)):
        x, y = p[0] + (q[0] - p[0]) * i / _steps(p, q), p[1] + (q[1] - p[1]) * i / _steps(p, q)
        hit.update(b for b in obstacles if b[0] < x < b[2] and b[1] < y < b[3])
    return hit


@pytest.mark.parametrize("seed", SEEDS)
def test_scene_segment_tests_match_the_plain_sampling_loops(seed):
    rng = random.Random(200 + seed)
    for n in (4, 40, 160):
        obstacles = _boxes(rng, n)
        for _ in range(80):
            p = (rng.uniform(-200, 2500), rng.uniform(-200, 2500))
            q = (p[0] + rng.uniform(-900, 900), p[1] + rng.uniform(-900, 900)) if rng.random() < 0.8 else (p[0], p[1] + rng.uniform(-900, 900))
            assert scene._hits(p, q, obstacles) is _hits_plain(p, q, obstacles)
            assert scene._hit_boxes(p, q, obstacles) == _hit_boxes_plain(p, q, obstacles)


@pytest.mark.parametrize("seed", SEEDS)
def test_label_hit_count_through_a_grid_equals_the_plain_count(seed):
    rng = random.Random(300 + seed)
    others = _boxes(rng, 90)
    grid = BoxGrid(others)
    for _ in range(100):
        x, y = rng.uniform(-200, 2500), rng.uniform(-200, 2500)
        rect = (x, y, x + rng.uniform(10, 140), y + rng.uniform(10, 30))
        assert labelplace._hit(rect, grid) == labelplace._hit(rect, others)


def _segments(rng, owners):
    lines = {}
    for owner in range(owners):
        x, y = rng.uniform(0, 2000), rng.uniform(0, 2000)
        pts = [(x, y)]
        for _ in range(rng.randint(1, 4)):
            x += rng.choice((0.0, 1.0, -1.0)) * rng.uniform(0, 500)         # horizontal, vertical and slanted legs
            y += rng.choice((0.0, 1.0, -1.0)) * rng.uniform(0, 500)
            pts.append((x, y))
        lines[owner] = pts
    return lines


@pytest.mark.parametrize("seed", SEEDS)
def test_line_index_crossed_equals_clipping_every_segment(seed):
    rng = random.Random(400 + seed)
    lines = _segments(rng, 70)
    index = labelplace._LineIndex()
    for owner, pts in lines.items():
        index.add(owner, pts)
    for _ in range(150):
        x, y = rng.uniform(-100, 2300), rng.uniform(-100, 2300)
        rect = (x, y, x + rng.uniform(10, 160), y + rng.uniform(10, 40))
        own = rng.randrange(70)
        plain = {o for o, pts in lines.items() if o != own and any(labelplace._clips(rect, a, b) for a, b in zip(pts, pts[1:]))}
        assert index.crossed(rect, own) == len(plain)
        assert index.crossed(rect, own, cap=2) == min(len(plain), 2)


def test_line_index_label_corner_exactly_on_a_line_still_counts():
    index = labelplace._LineIndex()
    index.add(1, [(0.0, 0.0), (200.0, 200.0)])
    assert index.crossed((100.0, 0.0, 200.0, 100.0), own=0) == 1       # the corner (100, 100) lies on the line
    assert index.crossed((101.0, 0.0, 200.0, 99.0), own=0) == 0        # clear of it
    assert index.crossed((100.0, 0.0, 200.0, 100.0), own=1) == 0       # its own line does not count


def _crossings_plain(points, page, centres, ends):
    from features.topology.layoutscore import crosses
    total = 0
    for index, conn in enumerate(page.connections):
        if conn.a in ends or conn.b in ends or conn.a not in centres or conn.b not in centres:
            continue
        line = [centres[conn.a], *(page.routes.get(index) or []), centres[conn.b]]
        for c, d in zip(line, line[1:]):
            for a, b in zip(points, points[1:]):
                if crosses((a[0], a[1], b[0], b[1]), (c[0], c[1], d[0], d[1])):
                    total += 1
    return total


@pytest.mark.parametrize("seed", SEEDS)
def test_crossings_of_with_box_pre_rejection_equals_testing_every_pair(seed):
    rng = random.Random(500 + seed)
    names = [f"N{i}" for i in range(25)]
    centres = {n: (rng.uniform(0, 1500), rng.uniform(0, 1500)) for n in names}
    conns, routes = [], {}
    for i in range(60):
        a, b = rng.sample(names, 2)
        conns.append(types.SimpleNamespace(a=a, b=b))
        if rng.random() < 0.4:
            routes[i] = [(rng.uniform(0, 1500), rng.uniform(0, 1500)) for _ in range(rng.randint(1, 3))]
    page = types.SimpleNamespace(connections=conns, routes=routes)
    for _ in range(40):
        points = [(rng.uniform(-50, 1600), rng.uniform(-50, 1600)) for _ in range(rng.randint(2, 5))]
        ends = set(rng.sample(names, rng.randint(0, 3)))
        assert scene._crossings_of(points, page, centres, ends) == _crossings_plain(points, page, centres, ends)


def test_grid_keeps_the_engine_from_growing_with_the_square_of_the_boxes():
    """Not a benchmark: 6000 segment questions against 3000 boxes would take seconds with the plain loop and well under a second with the grid."""
    rng = random.Random(9)
    obstacles = _boxes(rng, 3000, span=30000.0)
    started = time.perf_counter()
    for _ in range(6000):
        p = (rng.uniform(0, 30000), rng.uniform(0, 30000))
        scene._hits(p, (p[0] + 400, p[1] + 250), obstacles)
    assert time.perf_counter() - started < 3.0
