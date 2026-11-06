"""The label and line-routing shortcuts of the quality sweep must give exactly the answers of the plain loops they replace."""
from __future__ import annotations

import random

from features.topology import labelplace, scene


def _plain_hits(p, q, obstacles):
    length = max(abs(q[0] - p[0]), abs(q[1] - p[1]))
    steps = max(int(length // 12), 2)
    for i in range(1, steps):
        x = p[0] + (q[0] - p[0]) * i / steps
        y = p[1] + (q[1] - p[1]) * i / steps
        if any(x0 < x < x1 and y0 < y < y1 for x0, y0, x1, y1 in obstacles):
            return True
    return False


def test_hits_prefilter_matches_the_plain_loop():
    rng = random.Random(7)
    for _ in range(400):
        boxes = [(x, y, x + rng.uniform(10, 90), y + rng.uniform(10, 60)) for x, y in ((rng.uniform(0, 600), rng.uniform(0, 400)) for _ in range(rng.randint(0, 12)))]
        p, q = (rng.uniform(0, 600), rng.uniform(0, 400)), (rng.uniform(0, 600), rng.uniform(0, 400))
        assert scene._hits(p, q, boxes) == _plain_hits(p, q, boxes)


def test_crossed_counts_other_lines_and_stops_at_the_cap():
    index = labelplace._LineIndex()
    for owner in range(6):
        index.add(owner, [(0.0, 10.0 + owner), (200.0, 10.0 + owner)])           # six horizontal lines through the label
    index.add(9, [(0.0, 500.0), (200.0, 500.0)])                                  # one far away
    rect = (50.0, 0.0, 90.0, 30.0)
    assert index.crossed(rect, own=0) == 5                                         # its own line is not counted
    assert index.crossed(rect, own=99) == 6
    assert index.crossed(rect, own=99, cap=3) == 3                                 # at least the cap is all the caller needs
    assert index.crossed((50.0, 400.0, 90.0, 430.0), own=99) == 0
