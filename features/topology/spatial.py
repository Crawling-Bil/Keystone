"""A uniform grid over rectangles, so "which boxes lie under this segment or label" looks at a few cells, not at every box.

The topology engine asks that question hundreds of thousands of times for a 100-device estate (a routed line against every device
box, a label against every other label), and the plain loops made the work grow with the square of the device count.  The grid
answers EXACTLY what the loop answered: it only narrows the candidates, then applies the same strict overlap test, and it returns
the boxes in their original order.  ``tests/test_topology_spatial.py`` compares it with the plain loop on random cases.
"""
from __future__ import annotations

import threading

Box = tuple[float, float, float, float]

CELL = 120.0                 # px; about the size of a device icon with its caption
MIN_BOXES = 24               # fewer boxes than this are scanned directly: a grid would cost more than it saves


class BoxGrid:
    """Rectangles ``(x0, y0, x1, y1)`` in a grid of ``CELL``-px cells; boxes can be added one by one."""

    def __init__(self, boxes: list[Box] | tuple[Box, ...] = (), cell: float = CELL) -> None:
        self.cell = cell
        self.boxes: list[Box] = []
        self.cells: dict[tuple[int, int], list[int]] = {}
        for box in boxes:
            self.add(box)

    def add(self, box: Box) -> None:
        index = len(self.boxes)
        self.boxes.append(box)
        cell = self.cell
        low_x, high_x = (box[0], box[2]) if box[0] <= box[2] else (box[2], box[0])          # an inverted box is still found, as the plain loop finds it
        low_y, high_y = (box[1], box[3]) if box[1] <= box[3] else (box[3], box[1])
        for cx in range(int(low_x // cell), int(high_x // cell) + 1):
            for cy in range(int(low_y // cell), int(high_y // cell) + 1):
                self.cells.setdefault((cx, cy), []).append(index)

    def overlapping(self, left: float, top: float, right: float, bottom: float) -> list[Box]:
        """The boxes that overlap the rectangle (left, top, right, bottom) strictly (touching edges do not count), in the order they were added."""
        cell = self.cell
        first_x, last_x = int(left // cell), int(right // cell)
        first_y, last_y = int(top // cell), int(bottom // cell)
        boxes = self.boxes
        if (last_x - first_x + 1) * (last_y - first_y + 1) > len(boxes):                    # a huge query: the direct scan is cheaper
            return [b for b in boxes if b[0] < right and b[2] > left and b[1] < bottom and b[3] > top]
        found: set[int] = set()
        cells = self.cells
        for cx in range(first_x, last_x + 1):
            for cy in range(first_y, last_y + 1):
                members = cells.get((cx, cy))
                if members:
                    found.update(members)
        out = []
        for index in sorted(found):
            b = boxes[index]
            if b[0] < right and b[2] > left and b[1] < bottom and b[3] > top:
                out.append(b)
        return out

    def count(self, rect: Box) -> int:
        """How many boxes overlap ``rect`` strictly."""
        return len(self.overlapping(rect[0], rect[1], rect[2], rect[3]))


_local = threading.local()


def near(obstacles: list[Box], left: float, top: float, right: float, bottom: float) -> list[Box]:
    """``[b for b in obstacles if overlaps]`` through a grid that is built once per obstacle list and kept for the next call with the same list.

    The callers build ``obstacles`` once for a line and ask about it dozens of times; the list is never changed in between.  A list that
    was changed anyway (another length, another first or last box) is noticed and the grid is rebuilt.
    """
    if len(obstacles) < MIN_BOXES:
        return [b for b in obstacles if b[0] < right and b[2] > left and b[1] < bottom and b[3] > top]
    held = getattr(_local, "held", None)
    if held is None or held[0] is not obstacles or len(held[1].boxes) != len(obstacles) or held[1].boxes[0] is not obstacles[0] or held[1].boxes[-1] is not obstacles[-1]:
        held = (obstacles, BoxGrid(obstacles))
        _local.held = held
    return held[1].overlapping(left, top, right, bottom)
