"""Layout corpus: the same numbers for every topology we can build, so an engine change is judged on many networks, not on the one that was open.

Per page: ``cross`` (line crossings), ``thru`` (lines through an icon), ``ov`` (px of different cables running on one line outside the icons), ``crowd`` (px of lines 2.5 to 7 px
apart), ``title`` (frame titles with a line through them), ``n`` (icons) and ``pos`` (a short hash of every icon position, to see that a page did not move).  The five demo sets are
always in; a folder of stored packs (``topology.json`` of a run) or of capture folders can be added with ``--packs``.  Nothing about a customer is kept in a result: pages and packs
are named by a short hash, so a result can be written to a file, compared and shared.

    python -m features.topology.corpus --write baseline.json                  # the demo sets
    python -m features.topology.corpus --packs D:/packs --write now.json      # plus a folder of stored packs
    python -m features.topology.corpus --packs D:/packs --baseline before.json # list the pages that got worse
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import sys
from typing import Any

from . import demo, layoutscore as LS, service as S
from .state import read_state

NW = NH = 76
def clip_out(seg, rects):
    """cut the parts of seg inside any rect (icons of its own ends): returns list of segments outside"""
    pts = [0.0, 1.0]
    x0, y0, x1, y1 = seg
    for (l, t, r, b) in rects:
        dx, dy = x1 - x0, y1 - y0
        t0, t1 = 0.0, 1.0; ok = True
        for p, q in ((-dx, x0 - l), (dx, r - x0), (-dy, y0 - t), (dy, b - y0)):
            if p == 0:
                if q < 0: ok = False; break
                continue
            tt = q / p
            if p < 0:
                if tt > t1: ok = False; break
                t0 = max(t0, tt)
            else:
                if tt < t0: ok = False; break
                t1 = min(t1, tt)
        if ok and t1 > t0: pts += [t0, t1]
    pts = sorted(set(pts)); out = []
    for a, b in zip(pts, pts[1:]):
        m = (a + b) / 2; mx, my = x0 + (x1 - x0) * m, y0 + (y1 - y0) * m
        if not any(l < mx < r and t < my < b2 for (l, t, r, b2) in rects):
            out.append((x0 + (x1 - x0) * a, y0 + (y1 - y0) * a, x0 + (x1 - x0) * b, y0 + (y1 - y0) * b))
    return out
def overlay(page, eps=2.5, minlen=8.0, lo_gap=0.0, hi_gap=None):
    centre = {k: (p.x + NW / 2, p.y + NH / 2) for k, p in page.nodes.items()}
    lines = []
    for i, c in enumerate(page.connections):
        if c.a in centre and c.b in centre and c.a != c.b:
            pts = LS._polyline(page, c, i, centre)
            rects = [(centre[k][0] - NW / 2 + 2, centre[k][1] - NH / 2 + 2, centre[k][0] + NW / 2 - 2, centre[k][1] + NH / 2 - 2) for k in (c.a, c.b)]
            segs = []
            for (a, b) in zip(pts, pts[1:]):
                segs += clip_out((a[0], a[1], b[0], b[1]), rects)
            lines.append((i, segs))
    total = 0.0; pairs = 0
    grid = {}
    for li, (i, segs) in enumerate(lines):
        for si, s in enumerate(segs):
            for cx in range(int(min(s[0], s[2]) // 200), int(max(s[0], s[2]) // 200) + 1):
                for cy in range(int(min(s[1], s[3]) // 200), int(max(s[1], s[3]) // 200) + 1):
                    grid.setdefault((cx, cy), []).append((li, si))
    seen = set()
    for mem in grid.values():
        for ai, a in enumerate(mem):
            for b in mem[ai + 1:]:
                if a[0] == b[0] or (a, b) in seen: continue
                seen.add((a, b))
                ca, cb = page.connections[lines[a[0]][0]], page.connections[lines[b[0]][0]]
                if lines[a[0]][0] in page.bus and lines[b[0]][0] in page.bus and {ca.a, ca.b} & {cb.a, cb.b}:
                    continue    # the lines of one bus share their run on purpose
                p = lines[a[0]][1][a[1]]; q = lines[b[0]][1][b[1]]
                lp = math.hypot(p[2] - p[0], p[3] - p[1]); lq = math.hypot(q[2] - q[0], q[3] - q[1])
                if lp < minlen or lq < minlen: continue
                ux, uy = (p[2] - p[0]) / lp, (p[3] - p[1]) / lp
                vx, vy = (q[2] - q[0]) / lq, (q[3] - q[1]) / lq
                if abs(ux * vy - uy * vx) > 0.03: continue
                d1 = abs((q[0] - p[0]) * uy - (q[1] - p[1]) * ux); d2 = abs((q[2] - p[0]) * uy - (q[3] - p[1]) * ux)
                dmax = max(d1, d2); dmin = min(d1, d2)
                if hi_gap is None:
                    if dmax > eps: continue
                else:
                    if not (lo_gap < dmin and dmax <= hi_gap): continue
                t1 = (q[0] - p[0]) * ux + (q[1] - p[1]) * uy; t2 = (q[2] - p[0]) * ux + (q[3] - p[1]) * uy
                lo, hi = max(0, min(t1, t2)), min(lp, max(t1, t2))
                if hi - lo >= minlen: total += hi - lo; pairs += 1
    return round(total), pairs
def title_hits(page):
    centre = {k: (p.x + NW / 2, p.y + NH / 2) for k, p in page.nodes.items()}
    segs = []
    for i, c in enumerate(page.connections):
        if c.a in centre and c.b in centre and c.a != c.b:
            pts = LS._polyline(page, c, i, centre)
            segs += [(a[0], a[1], b[0], b[1]) for a, b in zip(pts, pts[1:])]
    hits = 0
    for title, x, y, w, h in page.end_boxes:
        spot = None
        try:
            from features.topology import titles
            spot = titles.end_title_spot(page, (title, x, y, w, h))
        except Exception:
            pass
        tx, ty, anchor = (x + spot, y + 20, "start") if spot is not None else (x + 10, y + 20, "start")
        tw = 6.9 * len(title) + 4
        rect = (tx - tw, ty - 13, tx, ty + 4) if anchor == "end" else (tx, ty - 13, tx + tw, ty + 4)
        if any(LS.runs_through(sg, rect) for sg in segs): hits += 1
    return hits
def row(page):
    ov, pr = overlay(page)
    crowd, cp = overlay(page, minlen=20.0, lo_gap=2.5, hi_gap=7.0)
    sc = LS.score_page(page)
    return {"ov": ov, "pairs": pr, "crowd": crowd, "cpairs": cp, "title": title_hits(page), "cross": sc["crossings"], "thru": sc["through"], "n": len(page.nodes)}

BUILD = dict(group="auto", view="all", collapse_endpoints=False, include_hosts=False, group_endpoints=True, collapse_aps=False)
PAGE_GROUPS = ("pages", "l3_pages", "l3_extra_pages")
WORSE_CROSS = 0           # a page is worse when it has more crossings or lines through icons than before, or this many px more overlay
WORSE_OVERLAY = 200


def _short(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]


def positions(page) -> str:
    return _short(json.dumps(sorted((k, round(n.x), round(n.y)) for k, n in page.nodes.items())))


def measure_build(label: str, built: dict, named: bool = False) -> dict[str, dict[str, Any]]:
    """The rows of one build; ``named`` keeps the page names (the demo sets are invented), otherwise they are hashed."""
    out: dict[str, dict[str, Any]] = {}
    for group in PAGE_GROUPS:
        for page in built.get(group) or []:
            key = f"{label}|{group}|{page.name if named else _short(page.name)}"
            try:
                out[key] = {**row(page), "pos": positions(page)}
            except Exception as error:                       # a page that cannot be scored is reported, not fatal
                out[key] = {"err": type(error).__name__}
    return out


def demo_rows(sets: tuple[str, ...] = ()) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for item in demo.list_sets():
        if sets and item["id"] not in sets:
            continue
        files = [(f["name"], demo.read_file(item["id"], f["name"]).decode("utf-8")) for f in item["files"]]
        rows.update(measure_build("demo-" + item["id"], S.build_topology(files, **{**BUILD, "group": item.get("group", "none")}), named=True))
    return rows


def pack_rows(root: str) -> dict[str, dict[str, Any]]:
    """Every stored pack (a ``topology.json``, the same file twice counts once) and every folder of ``.txt`` captures under ``root``."""
    rows: dict[str, dict[str, Any]] = {}
    seen: set[str] = set()
    for path in sorted(glob.glob(os.path.join(root, "**", "topology.json"), recursive=True)):
        raw = open(path, "rb").read()
        digest = hashlib.md5(raw).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        rows.update(measure_build("pack-" + digest[:8], S.build_topology([], devices=read_state(raw), **BUILD)))
    for folder in sorted({os.path.dirname(p) for p in glob.glob(os.path.join(root, "**", "*.txt"), recursive=True)}):
        files = [(os.path.basename(p), open(p, encoding="utf-8", errors="replace").read()) for p in sorted(glob.glob(os.path.join(folder, "*.txt")))]
        if len(files) < 2:
            continue
        digest = hashlib.md5("".join(t for _, t in files).encode("utf-8")).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        rows.update(measure_build("caps-" + digest[:8], S.build_topology(files, **BUILD)))
    return rows


def compare(before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
    """Pages in both results, sorted into worse (more crossings or lines through icons, or clearly more overlay), better, moved (same score, other positions) and missing."""
    worse, better, moved, missing = [], [], [], []
    for key, old in before.items():
        new = after.get(key)
        if new is None:
            missing.append(key)
            continue
        if "err" in old or "err" in new:
            if old.get("err") != new.get("err"):
                worse.append(f"{key} (error {old.get('err')} -> {new.get('err')})")
            continue
        delta = {m: new[m] - old[m] for m in ("cross", "thru", "ov", "crowd", "title")}
        text = f"{key} n={new['n']} " + " ".join(f"{m}{d:+d}" for m, d in delta.items() if d)
        if delta["cross"] > WORSE_CROSS or delta["thru"] > 0 or delta["ov"] > WORSE_OVERLAY:
            worse.append(text)
        elif any(delta.values()):
            better.append(text)
        elif old.get("pos") != new.get("pos"):
            moved.append(key)
    return {"worse": worse, "better": better, "moved": moved, "missing": missing}


def totals(rows: dict[str, dict[str, Any]]) -> dict[str, int]:
    good = [r for r in rows.values() if "err" not in r]
    return {"pages": len(rows), **{m: sum(r[m] for r in good) for m in ("cross", "thru", "ov", "crowd", "title")}}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score the layout of the demo sets and of a folder of stored packs.")
    parser.add_argument("--packs", help="folder with stored packs (topology.json) or capture folders (.txt)")
    parser.add_argument("--write", help="write the result to this file")
    parser.add_argument("--baseline", help="compare with this earlier result and list the pages that got worse")
    args = parser.parse_args(argv)
    rows = demo_rows()
    if args.packs:
        rows.update(pack_rows(args.packs))
    print(json.dumps(totals(rows)))
    if args.write:
        with open(args.write, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, sort_keys=True, indent=0)
    if args.baseline:
        with open(args.baseline, encoding="utf-8") as handle:
            result = compare(json.load(handle), rows)
        for name in ("worse", "better", "moved", "missing"):
            print(f"{name}: {len(result[name])}")
            for line in result[name][:40]:
                print("   ", line)
        return 1 if result["worse"] else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
