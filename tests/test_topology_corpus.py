"""The layout corpus: the same numbers for every topology, so an engine change is judged on many networks.  Demo sets (invented) always; stored packs when KEYSTONE_PACKS names a folder."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from features.topology import corpus

ROOT = Path(__file__).resolve().parent.parent
BASELINE = Path(__file__).resolve().parent / "data" / "layout_baseline_demos.json"


def _row(**over):
    return {"cross": 10, "thru": 0, "ov": 0, "crowd": 0, "title": 0, "n": 20, "pos": "aa", **over}


def test_compare_sorts_pages_into_worse_better_moved_and_missing():
    before = {"a": _row(), "b": _row(), "c": _row(), "d": _row(), "e": _row(), "gone": _row()}
    after = {"a": _row(cross=10 + corpus.WORSE_CROSS + 1), "b": _row(cross=4), "c": _row(pos="bb"), "d": _row(thru=1), "e": _row()}
    result = corpus.compare(before, after)
    assert [t.split()[0] for t in result["worse"]] == ["a", "d"]
    assert [t.split()[0] for t in result["better"]] == ["b"]
    assert result["moved"] == ["c"] and result["missing"] == ["gone"]


def test_a_new_page_is_not_a_regression():
    assert corpus.compare({"a": _row()}, {"a": _row(), "new": _row(cross=500)})["worse"] == []


def test_an_error_is_worse_only_when_it_is_new():
    assert corpus.compare({"a": _row()}, {"a": {"err": "KeyError"}})["worse"]
    assert not corpus.compare({"a": {"err": "KeyError"}}, {"a": {"err": "KeyError"}})["worse"]


def test_totals_add_up_the_pages_that_could_be_scored():
    rows = {"a": _row(), "b": _row(cross=5), "c": {"err": "KeyError"}}
    assert corpus.totals(rows) == {"pages": 3, "cross": 15, "thru": 0, "ov": 0, "crowd": 0, "title": 0}


def test_demo_rows_are_named_and_scored():
    rows = corpus.demo_rows(("before",))
    assert rows and all(key.startswith("demo-before|") for key in rows)
    assert all({"cross", "thru", "ov", "n", "pos"} <= set(r) for r in rows.values())


def test_the_numbers_do_not_depend_on_the_order_of_a_python_set():
    """Two runs with another hash seed give the same positions (a tie between two clouds once depended on it)."""
    code = "import json,sys; from features.topology import corpus; print(json.dumps(corpus.demo_rows(('dcdrc',)), sort_keys=True))"
    out = []
    for seed in ("1", "3"):                              # these two gave different positions before the tie was fixed
        run = subprocess.run([sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, env={**os.environ, "PYTHONHASHSEED": seed, "NES_SECRET_KEY": "x"}, timeout=300)
        assert run.returncode == 0, run.stderr[-400:]
        out.append(run.stdout.strip().splitlines()[-1])
    assert out[0] == out[1]


def test_no_demo_page_is_worse_than_the_stored_baseline():
    """``tests/data/layout_baseline_demos.json`` holds numbers only (invented demo names).  Rewrite it on purpose, after an engine change that is better:
    python -m features.topology.corpus --write tests/data/layout_baseline_demos.json"""
    result = corpus.compare(json.loads(BASELINE.read_text(encoding="utf-8")), corpus.demo_rows())
    assert result["worse"] == [] and result["missing"] == []


@pytest.mark.skipif(not os.environ.get("KEYSTONE_PACKS"), reason="set KEYSTONE_PACKS to a folder of stored packs to run the real-network corpus")
def test_no_stored_pack_page_is_worse_than_its_baseline():
    baseline = os.environ.get("KEYSTONE_PACKS_BASELINE")
    if not baseline:
        pytest.skip("set KEYSTONE_PACKS_BASELINE to the result of an earlier run (python -m features.topology.corpus --packs DIR --write FILE)")
    result = corpus.compare(json.loads(Path(baseline).read_text(encoding="utf-8")), corpus.pack_rows(os.environ["KEYSTONE_PACKS"]))
    assert result["worse"] == [], result["worse"][:10]
