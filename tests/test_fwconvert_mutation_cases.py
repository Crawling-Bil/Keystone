"""Regression cases found by mutation testing of the FortiGate <-> PAN-OS converter.

A mutation run (one operator flipped at a time in ``fwconvert``: ``and`` to ``or``, ``==`` to ``!=``, ``in`` to ``not in`` ...) leaves some changes that no
golden file notices.  Each case here is a small edit of a synthetic fixture (delete a line or a block, swap a word or a number) that one of those changes
turns into a different answer.  The case stores only the edit and the *difference* between the converted fixture and the converted edit, so a failure reads
as "this line is no longer written" instead of a hash.

If the converter's output is meant to change, run ``python tests/test_fwconvert_mutation_cases.py --update`` and read the diff of the JSON file before accepting it.
"""
from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "firewall"
CASES_FILE = FIXTURES / "golden" / "mutation_cases.json"
SOURCE_VENDOR = {"fortigate": ("fwconvert_fortigate_synthetic.conf", "fortigate_synthetic_7.2.conf", "fortigate_vdom_edge_synthetic.conf", "fortigate_multivdom_synthetic.conf",
                               "fortigate_hardened_synthetic.conf")}


def _vendor(base: str) -> tuple[str, str]:
    return ("fortigate", "panos") if base in SOURCE_VENDOR["fortigate"] else ("panos", "fortigate")


def _edit(base: str, ops: list[list]) -> str:
    lines = (FIXTURES / base).read_text(encoding="utf-8").split("\n")
    for op in ops:
        if op[0] == "del":
            for index in range(op[1], min(op[2], len(lines) - 1) + 1):
                lines[index] = None
        elif op[0] == "ins":
            index = op[1]
            if index < len(lines):
                lines[index] = (lines[index] if lines[index] is not None else "") + "\n" + op[2]
        elif op[0] == "rep":
            index, old, new = op[1], op[2], op[3]
            if index < len(lines) and lines[index] is not None and old in lines[index]:
                lines[index] = lines[index].replace(old, new, 1)
    return "\n".join(line for line in lines if line is not None)


def _convert(text: str, base: str, opts: dict):
    from features.configuration_studio.converter_engine.fwconvert import convert
    source, target = _vendor(base)
    result = convert(text, source, target, layers=list(opts["layers"]) if "layers" in opts else None, interface_map={},
                     disable_widened=opts.get("disable_widened", True), vdom=opts.get("vdom", ""))
    assert result.ok, result.error
    return result.output, result.report.to_csv()


def _diff(before: str, after: str) -> list[str]:
    return [line for line in difflib.unified_diff(before.split("\n"), after.split("\n"), lineterm="", n=0) if not line.startswith(("---", "+++", "@@"))]


def compute(case: dict) -> dict:
    """The difference between the converted fixture and the converted edit of it."""
    base_text = (FIXTURES / case["base"]).read_text(encoding="utf-8")
    reference = _convert(base_text, case["base"], {} if not case["ops"] else case["opts"])
    edited = _convert(_edit(case["base"], case["ops"]), case["base"], case["opts"])
    return {"output": _diff(reference[0], edited[0]), "report": _diff(reference[1], edited[1])}


def _load() -> list[dict]:
    return json.loads(CASES_FILE.read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", _load(), ids=lambda case: case["id"])
def test_edit_of_a_fixture_changes_the_conversion_as_recorded(case):
    got = compute(case)
    assert got["output"] == case["expect"]["output"], "the converted configuration changed"
    assert got["report"] == case["expect"]["report"], "the conversion report changed"


if __name__ == "__main__":
    if "--update" in sys.argv:
        sys.path.insert(0, str(ROOT.parent))
        cases = _load()
        for case in cases:
            case["expect"] = compute(case)
        CASES_FILE.write_text(json.dumps(cases, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"updated {len(cases)} cases")
