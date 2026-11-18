"""The demo captures are made by ``tools/demo_generator``: regenerating them gives the shipped files byte for byte, and the hand-placed pages of the layout files stay as written."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GEN = ROOT / "tools" / "demo_generator"
DEMO = ROOT / "features" / "topology" / "demo"


def _run(script: str, *args: str) -> None:
    done = subprocess.run([sys.executable, str(GEN / script), *args], cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr[-600:]


def _lf(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")           # a Windows checkout may hold CRLF


def _pages(path: Path) -> dict[str, dict[str, tuple[str, str]]]:
    text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    out: dict[str, dict[str, tuple[str, str]]] = {}
    for name, body in re.findall(r'<diagram name="([^"]+)".*?>(.*?)</diagram>', text, re.S):
        out[name] = {key: (x, y) for key, x, y in re.findall(r'node_key="([^"]+)".*?<mxGeometry x="([^"]+)" y="([^"]+)"', body)}
    return out


@pytest.mark.parametrize("script,set_id,count", [("gen.py", "multisite", 44), ("gen_dcdrc.py", "dcdrc", 64)])
def test_regenerating_a_demo_set_gives_the_shipped_captures(tmp_path, script, set_id, count):
    out = tmp_path / "captures"
    _run(script, str(out))
    made = sorted(p.name for p in out.glob("*.txt"))
    shipped = sorted(p.name for p in (DEMO / set_id).glob("*.txt"))
    assert len(made) == count and made == shipped
    assert [name for name in made if _lf(out / name) != _lf(DEMO / set_id / name)] == []


@pytest.mark.parametrize("script,set_id,hand", [("layout_multisite.py", "multisite", ["HQ"]), ("layout_dcdrc.py", "dcdrc", ["HQ-DC", "DRC"])])
def test_the_hand_placed_pages_of_the_layout_file_stay_as_written(tmp_path, script, set_id, hand):
    captures = tmp_path / "captures"
    _run("gen.py" if set_id == "multisite" else "gen_dcdrc.py", str(captures))
    layout = tmp_path / "layout.drawio"
    _run(script, str(captures), str(layout))
    made, shipped = _pages(layout), _pages(DEMO / set_id / "layout.drawio")
    assert sorted(made) == sorted(shipped)
    for page in hand:
        assert made[page] == shipped[page], page
