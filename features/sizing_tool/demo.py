"""Demo captures of the Sizing Tool.

The five scenarios of the Topology Builder are reused as they are (``features/topology/demo``): the data center before and after a change window, the
firewall and F5 site, the head quarter with six branches, and the same company with a disaster recovery site.  Those captures were written for
drawing a topology, so they hold few licences, optics or access points; the sixth set, ``campus``, is written for sizing: a campus site whose
captures carry the inventory, licence, transceiver and PoE output, a controller with access points from two vendors, and one box of every
other family.  Nothing in any set is a customer capture (invented names, ``example.test``, documentation address ranges).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from features.topology import demo as topology_demo

DEMO_DIR = Path(__file__).resolve().parent / "demo"
OWN_SETS = (
    {"id": "campus", "label": "Campus with wireless and licences",
     "description": "A campus site written for sizing: Catalyst 9400 core with line cards, power supplies and optics, a stack with PoE, Huawei and Aruba switches, an ISR router, "
                    "a Palo Alto and a FortiGate firewall with licences, an F5 BIG-IP with provisioned modules, and two wireless controllers (Cisco C9800 and Huawei AC) with their access points."},
)


def _own_folder(set_id: str) -> Path | None:
    for item in OWN_SETS:
        if item["id"] == set_id:
            folder = DEMO_DIR / set_id
            return folder if folder.is_dir() else None
    return None


def list_sets() -> list[dict[str, Any]]:
    """Every set with its capture count: the topology sets first (same labels as the Topology Builder), then this tool's own."""
    out = []
    for item in topology_demo.list_sets():
        files = [f for f in item["files"] if f["name"].endswith(".txt")]
        out.append({"id": f"topology:{item['id']}", "label": item["label"], "description": item["description"], "origin": "Topology Builder", "files": files})
    for item in OWN_SETS:
        folder = _own_folder(item["id"])
        files = sorted(folder.glob("*.txt")) if folder else []
        out.append({**item, "origin": "Sizing Tool", "files": [{"name": f.name, "size": f.stat().st_size} for f in files]})
    return out


def read_set(set_id: str) -> list[tuple[str, bytes]]:
    """The captures of one set as ``(name, bytes)``; an unknown id gives an empty list."""
    if set_id.startswith("topology:"):
        inner = set_id.split(":", 1)[1]
        listed = next((s for s in topology_demo.list_sets() if s["id"] == inner), None)
        out = []
        for entry in (listed or {}).get("files", []):
            if entry["name"].endswith(".txt"):
                data = topology_demo.read_file(inner, entry["name"])
                if data is not None:
                    out.append((entry["name"], data))
        return out
    folder = _own_folder(set_id)
    if folder is None:
        return []
    return [(f.name, f.read_bytes()) for f in sorted(folder.glob("*.txt")) if f.is_file() and not f.is_symlink()]
