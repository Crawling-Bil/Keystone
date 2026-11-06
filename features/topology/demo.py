"""Demo captures for the Topology Builder's "Load demo data" button.

Four sets of invented captures (documentation names, ``example.test``).  The first three are a small data center (10.20.0.0/16):

* ``before``: two NX-OS core switches in a vPC pair, four IOS XE access switches dual-homed to both, one firewall that only the LLDP table mentions;
* ``after``:  the same network after a change window: a fifth access switch, one access uplink pulled (ACC3 is now single-homed: TOPO-035) and one management address changed;
* ``edge``:   a different, smaller site to show the other vendors: the two NX-OS core switches with a FortiGate firewall (an aggregate of two ports, one to each core, a VLAN sub-interface, an
  uplink to an ISP) and an F5 BIG-IP (a two-port LACP trunk, one port to each core, two virtual servers, two pools) hanging off the vPC pair.

The fourth, ``multisite``, is a company: a head quarter (LAN zone, data-center zone, core, edge, WAN firewalls and routers; hostnames HQ-xxx) and six branches
(JKT, SBY, YOG, MKS, MED, BAL; one router and three switches each, two MPLS providers per branch; the switches of JKT, SBY and YOG are a chain SW1 - SW2 - SW3, the ones of MKS, MED and BAL a star: SW1 with two downlinks SW2 and SW3) in 44 captures of five vendors (Cisco NX-OS and IOS XE, Aruba AOS-CX, Huawei VRP,
FortiGate, Palo Alto) and a ready-made ``layout.drawio`` (the "Keep my layout" file: the head quarter page drawn tier by tier, WAN on top, then edge, core, the two zones, the LAN distribution pair and the access switches).  Addresses are private (10.0.0.0/8) with documentation prefixes for the providers.  The addressing plan is in docs/modules/topology-demo-multisite.md.

Build the first, pin it, build the second: the baseline banner shows the changes.  No customer capture is in these files.
"""

from __future__ import annotations

from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent / "demo"

SETS = (
    {"id": "before", "label": "Data center today", "description": "Two vPC core switches and four access switches (6 captures)."},
    {"id": "after", "label": "After a change window", "description": "The same network with a new access switch, a pulled uplink (leaving one switch single-homed) and a changed management address (7 captures). Build it after pinning the first one."},
    {"id": "edge", "label": "Firewall and F5", "description": "Two vPC core switches with a FortiGate firewall and an F5 BIG-IP on port-channels (4 captures): the F5 map, the firewall and the L3 views."},
    {"id": "multisite", "group": "auto", "layout": "layout.drawio", "label": "Head quarter and 6 branches", "description": "A company: head quarter with a LAN zone, a data-center zone, core, edge, WAN firewalls and routers, plus six branches over two MPLS providers each (44 captures from Cisco, Aruba, Huawei, FortiGate and Palo Alto). Loads with \"Automatic\" grouping (one page per site) and a ready-made layout of the head quarter page."},
)


def _folder(set_id: object) -> Path | None:
    for item in SETS:
        if item["id"] == set_id:
            folder = DEMO_DIR / str(item["id"])
            return folder if folder.is_dir() else None
    return None


def list_sets() -> list[dict]:
    """Each set with its files (name and size), in a fixed order."""
    out = []
    for item in SETS:
        folder = _folder(item["id"])
        files = sorted(folder.glob("*.txt")) if folder else []
        layout = str(item.get("layout", ""))
        out.append({**item, "layout": layout if folder and layout and (folder / layout).is_file() else "",
                    "files": [{"name": f.name, "size": f.stat().st_size} for f in files]})
    return out


def read_file(set_id: object, name: object) -> bytes | None:
    """The bytes of one demo capture, only when the name is in the set (a name is never turned into a path)."""
    folder = _folder(set_id)
    if folder is None:
        return None
    declared = next((str(i.get("layout", "")) for i in SETS if i["id"] == set_id), "")
    for candidate in [*folder.glob("*.txt"), *([folder / declared] if declared else [])]:
        if candidate.name == name and candidate.is_file() and not candidate.is_symlink():
            return candidate.read_bytes()
    return None
