"""What changed between two topology runs.

Two ``topology.json`` files (or the ``keystone-topology-pack.zip`` that holds one) are read and compared table by table:

* **Devices** by name: added, removed, and changed role, vendor, model, software version, management address, serial numbers, stack size,
  vPC domain and role, captured or only seen by neighbors, and the commands that were captured (``has_*`` columns).
* **Links** by their two ends (device and port, in either order): added, removed, moved to another port (re-cabled), and changed state,
  protocols, bundle, kind, vPC id, subnet, native VLAN, and per end the speed, rated speed, port state and duplex.
* **Findings** by finding id and device list: new and resolved ones, and a change of severity.
* **Hosts** (MAC addresses) and **Behind devices**: added, removed, moved to another switch or port, changed address or VLAN.

Every row says whether it needs attention.  A device or a link that disappears, a link that slows down, a duplex, bundle or native VLAN change, a
new management address, a vPC role change and a new medium finding need attention; additions and the rest are information.

A device that is in the first run and not in the second may simply not have been captured the second time.  The summary says how many devices
were captured in both runs, and a device that is still in the second run but was only seen by neighbors is reported as "no longer captured".

Nothing here raises for a file that is merely different: ``load_run`` raises ``DiffError`` with a plain message, ``compare_runs`` is total.
"""

from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any

MAX_BYTES = 150 * 1024 * 1024
MAX_ROWS_PER_AREA = 3000
AREAS = ("Devices", "Links", "Findings", "Hosts", "Behind devices")
COLUMNS = ["area", "change", "impact", "item", "field", "before", "after", "why"]

DEVICE_FIELDS = ("role", "vendor", "model", "os_version", "management_ip", "serial", "stack_members", "vpc_domain", "vpc_role")
LINK_FIELDS = ("state", "protocols", "kind", "vpc_id", "subnet", "native_vlan", "duplex")
END_FIELDS = ("bundle", "speed", "rated", "port_state", "duplex")
HOST_FIELDS = ("ip_address", "vlan")

_ATTENTION_DEVICE = {"management_ip": "the address that SSH, SNMP and the neighbor tables use changed",
                     "vpc_role": "a vPC role change means a failover or a re-election happened",
                     "vpc_domain": "the vPC domain changed"}
_STATE_QUALITY = {"confirmed": 3, "single": 2, "inferred": 1, "conflict": 0}          # features/topology/graph.py: how well the two ends of a link agree
_ATTENTION_LINK = {"duplex": "a duplex change on a link is the classic cause of late collisions and CRC errors",
                   "native_vlan": "a native VLAN change on a trunk moves untagged traffic into another VLAN",
                   "bundle": "the port left, joined or changed its port-channel",
                   "kind": "the link type changed (for example a bundle member became a single link)",
                   "vpc_id": "the vPC id of the bundle changed"}


class DiffError(ValueError):
    """The file is not a topology run this builder wrote."""


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def parse_speed(text: str) -> int:
    """'10G' -> 10000, '100M' -> 100, '' or anything else -> 0 (megabits per second)."""
    match = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([GgMm])(?:bps|b/s)?\s*", text or "")
    if not match:
        return 0
    number = float(match.group(1))
    return int(round(number * (1000 if match.group(2).lower() == "g" else 1)))


def load_run(data: bytes) -> dict[str, Any]:
    """The tables of one run from the bytes of a ``topology.json`` or a pack ZIP; raises DiffError with a plain message."""
    if len(data) > MAX_BYTES:
        raise DiffError(f"The file is larger than {MAX_BYTES // (1024 * 1024)} MB.")
    if data[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as pack:
                member = next((i for i in pack.infolist() if i.filename.replace("\\", "/").split("/")[-1] == "topology.json" and "_anonymized" not in i.filename), None)
                if member is None:
                    raise DiffError("This ZIP has no topology.json. Use keystone-topology-pack.zip or the topology.json inside it.")
                if member.file_size > MAX_BYTES:
                    raise DiffError(f"The topology.json inside the ZIP is larger than {MAX_BYTES // (1024 * 1024)} MB.")
                data = pack.read(member)
        except zipfile.BadZipFile as exc:
            raise DiffError("The ZIP file cannot be opened.") from exc
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise DiffError("The file is not readable JSON. Use a topology.json written by the Topology Builder.") from exc
    if not isinstance(document, dict) or not isinstance(document.get("devices"), list) or not isinstance(document.get("links"), list):
        raise DiffError("This file has no devices and links tables. Use a topology.json written by the Topology Builder.")
    run: dict[str, Any] = {}
    for table in ("devices", "links", "hosts", "behind", "findings"):
        rows = document.get(table, [])
        run[table] = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    return run


# ---- devices ----------------------------------------------------------------------------------------------------------------------------------

def _is_captured(row: dict) -> bool:
    return _text(row.get("captured")).lower().startswith("yes")


def _device_rows(before: list[dict], after: list[dict]) -> tuple[list[dict], dict[str, int]]:
    old = {_text(r.get("device")): r for r in before if _text(r.get("device"))}
    new = {_text(r.get("device")): r for r in after if _text(r.get("device"))}
    rows: list[dict] = []
    counts = {"added": 0, "removed": 0, "changed": 0, "same": 0}
    both_captured = 0
    for name in sorted(set(old) | set(new), key=str.lower):
        a, b = old.get(name), new.get(name)
        if a is None:
            counts["added"] += 1
            rows.append(_row("Devices", "added", "info", name, "", "", f"{_text(b.get('role'))} {_text(b.get('model'))}".strip(),
                             "captured" if _is_captured(b) else "seen by neighbors only"))
            continue
        if b is None:
            counts["removed"] += 1
            rows.append(_row("Devices", "removed", "attention", name, "", f"{_text(a.get('role'))} {_text(a.get('model'))}".strip(), "",
                             "not in the second run: it may not have been captured again, or it left the network"))
            continue
        changed = False
        if _is_captured(a) and _is_captured(b):
            both_captured += 1
        if _is_captured(a) != _is_captured(b):
            changed = True
            lost = _is_captured(a) and not _is_captured(b)
            rows.append(_row("Devices", "changed", "attention" if lost else "info", name, "captured", _text(a.get("captured")), _text(b.get("captured")),
                             "no longer captured: its own tables are missing from the second run" if lost else "now captured: its links are confirmed from both ends"))
        for field in DEVICE_FIELDS:
            x, y = _text(a.get(field)), _text(b.get(field))
            if x != y:
                changed = True
                # a field the first run did not know (empty) that the second run fills in is information; a value that changes is the thing to read
                attention = field in _ATTENTION_DEVICE and bool(x) and bool(y)
                rows.append(_row("Devices", "changed", "attention" if attention else "info", name, field, x, y, _ATTENTION_DEVICE.get(field, "") if attention else ""))
        gained = sorted(k[4:] for k in b if k.startswith("has_") and _text(b.get(k)) == "yes" and _text(a.get(k)) == "no")
        lost_cov = sorted(k[4:] for k in a if k.startswith("has_") and _text(a.get(k)) == "yes" and _text(b.get(k)) == "no")
        if gained or lost_cov:
            changed = True
            rows.append(_row("Devices", "changed", "info", name, "captured commands",
                             ", ".join(f"-{c}" for c in lost_cov), ", ".join(f"+{c}" for c in gained),
                             "the capture holds different tables: a missing one means a part of the picture (hosts, routes, bundles) is not in the second run" if lost_cov else ""))
        counts["changed" if changed else "same"] += 1
    counts["captured_in_both"] = both_captured
    return rows, counts


# ---- links ------------------------------------------------------------------------------------------------------------------------------------

def _link_key(row: dict) -> tuple:
    a = (_text(row.get("device_a")), _text(row.get("port_a")))
    b = (_text(row.get("device_b")), _text(row.get("port_b")))
    return tuple(sorted((a, b), key=lambda e: (e[0].lower(), e[1].lower())))


def _link_view(row: dict) -> dict[str, Any]:
    """One link with its ends in key order, so ``end_a`` is always the same end in both runs whichever way the run wrote it."""
    key = _link_key(row)
    straight = (_text(row.get("device_a")), _text(row.get("port_a"))) == key[0]
    suffix_first, suffix_second = ("a", "b") if straight else ("b", "a")
    view: dict[str, Any] = {"key": key, "row": row}
    for field in LINK_FIELDS:
        view[field] = _text(row.get(field))
    for position, suffix in (("first", suffix_first), ("second", suffix_second)):
        view[position] = {"bundle": _text(row.get(f"bundle_{suffix}")), "speed": _text(row.get(f"speed_{suffix}")), "rated": _text(row.get(f"rated_{suffix}")),
                          "port_state": _text(row.get(f"port_state_{suffix}")), "duplex": _text(row.get(f"duplex_{suffix}"))}
    return view


def _link_name(key: tuple) -> str:
    return f"{key[0][0]} {key[0][1]} - {key[1][0]} {key[1][1]}".replace("  ", " ")


def _link_rows(before: list[dict], after: list[dict]) -> tuple[list[dict], dict[str, int]]:
    old: dict[tuple, dict] = {}
    new: dict[tuple, dict] = {}
    for row in before:
        view = _link_view(row)
        old.setdefault(view["key"], view)
    for row in after:
        view = _link_view(row)
        new.setdefault(view["key"], view)
    rows: list[dict] = []
    counts = {"added": 0, "removed": 0, "changed": 0, "moved": 0, "same": 0}
    removed = [k for k in old if k not in new]
    added = [k for k in new if k not in old]
    moved_pairs = _match_moved(removed, added)
    moved_old = {o for o, _ in moved_pairs}
    moved_new = {n for _, n in moved_pairs}
    for key in sorted(old, key=lambda k: _link_name(k).lower()):
        if key in new:
            changed = False
            a, b = old[key], new[key]
            for field in LINK_FIELDS:
                if a[field] != b[field]:
                    changed = True
                    # protocols and the subnet change as captures are added; only the fields with an operational meaning are flagged,
                    # and only when both runs had a value (a value that appears for the first time is just a better capture)
                    if field == "state":
                        attention = _STATE_QUALITY.get(b[field], 1) < _STATE_QUALITY.get(a[field], 1)          # confirmed -> single / inferred / conflict is worse; the other way is a better capture
                        why = "the link is now seen from fewer ends, or the two ends disagree" if attention else ""
                    else:
                        attention = field in _ATTENTION_LINK and bool(a[field]) and bool(b[field])
                        why = _ATTENTION_LINK.get(field, "") if attention else ""
                    rows.append(_row("Links", "changed", "attention" if attention else "info", _link_name(key), field, a[field], b[field], why))
            for position, end in (("first", key[0]), ("second", key[1])):
                for field in END_FIELDS:
                    x, y = a[position][field], b[position][field]
                    if x == y:
                        continue
                    changed = True
                    label = f"{field.replace('_', ' ')} at {end[0]} {end[1]}".strip()
                    attention, why = _end_change(field, x, y)
                    rows.append(_row("Links", "changed", "attention" if attention else "info", _link_name(key), label, x, y, why))
            counts["changed" if changed else "same"] += 1
    for key in sorted(removed, key=lambda k: _link_name(k).lower()):
        if key in moved_old:
            continue
        counts["removed"] += 1
        rows.append(_row("Links", "removed", "attention", _link_name(key), "", old[key]["state"], "",
                         "not seen in the second run: the cable moved, the port is down, or the neighbor table was not captured"))
    for key in sorted(added, key=lambda k: _link_name(k).lower()):
        if key in moved_new:
            continue
        counts["added"] += 1
        rows.append(_row("Links", "added", "info", _link_name(key), "", "", new[key]["state"], ""))
    for old_key, new_key in sorted(moved_pairs, key=lambda p: _link_name(p[0]).lower()):
        counts["moved"] += 1
        rows.append(_row("Links", "moved", "attention", _link_name(old_key), "ports", _link_name(old_key), _link_name(new_key),
                         "the same pair of devices (or the same port) is now connected through different ports: re-cabled, or a different neighbor on that port"))
    return rows, counts


def _end_change(field: str, before: str, after: str) -> tuple[bool, str]:
    if field == "speed":
        x, y = parse_speed(before), parse_speed(after)
        if x and y and y < x:
            return True, "the negotiated speed dropped: a bad cable or transceiver, or a port forced to a lower speed"
        return False, ""
    if field == "port_state":
        if after and after not in ("up", "connected") and before in ("up", "connected"):
            return True, "the port was up and is now not"
        return False, ""
    if field == "duplex":
        if before and after and before != after:
            return True, _ATTENTION_LINK["duplex"]
        return False, ""
    if field == "bundle":
        if before and after:
            return True, _ATTENTION_LINK["bundle"]
        if before and not after:
            return True, "the port is no longer a member of a port-channel"
        return False, ""
    return False, ""


def _match_moved(removed: list[tuple], added: list[tuple]) -> list[tuple]:
    """A removed and an added link that are the same cable seen again: they share one end exactly and the other end is on the same device
    (a port change), or they join the same two devices through ports that both changed and are the only such pair."""
    pairs: list[tuple] = []
    free_added = set(added)
    used_removed: set = set()
    for old in removed:
        candidates = [new for new in free_added if _shares_one_end(old, new)]
        if len(candidates) == 1 and len([o for o in removed if o not in used_removed and _shares_one_end(o, candidates[0])]) == 1:
            pairs.append((old, candidates[0]))
            free_added.discard(candidates[0])
            used_removed.add(old)
    rest_old = [o for o in removed if o not in used_removed]
    by_devices: dict[tuple, list[tuple]] = {}
    for key in rest_old:
        by_devices.setdefault(tuple(sorted((key[0][0].lower(), key[1][0].lower()))), []).append(key)
    for old in rest_old:
        devices = tuple(sorted((old[0][0].lower(), old[1][0].lower())))
        news = [n for n in free_added if tuple(sorted((n[0][0].lower(), n[1][0].lower()))) == devices]
        if len(news) == 1 and len(by_devices[devices]) == 1:
            pairs.append((old, news[0]))
            free_added.discard(news[0])
    return pairs


def _shares_one_end(old: tuple, new: tuple) -> bool:
    for i in (0, 1):
        for j in (0, 1):
            if old[i] == new[j] and old[1 - i][0].lower() == new[1 - j][0].lower() and old[1 - i] != new[1 - j]:
                return True
    return False


# ---- findings, hosts, behind --------------------------------------------------------------------------------------------------------------------

def _finding_rows(before: list[dict], after: list[dict]) -> tuple[list[dict], dict[str, int]]:
    def keyed(rows: list[dict]) -> dict[tuple, dict]:
        out: dict[tuple, dict] = {}
        for row in rows:
            devices = row.get("devices", [])
            devices = devices if isinstance(devices, list) else [part.strip() for part in str(devices).split(",") if part.strip()]
            out.setdefault((_text(row.get("id")), tuple(sorted(_text(d) for d in devices))), row)
        return out
    old, new = keyed(before), keyed(after)
    rows: list[dict] = []
    counts = {"added": 0, "resolved": 0, "changed": 0, "same": 0}
    # a finding that covers a list of devices (TOPO-004 "advertised but not captured") keeps its id while the list changes: one row, not a pair
    left_old = {k: v for k, v in old.items() if k not in new}
    left_new = {k: v for k, v in new.items() if k not in old}
    rescoped: set = set()
    for code in sorted({k[0] for k in left_old} & {k[0] for k in left_new}):
        olds = [k for k in left_old if k[0] == code]
        news = [k for k in left_new if k[0] == code]
        if len(olds) == 1 and len(news) == 1:
            a, b = left_old[olds[0]], left_new[news[0]]
            counts["changed"] += 1
            rescoped.update((olds[0], news[0]))
            worse = _severity_rank(_text(b.get("severity"))) < _severity_rank(_text(a.get("severity")))
            rows.append(_row("Findings", "changed", "attention" if worse else "info", f"{code} {_text(b.get('title'))}".strip(), "devices",
                             ", ".join(olds[0][1][:6]) + (" ..." if len(olds[0][1]) > 6 else ""), ", ".join(news[0][1][:6]) + (" ..." if len(news[0][1]) > 6 else ""),
                             "the finding is still reported, for other devices" if not worse else "the finding is still reported and its severity went up"))
    for key in sorted(set(old) | set(new)):
        if key in rescoped:
            continue
        a, b = old.get(key), new.get(key)
        label = f"{key[0]} {_text((b or a).get('title'))}".strip()
        scope = ", ".join(key[1][:4]) + (" ..." if len(key[1]) > 4 else "")
        if a is None:
            counts["added"] += 1
            medium = _text(b.get("severity")) == "medium"
            rows.append(_row("Findings", "added", "attention" if medium else "info", label, scope, "", _text(b.get("severity")),
                             "a new finding of medium severity" if medium else ""))
        elif b is None:
            counts["resolved"] += 1
            rows.append(_row("Findings", "resolved", "info", label, scope, _text(a.get("severity")), "", "no longer reported in the second run"))
        elif _text(a.get("severity")) != _text(b.get("severity")):
            counts["changed"] += 1
            worse = _severity_rank(_text(b.get("severity"))) < _severity_rank(_text(a.get("severity")))
            rows.append(_row("Findings", "changed", "attention" if worse else "info", label, scope or "severity", _text(a.get("severity")), _text(b.get("severity")), ""))
        else:
            counts["same"] += 1
    return rows, counts


def _severity_rank(severity: str) -> int:
    return {"medium": 0, "low": 1, "info": 2}.get(severity, 3)


def _host_rows(before: list[dict], after: list[dict]) -> tuple[list[dict], dict[str, int]]:
    old = {_text(r.get("mac")).lower(): r for r in before if _text(r.get("mac"))}
    new = {_text(r.get("mac")).lower(): r for r in after if _text(r.get("mac"))}
    rows: list[dict] = []
    counts = {"added": 0, "removed": 0, "moved": 0, "changed": 0, "same": 0}
    for mac in sorted(set(old) | set(new)):
        a, b = old.get(mac), new.get(mac)
        if a is None:
            counts["added"] += 1
            rows.append(_row("Hosts", "added", "info", mac, "", "", f"{_text(b.get('device'))} {_text(b.get('port'))}".strip(), _text(b.get("ip_address"))))
        elif b is None:
            counts["removed"] += 1
            rows.append(_row("Hosts", "removed", "info", mac, "", f"{_text(a.get('device'))} {_text(a.get('port'))}".strip(), "", _text(a.get("ip_address"))))
        else:
            place_a = (_text(a.get("device")), _text(a.get("port")))
            place_b = (_text(b.get("device")), _text(b.get("port")))
            changed = False
            if place_a != place_b:
                counts["moved"] += 1
                changed = True
                rows.append(_row("Hosts", "moved", "info", mac, "location", " ".join(place_a).strip(), " ".join(place_b).strip(),
                                 "learned on another switch or port: a virtual machine moved, a cable was moved, or the MAC table aged differently"))
            for field in HOST_FIELDS:
                x, y = _text(a.get(field)), _text(b.get(field))
                if x != y and x and y:
                    changed = True
                    rows.append(_row("Hosts", "changed", "info", mac, field.replace("_", " "), x, y, ""))
            if not changed:
                counts["same"] += 1
    return rows, counts


def _behind_rows(before: list[dict], after: list[dict]) -> tuple[list[dict], dict[str, int]]:
    def keyed(rows: list[dict]) -> dict[tuple, dict]:
        return {(_text(r.get("behind")), _text(r.get("switch")), _text(r.get("port"))): r for r in rows}
    old, new = keyed(before), keyed(after)
    rows: list[dict] = []
    counts = {"added": 0, "removed": 0, "changed": 0, "same": 0}
    for key in sorted(set(old) | set(new)):
        a, b = old.get(key), new.get(key)
        item = f"{key[0]} behind {key[1]} {key[2]}"
        if a is None:
            counts["added"] += 1
            rows.append(_row("Behind devices", "added", "info", item, "mac addresses", "", _text(b.get("mac_addresses")), ""))
        elif b is None:
            counts["removed"] += 1
            rows.append(_row("Behind devices", "removed", "info", item, "mac addresses", _text(a.get("mac_addresses")), "", ""))
        elif _text(a.get("mac_addresses")) != _text(b.get("mac_addresses")) or _text(a.get("vlans")) != _text(b.get("vlans")):
            counts["changed"] += 1
            if _text(a.get("mac_addresses")) != _text(b.get("mac_addresses")):
                rows.append(_row("Behind devices", "changed", "info", item, "mac addresses", _text(a.get("mac_addresses")), _text(b.get("mac_addresses")), ""))
            if _text(a.get("vlans")) != _text(b.get("vlans")):
                rows.append(_row("Behind devices", "changed", "info", item, "vlans", _text(a.get("vlans")), _text(b.get("vlans")), ""))
        else:
            counts["same"] += 1
    return rows, counts


# ---- the whole comparison -----------------------------------------------------------------------------------------------------------------------

def _row(area: str, change: str, impact: str, item: str, field: str, before: str, after: str, why: str) -> dict[str, str]:
    return {"area": area, "change": change, "impact": impact, "item": item, "field": field, "before": before, "after": after, "why": why}


def compare_runs(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """``{"summary": ..., "rows": [...], "columns": [...]}``; rows are ordered by area, then the ones that need attention, then by name.
    An area with more than ``MAX_ROWS_PER_AREA`` rows keeps the first rows and says so in ``summary["truncated"]``."""
    parts = {
        "Devices": _device_rows(before.get("devices", []), after.get("devices", [])),
        "Links": _link_rows(before.get("links", []), after.get("links", [])),
        "Findings": _finding_rows(before.get("findings", []), after.get("findings", [])),
        "Hosts": _host_rows(before.get("hosts", []), after.get("hosts", [])),
        "Behind devices": _behind_rows(before.get("behind", []), after.get("behind", [])),
    }
    rows: list[dict] = []
    areas: dict[str, dict[str, int]] = {}
    truncated: dict[str, int] = {}
    for area in AREAS:
        area_rows, counts = parts[area]
        areas[area] = counts
        area_rows = sorted(area_rows, key=lambda r: (r["impact"] != "attention",))               # stable: attention first, names stay in order
        if len(area_rows) > MAX_ROWS_PER_AREA:
            truncated[area] = len(area_rows) - MAX_ROWS_PER_AREA
            area_rows = area_rows[:MAX_ROWS_PER_AREA]
        rows.extend(area_rows)
    attention = sum(1 for r in rows if r["impact"] == "attention")
    differences = sum(counts.get("added", 0) + counts.get("removed", 0) + counts.get("changed", 0) + counts.get("moved", 0) + counts.get("resolved", 0)
                      for counts in areas.values())
    summary = {
        "areas": areas, "attention": attention, "differences": differences, "truncated": truncated,
        "before": {"devices": len(before.get("devices", [])), "links": len(before.get("links", [])), "findings": len(before.get("findings", [])), "hosts": len(before.get("hosts", []))},
        "after": {"devices": len(after.get("devices", [])), "links": len(after.get("links", [])), "findings": len(after.get("findings", [])), "hosts": len(after.get("hosts", []))},
        "captured_in_both": areas["Devices"].get("captured_in_both", 0),
        "verdict": "identical" if not differences else ("attention" if attention else "changed"),
    }
    return {"summary": summary, "rows": rows, "columns": COLUMNS}
