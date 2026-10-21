"""Save and restore what the builder learned from the captures, so a later run can add devices to an earlier one.

``topology.json`` carries a ``state`` block with every captured device (neighbors, bundles, vPC, MAC and ARP tables).
Uploading that file next to new captures rebuilds the whole estate: devices in the new captures replace the saved ones
(matched by serial number or hostname), every other saved device is carried over.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
from typing import Any

from .extract import Device, HalfEdge
from .names import short_host

STATE_VERSION = 1
MAX_STATE_BYTES = 120 * 1024 * 1024
MAX_DEVICES = 500
MAX_ROWS = 400_000


class StateError(ValueError):
    """The file is not a Keystone topology.json with a saved state."""


def _plain(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, HalfEdge):
        return {k: _plain(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    return value


def device_to_state(device: Device) -> dict[str, Any]:
    return {f.name: _plain(getattr(device, f.name)) for f in dataclasses.fields(Device) if f.name not in ("key", "carried", "role_hint")}


def devices_to_state(devices: list[Device]) -> dict[str, Any]:
    captured = [d for d in devices if d.captured]
    return {"version": STATE_VERSION, "created": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "devices": [device_to_state(d) for d in captured]}


def state_json(devices: list[Device]) -> str:
    """Compact JSON text for the ``state`` block (MAC tables make it large; indentation would double it)."""
    return json.dumps(devices_to_state(devices), separators=(",", ":"), ensure_ascii=False)


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


def _half(raw: Any) -> HalfEdge:
    if not isinstance(raw, dict):
        raise StateError("A saved neighbor entry is not readable.")
    kwargs: dict[str, Any] = {}
    for f in dataclasses.fields(HalfEdge):
        if f.name not in raw:
            continue
        kwargs[f.name] = {_text(p) for p in raw[f.name]} if f.name == "protocols" and isinstance(raw[f.name], list) else _text(raw[f.name])
    kwargs.setdefault("local_port", "")
    kwargs.setdefault("remote_name", "")
    kwargs.setdefault("remote_port", "")
    return HalfEdge(**kwargs)


def _rows(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or len(raw) > MAX_ROWS:
        return []
    return [dict(row) for row in raw if isinstance(row, dict)]


def device_from_state(raw: Any) -> Device:
    if not isinstance(raw, dict) or not isinstance(raw.get("hostname"), str):
        raise StateError("A saved device has no hostname.")
    device = Device(key="", hostname=raw["hostname"])
    for f in dataclasses.fields(Device):
        if f.name in ("key", "hostname", "carried", "role_hint") or f.name not in raw:
            continue
        value, default = raw[f.name], getattr(device, f.name)
        if f.name == "halves":
            if not isinstance(value, list):
                raise StateError("The saved neighbors are not a list.")
            device.halves = [_half(h) for h in value]
        elif f.name in ("mac_table", "arp_table"):
            setattr(device, f.name, _rows(value))
        elif f.name == "l3":
            device.l3 = _rows(value)
        elif isinstance(default, bool):
            setattr(device, f.name, bool(value))
        elif isinstance(default, int):
            setattr(device, f.name, int(value) if isinstance(value, (int, float)) else default)
        elif isinstance(default, set):
            setattr(device, f.name, {_text(v) for v in value} if isinstance(value, list) else set())
        elif isinstance(default, list):
            setattr(device, f.name, [_text(v) for v in value] if isinstance(value, list) else [])
        elif isinstance(default, dict):
            if isinstance(value, dict):
                setattr(device, f.name, {_text(k): (dict(v) if isinstance(v, dict) else v if isinstance(v, (int, list)) else _text(v)) for k, v in value.items()})
        else:
            setattr(device, f.name, _text(value))
    device.captured = True
    device.carried = True
    return device


def read_state(data: bytes) -> list[Device]:
    """The devices saved in an earlier ``topology.json``; raises StateError with a plain message when the file is something else."""
    if len(data) > MAX_STATE_BYTES:
        raise StateError(f"The previous topology.json is larger than {MAX_STATE_BYTES // (1024 * 1024)} MB.")
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise StateError("The previous run file is not readable JSON.") from exc
    state = document.get("state") if isinstance(document, dict) else None
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION or not isinstance(state.get("devices"), list):
        raise StateError("This topology.json has no saved state. Use a topology.json written by this version of the Topology Builder.")
    if len(state["devices"]) > MAX_DEVICES:
        raise StateError(f"The saved state holds more than {MAX_DEVICES} devices.")
    return [device_from_state(raw) for raw in state["devices"]]


def merge(carried: list[Device], fresh: list[Device]) -> tuple[list[Device], list[str]]:
    """Fresh captures win; a saved device is dropped when a new capture has the same serial number or hostname.
    Returns the combined list (saved devices first) and the hostnames that were replaced."""
    serials = {s for d in fresh for s in d.serials}
    hosts = {short_host(d.hostname) for d in fresh if d.hostname}
    kept, replaced = [], []
    for device in carried:
        if (device.serials & serials) or (short_host(device.hostname) in hosts):
            replaced.append(device.hostname)
        else:
            kept.append(device)
    return kept + fresh, sorted(replaced)
