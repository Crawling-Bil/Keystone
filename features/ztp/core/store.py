"""Pre-registration store for Zero Touch Provisioning (ZTP).

Before a factory-default switch is ever powered on, an engineer records
its ESN (serial number), MAC address, and intended identity (hostname,
management IP, site) here. This is the data that later gets rendered
into the ZTP intermediate file (see intermediate_file.py) and the
per-device bootstrap config (see config_template.py) — it is the direct
replacement for typing the same information in at a console.

Keyed by ESN because that's what the switch itself uses to find its own
entry inside the intermediate file (see Huawei's "Intermediate File in
the INI Format" — the ESN field is the match key). MAC is stored
alongside because a DHCP reservation (so the switch gets a predictable
IP during staging) is keyed by MAC, not ESN — two different systems,
two different identifiers, both captured at registration time.

Deliberately self-contained (own JSON read/write helpers) rather than
importing routes.py's, to avoid a circular import — routes.py imports
from this package, not the other way around.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEVICES_FILE = DATA_DIR / "ztp_devices.json"

_lock = threading.RLock()

_ESN_RE = re.compile(r"^[A-Za-z0-9]{6,32}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


class ZtpStoreError(ValueError):
    """Raised for invalid pre-registration data (bad ESN/MAC/IP, etc.)."""


class ZtpStoreReadError(RuntimeError):
    """Raised when the on-disk device store exists but can't be read
    (permission error, disk I/O error, corrupted JSON) -- deliberately
    NOT raised when the file simply doesn't exist yet (a brand new
    install has no store file, and that's a legitimate empty store,
    handled separately below).

    WHY THIS MATTERS: an earlier version of _read_unlocked() caught
    (json.JSONDecodeError, OSError) unconditionally and returned the
    caller's `default` (an empty devices list) for BOTH "file doesn't
    exist" and "file exists but couldn't be read" -- indistinguishable
    to every caller. upsert_device() unconditionally calls
    _write_unlocked() at the end of its critical section regardless of
    whether the read that fed it actually succeeded, so a single
    TRANSIENT read failure (a momentary permission glitch, a slow/
    flaky filesystem, anything that raises OSError) during ANY device
    registration silently turned "read the real store" into "start
    from an empty store" -- and the very next write then overwrote the
    real file, permanently deleting every other pre-registered device
    except the one just being added, with no error shown anywhere: the
    API call still returns 200 success. That's the exact kind of
    silent, hard-to-reproduce data loss this class of bug produces --
    caught here by making an unreadable-but-existing store a loud
    failure instead of a silent empty one."""


def _read_unlocked(default):
    if not DEVICES_FILE.exists():
        return default
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        raise ZtpStoreReadError(
            f"Could not read the ZTP device store at {DEVICES_FILE} ({exc}). "
            "Refusing to silently treat this as an empty store -- doing so "
            "would risk the next write (register/delete/mark-status) "
            "overwriting real data. Fix the underlying issue (file "
            "permissions, disk space, a corrupted JSON file) and retry."
        ) from exc


def _write_unlocked(data):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(DATA_DIR), prefix=f".{DEVICES_FILE.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4)
        os.replace(tmp_name, DEVICES_FILE)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _normalize_esn(esn):
    esn = str(esn or "").strip().upper()
    if not _ESN_RE.match(esn):
        raise ZtpStoreError(
            f"Invalid ESN {esn!r} — expected 6-32 alphanumeric characters "
            "(check `display device esn` output on the unit)."
        )
    return esn


def _normalize_mac(mac):
    mac = str(mac or "").strip()
    if not mac:
        return ""
    if not _MAC_RE.match(mac):
        raise ZtpStoreError(
            f"Invalid MAC {mac!r} — expected AA:BB:CC:DD:EE:FF format."
        )
    return mac.lower()


def list_devices():
    """Return all pre-registered ZTP devices, most recently updated first."""
    with _lock:
        data = _read_unlocked({"devices": []})
    devices = data.get("devices", [])
    return sorted(devices, key=lambda d: d.get("updated_at", ""), reverse=True)


def get_device(esn):
    esn = _normalize_esn(esn)
    for device in list_devices():
        if device.get("esn") == esn:
            return device
    return None


def upsert_device(record):
    """Create or update a pre-registration entry, keyed by ESN.

    Required: esn, hostname, mgmt_ip. Recommended: mac (for a DHCP
    reservation), site. Optional: mgmt_mask, gateway, vrp_username,
    vrp_password, vrp_version (skips re-flashing firmware that's already
    correct), firmware_filename (omit to deploy config only, no
    SOFTWARE file), site.
    """
    esn = _normalize_esn(record.get("esn"))
    hostname = str(record.get("hostname") or "").strip()
    mgmt_ip = str(record.get("mgmt_ip") or "").strip()
    if not hostname:
        raise ZtpStoreError("hostname is required.")
    if not mgmt_ip:
        raise ZtpStoreError("mgmt_ip is required.")

    mac = _normalize_mac(record.get("mac"))
    now = time.strftime("%Y-%m-%dT%H:%M:%S")

    with _lock:
        data = _read_unlocked({"devices": []})
        devices = data.setdefault("devices", [])
        existing = next((d for d in devices if d.get("esn") == esn), None)

        entry = {
            "esn": esn,
            "mac": mac,
            "hostname": hostname,
            "mgmt_ip": mgmt_ip,
            "mgmt_mask": str(record.get("mgmt_mask") or "255.255.255.0").strip(),
            "gateway": str(record.get("gateway") or "").strip(),
            "site": str(record.get("site") or "").strip(),
            "vendor": str(record.get("vendor") or "Huawei").strip(),
            "model": str(record.get("model") or "").strip(),
            "vrp_version": str(record.get("vrp_version") or "").strip(),
            "firmware_filename": str(record.get("firmware_filename") or "").strip(),
            "vrp_username": str(record.get("vrp_username") or "ztp-admin").strip(),
            "vrp_password": str(record.get("vrp_password") or ""),
            "status": (existing or {}).get("status", "pending"),
            "created_at": (existing or {}).get("created_at", now),
            "updated_at": now,
        }

        if not entry["vrp_password"]:
            raise ZtpStoreError(
                "vrp_password is required — this becomes the device's local-user "
                "password in the bootstrap config, without it the device won't be "
                "remotely reachable after ZTP (Huawei explicitly documents this as "
                "a deployment-failure condition)."
            )

        if existing:
            devices[devices.index(existing)] = entry
        else:
            devices.append(entry)

        _write_unlocked(data)

    return entry


def delete_device(esn):
    esn = _normalize_esn(esn)
    with _lock:
        data = _read_unlocked({"devices": []})
        devices = data.get("devices", [])
        remaining = [d for d in devices if d.get("esn") != esn]
        removed = len(remaining) != len(devices)
        if removed:
            data["devices"] = remaining
            _write_unlocked(data)
    return removed


def mark_status(esn, status):
    """status is one of: pending, provisioned, failed."""
    esn = _normalize_esn(esn)
    with _lock:
        data = _read_unlocked({"devices": []})
        devices = data.get("devices", [])
        for device in devices:
            if device.get("esn") == esn:
                device["status"] = status
                device["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
                _write_unlocked(data)
                return device
    return None
