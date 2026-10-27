"""Parsers for the second set of Catalyst SD-WAN commands: OMP summary, installed certificates, per-tunnel packet counters and BFD history.

Formats were read from real captures of two cEdge routers in controller mode (a C8200 on IOS-XE 17.09.03a and a C8300); the points that are
easy to get wrong are recorded next to the code that handles them.

* ``show sdwan omp summary`` is a key/value list (``oper-state UP``, ``vsmart-peers 2``, a dozen sent/received/installed counters).
* ``show sdwan certificate installed`` prints OpenSSL text, one block per certificate, under two headings: ``Board-id certificate`` (the
  Cisco SUDI certificate, valid until 2099) and ``Installed device certificates`` (the enterprise certificate; empty when the router
  authenticates with the SUDI certificate).
* ``show sdwan tunnel statistics`` prints one ``tunnel stats ipsec <src> <dst> <sport> <dport>`` header per tunnel with indented key/value
  lines; about 750 tunnels on a hub router.
* ``show sdwan bfd history`` prints twelve columns, the last one headed ``DEL``.  Cisco documents neither the column nor the MIB object
  behind it (``bfdHistoryListDel``, an unsigned byte): every device that tears a session down writes a *down* record that carries the
  final packet counters and, in the same second, a second *down* record with zero counters and ``DEL 1``.  That second record is read as the
  deletion marker of the session and never counted as one more drop.

The history has **no local color or local address column**: a router with two WAN colors that both reach the same remote TLOC prints the records of both
  tunnels under the same SYSTEM IP / COLOR / DST PUBLIC IP, interleaved.  The analysis therefore works per *remote TLOC* and never claims that a tunnel is
  down now from its last record; the live state comes from ``show sdwan bfd sessions``.

Dates in ``show sdwan bfd history`` are ``MM/DD/YY HH:MM:SS`` (month first: the real captures contain days above 12 in the middle field).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any

from .runtime_sdwan import is_ip

# --------------------------------------------------------------------------
# show sdwan omp summary
# --------------------------------------------------------------------------

_OMP_TEXT_KEYS = {"oper-state", "admin-state", "personality", "device-role", "omp-uptime"}


def parse_omp_summary(lines: list[str]) -> dict[str, Any]:
    """Key/value list -> flat dict with underscores in the keys; numeric values are integers, ``oper_state`` is kept as printed (UP/DOWN)."""
    out: dict[str, Any] = {}
    for line in lines:
        pair = re.match(r"^([a-z][a-z0-9-]*)\s+(\S.*?)\s*$", line)
        if not pair:
            continue
        key, value = pair.group(1), pair.group(2)
        if key in _OMP_TEXT_KEYS or not re.fullmatch(r"\d+", value):
            out[key.replace("-", "_")] = value
        else:
            out[key.replace("-", "_")] = int(value)
    return out if "oper_state" in out else {}


# --------------------------------------------------------------------------
# show sdwan certificate installed
# --------------------------------------------------------------------------

_DATE = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})")
_DN_SPLIT = re.compile(r",\s*(?=[A-Za-z]+\s*=)")
_RULER = re.compile(r"^-{3,}\s*$")


def openssl_stamp(text: str) -> str:
    """OpenSSL date ('Aug  9 20:58:26 2099 GMT') -> ISO string, '' when it does not read."""
    match = _DATE.search(text or "")
    if not match:
        return ""
    try:
        return datetime.strptime(" ".join(match.groups()), "%b %d %H:%M:%S %Y").isoformat()
    except ValueError:
        return ""


def _dn(text: str) -> dict[str, str]:
    """Distinguished name -> {CN, O, OU}; the serialNumber component (it carries the router's serial) is dropped on purpose."""
    out: dict[str, str] = {}
    for part in _DN_SPLIT.split(text.strip()):
        key, _, value = part.partition("=")
        key = key.strip()
        if key in ("CN", "O", "OU") and key not in out:
            out[key] = value.strip()
    return out


def parse_certificates(lines: list[str]) -> dict[str, Any]:
    """``show sdwan certificate installed``: one record per certificate with its section, subject/issuer names, validity and key size.

    A section is a heading line followed by a ruler of dashes.  A section without a certificate is reported in ``empty_sections``
    (the second heading of a router that authenticates with the SUDI certificate).
    """
    certificates: list[dict[str, Any]] = []
    sections: list[str] = []
    section = ""
    current: dict[str, Any] | None = None
    after_serial = False
    for index, raw in enumerate(lines):
        text = raw.strip()
        if not text:
            continue
        nxt = lines[index + 1].strip() if index + 1 < len(lines) else ""
        if raw[:1].strip() and not raw.startswith("Certificate:") and _RULER.match(nxt) and not _RULER.match(text):
            section = text
            sections.append(section)
            current = None
            continue
        if _RULER.match(text):
            continue
        if raw.startswith("Certificate:"):
            current = {"section": section, "serial": "", "subject": {}, "issuer": {}, "not_before": "", "not_after": "", "key_bits": None, "algorithm": "", "ca": None}
            certificates.append(current)
            after_serial = False
            continue
        if current is None:
            continue
        if after_serial:
            current["serial"] = text
            after_serial = False
            continue
        if text.startswith("Serial Number:"):
            rest = text.split(":", 1)[1].strip()
            if rest:
                current["serial"] = rest
            else:
                after_serial = True
        elif text.startswith("Issuer:"):
            current["issuer"] = _dn(text.split(":", 1)[1])
        elif text.startswith("Subject:") and not current["subject"]:
            current["subject"] = _dn(text.split(":", 1)[1])
        elif text.startswith("Not Before"):
            current["not_before"] = openssl_stamp(text)
        elif text.startswith("Not After"):
            current["not_after"] = openssl_stamp(text)
        elif text.startswith("Signature Algorithm:") and not current["algorithm"]:
            current["algorithm"] = text.split(":", 1)[1].strip()
        elif "Public-Key:" in text and current["key_bits"] is None:
            bits = re.search(r"\((\d+)\s*bit\)", text)
            current["key_bits"] = int(bits.group(1)) if bits else None
        elif text.startswith("CA:"):
            current["ca"] = text.split(":", 1)[1].strip().upper() == "TRUE"
    if not sections and not certificates:
        return {}
    filled = {c["section"] for c in certificates}
    return {"certificates": certificates, "sections": sections, "empty_sections": [s for s in sections if s not in filled]}


# --------------------------------------------------------------------------
# show sdwan tunnel statistics
# --------------------------------------------------------------------------

_TUNNEL_HEAD = re.compile(r"^tunnel stats\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(\d+)\s*$")
_TUNNEL_INT = {"tx_pkts": "tx_pkts", "tx_octets": "tx_octets", "rx_pkts": "rx_pkts", "rx_octets": "rx_octets", "tunnel-mtu": "mtu", "tcp-mss-adjust": "tcp_mss"}
_TUNNEL_TEXT = {"system-ip": "system_ip", "local-color": "local_color", "remote-color": "remote_color"}


def parse_tunnel_statistics(lines: list[str]) -> list[dict[str, Any]]:
    """One record per tunnel: endpoints, system IP, colors, MTU and the IPv4 packet / octet counters (IPv6 and multicast counters are not kept)."""
    tunnels: list[dict[str, Any]] = []
    tunnel: dict[str, Any] | None = None
    for raw in lines:
        head = _TUNNEL_HEAD.match(raw.strip())
        if head and not raw[:1].isspace():
            tunnel = {"protocol": head.group(1), "src_ip": head.group(2), "dst_ip": head.group(3), "src_port": head.group(4), "dst_port": head.group(5),
                      "system_ip": "", "local_color": "", "remote_color": "", "mtu": None, "tcp_mss": None, "tx_pkts": None, "tx_octets": None, "rx_pkts": None, "rx_octets": None}
            tunnels.append(tunnel)
            continue
        if tunnel is None:
            continue
        pair = re.match(r"^\s+([a-z][\w-]*)\s+(\S+)\s*$", raw)
        if not pair:
            continue
        key, value = pair.group(1), pair.group(2)
        if key in _TUNNEL_INT and re.fullmatch(r"\d+", value):
            tunnel[_TUNNEL_INT[key]] = int(value)
        elif key in _TUNNEL_TEXT:
            tunnel[_TUNNEL_TEXT[key]] = value
    return [t for t in tunnels if t["system_ip"] or t["tx_pkts"] is not None]


# --------------------------------------------------------------------------
# show sdwan bfd history
# --------------------------------------------------------------------------

_HISTORY_DATE = re.compile(r"^(\d{2})/(\d{2})/(\d{2})$")
_HISTORY_TIME = re.compile(r"^\d{2}:\d{2}:\d{2}$")


def parse_bfd_history(lines: list[str]) -> list[dict[str, Any]]:
    """One row per BFD state record: SYSTEM IP, SITE ID, COLOR, STATE, DST PUBLIC IP / PORT, ENCAP, TIME, RX PKTS, TX PKTS, DEL.

    The row is anchored on the date and time columns (the destination address is IPv4 or IPv6 and the color is one word), so a
    wider address does not move the later columns.  ``time`` is an ISO string, ``deleted`` is the DEL column as an integer.
    """
    rows: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if len(parts) < 12 or not is_ip(parts[0]) or parts[3] not in ("up", "down", "init", "invalid", "inactive", "admin-down"):
            continue
        at = next((i for i in range(7, len(parts) - 4) if _HISTORY_DATE.match(parts[i]) and _HISTORY_TIME.match(parts[i + 1])), None)
        if at is None:
            continue
        tail = parts[at + 2:at + 5]
        if len(tail) < 3 or not all(item.isdigit() for item in tail):
            continue
        month, day, year = (int(x) for x in _HISTORY_DATE.match(parts[at]).groups())  # type: ignore[union-attr]
        try:
            moment = datetime.strptime(f"{2000 + year:04d}-{month:02d}-{day:02d} {parts[at + 1]}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        rows.append({
            "system_ip": parts[0], "site_id": parts[1], "color": parts[2], "state": parts[3], "dst_ip": parts[4], "dst_port": parts[5],
            "encap": parts[at - 1], "time": moment.isoformat(), "rx_pkts": int(tail[0]), "tx_pkts": int(tail[1]), "deleted": int(tail[2]),
        })
    return rows


def summarize_bfd_history(rows: list[dict[str, Any]], window: float = 10.0) -> dict[str, Any]:
    """Per session counts and the moments at which several sessions went down together.

    The unit is the remote TLOC: system IP, color and destination address (the output has no local color, so tunnels from different local
    TLOCs to the same remote TLOC share one entry).  The destination port is not part of the key because a remote router that restarts or
    re-maps its NAT comes back on another port (the real capture shows 12426 and 12406 on the same address).  A *drop* is a down record with ``DEL 0`` that carries
    packet counters: the session had been exchanging BFD packets and stopped.  A down record with zero counters and ``DEL 0`` is a
    session that did not come up (or the first state after a restart) and is counted as ``attempts``; ``DEL 1`` records are the deletion
    marker described in the module doc and only counted as ``teardowns``.  Drops of different sessions at most ``window`` seconds
    apart (chained) form one *burst*.
    """
    sessions: dict[tuple[str, str, str], dict[str, Any]] = {}
    drops: list[tuple[datetime, tuple[str, str, str]]] = []
    for row in rows:
        key = (row["system_ip"], row["color"], row["dst_ip"])
        item = sessions.get(key)
        if item is None:
            item = {"system_ip": row["system_ip"], "site_id": row["site_id"], "color": row["color"], "dst_ip": row["dst_ip"], "ports": [], "encap": row["encap"],
                    "records": 0, "ups": 0, "drops": 0, "attempts": 0, "teardowns": 0, "first": row["time"], "last": row["time"], "last_state": row["state"], "last_drop": ""}
            sessions[key] = item
        item["records"] += 1
        if row["dst_port"] not in item["ports"]:
            item["ports"].append(row["dst_port"])
        if row["time"] < item["first"]:
            item["first"] = row["time"]
        if row["time"] >= item["last"]:
            item["last"], item["last_state"] = row["time"], row["state"]
        if row["state"] == "up":
            item["ups"] += 1
        elif row["state"] == "down":
            if row["deleted"]:
                item["teardowns"] += 1
            elif row["rx_pkts"] or row["tx_pkts"]:
                item["drops"] += 1
                item["last_drop"] = max(item["last_drop"], row["time"])
                drops.append((datetime.fromisoformat(row["time"]), key))
            else:
                item["attempts"] += 1
    drops.sort()
    bursts: list[dict[str, Any]] = []
    group: list[tuple[datetime, tuple[str, str, str]]] = []
    for entry in drops + [(datetime.max, ("", "", ""))]:
        if group and (entry[0] - group[-1][0]).total_seconds() > window:
            members = {k for _, k in group}
            if len(members) >= 2:
                bursts.append({"time": group[0][0].isoformat(), "sessions": len(members), "colors": sorted({k[1] for k in members}), "remotes": sorted({k[0] for k in members}),
                               "seconds": round((group[-1][0] - group[0][0]).total_seconds())})
            group = []
        group.append(entry)
    times = [r["time"] for r in rows]
    return {
        "rows": len(rows), "first": min(times) if times else "", "last": max(times) if times else "", "sessions": sorted(sessions.values(), key=lambda s: (-s["drops"], s["system_ip"], s["color"])),
        "drops": sum(s["drops"] for s in sessions.values()), "bursts": bursts,
    }


def days_between(start: str, end: datetime) -> float | None:
    """Days from an ISO stamp to ``end`` (negative when the stamp is later)."""
    if not start:
        return None
    try:
        return (end - datetime.fromisoformat(start)) / timedelta(days=1)
    except ValueError:
        return None
