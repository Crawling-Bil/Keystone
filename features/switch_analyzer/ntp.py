"""Time synchronisation read from ``show ntp status`` / ``show ntp associations`` (Cisco IOS XE, Aruba AOS-CX) and ``display ntp status`` /
``display ntp sessions`` (Huawei VRP).

A switch with a wrong clock stamps every log line, every AAA accounting record and every SNMP trap with a time nobody can correlate.  Audit rules for
financial institutions (OJK POJK 11/2022 on IT security, PCI DSS v4.0 requirement 10.6 "time synchronization") ask for synchronised clocks, and NTP's own
best practice asks for several independent sources so one bad server is outvoted (RFC 8633, section 3).  The configuration says which servers are
*configured*; only these commands say whether the clock is *synchronised* and which server is actually used.

Layouts were read from captures of ours:

* IOS XE (Catalyst 9300 17.3, ASR1002-X): ``Clock is synchronized, stratum 4, reference is 172.17.254.254``, ``clock offset is -5.5000 msec``,
  ``system poll interval is 512, last update was 349 sec ago.``; associations ``address ref clock st when poll reach delay offset disp`` where the first
  characters are the selection flag (``*`` sys.peer, ``#`` selected, ``+`` candidate, ``-`` outlyer, ``x`` falseticker) and ``~`` (configured).  A
  server with ``st 16``, ``reach 0`` and ``.TIME.`` is configured but never answered.
* AOS-CX (6200F, 10.16): ``NTP Server : 172.17.254.254 at stratum 4``, ``Time accuracy : Within 0.009969 seconds``; associations
  ``ID NAME REMOTE REF-ID ST LAST POLL REACH`` with ``*`` / ``+`` flags.
* Huawei VRP V600R025C00: ``clock status: synchronized``, ``clock stratum: 2``, ``clock offset: 0.0000 ms``; ``display ntp sessions`` prints one
  ``clock source: <address>`` block per server (format taken from the command reference in the project's Huawei Official Reference folder).

Sources:

* Cisco IOS XE, Setting Time and Calendar Services (NTP):
  https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/configuration/xe-16/bsm-xe-16-book/bsm-time-calendar-set.html
* IETF RFC 8633, Network Time Protocol Best Current Practices: https://www.rfc-editor.org/rfc/rfc8633
* PCI DSS v4.0, requirement 10.6 (time synchronization): https://www.pcisecuritystandards.org/document_library/
* Huawei CloudEngine S-series V600R025C00 Command Reference, "NTP Configuration Commands" (display ntp status / display ntp sessions):
  https://support.huawei.com/enterprise/en/index.html
"""
from __future__ import annotations

import re
from typing import Any

from . import capture_text

DOCS = {
    "cisco": "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/configuration/xe-16/bsm-xe-16-book/bsm-time-calendar-set.html",
    "rfc": "https://www.rfc-editor.org/rfc/rfc8633",
}

PATTERN_STATUS = (r"sh(?:ow)? ntp status", r"dis(?:play)? ntp status", r"dis(?:play)? ntp-service status")
PATTERN_PEERS = (r"sh(?:ow)? ntp associations", r"sh(?:ow)? ntp peer-status", r"dis(?:play)? ntp sessions", r"dis(?:play)? ntp-service sessions")

_IOS_STATUS = re.compile(r"^Clock is (?P<sync>synchronized|unsynchronized),\s*stratum (?P<st>\d+)(?:,\s*reference is (?P<ref>\S+)|,\s*no reference clock)?", re.IGNORECASE)
_IOS_OFFSET = re.compile(r"clock offset is (?P<v>-?[\d.]+) msec", re.IGNORECASE)
_IOS_POLL = re.compile(r"system poll interval is (?P<poll>\d+),\s*last update was (?P<ago>\d+) sec ago", re.IGNORECASE)
_CX_ENABLED = re.compile(r"^\s*NTP\s*:\s*(?P<v>Enabled|Disabled)", re.IGNORECASE)
_CX_SERVER = re.compile(r"^\s*NTP Server\s*:\s*(?P<ref>\S+)\s+at stratum (?P<st>\d+)", re.IGNORECASE)
_CX_ACCURACY = re.compile(r"^\s*Time accuracy\s*:\s*Within (?P<v>[\d.]+) seconds", re.IGNORECASE)
_VRP_STATUS = re.compile(r"^\s*clock status:\s*(?P<v>\S+)", re.IGNORECASE)
_VRP_STRATUM = re.compile(r"^\s*clock stratum:\s*(?P<v>\d+)", re.IGNORECASE)
_VRP_REF = re.compile(r"^\s*reference clock ID:\s*(?P<v>.+?)\s*$", re.IGNORECASE)
_VRP_OFFSET = re.compile(r"^\s*clock offset:\s*(?P<v>-?[\d.]+)\s*ms", re.IGNORECASE)

# `*~172.28.254.254  10.126.45.5  4  979  1024  377  1.000  -1.500  1.974`   (flag, configured mark, address, ref clock, st, when, poll, reach, delay, offset, disp)
_IOS_PEER = re.compile(r"^(?P<flag>[ *#+\-xo.])(?P<cfg>~?)(?P<addr>[0-9A-Za-z:._\-]+)\s+(?P<ref>\S+)\s+(?P<st>\d+)\s+(?P<when>\S+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s+"
                       r"(?P<delay>-?[\d.]+)\s+(?P<offset>-?[\d.]+)\s+(?P<disp>[\d.]+)")
# `* 1  172.17.254.254  172.17.254.254   172.17.59.10  4  690 1024   377`
_CX_PEER = re.compile(r"^(?P<flag>[ *#+\-x]?)\s*(?P<id>\d+)\s+(?P<name>\S+)\s+(?P<addr>\S+)\s+(?P<ref>\S+)\s+(?P<st>\d+)\s+(?P<when>\S+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s*$")

# NX-OS `show ntp peer-status`:  `*172.17.254.254   0.0.0.0   3   64   377   0.00076management`  (the delay runs into the VRF name)
_NXOS_PEER = re.compile(r"^(?P<flag>[*+\-=])(?P<addr>\S+)\s+(?P<local>\S+)\s+(?P<st>\d+)\s+(?P<poll>\d+)\s+(?P<reach>\d+)\s+(?P<delay>\d+\.\d{5})(?P<vrf>\S*)\s*$")

_FLAG = {"*": "sys.peer (in use)", "#": "selected", "+": "candidate", "-": "outlyer", "x": "falseticker", "o": "PPS peer", ".": "excess"}


def _ok(block: list[str]) -> bool:
    return bool(block) and not re.match(r"^\s*(?:%|\^|invalid\b|unknown\b|error\b|unrecognized\b)", block[0], re.IGNORECASE)


def _num(text: str | None) -> float | None:
    try:
        return float(text) if text is not None else None
    except ValueError:
        return None


def parse_status(block: list[str]) -> dict[str, Any]:
    """``{"dialect", "synchronized" (True / False / None), "stratum", "reference", "offset_ms", "poll", "last_update_s", "enabled"}``; ``{}`` when nothing was read."""
    out: dict[str, Any] = {}
    for line in block:
        text = line.strip()
        match = _IOS_STATUS.match(text)
        if match:
            out.update(dialect="ios", synchronized=match.group("sync").lower() == "synchronized", stratum=int(match.group("st")), reference=match.group("ref") or "")
            continue
        match = _IOS_OFFSET.search(text)
        if match:
            out["offset_ms"] = _num(match.group("v"))
        match = _IOS_POLL.search(text)
        if match:
            out["poll"], out["last_update_s"] = int(match.group("poll")), int(match.group("ago"))
        match = _CX_ENABLED.match(line)
        if match:
            out.update(dialect="aoscx", enabled=match.group("v").lower() == "enabled")
            out.setdefault("synchronized", None)
            continue
        match = _CX_SERVER.match(line)
        if match:
            out.update(dialect="aoscx", synchronized=True, stratum=int(match.group("st")), reference=match.group("ref"))
            continue
        match = _CX_ACCURACY.match(line)
        if match:
            out["offset_ms"] = round(float(match.group("v")) * 1000, 3)
            continue
        if re.search(r"\b(?:not synchronized|unsynchronized)\b", text, re.IGNORECASE) and out.get("dialect") == "aoscx":
            out["synchronized"] = False
        match = _VRP_STATUS.match(line)
        if match:
            out.update(dialect="vrp", synchronized=match.group("v").lower().rstrip(",") == "synchronized")
            continue
        match = _VRP_STRATUM.match(line)
        if match:
            out["stratum"] = int(match.group("v"))
            continue
        match = _VRP_REF.match(line)
        if match:
            out["reference"] = "" if match.group("v").lower() == "none" else match.group("v")
            continue
        match = _VRP_OFFSET.match(line)
        if match:
            out["offset_ms"] = _num(match.group("v"))
    return out if out.get("dialect") else {}


def _peer_row(address: str, flag: str, configured: bool, ref: str, stratum: int, when: str, poll: int | str, reach: int, delay: float | None, offset: float | None) -> dict[str, Any]:
    return {"address": address, "state": _FLAG.get(flag, ""), "configured": configured, "ref": ref, "stratum": stratum, "when": when, "poll": poll,
            "reach": reach, "delay_ms": delay, "offset_ms": offset, "usable": reach > 0 and 0 < stratum < 16}


def parse_peers(block: list[str]) -> list[dict[str, Any]]:
    """The time sources of ``show ntp associations`` (IOS XE, AOS-CX) or ``display ntp sessions`` (VRP), one dict per source."""
    peers: list[dict[str, Any]] = []
    vrp: dict[str, str] | None = None

    def close_vrp() -> None:
        if vrp and vrp.get("address"):
            status = vrp.get("status", "")
            flag = "*" if "master" in status else "+" if "candidate" in status else "#" if "selected" in status else ""
            reach = int(vrp["reach"]) if vrp.get("reach", "").isdigit() else 0
            peers.append(_peer_row(vrp["address"], flag, "configured" in status, vrp.get("ref", ""), int(vrp["stratum"]) if vrp.get("stratum", "").isdigit() else 16,
                                   vrp.get("now", ""), vrp.get("poll", ""), reach, _num(vrp.get("delay")), _num(vrp.get("offset"))))
            peers[-1]["usable"] = reach > 0 and "unsynced" not in status and "invalid" not in status and "insane" not in status and peers[-1]["stratum"] < 16

    for line in block:
        text = line.rstrip()
        source = re.match(r"^\s*clock source:\s*(\S+)", text, re.IGNORECASE)
        if source:
            close_vrp()
            vrp = {"address": source.group(1)}
            continue
        if vrp is not None:
            field = re.match(r"^\s*(clock stratum|clock status|reference clock ID|reach|current poll|now|offset|delay|disper):\s*(.+?)\s*$", text, re.IGNORECASE)
            if field:
                key = {"clock stratum": "stratum", "clock status": "status", "reference clock id": "ref", "reach": "reach", "current poll": "poll", "now": "now",
                       "offset": "offset", "delay": "delay", "disper": "disper"}[field.group(1).lower()]
                value = field.group(2)
                vrp[key] = re.sub(r"\s*ms$", "", value) if key in ("offset", "delay", "disper") else value.lower() if key == "status" else value
            continue
        match = _NXOS_PEER.match(text)
        if match:
            row = _peer_row(match.group("addr"), "*" if match.group("flag") == "*" else "+" if match.group("flag") == "+" else "", True, "", int(match.group("st")), "",
                            int(match.group("poll")), int(match.group("reach")), float(match.group("delay")) * 1000, None)
            row["vrf"] = match.group("vrf")
            row["nxos"] = True
            peers.append(row)
            continue
        match = _IOS_PEER.match(text)
        if match:
            peers.append(_peer_row(match.group("addr"), match.group("flag"), bool(match.group("cfg")), match.group("ref"), int(match.group("st")), match.group("when"),
                                   int(match.group("poll")), int(match.group("reach")), _num(match.group("delay")), _num(match.group("offset"))))
            continue
        match = _CX_PEER.match(text)
        if match:
            peers.append(_peer_row(match.group("addr"), match.group("flag").strip(), True, match.group("ref"), int(match.group("st")), match.group("when"),
                                   int(match.group("poll")), int(match.group("reach")), None, None))
    close_vrp()
    return peers


def read(clean: list[str], host: str | None = None) -> dict[str, Any]:
    """``{"status": {...}, "peers": [...], "commands": [...]}``; the last good block of each command wins."""
    def keep(index: int) -> bool:
        return host is None or capture_text.prompt_host(clean[index]) in (None, host)

    status: dict[str, Any] = {}
    for index, block in capture_text.find_blocks(clean, PATTERN_STATUS):
        if keep(index) and _ok(block):
            parsed = parse_status(block)
            if parsed:
                status = parsed
    peers: list[dict[str, Any]] = []
    for index, block in capture_text.find_blocks(clean, PATTERN_PEERS):
        if keep(index) and _ok(block):
            parsed_peers = parse_peers(block)
            if parsed_peers:
                peers = parsed_peers
    if not status and peers and all(peer.get("nxos") for peer in peers):
        # NX-OS has no overall status in peer-status: the clock is synchronised when a peer is marked "selected for sync" (*).
        chosen = next((peer for peer in peers if peer["state"].startswith("sys.peer")), None)
        status = {"dialect": "nxos", "synchronized": chosen is not None, "stratum": chosen["stratum"] + 1 if chosen else 16, "reference": chosen["address"] if chosen else ""}
    commands = [name for name, part in (("ntp status", status), ("ntp associations", peers)) if part]
    return {"status": status, "peers": peers, "commands": commands}


def findings(view: dict[str, Any]) -> list[dict[str, Any]]:
    from features.analyzer_core.findings import finding

    out: list[dict[str, Any]] = []
    status, peers = view.get("status") or {}, view.get("peers") or []
    unsynchronized = status.get("synchronized") is False
    usable = {peer["address"] for peer in peers if peer["usable"]}
    listed = {peer["address"] for peer in peers}
    if unsynchronized:
        out.append(finding(
            "SW-NTP-001", "high", "Time", "The clock is not synchronised to any NTP server",
            obj="ntp",
            detail=(f"The device reports an unsynchronised clock (stratum {status.get('stratum', 16)}"
                    + (f"; {len(peers)} source(s) listed, none reachable" if peers and not usable else "")
                    + "). Every log line, AAA accounting record and SNMP trap carries a time that cannot be correlated with other devices, which fails the time-synchronisation "
                      "requirement of audit standards."),
            recommendation="Check that the configured NTP servers are reachable from the management VRF / interface (`ping`, ACLs on UDP 123, `ntp source`), that the stratum of the "
                           "server is below 16, and read `show ntp associations` for the servers that stay at reach 0.",
            reference=DOCS["cisco"]))
    elif peers and not usable:
        out.append(finding(
            "SW-NTP-002", "medium", "Time", f"None of the {len(listed)} configured NTP server(s) is usable",
            obj="ntp", detail="Every source shows reach 0 or stratum 16, so the clock is running free even though NTP is configured.",
            recommendation="Verify reachability of the servers (UDP 123, VRF, source interface) and that they are synchronised themselves.", reference=DOCS["cisco"]))
    if listed and len(usable) == 1 and not unsynchronized:
        only = next(iter(usable))
        out.append(finding(
            "SW-NTP-003", "low", "Time", "Only one NTP server is usable",
            obj="ntp", detail=(f"{only} is the only source that answers ({len(listed)} configured). With a single source NTP cannot detect a server that is wrong; RFC 8633 asks for "
                               "several independent sources (at least three, four recommended)."),
            recommendation="Configure at least two more independent servers (different upstream clocks) and confirm each reaches `reach 377`.", reference=DOCS["rfc"]))
    dead = sorted(listed - usable)
    if usable and dead:
        out.append(finding(
            "SW-NTP-004", "low", "Time", f"{len(dead)} configured NTP server(s) never answer",
            obj="ntp", detail="No reply (reach 0 / stratum 16) from: " + ", ".join(dead[:8]) + (" ..." if len(dead) > 8 else "") + ". The clock is still synchronised by the others, "
                              "but the redundancy the configuration promises is not there.",
            recommendation="Fix the path to these servers or remove them from the configuration.", reference=DOCS["cisco"]))
    offset = status.get("offset_ms")
    if isinstance(offset, (int, float)) and abs(offset) >= 500 and not unsynchronized:
        out.append(finding(
            "SW-NTP-005", "medium", "Time", f"The clock is {offset:+.1f} ms away from its NTP server",
            obj="ntp", detail="A synchronised clock normally stays within a few milliseconds. An offset this large is corrected by stepping or slewing and suggests a jittery path or a poor server.",
            recommendation="Check the path delay and the server stratum (`show ntp associations`).", reference=DOCS["cisco"]))
    if status.get("enabled") is False:
        out.append(finding(
            "SW-NTP-006", "medium", "Time", "NTP is disabled on this device",
            obj="ntp", detail="`show ntp status` reports NTP as Disabled; the clock is set by hand or by the hardware clock only.",
            recommendation="Enable NTP and configure the corporate time servers.", reference=DOCS["cisco"]))
    return out


def tables(view: dict[str, Any]) -> list[dict[str, Any]]:
    status, peers = view.get("status") or {}, view.get("peers") or []
    out: list[dict[str, Any]] = []
    rows: list[dict[str, str]] = []

    def add(label: str, value: Any) -> None:
        if value not in (None, ""):
            rows.append({"item": label, "value": str(value)})

    if status:
        sync = status.get("synchronized")
        add("Clock", "synchronized" if sync else "unsynchronized" if sync is False else "")
        add("Stratum", status.get("stratum"))
        add("Reference", status.get("reference"))
        add("Offset", f"{status['offset_ms']} ms" if status.get("offset_ms") is not None else "")
        add("Poll interval", f"{status['poll']} s" if status.get("poll") else "")
        add("Last update", f"{status['last_update_s']} s ago" if status.get("last_update_s") is not None else "")
        if status.get("enabled") is not None:
            add("NTP", "enabled" if status["enabled"] else "disabled")
    if rows:
        out.append({"tab": "health", "id": "ntp-status", "title": "Time synchronisation (NTP)",
                    "hint": "From show ntp status / display ntp status. A stack or switch should be synchronised to a server of stratum 2 to 4.",
                    "columns": [{"key": "item", "label": "Item"}, {"key": "value", "label": "Value"}], "rows": rows})
    if peers:
        out.append({"tab": "health", "id": "ntp-peers", "title": "NTP servers",
                    "hint": "From show ntp associations / display ntp sessions. A server with reach 0 or stratum 16 never answered; several independent usable servers are expected.",
                    "columns": [{"key": "address", "label": "Server"}, {"key": "state", "label": "Selection"}, {"key": "ref", "label": "Reference"}, {"key": "stratum", "label": "Stratum"},
                                {"key": "when", "label": "Last poll"}, {"key": "poll", "label": "Poll"}, {"key": "reach", "label": "Reach"}, {"key": "delay_ms", "label": "Delay (ms)"},
                                {"key": "offset_ms", "label": "Offset (ms)"}, {"key": "usable", "label": "Usable"}],
                    "rows": [{**peer, "usable": "yes" if peer["usable"] else "no"} for peer in peers]})
    return out


def counts(view: dict[str, Any]) -> dict[str, int]:
    return {"ntp_status": 1 if view.get("status") else 0, "ntp_peers": len(view.get("peers") or [])}
