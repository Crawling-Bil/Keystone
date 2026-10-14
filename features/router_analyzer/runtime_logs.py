"""``show logging``: logging settings and a digest of the buffered messages.

A router buffer can hold hundreds of thousands of lines (the captures this
was written against hold 8,400 to 172,000), so the parser never keeps the
messages themselves.  It counts per message mnemonic and extracts the few
event families an engineer actually reads: link and tunnel flaps, routing
adjacency changes, IP SLA / track transitions, configuration changes, failed
and successful logins, IPsec packets with an unknown SPI, IKE deletions,
licence throughput warnings and Smart Licensing failures.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

_MESSAGE = re.compile(
    r"^(?:\d+:\s*)?(?P<mark>[*.>])?(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Za-z]{2,5})?)?:?\s*"
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d)-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<text>.*)$"
)
# IOS-XE in controller mode prints SD-WAN daemon messages as
# ``%Cisco-SDWAN-<hostname>-<DAEMON>-<severity>-<TAG>-<code>: text`` (the hostname may contain hyphens).
_SDWAN_MESSAGE = re.compile(
    r"^(?:\d+:\s*)?(?P<mark>[*.>])?(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+)?\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Za-z]{2,5})?)?:?\s*"
    r"%Cisco-SDWAN-(?P<host>.+?)-(?P<daemon>[A-Z][A-Z0-9]*)-(?P<severity>\d)-(?P<tag>[A-Z]+)-(?P<code>\d+):\s*(?P<text>.*)$"
)
_OMP_PEER = re.compile(r"(vSmart|vManage) peer (\S+) state changed to (\w+)")
_OMP_COUNT = re.compile(r"Number of vSmarts connected\s*:\s*(\d+)")
# Facility/mnemonic pairs that point at a process or memory fault.  Cisco's own wording for
# each is in the IOS-XE system message guide; the finding says "indicator", not "crash".
_FAULT_TAGS = {
    "SYS-MALLOCFAIL": "memory allocation failure",
    "SYS-CPUHOG": "process held the CPU too long",
    "SYS-WATCHDOG": "watchdog",
}
SEVERITY_NAME = {0: "emergencies", 1: "alerts", 2: "critical", 3: "errors", 4: "warnings", 5: "notifications", 6: "informational", 7: "debugging"}

_LEVEL = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7}
MAX_EVENT_ROWS = 400


def severity_number(level: str) -> int | None:
    return _LEVEL.get((level or "").strip().lower())


def _settings(head: list[str]) -> dict[str, Any]:
    text = "\n".join(head)
    out: dict[str, Any] = {}
    match = re.search(r"Syslog logging:\s*(\w+)\s*\((\d+) messages dropped, (\d+) messages rate-limited, (\d+) flushes, (\d+) overruns", text)
    if match:
        out["enabled"] = match.group(1).lower() == "enabled"
        out["dropped"], out["rate_limited"] = int(match.group(2)), int(match.group(3))
    for key, label in (("console", "Console logging"), ("monitor", "Monitor logging"), ("buffer", "Buffer logging")):
        match = re.search(rf"{label}:\s*(?:level (\w+),\s*(\d+) messages? logged|disabled)", text)
        if match:
            out[key] = {"level": match.group(1) or "disabled", "logged": int(match.group(2) or 0)}
    match = re.search(r"Trap logging:\s*level (\w+),\s*(\d+) message lines logged", text)
    if match:
        out["trap"] = {"level": match.group(1), "logged": int(match.group(2))}
    match = re.search(r"Persistent logging:\s*(\w+)", text)
    if match:
        out["persistent"] = match.group(1).lower() != "disabled"
    match = re.search(r"Log Buffer \((\d+) bytes\)", text)
    if match:
        out["buffer_bytes"] = int(match.group(1))
    hosts = []
    for host in re.finditer(r"Logging to (\S+)\s+\((?:udp|tcp|tls) port (\d+)[^)]*?(?:,\s*audit \w+)?(?:,\s*(link \w+))?\)(?:,\s*(\d+) message lines logged,\s*(\d+) message lines rate-limited,\s*(\d+) message lines dropped-by-MD)?", text, re.S):
        hosts.append({"host": host.group(1), "port": host.group(2), "link": (host.group(3) or "").strip(), "logged": int(host.group(4) or 0), "dropped": int(host.group(6) or 0)})
    out["hosts"] = hosts
    match = re.search(r"Logging Source-Interface:\s*(\S+)", text)
    if match and not match.group(1).startswith("VRF"):
        out["source_interface"] = match.group(1)
    return out


def _flap(table: dict[str, dict[str, Any]], key: str, state: str, ts: str, reason: str = "") -> None:
    row = table.setdefault(key, {"down": 0, "up": 0, "first": ts, "last": ts, "events": 0, "reasons": {}})
    row["events"] += 1
    if state in ("down", "Down", "administratively down"):
        row["down"] += 1
        if reason:
            row["reasons"][reason] = row["reasons"].get(reason, 0) + 1
    elif state in ("up", "Up", "FULL", "Established"):
        row["up"] += 1
    row["last"] = ts or row["last"]
    row["first"] = row["first"] or ts


def parse_logging(lines: list[str]) -> dict[str, Any]:
    """Settings and event digest of ``show logging``."""
    if not lines or not any(re.search(r"Syslog logging|Log Buffer|%[A-Z0-9_]+-\d-", line) for line in lines[:60]):
        return {}
    split = next((i for i, line in enumerate(lines) if line.startswith("Log Buffer")), min(len(lines), 60))
    out: dict[str, Any] = {"settings": _settings(lines[: split + 1])}

    mnemonics: dict[tuple[str, int, str], dict[str, Any]] = {}
    severity_counts: Counter = Counter()
    flaps: dict[str, dict[str, dict[str, Any]]] = {"interfaces": {}, "tracks": {}, "ospf": {}, "bgp": {}, "omp": {}}
    omp_vsmarts: list[int] = []
    crashes: list[dict[str, str]] = []
    changes: list[dict[str, str]] = []
    failures: dict[tuple[str, str, str], int] = defaultdict(int)
    logins: Counter = Counter()
    login_users: Counter = Counter()
    spi_sources: Counter = Counter()
    spi_targets: Counter = Counter()
    spi_interfaces: Counter = Counter()
    ike_deletes: Counter = Counter()
    bandwidth: list[dict[str, Any]] = []
    smart_license = 0
    restarts: list[dict[str, str]] = []
    total = 0
    first = last = ""

    for line in lines[split + 1:]:
        match = _MESSAGE.match(line)
        if match:
            ts, facility, severity, mnemonic, text = (match.group("ts") or "").strip(), match.group("facility"), int(match.group("severity")), match.group("mnemonic"), match.group("text")
        else:
            match = _SDWAN_MESSAGE.match(line)
            if not match:
                continue
            ts, facility, severity, mnemonic, text = (match.group("ts") or "").strip(), f"SDWAN-{match.group('daemon')}", int(match.group("severity")), f"{match.group('tag')}-{match.group('code')}", match.group("text")
        total += 1
        first = first or ts
        last = ts or last
        severity_counts[severity] += 1
        key = (facility, severity, mnemonic)
        row = mnemonics.get(key)
        if row is None:
            mnemonics[key] = {"facility": facility, "severity": severity, "mnemonic": mnemonic, "count": 1, "first": ts, "last": ts, "example": text[:240]}
        else:
            row["count"] += 1
            row["last"] = ts or row["last"]

        tag = f"{facility}-{mnemonic}"
        if tag in ("LINEPROTO-UPDOWN", "LINK-UPDOWN"):
            m = re.search(r"Interface (\S+), changed state to (.+)$", text)
            if m:
                _flap(flaps["interfaces"], m.group(1), m.group(2).strip(), ts)
        elif tag == "TRACK-STATE":
            m = re.match(r"(\d+) (.+?) (Up|Down) -> (Up|Down)", text)
            if m:
                _flap(flaps["tracks"], f"track {m.group(1)} ({m.group(2)})", m.group(4), ts)
        elif tag == "OSPF-ADJCHG":
            m = re.match(r"Process (\d+), Nbr (\S+) on (\S+) from (\w+) to (\w+)(?:, (.*))?", text)
            if m:
                reason = (m.group(6) or "").replace("Neighbor Down:", "").strip()
                _flap(flaps["ospf"], f"{m.group(2)} on {m.group(3)}", "FULL" if m.group(5) == "FULL" else ("down" if m.group(5) == "DOWN" else "other"), ts, reason)
        elif tag in ("BGP-ADJCHANGE", "BGP_SESSION-ADJCHANGE"):
            m = re.match(r"neighbor (\S+) (?:vpn vrf (\S+) )?(?:IPv4 Unicast topology base removed from session\s+)?(Up|Down)?\s*(.*)$", text)
            if m and m.group(3):
                _flap(flaps["bgp"], m.group(1) + (f" (vrf {m.group(2)})" if m.group(2) else ""), m.group(3), ts, m.group(4).strip())
        elif tag == "SYS-CONFIG_I":
            m = re.match(r"Configured from (\S+) by (\S+)(?: on (\S+) \(([^)]+)\))?", text)
            if m and len(changes) < MAX_EVENT_ROWS:
                changes.append({"time": ts, "from": m.group(1), "user": m.group(2), "line": m.group(3) or "", "source": m.group(4) or ""})
        elif tag == "SEC_LOGIN-LOGIN_FAILED":
            m = re.search(r"\[user: ([^\]]*)\] \[Source: ([^\]]*)\].*?\[Reason: ([^\]]*)\]", text)
            if m:
                failures[(m.group(2), m.group(1), m.group(3))] += 1
        elif tag == "SEC_LOGIN-LOGIN_SUCCESS":
            m = re.search(r"\[user: ([^\]]*)\] \[Source: ([^\]]*)\]", text)
            if m:
                logins[m.group(2)] += 1
                login_users[m.group(1)] += 1
        elif tag == "CRYPTO-RECVD_PKT_INV_SPI":
            m = re.search(r"destaddr=(\S+), prot=(\d+), spi=\S+, srcaddr=(\S+), input interface=(\S+)", text)
            if m:
                spi_targets[m.group(1)] += 1
                spi_sources[m.group(3)] += 1
                spi_interfaces[m.group(4)] += 1
        elif tag == "CRYPTO-ISAKMP_MANUAL_DELETE":
            m = re.search(r"clear crypto sa peer (\S+?)'", text)
            if m:
                ike_deletes[m.group(1)] += 1
        elif facility == "BW_LICENSE":
            m = re.search(r"licensed bandwidth of (\d+) (\w+) during (\d+) sampling periods", text)
            if m:
                bandwidth.append({"time": ts, "mnemonic": mnemonic, "limit": f"{m.group(1)} {m.group(2)}", "periods": int(m.group(3)), "level": "max" if "MAX" in mnemonic else "threshold"})
        elif tag == "SMART_LIC-COMM_FAILED":
            smart_license += 1
        elif tag in ("SYS-RESTART", "SYS-RELOAD", "SYS-RESTART_REASON") and len(restarts) < 40:
            restarts.append({"time": ts, "message": text[:160], "kind": "reload requested" if tag == "SYS-RELOAD" else "restart"})
        elif facility == "SDWAN-OMPD":
            peer = _OMP_PEER.search(text)
            count = _OMP_COUNT.search(text)
            if peer:
                state = peer.group(3)
                # Up = healthy; Init / Down / Invalid = peer lost; Handshake is the step in between.
                _flap(flaps["omp"], f"{peer.group(1)} peer {peer.group(2)}", "up" if state == "Up" else ("other" if state == "Handshake" else "down"), ts, state)
            elif count:
                omp_vsmarts.append(int(count.group(1)))
        if len(crashes) < 40:
            kind = ""
            if facility == "PMAN" and "FAIL" in mnemonic:
                kind = "process failure"
            elif tag in _FAULT_TAGS:
                kind = _FAULT_TAGS[tag]
            elif "Traceback" in text or "-Traceback=" in text:
                kind = "software traceback"
            if kind:
                crashes.append({"time": ts, "tag": tag, "kind": kind, "message": text[:200]})

    out.update({
        "message_count": total, "first": first, "last": last,
        "by_severity": {SEVERITY_NAME[n]: severity_counts[n] for n in sorted(severity_counts)},
        "mnemonics": sorted(mnemonics.values(), key=lambda r: (-r["count"], r["mnemonic"]))[:60],
        "flaps": {kind: table for kind, table in flaps.items() if table},
        "config_changes": changes,
        "login_failures": [{"source": s, "user": u, "reason": r, "count": n} for (s, u, r), n in sorted(failures.items(), key=lambda kv: -kv[1])[:30]],
        "logins": {"count": sum(logins.values()), "sources": dict(logins.most_common(10)), "users": dict(login_users.most_common(10))},
        "invalid_spi": {"count": sum(spi_sources.values()), "sources": dict(spi_sources.most_common(10)), "targets": dict(spi_targets.most_common(5)), "interfaces": dict(spi_interfaces.most_common(5))},
        "ike_deletes": dict(ike_deletes.most_common(20)),
        "license_bandwidth": bandwidth[-20:],
        "smart_license_failures": smart_license,
        "restarts": restarts,
        "crashes": crashes,
        "omp_vsmarts": {"min": min(omp_vsmarts), "last": omp_vsmarts[-1]} if omp_vsmarts else {},
        "shown_lines": int(shown.group(1)) if (shown := re.search(r"Showing last (\d+) lines", "\n".join(lines[: split + 1]))) else 0,
    })
    return out


# --------------------------------------------------------------------------
# show logging count
# --------------------------------------------------------------------------

_COUNT_ROW = re.compile(r"^(?P<facility>\S+)\s+(?P<mnemonic>\S+)\s+(?P<sev>\d)\s+(?P<occur>\d+)\s+(?P<last>.+?)\s*$")


def parse_logging_count(lines: list[str]) -> list[dict[str, Any]]:
    """Per-mnemonic lifetime occurrence counts (since the counters were last cleared, which
    can be well before the current log buffer's oldest entry) — a cross-check on the digest
    'show logging' already builds from the buffer itself, for a mnemonic that scrolled out
    of the buffer but is still tallied here."""
    rows = []
    for line in lines:
        text = line.strip()
        if not text or text.startswith("Facility"):
            continue
        m = _COUNT_ROW.match(text)
        if m:
            rows.append({"facility": m.group("facility"), "mnemonic": m.group("mnemonic"), "severity": int(m.group("sev")),
                         "severity_name": SEVERITY_NAME.get(int(m.group("sev")), ""), "occurrences": int(m.group("occur")), "last_time": m.group("last")})
    return rows
