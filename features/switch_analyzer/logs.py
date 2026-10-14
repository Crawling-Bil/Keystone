"""Log digest of one switch capture: ``show logging`` / ``display logbuffer`` / ``display trapbuffer``.

A switch buffer holds from a few dozen to several hundred thousand lines, so the
parser never keeps the messages themselves. It counts per message id and keeps
only what an engineer reads first:

* interface flaps (link down / up per port),
* the notable events grouped by family (port protection such as err-disable and
  port-security, MAC flapping, spanning tree, EtherChannel / LACP, failed logins,
  configuration changes, restarts and stack events, hardware, DHCP snooping),
* the most frequent message ids,
* the logging settings of a Cisco device (buffer size, levels, collectors),
* findings in the shared finding model (``features.analyzer_core.findings``).

Formats this was written against (real captures in this project):

* Cisco IOS / IOS XE ``show logging``: ``*Mar  7 09:51:35.109: %LINK-3-UPDOWN: ...``
  (a Catalyst 3650 and several Catalyst 9300 / 2960 captures; the oldest line comes first),
* Huawei VRP ``display logbuffer`` / ``display trapbuffer``:
  ``2026-07-01 14:54:11.728+07:00 HOST %%01IFNET/2/linkDown_active(l):CID=...;...`` (S5735; the newest line comes first).

Written from the vendor's documentation and **not yet checked against a real capture**:
NX-OS ``show logging`` (same ``%FAC-SEV-MNEM`` layout as IOS) and the ArubaOS-Switch
event log (``W 01/15/26 10:12:33 00076 ports: ...``). The result says so in ``validated``.
"""
from __future__ import annotations

import re
from collections import Counter, deque
from typing import Any

from features.analyzer_core.findings import finding
from features.analyzer_core.logtime import log_window

from . import aoscx, aoscx_logs, capture_text

SEVERITY_NAME = {0: "emergencies", 1: "alerts", 2: "critical", 3: "errors", 4: "warnings", 5: "notifications", 6: "informational", 7: "debugging"}
MAX_EVENTS_PER_FAMILY = 150
MAX_FLAPS = 100
MAX_TOP = 40

# Documentation cited by the findings (opened and read on 2026-10-12).
DOCS = {
    "syslog": ("Cisco IOS XE 17.9.x System Message Guide", "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/17_xe/syslogs/17-9-x/b-system-message-guide-17-9-x.html"),
}

# ---------------------------------------------------------------- commands

_LOG_COMMANDS = {
    "cisco": [r"sh(?:ow)? logg?(?:i(?:n(?:g)?)?)?(?: (?:last \d+|logfile|buffered?|nvram|-{1,2}[a-z]+|\d+))*"],
    # AOS-CX: `show logging` is validated on real captures; `show events` is the name older releases use (not seen in a capture)
    # Flags (and the value a flag takes) only: Cisco's `show event manager policy registered` must not read as an event log.
    "aoscx": [r"sh(?:ow)? events?(?: -{1,2}[a-z]+(?: [^\s-]\S*)?)*"],
    "huawei": [r"dis(?:p(?:l(?:a(?:y)?)?)?)? (?:logbuffer|trapbuffer|logfile)(?: (?:[^|\s]+))*"],
}
ALL_LOG_PATTERNS = _LOG_COMMANDS["cisco"] + _LOG_COMMANDS["huawei"] + _LOG_COMMANDS["aoscx"]

# ---------------------------------------------------------------- message formats

_CISCO = re.compile(r"%(?P<fac>[A-Z][A-Z0-9_]*)-(?P<sev>[0-7])-(?P<mnem>[A-Z][A-Z0-9_]*):\s*(?P<text>.*)$")
_HUAWEI = re.compile(r"%%\d*(?P<module>[A-Za-z][A-Za-z0-9_\-]*)/(?P<sev>[0-9])/(?P<name>[A-Za-z0-9_\-]+)(?:\((?P<kind>[a-z])\))?(?:\[\d+\])?:(?P<text>.*)$")
_ARUBA = re.compile(r"^(?P<lvl>[IWMEDX])\s+(?P<date>\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<id>\d{4,6})\s+(?P<module>[A-Za-z0-9_\-]+):\s*(?P<text>.*)$")

# NX-OS writes "2026 Sep 23 15:25:40 <hostname> %FAC-SEV-MNEM: ..." (the host name follows the clock, no zone);
# IOS writes "Oct 12 10:00:00.123 UTC: %..." (a zone is followed by a colon). Only a token followed by ":" is a zone,
# so a host name such as LABSW1 is not cut into a fake time zone.
_CISCO_TIME = re.compile(
    r"\d{4}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"|[A-Z][a-z]{2}\s+\d{1,2}(?:\s+\d{4})?\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+[A-Z]{2,5}(?=\s*:))?"
    r"|\d{2}:\d{2}:\d{2}(?:\.\d+)?"
)
_HOST_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,62}$")
_HUAWEI_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:[.:]\d+)?(?:[+-]\d{2}:\d{2})?|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{4}\s+\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?"
)
_HUAWEI_LEAD = re.compile(r"^(?:(?:CID|Service)=[^;]*;)+")
_ARUBA_LEVEL = {"I": 6, "W": 4, "M": 3, "E": 3, "D": 7, "X": 3}

# A prefix before ``%FAC-n-MNEM`` is a timestamp (and perhaps a sequence number or host name);
# anything longer or with a prompt character is ordinary text that happens to contain a %-tag.
_MAX_PREFIX = 70


def _clip(text: str, size: int = 220) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= size else text[: size - 1] + "…"


def parse_message(line: str) -> dict[str, Any] | None:
    """One syslog line -> ``{style, ts, ident, tag, sev, text}`` or None."""
    stripped = line.strip()
    if not stripped:
        return None
    if "Event|" in stripped:        # AOS-CX: <iso time> <host> <daemon>[pid]: Event|<id>|LOG_<LEVEL>|||<text>
        return aoscx.parse_event(stripped)
    match = _HUAWEI.search(stripped) if "%%" in stripped else None
    if match:
        prefix = stripped[: match.start()].strip()
        stamp = _HUAWEI_TIME.search(prefix)
        if stamp:
            ts = stamp.group(0)
        else:  # "<timestamp> <host>": drop the host (last token)
            ts = prefix.rsplit(None, 1)[0] if " " in prefix else ""
        module, name = match.group("module"), match.group("name")
        return {"style": "huawei", "ts": ts, "ident": f"{module}/{match.group('sev')}/{name}", "tag": f"{module}/{name}",
                "sev": int(match.group("sev")), "text": _HUAWEI_LEAD.sub("", match.group("text").strip()), "module": module, "name": name}
    match = _CISCO.search(stripped) if "%" in stripped else None
    if match:
        prefix = stripped[: match.start()]
        if len(prefix) <= _MAX_PREFIX and "#" not in prefix and ">" not in prefix:
            stamp = _CISCO_TIME.search(prefix)
            fac, mnem = match.group("fac"), match.group("mnem")
            rest = prefix[stamp.end():].strip().rstrip(":").strip() if stamp else ""
            message = {"style": "cisco", "ts": stamp.group(0).strip() if stamp else "", "ident": f"{fac}-{match.group('sev')}-{mnem}",
                       "tag": f"{fac}-{mnem}", "sev": int(match.group("sev")), "text": match.group("text").strip(), "module": fac, "name": mnem}
            if rest and _HOST_TOKEN.match(rest):
                message["host"] = rest
            return message
    match = _ARUBA.match(stripped)
    if match:
        module = match.group("module")
        return {"style": "aruba", "ts": f"{match.group('date')} {match.group('time')}", "ident": f"{module}-{match.group('id')}",
                "tag": module.lower(), "sev": _ARUBA_LEVEL.get(match.group("lvl"), 6), "text": match.group("text").strip(), "module": module, "name": match.group("id")}
    return None


# ---------------------------------------------------------------- families

FAMILY_LABEL = {
    "protect": "Port protection (err-disable, port-security, BPDU / loop guard, storm control)",
    "macflap": "MAC address flapping / conflict",
    "stp": "Spanning tree",
    "channel": "EtherChannel / LACP",
    "auth": "Failed logins and authentication",
    "config": "Configuration changes",
    "restart": "Restarts and stack events",
    "hardware": "Hardware, power, CPU, memory, optics",
    "l2sec": "DHCP snooping, ARP inspection, SISF",
    "mismatch": "CDP / LLDP mismatches",
    "l3": "Routing and first-hop redundancy",
    "poe": "PoE",
    "neighbor": "LLDP neighbour changes",
    "time": "NTP",
}
# Families listed in the events table. Neighbour churn and NTP stay in the frequency table only.
QUIET_FAMILIES = {"neighbor", "time"}

_CISCO_FAMILIES: list[tuple[str, re.Pattern[str]]] = [
    ("protect", re.compile(
        r"PM-ERR_(?:DISABLE|RECOVER)\w*|PM-PORT_BOUNCED|PORT_SECURITY-\w+|SPANTREE-(?:BLOCK_BPDUGUARD|LOOPGUARD_\w+|ROOTGUARD_\w+|BLOCK_PVID_\w+|BLOCK_PORT_TYPE|BPDUGUARD\w*)"
        r"|ETHCNTR-LOOPBACK_DETECTED|STORM_CONTROL-\w+|UDLD-\w+|DHCP_SNOOPING-ERRDISABLE\w*|ETHPORT-IF_ERRDIS\w*|ETHPORT-ERR_DISABLE\w*")),
    ("macflap", re.compile(r"SW_MATM-\w+|L2FM-L2FM_MAC_MOVE\w*|SWPORT-MAC_CONFLICT")),
    ("stp", re.compile(r"SPANTREE\w*-\w+|STP-\w+|MSTP-\w+|PVST\w*-\w+")),
    ("channel", re.compile(r"EC-\w+|PAGP-\w+|LACP-\w+|ETHPC-\w+|ETH_PORT_CHANNEL-\w+|PORT_CHANNEL-\w+")),
    ("auth", re.compile(r"SEC_LOGIN-\w*FAIL\w*|AAA-\w+|DOT1X-\w*FAIL\w*|AUTHMGR-\w*FAIL\w*|MAB-\w*FAIL\w*|RADIUS-\w+|TACACS\w*-\w+")),
    ("config", re.compile(r"SYS-CONFIG_I|SYS-CONFIG_P|SYS-CONFIG_NV_I|PARSER-CFGLOG_LOGGEDCMD")),
    ("restart", re.compile(r"SYS-RESTART\w*|SYS-RELOAD|SYS-REDUNDANCY\w*|SYS-SYSTEM_RESTARTED|STACKMGR-\w+|PLATFORM_STACKPOWER-\w+")),
    ("hardware", re.compile(
        r"PLATFORM_ENV-\w+|PLATFORM_POWER-\w+|ILPOWER-\w+|PLATFORM-\w+|ENVIRONMENT-\w+|SFF8472-\w+|TRANSCEIVER-\w+|GBIC_SECURITY\w*-\w+|CMRP_PFU-\w+"
        r"|SYS-MALLOCFAIL|SYS-CPUHOG|SYS-WATCHDOG|FAN\w*-\w+|C[34]K_\w+")),
    ("l2sec", re.compile(r"DHCP_SNOOPING-\w+|SW_DAI-\w+|IP_SOURCE_GUARD-\w+|SISF-\w+")),
    ("mismatch", re.compile(r"CDP-\w*MISMATCH\w*|LLDP-\w*MISMATCH\w*")),
    ("l3", re.compile(r"OSPF-\w+|EIGRP-\w+|BGP-\w+|HSRP-\w+|VRRP-\w+|TRACK-STATE|IPSLA-\w+|DUAL-\w+")),
]
_HUAWEI_MODULES: dict[str, str] = {
    "LACP": "channel", "TRUNK": "channel", "ETRUNK": "channel",
    "MSTP": "stp", "STP": "stp", "RSTP": "stp",
    "STACK": "restart", "CSS": "restart",
    "POE": "poe", "LLDP": "neighbor", "NTP": "time",
    "SSH": "auth", "AAA": "auth", "TELNET": "auth", "LOGIN": "auth",
    "CFM": "config",
    "DHCP": "l2sec", "DHCPSNP": "l2sec", "DAI": "l2sec", "IPSG": "l2sec",
    "OSPF": "l3", "BGP": "l3", "ISIS": "l3", "VRRP": "l3",
    "CPUDEFEND": "hardware", "POWER": "hardware", "FAN": "hardware", "TEMP": "hardware", "ENTITYTRAP": "hardware", "SYSMON": "hardware", "HWTM": "hardware",
}
_HUAWEI_PROTECT = re.compile(r"BPDU|LOOP|STORM|PORTSEC|PORT_SECURITY|MACLIMIT|ERRDOWN|ERROR_DOWN", re.IGNORECASE)
_HUAWEI_MACFLAP = re.compile(r"MAC_?FLAP|MAC_?MOVE", re.IGNORECASE)
_HUAWEI_QUIET_DEVM = re.compile(r"hwPortUp|hwPortDown|hwOpticalModule\w*|entConfigChange", re.IGNORECASE)


def classify(message: dict[str, Any]) -> str:
    """Family key of a parsed message, or ``""``."""
    style = message["style"]
    if style == "cisco":
        for key, pattern in _CISCO_FAMILIES:
            if pattern.fullmatch(message["tag"]):
                return key
        return ""
    if style == "huawei":
        module, name = message["module"], message["name"]
        if module.upper() in ("DEVM",):
            # port up / down is read as a flap; optical module notices are inventory events
            return "" if _HUAWEI_QUIET_DEVM.search(name) else "hardware"
        if _HUAWEI_MACFLAP.search(name) or _HUAWEI_MACFLAP.search(message["text"][:80]):
            return "macflap"
        if _HUAWEI_PROTECT.search(name) or module.upper() in ("PORT-SECURITY", "PORTSEC", "LOOPDETECT", "STORMCTRL", "ERRDOWN"):
            return "protect"
        return _HUAWEI_MODULES.get(module.upper(), "")
    if style == "aruba":
        module = message["module"].lower()
        if module in ("stp", "mstp", "rstp"):
            return "stp"
        if module in ("lacp", "trunk", "trk"):
            return "channel"
        if module in ("auth", "radius", "tacacs", "dot1x", "mauth", "ssh", "login"):
            return "auth"
        if module in ("mac", "maclock"):
            return "macflap"
        if module in ("poe",):
            return "poe"
        if module in ("system", "chassis", "fan", "power"):
            return "hardware"
    if style == "aoscx":
        return aoscx_logs.classify(message)
    return ""


# ---------------------------------------------------------------- interface / object extraction

_IFACE = re.compile(
    r"\b((?:Gi|Te|Fa|Hu|Tw|Fo|Eth|Et|Po|Vl|Ap|Mg|GigabitEthernet|TenGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE|FastEthernet|Ethernet|Port-channel|Vlan|"
    r"GE|XGE|10GE|25GE|40GE|100GE|Eth-Trunk|MEth|Stack-Port)[A-Za-z\-]*\d[\w/.:\-]*)", re.IGNORECASE)
_MAC = re.compile(r"\b([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\b", re.IGNORECASE)


def _object(message: dict[str, Any]) -> str:
    text = message["text"]
    if "MAC" in message["tag"].upper() or message["name"].upper().startswith("MACFLAP"):
        found = _MAC.search(text)
        if found:
            return found.group(1)
    found = re.search(r"(?:ifName|PortName|Interface|EntPhysicalName)=([^,\s)]+)", text)
    if found:
        return found.group(1)
    found = _IFACE.search(text)
    return found.group(1).rstrip(".,:;)") if found else ""


# ---------------------------------------------------------------- flaps

_CISCO_STATE = re.compile(r"Interface (\S+), changed state to ([a-z ]+?)\s*$", re.IGNORECASE)
_CISCO_PROTO = re.compile(r"Line protocol on Interface (\S+), changed state to ([a-z ]+?)\s*$", re.IGNORECASE)
_NXOS_IF = re.compile(r"Interface (\S+) is (down|up)", re.IGNORECASE)
_HUAWEI_OPER = re.compile(r"ifName=([^,\s)]+).*?OperStatus=(UP|DOWN)", re.IGNORECASE)
_HUAWEI_LINESTATE = re.compile(r"interface (\S+) has entered the (UP|DOWN) state", re.IGNORECASE)
_HUAWEI_IFSTATE = re.compile(r"Interface (\S+) has turned into (UP|DOWN) state", re.IGNORECASE)
_HUAWEI_PHYS = re.compile(r"EntPhysicalName=([^,\s)]+)", re.IGNORECASE)
_ARUBA_PORT = re.compile(r"port (\S+) is now (on|off)-line", re.IGNORECASE)
_AOSCX_LINK = re.compile(r"Link status for interface (\S+) is (up|down)", re.IGNORECASE)


def _flap_event(message: dict[str, Any]) -> tuple[str, str, str, str] | None:
    """(source, interface, state, ts) when the message is a link transition, else None.

    Cisco prints both a physical-link and a line-protocol message for one transition, so
    they are kept apart (``link`` / ``proto``) and only one of them is counted per port.
    Huawei prints IFNET and DEVM messages for the same transition (``ifnet`` / ``devm``).
    """
    tag, text, style = message["tag"], message["text"], message["style"]
    if style == "cisco":
        if tag == "LINK-UPDOWN":
            match = _CISCO_STATE.search(text)
            if match:
                return "link", match.group(1), match.group(2).strip().lower(), message["ts"]
        elif tag == "LINEPROTO-UPDOWN":
            match = _CISCO_PROTO.search(text) or _CISCO_STATE.search(text)
            if match:
                return "proto", match.group(1), match.group(2).strip().lower(), message["ts"]
        elif tag.startswith("ETHPORT-IF_") and ("DOWN" in tag or tag.endswith("IF_UP")):
            match = _NXOS_IF.search(text)
            if match:
                state = "administratively down" if "administratively" in text.lower() else match.group(2).lower()
                return "link", match.group(1), state, message["ts"]
    elif style == "huawei":
        name = message["name"]
        if message["module"].upper() == "IFNET" and name.lower().startswith(("linkdown", "linkup")):
            match = _HUAWEI_OPER.search(text)
            if match:
                return "ifnet", match.group(1), match.group(2).lower(), message["ts"]
        elif message["module"].upper() in ("IFNET", "IFPDT") and name in ("LINK_STATE", "IF_STATE"):
            match = _HUAWEI_LINESTATE.search(text) or _HUAWEI_IFSTATE.search(text)
            if match:
                return "ifnet", match.group(1), match.group(2).lower(), message["ts"]
        elif message["module"].upper() == "DEVM" and name in ("hwPortDown", "hwPortUp"):
            match = _HUAWEI_PHYS.search(text)
            if match:
                return "devm", match.group(1), "down" if name == "hwPortDown" else "up", message["ts"]
    elif style == "aruba":
        match = _ARUBA_PORT.search(text)
        if match:
            return "link", match.group(1), "up" if match.group(2).lower() == "on" else "down", message["ts"]
    elif style == "aoscx":
        if message["tag"] == "intfd" and message["name"] in ("403", "404"):     # "Link status for interface 1/1/26 is up at 10 Gbps"
            match = _AOSCX_LINK.search(text)
            if match:
                return "link", match.group(1), match.group(2).lower(), message["ts"]
    return None


# ---------------------------------------------------------------- settings (Cisco show logging header)

def _settings(head: list[str]) -> dict[str, Any]:
    text = "\n".join(head)
    out: dict[str, Any] = {}
    match = re.search(r"Syslog logging:\s*(\w+)\s*\((\d+) messages dropped, (\d+) messages rate-limited", text)
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
    hosts = re.findall(r"Logging to (\S+)\s+\((?:udp|tcp|tls) port (\d+)", text)
    out["hosts"] = [{"host": host, "port": port} for host, port in hosts]
    return out


# ---------------------------------------------------------------- driver

def _blocks(clean: list[str], vendor: str) -> list[tuple[str, list[str]]]:
    """(command, lines) for every log command in the capture."""
    found: list[tuple[str, list[str]]] = []
    for index, line in enumerate(clean):
        parts = capture_text.split_command(line)
        if not parts:
            continue
        command = parts[0]
        if not any(re.fullmatch(pattern, command) for pattern in ALL_LOG_PATTERNS):
            continue
        block, _cursor = capture_text._block_after(clean, index + 1, [parts[1]] if parts[1] else [])
        found.append((command, block))
    return found


def _vendor_key(vendor: str) -> str:
    low = (vendor or "").lower()
    return "huawei" if "huawei" in low else ("aruba" if "aruba" in low else "cisco")


def _empty(captured: bool = False) -> dict[str, Any]:
    return {
        "captured": captured, "source": "", "style": "", "order": "", "validated": "", "inline": False,
        "settings": {}, "message_count": 0, "first": "", "last": "", "by_severity": [], "top": [], "flaps": [],
        "events": [], "families": [], "sources": [], "findings": [], "note": "",
    }


def build_logs(clean: list[str], vendor: str) -> dict[str, Any]:
    """Digest of the capture's log buffer (see the module docstring)."""
    blocks = _blocks(clean, vendor)
    candidates: list[dict[str, Any]] = []
    for command, block in blocks:
        parsed = [m for m in (parse_message(line) for line in block) if m]
        candidates.append({"command": command, "lines": block, "messages": parsed})
    inline = False
    chosen: dict[str, Any] | None = None
    usable = [c for c in candidates if c["messages"]]
    if usable:
        # logbuffer wins over trapbuffer (the same event is printed in both buffers); otherwise the longest
        preferred = [c for c in usable if "trapbuffer" not in c["command"]] or usable
        chosen = max(preferred, key=lambda c: len(c["messages"]))
    elif not blocks:
        harvested = [m for m in (parse_message(line) for line in clean) if m]
        if harvested:
            chosen = {"command": "", "lines": [], "messages": harvested}
            inline = True
    if chosen is None:
        out = _empty(captured=bool(blocks))
        out["sources"] = [{"command": c["command"], "messages": 0, "used": False} for c in candidates]
        return out
    out = _digest(chosen["messages"], chosen["lines"], chosen["command"], inline)
    out["captured"] = True
    out["sources"] = [{"command": c["command"], "messages": len(c["messages"]), "used": c is chosen} for c in candidates]
    out["findings"] = _findings(out, vendor)
    return out


def _digest(messages: list[dict[str, Any]], lines: list[str], command: str, inline: bool) -> dict[str, Any]:
    style = messages[0]["style"]
    newest_first = style == "huawei"
    out = _empty(captured=True)
    out["inline"] = inline
    out["style"] = style
    out["source"] = "messages seen on the console while the capture ran" if inline else command
    out["order"] = "newest first" if newest_first else "oldest first"
    out["validated"] = "real captures" if style in ("cisco", "huawei", "aoscx") else "vendor documentation only (no real capture seen yet)"
    if style == "aruba":
        out["note"] = "ArubaOS-Switch event-log layout read from HPE documentation; not yet checked against a real capture."
    if style == "aoscx":
        # the switch prints UTC until it applies its time zone at boot; show every message in the zone of the newest one
        out["timezone"] = aoscx.normalise_times(messages)
        if out["timezone"]:
            out["note"] = f"Time stamps are shown in UTC{out['timezone']}, the zone of the newest message; the switch logs in UTC for the first minutes after a boot."
    if style == "cisco" and not inline:
        split = next((i for i, line in enumerate(lines) if line.startswith("Log Buffer")), min(len(lines), 60))
        out["settings"] = _settings(lines[: split + 1])

    sev_counts: Counter = Counter()
    top: dict[str, dict[str, Any]] = {}
    fam_total: Counter = Counter()
    fam_serious: Counter = Counter()  # severity 4 (warnings) or worse
    fam_tags: dict[str, Counter] = {}
    fam_events: dict[str, deque] = {}
    flap_sources: dict[str, dict[str, dict[str, Any]]] = {}
    first_ts = last_ts = ""

    for index, message in enumerate(messages):
        sev = message["sev"]
        sev_counts[sev] += 1
        stamp = message["ts"]
        if not first_ts:
            first_ts = stamp
        if stamp:
            last_ts = stamp
        row = top.get(message["ident"])
        if row is None:
            top[message["ident"]] = {"id": message["ident"], "severity": SEVERITY_NAME.get(sev, str(sev)), "count": 1, "first": stamp, "last": stamp, "example": _clip(message["text"], 200)}
        else:
            row["count"] += 1
            row["last"] = stamp or row["last"]

        flap = _flap_event(message)
        if flap:
            source, interface, state, when = flap
            table = flap_sources.setdefault(source, {})
            entry = table.setdefault(interface, {"interface": interface, "down": 0, "up": 0, "admin_down": 0, "first": when, "last": when})
            if "administratively" in state:
                entry["admin_down"] += 1
            elif state.startswith("down"):
                entry["down"] += 1
            elif state.startswith("up"):
                entry["up"] += 1
            entry["last"] = when or entry["last"]
            continue

        family = classify(message)
        if not family:
            continue
        fam_total[family] += 1
        if sev <= 4:
            fam_serious[family] += 1
        fam_tags.setdefault(family, Counter())[message["ident"]] += 1
        if family in QUIET_FAMILIES:
            continue
        events = fam_events.setdefault(family, deque(maxlen=MAX_EVENTS_PER_FAMILY))
        # keep the newest rows of every family: the deque drops the oldest when the file is oldest-first,
        # and for a newest-first file the first rows are the ones kept (see below)
        if newest_first and len(events) >= MAX_EVENTS_PER_FAMILY:
            continue
        events.append({
            "time": stamp, "family": family, "label": FAMILY_LABEL[family], "id": message["ident"],
            "severity": SEVERITY_NAME.get(sev, str(sev)), "object": _object(message), "text": _clip(message["text"]),
            "order": index,
        })

    # one flap source per port: the physical-link message, else the line-protocol one
    chosen_flaps: dict[str, dict[str, Any]] = {}
    primary = ("ifnet", "devm") if style == "huawei" else ("link", "proto")
    for source in primary:
        for interface, entry in flap_sources.get(source, {}).items():
            if interface not in chosen_flaps:
                chosen_flaps[interface] = dict(entry, kind={"link": "link", "proto": "line protocol", "ifnet": "interface status", "devm": "physical port"}[source])
    if "link" in flap_sources and style == "aruba":
        chosen_flaps = {k: dict(v, kind="port") for k, v in flap_sources["link"].items()}
    flaps = []
    for entry in chosen_flaps.values():
        if newest_first:  # the file lists the newest event first
            entry["first"], entry["last"] = entry["last"], entry["first"]
        flaps.append(entry)
    flaps.sort(key=lambda e: (-e["down"], -e["up"], e["interface"]))
    out["flaps"] = flaps[:MAX_FLAPS]
    out["flap_total"] = len(flaps)

    out["message_count"] = len(messages)
    out["first"], out["last"] = (last_ts, first_ts) if newest_first else (first_ts, last_ts)
    out["duration"] = log_window(out["first"], out["last"])   # how many days / hours / minutes the buffer covers
    out["by_severity"] = [{"level": SEVERITY_NAME.get(n, str(n)), "number": n, "count": sev_counts[n]} for n in sorted(sev_counts)]
    out["top"] = sorted(top.values(), key=lambda r: (-r["count"], r["id"]))[:MAX_TOP]
    if newest_first:  # a Huawei buffer: first/last of a row are swapped like the flaps
        for row in out["top"]:
            row["first"], row["last"] = row["last"], row["first"]
    rows = [row for family in fam_events for row in fam_events[family]]
    rows.sort(key=lambda r: r["order"] if newest_first else -r["order"])
    out["events"] = [{k: v for k, v in row.items() if k != "order"} for row in rows]
    out["families"] = [{"key": key, "label": FAMILY_LABEL[key], "count": fam_total[key],
                        "top": [{"id": ident, "count": n} for ident, n in fam_tags[key].most_common(3)]}
                       for key in sorted(fam_total, key=lambda k: -fam_total[k])]
    if style == "cisco" and any(row["id"].startswith(("ETHPORT-", "L2FM-", "VPC-", "ETH_PORT_CHANNEL-")) for row in out["top"]):
        out["note"] = "NX-OS stamps each message as year, month, day, clock and the switch name, with no time zone, so the times below are the switch's own local clock. The rest of the line uses the IOS layout (%FACILITY-SEVERITY-MNEMONIC)."
    if style == "aoscx":
        out["aoscx"] = aoscx.log_facts(messages)
    out["family_counts"] = dict(fam_total)
    out["family_serious"] = dict(fam_serious)
    out["family_tags"] = {key: dict(counter) for key, counter in fam_tags.items()}
    settings = out["settings"]
    if settings.get("buffer"):
        logged = settings["buffer"].get("logged", 0)
        out["buffer_visible"] = len(messages)
        out["buffer_overwritten"] = max(0, logged - len(messages))
    return out


# ---------------------------------------------------------------- findings

def _count(out: dict[str, Any], family: str) -> int:
    return int(out.get("family_counts", {}).get(family, 0))


def _tags(out: dict[str, Any], family: str, *needles: str) -> int:
    return sum(n for ident, n in out.get("family_tags", {}).get(family, {}).items() if any(x in ident for x in needles))


def _events(out: dict[str, Any], family: str) -> list[dict[str, Any]]:
    return [row for row in out["events"] if row["family"] == family]


def _tag_total(out: dict[str, Any], family: str, pattern: str, *, skip_clear: bool = False) -> int:
    """Messages of a family whose id matches ``pattern`` (a ``_clear`` / ``_resume`` id is a recovery, not a fault)."""
    total = 0
    for ident, n in out.get("family_tags", {}).get(family, {}).items():
        if skip_clear and ident.endswith(("_clear", "_resume")):
            continue
        if re.search(pattern, ident, re.IGNORECASE):
            total += n
    return total


def _findings(out: dict[str, Any], vendor: str) -> list[dict[str, Any]]:
    ref = DOCS["syslog"][1] if out["style"] == "cisco" else ""
    where = f"from {out['source']}"
    result: list[dict[str, Any]] = []

    flapping = [f for f in out["flaps"] if f["down"] >= 3]
    for entry in flapping[:10]:
        severity = "high" if entry["down"] >= 10 else "medium"
        result.append(finding(
            "SW-EVT-001", severity, "Logs", f"{entry['interface'] if re.search(r'[A-Za-z]{2}', entry['interface']) else 'Port ' + entry['interface']} went down {entry['down']} times",
            obj=entry["interface"],
            detail=(f"{entry['down']} link-down and {entry['up']} link-up messages between {entry['first'] or '?'} and {entry['last'] or '?'} ({entry['kind']} messages, {where}). "
                    "Repeated transitions on one port point at the cable, the transceiver, a duplex or speed mismatch, or the device on the far end."),
            recommendation="Check the cable and transceiver, compare speed and duplex on both ends, and read the interface error counters.",
            reference=ref))
    if len(flapping) > 10:
        result.append(finding(
            "SW-EVT-001", "medium", "Logs", f"{len(flapping) - 10} more ports went down 3 or more times", obj="",
            detail="Shown in the Logs tab, interface flaps table.", reference=ref))

    protect = _events(out, "protect")
    if protect:
        by_id = Counter(row["id"] for row in protect)
        sample = protect[0]
        result.append(finding(
            "SW-EVT-002", "high", "Logs", f"{_count(out, 'protect')} port-protection message(s): {', '.join(i for i, _ in by_id.most_common(3))}",
            obj=sample["object"], detail=f"Latest: {sample['text']} ({where}). A port in err-disable carries no traffic until it is recovered.",
            recommendation="Find the cause named in the message, fix it, then recover the port (shutdown / no shutdown or errdisable recovery).",
            reference=ref))

    macflap = _events(out, "macflap")
    if macflap:
        objects = Counter(row["object"] for row in macflap if row["object"])
        severity = "high" if _count(out, "macflap") >= 10 else "medium"
        sample = macflap[0]
        result.append(finding(
            "SW-EVT-003", severity, "Logs", f"MAC address flapping or conflict ({_count(out, 'macflap')} message(s))",
            obj=", ".join(o for o, _ in objects.most_common(3)), detail=f"Latest: {sample['text']} ({where}). The same MAC address is learned on different ports, which is the signature of a Layer-2 loop or a duplicated address.",
            recommendation="Trace the MAC address to both ports, remove the loop or the duplicate, and confirm spanning tree is running on those links.",
            reference=ref))

    topo = _tags(out, "stp", "TOPOTRAP", "ROOTCHANGE") if out["style"] == "cisco" else (0 if out["style"] == "aoscx" else _count(out, "stp"))
    if topo >= 5:
        result.append(finding(
            "SW-EVT-004", "medium", "Logs",
            f"{topo} spanning-tree topology-change or root-change messages" if out["style"] == "cisco" else f"{topo} spanning-tree messages",
            detail=f"Frequent topology changes flush the MAC table and cause flooding ({where}).",
            recommendation="Find the port that keeps flapping (it is usually an access port without PortFast) and the root bridge that moves.",
            reference="https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_optional_spanning_tree_features.html" if out["style"] == "cisco" else ""))

    channel = [] if out["style"] == "aoscx" else _events(out, "channel")     # AOS-CX has its own LACP finding (aoscx_logs)
    channel_fault = r"CANNOT_BUNDLE|DONTBNDL|UNBUNDLE|NEGOTIATE|STATE_DOWN|LinkLoss|NOT_AGG|SUSPEND"
    bad_total = _tag_total(out, "channel", channel_fault, skip_clear=True)
    bad_channel = [row for row in channel if not row["id"].endswith(("_clear", "_resume")) and re.search(channel_fault, row["id"], re.IGNORECASE)]
    if bad_total and bad_channel:
        sample = bad_channel[0]
        result.append(finding(
            "SW-EVT-005", "medium", "Logs", f"{bad_total} EtherChannel / LACP problem message(s)",
            obj=sample["object"], detail=f"Latest: {sample['text']} ({where}). A member that cannot bundle carries no traffic and sends no LACPDUs.",
            recommendation="Compare the member port's configuration with the port-channel and with the other members, then read show etherchannel summary / display eth-trunk.",
            reference="https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lyr2/b_179_lyr2_9300_cg/configuring_etherchannels.html" if out["style"] == "cisco" else ""))

    auth = _events(out, "auth")
    failures = [row for row in auth if re.search(r"FAIL|DENIED|REJECT", row["id"] + " " + row["text"], re.IGNORECASE)]
    fail_total = _tag_total(out, "auth", r"FAIL|DENIED|REJECT")
    if fail_total >= 5 and failures:
        result.append(finding(
            "SW-EVT-006", "medium", "Logs", f"{fail_total} failed login or authentication message(s)",
            detail=f"Latest: {failures[0]['text']} ({where}). Repeated failures can be a mistyped credential, an unreachable AAA server or a password-guessing attempt.",
            recommendation="Check the source address in the messages, confirm the AAA servers answer, and restrict management access with an ACL.",
            reference=ref))

    hardware = _events(out, "hardware")
    serious = [row for row in hardware if row["severity"] in ("emergencies", "alerts", "critical", "errors", "warnings")]
    serious_total = int(out.get("family_serious", {}).get("hardware", 0))
    if serious_total and serious:
        ids = Counter(row["id"] for row in serious)
        result.append(finding(
            "SW-EVT-007", "medium", "Logs", f"{serious_total} hardware, power, CPU or memory message(s): {', '.join(i for i, _ in ids.most_common(3))}",
            obj=serious[0]["object"], detail=f"Latest: {serious[0]['text']} ({where}).",
            recommendation="Read the message in the vendor's system message reference, then check the component it names (power supply, fan, transceiver, CPU, memory).",
            reference=ref))

    mismatch = [] if out["style"] == "aoscx" else _events(out, "mismatch")   # AOS-CX: PVID mismatch finding in aoscx_logs
    if mismatch:
        result.append(finding(
            "SW-EVT-008", "medium", "Logs", f"{_count(out, 'mismatch')} CDP / LLDP mismatch message(s)",
            obj=mismatch[0]["object"], detail=f"Latest: {mismatch[0]['text']} ({where}). A duplex or native-VLAN mismatch between two switches degrades the link without taking it down.",
            recommendation="Set the same duplex / speed and native VLAN on both ends.", reference=ref))

    l2sec = _events(out, "l2sec")
    denied = [row for row in l2sec if re.search(r"DENY|VIOLATION|UNTRUSTED|EXCESS|DROP", row["id"] + " " + row["text"], re.IGNORECASE)]
    denied_total = _tag_total(out, "l2sec", r"DENY|VIOLATION|UNTRUSTED|EXCESS|DROP")
    if denied_total and denied:
        result.append(finding(
            "SW-EVT-009", "low", "Logs", f"{denied_total} DHCP-snooping / ARP-inspection / SISF message(s)",
            obj=denied[0]["object"], detail=f"Latest: {denied[0]['text']} ({where}).",
            recommendation="Confirm the port is meant to be untrusted; trust only uplinks and DHCP server ports.", reference=ref))

    restart = _events(out, "restart")
    if restart:
        faults = int(out.get("family_serious", {}).get("restart", 0))
        result.append(finding(
            "SW-EVT-010", "medium" if faults else "info", "Logs",
            f"{_count(out, 'restart')} restart, reload or stack message(s)" + (f", {faults} of them warning level or worse" if faults else ""),
            detail=f"Latest: {restart[0]['text']} ({restart[0]['time'] or 'no time'}; {where}).", reference=ref))

    settings = out.get("settings", {})
    if settings.get("buffer") and out.get("buffer_overwritten", 0) > 0 and settings.get("buffer_bytes", 0) <= 16384:
        result.append(finding(
            "SW-EVT-011", "low", "Logs", f"Log buffer is {settings['buffer_bytes']} bytes and has overwritten older messages",
            detail=(f"{settings['buffer']['logged']} messages were logged since the counters were cleared, but the buffer only holds the latest {out['buffer_visible']}. "
                    "History before that is gone, which is what you need when an incident is reported a day later."),
            recommendation="Raise the buffer, for example `logging buffered 262144 informational`, and send logs to a syslog collector.",
            reference=ref))

    by_level = {row["level"]: row["count"] for row in out["by_severity"]}
    serious_unclassified = by_level.get("emergencies", 0) + by_level.get("alerts", 0)
    if serious_unclassified:
        result.append(finding(
            "SW-EVT-012", "high", "Logs", f"{serious_unclassified} emergency or alert level message(s)",
            detail="Severity 0 and 1 messages mean the device reports it cannot work normally. See the most frequent messages in the Logs tab.", reference=ref))
    if out["style"] == "aoscx":
        for item in result:
            if not item["reference"]:
                item["reference"] = (aoscx.GUIDE_DOCS["interface"] if item["id"] == "SW-EVT-001"
                                     else aoscx.GUIDE_DOCS["vsf"] if item["id"] == "SW-EVT-010" else aoscx.EVENT_DOCS["home"])
        result.extend(aoscx_logs.findings(out))
    return result
