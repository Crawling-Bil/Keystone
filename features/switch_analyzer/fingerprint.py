"""Vendor / model fingerprint for the Switch Analyzer.

Why this exists
---------------
Configuration Studio's ``DeviceDetector`` scores a file by counting vendor
keywords anywhere in the text. That is good enough for a clean
``show running-config`` but it is wrong for a capture that has no
running-config at all (a session taken in user EXEC mode, where ``show run``
answered "% Invalid input detected"): there is nothing left but show-command
output, and the only vendor keywords that remain are generic words such as
"trunk " / "tagged " that happen to be on the Aruba list. Confirmed on a real
Cisco Catalyst 2960S capture (WS-C2960S-F48TS-L, "Cisco IOS Software, C2960S
... Version 15.0(2)SE") that was reported as Aruba.

How it decides
--------------
Signals are grouped by how much they can be trusted:

* IDENTITY signals are read only from the device's OWN identity commands
  (``show version`` / ``display version`` / ``show inventory`` / ``show
  system`` / ``display device``). A neighbor's banner echoed by LLDP/CDP is not
  in those sections, so it cannot hijack the result (a real Cisco 3650 capture
  contains a Huawei neighbor's "VRP (R) software" line).
* CONFIG signals are configuration statements anchored at the start of a line
  (``sysname``, ``switchport mode``, ``; JL356A Configuration Editor`` ...).
* OUTPUT signals are the table headers each vendor prints
  ("Protocol Address Age (min) Hardware Addr", "PHY: Physical", "Status and
  Counters - Port Address Table" ...).

The vendor with the highest score wins; the result carries the evidence so a
wrong call is easy to diagnose, and a confidence level so callers can fall
back to the older detector when nothing is conclusive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .capture_text import clean_lines, command_outputs

VENDORS = ("Cisco", "Aruba", "Huawei")
_BODY_SAMPLE_LIMIT = 6_000_000

_IDENTITY_COMMANDS = [
    r"sh(?:ow)? ver(?:sion)?",
    r"dis(?:p(?:l(?:a(?:y)?)?)?)? ver(?:sion)?",
    r"sh(?:ow)? inv(?:entory)?",
    r"sh(?:ow)? system(?: information|-information| inventory)?",
    r"sh(?:ow)? modules?",
    r"sh(?:ow)? switch",
    r"dis(?:p(?:l(?:a(?:y)?)?)?)? device",
    r"dis(?:p(?:l(?:a(?:y)?)?)?)? device elabel(?: brief)?",
]

# (regex, weight, label) -- regexes are applied with re.MULTILINE | re.IGNORECASE
_IDENTITY: dict[str, list[tuple[str, int, str]]] = {
    "Cisco": [
        (r"Cisco IOS Software", 12, "Cisco IOS Software banner"),
        (r"Cisco IOS[ -]XE Software", 12, "Cisco IOS XE banner"),
        (r"Cisco Internetwork Operating System", 12, "Cisco IOS banner"),
        (r"Cisco Nexus Operating System", 14, "NX-OS banner"),
        (r"^\s*cisco\s+(?:WS-C|WS-X|Nexus|N\d|C\d|ISR|ASR|IE-|CBS)", 10, "'cisco <model>' hardware line"),
        (r"\bPID:\s*(?:WS-[CX]|C9\d{3}|C\d{4}|N\dK|N9K|IE-\d|CBS|ISR|ASR)", 10, "inventory PID (Cisco part number)"),
        (r"DESCR:\s*\"[^\"]*(?:WS-[CX]\d|Catalyst|Nexus|C9\d{3}|N9K)", 10, "inventory description (Cisco)"),
        (r"Model [Nn]umber\s*:\s*(?:WS-C|C9|C\d{4}|N\d)", 10, "Model Number (Cisco)"),
        (r"System image file is", 6, "System image file"),
        (r"Configuration register is", 6, "Configuration register"),
        (r"Processor board ID", 4, "Processor board ID"),
        (r"^\s*Switch Ports Model\s+SW Version", 8, "Switch Ports Model table"),
    ],
    "Aruba": [
        (r"Software revision\s*:\s*[A-Z]{1,2}\.\d+", 12, "Software revision (ArubaOS-Switch)"),
        (r"^\s*[A-Z]{1,2}\.\d{2}\.\d{2}(?:\.\d+)?\s*$", 10, "ProCurve/ArubaOS-Switch version string"),
        (r"\bProCurve\b", 10, "ProCurve"),
        (r"\bArubaOS(?:-Switch|-CX)?\b", 12, "ArubaOS"),
        # ArubaOS-CX `show version`: a bare "AOS-CX" line, "Version : ML.10.16.1020", "Build ID : AOS-CX:ML.10..."
        (r"^\s*AOS-CX\s*$", 14, "AOS-CX banner (show version)"),
        (r"^\s*Build ID\s*:\s*AOS-CX:", 10, "AOS-CX build ID"),
        (r"^\s*Version\s*:\s*[A-Z]{2}\.\d{2}\.\d{2}\.\d{4}\s*$", 8, "AOS-CX version string"),
        (r"\bHPE?\s+(?:J[A-Z]?\d{3,4}|ProCurve|\d{4}\w*\s+Switch)", 10, "HP switch banner"),
        (r"\bAruba\s+(?:\d{4}|JL\d+|Switch)", 8, "Aruba model banner"),
        (r"^\s*Image stamp\s*:", 8, "Image stamp"),
        (r"^\s*Base MAC Addr\s*:", 6, "Base MAC Addr"),
    ],
    "Huawei": [
        (r"VRP\s*\(R\)\s*software", 14, "VRP software banner"),
        (r"Huawei YunShan OS", 14, "YunShan OS banner"),
        (r"Huawei Versatile Routing Platform", 14, "VRP banner"),
        (r"HUAWEI\s+(?:CloudEngine\s+)?(?:[SC]E?\d{3,5}|AR\d{3,5})", 12, "HUAWEI <model> banner"),
        (r"\bQuidway\b", 10, "Quidway"),
        (r"BOARD\s*TYPE\s*=\s*\S+", 8, "elabel BOARD TYPE"),
        (r"Huawei Technologies Co", 6, "Huawei Technologies"),
    ],
}

_CONFIG: dict[str, list[tuple[str, int, str]]] = {
    "Cisco": [
        (r"^version\s+\d+\.\d+", 3, "'version x.y' header"),
        (r"^Current configuration\s*:\s*\d+\s*bytes", 6, "'Current configuration : N bytes'"),
        (r"^Building configuration", 4, "'Building configuration...'"),
        (r"^service (?:timestamps|password-encryption|pad|call-home)", 4, "service ... statement"),
        (r"^\s*switchport (?:mode|access vlan|trunk)", 4, "switchport statements"),
        (r"^spanning-tree mode (?:pvst|rapid-pvst|mst)", 4, "spanning-tree mode"),
        (r"^interface (?:GigabitEthernet|FastEthernet|TenGigabitEthernet|Port-channel|Ethernet)\S*\d", 2, "Cisco interface names"),
        (r"^enable (?:secret|password)", 4, "enable secret"),
        (r"^line (?:con|vty)\s+\d", 3, "line con/vty"),
        (r"^feature\s+(?:vpc|lacp|interface-vlan|hsrp|ospf|bgp|lldp)\b", 5, "NX-OS feature statements"),
        (r"^vrf context management", 5, "NX-OS vrf context"),
        (r"^ip routing$", 2, "ip routing"),
        (r"^no ip domain[- ]lookup", 3, "no ip domain-lookup"),
    ],
    "Aruba": [
        (r"^;\s*\S+\s+Configuration Editor", 14, "'; <model> Configuration Editor' header"),
        (r"^!Version AOS-CX\s+\S+", 14, "'!Version AOS-CX' header"),
        (r"^vsf member \d+", 4, "vsf member"),
        (r"^Running configuration:\s*$", 6, "'Running configuration:'"),
        (r"^module\s+\d+\s+type\s+\S+", 8, "module N type"),
        (r"^hostname\s+\"", 3, "quoted hostname"),
        (r"^snmp-server community \"", 3, "quoted snmp community"),
        (r"^\s+(?:un)?tagged\s+[\dA-Za-z,\-]+\s*$", 3, "tagged/untagged VLAN lines"),
        (r"^no tftp server", 4, "no tftp server"),
        (r"^interface\s+(?:\d+|[A-D]\d+|Trk\d+)\s*$", 3, "bare-number interface"),
        (r"^trunk\s+\S+\s+trk\d+\s+(?:lacp|trunk)", 4, "trunk statement"),
    ],
    "Huawei": [
        (r"^sysname\s+\S+", 10, "sysname"),
        (r"^interface\s+(?:GigabitEthernet|XGigabitEthernet|\d+GE|Eth-Trunk|Vlanif|MEth|NULL|LoopBack)\S*\d", 3, "Huawei interface names"),
        (r"^\s*port link-type\s+(?:access|trunk|hybrid)", 5, "port link-type"),
        (r"^\s*undo shutdown", 3, "undo shutdown"),
        (r"^\s*undo\s+\S+", 1, "undo statements"),
        (r"^stp mode\s+(?:rstp|mstp|stp|vbst)", 4, "stp mode"),
        (r"^info-center\s+\S+", 3, "info-center"),
        (r"^acl number\s+\d+", 3, "acl number"),
        (r"^user-interface\s+(?:vty|con)", 4, "user-interface"),
        (r"^aaa\s*$", 2, "aaa block"),
        (r"^return\s*$", 1, "return"),
        (r"^<[^<>\s]+>\s*display\s", 5, "<host>display prompt"),
    ],
}

_OUTPUT: dict[str, list[tuple[str, int, str]]] = {
    "Cisco": [
        (r"^Protocol\s+Address\s+Age\s*\(min\)\s+Hardware Addr", 6, "IOS 'show ip arp' table"),
        (r"^\s*Vlan\s+Mac Address\s+Type\s+Ports\s*$", 6, "IOS 'show mac address-table' table"),
        (r"^Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol", 6, "IOS 'show ip interface brief' table"),
        (r"^Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type", 5, "IOS/NX-OS 'show interface status' table"),
        (r"administratively down", 2, "'administratively down'"),
        (r"^IP Interface Status for VRF", 6, "NX-OS 'show ip interface brief'"),
        (r"^\s*VLAN\s+MAC Address\s+Type\s+age\s+Secure NTFY Ports", 6, "NX-OS MAC table"),
        # A capture that is only a licence excerpt has no `show version`, no hostname and no running-config, so
        # these licence layouts are the only evidence there is. Each is printed by Cisco platforms alone.
        # IOS classic licensing: `show license all` / `show license` on Catalyst 3560/3750/2960 ...
        (r"^License Store:\s*(?:Primary|Built-In)", 8, "IOS 'show license' store"),
        (r"^StoreIndex:\s*\d+\s+Feature:", 8, "IOS 'show license' feature entry"),
        # IOS / IOS XE smart licensing (16.x) and smart licensing using policy (17.3+)
        (r"^Smart Licensing Status\s*$", 8, "IOS XE 'show license status/all' header"),
        (r"^Smart Licensing is (?:ENABLED|DISABLED)", 6, "IOS XE smart licensing state"),
        (r"^Smart Licensing Using Policy", 8, "IOS XE 'show license summary' (using policy)"),
        (r"^License Authorization:\s*$", 4, "IOS XE 'License Authorization' block"),
        (r"^\s*Enforcement type:\s*(?:NOT )?ENFORCED", 4, "IOS XE licence enforcement type"),
        (r"^\s*Export status:\s*(?:NOT )?RESTRICTED", 4, "IOS XE licence export status"),
        (r"UDI:\s*PID:\s*\S+\s*,\s*SN:", 8, "licence UDI (PID, SN)"),
        # NX-OS `show license usage`
        (r"^Feature\s+Ins\s+Lic\s+Count\s+Status\s+Expiry Date", 8, "NX-OS 'show license usage' table"),
        # NX-OS excerpts (a route table or a trunk table pasted without `show version`)
        (r"^IP Route Table for VRF\s", 8, "NX-OS 'show ip route' header"),
        (r"^\s*\*{0,2}\S+/\d+,\s*ubest/mbest:", 6, "NX-OS route 'ubest/mbest' line"),
        (r"^IP ARP Table - Adjacency Summary", 8, "NX-OS 'show ip arp summary'"),
        (r"^Port\s+Native\s+Status\s+Port\s*$", 8, "NX-OS 'show interface trunk' table"),
        # A capture of live-state commands only (show hsrp / show ip ospf neighbors / show ip arp typed on a Nexus) has no `show version`: the login banner and these
        # layouts are the evidence. The banner is the first lines of every NX-OS session; the others are printed by NX-OS and IOS alone.
        (r"^Cisco Nexus Operating System \(NX-OS\) Software", 14, "NX-OS login banner"),
        (r"^IP ARP Table for context \S+", 8, "NX-OS 'show ip arp' header"),
        (r"^\s*\*:IPv6 group\s+#:group belongs to a bundle", 8, "NX-OS 'show hsrp brief' legend"),
        (r"^\S+ - Group \d+ \(HSRP-V[12]\) \(IPv[46]\)\s*$", 8, "NX-OS 'show hsrp' group header"),
        (r"^\s*Local state is \S+.*priority \d+ \(Cfged \d+\)", 8, "NX-OS HSRP local-state line"),
        (r"^\s*Interface\s+Grp\s+Pri(?:o)?\s+P\s+State\s+Active", 8, "'show hsrp brief' / 'show standby brief' header"),
        (r"^\s*OSPF Process ID \S+ VRF \S+", 8, "NX-OS OSPF process header"),
    ],
    "Aruba": [
        (r"Status and Counters - Port Address Table", 8, "Aruba MAC table"),
        (r"^\s*IP ARP table\s*$", 6, "Aruba ARP table"),
        (r"^\s*Port\s+Type\s+\|\s+Alert\s+Enabled\s+Status", 6, "Aruba 'show interfaces brief'"),
        (r"Status and Counters - ", 3, "Aruba 'Status and Counters' header"),
        # ArubaOS-CX output seen without any identity command (a `show interface` / `show logging` excerpt)
        (r"^\s*Admin state is (?:up|down)\s*$", 4, "ArubaOS-CX 'Admin state is' line"),
        (r"^Interface \d+/\d+/\d+ is (?:up|down)\b", 4, "ArubaOS-CX interface block"),
        (r"\b\S+\[\d+\]: Event\|\d+\|LOG_[A-Z]+\|", 6, "ArubaOS-CX event-log line"),
        (r"^\s*MAC Address\s+Port\s+VLAN\s*$", 4, "Aruba MAC table header"),
    ],
    "Huawei": [
        (r"^PHY:\s*Physical", 6, "Huawei 'display interface' legend"),
        (r"^\*down:\s*administratively down", 6, "Huawei '*down' legend"),
        (r"^MAC Address\s+VLAN/VSI(?:/BD)?\s+Learned-From", 8, "Huawei MAC table"),
        (r"^IP ADDRESS\s+MAC ADDRESS\s+EXP", 8, "Huawei ARP table"),
        (r"^Interface\s+IP Address/Mask\s+Physical\s+Protocol", 6, "Huawei 'display ip interface brief'"),
    ],
}

_MODEL_VENDOR = [
    ("Cisco", re.compile(r"^(?:WS-[CX]\d|C9\d{3}|C\d{4}|CBS\d|IE-\d|N\dK|N9K|N\d{4}|ISR|ASR|SG\d)", re.I)),
    ("Aruba", re.compile(r"^(?:JL\d{3}[A-Z]?|J[A-Z]?\d{3,4}[A-Z]?|JG\d{3}[A-Z]?|JH\d{3}[A-Z]?|R\d[A-Z]\d{2}[A-Z]?|Aruba|2530|2540|2920|2930|3810|5400)", re.I)),
    ("Huawei", re.compile(r"^(?:S\d{3,5}|CE\d{4}|AR\d{3,4}|CloudEngine)", re.I)),
]


@dataclass
class Detection:
    vendor: str = ""
    confidence: str = "none"  # high | medium | low | none
    scores: dict[str, int] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    model_hint: str = ""

    def as_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "confidence": self.confidence,
            "scores": dict(self.scores),
            "evidence": list(self.evidence),
            "model_hint": self.model_hint,
        }


def vendor_from_model(model: str) -> str:
    """Vendor implied by a hardware part number such as WS-C2960S-F48TS-L,
    JL356A or S5735-S48T4X. Empty when the model is not recognised."""
    model = (model or "").strip()
    if not model:
        return ""
    for vendor, pattern in _MODEL_VENDOR:
        if pattern.match(model):
            return vendor
    return ""


def _identity_text(lines: list[str]) -> str:
    chunks: list[str] = []
    for section in command_outputs(lines, _IDENTITY_COMMANDS):
        chunks.append("\n".join(section[:80]))
    return "\n".join(chunks)


def _score(table: dict[str, list[tuple[str, int, str]]], text: str, cap: int) -> dict[str, tuple[int, list[str]]]:
    result: dict[str, tuple[int, list[str]]] = {}
    for vendor, signals in table.items():
        total = 0
        hits: list[str] = []
        for pattern, weight, label in signals:
            if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                total += weight
                hits.append(label)
        result[vendor] = (min(total, cap), hits)
    return result


def _model_hint(identity: str, lines: list[str]) -> str:
    for pattern in (
        r"\bPID:\s*([A-Za-z0-9][\w./\-]+)",
        r"DESCR:\s*\"?(WS-[CX]\S+|C9\S+)",
        r"^\s*cisco\s+(WS-\S+|Nexus\d*\s+\S+|C\d\S*|ISR\S*|ASR\S*|N\d\S*)",
        r"Model [Nn]umber\s*:\s*(\S+)",
        r"^\s*Chassis\s+\d+\s+(JL\w+)\s",  # ArubaOS-CX `show system inventory`
        r"^;\s*(\S+)\s+Configuration Editor",
        r"BOARD\s*TYPE\s*=\s*(\S+)",
    ):
        match = re.search(pattern, identity, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(1).strip().rstrip(",")
    return ""


def detect(text: str) -> Detection:
    """Fingerprint the vendor of a capture or configuration."""
    lines = clean_lines(text)
    body = "\n".join(lines)
    if len(body) > _BODY_SAMPLE_LIMIT:
        # A 35 MB log dump took 20 s to score. The identity commands are read from every line; the keyword tables
        # only need the start (configuration, `show version`) and the end (the last commands) of the capture.
        body = body[:_BODY_SAMPLE_LIMIT * 2 // 3] + "\n" + body[-_BODY_SAMPLE_LIMIT // 3:]
    identity = _identity_text(lines)

    scores = {vendor: 0 for vendor in VENDORS}
    evidence: dict[str, list[str]] = {vendor: [] for vendor in VENDORS}

    for table, source, cap in ((_IDENTITY, identity, 40), (_CONFIG, body, 40), (_OUTPUT, body, 20)):
        for vendor, (points, hits) in _score(table, source, cap).items():
            scores[vendor] += points
            evidence[vendor].extend(hits)

    # The Aruba header ("; JL356A Configuration Editor") is part of the
    # running-config, not an identity command, so it is picked up through the
    # CONFIG table above; model hint reads it from the whole body too.
    model = _model_hint(identity, lines) or _model_hint(body, lines)
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    best_vendor, best_score = ranked[0]
    runner_up = ranked[1][1]

    detection = Detection(scores=scores, model_hint=model)
    if best_score < 6:
        detection.confidence = "none"
        return detection

    if best_score >= 14 and best_score >= runner_up * 2:
        confidence = "high"
    elif best_score >= 8 and best_score > runner_up:
        confidence = "medium"
    else:
        confidence = "low"

    # A recognised hardware part number is the most direct statement of the
    # brand. If it disagrees with the keyword score, trust the part number
    # but only when it came from the device's own identity sections.
    model_vendor = vendor_from_model(_model_hint(identity, lines))
    if model_vendor and model_vendor != best_vendor and scores.get(model_vendor, 0) > 0:
        best_vendor = model_vendor
        confidence = "medium" if confidence == "high" else confidence

    detection.vendor = best_vendor
    detection.confidence = confidence
    detection.evidence = evidence[best_vendor][:6]
    return detection
