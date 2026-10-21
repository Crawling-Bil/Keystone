"""Name handling: hostnames, serials and interface names must compare equal across vendors and commands."""

from __future__ import annotations

import re

_SERIAL_SUFFIX = re.compile(r"\(([A-Za-z0-9]{6,20})\)\s*$")
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
# LLDP summary tables print the capability codes in front of the port id ("BR Ethernet1/49").
_CAPABILITY_PREFIX = re.compile(r"^(?:[BRTWSCODPA]{1,6})\s+(?=\S*\d)")

# longest prefix first; the value is the short form used for comparing and for labels
_PORT_PREFIXES = (
    ("twentyfivegige", "Twe"), ("twentyfivegigabitethernet", "Twe"), ("twe", "Twe"),
    ("hundredgige", "Hu"), ("hundredgigabitethernet", "Hu"), ("hu", "Hu"),
    ("fortygigabitethernet", "Fo"), ("fortygige", "Fo"), ("fo", "Fo"),
    ("tengigabitethernet", "Te"), ("tengige", "Te"), ("te", "Te"),
    ("gigabitethernet", "Gi"), ("gige", "Gi"), ("gi", "Gi"),
    ("fastethernet", "Fa"), ("fa", "Fa"),
    ("ethernet", "Eth"), ("eth", "Eth"),
    ("port-channel", "Po"), ("portchannel", "Po"), ("po", "Po"),
    ("mgmt", "mgmt"),
    ("xgigabitethernet", "XGE"), ("10ge", "XGE"), ("xge", "XGE"),
    ("25ge", "25GE"), ("40ge", "40GE"), ("100ge", "100GE"),
    ("eth-trunk", "Eth-Trunk"), ("ge", "GE"),
)
_PORT_RE = re.compile(r"^([0-9]*[A-Za-z][A-Za-z\-]*?)\s*([0-9][0-9/.:]*)?$")


def strip_capability_prefix(port: str) -> str:
    """Remove LLDP capability codes glued to a port id: 'BR Ethernet1/49' -> 'Ethernet1/49'."""
    return _CAPABILITY_PREFIX.sub("", (port or "").strip())


def canon_port(port: str) -> str:
    """Short, comparable interface name: TenGigabitEthernet1/1/1 and Te1/1/1 both become 'Te1/1/1'."""
    text = strip_capability_prefix(port)
    if not text:
        return ""
    match = _PORT_RE.match(text)
    if not match:
        return text
    word, digits = match.group(1), match.group(2) or ""
    lowered = word.lower()
    for prefix, short in _PORT_PREFIXES:
        if lowered == prefix:
            return f"{short}{digits}"
    return f"{word}{digits}"


def split_serial(name: str) -> tuple[str, str]:
    """'LAB-AGG1.lab.example(FDO00000001)' -> ('LAB-AGG1.lab.example', 'FDO00000001')."""
    text = (name or "").strip()
    match = _SERIAL_SUFFIX.search(text)
    if match:
        return text[: match.start()].strip(), match.group(1).upper()
    return text, ""


_DOTTED_MAC = re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$", re.I)


def short_host(name: str) -> str:
    """Upper-case hostname without domain and without a '(SERIAL)' suffix. IP addresses are returned unchanged."""
    base, _ = split_serial(name)
    if not base:
        return ""
    if _IP.match(base):
        return base
    if _DOTTED_MAC.match(base):
        return base.lower()                      # a MAC used as a name (Cisco dotted form) keeps its dots
    return base.split(".")[0].strip().upper()


_PLATFORM_VERSION = re.compile(r"^(?P<model>.+?)[\s,]+v?(?P<version>\d+\.\d+(?:\.\d+)*[A-Za-z0-9()]*)$")
_VENDOR_BY_MODEL = (
    ("Cisco", re.compile(r"^(N\d[A-Z]?-|N\dK|C\d{4}|CISCO|WS-|UCS|ASR|ISR|CSR|IE-|AIR-|CBS|SG\d|MDS)", re.I)),
    ("Fortinet", re.compile(r"^(FortiGate|FortiSwitch|FortiAP|FG-|FGT)", re.I)),
    ("Palo Alto Networks", re.compile(r"^PA-\d", re.I)),
    ("F5", re.compile(r"^(BIG-IP|BIGIP)", re.I)),
    ("Aruba", re.compile(r"^(Aruba|JL\d|J\d{4})", re.I)),
)


_ARUBA_ANW = re.compile(r"^(?:HPE|Aruba|HP)\s+ANW\s+(?P<model>\S+)\s+(?P<version>[A-Z]{1,3}\.\d+(?:\.\d+)+\S*)\s*$", re.I)


def split_platform(platform: str) -> tuple[str, str, str]:
    """('FortiGate-1800F v7.2.9') -> ('FortiGate-1800F', '7.2.9', 'Fortinet'). The vendor is only named when the model
    prefix says so unambiguously; otherwise it stays empty rather than guessed."""
    text = (platform or "").strip()
    version = ""
    anw = _ARUBA_ANW.match(text)
    if anw:                                                    # LLDP system description of an AOS-CX switch: "HPE ANW JL724B ML.10.16.1020"
        return anw.group("model"), anw.group("version"), "Aruba"
    found = _PLATFORM_VERSION.match(text)
    if found and not text.lower().startswith("cisco"):
        text, version = found.group("model").strip(), found.group("version")
    vendor = next((name for name, pattern in _VENDOR_BY_MODEL if pattern.match(text)), "")
    return text, version, vendor


_NAME_SPEED = (("hu", 100000), ("100ge", 100000), ("fo", 40000), ("40ge", 40000), ("twe", 25000), ("25ge", 25000), ("te", 10000),
               ("xge", 10000), ("10ge", 10000), ("gi", 1000), ("ge", 1000), ("fa", 100))
_SPEED_IN_TEXT = re.compile(r"(?<!\d)(100|40|25|10)\s*G(?:B|E|IG)?", re.I)
_GIGABIT_TEXT = re.compile(r"1000\s*base|10/100/1000|\bGE\b|\b1G(?:B|E)?\b|\b1000\s*BASE", re.I)


def speed_from_port(port: str) -> int:
    """Rated speed in Mbit/s that the interface *name* implies (Te = 10 G, Gi = 1 G); 0 when the name says nothing (Eth1/1 on NX-OS)."""
    text = canon_port(port).lower()
    for prefix, speed in _NAME_SPEED:
        if re.match(rf"^{prefix}\d", text):
            return speed
    return 0


def speed_from_transceiver(text: str) -> int:
    """Rated speed in Mbit/s from a transceiver type or PID such as '10Gbase-SR', 'SFP-H25GB-SR', 'QSFP-40G-SR-BD', '1000base-T'."""
    found = _SPEED_IN_TEXT.search(text or "")
    if found:
        return int(found.group(1)) * 1000
    return 1000 if _GIGABIT_TEXT.search(text or "") else 0


def speed_text(mbps: int) -> str:
    """10000 -> '10G', 1000 -> '1G', 100 -> '100M', 0 -> ''."""
    if not mbps:
        return ""
    return f"{mbps // 1000}G" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps}M"


def is_ip(text: str) -> bool:
    return bool(_IP.match((text or "").strip()))


def is_bundle_name(port: str) -> bool:
    return canon_port(port).lower().startswith(("po", "eth-trunk", "bridge-aggregation", "lag"))


def port_sort_key(port: str) -> tuple:
    return tuple(int(part) if part.isdigit() else 0 for part in re.findall(r"\d+", port or "")) or (0,)
