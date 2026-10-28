"""Anonymized copy of a topology: the same pictures and tables, with the names and numbers that identify a network replaced.

The copy is built from the *saved device state* (the same data ``topology.json`` carries), so every derived fact (links, roles, sites, L3
edges, findings) is computed again from the pseudonyms and the pictures stay consistent with each other.  Nothing here edits an output file.

What is replaced, and how (all consistent within one export; every export uses a new random key, so two exports of the same captures do not match each other):

* **Hostnames, domain labels, file names, descriptions, VRF names and F5 object names** - word by word.  A word that only names things
  (``SBY``, ``Akunting``) becomes another word of the same length and the same letter / digit pattern (``QRZ``, ``Xmgvpbc``), in the case of the
  original, so a hostname still reads like a hostname and the order of devices in a row stays alike (the pseudonyms are handed out in natural
  order of the original words).  Words that carry meaning for the picture stay: role words (``FW``, ``CORE``, ``SW``), interface and protocol
  names, generic words (``uplink``, ``to``), the words the program itself prints, and numbers.  See ``VOCABULARY``.
* **IPv4 and IPv6 addresses** - prefix-preserving: two addresses that share a /24 (or any shorter prefix) still share one, so subnets, /30
  peers and the L3 picture keep their shape.  The last octet is kept, so ``.1`` is still ``.1``.  Private ranges stay private, public stay
  public, masks and wildcard masks are untouched, a prefix such as ``10.1.0.0/24`` stays a valid network.
* **MAC addresses** - the vendor prefix (OUI) stays (a VMware host is still recognised), the rest is replaced.  Multicast, broadcast and
  FHRP virtual MACs stay.
* **Serial numbers** - same length and same letter / digit pattern, other characters.

The key to every replacement is written to a separate file (``anonymization-map.csv``) that never goes into the shareable pack.  A scan of the
finished files for any original name, address or serial is part of the result: leftovers are reported, not hidden.
"""

from __future__ import annotations

import functools
import hashlib
import json
import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

from .extract import Device
from .inferred import _CLOUD_WORDS, _STOP
from .l3cloud import PROVIDERS, WORD_TYPE, _TYPE_WORDS
from .roles import _WORD_RULES
from .state import device_from_state, device_to_state

# ----------------------------------------------------------------------------------------------------------------- vocabulary
VOCABULARY = frozenset("""
a an the of for to from in on at by with and or not no new old via per vs
interface interfaces port ports link links uplink downlink peer peers member members bundle channel trunk trunks lag ae po portchannel eth
ethernet fastethernet gigabitethernet tengigabitethernet twentyfivegige fortygigabitethernet hundredgige fortygige tengige gigabit gig gige
fa gi te tw twe fo fi hu hun et eth xe ge xge mgmt management oob console serial sfp qsfp slot module stack stacking unit
vlan vlans vl vlanif vif svi bvi bdi ve loopback lo tunnel tu tun null nve nvi vxlan vni vtep irb ethtrunk eth-trunk bridge br
ospf bgp eigrp isis rip static connected local hsrp vrrp glbp fhrp lacp pagp stp rstp mstp pvst rpvst cdp lldp vtp dhcp dns ntp snmp ssh telnet
http https tcp udp icmp ip ipv4 ipv6 arp mac bfd mpls ldp vpn vrf vxlan evpn sdwan omp ipsec gre tls ssl qos acl nat pat ha vpc mlag mclag vsf vss irf
sync config configuration failover cluster active standby primary secondary backup master slave pri sec
core agg aggr aggregation access distribution dist edge border leaf spine tor router rtr rt switch sw firewall fw fwl ngfw lb slb gslb ltm gtm adc
wlc wlan ap aps wap phone server srv host hosts fabric fi ucs esx esxi hv vm vms san nas wan lan man dmz inside outside internet isp provider transit
backbone ce pe cr ds as ext
self client side production prod test lab dev staging uat sit nft demo temp
system intf int vmanage viptela vedge catalyst nexus cisco huawei aruba juniper fortinet fortigate paloalto palo alto f5 bigip big mikrotik hpe hp dell
default global public private mpls biz lte ethernet wired wireless broadband metro red blue green silver gold bronze custom
up down admin shutdown enabled disabled established full half auto on off yes
g m k gbps mbps kbps
txt log cfg conf bak backup zip json csv xml html
com net org edu gov int local lan localdomain internal id co io info biz
hq dc dr
connect connected connection conn user users voice data spare unused reserved free nouse vsx isl keepalive telco wanr gw gateway
round robin ratio least connections observed predictive fastest dynamic virtual pool address protocol reached ok monitor check response code available offline
enabled disabled forwarding standard performance profile persistence snat automap iapp irule rule policy partition route domain floating selfip self-ip
""".split())

_ROLE_RULES = [re.compile(pattern, re.I) for _, pattern in _WORD_RULES]
# words the program itself reads in names and descriptions (neighbor inference, provider clouds): they must stay readable, or the picture changes
_PROGRAM_WORDS = {w.lower() for text in [*_STOP, *_CLOUD_WORDS, *PROVIDERS, *(word for word, _ in WORD_TYPE), *_TYPE_WORDS] for w in re.findall(r"[A-Za-z0-9]+", text)}
VOCABULARY = frozenset(VOCABULARY | _PROGRAM_WORDS)
_FREE_KEYS = frozenset(("description", "remote_port_desc", "name", "vrf", "id", "parent", "pool", "default pool", "members", "node", "used by",
                        "destination", "badge", "vlan", "interfaces", "interface", "source", "unit", "chassis", "hostname", "fqdn", "remote_name", "reason", "facts"))
_NAME_KEYS = frozenset(("hostname", "fqdn", "remote_name", "source", "unit", "chassis"))    # their words are the hostname words other fields refer to
_FREE_VALUE_DICTS = frozenset(("descriptions",))        # every value is free text, the keys are ports
_NAMED_KEY_DICTS = frozenset(("state", "trunks", "wan_colour"))   # the keys are interface / trunk / colour names
_NO_ADDRESS_KEYS = frozenset(("os_version", "release", "remote_platform", "model"))   # 17.9.4.1 is a version, not an address
_SPECIAL_FIRST_OCTETS = {100: lambda n: n >> 22 == 102401, 169: lambda n: n >> 16 == 0xA9FE, 172: lambda n: n >> 20 == 0xAC1, 192: lambda n: n >> 16 == 0xC0A8}
_CLEAN_OCTETS = tuple(o for o in range(1, 224) if o not in (10, 100, 127, 169, 172, 192))

_TOKEN = re.compile(
    r"(?P<maccol>(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?P<sep>[:-])(?:[0-9A-Fa-f]{2}(?P=sep)){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f]|[:-][0-9A-Fa-f]))"
    r"|(?P<machy>(?<![0-9A-Fa-f-])[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}(?![0-9A-Fa-f]|-[0-9A-Fa-f]))"
    r"|(?P<dash>(?<![\d.])(?:\d{1,3}-){3}\d{1,3}(?![\d]))"
    r"|(?P<ip4>(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d))"
    r"|(?P<macdot>(?<![0-9A-Fa-f.])[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}(?![0-9A-Fa-f]|\.[0-9A-Fa-f]))"
    r"|(?P<mac12>(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f]))"
    r"|(?P<ip6>(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:]))"
    r"|(?P<word>[A-Za-z0-9]+)")
_WORDS = re.compile(r"[A-Za-z0-9]+")


@functools.lru_cache(maxsize=1)
def own_words() -> frozenset[str]:
    """Every word the program itself can print: the words of all string constants in this package (report prose, legends, labels, drawio style names).
    The leftover scan must not flag these; it looks for words that came from the captures."""
    import ast
    from pathlib import Path
    words: set[str] = set()
    for path in Path(__file__).parent.glob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                words.update(w.lower() for w in _WORDS.findall(node.value))
    return frozenset(words)


def _natural(word: str) -> list[tuple[int, Any]]:
    return [(0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"(\d+)", word.lower()) if p]


def _is_mask(n: int) -> bool:
    inverse = ~n & 0xFFFFFFFF
    return inverse & (inverse + 1) == 0 or n & (n + 1) == 0       # netmask (ones then zeros) or wildcard (zeros then ones)


def _worth_a_serial(text: str) -> bool:
    """A serial number is replaced wherever it appears as a word; short or digit-free values (``NA``, ``stack``) would hit ordinary words."""
    return len(text) >= 5 and any(c.isdigit() for c in text) and bool(_WORDS.fullmatch(text))


def _style(mapped: str, original: str) -> str:
    if original.islower():
        return mapped.lower()
    if not original.isupper() and original[:1].isupper() and original[1:].islower():
        return mapped.capitalize()
    return mapped


def _candidate(word: str, slots: list[int], counter: int) -> str:
    """The ``counter``-th pseudonym of this shape: letters in the letter positions (base 26, base 36 when 26 ** n is used up), digits copied."""
    base = 26 if counter < 26 ** len(slots) else 36
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[:base]
    out = list(word.upper())
    value = counter
    for position in reversed(slots):
        value, digit = divmod(value, base)
        out[position] = alphabet[digit]
    return "".join(out)


@dataclass
class Anonymized:
    devices: list[Device]
    title: str
    hints: str
    mapping: list[dict[str, str]] = field(default_factory=list)
    sensitive: dict[str, set[str]] = field(default_factory=dict)     # kind -> original values the finished files must not contain
    state_text: str = ""                                              # the anonymized saved state as JSON: addresses are checked here, where nothing is derived


class Anonymizer:
    """One export's worth of consistent pseudonyms.  ``salt`` makes the address and serial replacements unguessable; tests pass a fixed one."""

    def __init__(self, salt: bytes | None = None) -> None:
        self.salt = salt or secrets.token_bytes(16)
        self.words: dict[str, str] = {}              # lower-case original word -> pseudonym word
        self.name_words: set[str] = set()            # words of hostnames: replaced wherever they occur
        self.free_words: set[str] = set()            # words of free text: replaced inside free text
        self.serials: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.out_addresses: set[str] = set()          # every address the anonymizer wrote (a pseudonym may equal another original address)
        self.macs: dict[str, str] = {}
        self._flip: dict[tuple[int, int, int], int] = {}
        self._octets: dict[int, int] = {}
        order = sorted(_CLEAN_OCTETS, key=lambda o: self._digest(b"octet", str(o).encode())[0:4])
        self._octet_map = dict(zip(sorted(_CLEAN_OCTETS), order))

    # ------------------------------------------------------------------ primitives
    def _digest(self, *parts: bytes, size: int = 16) -> bytes:
        return hashlib.blake2b(b"\0".join(parts), key=self.salt, digest_size=size).digest()

    def _bit(self, width: int, prefix: int, tweak: int) -> int:
        key = (width, prefix, tweak)
        bit = self._flip.get(key)
        if bit is None:
            bit = self._flip[key] = self._digest(b"bit", width.to_bytes(2, "big"), prefix.to_bytes(17, "big"), tweak.to_bytes(2, "big"), size=1)[0] & 1
        return bit

    # ------------------------------------------------------------------ addresses
    def ipv4(self, text: str, plen: int | None = None) -> str:
        """Mapped dotted address; ``plen`` zeroes the host bits of the result when the text was a network (``10.1.0.0/24``)."""
        octets = text.split(".")
        n = (int(octets[0]) << 24) | (int(octets[1]) << 16) | (int(octets[2]) << 8) | int(octets[3])
        if _is_mask(n):
            return text
        mapped = self._map4(n)
        if plen is not None and 0 <= plen < 32:
            hostmask = (1 << (32 - plen)) - 1
            if n & hostmask == 0:                                    # a network (10.1.0.0/24) stays a network; 10.1.0.5/24 is a host with a length
                mapped &= ~hostmask & 0xFFFFFFFF
        out = ".".join(str((mapped >> s) & 255) for s in (24, 16, 8, 0))
        self.ips.setdefault(text, out)
        self.out_addresses.add(out)
        return out

    def _map4(self, n: int) -> int:
        first = n >> 24
        if first == 0 or first == 127 or first >= 224:
            return n
        fixed = 0
        if first == 10:
            fixed = 8
        elif n >> 20 == 0xAC1:
            fixed = 12
        elif n >> 16 == 0xC0A8 or n >> 16 == 0xA9FE:
            fixed = 16
        elif n >> 22 == 102401:
            fixed = 10
        elif first in self._octet_map:
            base = (self._octet_map[first] << 24) | (n & 0xFFFFFF)
            return self._scramble_keep_host(base, 8, 24, orig=n)
        else:                                                   # 100, 169, 172, 192 outside their special ranges keep the first octet
            return self._scramble_keep_host(n, 8, 24, orig=n, avoid=_SPECIAL_FIRST_OCTETS.get(first))
        return self._scramble_keep_host(n, fixed, 24, orig=n)

    def _scramble_keep_host(self, value: int, start: int, stop: int, orig: int, avoid: Callable[[int], bool] | None = None) -> int:
        for tweak in range(64):
            out = self._scramble_from(orig, value, start, stop, tweak)
            if avoid is None or not avoid(out):
                return out
        return value

    def _scramble_from(self, orig: int, value: int, start: int, stop: int, tweak: int) -> int:
        """Flip bits ``start`` .. ``stop`` of ``value`` by the PRF of the *original* prefix, keep everything else."""
        out = value
        for i in range(start, stop):
            if self._bit(32, orig >> (32 - i), (tweak << 8) | i):
                out ^= 1 << (31 - i)
        return out

    def ipv6(self, text: str, plen: int | None = None) -> str:
        try:
            addr = ipaddress.IPv6Address(text)
        except ValueError:
            return text
        n = int(addr)
        if n in (0, 1) or n >> 120 == 0xFF:                              # :: and ::1 and multicast ff00::/8 are protocol constants
            return text
        fixed = 3 if n >> 125 == 1 else 7 if n >> 121 == 0x7E else 64 if n >> 118 == 0x3FA else 0       # link-local stays fe80::/64, only the interface id changes
        out = n
        for i in range(fixed, 112):
            if self._bit(128, n >> (128 - i), i):
                out ^= 1 << (127 - i)
        if plen is not None and 0 <= plen < 128 and n & ((1 << (128 - plen)) - 1) == 0:
            out &= ((1 << 128) - 1) ^ ((1 << (128 - plen)) - 1)
        result = str(ipaddress.IPv6Address(out))
        self.ips.setdefault(text, result)
        self.out_addresses.add(result)
        return result

    def mac(self, text: str) -> str:
        digits = re.sub(r"[^0-9A-Fa-f]", "", text).lower()
        if int(digits[1], 16) & 1 or digits == "0" * 12 or re.match(r"(00000c07ac|00000c9ff|00005e0001|00005e0002|0007b400|00005e00)", digits):
            return text                                              # multicast / broadcast / FHRP virtual MACs are protocol constants
        mapped = self.macs.get(digits)
        if mapped is None:
            tail = self._digest(b"mac", digits.encode(), size=3).hex()
            mapped = self.macs[digits] = digits[:6] + tail
        upper = text.upper() == text and any(c.isalpha() for c in text)
        shown = mapped.upper() if upper else mapped
        if "." in text:
            return f"{shown[0:4]}.{shown[4:8]}.{shown[8:12]}"
        if "-" in text and len(text.split("-")[0]) == 4:             # Huawei: 0050-5611-2233
            return f"{shown[0:4]}-{shown[4:8]}-{shown[8:12]}"
        for sep in (":", "-"):
            if sep in text:
                return sep.join(shown[i:i + 2] for i in range(0, 12, 2))
        return shown

    def serial(self, text: str) -> str:
        mapped = self.serials.get(text.lower())
        if mapped is None:
            stream = self._digest(b"serial", text.lower().encode(), size=max(len(text), 1) * 2)
            chars = []
            for i, ch in enumerate(text):
                value = stream[i]
                chars.append(str(value % 10) if ch.isdigit() else chr(65 + value % 26) if ch.isupper() else chr(97 + value % 26))
            mapped = self.serials[text.lower()] = "".join(chars)
        return mapped

    # ------------------------------------------------------------------ words
    def keeps(self, word: str) -> bool:
        low = word.lower()
        if low.isdigit() or low in VOCABULARY:
            return True
        letters = re.sub(r"\d", "", low)
        if len(letters) <= 1 or letters in VOCABULARY:
            return True
        return any(rule.search(f"-{word}-") for rule in _ROLE_RULES)

    def _word(self, word: str, free: bool) -> str:
        low = word.lower()
        if low in self.serials:
            return _style(self.serials[low], word)
        if free:
            if self.keeps(word):
                return word
        elif low not in self.name_words or self.keeps(word):
            return word
        mapped = self.words.get(low)
        return word if mapped is None else _style(mapped, word)

    # ------------------------------------------------------------------ text
    def text(self, value: str, free: bool = False, addresses: bool = True) -> str:
        """One string: addresses and MACs first (they are matched as whole tokens), then the words."""
        if not value:
            return value

        def swap(m: re.Match[str]) -> str:
            kind = m.lastgroup if m.lastgroup != "sep" else "maccol"
            token = m.group()
            if kind == "word":
                return self._word(token, free)
            if not addresses and kind in ("ip4", "dash", "ip6"):
                return token
            if kind == "ip4":
                parts = token.split(".")
                if any(int(p) > 255 for p in parts):
                    return token
                rest = m.string[m.end():m.end() + 4]
                length = re.match(r"/(\d{1,2})(?!\d)", rest)
                return self.ipv4(token, int(length.group(1)) if length else None)
            if kind == "dash":
                parts = token.split("-")
                if any(int(p) > 255 for p in parts) or len(token) < 7:
                    return token
                return self.ipv4(".".join(parts)).replace(".", "-")
            if kind in ("macdot", "maccol", "machy", "mac12"):
                return self.mac(token)
            if kind == "ip6":
                if token.count(":") < 2 or ":::" in token:
                    return token
                length = re.match(r"/(\d{1,3})(?!\d)", m.string[m.end():m.end() + 5])
                return self.ipv6(token, int(length.group(1)) if length else None)
            return token

        return _TOKEN.sub(swap, value)

    # ------------------------------------------------------------------ walk over the state
    def _collect(self, value: Any, key: str = "", free: bool = False, names: bool = False) -> None:
        if isinstance(value, str):
            if free or names:
                for word in _WORDS.findall(value):
                    low = word.lower()
                    if self.keeps(word) or low in self.serials:
                        continue
                    self.free_words.add(low)
                    if names:
                        self.name_words.add(low)
            return
        if isinstance(value, dict):
            lower = key.lower()
            for k, v in value.items():
                if lower in _NAMED_KEY_DICTS:
                    self._collect(str(k), free=True)
                self._collect(v, str(k), free or lower in _FREE_VALUE_DICTS or str(k).lower() in _FREE_KEYS, names or str(k).lower() in _NAME_KEYS)
        elif isinstance(value, (list, tuple, set)):
            for v in value:
                self._collect(v, key, free, names)

    def _apply(self, value: Any, key: str = "", free: bool = False, plain: bool = False) -> Any:
        if isinstance(value, str):
            return self.text(value, free=free, addresses=not plain)
        if isinstance(value, dict):
            lower = key.lower()
            out = {}
            for k, v in value.items():
                new_key = self.text(k, free=lower in _NAMED_KEY_DICTS) if isinstance(k, str) else k
                lk = str(k).lower()
                out[new_key] = self._apply(v, str(k), free or lower in _FREE_VALUE_DICTS or lk in _FREE_KEYS, plain or lk in _NO_ADDRESS_KEYS)
            return out
        if isinstance(value, list):
            return [self._apply(v, key, free, plain) for v in value]
        return value

    def _number_words(self) -> None:
        """One pseudonym per word, of the *same length and the same letter / digit pattern* as the word: the program's rules about names (a name
        shorter than 4 characters is not looked for in descriptions, a fragment needs a digit) then see the same shape.  Within one shape the
        pseudonyms run in natural order of the words (AAAAA1, AAAAB2 ...); a pseudonym never equals a role word, a vocabulary word or a word of the data."""
        ordered = sorted(self.free_words | self.name_words, key=_natural)
        taken = set(ordered)
        used: dict[tuple[bool, ...], int] = {}
        self.words = {}
        for low in ordered:
            shape = tuple(c.isdigit() for c in low)
            slots = [i for i, digit in enumerate(shape) if not digit]
            counter = used.get(shape, 0)
            while True:
                candidate = _candidate(low, slots, counter)
                counter += 1
                if candidate.lower() not in taken and not self.keeps(candidate):
                    break
            used[shape] = counter
            taken.add(candidate.lower())
            self.words[low] = candidate

    # ------------------------------------------------------------------ public
    def run(self, devices: list[Device], title: str = "", hints: str = "") -> Anonymized:
        states = [device_to_state(d) for d in devices if d.captured]
        for state in states:
            for serial in list(state.get("serials", [])) + [h.get("remote_serial", "") for h in state.get("halves", [])]:
                if _worth_a_serial(str(serial)):
                    self.serial(str(serial))
        for state in states:
            self._collect(state)
        self._collect(title, free=True, names=False)
        self._collect(hints, free=True)
        self._number_words()
        anonymised = []
        for state in states:
            device = device_from_state(self._apply(state))
            device.captured = True
            device.carried = False
            anonymised.append(device)
        new_title = self.text(title, free=True) if title else ""
        new_hints = self.text(hints, free=True) if hints else ""
        mapping = self._mapping_rows()
        state_text = json.dumps([device_to_state(d) for d in anonymised], ensure_ascii=False)
        return Anonymized(anonymised, new_title, new_hints, mapping, self._sensitive(), state_text)

    def _mapping_rows(self) -> list[dict[str, str]]:
        rows = [{"kind": "word", "original": low, "replacement": new} for low, new in sorted(self.words.items(), key=lambda kv: kv[1])]
        rows += [{"kind": "serial", "original": low.upper(), "replacement": new} for low, new in sorted(self.serials.items())]
        rows += [{"kind": "address", "original": a, "replacement": b} for a, b in sorted(self.ips.items(), key=lambda kv: kv[1])]
        rows += [{"kind": "mac", "original": a, "replacement": b} for a, b in sorted(self.macs.items(), key=lambda kv: kv[1])]
        return rows

    def _sensitive(self) -> dict[str, set[str]]:
        """What a finished file must not contain.  A value that is also a pseudonym (a word, an address, a MAC or a serial the program wrote itself) is
        left out: it cannot be told apart from the original."""
        written_words = {w.lower() for w in self.words.values()}
        written_serials = {v.lower() for v in self.serials.values()}
        written_macs = set(self.macs.values())
        return {"word": {w for w in self.words if len(w) >= 3 and w not in written_words and w not in own_words()},
                "serial": {s for s in self.serials if s not in written_serials},
                "address": {a for a, b in self.ips.items() if a != b and a not in self.out_addresses},
                "mac": {m for m, b in self.macs.items() if m != b and m not in written_macs}}


def anonymize(devices: list[Device], title: str = "", hints: str = "", salt: bytes | None = None) -> Anonymized:
    return Anonymizer(salt).run(devices, title, hints)


# ----------------------------------------------------------------------------------------------------------------- leftover scan
def find_leftovers(result: Anonymized, texts: dict[str, str], limit: int = 40) -> list[dict[str, str]]:
    """Original names, serials or MACs still present in the finished files, and original addresses still present in the anonymized saved state:
    ``[{kind, value, file}]`` (first file only).  An address is not looked for in the finished files: Keystone computes networks and ranges
    from the pseudonyms, and a computed address can equal an original one without being it."""
    wanted = result.sensitive
    found: dict[tuple[str, str], str] = {}

    def scan(name: str, text: str, addresses: bool) -> None:
        for m in _TOKEN.finditer(text):
            kind, token = m.lastgroup, m.group()
            if kind == "word":
                low = token.lower()
                if low in wanted["word"]:
                    found.setdefault(("word", low), name)
                elif low in wanted["serial"]:
                    found.setdefault(("serial", low.upper()), name)
            elif kind in ("macdot", "maccol", "machy", "mac12"):
                digits = re.sub(r"[^0-9A-Fa-f]", "", token).lower()
                if digits in wanted["mac"]:
                    found.setdefault(("mac", digits), name)
            elif addresses and kind in ("ip4", "ip6") and token.lower() in wanted["address"]:
                found.setdefault(("address", token), name)

    for name, text in texts.items():
        scan(name, text, False)
    scan("(saved state)", result.state_text, True)
    return [{"kind": k, "value": v, "file": f} for (k, v), f in sorted(found.items())][:limit]
