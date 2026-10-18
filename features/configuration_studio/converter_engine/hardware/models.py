"""Data classes for the hardware catalog.

The catalog answers one question for the converters: *which physical ports does this box really have, and what does the CLI call
each of them?*  Port names are generated from templates so a stack of N members, or a module in the uplink slot, never needs a
hand-typed list.

Naming templates use ``{m}`` for the stack/VSF member, ``{n}`` for the port number inside the group.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# CLI keyword -> speed class.  The keyword in a running-config tells the operating speed of that stanza; a multi-speed port
# (for example a 25G SFP28 cage) can legitimately appear under more than one keyword.
SPEED_BY_KEYWORD = {
    "FastEthernet": "100M",
    "GigabitEthernet": "1G",
    "TwoGigabitEthernet": "mGig",
    "FiveGigabitEthernet": "mGig",
    "TenGigabitEthernet": "10G",
    "TwentyFiveGigE": "25G",
    "FortyGigabitEthernet": "40G",
    "HundredGigE": "100G",
    # Huawei VRP keywords (CloudEngine switches): GE / MultiGE / 10GE / 25GE / 40GE / 100GE; older releases spell the
    # 10G ports XGigabitEthernet.
    "GE": "1G",
    "MultiGE": "mGig",
    "XGigabitEthernet": "10G",
    "10GE": "10G",
    "25GE": "25G",
    "40GE": "40G",
    "100GE": "100G",
}

# Abbreviations that show up in ``show`` output and in some running-configs.
KEYWORD_ABBREVIATIONS = {
    "fa": "FastEthernet",
    "gi": "GigabitEthernet",
    "tw": "TwoGigabitEthernet",
    "fi": "FiveGigabitEthernet",
    "te": "TenGigabitEthernet",
    "twe": "TwentyFiveGigE",
    "fo": "FortyGigabitEthernet",
    "hu": "HundredGigE",
}

SPEED_ORDER = ["100M", "1G", "mGig", "10G", "25G", "40G", "100G"]


@dataclass(frozen=True)
class PortGroup:
    """A run of identical ports: ``prefix`` + template filled with member and ``first..last``."""

    role: str  # access | uplink | mgmt
    prefix: str  # canonical CLI keyword ("GigabitEthernet", "Ethernet", "" for Aruba CX)
    template: str  # "{m}/0/{n}" | "1/{n}" | "0/0/{n}" | "0/0" ...
    first: int
    last: int
    speed: str  # speed class of the primary personality
    medium: str  # "RJ45", "SFP+", "QSFP28" ...
    poe: str = ""  # "", "PoE+", "UPOE" ...
    aliases: tuple[str, ...] = ()  # other CLI keywords that address the same physical port
    note: str = ""
    per_member: bool = True  # False: one per box regardless of member count (management)

    @property
    def count(self) -> int:
        return self.last - self.first + 1

    def keywords(self) -> tuple[str, ...]:
        return (self.prefix, *self.aliases)

    def name(self, member: int, number: int, keyword: str | None = None) -> str:
        return f"{keyword if keyword is not None else self.prefix}{self.template.format(m=member, n=number)}"

    def range_label(self) -> str:
        return self.template.format(m="<m>", n=f"{self.first}-{self.last}" if self.count > 1 else self.first)


@dataclass(frozen=True)
class UplinkModule:
    """A field-replaceable uplink/network module in the slot-1 position of a modular Catalyst."""

    key: str
    label: str
    ports: int
    speed: str  # fastest speed class
    keywords: tuple[str, ...]  # CLI keywords this module's ports may appear under (primary first)
    medium: str
    note: str = ""

    def group(self) -> PortGroup:
        return PortGroup(
            role="uplink",
            prefix=self.keywords[0],
            template="{m}/1/{n}",
            first=1,
            last=self.ports,
            speed=self.speed,
            medium=self.medium,
            aliases=self.keywords[1:],
            note=self.note or f"{self.key} in network-module slot 1",
        )


@dataclass(frozen=True)
class ModuleSlot:
    """An expansion slot on a router: how its interfaces are named and what was actually seen in it."""

    name: str  # "NIM slot 1"
    naming: str  # "GigabitEthernet0/1/<port>"
    accepts: str
    observed: str = ""  # module and ports seen in a sample config, if any


@dataclass(frozen=True)
class HardwareModel:
    key: str  # canonical product ID, e.g. "C9300-48P"
    vendor: str  # Cisco | Aruba
    kind: str  # switch | router
    platform: str  # "Catalyst 9300" ...
    os_name: str  # IOS-XE | NX-OS | AOS-CX | IOS
    label: str
    summary: str
    groups: tuple[PortGroup, ...]
    modules: tuple[str, ...] = ()  # compatible UplinkModule keys
    default_module: str = ""
    max_members: int | None = None
    detect: tuple[str, ...] = ()  # strings (upper-case) that identify this model in a config / inventory
    doc_title: str = ""
    doc_url: str = ""
    target_ok: bool = False  # the translators emit this OS's syntax, so it may be picked as a conversion target
    samples: tuple[str, ...] = ()  # which sample folders had it (no hostnames are stored)
    slots: tuple[ModuleSlot, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    def all_keys(self) -> tuple[str, ...]:
        return (self.key, *self.detect)
