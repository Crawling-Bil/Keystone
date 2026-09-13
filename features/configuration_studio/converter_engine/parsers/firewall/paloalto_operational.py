"""Parser for a PAN-OS "show"-command capture -- a PuTTY/terminal
session log of an admin running show system info / show interface all
/ show routing route / etc. interactively (as opposed to either PAN-OS
config export format the other two parsers in this package handle).
Built directly from a real PA-3020 (PAN-OS 9.0.5) capture -- see
_clean_putty_capture's own docstring for the exact terminal artifacts
that capture format is full of and how each one is undone.

This is a fundamentally different KIND of source than the "set"-format
CLI (paloalto.py) or the XML running-config export (paloalto_xml.py):
those are both *configuration* exports -- what the device is set up to
do -- and this is an *operational* capture -- what the device reports
about itself and its current state. The two are complementary rather
than overlapping: model/serial/sw-version/uptime and real hardware
port speed/duplex/state/MAC exist ONLY here (a config export has no
idea what firmware it's running or which physical link is up), while
security rules/NAT/zone definitions/address objects exist ONLY in a
config export (an operational capture never lists the policy, just
what it currently matches against). A dashboard built from this source
alone is therefore deliberately partial -- see PaloAltoOperationalCaptureParser's
own docstring for exactly which PaloAltoNativeConfig fields it can and
cannot populate.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from features.configuration_studio.converter_engine.models.paloalto_native import (
    PaDeviceInfo,
    PaInterface,
    PaloAltoNativeConfig,
    PaStaticRoute,
    PaVirtualRouter,
    PaZone,
)

_ANSI_ESCAPE_RE = re.compile(r"\x1b(\[[0-9;?]*[a-zA-Z]|[=>])")

_PROMPT_COMMAND_RE = re.compile(r"^\S+@\S+>\s*(show|request)\s+(.+)$")
_BARE_PROMPT_RE = re.compile(r"^\S+@\S+>\s*$")
# The `less` pager's own "lines N-M" status banner (rendered in reverse
# video -- see _clean_putty_capture's docstring). It's meant to be
# transient screen furniture the terminal overwrites, so it only
# survives into the cleaned text as its own standalone line when
# whatever read the file translated the capture's mid-line "\r" redraw
# into a real "\n" before this parser ever saw it (Python's own
# universal-newlines text mode does exactly that -- and does, on the
# actual upload path: config_upload.save() + Path.read_text() upstream
# in switch_analyzer/routes.py). Confirmed on the real reference
# capture this parser was built against, where one such banner landed
# midway through "show interface all"'s logical-interface table and,
# left unfiltered, was sliced into a bogus extra interface row.
_PAGER_BANNER_RE = re.compile(r"^lines?\s+\d+-\d+$", re.IGNORECASE)
# Unanchored variant of _PROMPT_COMMAND_RE for looks_like_paloalto_operational_capture:
# that check runs against the RAW (uncleaned) text, where a real prompt
# line is usually preceded by a mid-line "\r" redraw rather than a true
# "\n" line start (see _clean_putty_capture's own docstring), so a
# "^"-anchored search against the whole multi-line blob would only ever
# test the very first character of the file -- this sniff only needs to
# know the pattern occurs somewhere, not at a specific column.
_PROMPT_COMMAND_SNIFF_RE = re.compile(r"\S+@\S+>\s*(show|request)\s+\S+")


class PaloAltoOperationalParseError(ValueError):
    """Raised when the given text doesn't look like a PAN-OS
    show-command capture this parser recognizes at all (see
    looks_like_paloalto_operational_capture)."""


def _clean_putty_capture(raw_text: str) -> str:
    """Undoes three kinds of terminal-emulation noise a raw PuTTY log
    of an interactive PAN-OS CLI session is full of, all confirmed on
    a real capture:

    1. ANSI escape sequences (cursor/mode control, e.g. "\\x1b[?1h",
       "\\x1b[K", the pager's reverse-video "\\x1b[7m...\\x1b[27m") --
       stripped outright, they carry no data.

    2. Bare carriage returns used for in-place redraw rather than a
       line ending -- most visibly, PAN-OS's own tab-completion/typeahead
       echo, where a single logical command line arrives as multiple
       "\\r"-separated redraws of an increasingly complete command (e.g.
       "show \\rshow system \\rshow system info"). Only the text after the
       LAST "\\r" in a line is what was actually left on screen, so
       that's the only part kept.

    3. Backspace bytes (\\x08) embedded mid-field in wrapped table
       output (confirmed in "show interface all"'s logical-interface
       table, where a narrow terminal wrapped a long CIDR address and
       the redraw used a literal backspace instead of reflowing) --
       resolved the same way a real terminal would: each backspace
       deletes the character immediately before it. E.g. the raw bytes
       "103.164.100.2" + " " + "\\x08" + "43/28" reconstruct to the
       real address "103.164.100.243/28", not visible as such in the
       raw log without this step.
    """
    text = _ANSI_ESCAPE_RE.sub("", raw_text)
    cleaned_lines: list[str] = []
    for line in text.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if "\r" in line:
            line = line.rsplit("\r", 1)[1]
        buf: list[str] = []
        for ch in line:
            if ch == "\x08":
                if buf:
                    buf.pop()
            else:
                buf.append(ch)
        cleaned_lines.append("".join(buf))
    return "\n".join(cleaned_lines)


def looks_like_paloalto_operational_capture(raw_text: str) -> bool:
    """Auto Detect / vendor-sniff hook, mirroring
    PaloAltoFirewallParser._looks_like_xml's role for the XML source.
    Deliberately cheap (no cleaning pass) since it only needs to rule
    the *other* two Palo Alto formats out and find one confident marker
    a real captured session always has."""
    stripped = raw_text.lstrip("﻿ \t\r\n")
    if stripped.startswith("<?xml") or stripped.startswith("<config"):
        return False
    if stripped.startswith("set "):
        return False
    return bool(_PROMPT_COMMAND_SNIFF_RE.search(raw_text)) and "show system info" in raw_text.lower()


def _parse_kv_section(lines: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lines:
        match = re.match(r"^([\w.-]+):\s?(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2).strip()
    return values


# "show interface all"'s logical-interface table is fixed-width in its
# HEADER only -- real column values routinely overflow their nominal
# width with no truncation (confirmed on the real reference capture:
# a 16-char-wide "zone" column header next to a real 22-character zone
# name), which shifts every column after it for that one row. Column-
# position slicing therefore can't reliably recover overflowing
# fields; token-sequence matching does, since every field here is
# either purely numeric (id/vsys/tag) or a single non-whitespace
# token (forwarding is "N/A"/"ha"/"vr:<name>", never containing a
# space) -- only zone and address can be empty or contain nothing
# regex needs to special-case beyond ".*?"/".*" doing the right thing
# by construction.
_LOGICAL_ROW_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<id>\d+)\s+(?P<vsys>\d+)\s+(?P<zone>.*?)\s+"
    r"(?P<forwarding>\S+)\s+(?P<tag>\d+)\s+(?P<address>.*)$"
)
# A continuation row for an interface with more than one IP (e.g. a
# secondary address) repeats only the address, right-aligned under the
# address column with everything else blank -- recognizable as a
# non-blank line where address is the ONLY token, and continuation
# rows never contain "N/A" (that would just be a first/only address).
_BARE_ADDRESS_RE = re.compile(r"^[0-9a-fA-F.:]+(/\d+)?$")


class PaloAltoOperationalCaptureParser:
    """Parses a PAN-OS interactive show-command capture into
    PaloAltoNativeConfig -- the same model the "set"-format and XML
    parsers target, so firewall_service.py's _build_from_paloalto()
    consumes all three sources unmodified.

    What this source CAN populate that neither config export can:
    config.device_info (model/serial/sw-version/uptime -- runtime
    identity, never present in a static config) and each PaInterface's
    hw_speed_duplex_state/hw_mac_address (live hardware link state,
    likewise never in a config). What it CANNOT populate at all:
    security_rules, nat_rules, address_objects, security_profiles,
    qos_profiles, ike/ipsec crypto -- none of that is operational
    data, it only ever exists in a config export. zones/interfaces/
    virtual_routers ARE populated here (from "show interface all"'s
    logical table and "show routing route"), but reflect only the
    interfaces/routes/zones the device happens to be actively using
    at capture time, not the full configured set the XML/set-format
    sources would show.
    """

    def parse_file(self, filename) -> PaloAltoNativeConfig:
        # newline="" keeps a bare mid-line "\r" (PAN-OS's own tab-
        # completion echo -- see _clean_putty_capture) distinct from a
        # real line ending, rather than Python's default universal-
        # newlines text mode translating it into another "\n" before
        # this parser ever sees it. Belt-and-suspenders: the app's own
        # upload path (switch_analyzer/routes.py) reads with the
        # default translation before this parser ever runs, so
        # _PAGER_BANNER_RE above is what actually protects that path;
        # this only matters when parse_file() is called directly on an
        # on-disk capture.
        with open(filename, "r", encoding="utf-8", errors="ignore", newline="") as file:
            raw_text = file.read()
        return self.parse_text(raw_text, source_file=str(filename))

    def parse_text(self, raw_text: str, source_file: str = "") -> PaloAltoNativeConfig:
        if not looks_like_paloalto_operational_capture(raw_text):
            raise PaloAltoOperationalParseError(
                "Doesn't look like a PAN-OS show-command capture (no 'show system info' output found)"
            )

        cleaned = _clean_putty_capture(raw_text)
        sections = self._split_into_sections(cleaned)

        config = PaloAltoNativeConfig(
            hostname="",
            source_vendor="Palo Alto",
            source_device_type="Firewall",
            source_file=source_file,
        )
        config.source_format = "operational"

        system_info = _parse_kv_section(sections.get("system info", []))
        if system_info:
            config.hostname = system_info.get("hostname", "")
            config.device_info = PaDeviceInfo(
                hostname=system_info.get("hostname", ""),
                mgmt_ip=system_info.get("ip-address", ""),
                mgmt_netmask=system_info.get("netmask", ""),
                mgmt_gateway=system_info.get("default-gateway", ""),
                domain="",
                timezone="",
            )
            # Runtime-only identity fields no config export ever carries
            # -- stashed in metadata rather than adding one-off fields to
            # PaDeviceInfo, since these are specific to this one source.
            config.metadata["model"] = system_info.get("model", "")
            config.metadata["serial"] = system_info.get("serial", "")
            config.metadata["sw_version"] = system_info.get("sw-version", "")
            config.metadata["uptime"] = system_info.get("uptime", "")
            config.metadata["family"] = system_info.get("family", "")
            config.metadata["app_version"] = system_info.get("app-version", "")
            config.metadata["av_version"] = system_info.get("av-version", "")
            config.metadata["threat_version"] = system_info.get("threat-version", "")
            config.metadata["mac_address"] = system_info.get("mac-address", "")

        hw_by_name, logical_rows = self._parse_interface_all(sections.get("interface all", []))
        self._build_interfaces_and_zones(config, hw_by_name, logical_rows)
        self._build_routing(config, sections.get("routing route", []))

        return config

    # -- section splitting ---------------------------------------------------

    @staticmethod
    def _split_into_sections(cleaned_text: str) -> dict[str, list[str]]:
        sections: dict[str, list[str]] = {}
        current_key: Optional[str] = None
        for line in cleaned_text.split("\n"):
            command_match = _PROMPT_COMMAND_RE.match(line.strip())
            if command_match:
                # The fullest/last-typed command line wins when PAN-OS's
                # own tab-completion echo left more than one recognizable
                # prompt on the same logical line -- not an issue after
                # _clean_putty_capture already collapsed those, but the
                # normalized key (lowercased, single-spaced) still keeps
                # "show interface all" distinct from a differently-cased
                # or double-spaced echo of the same command.
                current_key = " ".join(command_match.group(2).lower().split())
                sections.setdefault(current_key, [])
                continue
            if _BARE_PROMPT_RE.match(line.strip()):
                current_key = None
                continue
            if _PAGER_BANNER_RE.match(line.strip()):
                continue
            if current_key is not None:
                sections[current_key].append(line)
        return sections

    # -- "show interface all" ------------------------------------------------

    @staticmethod
    def _parse_interface_all(lines: list[str]) -> tuple[dict[str, dict[str, str]], list[list[str]]]:
        hw_by_name: dict[str, dict[str, str]] = {}
        logical_rows: list[list[str]] = []

        # Hardware table: "name  id  speed/duplex/state  mac address"
        # header, a dashes line, then one whitespace-separated row per
        # physical/virtual interface until the next blank line.
        hw_start = next((i for i, line in enumerate(lines) if line.strip().startswith("name") and "speed/duplex/state" in line), None)
        if hw_start is not None:
            for line in lines[hw_start + 2:]:
                if not line.strip():
                    break
                parts = line.split()
                if len(parts) >= 4:
                    hw_by_name[parts[0]] = {
                        "id": parts[1],
                        "speed_duplex_state": parts[2],
                        "mac_address": parts[3],
                    }

        # Logical table: token-sequence matched per row (see
        # _LOGICAL_ROW_RE's own comment for why column-position slicing
        # doesn't work here), skipping straight past the header and its
        # dashes line since neither is real data.
        logical_start = next((i for i, line in enumerate(lines) if line.strip().startswith("name") and "forwarding" in line), None)
        if logical_start is not None and logical_start + 1 < len(lines):
            for line in lines[logical_start + 2:]:
                stripped = line.strip()
                if not stripped:
                    break
                row_match = _LOGICAL_ROW_RE.match(line)
                if row_match:
                    logical_rows.append([
                        row_match.group("name"), row_match.group("id"), row_match.group("vsys"),
                        row_match.group("zone").strip(), row_match.group("forwarding"),
                        row_match.group("tag"), row_match.group("address").strip(),
                    ])
                elif _BARE_ADDRESS_RE.match(stripped):
                    # Continuation row: everything blank except a second
                    # address for the interface named on the row above.
                    logical_rows.append(["", "", "", "", "", "", stripped])

        return hw_by_name, logical_rows

    @staticmethod
    def _build_interfaces_and_zones(
        config: PaloAltoNativeConfig,
        hw_by_name: dict[str, dict[str, str]],
        logical_rows: list[list[str]],
    ) -> None:
        interfaces_by_name: dict[str, PaInterface] = {}
        order: list[str] = []
        zones_by_name: dict[str, list[str]] = {}
        vr_interfaces: dict[str, list[str]] = {}

        last_name = ""
        for row in logical_rows:
            # row = [name, id, vsys, zone, forwarding, tag, address]
            padded = row + [""] * (7 - len(row))
            name, _id, _vsys, zone, forwarding, tag, address = padded[:7]

            if name:
                last_name = name
                interface_type = (
                    "ethernet" if name.startswith("ethernet") else
                    "tunnel" if name.startswith("tunnel") else
                    "vlan" if name == "vlan" else
                    "loopback" if name == "loopback" else
                    "other"
                )
                iface = PaInterface(name=name, interface_type=interface_type, mode="layer3")
                tag_digits = tag.strip()
                if tag_digits.isdigit() and int(tag_digits) > 0:
                    iface.tag = int(tag_digits)
                if zone:
                    iface.zone = zone
                    zones_by_name.setdefault(zone, [])
                    if name not in zones_by_name[zone]:
                        zones_by_name[zone].append(name)
                vr_match = re.match(r"vr:(\S+)", forwarding)
                if vr_match:
                    vr_name = vr_match.group(1)
                    vr_interfaces.setdefault(vr_name, [])
                    if name not in vr_interfaces[vr_name]:
                        vr_interfaces[vr_name].append(name)
                hw = hw_by_name.get(name, {})
                iface.hw_speed_duplex_state = hw.get("speed_duplex_state", "")
                iface.hw_mac_address = hw.get("mac_address", "")
                interfaces_by_name[name] = iface
                order.append(name)
                target_name = name
            else:
                target_name = last_name

            if address and address.upper() != "N/A" and target_name in interfaces_by_name:
                interfaces_by_name[target_name].ip_addresses.append(address)

        # A physical port with no logical/IP configuration at all (e.g.
        # an unused ethernet1/x) still shows up in the hardware table
        # but never gets a logical-table row -- included here too, since
        # Port Mapping should show every physical port, not just the
        # ones currently carrying traffic.
        for hw_name, hw in hw_by_name.items():
            if hw_name in interfaces_by_name:
                continue
            interface_type = "ethernet" if hw_name.startswith("ethernet") else "other"
            iface = PaInterface(name=hw_name, interface_type=interface_type)
            iface.hw_speed_duplex_state = hw.get("speed_duplex_state", "")
            iface.hw_mac_address = hw.get("mac_address", "")
            interfaces_by_name[hw_name] = iface
            order.append(hw_name)

        config.interfaces = [interfaces_by_name[name] for name in order]
        config.zones = [PaZone(name=name, interfaces=members) for name, members in zones_by_name.items()]
        config.virtual_routers = [
            PaVirtualRouter(name=name, interfaces=members) for name, members in vr_interfaces.items()
        ]

    # -- "show routing route" ------------------------------------------------

    _ROUTE_ROW_RE = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)\s")

    @classmethod
    def _build_routing(cls, config: PaloAltoNativeConfig, lines: list[str]) -> None:
        """"show routing route" prints one VIRTUAL ROUTER: <name> block
        per virtual router, each with its own "destination / nexthop /
        metric / flags / age / interface" table -- flags is written as
        two space-separated letters (e.g. "A  S", "A  H"), which makes
        it indistinguishable by column position from the surrounding
        whitespace-separated fields, so this only ever extracts the
        three fields that DO have an unambiguous, fixed position
        (destination/nexthop/metric always come first, in that order,
        on every real row) rather than trying to also locate the
        interface column reliably.
        """
        vr_by_name = {vr.name: vr for vr in config.virtual_routers}
        current_vr: Optional[str] = None
        for line in lines:
            vr_header = re.match(r"^VIRTUAL ROUTER:\s*(\S+)", line.strip())
            if vr_header:
                current_vr = vr_header.group(1)
                if current_vr not in vr_by_name:
                    vr = PaVirtualRouter(name=current_vr)
                    config.virtual_routers.append(vr)
                    vr_by_name[current_vr] = vr
                continue
            if current_vr is None or not line.strip():
                continue
            route_match = cls._ROUTE_ROW_RE.match(line.strip())
            if not route_match:
                continue
            destination, nexthop, metric = route_match.groups()
            if not re.match(r"^[0-9a-fA-F:.]+(/\d+)?$", destination):
                continue  # not a route row (e.g. the "destination ... nexthop ..." header itself)
            vr_by_name[current_vr].static_routes.append(
                PaStaticRoute(destination=destination, nexthop=nexthop, metric=int(metric))
            )
