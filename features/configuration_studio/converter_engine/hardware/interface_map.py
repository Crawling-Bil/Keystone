"""Interface map: every physical source port -> the port it becomes on the target switch.

The map is built from three inputs: the source model (from the catalog, detected in the config text), the target model (catalog
entry or Huawei model name) and the interface names found in the config.  Ports are matched by *role* (access, uplink, management),
*speed class* and *position*, never by the digits in the name alone, because the same digits mean different things on different
platforms (``Te1/1/3`` is the third port of the uplink module, not the third 10G port of the box).

Row statuses:

``ok``       exact speed class, and the transceiver/cable type still fits
``review``   the port exists but something changes (speed class, copper cage -> SFP cage) or the target model was not chosen
``missing``  the target has no port to put it on; the converter still writes a name so the config stays readable, but it is flagged
``stanza``   the config has a stanza for a port that is not a physical port on the source model (a multi-speed personality
             stanza of a module slot, or a leftover); informational
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable

from .catalog import detect_model, detect_modules, get_model, split_target_key
from .models import KEYWORD_ABBREVIATIONS, SPEED_BY_KEYWORD, SPEED_ORDER, HardwareModel, PortGroup, UplinkModule
from .switches import UPLINK_MODULES

LOGICAL_KEYWORDS = (
    "vlan", "loopback", "port-channel", "tunnel", "lag", "bdi", "dialer", "nve", "appgigabitethernet", "cellular", "serial",
    "null", "eth-trunk", "vlanif", "stack-port", "m-lag",
)
_NAME_RE = re.compile(r"^(?P<kw>\d*[A-Za-z][A-Za-z\-]*?)?(?P<nums>\d+(?:/\d+)*)$")
_HUAWEI_PREFIX = {"100M": "GE", "1G": "GE", "mGig": "10GE", "10G": "10GE", "25G": "25GE", "40G": "40GE", "100G": "100GE"}
_HUAWEI_KEYWORDS_LOWER = {k.lower(): k for k in ("GE", "MultiGE", "XGigabitEthernet", "10GE", "25GE", "40GE", "100GE", "MEth")}
_HUAWEI_KEYWORDS = frozenset(_HUAWEI_KEYWORDS_LOWER.values())
_RANK = {speed: index for index, speed in enumerate(SPEED_ORDER)}


def canonical_keyword(keyword: str) -> str:
    low = keyword.lower()
    if low in KEYWORD_ABBREVIATIONS:
        return KEYWORD_ABBREVIATIONS[low]
    for known in SPEED_BY_KEYWORD:
        if known.lower() == low:
            return known
    if low == "ethernet":
        return "Ethernet"
    if low in _HUAWEI_KEYWORDS_LOWER:
        return _HUAWEI_KEYWORDS_LOWER[low]
    return keyword


def parse_name(name: str) -> dict | None:
    """Split an interface name into keyword and numbers; ``None`` for logical interfaces and sub-interfaces."""
    text = str(name or "").strip()
    if not text or "." in text:
        return None
    low = text.lower()
    if low.startswith(LOGICAL_KEYWORDS):
        return None
    match = _NAME_RE.match(text)
    if not match:
        return None
    nums = tuple(int(part) for part in match.group("nums").split("/"))
    return {"keyword": canonical_keyword(match.group("kw") or ""), "nums": nums, "name": text}


# --------------------------------------------------------------------------------------------------------------------------
# Source side
# --------------------------------------------------------------------------------------------------------------------------


@dataclass
class SourcePort:
    name: str
    role: str
    speed: str
    member: int
    ordinal: int
    medium: str
    in_use: bool
    group: str
    modelled: bool = True  # False when the name could not be matched to a physical port of the source model
    unknown_speed: bool = False


def _template_regex(template: str) -> re.Pattern[str]:
    parts = re.split(r"(\{m\}|\{n\})", template)
    out = ""
    for part in parts:
        out += {"{m}": r"(?P<m>\d+)", "{n}": r"(?P<n>\d+)"}.get(part, re.escape(part))
    return re.compile(out + "$")


def _match_group(group: PortGroup, keyword: str, numbers: str) -> tuple[int, int] | None:
    if keyword not in {canonical_keyword(k) if k else "" for k in group.keywords()}:
        return None
    found = _template_regex(group.template).match(numbers)
    if not found:
        return None
    groups = found.groupdict()
    number = int(groups["n"]) if "n" in groups else group.first
    member = int(groups["m"]) if "m" in groups else 1
    member = member or 1  # older VRP names the first (only) unit 0: GigabitEthernet0/0/1
    if not group.first <= number <= group.last:
        return None
    return member, number


def model_groups(model: HardwareModel, modules: Iterable[UplinkModule]) -> list[PortGroup]:
    groups = list(model.groups)
    groups.extend(module.group() for module in modules)
    return groups


def classify_with_model(parsed: dict, groups: list[PortGroup]) -> tuple[PortGroup, int, int] | None:
    numbers = "/".join(str(n) for n in parsed["nums"])
    for group in groups:
        hit = _match_group(group, parsed["keyword"], numbers)
        if hit:
            return group, hit[0], hit[1]
    return None


def classify_by_name(parsed: dict) -> SourcePort | None:
    """Best effort when the source model is unknown: read role, speed and position from the name alone."""
    keyword, nums, name = parsed["keyword"], parsed["nums"], parsed["name"]
    speed = SPEED_BY_KEYWORD.get(keyword)
    if keyword == "mgmt":
        return SourcePort(name, "mgmt", "1G", 1, 1, "RJ45", True, "management", modelled=False)
    if keyword == "MEth":
        return SourcePort(name, "mgmt", "1G", 1, 1, "RJ45", True, "management", modelled=False)
    if keyword in _HUAWEI_KEYWORDS and len(nums) == 3:
        # Huawei: <unit>/<subcard>/<port>; the fixed-port CloudEngine access models take 1G and Multi-GE ports as access ports
        # and everything faster as uplink cages.
        role = "access" if speed in ("1G", "mGig") else "uplink"
        return SourcePort(name, role, speed or "1G", nums[0] or 1, nums[2], "", True, "Huawei", modelled=False)
    if keyword == "Ethernet" and len(nums) == 2:
        # Nexus style: the keyword never says the speed.
        return SourcePort(name, "access", "1G", nums[0], nums[1], "", True, "Ethernet", modelled=False, unknown_speed=True)
    if speed and len(nums) == 3:
        member, slot, port = nums
        role = "access" if slot == 0 else "uplink"
        return SourcePort(name, role, speed, member, port, "", True, f"slot {slot}", modelled=False)
    if speed and nums == (0, 0):
        return SourcePort(name, "mgmt", speed, 1, 1, "RJ45", True, "management", modelled=False)
    if speed and len(nums) == 2:
        return SourcePort(name, "access", speed, 1, nums[1], "", True, "standalone", modelled=False)
    if not keyword and len(nums) == 3:
        return SourcePort(name, "access", "1G", nums[0], nums[2], "", True, f"slot {nums[1]}", modelled=False)
    return None


# --------------------------------------------------------------------------------------------------------------------------
# Target side
# --------------------------------------------------------------------------------------------------------------------------


@dataclass
class TargetPort:
    name_for: Callable[[int], str]
    role: str
    speed: str
    ordinal: int
    medium: str


@dataclass
class TargetLayout:
    vendor: str
    key: str
    label: str
    ports: list[TargetPort]
    mgmt: Callable[[int], str] | None
    max_members: int | None = None
    generic: Callable[[str, str, int, int], str | None] | None = None  # used when no model was chosen

    def pool(self, role: str, speed: str) -> list[TargetPort]:
        return sorted((p for p in self.ports if p.role == role and p.speed == speed), key=lambda p: p.ordinal)

    def counts(self, role: str) -> str:
        speeds: dict[str, int] = {}
        for port in self.ports:
            if port.role == role:
                speeds[port.speed] = speeds.get(port.speed, 0) + 1
        return ", ".join(f"{count}x {speed}" for speed, count in speeds.items()) or "none"


def _ports_from_groups(groups: list[PortGroup]) -> list[TargetPort]:
    ports: list[TargetPort] = []
    for group in groups:
        if group.role == "mgmt":
            continue
        for number in range(group.first, group.last + 1):
            ports.append(
                TargetPort(
                    name_for=lambda member, g=group, n=number: g.name(member, n),
                    role=group.role,
                    speed=group.speed,
                    ordinal=number - group.first + 1,
                    medium=group.medium,
                )
            )
    return ports


def _mgmt_from_groups(groups: list[PortGroup]) -> Callable[[int], str] | None:
    for group in groups:
        if group.role == "mgmt":
            return lambda member, g=group: g.name(member, g.first)
    return None


def _generic_huawei(role: str, speed: str, ordinal: int, member: int) -> str | None:
    return f"{_HUAWEI_PREFIX.get(speed, 'GE')}{member}/0/{ordinal}"


def _generic_cisco(role: str, speed: str, ordinal: int, member: int) -> str | None:
    keyword = {"100M": "FastEthernet", "1G": "GigabitEthernet", "mGig": "TenGigabitEthernet", "10G": "TenGigabitEthernet",
               "25G": "TwentyFiveGigE", "40G": "FortyGigabitEthernet", "100G": "HundredGigE"}.get(speed, "GigabitEthernet")
    return f"{keyword}{member}/{0 if role == 'access' else 1}/{ordinal}"


def _generic_aruba(role: str, speed: str, ordinal: int, member: int) -> str | None:
    return f"{member}/1/{ordinal}" if role == "access" else None


def build_target_layout(vendor: str, model_value: str | None) -> TargetLayout:
    """Layout of the chosen target; without a model it falls back to a naming rule only (no port-count check)."""
    vendor_key = str(vendor or "").strip().lower()
    base, module_key = split_target_key(model_value)
    generic = {"huawei": _generic_huawei, "cisco": _generic_cisco, "aruba": _generic_aruba}.get(vendor_key)
    mgmt_generic = {"huawei": lambda m: "MEth0/0/0", "cisco": lambda m: "GigabitEthernet0/0", "aruba": None}.get(vendor_key)

    # Catalog entry (Cisco, Aruba and Huawei alike); no model, or a name the catalog does not know, falls back to the naming rule.
    model = get_model(base) if base else None
    if model and model.vendor.lower() == vendor_key and model.kind == "switch":
        module = UPLINK_MODULES.get(module_key) if module_key else (UPLINK_MODULES.get(model.default_module) if model.modules else None)
        groups = model_groups(model, [module] if module else [])
        label = model.key + (f" + {module.key}" if module else "")
        return TargetLayout(model.vendor, label, model.label, _ports_from_groups(groups), _mgmt_from_groups(groups), model.max_members, None)
    return TargetLayout(vendor, "", "", [], mgmt_generic, None, generic)


# --------------------------------------------------------------------------------------------------------------------------
# Mapping
# --------------------------------------------------------------------------------------------------------------------------


def _resolve(layout: TargetLayout, port: SourcePort) -> tuple[TargetPort | None, str, str]:
    """``(target, status, note)`` for one source port against an explicit target layout."""
    if port.role == "mgmt":
        if layout.mgmt is None:
            return None, "missing", f"{layout.label} has no management port in this catalog; use an SVI on a data VLAN for management."
        return TargetPort(layout.mgmt, "mgmt", "1G", 1, "RJ45"), "ok", ""
    start = _RANK.get(port.speed, 0)
    notes: list[str] = []
    for speed in [s for s in SPEED_ORDER if _RANK[s] >= start]:
        pool = layout.pool(port.role, speed)
        if not pool:
            continue
        if port.ordinal > len(pool):
            return None, "missing", (
                f"{layout.label} has only {len(pool)}x {speed} {port.role} port(s); "
                f"{port.role} port {port.ordinal} has no equivalent."
            )
        target = pool[port.ordinal - 1]
        status = "ok"
        # A Multi-GE copper port (100M/1G/2.5G/5G/10G BASE-T) carries a 100M/1G copper link unchanged.
        multi_speed_copper = speed == "mGig" and port.speed in ("100M", "1G") and "RJ45" in target.medium and "RJ45" in (port.medium or "RJ45")
        if speed != port.speed and not multi_speed_copper:
            status = "review"
            notes.append(f"speed class changes {port.speed} -> {speed}")
        if "RJ45" in port.medium and "RJ45" not in target.medium:
            status = "review"
            notes.append(f"copper {port.medium} port lands on a {target.medium} cage: use a copper SFP/SFP+ or change the cabling")
        return target, status, "; ".join(notes)
    if "RJ45" in port.medium:
        # Multi-speed copper (100M/1G/10G BASE-T, mGig): a slower copper port still carries the link, at the slower rate.
        for speed in reversed([s for s in SPEED_ORDER if _RANK[s] < start]):
            pool = layout.pool(port.role, speed)
            if pool and port.ordinal <= len(pool):
                return pool[port.ordinal - 1], "review", (
                    f"{port.speed}-capable copper port lands on a {speed}-only port: the link will negotiate at {speed} or lower"
                )
    return None, "missing", f"{layout.label} has no {port.role} port at {port.speed} or faster (it offers: {layout.counts(port.role)})."


def _map_one(layout: TargetLayout, port: SourcePort, same_names: bool) -> dict:
    member = port.member
    target_name = ""
    target_speed = ""
    status = "ok"
    note = ""
    if layout.max_members and member > layout.max_members:
        status, note = "missing", f"Stack member {member} exceeds the {layout.max_members}-member limit of {layout.label}."
    elif layout.ports or (layout.generic is None and layout.mgmt):
        target, status, note = _resolve(layout, port)
        if target:
            target_name, target_speed = target.name_for(member), target.speed
    elif same_names:
        target_name, target_speed = port.name, port.speed
    elif port.role == "mgmt":
        target_name = layout.mgmt(member) if layout.mgmt else ""
        status = "ok" if target_name else "missing"
        note = "" if target_name else "No management port on the target; use an SVI."
    else:
        name = layout.generic(port.role, port.speed, port.ordinal, member) if layout.generic else None
        target_speed = port.speed
        if name is None:
            status, note = "missing", "Choose a Target Model: this vendor's uplink numbering depends on the model."
        else:
            target_name = name
            if port.unknown_speed:
                status, note = "review", 'The "Ethernet" keyword does not say the speed; confirm the real port speed before trusting this name.'
            elif port.role == "uplink":
                status = "review"
                note = "Target Model not chosen: the port is numbered by its speed class and position, but its existence on the target is not checked."
            elif port.speed not in ("1G", "100M"):
                status = "review"
                note = f"Target Model not chosen: {port.speed} access port is numbered by speed class; check the target actually has it."
    if not target_name and status != "missing":
        status = "missing"
    return {
        "source": port.name,
        "role": port.role,
        "speed": port.speed,
        "medium": port.medium,
        "member": member,
        "in_use": port.in_use,
        "group": port.group,
        "target": target_name,
        "target_speed": target_speed,
        "status": status,
        "note": note,
    }


def build_interface_map(
    interfaces: Iterable[tuple[str, bool]],
    *,
    source_text: str = "",
    source_vendor: str = "",
    target_vendor: str,
    target_model: str | None = None,
    source_model: HardwareModel | None = None,
    source_modules: list[UplinkModule] | None = None,
) -> dict:
    """Build the full map.  ``interfaces`` is ``[(name, in_use), ...]`` as found in the parsed config."""
    warnings: list[str] = []
    others: list[HardwareModel] = []
    if source_model is None and source_text:
        source_model, others = detect_model(source_text, "switch")
    modules = list(source_modules or [])
    if source_model is not None and source_model.modules and not modules:
        modules = detect_modules(source_text, source_model)
        if not modules:
            assumed = UPLINK_MODULES.get(source_model.default_module)
            if assumed:
                modules = [assumed]
                warnings.append(
                    f"No uplink module PID found in the source for {source_model.key}; assumed {assumed.key}. "
                    "Include 'show inventory' in the capture to make this exact."
                )
    if others:
        warnings.append("Other models are named in the same file: " + ", ".join(m.key for m in others) + ". The map uses " + (source_model.key if source_model else "name rules") + ".")

    layout = build_target_layout(target_vendor, target_model)
    groups = model_groups(source_model, modules) if source_model else []
    same_names = (
        not layout.ports
        and layout.generic is not None
        and str(source_vendor or (source_model.vendor if source_model else "")).lower() == str(target_vendor).lower()
        and bool(source_model)
        and not target_model
    )

    configured: dict[str, bool] = {}
    for name, in_use in interfaces:
        configured[name] = configured.get(name, False) or bool(in_use)

    rows: list[dict] = []
    seen: set[str] = set()
    members: set[int] = set()
    stanzas: list[tuple[dict, bool]] = []
    classified: dict[str, SourcePort] = {}

    for name, in_use in configured.items():
        parsed = parse_name(name)
        if parsed is None:
            continue
        if source_model is not None:
            hit = classify_with_model(parsed, groups)
            if hit:
                group, member, number = hit
                port = SourcePort(name, group.role, group.speed, member, number - group.first + 1, group.medium, in_use,
                                  group.range_label() if group.role != "mgmt" else "management")
                classified[name] = port
                if group.per_member:
                    members.add(member)
                continue
            stanzas.append((parsed, in_use))
        else:
            port = classify_by_name(parsed)
            if port:
                port.in_use = in_use
                classified[name] = port

    # Full expansion of the source box so unused ports are in the map too.
    if source_model is not None:
        members = members or {1}
        for group in groups:
            for member in sorted(members) if group.per_member else [1]:
                for number in range(group.first, group.last + 1):
                    name = group.name(member, number)
                    keyword_hits = [name] + [group.name(member, number, k) for k in group.aliases]
                    live = next((k for k in keyword_hits if k in classified), None)
                    port = classified.get(live) if live else None
                    if port is None:
                        port = SourcePort(name, group.role, group.speed, member, number - group.first + 1, group.medium, False,
                                          group.range_label() if group.role != "mgmt" else "management")
                    if port.name in seen:
                        continue
                    seen.add(port.name)
                    for k in keyword_hits:
                        seen.add(k)
                    rows.append(_map_one(layout, port, same_names))
    for name, port in classified.items():
        if name in seen:
            continue
        seen.add(name)
        rows.append(_map_one(layout, port, same_names))

    for parsed, in_use in stanzas:
        if parsed["name"] in seen:
            continue
        seen.add(parsed["name"])
        if not in_use:
            continue
        rows.append(
            {
                "source": parsed["name"], "role": "", "speed": SPEED_BY_KEYWORD.get(parsed["keyword"], ""), "medium": "", "member": parsed["nums"][0],
                "in_use": True, "group": "", "target": "", "target_speed": "", "status": "stanza",
                "note": f"Configured, but {source_model.key if source_model else 'the source'} has no physical port with this name.",
            }
        )

    # A multi-speed personality stanza that is not configured is not worth a row.
    rows = [r for r in rows if not (r["status"] == "stanza" and not r["in_use"])]
    rows.sort(key=lambda r: (r["member"], {"access": 0, "uplink": 1, "mgmt": 2, "": 3}.get(r["role"], 3), _natural(r["source"])))

    counts = {"ok": 0, "review": 0, "missing": 0, "stanza": 0}
    used = {"ok": 0, "review": 0, "missing": 0, "stanza": 0}
    for row in rows:
        counts[row["status"]] += 1
        if row["in_use"]:
            used[row["status"]] += 1
    return {
        "source_model": source_model.key if source_model else "",
        "source_label": source_model.label if source_model else "",
        "source_modules": [m.key for m in modules],
        "source_doc": {"title": source_model.doc_title, "url": source_model.doc_url} if source_model else None,
        "target_model": layout.key,
        "target_label": layout.label,
        "members": sorted(members) if members else [],
        "rows": rows,
        "counts": counts,
        "configured_counts": used,
        "port_check": bool(layout.ports),
        "warnings": warnings,
    }


def _natural(text: str) -> list:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", text)]


# --------------------------------------------------------------------------------------------------------------------------
# Hook used by the converter engine
# --------------------------------------------------------------------------------------------------------------------------


def _interface_in_use(interface) -> bool:
    return bool(
        getattr(interface, "description", "")
        or getattr(interface, "mode", "")
        or getattr(interface, "access_vlan", None)
        or getattr(interface, "ip_address", "")
        or getattr(interface, "channel_group", None)
        or getattr(interface, "shutdown", False)
        or getattr(interface, "allowed_vlans", None)
    )


def prepare_port_map(config, source_text: str, target_vendor: str, target_model: str | None) -> dict | None:
    """Attach ``config.metadata['interface_map']`` and ``['port_map']`` (source name -> {target, note, status, role, member}).

    Only switch configs are handled; anything else is left untouched.  The translators read ``port_map`` for the ports whose
    numbering cannot be derived from the name alone (uplink-module ports, stack members beyond the confirmed templates).
    """
    if getattr(config, "source_device_type", "").lower() != "switch" or not hasattr(config, "interfaces"):
        return None
    interfaces = [(i.name, _interface_in_use(i)) for i in config.interfaces]
    result = build_interface_map(
        interfaces,
        source_text=source_text,
        source_vendor=getattr(config, "source_vendor", ""),
        target_vendor=target_vendor,
        target_model=target_model,
    )
    port_map: dict[str, dict] = {}
    layout = build_target_layout(target_vendor, target_model)
    for row in result["rows"]:
        if not row["role"]:
            continue
        target = row["target"]
        note = row["note"] or None
        if row["status"] == "missing":
            number = re.search(r"(\d+)$", row["source"])
            ordinal = int(number.group(1)) if number else 1
            target = (layout.generic(row["role"], row["speed"], ordinal, row["member"]) if layout.generic else None) or row["source"]
            note = note or "No equivalent port on the target model."
        port_map[row["source"]] = {
            "target": target,
            "note": note,
            "status": row["status"],
            "role": row["role"],
            "member": row["member"],
        }
    config.source_model = result["source_model"]
    config.metadata["interface_map"] = result
    config.metadata["port_map"] = port_map
    return result
