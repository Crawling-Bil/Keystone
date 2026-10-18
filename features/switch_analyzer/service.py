from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

from features.configuration_studio.service import create_engine
from . import aoscx, bundles, capture_text, coverage, finding_context, findings, fingerprint, fhrp, fhrp_live, health, health_aoscx, l3, live_state, logs, nxos_extras, nxos_routes, ntp, ospf_db, ospf_live, parts, redundancy, runtime_parser, serials, show_tables, stp_detail, stp_inconsistent, tabs

IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Global-command line patterns for DNS servers / domain name across the
# vendors this analyzer sees. These live outside the shared SwitchConfig
# model (which doesn't have dedicated DNS fields) so they're pulled
# straight out of the raw, uncategorized "global_commands" bucket that
# every switch parser already collects.
DNS_SERVER_PATTERNS = [
    re.compile(r"^ip name-server\s+(.+)$", re.IGNORECASE),
    re.compile(r"^dns\s+server\s+(\S+)", re.IGNORECASE),
    re.compile(r"^ip dns server-address\s+(\S+)", re.IGNORECASE),
]
DOMAIN_NAME_PATTERNS = [
    re.compile(r"^ip domain[- ]name\s+(\S+)", re.IGNORECASE),
    re.compile(r"^dns\s+domain\s+(\S+)", re.IGNORECASE),
]

# Light-touch SNMP line recognition. This intentionally does not try to
# fully model every vendor's SNMP grammar — it just pulls out the
# handful of fields worth surfacing on a dashboard, and always keeps
# the raw commands available for anyone who wants the full detail.
SNMP_PATTERNS = {
    "community": [
        re.compile(r"^snmp-server community (\S+)", re.IGNORECASE),
        re.compile(r"^snmp-agent community \S+ cipher \S+", re.IGNORECASE),
    ],
    "location": [
        re.compile(r"^snmp-server location\s+(.+)$", re.IGNORECASE),
        re.compile(r"^snmp-agent sys-info location\s+(.+)$", re.IGNORECASE),
    ],
    "contact": [
        re.compile(r"^snmp-server contact\s+(.+)$", re.IGNORECASE),
        re.compile(r"^snmp-agent sys-info contact\s+(.+)$", re.IGNORECASE),
    ],
    "host": [
        re.compile(r"^snmp-server host\s+(\S+)", re.IGNORECASE),
        re.compile(r"^snmp-agent target-host trap address udp-domain\s+(\S+)", re.IGNORECASE),
    ],
}


def analyze(text: str, *, filename: str = "pasted-switch-config.txt", vendor: str = "Auto Detect") -> dict[str, Any]:
    """Parse a switch configuration and return an analyzer-friendly summary.

    Reuses the same Cisco/Huawei/Aruba switch parsers that power
    Configuration Studio's conversion engine — this module is read-only
    analysis, not conversion, so no target vendor is involved.
    """
    engine = create_engine()

    # Vendor/brand comes from the device's own identity (show version /
    # inventory / config header) rather than keyword counting, which mistook
    # a config-less Cisco Catalyst 2960S capture for Aruba. Only used for
    # "Auto Detect"; an explicit pick is respected but contradicted picks are
    # reported in result["detection"]["warning"].
    detection = fingerprint.detect(text)
    detection_info = _detection_info(detection, vendor, engine)
    effective_vendor = detection_info["vendor_used"]

    tmp_dir = Path("/tmp") if Path("/tmp").exists() else Path.cwd()
    tmp_path = tmp_dir / f"switch-analyzer-{abs(hash(text)) % (10 ** 8)}-{Path(filename).name}"
    tmp_path.write_text(text, encoding="utf-8")

    try:
        config = engine.parse(
            tmp_path,
            source_vendor=effective_vendor,
            source_device_type="Switch",
        )
    finally:
        tmp_path.unlink(missing_ok=True)

    detected_vendor = str(getattr(config, "source_vendor", "") or effective_vendor)
    detection_info["vendor_reported"] = detected_vendor

    lines = capture_text.expand_command_echoes(text.splitlines())
    clean = capture_text.clean_lines(text)
    # Only the Logs tab and Coverage need the device log itself. A 35 MB ArubaOS-CX `show logging` dump (180,000 syslog
    # lines) made every table reader scan all of it; they get the capture without those lines.
    clean_all = clean
    clean, lines = _without_syslog_flood(clean_all, lines)
    # ArubaOS-CX (6000 / 6100 / 6200 / 6300 ...) has its own CLI; its show output is read by aoscx.py and replaces the readers that find nothing in it.
    av = aoscx.build(clean) if aoscx.is_aoscx(clean) else None
    interface_brief = runtime_parser.parse_interface_brief(lines)
    if detected_vendor.lower() == "huawei":
        interface_brief = _normalize_huawei_brief_keys(interface_brief)
    # the cleaned capture: a pasted command list puts `show cdp neighbors` on a line of its own ahead of the real prompt line, and the section reader stops at the next bare command
    neighbors = runtime_parser.parse_neighbors(clean)
    port_channels = runtime_parser.parse_port_channels(lines)
    if av:
        neighbors = av["neighbors"] or neighbors
        port_channels = av["port_channels"] or port_channels
    os_version = runtime_parser.parse_version(lines)
    if av and (av["os_version"]["os_version"] or av["os_version"]["model"]):
        os_version = av["os_version"]
    routing_table = runtime_parser.parse_ip_route_table(lines)
    # NX-OS prints a prefix line plus one `via` line per next hop; the IOS reader above finds nothing in that layout
    routing_table += nxos_routes.parse_ip_routes(clean)
    if av and av["routes"]:
        routing_table = list(av["routes"])
    for route_row in routing_table:
        # one routing protocol name per row (Connected / Static / OSPF ...) for the filter chips on the Routing tab
        route_row["group"] = l3.protocol_group(route_row.get("protocol", "")) or "Other"
    arp_table, arp_check = live_state.parse_arp_with_meta(clean)
    mac_table, mac_check = live_state.parse_mac_table_with_meta(clean)
    if av and not arp_table and av["arp_meta"]:
        arp_table, arp_check = av["arp"], av["arp_meta"]
    if av and not mac_table and av["mac_meta"]:
        mac_table, mac_check = av["mac"], av["mac_meta"]
    tables = show_tables.build(clean)
    stp_view = stp_detail.build_spanning_tree(clean)
    if av:
        tables["vlan_db"] = av["vlan_db"] if av["vlan_db"]["captured"] else tables["vlan_db"]
        tables["trunks"] = av["trunks"] if av["trunks"]["captured"] else tables["trunks"]
        tables["mac_count"] = av["mac_count"] or tables["mac_count"]
        stp_view = av["stp"] if av["stp"]["captured"] else stp_view
    _attach_device_counts(arp_check, len(arp_table), tables["arp_summary"], "ARP", "IP ARP entries")
    # the device does not count its own CPU rows ("All 0100.0ccc.cccc STATIC CPU"), so the host rows are what its total matches
    _attach_device_counts(mac_check, sum(1 for row in mac_table if not row.get("system")), tables["mac_count"], "MAC", "MAC entries")
    live_observations = live_state.observe_interface_states(clean)
    if av:
        live_state.add_observations(live_observations, av["observations"])
    config_admin = live_state.config_admin_state(clean, detected_vendor)
    # Cleaned lines: a session-log record header in front of `NAME:` / the
    # transceiver block would otherwise hide it from the reader.
    transceivers = runtime_parser.parse_transceivers(clean)
    if av and av["transceivers"]:
        transceivers = av["transceivers"]
    poe = runtime_parser.parse_poe(lines)
    vpc_mlag = runtime_parser.parse_vpc_mlag(lines)
    vpc_mlag = nxos_extras.refine_vpc(vpc_mlag, clean)       # NX-OS: the live `show vpc` rows (down*, wrapped reasons) from the cleaned capture
    # Session-log captures prefix every line with a record header, which hides
    # `NAME:` / `Switch 1` from the inventory parser; the cleaned text is the
    # same capture without the transport noise.
    inventory = runtime_parser.parse_inventory(clean)
    if av and (av["inventory"]["modules"] or av["inventory"]["stack"]["members"]):
        inventory = dict(inventory, **av["inventory"])
    # The device's own serial number (and one per stack member). Taken from the
    # live stack table, before the config-only stack fallback below.
    serial_info = serials.parse_serials(clean, detected_vendor, inventory["stack"]["members"])
    if av and av["serials"]["serial_number"]:
        serial_info = av["serials"]

    interfaces = _build_interfaces(config, interface_brief, live_observations, config_admin, detected_vendor)
    if av:
        _apply_aoscx_detail(interfaces, av["interfaces"])
    _apply_runtime_descriptions(interfaces, tables["descriptions"]["rows"])
    _apply_runtime_trunks(interfaces, tables["trunks"]["rows"])
    l3_view = l3.build_l3(clean, detected_vendor, interfaces=interfaces, routing_table=routing_table)
    routes = _build_routes(config, l3_view)
    vlans = _build_vlans(config, runtime_parser.parse_vlan_brief(lines), tables["vlan_db"])
    dns = _extract_dns(config)
    snmp = _extract_snmp(config)
    dhcp = _build_dhcp(config, interfaces)

    _enrich_port_channels(port_channels, interfaces)
    vpc_mlag = _apply_vpc_mlag_config_fallback(vpc_mlag, config, interfaces)
    inventory = _apply_stack_config_fallback(inventory, config)
    if not os_version.get("model"):
        # A backup without `show version` (Nexus / ASR / 3825 captures): the model is still printed by `show inventory` (the chassis row) or recognised from the file
        chassis = next((m.get("pid") for m in inventory.get("modules") or [] if m.get("pid") and "chassis" in f"{m.get('slot', '')} {m.get('description', '')}".lower()), "")
        model = chassis or str(detection_info.get("model_hint") or "")
        if model:
            os_version = dict(os_version, model=model)
    if not os_version.get("model") or not os_version.get("os_version"):
        os_version = _sdwan_identity(clean, os_version)
    poe = _apply_poe_config_fallback(poe, config)

    # Transceiver rows only carry install/type data — cross-reference the
    # already-built interface table for the up/down status the user asked
    # to see alongside each transceiver, instead of re-parsing it.
    #
    # The interfaces table is keyed by whatever name "show ip interface
    # brief" / "display ip interface brief" (or the running-config) used,
    # which for Cisco is always the FULL interface name
    # ("GigabitEthernet1/1/1"). A Catalyst transceiver row's interface
    # comes from "show inventory" instead, which uses the SHORT form
    # ("Gi1/1/1") — a real capture confirmed this mismatch left every
    # transceiver's status blank even though the underlying up/down data
    # was already correctly parsed. Index by both forms so either lookup
    # style hits.
    status_by_interface: dict[str, str] = {}
    for item in interfaces:
        status_by_interface[item["name"]] = item["status"]
        short_name = runtime_parser._short_cisco_interface_name(item["name"])
        status_by_interface.setdefault(short_name, item["status"])
    for item in transceivers:
        status = status_by_interface.get(item["interface"])
        if status is None:
            short_name = runtime_parser._short_cisco_interface_name(item["interface"])
            status = status_by_interface.get(short_name, "")
        item["status"] = status

    # The Overview "Serial Numbers" table: hardware parts and every installed
    # transceiver, each with its PID and serial (see parts.py).
    device_parts = parts.build_parts(
        inventory["modules"],
        transceivers,
        is_stack=inventory["stack"]["mode"] == "Stack",
        aruba_chassis=serials.aruba_chassis(clean) if detected_vendor.lower() == "aruba" and not av else None,
    )
    capture_notes = _capture_notes(clean)

    up_count = sum(1 for item in interfaces if item["status"] == live_state.UP)
    down_count = sum(1 for item in interfaces if item["status"] == live_state.DOWN)
    admin_down_count = sum(1 for item in interfaces if item["status"] == live_state.ADMIN_DOWN)
    unknown_count = sum(1 for item in interfaces if item["status"] == live_state.UNKNOWN)

    pbr_summary = _build_pbr_summary(config)
    logs_view = logs.build_logs(clean_all, detected_vendor)
    if av:
        health_view = health_aoscx.build(clean, av, facts=logs_view.get("aoscx"), interfaces=interfaces)
    else:
        health_view = health.build_health(clean, detected_vendor, interfaces=interfaces, port_channels=port_channels, dhcp=dhcp)

    # Which bundle each physical port belongs to (Interfaces tab); a bundle the live table did not list gets a Port-Channel row
    bundle_view = bundles.build(interfaces, port_channels, health_view.get("lacp"), getattr(config, "interfaces", []), bundles.default_prefix(detected_vendor, bool(av)))
    if bundle_view["added"]:
        _enrich_port_channels(port_channels, interfaces)

    # A file that holds two devices (a second device's show output pasted below the first): the live HSRP / OSPF tables are read from the commands typed at this device's prompt only
    device_host = _device_host(clean, config.hostname)
    fhrp_view = fhrp.analyse(clean, device_host)   # HSRP / VRRP groups from the configuration, the live state from Huawei `display vrrp`, NX-OS `show hsrp`, IOS `show standby brief`
    ospf_state = ospf_live.read(clean, device_host)
    stp_inc_view = stp_inconsistent.read(clean, device_host)  # `show spanning-tree inconsistentports`
    ntp_view = ntp.read(clean, device_host)                   # `show ntp status` / `show ntp associations` / `display ntp status` / `display ntp sessions`
    redundancy_view = redundancy.read(clean, device_host)     # `show redundancy states` / `show redundancy` / `show redundancy history` (IOS XE SSO)
    ospf_dbv = ospf_db.read(clean, device_host)     # `show ip ospf interface brief` and the link-state database summary
    ospf_view = {"neighbors": ospf_state["neighbors"], "summary": ospf_state["summary"],
                 "findings": ospf_live.findings(ospf_state["neighbors"]) + ospf_db.findings(ospf_dbv, ospf_state["neighbors"]),
                 "checks": ospf_live.checks(ospf_state) + ospf_db.checks(ospf_dbv, ospf_state["neighbors"]),
                 "interfaces": ospf_dbv["interfaces"], "database": ospf_dbv["database"]}
    capture_notes += _scope_notes(clean, device_host) + ospf_db.notes(ospf_dbv)

    result = {
        # the device's own name: the configuration's hostname, else the prompt it was typed at (`SW1#`), else the file name
        "hostname": config.hostname or capture_text.dominant_prompt_host(clean_all) or Path(filename).stem,
        "vendor": detected_vendor,
        "detection": detection_info,
        "device_type": getattr(config, "source_device_type", "Switch"),
        "os_version": os_version,
        "interfaces": interfaces,
        "routes": routes,
        "routing_table": routing_table,
        "arp_table": arp_table,
        "mac_table": mac_table,
        # Device-reported totals vs rows found (live_state._table_meta): a table
        # shorter than the device said it printed means the capture lost lines.
        "table_checks": {"arp": arp_check, "mac": mac_check, **_group_checks(fhrp_view, ospf_state)},
        "neighbors": neighbors,
        "port_channels": port_channels,
        "vlans": vlans,
        "vlan_summary": _vlan_summary(tables["vlan_db"]),
        "trunks": tables["trunks"],
        "spanning_tree": stp_view,
        "interface_descriptions": {"captured": tables["descriptions"]["captured"], "rows": len(tables["descriptions"]["rows"]),
                                   "described": tables["descriptions"]["described"]},
        "dns": dns,
        "snmp": snmp,
        "dhcp": dhcp,
        "transceivers": transceivers,
        "poe": poe,
        "vpc_mlag": vpc_mlag,
        "inventory": inventory,
        "parts": device_parts,
        "capture_notes": capture_notes,
        "serials": serial_info,
        "routing_protocols": _routing_protocol_summary(config),
        "l3": l3_view,
        "health": health_view,
        # Sections a module adds to an existing tab (Nexus CPU / memory, vPC statistics, LACP counters ...): the page appends each to its tab.
        "extra_tables": list(health_view.get("extra_tables") or []) + fhrp_view["tables"] + redundancy.tables(redundancy_view) + ntp.tables(ntp_view) + _ospf_tables(ospf_state, ospf_dbv),
        "extras": {**dict(health_view.get("extra_counts") or {}), **fhrp_view["counts"], **redundancy.counts(redundancy_view), **ntp.counts(ntp_view), **stp_inconsistent.counts(stp_inc_view), "ospf_nbr": len(ospf_state["neighbors"]), "ospf_nbr_summary": len(ospf_state["summary"]), **ospf_db.counts(ospf_dbv)},
        # Live first-hop redundancy and OSPF state (the Compare Devices pair check and the Findings tab read these)
        "redundancy": {**redundancy_view, "findings": redundancy.findings(redundancy_view, inventory)},
        "ntp": {**ntp_view, "findings": ntp.findings(ntp_view)},
        "stp_inconsistent": {**stp_inc_view, "findings": stp_inconsistent.findings(stp_inc_view)},
        "fhrp": {"groups": fhrp_view["groups"], "summary": fhrp_view["summary"], "findings": fhrp_view["findings"], "config_hsrp": fhrp_view["config_hsrp"]},
        "ospf_live": ospf_view,
        "logs": logs_view,
        "pbr": pbr_summary,
        "spanning_tree_commands": list(getattr(config, "spanning_tree_commands", [])),
        "ntp_commands": list(getattr(config, "ntp_commands", [])),
        "aaa_commands": list(getattr(config, "aaa_commands", [])),
        "logging_commands": list(getattr(config, "logging_commands", [])),
        "cards": {
            "total_interfaces": len(interfaces),
            "interfaces_up": up_count,
            "interfaces_down": down_count,
            "interfaces_admin_down": admin_down_count,
            "interfaces_unknown": unknown_count,
            "total_vlans": len(vlans),
            "trunk_count": len(tables["trunks"]["rows"]),
            "stp_instances": len(stp_view["instances"]),
            "stp_broken_ports": len(stp_view["broken"]),
            "total_routes": len(routes),
            "dns_servers": len(dns["servers"]),
            "neighbor_count": len(neighbors),
            "port_channel_count": len(port_channels),
            "arp_entries": len(arp_table),
            "mac_entries": len(mac_table),
            "transceiver_count": len(transceivers),
            "poe_port_count": len(poe),
            "vpc_mlag_count": len(vpc_mlag["members"]),
            "stack_mode": inventory["stack"]["mode"] or "Unknown",
            "dhcp_pool_count": len(dhcp["pools"]),
            "dhcp_snooping_enabled": dhcp["snooping"]["enabled"],
            "has_custom_routing": pbr_summary["has_custom_routing"],
            "health_findings": len(health_view["findings"]),
            "health_attention": health_view["counts"].get("high", 0) + health_view["counts"].get("medium", 0),
            **_l3_cards(l3_view),
        },
    }
    # Findings, Coverage and the tab map are built from the finished result, in this order.
    result["coverage"] = coverage.build_coverage(clean_all, detected_vendor, result)
    result["findings"] = findings.build_findings(result)
    finding_context.attach(result)       # neighbour, bundle, vPC and log detail next to each finding
    result["cards"]["findings_total"] = len(result["findings"])
    result["cards"]["findings_high"] = sum(1 for item in result["findings"] if item["severity"] == "high")
    result["cards"]["findings_medium"] = sum(1 for item in result["findings"] if item["severity"] == "medium")
    result["tabs"] = tabs.build_tabs(result)
    return result


_SYSLOG_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}")
_SYSLOG_FLOOD_LINES = 5000


def _without_syslog_flood(clean: list[str], lines: list[str]) -> tuple[list[str], list[str]]:
    """Both line lists without ISO-8601 syslog lines when the capture holds thousands of them, else unchanged."""
    if len(clean) < _SYSLOG_FLOOD_LINES * 2:
        return clean, lines
    kept = [line for line in clean if not _SYSLOG_ISO.match(line)]
    if len(clean) - len(kept) < _SYSLOG_FLOOD_LINES:
        return clean, lines
    return kept, [line for line in lines if not _SYSLOG_ISO.match(line)]


def _device_host(clean: list[str], hostname: str) -> str | None:
    """The prompt host whose commands describe this device: None when the capture has a single prompt (nothing to separate), else the one named like the configuration's
    hostname, else the host that typed the most commands."""
    counts = capture_text.prompt_host_counts(clean)
    if len(counts) < 2:
        return None
    for host in counts:
        if hostname and host.lower() == hostname.lower():
            return host
    return capture_text.dominant_prompt_host(clean)


def _scope_notes(clean: list[str], host: str | None) -> list[dict[str, str]]:
    """A note for the live HSRP / OSPF output that was typed at another prompt and so left out."""
    if host is None:
        return []
    other: dict[str, int] = {}
    for patterns in (fhrp_live.PATTERN_DETAIL, fhrp_live.PATTERN_BRIEF, fhrp_live.PATTERN_SUMMARY, ospf_live.PATTERN_NEIGHBORS, ospf_live.PATTERN_SUMMARY, ospf_db.PATTERN_INTERFACE, ospf_db.PATTERN_DATABASE):
        for index, _block in capture_text.find_blocks(clean, patterns):
            typed_at = capture_text.prompt_host(clean[index])
            if typed_at and typed_at != host:
                other[typed_at] = other.get(typed_at, 0) + 1
    if not other:
        return []
    names = ", ".join(f"{name} ({count} command{'s' if count != 1 else ''})" for name, count in sorted(other.items()))
    return [{"level": "warning", "text": f"HSRP / OSPF output typed at another prompt was left out: {names}. The HSRP and OSPF tables are those of {host}. Upload that device's capture on its own to see it."}]


def _ospf_tables(ospf_state: dict[str, Any], ospf_dbv: dict[str, Any]) -> list[dict[str, Any]]:
    """The OSPF tables of the Routing tab in reading order: processes, interfaces, neighbours, neighbour summary, database totals, Router LSAs."""
    by_id = {table["id"]: table for table in ospf_live.tables(ospf_state) + ospf_db.tables(ospf_dbv, ospf_state["neighbors"])}
    return [by_id[key] for key in ("ospf-overview", "ospf-interfaces", "ospf-neighbors", "ospf-neighbor-summary", "ospf-lsdb", "ospf-routers") if key in by_id]


def _group_checks(fhrp_view: dict[str, Any], ospf_state: dict[str, Any]) -> dict[str, Any]:
    """The device's own count of HSRP groups (``show hsrp summary``) against the groups the other HSRP commands listed, in the shape of the ARP / MAC checks."""
    out: dict[str, Any] = {}
    reported = fhrp_view.get("reported")
    if reported is not None and fhrp_view.get("listed") is not None:
        out["hsrp"] = {"reported": reported, "source": "show hsrp summary", "parsed": fhrp_view["listed"], "complete": fhrp_view["listed"] >= reported, "captured": True, "device": {}, "device_note": ""}
    return out


def _capture_notes(clean: list[str]) -> list[dict[str, str]]:
    """Warnings about the capture itself, shown above the Overview tables.

    A file that holds commands typed at more than one prompt (two devices
    pasted into one file) cannot be told apart by most tables; the reader
    cannot know which rows belong to the device, so it says so instead of
    guessing. Only the Huawei transceiver output is cut by prompt host (see
    runtime_parser._huawei_transceiver_runs)."""
    counts = capture_text.prompt_host_counts(clean)
    if len(counts) < 2:
        return []
    ranked = sorted(counts.items(), key=lambda item: -item[1])
    listed = ", ".join(f"{host} ({count})" for host, count in ranked[:4])
    more = f" and {len(ranked) - 4} more" if len(ranked) > 4 else ""
    notes = [{
        "level": "warning",
        "text": (
            f"This file holds commands typed at {len(ranked)} different prompts: {listed}{more}. "
            "Most tables are read from the whole file, so check that every table belongs to this device."
        ),
    }]
    scope = runtime_parser.transceiver_scope_note(clean)
    if scope:
        runs = scope["ignored_runs"]
        notes.append({
            "level": "warning",
            "text": (
                f"Transceiver output from {runs} run{'s' if runs != 1 else ''} typed at another prompt was left out; "
                f"transceiver rows are those of {scope['used_host']}."
            ),
        })
    return notes


def _normalize_huawei_brief_keys(interface_brief: dict[str, dict]) -> dict[str, dict]:
    from features.configuration_studio.converter_engine.parsers.switch.huawei import HuaweiSwitchParser
    return {
        HuaweiSwitchParser.normalize_interface_name(name): value
        for name, value in interface_brief.items()
    }


def _format_allowed_vlans(allowed_vlans: list[str] | None, mode: str = "", vendor: str = "") -> str:
    """Render Interface.allowed_vlans (a list like ["100", "101-110"] or
    the single-element ["all"] Cisco/Huawei both use for 'allow every
    VLAN') the way the user asked to see it on the Port-Channel/Eth-
    Trunk and vPC/M-LAG tables: "100, 101, 102" or "All".

    A trunk port with NO "switchport trunk allowed vlan ..." line at
    all is a real, common case (confirmed on a real Catalyst 3650:
    Po1/Po2/Po3 are "switchport mode trunk" with no allowed-vlan line),
    and on Cisco that means every VLAN is allowed by default — "show
    interface trunk" reports "1-4094" for exactly these ports. Huawei's
    default is different (an unrestricted "port link-type trunk" only
    passes VLAN 1 until an explicit "port trunk allow-pass vlan ..."
    line is added), and no real capture in this project has shown that
    exact case, so this only fills in "All" for a Cisco source rather
    than guess at the Huawei default.
    """
    if allowed_vlans:
        if len(allowed_vlans) == 1 and allowed_vlans[0].strip().lower() == "all":
            return "All"
        return ", ".join(allowed_vlans)
    if mode.strip().lower() == "trunk" and vendor.strip().lower() == "cisco":
        return "All"
    return ""


def _mask_to_prefix_length(mask: str) -> int | None:
    """Dotted-decimal subnet mask -> CIDR prefix length (e.g.
    "255.255.254.0" -> 23), for combining with an interface's own IP
    address into "x.x.x.x/y" form. Returns None for anything that isn't
    a clean 4-octet dotted mask (so callers can fall back to the bare
    IP rather than show a nonsense prefix).
    """
    octets = mask.split(".")
    if len(octets) != 4:
        return None
    bits = 0
    for octet in octets:
        if not octet.isdigit():
            return None
        value = int(octet)
        if not 0 <= value <= 255:
            return None
        bits += bin(value).count("1")
    return bits


def _format_ip_with_mask(ip_address: str, subnet_mask: str = "") -> str:
    """Render an interface's IP the way the user asked to see it:
    "x.x.x.x/y" (falls back to the bare IP when no usable mask is
    available — never invents one). Also passes through an already-
    CIDR value untouched, which covers Huawei's "display ip interface
    brief" ("IP Address/Mask" column prints e.g. "10.85.28.2/23" as a
    single token already) once that command's own row-parsing is fixed
    to actually match real output (see runtime_parser._HUAWEI_IF_BRIEF_ROW).
    """
    ip_address = (ip_address or "").strip()
    if not ip_address or "/" in ip_address:
        return ip_address
    prefix = _mask_to_prefix_length(subnet_mask) if subnet_mask else None
    if prefix is None:
        return ip_address
    return f"{ip_address}/{prefix}"


def _detection_info(detection: fingerprint.Detection, requested: str, engine) -> dict[str, Any]:
    """Explain how the vendor was chosen, and flag a contradicted pick."""
    info: dict[str, Any] = {
        "requested": requested,
        "fingerprint": detection.vendor,
        "confidence": detection.confidence,
        "evidence": list(detection.evidence),
        "model_hint": detection.model_hint,
        "method": "",
        "vendor_used": requested,
        "warning": "",
    }
    if engine.is_auto(requested):
        if detection.vendor and detection.confidence in ("high", "medium"):
            info["vendor_used"] = detection.vendor
            info["method"] = "device identity"
        else:
            info["method"] = "keyword scoring"
    else:
        info["method"] = "selected by user"
        if (
            detection.vendor
            and detection.confidence == "high"
            and detection.vendor.lower() != requested.strip().lower()
        ):
            reasons = ", ".join(detection.evidence[:3])
            info["warning"] = (
                f"Vendor was set to {requested}, but this capture identifies itself as "
                f"{detection.vendor} ({reasons}). Choose Auto Detect unless that is intended."
            )
    return info


def _natural_key(name: str) -> list:
    return [int(part) if part.isdigit() else part.lower() for part in re.split(r"(\d+)", name or "")]


def _resolve_interface_status(
    key: str,
    config_shutdown: bool,
    live_observations: dict[str, list[dict[str, Any]]],
    config_admin: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """One interface's final state: up / down / admin down / unknown.

    Live show-command state decides up vs down. "admin down" is the
    intentional case (shutdown / disable) so it is also assigned when the
    live table only says "down" but the running-config shuts the port.
    Without any live state, a shutdown in the config is still a certain
    admin down; anything else is "unknown" rather than a guessed "up"."""
    live = live_state.resolve_state(live_observations.get(key, []))
    config_entry = config_admin.get(key) or {}
    shut_in_config = bool(config_shutdown or config_entry.get("admin_down"))
    keyword = config_entry.get("keyword") or "shutdown"

    if live:
        state = live["state"]
        detail = live["detail"]
        if state == live_state.DOWN and shut_in_config:
            state = live_state.ADMIN_DOWN
            detail = f"{keyword} in config (link {detail})"
        elif state == live_state.UP and shut_in_config:
            detail = f"up, but config has {keyword} (capture and config differ)"
        if live.get("conflict") and state != live_state.ADMIN_DOWN:
            detail = f"{detail}; sources disagree"
        return {
            "status": state,
            "status_detail": detail,
            "status_source": ", ".join(live["sources"]),
            "protocol": live.get("protocol", ""),
            "live_ip": live.get("ip_address", ""),
        }
    if shut_in_config:
        return {
            "status": live_state.ADMIN_DOWN,
            "status_detail": f"{keyword} in config",
            "status_source": "config",
            "protocol": "",
            "live_ip": "",
        }
    return {
        "status": live_state.UNKNOWN,
        "status_detail": "no live state in this capture (enabled in config, link state not captured)",
        "status_source": "",
        "protocol": "",
        "live_ip": "",
    }


def _build_interfaces(
    config,
    interface_brief: dict[str, dict] | None = None,
    live_observations: dict[str, list[dict[str, Any]]] | None = None,
    config_admin: dict[str, dict[str, Any]] | None = None,
    vendor: str = "",
) -> list[dict[str, Any]]:
    interface_brief = interface_brief or {}
    live_observations = live_observations or {}
    config_admin = config_admin or {}
    results = []
    seen_keys: set[str] = set()
    for item in getattr(config, "interfaces", []):
        vlan = item.access_vlan if item.access_vlan is not None else item.native_vlan
        brief = interface_brief.get(item.name) or interface_brief.get(item.name.lower()) or {}
        key = live_state.interface_key(item.name)
        seen_keys.add(key)
        resolved = _resolve_interface_status(key, bool(item.shutdown), live_observations, config_admin)
        ip_address = item.ip_address or brief.get("ip_address", "") or resolved["live_ip"]
        subnet_mask = item.subnet_mask or brief.get("subnet_mask", "")
        results.append({
            "name": item.name,
            "status": resolved["status"],
            "status_detail": resolved["status_detail"],
            "status_source": resolved["status_source"],
            "protocol": brief.get("protocol", "") or resolved["protocol"],
            "mode": item.mode or "",
            "vlan": vlan if vlan is not None else "",
            "ip_address": _format_ip_with_mask(ip_address, subnet_mask),
            "description": item.description or "",
            "port_security": "Enabled" if item.port_security_enabled else "",
            # HSRP virtual IP (Cisco "standby <group> ip <vip>") or its
            # Huawei VRRP equivalent ("vrrp vrid <id> virtual-ip <vip>",
            # huawei.py) — surfaced under one vendor-neutral column
            # rather than two, since a given interface only ever runs
            # one or the other.
            "hsrp_vrrp_ip": item.hsrp_virtual_ip or getattr(item, "vrrp_virtual_ip", "") or "",
            "allowed_vlans": _format_allowed_vlans(
                getattr(item, "allowed_vlans", None),
                item.mode or "",
                str(getattr(config, "source_vendor", "") or ""),
            ),
            "poe_enabled": bool(getattr(item, "poe_enabled", False)),
            "source": "show/display" if resolved["status_source"] and resolved["status_source"] != "config" else "config",
        })

    # Interfaces that only appear in the runtime tables (sub-interfaces, ports
    # with no config block at all -- an ArubaOS-Switch running-config only
    # lists ports that differ from the default) still deserve a row.
    for key, observations in live_observations.items():
        if key in seen_keys:
            continue
        seen_keys.add(key)
        display_name = max((o["name"] for o in observations), key=len)
        if vendor.strip().lower() == "huawei":
            from features.configuration_studio.converter_engine.parsers.switch.huawei import HuaweiSwitchParser
            display_name = HuaweiSwitchParser.normalize_interface_name(display_name)
        resolved = _resolve_interface_status(key, False, live_observations, config_admin)
        ip_address = resolved["live_ip"] or (interface_brief.get(display_name, {}) or {}).get("ip_address", "")
        # a table that carries more than the state (AOS-CX `show interface`: description, VLAN mode, VLANs) fills the row
        extra = {field: next((o[field] for o in observations if o.get(field) not in (None, "")), "") for field in ("description", "vlan_mode", "access_vlan", "native_vlan", "allowed_vlans")}
        results.append({
            "name": display_name,
            "status": resolved["status"],
            "status_detail": resolved["status_detail"],
            "status_source": resolved["status_source"],
            "protocol": resolved["protocol"],
            "mode": extra["vlan_mode"],
            "vlan": extra["access_vlan"] if extra["access_vlan"] != "" else extra["native_vlan"],
            "ip_address": _format_ip_with_mask(ip_address, ""),
            "description": extra["description"],
            "port_security": "",
            "hsrp_vrrp_ip": "",
            "allowed_vlans": extra["allowed_vlans"],
            "poe_enabled": False,
            "source": "show/display",
        })

    # A few runtime-only rows from the legacy brief parser that the newer
    # tables did not cover (kept so no previously reported interface vanishes).
    for name, brief in interface_brief.items():
        key = live_state.interface_key(name)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        legacy = (brief.get("status") or "").lower()
        status = live_state.ADMIN_DOWN if legacy == "administratively down" else (
            legacy if legacy in (live_state.UP, live_state.DOWN) else live_state.UNKNOWN
        )
        results.append({
            "name": name,
            "status": status,
            "status_detail": legacy or "no status",
            "status_source": "interface brief",
            "protocol": brief.get("protocol", ""),
            "mode": "",
            "vlan": "",
            "ip_address": _format_ip_with_mask(brief.get("ip_address", ""), brief.get("subnet_mask", "")),
            "description": "",
            "port_security": "",
            "hsrp_vrrp_ip": "",
            "allowed_vlans": "",
            "poe_enabled": False,
            "source": "show/display",
        })

    if vendor.strip().lower() == "aruba":
        results.sort(key=lambda row: _natural_key(row["name"]))
    return results


def _canonical_interface_key(name: str) -> str:
    """Lower-case, punctuation-stripped key so the same physical/logical
    interface can be matched across differently-formatted names, e.g. a
    port-channel summary table's short "Po7" against a config block's
    "port-channel7" (see _port_channel_interface_key), or "Eth-Trunk1"
    against itself when case differs.
    """
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


_PO_SHORT_NAME_RE = re.compile(r"^Po(\d+)$", re.IGNORECASE)
_ETH_TRUNK_NAME_RE = re.compile(r"^Eth-Trunk(\d+)$", re.IGNORECASE)


def _port_channel_interface_key(name: str) -> str:
    """'show etherchannel/port-channel summary' reports the short Cisco
    form ("Po7"), while the interface's own config block is named
    "Port-channel7" / "port-channel7" — expand the short form to the
    same canonical key _build_interfaces() would produce for it.

    Huawei's 'display eth-trunk' summary reports "Eth-Trunk7" — this
    does NOT already match its own config block, despite what this
    function used to assume: HuaweiSwitchParser.normalize_interface_name
    rewrites "interface Eth-Trunk7" to "Port-channel7" when building
    config.interfaces (so the two vendors' Interface rows share one
    naming scheme), so _build_interfaces() never produces an "Eth-
    Trunk7"-named row at all — the raw canonical key of "Eth-Trunk7"
    ("ethtrunk7") could never hit "portchannel7" and Huawei's Port-
    Channel/Eth-Trunk table silently got NO Description/Mode/VLAN
    enrichment (confirmed on a real S5755 live capture, every Eth-Trunk
    row came back blank). Expand it the same way "Po7" is expanded.
    """
    lag_match = re.match(r"^lag(\d+)$", name or "", re.IGNORECASE)         # ArubaOS-CX aggregate
    if lag_match:
        return _canonical_interface_key(f"portchannel{lag_match.group(1)}")
    po_match = _PO_SHORT_NAME_RE.match(name or "")
    if po_match:
        return _canonical_interface_key(f"portchannel{po_match.group(1)}")
    eth_trunk_match = _ETH_TRUNK_NAME_RE.match(name or "")
    if eth_trunk_match:
        return _canonical_interface_key(f"portchannel{eth_trunk_match.group(1)}")
    return _canonical_interface_key(name)


def _enrich_port_channels(port_channels: list[dict[str, Any]], interfaces: list[dict[str, Any]]) -> None:
    """Cross-reference each Port-Channel/Eth-Trunk summary row (from the
    live 'show port-channel summary' / 'display eth-trunk' parser, which
    only ever carries Name/Protocol/Status/Members) against the same
    interface's own config block — already fully parsed by
    _build_interfaces() — to add Description/Mode/VLAN, the same way a
    physical port already shows them. Mutates each dict in place so the
    single-device view, the compare view, and the Excel export all pick
    it up from the one place it's computed.
    """
    by_key = {_canonical_interface_key(item["name"]): item for item in interfaces}
    for pc in port_channels:
        iface = by_key.get(_port_channel_interface_key(pc.get("name", "")))
        pc["description"] = iface["description"] if iface else pc.get("description", "")
        pc["mode"] = iface["mode"] if iface else pc.get("mode", "")
        pc["vlan"] = iface["vlan"] if iface else pc.get("vlan", "")
        # Trunk-allowed VLANs on the port-channel/Eth-Trunk itself (e.g.
        # "100, 101, 102" or "All") — same already-parsed
        # Interface.allowed_vlans field a physical trunk port uses,
        # cross-referenced the same way Description/Mode/VLAN already are.
        pc["allowed_vlans"] = iface["allowed_vlans"] if iface else pc.get("allowed_vlans", "")
        # A Port-Channel/Eth-Trunk can be a routed port (Cisco "no
        # switchport" + "ip address ...", Huawei "undo portswitch" +
        # "ip address ...", both now set Interface.mode = "routed" —
        # see cisco.py/huawei.py) — surface its IP address the same way
        # a routed physical port already does, instead of leaving the
        # user to cross-reference the Interfaces tab by hand.
        pc["ip_address"] = iface["ip_address"] if iface else pc.get("ip_address", "")


def _apply_vpc_mlag_config_fallback(
    vpc_mlag: dict[str, Any], config, interfaces: list[dict[str, Any]]
) -> dict[str, Any]:
    """vpc_mlag as parsed so far only ever comes from a LIVE status
    command — 'show vpc brief'/'show vpc role' (Cisco NX-OS) or 'display
    m-lag brief'/'display m-lag summary' (Huawei) — which only exist on
    a device that is actually up and has formed a peer session. A draft
    config for a switch that hasn't been deployed yet (exactly the "new
    Huawei draft" / Device B case in Compare Devices) was never live, so
    it never ran those commands — the table is correctly empty, not
    buggy, because there is genuinely no vPC/M-LAG STATE to report yet.

    What the draft DOES have is the static configuration itself:
      * Cisco/NX-OS "vpc domain <id>", "vpc peer-link" / "vpc <id>" —
        SwitchConfig.vpc_domain_id / Interface.is_vpc_peer_link /
        Interface.vpc_id, populated by cisco.py.
      * Huawei M-LAG "dfs-group <id>", "peer-link <id>" / "dfs-group
        <id> m-lag <member-id>" — SwitchConfig.mlag_dfs_group_id /
        Interface.is_mlag_peer_link / Interface.mlag_id, populated by
        huawei.py. Confirmed real VRP syntax on a real S5755 M-LAG
        pair (TTC-SWCODI-MN/BU-DMZ).
    So when there's no live status, fall back to reporting that
    configuration instead of leaving the tab blank — clearly labeled
    "configured (not active)" rather than an up/down state, since
    there's no peer to actually check consistency against.

    Also fills in, on top of either the live table or the fallback
    above, several fields the user asked for that a live status command
    never actually prints: the peer-keepalive (vPC) / dual-active
    detection (M-LAG) source+peer IPs (confirmed on a real Nexus 9108:
    even a real live "sh vpc peer-keepalive" only ever shows the
    DESTINATION address, never this switch's own source IP — the
    complete picture only ever comes from the static config either
    way), which port-channel/Eth-Trunk is the peer-link, and the VLANs
    allowed on the peer-link and each member port (joining the already-
    enriched interfaces table's allowed_vlans/vlan, the same fields
    _enrich_port_channels already surfaces for a plain port-channel).
    """
    interfaces_by_key = {_canonical_interface_key(item["name"]): item for item in interfaces}

    def vlans_for(port_name: str) -> str:
        iface = interfaces_by_key.get(_port_channel_interface_key(port_name))
        if not iface:
            return ""
        return iface["allowed_vlans"] or (str(iface["vlan"]) if iface["vlan"] != "" else "")

    config_interfaces = list(getattr(config, "interfaces", []))
    vpc_domain_id = getattr(config, "vpc_domain_id", None)
    mlag_dfs_group_id = getattr(config, "mlag_dfs_group_id", None)
    peer_link_iface = next(
        (i for i in config_interfaces if getattr(i, "is_vpc_peer_link", False) or getattr(i, "is_mlag_peer_link", False)),
        None,
    )
    members_config = [
        i for i in config_interfaces
        if getattr(i, "vpc_id", None) is not None or getattr(i, "mlag_id", None) is not None
    ]

    if vpc_mlag["members"] or vpc_mlag["summary"]:
        vpc_mlag["source"] = "live"
    elif vpc_domain_id is None and mlag_dfs_group_id is None and peer_link_iface is None and not members_config:
        vpc_mlag["source"] = "none"
        return vpc_mlag
    else:
        vpc_mlag["summary"] = {
            "domain_id": str(vpc_domain_id if vpc_domain_id is not None else (mlag_dfs_group_id or "")),
            "peer_link": peer_link_iface.name if peer_link_iface else "",
        }
        vpc_mlag["members"] = [
            {
                "id": str(i.vpc_id if getattr(i, "vpc_id", None) is not None else i.mlag_id),
                "port": i.name,
                "status": "configured (not active)",
                "consistency": "",
                "vlans": vlans_for(i.name),
            }
            for i in members_config
        ]
        vpc_mlag["source"] = "config"

    summary = vpc_mlag.get("summary") or {}

    if not summary.get("peer_link") and peer_link_iface:
        summary["peer_link"] = peer_link_iface.name

    if summary.get("peer_link") and "peer_link_vlans" not in summary:
        peer_link_vlans = vlans_for(summary["peer_link"])
        if not peer_link_vlans and peer_link_iface:
            # A peer-link with no explicit allow-list carries every
            # VLAN by default on both vendors — Cisco vPC's peer-link
            # is a normal trunk defaulting to "all" the same as any
            # other unrestricted trunk (see _format_allowed_vlans), and
            # Huawei's M-LAG peer-link auto-carries every VLAN in the
            # local VLAN database with no allow-list mechanism at all
            # ("port vlan exclude" is exclude-only) — confirmed on a
            # real S5755 M-LAG peer-link's own authoring comments.
            peer_link_vlans = "All"
        summary["peer_link_vlans"] = peer_link_vlans

    keepalive_source_ip = (
        getattr(config, "vpc_peer_keepalive_source_ip", "")
        or getattr(config, "mlag_dual_active_source_ip", "")
    )
    keepalive_dest_ip = (
        getattr(config, "vpc_peer_keepalive_dest_ip", "")
        or getattr(config, "mlag_dual_active_peer_ip", "")
    )
    keepalive_vrf = getattr(config, "vpc_peer_keepalive_vrf", "")
    if keepalive_source_ip:
        summary.setdefault("peer_keepalive_source_ip", keepalive_source_ip)
    if keepalive_dest_ip:
        summary.setdefault("peer_keepalive_dest_ip", keepalive_dest_ip)
    if keepalive_vrf:
        summary.setdefault("peer_keepalive_vrf", keepalive_vrf)

    for member in vpc_mlag["members"]:
        if not member.get("vlans"):
            member["vlans"] = vlans_for(member.get("port", ""))

    vpc_mlag["summary"] = summary
    return vpc_mlag


def _sdwan_identity(clean: list[str], os_version: dict[str, Any]) -> dict[str, Any]:
    """Model and software version from `show sdwan system status` (a Catalyst 8000V/8200 in controller mode prints them there instead of in `show version`)."""
    for index, line in enumerate(clean):
        parts = capture_text.split_command(line)
        if not parts or not re.fullmatch(r"show sdwan system status", parts[0]):
            continue
        found: dict[str, str] = {}
        for row in clean[index + 1:index + 80]:
            if capture_text.split_command(row):
                break
            match = re.match(r"^\s*(Version|Model name)\s*:\s*(\S+)", row)
            if match:
                found.setdefault(match.group(1), match.group(2))
        updated = dict(os_version)
        if not updated.get("model") and found.get("Model name"):
            updated["model"] = found["Model name"]
        if not updated.get("os_version") and found.get("Version"):
            updated["os_version"] = found["Version"]
        return updated
    return os_version


def _apply_stack_config_fallback(inventory: dict[str, Any], config) -> dict[str, Any]:
    """inventory["stack"] as parsed so far only ever comes from a LIVE
    'show switch' (Cisco StackWise) or 'display stack' (Huawei) table —
    a draft config for a switch that has never been deployed has no such
    section at all. Confirmed on a real S5755 draft: two "stack member N
    renumber N" / "stack member N priority N" blocks declaring a
    2-member stack, but zero "display stack" output anywhere in the
    file (it was never live), so stack detection reported "Unknown"
    even though the switch IS statically configured to form one.

    Mirrors _apply_vpc_mlag_config_fallback's pattern exactly: when
    there's no live table, fall back to the static declaration instead
    (Huawei's SwitchConfig.stack_members_config, populated by
    huawei.py's "stack"/"stack member ..." parsing), clearly labeled
    "configured (not active)" rather than a real up/down state. Role is
    inferred from priority — Huawei iStack elects the highest-priority
    member Master — which matches this project's own real draft's
    "Switch 1 (Master)" / "Switch 2 (Standby)" authoring comments.

    Cisco StackWise has no equivalent static pre-declaration in the
    running-config (stack membership there is purely a live, chassis-
    detected fact via 'show switch'), so this fallback only ever fires
    for a Huawei source until that changes.
    """
    if inventory["stack"]["members"]:
        return inventory

    stack_members_config = list(getattr(config, "stack_members_config", []))
    if not stack_members_config:
        return inventory

    priorities = [m.priority for m in stack_members_config if m.priority is not None]
    highest_priority = max(priorities) if priorities else None

    members = []
    for member in sorted(stack_members_config, key=lambda m: m.member_id):
        if member.priority is not None and highest_priority is not None:
            role = "Master" if member.priority == highest_priority else "Standby"
        else:
            role = ""
        members.append({
            "slot": str(member.member_id),
            "role": role,
            "mac": "",
            "state": "configured (not active)",
            "priority": member.priority if member.priority is not None else "",
        })

    inventory["stack"] = {
        "mode": "Stack" if len(members) > 1 else "Standalone",
        "member_count": len(members),
        "members": members,
        "source": "config",
    }
    return inventory


def _apply_poe_config_fallback(poe: list[dict[str, Any]], config) -> list[dict[str, Any]]:
    """poe as parsed so far only ever comes from a LIVE per-port table
    ('show power inline' on Cisco, 'show power-over-ethernet' on Aruba)
    or the CDP-detail power-drawn fallback. No real Huawei capture in
    this project has a live per-port PoE table at all — 'display poe
    information' / 'display poe-power' only ever print a slot/PSE-level
    power BUDGET (Power Max Value(mW), Available Power(mW), ...), never
    a per-port admin/oper state, confirmed across every real PoE-capable
    S5735 access switch draft in this project (none has ever been
    deployed with anything actually plugged in yet).

    What every one of those drafts DOES have is each port's own "poe
    enable" config line (Interface.poe_enabled, huawei.py) — so, mirroring
    the vPC/M-LAG and stack config-only fallback pattern, fall back to
    reporting THAT instead of leaving the tab blank: one row per
    PoE-enabled port, clearly labeled "configured (not active)" rather
    than a real oper state, since there's no live table to confirm
    against. Only fires when parse_poe() found nothing live to show —
    a real live table (once one exists in a real capture) always wins.
    """
    if poe:
        return poe

    fallback = []
    for item in getattr(config, "interfaces", []):
        if not getattr(item, "poe_enabled", False):
            continue
        fallback.append({
            "interface": item.name,
            "admin_status": "enabled",
            "oper_status": "configured (not active)",
            "power_watts": "",
            "device": "",
            "class": "",
            "max_watts": "",
            "source": "config (poe enable)",
        })
    return fallback


def _build_routes(config, l3_view: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """The static routes, each once.

    Read from the Layer-3 parse (l3.py) because it knows the forms the shared
    switch parsers do not: the VRF form ("ip route-static vpn-instance X ...",
    "vrf context" on Nexus), an exit interface instead of a next hop, and a
    description. A capture that echoes its route lines twice (the full config,
    then "display current-configuration | include ip route-static") would
    otherwise count one route three times. If the Layer-3 parse found none, the
    shared parser's routes are used, de-duplicated."""
    results: list[dict[str, Any]] = []
    for row in (l3_view or {}).get("static_routes", []):
        try:
            mask = str(ipaddress.IPv4Network(row["cidr"], strict=False).netmask)
        except ValueError:
            mask = ""
        results.append({
            "destination": row["destination"],
            "mask": mask,
            "next_hop": row["next_hop"] or row["interface"],
            "distance": row["distance"] if row["distance"] is not None else "",
            # "ip route-static ... track <id>" / "ip route ... track <id>" ties the
            # route to a track object (see _build_pbr_summary's track_objects).
            "track_id": int(row["track"]) if str(row["track"]).isdigit() else row["track"],
            "vrf": row["vrf"],
            "interface": row["interface"],
            "description": row["description"],
        })
    if results:
        return results
    seen: set[tuple] = set()
    for route in getattr(config, "routes", []):
        key = (route.destination, route.mask, route.next_hop, route.distance, getattr(route, "track_id", None))
        if key in seen or not IPV4_RE.match(str(route.destination or "")):
            continue
        seen.add(key)
        results.append({
            "destination": route.destination,
            "mask": route.mask,
            "next_hop": route.next_hop,
            "distance": route.distance if route.distance is not None else "",
            "track_id": route.track_id if getattr(route, "track_id", None) is not None else "",
            "vrf": "",
            "interface": "",
            "description": "",
        })
    return results


def _l3_cards(l3_view: dict[str, Any]) -> dict[str, Any]:
    """The few Layer-3 numbers the Overview cards show."""
    ospf = l3_view["ospf"]
    if not ospf["configured"]:
        ospf_status = "Not configured"
    elif any(item["code"] != "ospf_all_passive" for item in ospf["findings"]):
        ospf_status = "Configured, not running"
    elif ospf["findings"]:
        ospf_status = "Passive only"
    else:
        ospf_status = f"Running on {len(ospf['interfaces'])} interface{'s' if len(ospf['interfaces']) != 1 else ''}"
    defaults = l3_view["default_routes"]
    return {
        "l3_interface_count": len(l3_view["interfaces"]),
        "default_route": defaults[0]["next_hop"] if defaults else "",
        "ospf_status": ospf_status,
        "acl_count": len(l3_view["acls"]["definitions"]),
        "l3_finding_count": len(l3_view["findings"]),
    }


def _build_dhcp(config, interfaces: list[dict[str, Any]]) -> dict[str, Any]:
    """DHCP tab: server pools, per-interface relay/helper addresses, and
    DHCP Snooping status (global, per-VLAN, Option 82, per-interface
    trust/rate-limit) — all pulled from the same already-parsed
    SwitchConfig used for every other tab, no new parsing pass needed.

    Every field this reads was validated against real capture data this
    round: Cisco "ip dhcp pool"/"ip helper-address"/"ip dhcp snooping
    ..." (TTC-SWCO-PABXGA-3650, GTOPAS-PKU-SWCO-C3650, TTC-SWAC-LAN-
    2960) all worked already; Huawei's "dhcp snooping enable ipv4" /
    "dhcp snooping enable vlan <range>" / "dhcp snooping trusted" did
    NOT (see huawei.py's parser fixes this same round) — those real
    VRP command forms were previously unrecognized, so this tab would
    have silently shown DHCP Snooping as off on every real Huawei
    device that actually has it configured.
    """
    pools = []
    for pool in getattr(config, "dhcp_pools", []):
        pools.append({
            "name": pool.name,
            "network": pool.network,
            "mask": pool.mask,
            "gateway": ", ".join(pool.gateway),
            "dns_servers": ", ".join(pool.dns_servers),
            "domain_name": pool.domain_name,
            "lease": pool.lease,
            "options": list(pool.options),
        })

    helper_addresses = []
    trusted_interfaces = []
    rate_limited_interfaces = []
    for item in getattr(config, "interfaces", []):
        if getattr(item, "helper_addresses", None):
            helper_addresses.append({"interface": item.name, "servers": list(item.helper_addresses)})
        if getattr(item, "dhcp_snooping_trusted", False):
            trusted_interfaces.append(item.name)
        rate_limit = getattr(item, "dhcp_snooping_rate_limit_pps", None)
        if rate_limit is not None:
            rate_limited_interfaces.append({"interface": item.name, "limit_pps": rate_limit})

    return {
        "pools": pools,
        "helper_addresses": helper_addresses,
        "snooping": {
            "enabled": bool(getattr(config, "dhcp_snooping_enabled", False)),
            "vlans": list(getattr(config, "dhcp_snooping_vlans", [])),
            "option82_enabled": bool(getattr(config, "dhcp_snooping_option82_enabled", False)),
            "trusted_interfaces": trusted_interfaces,
            "rate_limited_interfaces": rate_limited_interfaces,
        },
        "raw_commands": list(getattr(config, "dhcp_commands", [])),
    }


def _build_vlans(config, runtime_vlans: list[dict[str, Any]] | None = None, vlan_db: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """VLANs from the config, plus those the device's own VLAN database lists ("show vlan" / "show vlan brief").

    A Cisco running-config only carries the VLANs that were created by hand in it; VLANs learned from VTP or kept
    in vlan.dat exist on the switch but never appear in the config (real captures: 0 of 4 on a 3650, 15 of 18 on a
    2960). The config entry wins where both exist, except that a VLAN the config declares without a name takes the
    database's name. ``show vlan`` adds the state, the access ports, the type and the MTU. The built-in VLANs
    (1 and 1002-1005) are not listed; ``_vlan_summary`` reports how many ports sit in VLAN 1.

    A capture with nothing from the device keeps the plain ``{vlan_id, name}`` rows.
    """
    vlan_db = vlan_db or {}
    by_id: dict[int, dict[str, Any]] = {}
    in_config: set[int] = set()
    on_device: set[int] = set()

    def entry(vlan_id: int, name: str) -> dict[str, Any]:
        item = by_id.get(vlan_id)
        if item is None:
            item = {"vlan_id": vlan_id, "name": name}
            by_id[vlan_id] = item
        elif not item["name"]:
            item["name"] = name
        return item

    for vlan in getattr(config, "vlans", []):
        entry(vlan.vlan_id, vlan.name)
        in_config.add(vlan.vlan_id)
    for item in runtime_vlans or []:
        entry(item["vlan_id"], item["name"])
        on_device.add(item["vlan_id"])
    details: dict[int, dict[str, Any]] = {}
    for row in vlan_db.get("rows") or []:
        if row["builtin"] or row["vlan_id"] == 1:
            continue
        entry(row["vlan_id"], row["name"])
        on_device.add(row["vlan_id"])
        details[row["vlan_id"]] = row
    if vlan_db.get("captured") or runtime_vlans:
        for vlan_id, item in by_id.items():
            row = details.get(vlan_id) or {}
            item.update(status=row.get("status", ""), ports=", ".join(row.get("ports", [])), port_count=row.get("port_count"),
                        type=row.get("type", ""), mtu=row.get("mtu", ""))
            if vlan_id in in_config and vlan_id in on_device:
                item["source"] = "config + device"
            elif vlan_id in in_config:
                item["source"] = "config only"
            else:
                item["source"] = "device only"
    return [by_id[key] for key in sorted(by_id)]


def _vlan_summary(vlan_db: dict[str, Any]) -> dict[str, Any]:
    """What ``show vlan summary`` counted next to what ``show vlan`` listed."""
    summary = dict(vlan_db.get("summary") or {})
    rows = vlan_db.get("rows") or []
    builtin = [row["vlan_id"] for row in rows if row["builtin"] or row["vlan_id"] == 1]
    default = next((row for row in rows if row["vlan_id"] == 1), None)
    return {"captured": bool(vlan_db.get("captured") or summary), "device": summary, "listed": len(rows), "builtin": len(builtin),
            "default_vlan_ports": default["port_count"] if default else None, "complete": vlan_db.get("complete", True)}


def _interface_lookup(rows: list[dict[str, Any]], name_key: str) -> dict[str, dict[str, Any]]:
    return {live_state.interface_key(row[name_key]): row for row in rows}


def _speed_text(mbps: int | None) -> str:
    if not mbps:
        return ""
    return f"{mbps // 1000} Gb/s" if mbps >= 1000 and mbps % 1000 == 0 else f"{mbps} Mb/s"


_CLOCK_WORDS = re.compile(r"^(?:[A-Z][a-z]{2}\s+)?(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?:\S+\s+)?(?P<year>\d{4})$")
_MONTH_NAMES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _compact_clock(text: str) -> str:
    """``Mon Oct 12 18:29:29 WIB 2026`` -> ``2026-10-12 18:29:29`` (the zone is the device's, shown once as Device Time on the Health tab)."""
    match = _CLOCK_WORDS.match((text or "").strip())
    if not match or match["mon"] not in _MONTH_NAMES:
        return text or ""
    return f"{match['year']}-{_MONTH_NAMES.index(match['mon']) + 1:02d}-{int(match['day']):02d} {match['time']}"


def _apply_aoscx_detail(interfaces: list[dict[str, Any]], detail: dict[str, dict[str, Any]]) -> None:
    """Speed, duplex, link age, link transitions and error / drop counters of ``show interface`` next to each interface row."""
    by_key = {live_state.interface_key(name): item for name, item in detail.items()}
    for row in interfaces:
        item = by_key.get(live_state.interface_key(row["name"]))
        if not item:
            continue
        row["speed"] = _speed_text(item["speed_mbps"]) if item["oper_state"] == "up" else ""
        row["duplex"] = item["duplex"] if item["oper_state"] == "up" else ""
        row["port_type"] = item["type"]
        row["mac_address"] = item["mac"]
        row["mtu"] = item["mtu"] if item["mtu"] is not None else ""
        row["link_since"] = _compact_clock(item["link_since"])
        row["link_for"] = item["link_duration"]
        row["transitions"] = item["transitions"] if item["transitions"] is not None else ""
        row["rx_errors"] = item["rx"].get("errors") or 0
        row["rx_crc"] = item["rx"].get("crc") or 0
        row["tx_dropped"] = item["tx"].get("dropped") or 0
        row["rx_packets"] = item["rx"].get("packets") or 0
        row["tx_packets"] = item["tx"].get("packets") or 0
        row["util_in"] = item["util_rx"] if item["util_rx"] is not None else ""
        row["util_out"] = item["util_tx"] if item["util_tx"] is not None else ""
        if not row["description"] and item["description"]:
            row["description"] = item["description"]
        if item["kind"] == "port" and not row["mode"] and item["vlan_mode"]:
            row["mode"] = item["vlan_mode"]
        if item["kind"] == "port" and row["vlan"] == "" and (item["access_vlan"] is not None or item["native_vlan"] is not None):
            row["vlan"] = item["access_vlan"] if item["access_vlan"] is not None else item["native_vlan"]
        if item["kind"] == "port" and not row["allowed_vlans"] and item["allowed_vlans"]:
            row["allowed_vlans"] = item["allowed_vlans"]


def _apply_runtime_descriptions(interfaces: list[dict[str, Any]], rows: list[dict[str, str]]) -> None:
    """Fill the description from ``show interface description`` where the configuration gave none (a capture
    without a running-config, or an interface the config does not list)."""
    if not rows:
        return
    by_key = _interface_lookup(rows, "interface")
    for item in interfaces:
        row = by_key.get(live_state.interface_key(item["name"]))
        if row and row["description"] and not item["description"]:
            item["description"] = row["description"]
            item["description_source"] = "show interface description"


def _apply_runtime_trunks(interfaces: list[dict[str, Any]], rows: list[dict[str, Any]]) -> None:
    """``show interface trunk`` is what the port really does: mode and allowed VLANs where the config said nothing."""
    if not rows:
        return
    by_key = _interface_lookup(rows, "port")
    for item in interfaces:
        row = by_key.get(live_state.interface_key(item["name"]))
        if not row:
            continue
        if not item["mode"] and row["status"] == "trunking":
            item["mode"] = "trunk"
        if not item["allowed_vlans"] and row["allowed"]:
            item["allowed_vlans"] = row["allowed"]


def _attach_device_counts(check: dict[str, Any], parsed: int, device: dict[str, Any], label: str, noun: str) -> None:
    """Put the device's own count (``show ip arp summary`` / ``show mac address-table count``) next to the table check.

    The count comes from a different command, run seconds apart, so a few entries of difference are normal
    (entries age out or are learned in between). The note names the gap only when it is large enough to matter."""
    check["device"] = device or {}
    check["device_note"] = ""
    if not device:
        return
    total = device.get("total")
    if total is None:
        return
    if label == "ARP":
        detail = f" ({device.get('incomplete', 0)} incomplete)"
    else:
        detail = f" ({device.get('dynamic', 0)} dynamic, {device.get('static', 0)} static)" if "dynamic" in device else ""
    text = f"The device counts {total} {noun}{detail}; this capture lists {parsed} " + ("host rows (the switch's own CPU rows are not counted)." if label == "MAC" else "rows.")
    gap = total - parsed
    check["device_gap"] = gap
    if gap > max(5, total // 20):
        text += (f" {gap} entries are not in the table above: the {label} command may have been filtered or cut, or entries were learned between the two commands.")
    elif -gap > max(5, total // 20):
        text += f" The table lists {-gap} more rows than the count; entries were learned between the two commands."
    check["device_note"] = text


def _routing_protocol_summary(config) -> dict[str, list[str]]:
    return {
        "ospf": list(getattr(config, "ospf_commands", [])),
        "eigrp": list(getattr(config, "eigrp_commands", [])),
        "default_gateway": getattr(config, "default_gateway", "") or "",
    }


def _build_pbr_summary(config) -> dict[str, Any]:
    """Policy-Based Routing / SLA-Track / NQA — everything that makes a
    device's real forwarding behavior different from a plain static/
    dynamic routing table, surfaced so a reviewer can tell "this device
    has custom route configuration" without having to hand-inspect the
    raw config. Union of the two vendors' own PBR mechanisms:

      Cisco: "ip sla <id>" probes + "track <id> ip sla <id>
      reachability" objects + "route-map ... set ip next-hop
      verify-availability ... track <id>" clauses applied via "ip
      policy route-map <name>" (either statically under an interface,
      OR — a real, currently-active pattern on TAM 2026's Catalyst
      3650 stacks — dynamically via an EEM applet's SNMP-OID
      link-state watch, which never shows up under the interface at
      all).

      Huawei: "nqa test-instance admin <name>" probes + optional
      "track <id> nqa admin <name>" objects + "traffic classifier /
      traffic behavior / traffic policy" MQC chains applied via
      "traffic-policy <name> {inbound|outbound}" under an interface.

    Every field here traces back to real capture data confirmed this
    round (GTOPAS-MKS/PKU/MND/SMG-SWCO-C3650.txt for the Cisco side,
    GTOPAS-MKS-SWCODI-S5755-FIX.txt for the live-deployed Huawei side,
    draft_huawei_master.txt / ADM-SWCODI-S5755.txt for the Huawei
    numbered-track-object template form) — see TAM
    memory-keystone.md Section 1ac. Single Device's Routing tab and
    Compare Devices' Routes section both read this same structure (no
    vendor-specific UI branching needed).
    """

    sla_tests: list[dict[str, Any]] = []

    for sla in getattr(config, "ip_sla_entries", []):
        sla_tests.append({
            "kind": "IP SLA",
            "id": f"IP SLA {sla.sla_id}",
            "test_type": sla.test_type,
            "destination": sla.destination,
            "frequency": sla.frequency if sla.frequency is not None else "",
            "timeout": sla.timeout if sla.timeout is not None else "",
            "probe_count": "",
        })

    for nqa in getattr(config, "nqa_test_instances", []):
        sla_tests.append({
            "kind": "NQA",
            "id": f"NQA {nqa.test_name}",
            "test_type": nqa.test_type,
            "destination": nqa.destination,
            "frequency": nqa.frequency if nqa.frequency is not None else "",
            "timeout": nqa.timeout if nqa.timeout is not None else "",
            "probe_count": nqa.probe_count if nqa.probe_count is not None else "",
        })

    track_objects: list[dict[str, Any]] = []
    for track in getattr(config, "track_objects", []):
        if track.nqa_name:
            tracks_desc = f"NQA {track.nqa_name}"
        elif track.sla_id is not None:
            tracks_desc = f"IP SLA {track.sla_id}"
        else:
            tracks_desc = ""
        track_objects.append({
            "track_id": track.track_id,
            "tracks": tracks_desc,
        })

    # Interface -> PBR-policy application, unified across both vendors'
    # own mechanism ("ip policy route-map" for Cisco, "traffic-policy
    # ... inbound/outbound" for Huawei) so the UI needs no per-vendor
    # branching.
    pbr_bindings: list[dict[str, Any]] = []
    for iface in getattr(config, "interfaces", []):
        policy_name = getattr(iface, "ip_policy_route_map", "") or ""
        if policy_name:
            pbr_bindings.append({
                "interface": iface.name,
                "policy_name": policy_name,
                "direction": "",
                "mechanism": "ip policy route-map",
            })
        for direction, attr in (
            ("inbound", "traffic_policy_inbound"),
            ("outbound", "traffic_policy_outbound"),
        ):
            policy_name = getattr(iface, attr, "") or ""
            if policy_name:
                pbr_bindings.append({
                    "interface": iface.name,
                    "policy_name": policy_name,
                    "direction": direction,
                    "mechanism": "traffic-policy",
                })

    # PBR policies themselves — Cisco route-map clauses and Huawei
    # traffic-policy classifier/behavior bindings, unified into one
    # "policy name / sequence / match / action / tracked-by" shape.
    pbr_policies: list[dict[str, Any]] = []

    for route_map in getattr(config, "route_maps", []):
        for clause in route_map.clauses:
            tracked_by = (
                f"Track {clause.set_next_hop_track_id}"
                if clause.set_next_hop_track_id is not None
                else ""
            )
            pbr_policies.append({
                "vendor_mechanism": "Cisco route-map",
                "policy_name": route_map.name,
                "sequence": clause.sequence,
                "action": clause.action,
                "match": f"ACL {clause.match_acl}" if clause.match_acl else "",
                "set_next_hop": clause.set_next_hop,
                "tracked_by": tracked_by,
            })

    classifiers_by_name = {c.name: c for c in getattr(config, "traffic_classifiers", [])}
    behaviors_by_name = {b.name: b for b in getattr(config, "traffic_behaviors", [])}

    for policy in getattr(config, "traffic_policies", []):
        for binding in policy.bindings:
            classifier = classifiers_by_name.get(binding.classifier)
            behavior = behaviors_by_name.get(binding.behavior)

            match = ""
            if classifier and classifier.acl_numbers:
                match = "ACL " + ", ".join(classifier.acl_numbers)

            set_next_hop = behavior.redirect_next_hop if behavior else ""
            if behavior and behavior.track_nqa_name:
                tracked_by = f"NQA {behavior.track_nqa_name}"
            elif behavior and behavior.track_id is not None:
                tracked_by = f"Track {behavior.track_id}"
            else:
                tracked_by = ""

            pbr_policies.append({
                "vendor_mechanism": "Huawei traffic-policy",
                "policy_name": policy.name,
                "sequence": binding.precedence if binding.precedence is not None else "",
                "action": "redirect",
                "match": match,
                "set_next_hop": set_next_hop,
                "tracked_by": tracked_by,
            })

    eem_dynamic_pbr = []
    for eem in getattr(config, "eem_pbr_bindings", []):
        eem_dynamic_pbr.append({
            "applet_name": eem.applet_name,
            "route_map_name": eem.route_map_name,
            "action": eem.action,
            "target_interfaces": list(eem.target_interfaces),
            "trigger_description": eem.trigger_description,
        })

    has_custom_routing = bool(
        sla_tests or track_objects or pbr_bindings or pbr_policies or eem_dynamic_pbr
    )

    return {
        "sla_tests": sla_tests,
        "track_objects": track_objects,
        "pbr_policies": pbr_policies,
        "pbr_bindings": pbr_bindings,
        "eem_dynamic_pbr": eem_dynamic_pbr,
        "has_custom_routing": has_custom_routing,
    }


def _extract_dns(config) -> dict[str, Any]:
    servers: list[str] = []
    domain = ""

    for line in getattr(config, "global_commands", []):
        text = str(line).strip()

        for pattern in DNS_SERVER_PATTERNS:
            match = pattern.match(text)
            if match:
                for token in match.group(1).split():
                    if IPV4_RE.match(token) and token not in servers:
                        servers.append(token)
                break

        for pattern in DOMAIN_NAME_PATTERNS:
            match = pattern.match(text)
            if match and not domain:
                domain = match.group(1)
                break

    return {"servers": servers, "domain": domain}


def _extract_snmp(config) -> dict[str, Any]:
    commands = list(getattr(config, "snmp_commands", []))
    summary = {"communities": [], "locations": [], "contacts": [], "hosts": []}

    for line in commands:
        text = str(line).strip()

        for pattern in SNMP_PATTERNS["community"]:
            match = pattern.match(text)
            if match and match.groups() and match.group(1) not in summary["communities"]:
                summary["communities"].append(match.group(1))

        for pattern in SNMP_PATTERNS["location"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["locations"]:
                summary["locations"].append(match.group(1))

        for pattern in SNMP_PATTERNS["contact"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["contacts"]:
                summary["contacts"].append(match.group(1))

        for pattern in SNMP_PATTERNS["host"]:
            match = pattern.match(text)
            if match and match.group(1) not in summary["hosts"]:
                summary["hosts"].append(match.group(1))

    return {
        "enabled": bool(commands),
        "summary": summary,
        "raw_commands": commands,
    }
