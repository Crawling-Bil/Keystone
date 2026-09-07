from __future__ import annotations

from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Font
from openpyxl.utils import get_column_letter

from ..sizing import build_sizing_summary


class SwitchExcelExporter:
    """Dumps one or more Switch Analyzer results (the same JSON the
    frontend renders into tabs) into a single multi-sheet .xlsx
    workbook — one sheet PER DATA CATEGORY (Interfaces, Transceivers,
    PoE, etc.), not one sheet-set per device. Every row carries a
    "Hostname" column, so combining more devices means more rows in the
    same sheets rather than more sheets — built for mapping many
    devices' data into one workbook for a sizing assessment, add
    devices to the `results` list to extend it. A single-device export
    (the common case from the analyzer's own Export button) is just a
    one-item list.
    """

    def __init__(self, results: list[dict[str, Any]] | dict[str, Any]):
        # Accept a bare single result too, so existing single-device
        # call sites don't need to remember to wrap it in a list.
        self.results: list[dict[str, Any]] = [results] if isinstance(results, dict) else list(results)

    @staticmethod
    def add_sheet(workbook: Workbook, title: str, headers: list[str], rows: list[list[Any]]) -> None:
        sheet = workbook.create_sheet(title[:31])  # Excel sheet-name length limit
        sheet.append(headers)
        for cell in sheet[1]:
            cell.font = Font(bold=True)
        for row in rows:
            sheet.append(row)
        for column in sheet.columns:
            max_length = max((len(str(cell.value or "")) for cell in column), default=0)
            sheet.column_dimensions[get_column_letter(column[0].column)].width = min(max_length + 2, 60)
        if rows:
            sheet.freeze_panes = "A2"
            sheet.auto_filter.ref = sheet.dimensions

    def export(self, path) -> None:
        self.build_workbook().save(path)

    def build_workbook(self) -> Workbook:
        workbook = Workbook()
        workbook.remove(workbook.active)

        device_info_rows: list[list[Any]] = []
        serial_rows: list[list[Any]] = []
        stack_rows: list[list[Any]] = []
        interface_rows: list[list[Any]] = []
        transceiver_rows: list[list[Any]] = []
        port_channel_rows: list[list[Any]] = []
        vpc_mlag_summary_rows: list[list[Any]] = []
        vpc_mlag_member_rows: list[list[Any]] = []
        poe_rows: list[list[Any]] = []
        vlan_rows: list[list[Any]] = []
        neighbor_rows: list[list[Any]] = []
        route_rows: list[list[Any]] = []
        routing_table_rows: list[list[Any]] = []
        arp_rows: list[list[Any]] = []
        dns_snmp_rows: list[list[Any]] = []
        dhcp_summary_rows: list[list[Any]] = []
        dhcp_pool_rows: list[list[Any]] = []
        dhcp_helper_rows: list[list[Any]] = []
        dhcp_snooping_rows: list[list[Any]] = []
        pbr_sla_rows: list[list[Any]] = []
        pbr_track_rows: list[list[Any]] = []
        pbr_policy_rows: list[list[Any]] = []
        pbr_binding_rows: list[list[Any]] = []
        pbr_eem_rows: list[list[Any]] = []

        for result in self.results:
            hostname = result.get("hostname", "")
            os_version = result.get("os_version") or {}
            inventory = result.get("inventory") or {"modules": [], "stack": {}}
            stack = inventory.get("stack") or {}
            cards = result.get("cards") or {}

            device_info_rows.append([
                hostname, result.get("vendor", ""), result.get("device_type", ""),
                os_version.get("os_version", ""), os_version.get("model", ""),
                stack.get("mode", ""), stack.get("member_count", ""),
                cards.get("total_interfaces", ""), cards.get("interfaces_up", ""),
                cards.get("interfaces_down", ""),
            ])

            for m in inventory.get("modules", []):
                serial_rows.append([hostname, m.get("slot", ""), m.get("description", ""), m.get("pid", ""), m.get("serial", "")])

            for m in stack.get("members", []):
                stack_rows.append([
                    hostname, m.get("slot", ""), m.get("role", ""), m.get("mac", ""),
                    m.get("state", ""), m.get("priority", ""),
                ])

            for i in result.get("interfaces", []):
                interface_rows.append([
                    hostname, i.get("name", ""), i.get("status", ""), i.get("protocol", ""), i.get("mode", ""),
                    i.get("vlan", ""), i.get("allowed_vlans", ""), i.get("ip_address", ""), i.get("description", ""),
                    i.get("port_security", ""), i.get("hsrp_vrrp_ip", ""),
                ])

            for t in result.get("transceivers", []):
                transceiver_rows.append([
                    hostname, t.get("interface", ""), t.get("status", ""), "Yes" if t.get("present") else "No",
                    t.get("type", ""), t.get("vendor_part_number", ""), t.get("serial_number", ""),
                ])

            for p in result.get("port_channels", []):
                port_channel_rows.append([
                    hostname, p.get("name", ""), p.get("protocol", ""), p.get("status", ""),
                    p.get("description", ""), p.get("mode", ""), p.get("vlan", ""),
                    p.get("allowed_vlans", ""), p.get("ip_address", ""), p.get("members", ""),
                ])

            # source: "live" (a real show-command session), "config" (no
            # live status yet — a not-yet-deployed draft, see
            # service._apply_vpc_mlag_config_fallback), or "none" (no
            # vPC/M-LAG at all). Carried into the export so a reviewer
            # opening the workbook later doesn't mistake a draft's
            # configured-only rows for a confirmed, active vPC/M-LAG.
            vpc_mlag = result.get("vpc_mlag") or {"summary": {}, "members": [], "source": "none"}
            source = vpc_mlag.get("source", "")
            for key, value in (vpc_mlag.get("summary") or {}).items():
                vpc_mlag_summary_rows.append([hostname, key.replace("_", " ").title(), value, source])
            for m in vpc_mlag.get("members", []):
                vpc_mlag_member_rows.append([
                    hostname, m.get("id", ""), m.get("port", ""), m.get("status", ""),
                    m.get("consistency", ""), m.get("vlans", ""), source,
                ])

            for p in result.get("poe", []):
                poe_rows.append([
                    hostname, p.get("interface", ""), p.get("admin_status", ""), p.get("oper_status", ""),
                    p.get("power_watts", ""), p.get("device", ""), p.get("class", ""), p.get("max_watts", ""),
                    p.get("source", ""),
                ])

            for v in result.get("vlans", []):
                vlan_rows.append([hostname, v.get("vlan_id", ""), v.get("name", "")])

            for n in result.get("neighbors", []):
                neighbor_rows.append([
                    hostname, n.get("protocol", ""), n.get("neighbor_id", ""), n.get("local_interface", ""),
                    n.get("remote_interface", ""), n.get("platform", ""),
                ])

            for r in result.get("routes", []):
                route_rows.append([
                    hostname, r.get("destination", ""), r.get("mask", ""), r.get("next_hop", ""),
                    r.get("distance", ""), r.get("track_id", ""),
                ])

            pbr = result.get("pbr") or {}
            for s in pbr.get("sla_tests", []):
                pbr_sla_rows.append([
                    hostname, s.get("kind", ""), s.get("id", ""), s.get("test_type", ""),
                    s.get("destination", ""), s.get("frequency", ""), s.get("timeout", ""),
                    s.get("probe_count", ""),
                ])
            for t in pbr.get("track_objects", []):
                pbr_track_rows.append([hostname, t.get("track_id", ""), t.get("tracks", "")])
            for p in pbr.get("pbr_policies", []):
                pbr_policy_rows.append([
                    hostname, p.get("vendor_mechanism", ""), p.get("policy_name", ""),
                    p.get("sequence", ""), p.get("action", ""), p.get("match", ""),
                    p.get("set_next_hop", ""), p.get("tracked_by", ""),
                ])
            for b in pbr.get("pbr_bindings", []):
                pbr_binding_rows.append([
                    hostname, b.get("interface", ""), b.get("policy_name", ""),
                    b.get("direction", ""), b.get("mechanism", ""),
                ])
            for e in pbr.get("eem_dynamic_pbr", []):
                pbr_eem_rows.append([
                    hostname, e.get("applet_name", ""), e.get("route_map_name", ""), e.get("action", ""),
                    ", ".join(e.get("target_interfaces", [])), e.get("trigger_description", ""),
                ])

            for r in result.get("routing_table", []):
                routing_table_rows.append([hostname, r.get("protocol", ""), r.get("destination", ""), r.get("next_hop", ""), r.get("interface", "")])

            for a in result.get("arp_table", []):
                arp_rows.append([hostname, a.get("ip_address", ""), a.get("mac_address", ""), a.get("age", ""), a.get("interface", "")])

            dns = result.get("dns") or {}
            snmp = result.get("snmp") or {}
            snmp_summary = snmp.get("summary") or {}
            dns_snmp_rows.append([
                hostname, ", ".join(dns.get("servers", [])), dns.get("domain", ""),
                "Yes" if snmp.get("enabled") else "No",
                ", ".join(snmp_summary.get("communities", [])),
                ", ".join(snmp_summary.get("locations", [])),
                ", ".join(snmp_summary.get("hosts", [])),
            ])

            dhcp = result.get("dhcp") or {}
            dhcp_snooping = dhcp.get("snooping") or {}
            dhcp_summary_rows.append([
                hostname,
                "Yes" if dhcp_snooping.get("enabled") else "No",
                ", ".join(dhcp_snooping.get("vlans", [])),
                "Yes" if dhcp_snooping.get("option82_enabled") else "No",
                len(dhcp.get("pools", [])),
                len(dhcp.get("helper_addresses", [])),
            ])
            for pool in dhcp.get("pools", []):
                dhcp_pool_rows.append([
                    hostname, pool.get("name", ""), pool.get("network", ""), pool.get("mask", ""),
                    pool.get("gateway", ""), pool.get("dns_servers", ""), pool.get("domain_name", ""),
                    pool.get("lease", ""), "; ".join(pool.get("options", [])),
                ])
            for helper in dhcp.get("helper_addresses", []):
                dhcp_helper_rows.append([hostname, helper.get("interface", ""), ", ".join(helper.get("servers", []))])
            trusted = set(dhcp_snooping.get("trusted_interfaces", []))
            rate_by_interface = {item.get("interface"): item.get("limit_pps") for item in dhcp_snooping.get("rate_limited_interfaces", [])}
            for interface_name in trusted | set(rate_by_interface):
                dhcp_snooping_rows.append([
                    hostname, interface_name,
                    "Trusted" if interface_name in trusted else "Untrusted",
                    rate_by_interface.get(interface_name, ""),
                ])

        self.add_sheet(workbook, "Device Info",
            ["Hostname", "Vendor", "Device Type", "OS Version", "Model", "Stack Mode",
             "Stack Member Count", "Total Interfaces", "Interfaces Up", "Interfaces Down"],
            device_info_rows)
        self.add_sheet(workbook, "Serial Numbers", ["Hostname", "Slot", "Description", "PID", "Serial Number"], serial_rows)
        self.add_sheet(workbook, "Stack Members", ["Hostname", "Slot", "Role", "MAC Address", "State", "Priority"], stack_rows)
        self.add_sheet(workbook, "Interfaces",
            ["Hostname", "Name", "Status", "Protocol", "Mode", "VLAN", "Allowed VLANs", "IP Address", "Description", "Port Security", "HSRP/VRRP IP"],
            interface_rows)
        self.add_sheet(workbook, "Transceivers",
            ["Hostname", "Interface", "Status", "Present", "Type", "Vendor Part Number", "Serial Number"],
            transceiver_rows)
        self.add_sheet(workbook, "Port-Channels",
            ["Hostname", "Name", "Protocol", "Status", "Description", "Mode", "VLAN", "Allowed VLANs", "IP Address", "Member Ports"],
            port_channel_rows)
        self.add_sheet(workbook, "VPC-MLAG Summary", ["Hostname", "Field", "Value", "Source"], vpc_mlag_summary_rows)
        self.add_sheet(workbook, "VPC-MLAG Members", ["Hostname", "ID", "Port", "Status", "Consistency", "VLANs", "Source"], vpc_mlag_member_rows)
        self.add_sheet(workbook, "PoE",
            ["Hostname", "Interface", "Admin Status", "Oper Status", "Power (W)", "Device", "Class", "Max (W)", "Source"],
            poe_rows)
        self.add_sheet(workbook, "VLANs", ["Hostname", "VLAN ID", "Name"], vlan_rows)
        self.add_sheet(workbook, "Neighbors",
            ["Hostname", "Protocol", "Neighbor", "Local Interface", "Remote Interface", "Platform"],
            neighbor_rows)
        self.add_sheet(workbook, "Static Routes", ["Hostname", "Destination", "Mask", "Next Hop", "Admin Distance", "Track ID"], route_rows)
        self.add_sheet(workbook, "Routing Table", ["Hostname", "Protocol", "Destination", "Next Hop", "Interface"], routing_table_rows)
        self.add_sheet(workbook, "PBR SLA-NQA Tests",
            ["Hostname", "Kind", "Test", "Type", "Destination", "Frequency (s)", "Timeout (s)", "Probe Count"],
            pbr_sla_rows)
        self.add_sheet(workbook, "PBR Track Objects", ["Hostname", "Track ID", "Tracks"], pbr_track_rows)
        self.add_sheet(workbook, "PBR Policies",
            ["Hostname", "Mechanism", "Policy Name", "Sequence/Precedence", "Action", "Match", "Set Next Hop", "Tracked By"],
            pbr_policy_rows)
        self.add_sheet(workbook, "PBR Interface Bindings",
            ["Hostname", "Interface", "Policy Name", "Direction", "Mechanism"], pbr_binding_rows)
        self.add_sheet(workbook, "PBR EEM Dynamic (Cisco)",
            ["Hostname", "Applet Name", "Route-Map", "Action", "Target Interfaces", "Trigger"], pbr_eem_rows)
        self.add_sheet(workbook, "ARP Table", ["Hostname", "IP Address", "MAC Address", "Age", "Interface"], arp_rows)
        self.add_sheet(workbook, "DNS-SNMP",
            ["Hostname", "DNS Servers", "Domain Name", "SNMP Configured", "SNMP Communities", "SNMP Locations", "SNMP Trap Hosts"],
            dns_snmp_rows)
        self.add_sheet(workbook, "DHCP Summary",
            ["Hostname", "Snooping Enabled", "Snooping VLANs", "Option 82 Enabled", "Pool Count", "Relay Interface Count"],
            dhcp_summary_rows)
        self.add_sheet(workbook, "DHCP Pools",
            ["Hostname", "Pool Name", "Network", "Mask", "Gateway", "DNS Servers", "Domain", "Lease", "Options"],
            dhcp_pool_rows)
        self.add_sheet(workbook, "DHCP Relay-Helper",
            ["Hostname", "Interface", "Relay/Helper Servers"], dhcp_helper_rows)
        self.add_sheet(workbook, "DHCP Snooping Interfaces",
            ["Hostname", "Interface", "Trust State", "Rate Limit (pps)"], dhcp_snooping_rows)

        self._add_sizing_sheet(workbook)

        return workbook

    def _add_sizing_sheet(self, workbook: Workbook) -> None:
        """"Sizing Summary" — one row per device plus an aggregate
        totals row and a port-speed breakdown, built from sizing.py's
        build_sizing_summary(). Placed first (index 0) so it's the
        workbook's landing page, same convention as the Comparison
        sheet in export_comparison().
        """
        summary = build_sizing_summary(self.results)
        devices = summary["devices"]
        totals = summary["totals"]

        sheet = workbook.create_sheet("Sizing Summary", 0)
        headers = [
            "Hostname", "Vendor", "Model", "OS Version", "Physical Ports",
            "Ports Up", "Ports Down", "Trunk Ports", "Port-Channels",
            "PoE Ports", "PoE Total (W)", "PoE Source", "Transceivers",
            "VLANs", "Static Routes",
            "OSPF Configured", "vPC/M-LAG Configured", "vPC/M-LAG Source",
            "vPC/M-LAG Members", "HSRP/VRRP SVIs", "Stack Mode", "Stack Members",
        ]
        sheet.append(headers)
        for cell in sheet[1]:
            cell.font = Font(bold=True)

        def yes_no(value: bool) -> str:
            return "Yes" if value else "No"

        for d in devices:
            sheet.append([
                d["hostname"], d["vendor"], d["model"], d["os_version"],
                d["physical_port_count"], d["physical_ports_up"], d["physical_ports_down"],
                d["trunk_port_count"], d["port_channel_count"],
                d["poe_port_count"], d["poe_total_watts"], d["poe_source"],
                d["transceiver_count"],
                d["vlan_count"], d["static_route_count"],
                yes_no(d["ospf_configured"]), yes_no(d["vpc_mlag_configured"]), d["vpc_mlag_source"],
                d["vpc_mlag_member_count"], d["hsrp_vrrp_svi_count"],
                d["stack_mode"], d["stack_member_count"],
            ])

        blank_row = [""] * len(headers)
        sheet.append(blank_row)
        sheet.append([
            f"TOTALS ({totals['device_count']} device(s))", "", "", "",
            totals["physical_port_count"], totals["physical_ports_up"], totals["physical_ports_down"],
            totals["trunk_port_count"], totals["port_channel_count"],
            totals["poe_port_count"], totals["poe_total_watts"], "",
            totals["transceiver_count"],
            totals["unique_vlan_count"], totals["static_route_count"],
            totals["ospf_device_count"], totals["vpc_mlag_device_count"], "",
            "", totals["hsrp_vrrp_svi_count"],
            f"{totals['stacked_device_count']} stacked", "",
        ])
        for cell in sheet[sheet.max_row]:
            cell.font = Font(bold=True)

        sheet.append(blank_row)
        sheet.append(["Note: VLANs total above is the unique VLAN-ID count across all devices (VLANs commonly repeat across switches at the same site, so a plain sum would double-count)."])
        sheet.append(blank_row)

        sheet.append(["Physical Port Count by Speed"])
        sheet[sheet.max_row][0].font = Font(bold=True)
        sheet.append(["Type", "Count"])
        for cell in sheet[sheet.max_row]:
            cell.font = Font(bold=True)
        for label, count in sorted(totals["port_type_totals"].items()):
            sheet.append([label, count])

        sheet.append(blank_row)
        sheet.append(["Transceiver Count by Type"])
        sheet[sheet.max_row][0].font = Font(bold=True)
        sheet.append(["Note: vendor-specific abbreviations for the same physical SFP/QSFP class are merged into one row (e.g. ArubaOS-Switch's \"1000SX\" and Cisco's \"1000BaseSX SFP\" are the same part) — see sizing.py for the confirmed aliases; anything not confirmed is kept exactly as the device reported it. Broken down by Vendor Part Number too, not just Type — the same media class can still be a different orderable SKU (a genuine Cisco GLC-SX-MMD vs. a third-party/compatible optic), so this is what to actually check against before ordering replacements."])
        sheet.append(["Type", "Vendor Part Number", "Count"])
        for cell in sheet[sheet.max_row]:
            cell.font = Font(bold=True)
        for row in totals["transceiver_part_totals"]:
            sheet.append([row["type"], row["vendor_part_number"], row["count"]])

        for column in sheet.columns:
            max_length = max((len(str(cell.value or "")) for cell in column), default=0)
            sheet.column_dimensions[get_column_letter(column[0].column)].width = min(max_length + 2, 42)
        sheet.freeze_panes = "A2"


def export_comparison(path, result_a: dict[str, Any], result_b: dict[str, Any], comparison: dict[str, Any]) -> None:
    """Two-device comparison export: the full per-device data (same
    sheets as a regular export, both devices combined via the Hostname
    column) plus one extra "Comparison" sheet up front summarizing the
    parity check — device info side-by-side, then VLAN/route/DNS-server
    presence across both devices, for the migration sign-off use case.
    """
    exporter = SwitchExcelExporter([result_a, result_b])
    workbook = exporter.build_workbook()

    device_a = comparison.get("device_a", {})
    device_b = comparison.get("device_b", {})
    field_labels = [
        ("hostname", "Hostname"), ("vendor", "Vendor"), ("model", "Model"),
        ("os_version", "OS Version"), ("stack_mode", "Stack Mode"),
        ("stack_member_count", "Stack Member Count"),
        ("total_interfaces", "Total Interfaces"), ("interfaces_up", "Interfaces Up"),
        ("interfaces_down", "Interfaces Down"), ("total_vlans", "Total VLANs"),
        ("total_routes", "Total Routes"), ("neighbor_count", "Neighbor Count"),
        ("port_channel_count", "Port-Channel Count"), ("transceiver_count", "Transceiver Count"),
        ("poe_port_count", "PoE Port Count"),
        ("has_custom_routing", "Has PBR / SLA-Track / NQA?"),
    ]

    def _comparison_value(key: str, value: Any) -> Any:
        if key == "has_custom_routing":
            return "Yes" if value else "No"
        return value

    comparison_rows = [
        [label, _comparison_value(key, device_a.get(key, "")), _comparison_value(key, device_b.get(key, ""))]
        for key, label in field_labels
    ]
    comparison_rows.append(["", "", ""])

    def diff_rows(title: str, diff: dict[str, list]) -> list[list]:
        rows = [[title, "", ""]]
        for value in diff.get("only_a", []):
            rows.append([value, "Only Device A", ""])
        for value in diff.get("only_b", []):
            rows.append([value, "", "Only Device B"])
        for value in diff.get("both", []):
            rows.append([value, "Both", "Both"])
        rows.append(["", "", ""])
        return rows

    comparison_rows += diff_rows("VLANs", comparison.get("vlans", {}))
    comparison_rows += diff_rows("Routes (destination)", comparison.get("routes", {}))
    comparison_rows += diff_rows("DNS Servers", comparison.get("dns_servers", {}))

    sheet = workbook.create_sheet("Comparison", 0)  # first sheet
    sheet.append(["Field / Value", "Device A", "Device B"])
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    for row in comparison_rows:
        sheet.append(row)
    for column in sheet.columns:
        max_length = max((len(str(cell.value or "")) for cell in column), default=0)
        sheet.column_dimensions[get_column_letter(column[0].column)].width = min(max_length + 2, 60)
    sheet.freeze_panes = "A2"

    workbook.save(path)
