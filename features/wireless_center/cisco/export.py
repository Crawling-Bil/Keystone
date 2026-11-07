"""Excel export of a Cisco 9800 analysis: one sheet per table of the page."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

HEAD = PatternFill("solid", fgColor="1F3A4D")


def _sheet(wb, title, headers, rows):
    ws = wb.create_sheet(title[:31])
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = HEAD
    for row in rows:
        ws.append(["Yes" if v is True else "No" if v is False else ", ".join(map(str, v)) if isinstance(v, list) else v for v in row])
    for i, h in enumerate(headers, 1):
        width = max([len(str(h))] + [len(str(ws.cell(r, i).value or "")) for r in range(2, min(ws.max_row, 300) + 1)])
        ws.column_dimensions[get_column_letter(i)].width = min(max(10, width + 2), 60)
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = Alignment(vertical="top", wrap_text=True)


def export(result: dict[str, Any], path: Path) -> None:
    m = result["cisco"]
    w = m["wlc"]
    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    for k, v in (("Hostname", w["hostname"]), ("Model", w["model"]), ("Serial", ", ".join(w["serials"])),
                 ("Software", w["software_version"]), ("Management", f"{w['management_interface']} {w['management_ip']}"),
                 ("HA", f"{w['ha_mode']} {w['ha_hardware']}".strip()), ("Country", w["country"]),
                 ("APs", len(m["aps"])), ("WLANs", len(m["wlans"])), ("Source", m["source_kind"])):
        ws.append([k, v])
    ws.column_dimensions["A"].width = 16
    ws.column_dimensions["B"].width = 50
    _sheet(wb, "Findings", ["Severity", "Category", "Finding", "Detail", "Affected"],
           [[f["severity"], f["category"], f["title"], f["detail"], f["items"]] for f in result["findings"]])
    _sheet(wb, "APs", ["AP Name", "Model", "Ethernet MAC", "Serial", "IP", "State", "Mode", "Policy Tag", "Site Tag", "RF Tag",
                       "Misconfigured", "Software", "Primary WLC", "Secondary WLC", "Location", "Last disconnect"],
           [[a.get("name"), a.get("model"), a["mac"], a.get("serial"), a.get("ip"), a["state"], a.get("mode"), a.get("policy_tag"),
             a.get("site_tag"), a.get("rf_tag"), a.get("misconfigured"), a.get("version"), a.get("primary_wlc"),
             a.get("secondary_wlc"), a.get("location"), a.get("disconnect_reason")] for a in m["aps"]])
    _sheet(wb, "WLANs", ["ID", "Profile", "SSID", "Status", "Security", "Auth list", "MAC filtering", "Broadcast", "Radio", "PSK"],
           [[x["id"], x["profile"], x["ssid"], x["status"], x.get("security_summary") or x["security"], x["auth_list"],
             x["mac_filtering"], x["broadcast"], x["radio_policy"], x["psk"]] for x in m["wlans"]])
    _sheet(wb, "Policy Profiles", ["Name", "Description", "Status", "VLAN", "Switching", "DHCP", "AAA override", "NAC",
                                   "Accounting", "Session timeout", "Idle timeout", "ACL"],
           [[p["name"], p["description"], p["status"], p["vlan"], p["switching"], p["dhcp"], p["aaa_override"], p["nac"],
             p["accounting"], p["session_timeout"], p["idle_timeout"], p["acl"]] for p in m["policy_profiles"]])
    _sheet(wb, "Policy Tags", ["Policy Tag", "Description", "WLAN", "Policy Profile"],
           [[t["name"], t["description"], mp["wlan"], mp["policy"]] for t in m["policy_tags"] for mp in (t["mappings"] or [{"wlan": "", "policy": ""}])])
    _sheet(wb, "Site Tags", ["Site Tag", "Description", "AP Join Profile", "Flex Profile", "Local site"],
           [[t["name"], t["description"], t["ap_profile"], t["flex_profile"], t["local_site"]] for t in m["site_tags"]])
    _sheet(wb, "RF Tags", ["RF Tag", "Description", "2.4 GHz", "5 GHz", "6 GHz"],
           [[t["name"], t["description"], t["rf_24"], t["rf_5"], t["rf_6"]] for t in m["rf_tags"]])
    _sheet(wb, "AP Join Profiles", ["Name", "Description", "Country", "Mgmt user", "SSH", "NTP", "Syslog", "Primary", "Secondary"],
           [[p["name"], p["description"], p["country"], p["mgmt_user"], p["ssh"], p["ntp"], p["syslog"], p["primary"], p["secondary"]] for p in m["ap_join_profiles"]])
    _sheet(wb, "Flex Profiles", ["Name", "Description", "Native VLAN", "VLANs", "ACLs"],
           [[p["name"], p["description"], p["native_vlan"], p["vlans"], p["acls"]] for p in m["flex_profiles"]])
    _sheet(wb, "RF Profiles", ["Name", "Band", "Description", "Tx min", "Tx max", "RX-SOP", "Mandatory rates", "Status"],
           [[p["name"], p["band"], p["description"], p["tx_min"], p["tx_max"], p["rx_sop"], p["mandatory"], p["status"]] for p in m["rf_profiles"]])
    _sheet(wb, "AAA", ["Name", "Type", "Address", "Ports"], [[s["name"], s["type"], s["address"], s["ports"]] for s in m["aaa"]["servers"]])
    _sheet(wb, "Local Users", ["Username", "Privilege", "Credential"], [[u["username"], u["privilege"], u["credential"]] for u in m["local_users"]])
    wb.save(path)
