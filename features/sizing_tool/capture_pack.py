"""The commands to collect before a sizing run, per vendor and platform: only what the Sizing Tool reads (identity, inventory, optics, PoE, licences, peaks).

Every command below is one the project's own collect lists already carry (``static/collect-scripts``, checked against real captures and vendor documentation) or one
the vendor documents for the purpose; ``tests/test_sizing_tool.py`` checks that each entry of the first kind is still present in its list, so the pack cannot drift.
The full per-platform lists remain the ones to use for an analyzer review; this pack is the short list a pre-sales engineer asks a customer for.
"""

from __future__ import annotations

from typing import Any

# (title, collect-scripts file or "", commands [(command, why)], documentation [(title, url)])
PACKS: tuple[dict[str, Any], ...] = (
    {"id": "cisco-catalyst", "vendor": "Cisco", "title": "Cisco Catalyst switch (IOS / IOS-XE)", "types": ["switch"], "source": "collect-cisco-catalyst.txt", "prompt": "terminal length 0",
     "commands": [("show version", "model, software, uptime, serial"), ("show inventory", "chassis, modules, power supplies, optics with part numbers"),
                  ("show interface status", "port speed and link state"), ("show interface transceiver", "optic type per port"), ("show power inline", "PoE budget and draw"),
                  ("show license summary", "licence level and state"), ("show license usage", "licences in use"), ("show processes cpu sorted", "CPU at the moment of the capture")],
     "docs": [("Cisco Catalyst 9300 Series Switches Data Sheet", "https://www.cisco.com/c/en/us/products/collateral/switches/catalyst-9300-series-switches/nb-06-cat9300-ser-data-sheet-cte-en.html")]},
    {"id": "cisco-nexus", "vendor": "Cisco", "title": "Cisco Nexus switch (NX-OS)", "types": ["switch"], "source": "collect-cisco-nexus.txt", "prompt": "terminal length 0",
     "commands": [("show version", "model, software"), ("show inventory", "chassis, modules, power supplies, fans"), ("show interface status", "port Type column (speed capability) and link state"),
                  ("show interface transceiver", "optic type per port"), ("show license usage", "licences in use"), ("show system resources", "CPU and memory")],
     "docs": [("Cisco Nexus 9000 and 3000 Series NX-OS Smart Licensing Using Policy User Guide", "https://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/nx-os/licensing/guide/cisco-nexus-nx-os-smart-licensing-using-policy-user-guide/m-smart-licensing-using-policy.html")]},
    {"id": "cisco-router", "vendor": "Cisco", "title": "Cisco router (ISR, ASR, Catalyst 8000; IOS-XE)", "types": ["router"], "source": "collect-router-cisco-ios-xe.txt", "prompt": "terminal length 0",
     "commands": [("show version", "model, software, serial"), ("show inventory", "chassis, modules, SPAs, power supplies"), ("show ip interface brief", "interfaces and state"),
                  ("show license summary", "licence level (Smart Licensing Using Policy)"), ("show license usage", "licences in use"), ("show platform resources", "CPU and memory of the platform"),
                  ("show process cpu history", "CPU peak over the last 72 hours")],
     "docs": [("Configure Licenses and Throughput for Catalyst 8000 Series Physical Platforms", "https://www.cisco.com/c/en/us/td/docs/routers/cloud_edge/configure-licenses-throughput-catalyst-8000-platforms.html")]},
    {"id": "huawei-s", "vendor": "Huawei", "title": "Huawei S / L / E-series switch (VRP)", "types": ["switch"], "source": "collect-huawei-s-l-e-series.txt", "prompt": "screen-length 0 temporary",
     "commands": [("display version", "model, software"), ("display device", "boards, stack members"), ("display device elabel brief", "serial numbers and part numbers"),
                  ("display interface brief", "ports and state"), ("display interface transceiver", "optics"), ("display poe power", "PoE budget"), ("display license", "licence file state"),
                  ("display cpu-usage", "CPU")],
     "docs": [("Huawei Product End of Life Policy", "https://support.huawei.com/ecolumnsweb/en/warranty-policy")]},
    {"id": "aruba-cx", "vendor": "Aruba", "title": "Aruba CX switch (AOS-CX)", "types": ["switch"], "source": "collect-aruba-cx.txt", "prompt": "no page",
     "commands": [("show version", "model, software"), ("show system inventory", "chassis, modules, power supplies"), ("show vsf", "VSF stack members"), ("show interface brief", "ports, speed, state"),
                  ("show interface transceiver", "optics"), ("show power-over-ethernet", "PoE budget"), ("show system resource-utilization", "CPU and memory")],
     "docs": [("Aruba Central Licensing Guide", "https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf")]},
    {"id": "aruba-os-switch", "vendor": "Aruba", "title": "Aruba / HPE ProCurve switch (ArubaOS-Switch, AOS-S)", "types": ["switch"], "source": "collect-aruba-switch.txt", "prompt": "no page",
     "commands": [("show version", "software"), ("show system", "name, serial, software revision"), ("show modules", "installed modules and product numbers"), ("show interfaces brief", "ports, type, state"),
                  ("show interfaces transceiver", "optics"), ("show power-over-ethernet brief", "PoE budget and draw")],
     "docs": [("HPE Aruba Networking Product Lifecycle Policy", "https://arubanetworking.hpe.com/techdocs/sdwan-PDFs/docs/eula/EC_LifecyclePolicy_latest.pdf")]},
    {"id": "palo-alto", "vendor": "Palo Alto", "title": "Palo Alto Networks firewall (PAN-OS)", "types": ["firewall"], "source": "collect-firewall-paloalto.txt", "prompt": "set cli pager off",
     "commands": [("show system info", "model, serial, PAN-OS version"), ("show high-availability state", "HA mode and state"), ("request license info", "subscriptions and their expiry dates"),
                  ("show session info", "sessions in use, session rate, throughput of the dataplane"), ("show running resource-monitor", "dataplane CPU over time")],
     "docs": [("PAN-OS CLI Cheat Sheet: Device Management", "https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-cheat-sheet-device-management"),
              ("Licensing, Registration, and Activation", "https://docs.paloaltonetworks.com/resources/licensing-registration-activation")]},
    {"id": "fortigate", "vendor": "Fortinet", "title": "Fortinet FortiGate (FortiOS)", "types": ["firewall"], "source": "collect-firewall-fortigate.txt", "prompt": "",
     "commands": [("get system status", "model, serial, FortiOS, licence status"), ("get system ha status", "HA mode"), ("get system performance status", "CPU, memory, sessions"),
                  ("diagnose sys session stat", "session statistics"), ("diagnose test update info", "FortiGuard contracts and expiry dates")],
     "docs": [("CLI troubleshooting cheat sheet (FortiGate 7.4)", "https://docs.fortinet.com/document/fortigate/7.4.0/cli-troubleshooting-cheat-sheet/420966/cli-troubleshooting-cheat-sheet"),
              ("Technical Tip: How to view license details via CLI and GUI", "https://community.fortinet.com/fortigate-3/technical-tip-how-to-view-license-details-via-cli-and-gui-95031")]},
    {"id": "f5-bigip", "vendor": "F5", "title": "F5 BIG-IP (TMOS)", "types": ["load_balancer"], "source": "collect-lb-f5-bigip.txt", "prompt": "",
     "commands": [("tmsh show sys hardware", "appliance model and serial"), ("tmsh show sys license", "licence bundle, add-ons and end dates"), ("tmsh show sys provision", "modules provisioned"),
                  ("tmsh show sys performance all-stats", "throughput, connections and SSL TPS: current, average and maximum"), ("tmsh show sys cpu", "CPU")],
     "docs": [("K7752: Licensing the BIG-IP system", "https://my.f5.com/manage/s/article/K7752")]},
    {"id": "mikrotik", "vendor": "MikroTik", "title": "MikroTik RouterOS", "types": ["router"], "source": "collect-firewall-mikrotik.txt", "prompt": "",
     "commands": [("/system resource print", "model, version, CPU, memory"), ("/system routerboard print", "serial and firmware"), ("/export verbose", "configuration"),
                  ("/system license print", "licence level")],
     "docs": [("RouterOS license keys", "https://help.mikrotik.com/docs/spaces/ROS/pages/328149/RouterOS+license+keys")]},
)
# commands the vendor documents for the purpose but the project's list does not carry (so the drift test skips them)
DOCUMENTED_ONLY = {"request license info", "show session info", "show running resource-monitor", "diagnose sys session stat", "diagnose test update info", "/system license print",
                   "show platform hardware throughput level"}


def packs_for(vendors: list[str] | None = None) -> list[dict[str, Any]]:
    out = []
    for pack in PACKS:
        if vendors and pack["vendor"] not in vendors:
            continue
        out.append({"id": pack["id"], "vendor": pack["vendor"], "title": pack["title"], "types": pack["types"], "commands": [{"command": c, "why": w} for c, w in pack["commands"]],
                    "docs": [{"title": t, "url": u} for t, u in pack["docs"]], "prompt": pack["prompt"]})
    return out


def as_text(pack_ids: list[str] | None = None) -> str:
    """One text file the engineer pastes into a session; each block is headed by the platform and says what the commands are for."""
    chosen = [p for p in PACKS if not pack_ids or p["id"] in pack_ids]
    lines = ["# Keystone Sizing Tool: capture pack", "# Read-only commands. Paste one block per device into an SSH session and save the whole terminal buffer as one file per device.",
             "# The Sizing Tool reads the hostname from the prompt, so keep the prompt in the saved file.", ""]
    for pack in chosen:
        lines.append(f"# ===== {pack['title']} =====")
        if pack["prompt"]:
            lines.append(pack["prompt"])
        for command, why in pack["commands"]:
            lines.append(f"{command}        # {why}" if not command.startswith("/") else f"{command}   # {why}")
        for title, url in pack["docs"]:
            lines.append(f"# Documentation: {title} {url}")
        lines.append("")
    return "\n".join(lines)
