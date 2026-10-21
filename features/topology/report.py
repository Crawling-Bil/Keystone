"""The documentation pack: one self-contained HTML report (diagram, tables, findings, one page per device) plus every export in one ZIP.

The report has no scripts and no external files. Open it in a browser and print it to PDF (landscape A4); each device starts on a new page.
"""

from __future__ import annotations

import datetime as _dt
import html
import io
import re
import zipfile
from typing import Any

from . import labels
from .findings import DOC_CDP, DOC_LACP, DOC_LLDP, DOC_VPC
from .graph import Graph, connection_speeds, link_speed
from .names import port_sort_key, speed_text

REFERENCES = (
    ("Cisco: CDP command reference (neighbor, native VLAN and port fields)", DOC_CDP),
    ("IEEE 802.1AB: Link Layer Discovery Protocol (LLDP)", DOC_LLDP),
    ("Cisco: understand and configure Nexus 9000 vPC", DOC_VPC),
    ("Cisco: troubleshoot LACP / port-channel summary flags", DOC_LACP),
)
CSS = """
body{font-family:Segoe UI,Helvetica,Arial,sans-serif;color:#1f2933;margin:0;padding:24px 32px;max-width:1500px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:30px 0 8px;border-bottom:2px solid #005073;padding-bottom:4px;color:#005073}
h3{font-size:15px;margin:18px 0 6px}p.meta{color:#52606d;margin:0 0 18px;font-size:13px}
table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0 14px}th,td{border:1px solid #cbd2d9;padding:4px 7px;text-align:left;vertical-align:top}
th{background:#005073;color:#fff;font-weight:600}tr:nth-child(even) td{background:#f5f7fa}
.cards{display:flex;flex-wrap:wrap;gap:10px}.card{border:1px solid #cbd2d9;border-radius:8px;padding:8px 14px;min-width:120px}
.card b{display:block;font-size:22px}.card span{font-size:11px;color:#52606d}
.sev-medium{background:#f8cbad!important}.sev-low{background:#ffe699!important}.sev-info{background:#ddebf7!important}
.diagram{border:1px solid #cbd2d9;border-radius:8px;padding:8px;margin:8px 0 18px;overflow:auto}.diagram svg{width:100%;height:auto;display:block}
.device{page-break-before:always}.note{font-size:12px;color:#52606d}code{background:#eef1f4;padding:1px 4px;border-radius:3px}
@media print{@page{size:A4 landscape;margin:12mm}body{padding:0}.diagram{break-inside:avoid}tr{break-inside:avoid}}
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _table(headers: list[str], rows: list[list[Any]], classes: list[str] | None = None) -> str:
    if not rows:
        return '<p class="note">Nothing to show.</p>'
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    def tag(i: int) -> str:
        return f' class="{_e(classes[i])}"' if classes and classes[i] else ""

    body = "".join(f"<tr{tag(i)}>" + "".join(f"<td>{_e(c)}</td>" for c in row) + "</tr>" for i, row in enumerate(rows))
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _link(url: str, text: str) -> str:
    return f'<a href="{_e(url)}">{_e(text)}</a>' if re.match(r"^https://[^\s\"<>]+$", url) else _e(text)


def bundles_table(graph: Graph) -> list[dict[str, Any]]:
    """One row per bundle, parallel group or peer-link: both ends, member ports, speed, protocol, vPC id, state."""
    rows = []
    for conn in graph.connections:
        if conn.kind not in ("bundle", "parallel", "peer-link"):
            continue
        rows.append({"device_a": conn.a, "bundle_a": conn.a_po, "ports_a": labels.compress_ports([l.a_port for l in conn.links]),
                     "device_b": conn.b, "bundle_b": conn.b_po, "ports_b": labels.compress_ports([l.b_port for l in conn.links]),
                     "kind": conn.kind, "members": len(conn.links), "speed": labels.speed_summary(graph, conn),
                     "protocol": labels.bundle_protocol(graph, conn), "vpc_id": conn.vpc_id, "state": conn.state})
    return sorted(rows, key=lambda r: (r["device_a"], port_sort_key(r["bundle_a"] or r["ports_a"]), r["device_b"]))


def device_ports(graph: Graph, key: str) -> list[list[str]]:
    rows = []
    for conn in graph.connections:
        if key not in (conn.a, conn.b) or conn.kind in ("host",):
            continue
        for link in conn.links:
            near, port, far, far_port = (link.a, link.a_port, link.b, link.b_port) if link.a == key else (link.b, link.b_port, link.a, link.a_port)
            po = conn.a_po if conn.a == key else conn.b_po
            far_name = graph.nodes[far].hostname if far in graph.nodes else far
            rows.append([port, po, far_name, far_port, speed_text(link_speed(graph, link)), conn.kind, link.state, "/".join(sorted(link.protocols))])
    return sorted(rows, key=lambda r: port_sort_key(r[0]))


def build_report(graph: Graph, summary: dict[str, Any], findings: list[dict], devices: list[dict], links: list[dict], hosts: list[dict],
                 behind: list[dict], svgs: list[dict], skipped: list[dict], title: str = "Network topology documentation",
                 settings: dict[str, Any] | None = None) -> str:
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    cards = [("captured", "Devices captured"), ("seen_only", "Seen by neighbors only"), ("connections", "Connections"), ("confirmed", "Links confirmed both ends"),
             ("single_sided", "Links one end only"), ("vpc_pairs", "vPC pairs"), ("hosts", "Hosts in MAC tables"), ("findings", "Findings")]
    out = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>{_e(title)}</title><style>{CSS}</style></head><body>",
           f"<h1>{_e(title)}</h1><p class='meta'>Generated {_e(now)} by Keystone Topology Builder from CDP/LLDP, port-channel, vPC, MAC and ARP data in device captures. "
           "Nothing in this report was typed in by hand.</p>",
           "<div class='cards'>" + "".join(f"<div class='card'><b>{_e(summary.get(k, 0))}</b><span>{_e(label)}</span></div>" for k, label in cards) + "</div>"]
    if settings:
        out.append("<h2>Build options</h2><p class='note'>The options that were set on the page for this run (the same text is in run-settings.txt).</p><pre>" + _e(settings_text(settings, summary)) + "</pre>")
    out.append("<h2>1. Diagrams</h2>")
    out.append("<p class='note'>Physical view: every cable. vPC view: each vPC pair is one frame and each bundle that spans a pair is one line. IP view: devices that share a subnet, with the address at each end and a table of every interface address. "
               "Black = confirmed from both ends, orange dashed = reported by one end only, red = the ends disagree, blue = vPC peer-link, grey box = seen by a neighbor but not captured.</p>")
    for page in svgs:
        kind = {"logical": "vPC view", "ip": "IP view"}.get(page.get("view"), "Physical view")
        out.append(f"<h3>{_e(page['name'])} <span class='note'>({kind})</span></h3><div class='diagram'>{page['svg']}</div>")
    out.append("<h2>2. Findings</h2>")
    out.append(_table(["ID", "Severity", "Finding", "Detail", "Next step", "Reference"],
                      [[f["id"], f["severity"], f["title"], f["detail"], f["recommendation"], f.get("reference", "")] for f in findings],
                      [f"sev-{f['severity']}" for f in findings]))
    out.append("<h2>3. Device inventory</h2>")
    cols = ["device", "captured", "role", "vendor", "model", "os_version", "management_ip", "serial", "stack_members", "vpc_domain", "vpc_role", "capture_run"]
    out.append(_table([c.replace("_", " ") for c in cols], [[d.get(c, "") for c in cols] for d in devices]))
    out.append("<h2>4. Bundles, vPC and peer-links</h2>")
    bundles = bundles_table(graph)
    out.append(_table(["Device A", "Bundle A", "Ports A", "Device B", "Bundle B", "Ports B", "Kind", "Members", "Speed", "Protocol", "vPC", "State"],
                      [[b["device_a"], b["bundle_a"], b["ports_a"], b["device_b"], b["bundle_b"], b["ports_b"], b["kind"], b["members"], b["speed"], b["protocol"], b["vpc_id"], b["state"]]
                       for b in bundles]))
    out.append("<h2>5. Hosts behind devices that were not captured</h2>")
    out.append("<p class='note'>MAC addresses learned on a port that faces a device nobody captured, for example the virtual machines behind a UCS fabric interconnect. "
               "VMware and Hyper-V are recognised by MAC prefix only: a hint, not proof.</p>")
    out.append(_table(["Behind", "Switch", "Port", "MAC addresses", "With IP", "VMware", "Hyper-V", "VLANs"],
                      [[b["behind"], b["switch"], b["port"], b["mac_addresses"], b["with_ip"], b["vmware"], b["hyper_v"], b["vlans"]] for b in behind]))
    out.append("<h2>6. Per-device pages</h2>")
    for key, node in sorted(graph.nodes.items(), key=lambda item: item[1].hostname):
        if not node.captured:
            continue
        out.append(f"<div class='device'><h3>{_e(node.hostname)}</h3>")
        facts = [("Role", node.role_hint), ("Vendor", node.vendor), ("Model", node.model), ("Software", node.os_version), ("Serial", ", ".join(sorted(node.serials))),
                 ("Management IP", node.mgmt_ip), ("Stack members", node.stack_members), ("vPC domain", node.vpc_domain), ("vPC role", node.vpc_role),
                 ("vPC peer-link", node.vpc_peer_link), ("Capture file", node.source), ("Data from", "previous run" if node.carried else "this run")]
        out.append(_table(["Item", "Value"], [[k, v] for k, v in facts if v not in ("", None)]))
        out.append("<p class='note'>Ports with a CDP/LLDP neighbor. Speed is the rating of the transceiver or port, not the negotiated rate.</p>")
        out.append(_table(["Port", "Bundle", "Neighbor", "Neighbor port", "Speed", "Kind", "State", "Protocol"], device_ports(graph, key)))
        mine = [b for b in behind if b["switch"] == node.hostname]
        if mine:
            out.append("<p class='note'>Hosts behind uncaptured devices on this switch:</p>")
            out.append(_table(["Behind", "Port", "MAC addresses", "With IP", "VMware", "VLANs"], [[b["behind"], b["port"], b["mac_addresses"], b["with_ip"], b["vmware"], b["vlans"]] for b in mine]))
        out.append("</div>")
    out.append("<h2>7. Method and limits</h2><ul class='note'>"
               "<li>A link is <b>confirmed</b> when both devices report it, <b>single-sided</b> when only one does (the other was not captured or does not send CDP/LLDP), and a <b>conflict</b> when the peer's own table says that port faces another device.</li>"
               "<li>Ends are matched by serial number, chassis MAC, hostname and management IP, and by canonical port name.</li>"
               "<li>A vPC frame appears only when both switches of the pair were captured and sit on the same row of the diagram.</li>"
               "<li>Speeds come from transceiver data (<code>show interface transceiver</code>) or the interface name; they are ratings, not negotiated rates.</li>"
               "<li>Neighbor tables are a snapshot. Devices marked <i>previous run</i> are as old as the run that saved them.</li></ul>")
    if skipped:
        out.append("<h3>Files that were not used</h3>" + _table(["File", "Reason"], [[s["file"], s["reason"]] for s in skipped]))
    out.append("<h2>References</h2><ul>" + "".join(f"<li>{_link(url, text)}</li>" for text, url in REFERENCES) + "</ul></body></html>")
    return "".join(out)


def slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-").lower() or "page"


SETTING_LABELS = (
    ("exclude_endpoints", "Exclude IP phones, PCs and servers: draw network devices only (router, firewall, load balancer, switch, access point)"),
    ("collapse_endpoints", "Collapse phones and hosts into one node per switch"),
    ("collapse_aps", "Collapse access points into one node per switch (off = every access point with its own hostname, model and IP address)"),
    ("show_ports", "Show port names on the lines"),
    ("infer_neighbors", "Infer neighbors where CDP/LLDP is silent (order of trust: ARP, then MAC address, then port description)"),
    ("include_routed", "Add routed /30 and /31 links found in interface addresses"),
    ("hide_mgmt", "Leave out-of-band management links (mgmt0) out of the picture; they stay in links.csv"),
    ("include_hosts", "Draw end hosts learned from MAC tables (up to 3 per port, more become one box)"),
)
CHOICE_LABELS = {
    "group": {"none": "One diagram", "prefix1": "Group by first hostname word (BGR, JKT, DRC)", "prefix2": "Group by first two hostname words (JKT-A02)",
              "prefix3": "Group by first three hostname words (JKT-GD1-LT1)"},
    "view": {"both": "Physical and vPC view", "physical": "Physical view only", "logical": "vPC view only", "ip": "Logical IP view only"},
    "line_style": {"speed": "Rated speed (1G, 10G, 25G, 40G, 100G)", "state": "Link state (confirmed, one end, conflict)"},
}


def settings_text(settings: dict[str, Any], summary: dict[str, Any] | None = None) -> str:
    """The options of one run as plain text (run-settings.txt): what was on the page, so a result can be reproduced and discussed without a screenshot."""
    summary = summary or {}
    lines = [f"Keystone Topology Builder {settings.get('tool_version', '')} - run settings".replace("  ", " "),
             f"Created: {settings.get('created', '')} (local time of the computer running Keystone)",
             f"Topology name: {settings.get('name') or '(not given)'}",
             f"Devices captured: {summary.get('captured', '')}   Seen by neighbors only: {summary.get('seen_only', '')}   Links: {summary.get('links', '')}   Findings: {summary.get('findings', '')}",
             "", "Options (on = checked on the page)"]
    for key, label in SETTING_LABELS:
        lines.append(f"  [{'on ' if settings.get(key) else 'off'}] {label}")
    lines.append("")
    for key, title in (("group", "Grouping"), ("view", "Diagram file contains"), ("line_style", "Style lines by")):
        lines.append(f"{title}: {CHOICE_LABELS[key].get(settings.get(key), settings.get(key, ''))}")
    lines.append(f"Add to a previous run: {'yes' if settings.get('previous_state') else 'no'}")
    lines.append(f"Keep my layout: {'yes' if settings.get('keep_layout') else 'no'}")
    return "\r\n".join(lines) + "\r\n"


def safe_name(text: str) -> str:
    """A topology name made safe for a file name: spaces become '-', anything but letters, digits, '.', '_' and '-' is dropped, 60 characters at most."""
    cleaned = re.sub(r"-{2,}", "-", re.sub(r"[^A-Za-z0-9._-]+", "", re.sub(r"\s+", "-", (text or "").strip())))
    return cleaned.strip(".-_")[:60]


def download_name(name: str, topology_name: str) -> str:
    """'links.csv' -> 'Panin-DC-links.csv' when the engineer named the topology, unchanged otherwise."""
    return f"{topology_name}-{name}" if topology_name else name


def make_pack(files: dict[str, bytes | str]) -> bytes:
    """ZIP of exports and the report. Names are fixed or slugged here; nothing from a capture becomes a path."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(f"keystone-topology-pack/{name}", content if isinstance(content, bytes) else content.encode("utf-8"))
    return buffer.getvalue()
