"""Excel sheets for the analysis tabs of a switch result: Findings, Health, Trunks, Spanning Tree and Logs.

``excel_exporter.SwitchExcelExporter`` writes one sheet per data category with a Hostname column, so several devices share a
sheet. This module reads the five tabs that were missing from that workbook and hands the exporter ready-made rows:

* ``new_rows()`` returns an empty ``{sheet title: [rows]}`` collector,
* ``collect(result, hostname, rows)`` adds one device's rows to it,
* ``HEADERS`` maps each sheet title to its header row and ``GROUPS`` says in which order the exporter writes them.

A result saved by an older build (no ``health``, ``logs``, ``trunks`` or ``spanning_tree`` key) simply adds no rows. Every
value is turned into text that Excel accepts: control characters are removed (a raw terminal log carries ESC and BEL, and
openpyxl refuses them) and a cell is cut at 32,000 characters (Excel's limit is 32,767).
"""
from __future__ import annotations

from typing import Any

from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

CELL_LIMIT = 32000

HEADERS: dict[str, list[str]] = {
    "Findings": ["Hostname", "ID", "Severity", "Category", "Title", "Object", "Detail", "Recommendation", "Reference", "What It Means", "Related Detail"],
    "Health": ["Hostname", "Section", "Field", "Value"],
    "Health LACP": ["Hostname", "Port", "Group", "Partner ID", "Partner Port", "Partner State", "State", "State Flags", "Flags", "Age"],
    "Health Environment": ["Hostname", "Type", "Name", "Location", "State", "Reading", "Problem"],
    "Health Licences": ["Hostname", "Table", "Licence / Feature", "Tag", "Type", "Count", "Status", "Start", "End", "Detail"],
    "Trunks": ["Hostname", "Port", "Mode", "Encapsulation", "Status", "Port-Channel", "Native VLAN", "Allows Every VLAN", "Allowed VLANs", "Active VLANs", "Forwarding VLANs"],
    "Spanning Tree": ["Hostname", "Instance", "Protocol", "Root", "Root Priority", "Root Address", "Root Cost", "Root Port", "Bridge Priority", "Bridge Address", "Ports", "Blocking", "Broken"],
    "Spanning Tree Ports": ["Hostname", "Instance", "Interface", "Role", "State", "Cost", "Priority", "Port Number", "Type", "Inconsistent"],
    "HSRP": ["Hostname", "Interface", "Protocol", "Group", "Virtual IP", "State", "State Detail", "Priority", "Preempt", "Active Router", "Standby Router", "Hello / Hold", "Version",
             "Authentication", "Tracking", "Name", "State Changes", "Last Change", "Virtual MAC"],
    "HSRP Summary": ["Hostname", "Item", "Value"],
    "OSPF Neighbours": ["Hostname", "Process", "VRF", "Neighbor ID", "Priority", "State", "Role", "Time", "Address", "Interface"],
    "OSPF Neighbour Summary": ["Hostname", "Process", "VRF", "Interface", "Down", "Attempt", "Init", "2-Way", "ExStart", "Exchange", "Loading", "Full", "Total"],
    "OSPF Interfaces": ["Hostname", "Process", "VRF", "Interface", "ID", "Area", "Address", "Cost", "State", "Neighbours", "Status"],
    "OSPF Processes": ["Hostname", "Process", "VRF", "Router ID", "Areas", "Interfaces", "Neighbours", "Router LSAs", "Network LSAs", "Summary LSAs", "ASBR LSAs", "External LSAs", "All LSAs"],
    "OSPF LSDB": ["Hostname", "Process", "VRF", "Area", "LSA Type", "LSAs", "Advertising Routers", "Oldest Age (s)", "Older Than 40 Min"],
    "OSPF Routers": ["Hostname", "Process", "VRF", "Area", "Advertising Router", "Seen As", "Links", "Age (s)", "Sequence"],
    "Logs": ["Hostname", "Field", "Value"],
    "Log Flaps": ["Hostname", "Interface", "Down", "Up", "Admin Down", "First", "Last", "Seen As"],
    "Log Events": ["Hostname", "Time", "Area", "Message", "Severity", "Object", "Text"],
    "Log Messages": ["Hostname", "Message", "Severity", "Count", "First", "Last", "Example"],
}

# The order the exporter writes them in, and after which existing sheet each group goes.
GROUPS: dict[str, tuple[str, ...]] = {
    "front": ("Findings", "Health", "Health LACP", "Health Environment", "Health Licences"),
    "layer2": ("Trunks", "Spanning Tree", "Spanning Tree Ports"),
    "layer3": ("HSRP", "HSRP Summary", "OSPF Neighbours", "OSPF Neighbour Summary", "OSPF Interfaces", "OSPF Processes", "OSPF LSDB", "OSPF Routers"),
    "logs": ("Logs", "Log Flaps", "Log Events", "Log Messages"),
}

# Keys the Health tab shows with a spelling that title-casing would get wrong.
_LABELS = {
    "nx_os_release": "NX-OS release", "vpc_role": "vPC role", "vpc_peer": "vPC peer", "vpc_keep_alive": "vPC keep-alive", "vpc_peer_switch": "vPC peer-switch",
    "bpdu_guard_default": "BPDU Guard default", "bpdu_protection": "BPDU protection", "bridge_id": "Bridge ID", "cpu_utilisation": "CPU utilisation",
    "rom_version": "ROM version", "portfast_default": "PortFast default", "loopguard_default": "Loop Guard default", "root_bridge_for": "Root bridge for",
}


def new_rows() -> dict[str, list[list[Any]]]:
    return {title: [] for title in HEADERS}


def _text(value: Any) -> str:
    """One cell: lists become ``a, b``, ``None`` becomes empty, control characters go, and the length is capped."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(_text(item) for item in value)
    elif isinstance(value, dict):
        value = "; ".join(f"{key}: {_text(item)}" for key, item in value.items())
    text = ILLEGAL_CHARACTERS_RE.sub("", str(value))
    return text if len(text) <= CELL_LIMIT else text[:CELL_LIMIT - 1] + "…"


def _cell(value: Any) -> Any:
    """Numbers stay numbers (so they sort), everything else becomes text."""
    if isinstance(value, bool) or value is None:
        return _text(value)
    if isinstance(value, (int, float)):
        return value
    return _text(value)


def _label(key: str) -> str:
    return _LABELS.get(key) or str(key).replace("_", " ").strip().capitalize()


def _row(hostname: str, *values: Any) -> list[Any]:
    return [hostname, *[_cell(value) for value in values]]


# ------------------------------------------------------------------ findings

def _findings(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    for item in result.get("findings") or []:
        rows["Findings"].append(_row(hostname, item.get("id"), item.get("severity"), item.get("category"), item.get("title"), item.get("object"),
                                     item.get("detail"), item.get("recommendation"), item.get("reference"), item.get("meaning"),
                                     "\n".join(f"{e.get('label')}: {e.get('value')}" for e in item.get("evidence") or [])))


# ------------------------------------------------------------------ health

def _ios_environment(env: dict[str, Any]) -> list[dict[str, Any]]:
    """The Cisco IOS Health result keeps sensors, fans and power supplies apart; the other platforms send ready rows."""
    out = [{"type": "Sensor", "name": item.get("name"), "location": item.get("location"), "state": item.get("state"), "reading": item.get("reading")}
           for item in env.get("sensors") or []]
    out += [{"type": "Fan", "name": f"Fan {item.get('fan')}", "location": f"switch {item.get('switch')}", "state": item.get("state"),
             "reading": f"{item.get('speed')} rpm, {item.get('airflow')}"} for item in env.get("fans") or []]
    out += [{"type": "Power supply", "name": f"{item.get('slot')} {item.get('pid')}".strip(), "location": "", "state": item.get("status"),
             "reading": f"{item.get('watts')} W, system power {item.get('system_power')}"} for item in env.get("power_supplies") or []]
    return out


def _health(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    health = result.get("health") or {}
    if not health:
        return
    summary = rows["Health"]
    if health.get("supported") is False:
        summary.append(_row(hostname, "Scope", "Health checks", health.get("note") or "Not available for this capture."))
        return
    counts = health.get("counts") or {}
    summary.append(_row(hostname, "Scope", "Platform checked", health.get("scope")))
    summary.append(_row(hostname, "Scope", "Findings",
                        f"{sum(int(value or 0) for value in counts.values())} ({counts.get('high', 0)} high, {counts.get('medium', 0)} medium, "
                        f"{counts.get('low', 0)} low, {counts.get('info', 0)} info) - listed on the Findings sheet"))

    software, licence, stp = health.get("software") or {}, health.get("licence") or {}, health.get("stp") or {}
    software_fields = software.get("display") or {
        key: software.get(key) for key in ("uptime", "last_reload", "last_reload_reason") if software.get(key)}
    for key, value in software_fields.items():
        summary.append(_row(hostname, "Software", _label(key), value))
    for key in ("smart_account", "virtual_account"):
        if licence.get(key):
            summary.append(_row(hostname, "Licence", _label(key), licence[key]))

    stp_fields = stp.get("display") or ({
        "mode": stp.get("mode"), "root_bridge_for": stp.get("root_for"), "portfast_default": stp.get("portfast_default"),
        "bpdu_guard_default": stp.get("bpduguard_default"), "loopguard_default": stp.get("loopguard_default")} if stp else {})
    for key, value in stp_fields.items():
        summary.append(_row(hostname, "Spanning tree", _label(key), value))

    detail = licence.get("detail") or {}
    for item in detail.get("status") or []:
        summary.append(_row(hostname, "Licence", item.get("label"), item.get("value")))
    if detail.get("note"):
        summary.append(_row(hostname, "Licence", "Summary", detail["note"]))

    environment = health.get("environment") or {}
    env_rows = environment["rows"] if isinstance(environment.get("rows"), list) else _ios_environment(environment)
    if env_rows:
        summary.append(_row(hostname, "Environment", "Components with a problem", environment.get("problems", 0)))
    for item in health.get("capture", {}).get("missing") or []:
        summary.append(_row(hostname, "Not in this capture", item.get("command"), item.get("adds")))

    for item in health.get("lacp") or []:
        rows["Health LACP"].append(_row(hostname, item.get("port"), item.get("group"), item.get("partner_id"), item.get("partner_port"),
                                        "Healthy" if item.get("healthy") else "Not bundled", item.get("state"), item.get("state_bits"),
                                        item.get("flags"), item.get("age")))
    for item in env_rows:
        problem = item.get("problem")
        rows["Health Environment"].append(_row(hostname, item.get("type"), item.get("name"), item.get("location"), item.get("state"),
                                               item.get("reading"), "" if problem is None else ("Yes" if problem else "No")))

    licence_table = rows["Health Licences"]
    for item in licence.get("licenses") or []:
        extra = "; ".join(f"{label}: {item[key]}" for key, label in (("expiry", "expiry"), ("comments", "comments")) if item.get(key))
        licence_table.append(_row(hostname, "In use", item.get("license"), item.get("tag"), "", item.get("count"), item.get("status"), "", "", extra))
    for item in detail.get("entitlements") or []:
        extra = "; ".join(f"{label}: {item[key]}" for key, label in (("enforcement", "enforcement"), ("export_status", "export status")) if item.get(key))
        licence_table.append(_row(hostname, "Entitlement", item.get("name"), item.get("tag"), item.get("license_type"), item.get("count"), item.get("status"), "", "", extra))
    for item in detail.get("terms") or []:
        licence_table.append(_row(hostname, "Term", item.get("license"), item.get("tag"), item.get("type"), "", "", item.get("start"), item.get("end"), ""))
    for item in detail.get("rtu") or []:
        extra = "; ".join(f"{label}: {item[key]}" for key, label in (
            ("version", "version"), ("eval_left", "evaluation left"), ("eval_total", "evaluation total"), ("period_used", "period used"), ("priority", "priority")) if item.get(key))
        licence_table.append(_row(hostname, "Right-to-use", item.get("feature"), "", item.get("license_type"), "", item.get("state"), "", "", extra))


# ------------------------------------------------------------------ trunks and spanning tree

def _trunks(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    for item in (result.get("trunks") or {}).get("rows") or []:
        rows["Trunks"].append(_row(hostname, item.get("port"), item.get("mode"), item.get("encapsulation"), item.get("status"), item.get("port_channel"),
                                   item.get("native_vlan"), bool(item.get("allowed_all")), item.get("allowed"), item.get("active"), item.get("forwarding")))


def _spanning_tree(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    stp = result.get("spanning_tree") or {}
    instances = stp.get("instances") or []
    for item in instances:
        ports = item.get("ports") or []
        blocking = item["blocking"] if "blocking" in item else sum(1 for port in ports if str(port.get("state_name", "")).lower() == "blocking")
        broken = item["inconsistent"] if "inconsistent" in item else sum(1 for port in ports if port.get("broken"))
        rows["Spanning Tree"].append(_row(hostname, item.get("id"), item.get("protocol"), "this switch" if item.get("is_root") else "other bridge",
                                          item.get("root_priority"), item.get("root_address"), item.get("root_cost"), item.get("root_port"),
                                          item.get("bridge_priority"), item.get("bridge_address"), len(ports), blocking, broken))
    ports = stp.get("ports") or [port for item in instances for port in item.get("ports") or []]
    for port in ports:
        rows["Spanning Tree Ports"].append(_row(hostname, port.get("instance"), port.get("interface"), port.get("role_name") or port.get("role"),
                                                port.get("state_name") or port.get("state"), port.get("cost"), port.get("priority"), port.get("port_number"),
                                                port.get("type"), port.get("inconsistent")))


# ------------------------------------------------------------------ logs

def _level(entry: Any) -> str:
    if not entry:
        return ""
    return f"{entry.get('level', '')}" + (f" ({entry['logged']} logged)" if entry.get("logged") is not None else "")


def _logs(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    logs = result.get("logs") or {}
    if not logs.get("captured"):
        return
    settings = logs.get("settings") or {}
    duration = logs.get("duration") or {}
    hosts = [host if isinstance(host, str) else f"{host.get('host', '')}{':' + str(host['port']) if host.get('port') else ''}" for host in settings.get("hosts") or []]
    fields: list[tuple[str, Any]] = [
        ("Messages in the buffer", logs.get("message_count", 0)),
        ("Window", f"{logs['first']} -> {logs['last']}" if logs.get("first") and logs.get("last") else ""),
        ("Duration", (duration.get("text", "") + (f" ({duration['assumed']})" if duration.get("assumed") else "")) if duration.get("text")
         else "not available: the time stamps carry no date"),
        ("Order in the file", logs.get("order") or "order unknown"),
    ]
    if settings.get("buffer_bytes"):
        fields.append(("Buffer size (bytes)", settings["buffer_bytes"]))
    for label, key in (("Console level", "console"), ("Monitor level", "monitor"), ("Buffer level", "buffer"), ("Trap (syslog servers) level", "trap")):
        if settings.get(key):
            fields.append((label, _level(settings[key])))
    if settings:
        fields.append(("Syslog servers", ", ".join(hosts) or "none"))
    if logs.get("buffer_overwritten"):
        fields.append(("Buffer overwritten", f"{logs['buffer_overwritten']} older messages are gone ({logs.get('buffer_visible', 0)} still visible)"))
    if settings.get("persistent") is not None:
        fields.append(("Persistent logging", bool(settings["persistent"])))
    fields.append(("Command", logs.get("source") or ""))
    fields.append(("Format", f"{logs.get('style', '')}{' - ' + logs['validated'] if logs.get('validated') else ''}"))
    fields.append(("Messages by severity", ", ".join(f"{item.get('level')} {item.get('count')}" for item in logs.get("by_severity") or [])))
    if logs.get("note"):
        fields.append(("About this log", logs["note"]))
    for label, value in fields:
        rows["Logs"].append(_row(hostname, label, value))

    for item in logs.get("flaps") or []:
        rows["Log Flaps"].append(_row(hostname, item.get("interface"), item.get("down"), item.get("up"), item.get("admin_down"), item.get("first"), item.get("last"), item.get("kind")))
    for item in logs.get("events") or []:
        rows["Log Events"].append(_row(hostname, item.get("time"), item.get("label"), item.get("id"), item.get("severity"), item.get("object"), item.get("text")))
    for item in logs.get("top") or []:
        rows["Log Messages"].append(_row(hostname, item.get("id"), item.get("severity"), item.get("count"), item.get("first"), item.get("last"), item.get("example")))


# ------------------------------------------------------------------ first-hop redundancy and OSPF (the tables of the Routing tab)

def _routing_tables(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    tables = {table.get("id"): table.get("rows") or [] for table in result.get("extra_tables") or []}
    for item in tables.get("fhrp-groups", []):
        rows["HSRP"].append(_row(hostname, item.get("interface"), item.get("protocol"), item.get("group"), item.get("virtual_ip"), item.get("state"), item.get("state_detail"), item.get("priority"),
                                 item.get("preempt"), item.get("active"), item.get("standby"), item.get("timers"), item.get("version"), item.get("auth"), item.get("track"), item.get("name"),
                                 item.get("changes"), item.get("last_change"), item.get("vmac")))
    for item in tables.get("hsrp-summary", []):
        rows["HSRP Summary"].append(_row(hostname, item.get("metric"), item.get("value")))
    for item in tables.get("ospf-neighbors", []):
        rows["OSPF Neighbours"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("neighbor_id"), item.get("priority"), item.get("state"), item.get("role"),
                                            item.get("time"), item.get("address"), item.get("interface")))
    for item in tables.get("ospf-neighbor-summary", []):
        rows["OSPF Neighbour Summary"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("interface"), item.get("down"), item.get("attempt"), item.get("init"),
                                                   item.get("twoway"), item.get("exstart"), item.get("exchange"), item.get("loading"), item.get("full"), item.get("total")))
    for item in tables.get("ospf-interfaces", []):
        rows["OSPF Interfaces"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("interface"), item.get("id"), item.get("area"), item.get("address"), item.get("cost"),
                                            item.get("state"), item.get("neighbors"), item.get("status")))
    for item in tables.get("ospf-overview", []):
        rows["OSPF Processes"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("router_id"), item.get("areas"), item.get("interfaces"), item.get("neighbors"),
                                           item.get("router"), item.get("network"), item.get("summary"), item.get("asbr"), item.get("external"), item.get("total")))
    for item in tables.get("ospf-lsdb", []):
        rows["OSPF LSDB"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("area"), item.get("type"), item.get("count"), item.get("advs"), item.get("oldest"), item.get("stale")))
    for item in tables.get("ospf-routers", []):
        rows["OSPF Routers"].append(_row(hostname, item.get("process"), item.get("vrf"), item.get("area"), item.get("router"), item.get("seen"), item.get("links"), item.get("age"), item.get("seq")))


def collect(result: dict[str, Any], hostname: str, rows: dict[str, list[list[Any]]]) -> None:
    """Add one device's Findings, Health, Trunks, Spanning Tree, HSRP / OSPF and Logs rows to the collector."""
    _findings(result, hostname, rows)
    _health(result, hostname, rows)
    _trunks(result, hostname, rows)
    _spanning_tree(result, hostname, rows)
    _routing_tables(result, hostname, rows)
    _logs(result, hostname, rows)
