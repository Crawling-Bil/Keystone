"""Expand the chapter templates into Index rows and data sheets.

A template node (templates/*.json) looks like:

    {
      "title": "VLAN and IP Addressing",      # {site} {hostname} {model} {vendor} {customer} {project}
      "type": "table",                        # group (default) | paragraph | table | image
      "repeat": "site",                       # site | device | model: one copy per item in scope
      "devices": {"tech": ["switch"], "role": "core|access"},   # narrow the scope first
      "inline_single": true,                  # repeat=device with one device: no heading level for it
      "optional": true,                       # drop when there is no data (tables) / no children (groups)
      "table": {"builder": "device", "tables": ["vlans"], "columns": [["VLAN ID", "vlan_id"]]},
      "caption": "VLAN {hostname}",
      "children": [ ... ]
    }

Table builders: device, inventory, boq, allocation, models_spec, mgmt_ip,
software, config, uat, static. A table with no rows becomes one "TBD" row
(the importer drops a table without rows) unless the node is optional, in
which case the whole heading is dropped. A group whose children were all
dropped is dropped too.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from . import narrative
from .datasets import Dataset, config_blocks
from .inventory import Device, TECH_LABELS

TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
PLACEHOLDER = "TBD"
RACK_DEVICE_FILL = "DDEBF7"   # light blue: a device in the rack
RACK_UNIT_FILL = "F2F2F2"     # light grey: the U number columns


@dataclass
class Node:
    title: str
    level: int
    kind: str = "group"                 # group | paragraph | table | image
    paragraphs: list = field(default_factory=list)
    headers: list = field(default_factory=list)
    rows: list = field(default_factory=list)
    caption: str = ""
    sheet_hint: str = ""
    placeholder: bool = False           # table/paragraph has no real data yet
    source: str = ""                    # where the content came from, for the preview
    more: list = field(default_factory=list)  # extra content blocks under the same heading (Node, title "")
    merges: list = field(default_factory=list)  # [data_row, col, n_rows, n_cols], 0-based over the data rows
    fills: list = field(default_factory=list)   # [data_row, col, "RRGGBB"], 0-based over the data rows
    center: bool = False                         # centre every data cell (rack layout)


@dataclass
class Scope:
    devices: list
    site: str = ""
    device: Optional[Device] = None
    model: str = ""
    tech: str = ""
    rack: str = ""


def load_template(name: str) -> dict:
    path = TEMPLATE_DIR / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def available_templates() -> list[dict]:
    out = []
    for path in sorted(TEMPLATE_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("technology"):
            out.append({"key": data["technology"], "label": data.get("label") or data["technology"],
                        "summary": data.get("summary", ""), "based_on": data.get("based_on", "")})
    order = ["switch", "wireless", "firewall", "router", "loadbalancer"]
    return sorted(out, key=lambda t: order.index(t["key"]) if t["key"] in order else 99)


# ---------------------------------------------------------------- helpers

class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def _fmt(text: str, values: dict) -> str:
    try:
        return str(text).format_map(_SafeDict(values))
    except (ValueError, IndexError):
        return str(text)


def _catalog(model: str):
    try:
        from features.configuration_studio.converter_engine.hardware.catalog import get_model

        return get_model(model)
    except Exception:
        return None


def _vendor_of(model: str, devices: list, datasets: dict) -> str:
    hw = _catalog(model)
    if hw is not None:
        return hw.vendor
    for device in devices:
        if device.model == model:
            vendor = (datasets.get(device.hostname) or Dataset()).facts.get("vendor", "")
            if vendor:
                return vendor.replace(" Networks", "").replace("Palo Alto", "Palo Alto")
    upper = model.upper()
    for prefix, vendor in (("PA-", "Palo Alto"), ("FG", "Fortinet"), ("S57", "Huawei"), ("S67", "Huawei"), ("S5", "Huawei"),
                           ("CE", "Huawei"), ("AIRENGINE", "Huawei"), ("C9", "Cisco"), ("WS-C", "Cisco"), ("ISR", "Cisco"),
                           ("ASR", "Cisco"), ("C8", "Cisco"), ("N9K", "Cisco"), ("JL", "Aruba"), ("BIG-IP", "F5")):
        if upper.startswith(prefix):
            return vendor
    return ""


def _values(project: dict, scope: Scope, datasets: dict) -> dict:
    values = {
        "customer": project.get("customer") or "the customer",
        "project": project.get("project_name") or "this project",
        "company": project.get("company") or "Multipolar Technology",
        "site": scope.site, "model": scope.model, "tech": TECH_LABELS.get(scope.tech, scope.tech),
        "vendor": _vendor_of(scope.model, scope.devices, datasets) if scope.model else "",
    }
    if scope.rack:
        values["rack"] = scope.rack
        sizes = [d.rack_size for d in scope.devices if d.rack == scope.rack]
        values["rack_size"] = f"{max(sizes)}U" if sizes else ""
    if scope.device is not None:
        values.update({"hostname": scope.device.hostname, "role": scope.device.role, "site": scope.device.site,
                       "model": scope.device.model or scope.model})
    return values


def _filter(devices: list, spec: Optional[dict]) -> list:
    if not spec:
        return list(devices)
    if "rack" in spec:
        placed = [d for d in devices if d.rack and d.u is not None]
        if spec["rack"] is False:
            # only when nothing in scope has a rack position (image fallback)
            return [] if placed else list(devices)
        devices = placed
    techs = spec.get("tech")
    role = spec.get("role")
    exclude = spec.get("exclude_role")
    out = []
    for device in devices:
        if techs and device.technology not in techs:
            continue
        if role and not re.search(role, device.role or "", re.I):
            continue
        if exclude and re.search(exclude, device.role or "", re.I):
            continue
        out.append(device)
    return out


def _pick(row: dict, keys: str) -> str:
    for key in keys.split("|"):
        key = key.strip()
        if key in row and row[key] not in (None, "", []):
            value = row[key]
            if isinstance(value, (list, tuple)):
                return ", ".join(str(v) for v in value)
            if isinstance(value, bool):
                return "Yes" if value else "No"
            return str(value)
    return ""


def _sites(devices: list) -> list[str]:
    return list(dict.fromkeys(d.site for d in devices))


def _models(devices: list) -> list[str]:
    return list(dict.fromkeys(d.model for d in devices if d.model))


# ---------------------------------------------------------------- table builders

def _device_rows(spec: dict, scope: Scope, datasets: dict) -> tuple[list, list, bool]:
    columns = spec.get("columns") or []
    devices = [scope.device] if scope.device is not None else scope.devices
    with_host = scope.device is None and len(devices) > 1 and spec.get("hostname_column", True)
    headers = (["Hostname"] if with_host else []) + [c[0] for c in columns]
    rows, any_config = [], False
    for device in devices:
        dataset = datasets.get(device.hostname) or Dataset()
        any_config = any_config or dataset.analyzed
        for name in spec.get("tables") or []:
            table = dataset.tables.get(name)
            if table:
                keys = [c[1] for c in columns]
                require = spec.get("require_any") or []
                for record in table:
                    values = [_pick(record, c[1]) for c in columns]
                    if require and not any(_pick(record, k) for k in require):
                        continue
                    if not any(values):
                        continue
                    rows.append(([device.hostname] if with_host else []) + values)
                break
    return headers, rows, any_config


def _inventory_rows(spec: dict, scope: Scope, datasets: dict) -> tuple[list, list]:
    columns = spec.get("columns") or [["Hostname", "hostname"], ["Model", "model"], ["Site", "site"]]
    rows = []
    for device in scope.devices:
        facts = (datasets.get(device.hostname) or Dataset()).facts
        record = {"site": device.site, "hostname": device.hostname, "model": device.model or facts.get("model", ""),
                  "role": device.role, "mgmt_ip": device.mgmt_address, "mgmt_cidr": device.mgmt_ip,
                  "netmask": device.mgmt_netmask, "serial": device.serial or facts.get("serial", ""),
                  "version": facts.get("version", ""), "vendor": facts.get("vendor", ""),
                  "technology": TECH_LABELS.get(device.technology, device.technology)}
        rows.append([_pick(record, c[1]) for c in columns])
    return [c[0] for c in columns], rows


def _mgmt_vlan(device: Device, dataset: Dataset) -> str:
    address = device.mgmt_address
    if not address:
        return ""
    for table in ("svi", "wlc_interfaces"):
        for row in dataset.tables.get(table) or []:
            if str(row.get("ip_address") or "").split("/")[0] == address:
                return str(row.get("vlan_id") or "")
    return ""


def _builder_rows(spec: dict, scope: Scope, datasets: dict, project: dict) -> tuple[list, list, str]:
    builder = spec.get("builder") or "static"
    if builder == "device":
        headers, rows, analyzed = _device_rows(spec, scope, datasets)
        return headers, rows, "config" if analyzed else "config (none uploaded)"
    if builder == "inventory":
        headers, rows = _inventory_rows(spec, scope, datasets)
        return headers, rows, "inventory"
    if builder == "boq":
        rows = []
        for model in _models(scope.devices):
            hw = _catalog(model)
            members = [d for d in scope.devices if d.model == model]
            rows.append([model, (hw.summary if hw else "") or _firewall_label(model) or PLACEHOLDER, str(len(members)),
                         ", ".join(_sites(members))])
        return ["Model", "Description", "Qty", "Site"], rows, "inventory"
    if builder == "allocation":
        roles = list(dict.fromkeys(d.role or TECH_LABELS.get(d.technology, "Device") for d in scope.devices))
        rows = []
        for site in _sites(scope.devices):
            members = [d for d in scope.devices if d.site == site]
            counts = [str(sum(1 for d in members if (d.role or TECH_LABELS.get(d.technology, "Device")) == r)) for r in roles]
            rows.append([site] + counts + [str(len(members))])
        if rows:
            total = [str(sum(int(r[i + 1]) for r in rows)) for i in range(len(roles))]
            rows.append(["Total"] + total + [str(len(scope.devices))])
        return ["Site"] + roles + ["Total"], rows, "inventory"
    if builder == "models_spec":
        return _model_spec(scope.model, scope.devices, datasets)
    if builder == "mgmt_ip":
        rows = []
        for device in scope.devices:
            dataset = datasets.get(device.hostname) or Dataset()
            rows.append([device.hostname, device.mgmt_address or PLACEHOLDER, device.mgmt_netmask,
                         _mgmt_vlan(device, dataset), device.role, device.site])
        return ["Hostname", "Management IP", "Subnetmask", "Vlan ID", "Type", "Site"], rows, "inventory + config"
    if builder == "software":
        rows = []
        for model in _models(scope.devices):
            versions = sorted({(datasets.get(d.hostname) or Dataset()).facts.get("version", "")
                               for d in scope.devices if d.model == model} - {""})
            rows.append([model, ", ".join(versions) or "-", PLACEHOLDER, ""])
        return ["Device Model", "Current Software", "Recommended Software", "Notes"], rows, "config"
    if builder == "config":
        device = scope.device
        if device is None or not device.config_text:
            return ["Configuration", "Remarks"], [], "config (none uploaded)"
        rows = [[b["configuration"], b["remarks"]] for b in config_blocks(device.config_text)]
        return ["Configuration", "Remarks"], rows, "config"
    if builder == "uat":
        tests = spec.get("tests") or {}
        rows = []
        for device in scope.devices:
            for item in tests.get(device.technology) or tests.get("default") or []:
                rows.append([device.hostname, item[0], item[1] if len(item) > 1 else "", ""])
        return ["Hostname", "Test Item", "Expected Result", "Result"], rows, "template"
    # static
    headers = spec.get("headers") or []
    rows = [[_fmt(cell, _values(project, scope, datasets)) for cell in row] for row in spec.get("rows") or []]
    return headers, rows, "template"


def _rack_rows(scope: Scope) -> tuple[list, list, list]:
    """One rack, top unit first: U | Device | U. A device taller than 1U
    is one merged cell over its units; the name sits in its top unit."""
    members = [d for d in scope.devices if d.rack == scope.rack and d.u is not None]
    if not members:
        return [], [], [], []
    size = max(d.rack_size for d in members)
    occupant: dict = {}
    for device in sorted(members, key=lambda d: (d.u, d.hostname)):
        units = range(device.u, device.u + device.u_height)
        if any(u in occupant for u in units) or device.u + device.u_height - 1 > size:
            continue  # overlap or out of the rack: reported in the device notes
        for u in units:
            occupant[u] = device
    rows, merges = [], []
    index = 0
    unit = size
    while unit >= 1:
        device = occupant.get(unit)
        if device is None:
            rows.append([str(unit), "", str(unit)])
            unit -= 1
            index += 1
            continue
        top = device.u + device.u_height - 1
        label = f"{device.hostname} ({device.model})" if device.model else device.hostname
        for u in range(top, device.u - 1, -1):
            rows.append([str(u), label if u == top else "", str(u)])
        if device.u_height > 1:
            merges.append([index, 1, device.u_height, 1])
        index += device.u_height
        unit = device.u - 1
    fills = [[r, c, RACK_UNIT_FILL] for r in range(len(rows)) for c in (0, 2)]
    fills += [[r, 1, RACK_DEVICE_FILL] for r, row in enumerate(rows) if row[1]]
    return ["U", f"{scope.rack} ({size}U)", "U"], rows, merges, fills


def _firewall_label(model: str) -> str:
    try:
        from features.configuration_studio.converter_engine.translators.firewall.paloalto import PALOALTO_TARGET_MODELS
    except Exception:
        return ""
    for entry in PALOALTO_TARGET_MODELS:
        if entry["model"].upper() == model.strip().upper():
            return entry["label"]
    return ""


def _model_spec(model: str, devices: list, datasets: dict) -> tuple[list, list, str]:
    hw = _catalog(model)
    headers = ["Item", "Specification"]
    if hw is None:
        label = _firewall_label(model)
        if label:
            return headers, [["Model", model], ["Description", label]], "hardware table (firewall converter)"
        return headers, [["Model", model], ["Description", PLACEHOLDER], ["Ports", PLACEHOLDER]], "inventory"
    rows = [["Model", hw.key], ["Platform", hw.platform], ["Software", hw.os_name], ["Description", hw.summary]]
    for group in hw.groups:
        speed = f" {group.speed}" if group.speed else ""
        medium = f" {group.medium}" if group.medium else ""
        poe = f", {group.poe}" if group.poe else ""
        rows.append([f"Ports ({group.role})", f"{group.count}x{speed}{medium}{poe}".strip()])
    if hw.max_members:
        rows.append(["Stacking", f"Up to {hw.max_members} members"])
    if hw.doc_url:
        rows.append(["Data sheet", hw.doc_url])
    return headers, rows, "hardware catalog"


# ---------------------------------------------------------------- expansion

def expand(nodes: list, scope: Scope, level: int, project: dict, datasets: dict) -> list:
    out: list = []
    for spec in nodes:
        out += _expand_node(spec, scope, level, project, datasets)
    return out


def _expand_node(spec: dict, scope: Scope, level: int, project: dict, datasets: dict) -> list:
    devices = _filter(scope.devices, spec.get("devices"))
    if spec.get("devices") and not devices:
        return []
    scope = Scope(devices=devices, site=scope.site, device=scope.device, model=scope.model, tech=scope.tech, rack=scope.rack)
    repeat = spec.get("repeat")
    if repeat:
        items = []
        if repeat == "site":
            items = [Scope(devices=[d for d in devices if d.site == s], site=s, device=None, model=scope.model, tech=scope.tech)
                     for s in _sites(devices)]
        elif repeat == "device":
            items = [Scope(devices=[d], site=d.site, device=d, model=d.model, tech=scope.tech) for d in devices]
        elif repeat == "rack":
            racks = list(dict.fromkeys(d.rack for d in devices if d.rack and d.u is not None))
            items = [Scope(devices=[d for d in devices if d.rack == r and d.u is not None], site=scope.site, device=None,
                           model=scope.model, tech=scope.tech, rack=r) for r in racks]
        elif repeat == "model":
            items = [Scope(devices=[d for d in devices if d.model == m], site=scope.site, device=None, model=m, tech=scope.tech)
                     for m in _models(devices)]
        single = repeat == "device" and spec.get("inline_single") and len(items) == 1
        body = {k: v for k, v in spec.items() if k not in ("repeat", "devices")}
        out = []
        for item in items:
            if spec.get("flatten"):
                # no heading for the item itself: its children repeat in place
                # (Before/After per site, side by side, as in the existing LLDs)
                out += expand(spec.get("children") or [], item, level, project, datasets)
            elif single:
                out += expand(spec.get("children") or [], item, level, project, datasets) if spec.get("children") \
                    else _single(body, item, level, project, datasets)
            else:
                out += _single(body, item, level, project, datasets)
        return out
    return _single(spec, scope, level, project, datasets)


def _fill(node: Node, spec: dict, scope: Scope, project: dict, datasets: dict, values: dict) -> bool:
    """Put the content of one block spec into node. False = drop it
    (optional and empty)."""
    kind = node.kind
    if kind == "paragraph":
        if spec.get("narrative"):
            node.paragraphs = narrative.paragraphs(spec["narrative"], project, scope, datasets)
            node.source = "project"
        else:
            text = spec.get("text") or []
            node.paragraphs = [_fmt(t, values) for t in (text if isinstance(text, list) else [text])]
            node.source = "template"
        node.placeholder = not any(p.strip() for p in node.paragraphs)
        if node.placeholder:
            if spec.get("optional"):
                return False
            node.paragraphs = [PLACEHOLDER]
    elif kind == "table" and (spec.get("table") or {}).get("builder") == "rack":
        node.headers, node.rows, node.merges, node.fills = _rack_rows(scope)
        node.center = True
        node.source = "inventory"
        if not node.rows:
            return False
    elif kind == "table":
        headers, rows, source = _builder_rows(spec.get("table") or {}, scope, datasets, project)
        if (spec.get("table") or {}).get("numbered", True) and headers and headers[0] != "No":
            headers = ["No"] + headers
            rows = [[str(i + 1)] + r for i, r in enumerate(rows)]
        node.headers, node.rows, node.source = headers, rows, source
        if not rows:
            if spec.get("optional"):
                return False
            node.placeholder = True
            node.rows = [[PLACEHOLDER] + [""] * (len(headers) - 1)] if headers else [[PLACEHOLDER]]
            if not headers:
                node.headers = ["Item"]
    elif kind == "image":
        node.source = "manual"
        node.placeholder = True
    return True


def _single(spec: dict, scope: Scope, level: int, project: dict, datasets: dict) -> list:
    values = _values(project, scope, datasets)
    title = _fmt(spec.get("title") or "", values).strip()
    kind = spec.get("type") or ("group" if spec.get("children") or spec.get("blocks") else "paragraph")
    node = Node(title=title, level=level, kind=kind, caption=_fmt(spec.get("caption") or "", values),
                sheet_hint=_fmt(spec.get("sheet") or title, values))
    if not _fill(node, spec, scope, project, datasets, values):
        return []
    # "blocks": more content under the same heading, written as continuation
    # rows (empty Judul Heading) that the Document Generator adds to it.
    for index, block in enumerate(spec.get("blocks") or [], start=2):
        extra = Node(title="", level=level, kind=block.get("type") or "paragraph",
                     caption=_fmt(block.get("caption") or "", values),
                     sheet_hint=_fmt(block.get("sheet") or f"{title} {index}", values))
        if _fill(extra, block, scope, project, datasets, values):
            node.more.append(extra)
    children = expand(spec.get("children") or [], scope, level + 1, project, datasets)
    if kind == "group" and (spec.get("children") or spec.get("blocks")) and not children and not node.more:
        return []
    return [node] + children


def build(project: dict, devices: list, datasets: dict, technologies: list) -> list:
    """Full tree: common chapters with each technology's chapters inserted
    where the common template has {"insert": "technology"}."""
    common = load_template("common")
    tech_nodes = []
    blocks = []
    for tech in technologies:
        template = load_template(tech)
        accepted = template.get("devices") or [tech]
        # A device goes to its own technology's chapters; another template
        # (wireless also lists switches) only takes it when that technology
        # is not selected, so nothing is written twice.
        members = [d for d in devices if d.technology == tech
                   or (d.technology in accepted and d.technology not in technologies)]
        scope = Scope(devices=members, tech=tech)
        blocks.append((tech, expand(template.get("chapters") or [], scope, 1, project, datasets)))
    titles = {}
    for tech, block in blocks:
        for node in block:
            if node.level == 1:
                titles.setdefault(node.title, set()).add(tech)
    for tech, block in blocks:
        for node in block:
            if node.level == 1 and len(titles.get(node.title, ())) > 1:
                node.title = f"{node.title} - {TECH_LABELS.get(tech, tech)}"
        tech_nodes += block
    in_scope = [d for d in devices if any(d.technology in (load_template(t).get("devices") or [t]) for t in technologies)]
    root = Scope(devices=in_scope)
    nodes: list = []
    for spec in common.get("chapters") or []:
        if spec.get("insert") == "technology":
            nodes += tech_nodes
        else:
            nodes += expand([spec], root, 1, project, datasets)
    narrative.fill_document_scope(nodes, project)
    return nodes
