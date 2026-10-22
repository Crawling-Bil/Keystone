"""Turn one device's config into named tables for the LLD templates.

Every analyzer in Keystone already reads these configs; each returns a
slightly different shape. The adapters here flatten them into one form:

    Dataset.tables = {"interfaces": [row, ...], "vlans": [...], ...}
    Dataset.facts  = {"hostname", "vendor", "model", "version", "serial"}

Table names are the analyzer's own section ids, so a template can list the
candidates for each vendor (PAN-OS "security_rules", FortiGate "policies").
An analyzer that fails on a file never stops the index: the device keeps an
empty dataset and a note.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .inventory import Device


@dataclass
class Dataset:
    tables: dict = field(default_factory=dict)
    facts: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)
    analyzed: bool = False


def _str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ", ".join(_str(v) for v in value if _str(v))
    if isinstance(value, dict):
        return ", ".join(f"{k}={_str(v)}" for k, v in value.items() if _str(v))
    return str(value).strip()


def _sections(result: dict) -> tuple[dict, dict]:
    tables, kv = {}, {}
    for section in result.get("sections") or []:
        if not isinstance(section, dict):
            continue
        if section.get("kind") == "table":
            tables[section.get("id")] = [
                {k: v for k, v in row.items() if not str(k).startswith("_")}
                for row in section.get("rows") or [] if isinstance(row, dict)
            ]
        elif section.get("kind") == "kv":
            for item in section.get("items") or section.get("rows") or []:
                if isinstance(item, dict) and item.get("label"):
                    kv[str(item["label"]).lower()] = _str(item.get("value"))
    return tables, kv


def _info(result: dict) -> dict:
    out = {}
    for item in result.get("info") or []:
        if isinstance(item, dict) and item.get("label"):
            out[str(item["label"]).lower()] = _str(item.get("value"))
    return out


def _first(mapping: dict, *keys: str) -> str:
    """Value of the first label that equals a key, else the first label
    that contains it as a whole word."""
    for key in keys:
        if mapping.get(key):
            return mapping[key]
    for key in keys:
        pattern = re.compile(r"\b" + re.escape(key) + r"\b")
        for label, value in mapping.items():
            if value and pattern.search(label):
                return value
    return ""


def _generic(result: dict) -> Dataset:
    tables, kv = _sections(result)
    info = {**kv, **_info(result)}
    facts = {
        "hostname": _str(result.get("hostname")),
        "vendor": _str(result.get("vendor")),
        "model": _first(info, "model", "platform"),
        "version": _first(info, "pan-os version", "fortios", "tmos version", "software version", "version"),
        "serial": _first(info, "serial", "serial number"),
    }
    return Dataset(tables=tables, facts=facts, analyzed=True)


def _switch(text: str, name: str) -> Dataset:
    from features.switch_analyzer import service

    result = service.analyze(text, filename=name)
    svi = {}
    for row in (result.get("l3") or {}).get("interfaces") or []:
        if row.get("vlan_id") not in (None, ""):
            svi[str(row["vlan_id"])] = row.get("address") or ""
    vlans = []
    for row in result.get("vlans") or []:
        vid = str(row.get("vlan_id") or "")
        vlans.append({"vlan_id": vid, "name": row.get("name") or "", "description": row.get("description") or row.get("name") or "",
                      "ip_address": svi.get(vid, "")})
    interfaces = []
    for row in result.get("interfaces") or []:
        mode = str(row.get("mode") or "")
        vlan = row.get("allowed_vlans") if mode == "trunk" else row.get("vlan")
        interfaces.append({
            "name": row.get("name") or "", "description": row.get("description") or "",
            "mode": mode.title() if mode else "", "vlan": _str(vlan), "ip_address": row.get("ip_address") or "",
            "status": row.get("status") or "",
        })
    l3 = result.get("l3") or {}
    routes = [{"destination": r.get("prefix") or r.get("destination") or r.get("network") or "",
               "next_hop": r.get("next_hop") or r.get("nexthop") or "", "interface": r.get("interface") or "",
               "vrf": r.get("vrf") or "", "distance": r.get("distance") or r.get("ad") or ""}
              for r in (l3.get("static_routes") or []) + (l3.get("default_routes") or []) if isinstance(r, dict)]
    port_channels = [{k: _str(v) for k, v in row.items()} for row in result.get("port_channels") or [] if isinstance(row, dict)]
    version = result.get("os_version") or {}
    serials = result.get("serials") or {}
    facts = {
        "hostname": _str(result.get("hostname")), "vendor": _str(result.get("vendor")),
        "model": _str(version.get("model")), "version": _str(version.get("os_version")),
        "serial": _str(serials.get("serial_number")),
    }
    tables = {"vlans": vlans, "interfaces": interfaces, "static_routes": routes, "port_channels": port_channels,
              "svi": [{"interface": r.get("name"), "vlan_id": _str(r.get("vlan_id")), "ip_address": r.get("address") or "",
                       "description": r.get("description") or "", "vrf": r.get("vrf") or ""}
                      for r in l3.get("interfaces") or []]}
    return Dataset(tables=tables, facts=facts, analyzed=True)


def _wireless(text: str, name: str) -> Dataset:
    from features.wireless_center import service

    result = service.analyze(text)
    data = result.get("data") or {}
    wlc = data.get("wlc") or {}
    interfaces = [{"name": r.get("name") or "", "ip_address": r.get("ip") or "", "netmask": r.get("mask") or "",
                   "vlan_id": (re.search(r"(\d+)$", r.get("name") or "") or [None, ""])[1] if r.get("name") else ""}
                  for r in data.get("interfaces") or [] if isinstance(r, dict)]
    tables = {
        "ssids": [{k: _str(v) for k, v in r.items()} for r in result.get("ssid_catalog") or []],
        "ap_groups": [{k: _str(v) for k, v in r.items()} for r in result.get("group_mapping") or []],
        "aps": [{k: _str(v) for k, v in r.items()} for r in data.get("aps") or [] if isinstance(r, dict)],
        "wlc_interfaces": interfaces,
        "local_users": [{k: _str(v) for k, v in r.items() if k != "password"} for r in data.get("local_users") or [] if isinstance(r, dict)],
    }
    facts = {"hostname": _str(wlc.get("hostname")), "vendor": _str(data.get("vendor")), "model": _str(wlc.get("model")),
             "version": _str(wlc.get("software_version")), "serial": _str(wlc.get("esn"))}
    return Dataset(tables=tables, facts=facts, analyzed=True)


def _service_for(tech: str):
    if tech == "firewall":
        from features.firewall_analyzer.service import analyze
        return lambda text, name: _generic(analyze(text, name))
    if tech == "router":
        from features.router_analyzer.service import analyze
        return lambda text, name: _generic(analyze(text, name))
    if tech == "loadbalancer":
        from features.lb_analyzer.service import analyze
        return lambda text, name: _generic(analyze(text, name))
    if tech == "switch":
        return _switch
    if tech == "wireless":
        return _wireless
    return None


def analyze_device(device: Device) -> Dataset:
    if not device.config_text:
        return Dataset()
    runner = _service_for(device.technology)
    if runner is None:
        return Dataset(notes=["No analyzer for this technology; config not read."])
    try:
        dataset = runner(device.config_text, device.config_name or f"{device.hostname}.txt")
    except Exception as exc:  # an unreadable file must not stop the index
        return Dataset(notes=[f"Config could not be read: {exc}"])
    if device.technology == "wireless" and not any(dataset.tables.values()):
        # A wireless project's switches are often listed as wireless devices.
        try:
            switch = _switch(device.config_text, device.config_name)
            if any(switch.tables.values()):
                return switch
        except Exception:
            pass
    return dataset


# ---------------------------------------------------------------- config blocks

_SECTION_MARKERS = re.compile(r"(show running-config|show run\b|display current-configuration|display current|show configuration|show config running)", re.I)


def config_blocks(text: str, limit: int = 400) -> list[dict[str, str]]:
    """Split a config into readable blocks (Configuration | Remarks): one per
    top-level stanza for indented configs, one per object path for flat
    'set' configs. Terminal prompts before the config are dropped."""
    lines = text.replace("\r", "").split("\n")
    for index, line in enumerate(lines):
        if _SECTION_MARKERS.search(line):
            lines = lines[index + 1:]
            break
    set_lines = [l for l in lines if l.startswith("set ")]
    blocks: list[dict[str, str]] = []
    if len(set_lines) > len(lines) * 0.5:
        groups: dict[str, list[str]] = {}
        wide = {"network", "rulebase", "pre-rulebase", "post-rulebase", "deviceconfig", "shared", "mgt-config", "profiles"}
        for line in set_lines:
            parts = line.split()
            if parts[1:2] == ["template"] or parts[1:2] == ["device-group"]:
                parts = parts[:1] + parts[3:] if parts[1] == "device-group" else parts[:1] + parts[5:]
            key = " ".join(parts[1:3]) if len(parts) > 2 and parts[1] in wide else (parts[1] if len(parts) > 1 else "set")
            groups.setdefault(key, []).append(line)
        for key, members in groups.items():
            blocks.append({"configuration": "\n".join(members), "remarks": key})
    else:
        current: list[str] = []
        def flush():
            body = [l for l in current if l.strip() not in ("!", "#", "")]
            if body:
                head = body[0].strip().split()
                blocks.append({"configuration": "\n".join(body), "remarks": head[0] if head else ""})
        for line in lines:
            if re.match(r"^\S.*[>#]\s*(show|display|exit|end|quit)\b", line):
                continue
            if re.match(r"^(Building configuration|Current configuration\s*:|end\s*$|return\s*$)", line.strip()):
                continue
            if line[:1] not in (" ", "\t") or line.strip() in ("!", "#"):
                flush()
                current = [line]
            else:
                current.append(line)
        flush()
    # merge consecutive one-line blocks of the same kind (vlan 10 / vlan 20 ...)
    merged: list[dict[str, str]] = []
    for block in blocks:
        if merged and block["remarks"] == merged[-1]["remarks"] and "\n" not in block["configuration"] \
                and merged[-1]["configuration"].count("\n") < 60:
            merged[-1]["configuration"] += "\n" + block["configuration"]
        else:
            merged.append(dict(block))
    return merged[:limit]
