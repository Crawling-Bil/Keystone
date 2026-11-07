"""Entry point: ``convert(text, source, target, ...)`` for FortiGate <-> PAN-OS, layer by layer, with the loss report."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .model import FwModel
from .report import Report

LAYERS = ("interfaces", "objects", "policies", "nat", "routes", "vpn")
LAYER_LABEL = {"interfaces": "Interfaces and zones", "objects": "Objects (addresses, services)", "policies": "Security policy", "nat": "NAT", "routes": "Routing", "vpn": "Site-to-site VPN"}
_NEEDS = {"policies": ("interfaces", "objects"), "nat": ("interfaces", "objects"), "vpn": ("interfaces",), "routes": ("interfaces",)}
VENDORS = ("fortigate", "panos")
MAX_CHARS = 20_000_000


@dataclass
class ConvertResult:
    ok: bool
    output: str
    report: Report
    model: FwModel | None
    source: str
    target: str
    layers: list[str]
    error: str = ""


def detect(text: str) -> str:
    """``"fortigate"``, ``"panos"`` or ``""`` from the first lines of a configuration."""
    head = text[:20000]
    if re.search(r"^\s*config (?:system|firewall|vpn|router) ", head, re.M) or "#config-version=FG" in head or "#config-version=" in head and "FG" in head[:200]:
        return "fortigate"
    stripped = head.lstrip("﻿ \t\r\n")
    if stripped.startswith("<?xml") or stripped.startswith("<config") or re.search(r"^\s*set (?:deviceconfig|network|rulebase|zone|address|service|shared|vsys|device-group|template) ", head, re.M) or re.search(r"^\s*(?:config|deviceconfig|network|rulebase|mgt-config) \{", head, re.M):
        return "panos"
    return ""


def expand_layers(layers: list[str] | None) -> tuple[list[str], list[str]]:
    chosen = [l for l in LAYERS if l in (layers or LAYERS)]
    added: list[str] = []
    for layer in list(chosen):
        for need in _NEEDS.get(layer, ()):
            if need not in chosen:
                chosen.append(need)
                added.append(f"{LAYER_LABEL[need]} (needed by {LAYER_LABEL[layer]})")
    return [l for l in LAYERS if l in chosen], added


def convert(text: str, source: str, target: str, layers: list[str] | None = None, interface_map: dict[str, str] | None = None,
            disable_widened: bool = True, vdom: str = "") -> ConvertResult:
    source, target = (source or "").lower(), (target or "").lower()
    report = Report()
    chosen, added = expand_layers(layers)
    if source == "auto" or not source:
        source = detect(text)
    if source not in VENDORS or target not in VENDORS or source == target:
        return ConvertResult(False, "", report, None, source, target, chosen, "Choose FortiGate or PAN-OS as the source and the other one as the target.")
    if not text.strip():
        return ConvertResult(False, "", report, None, source, target, chosen, "The configuration is empty.")
    for note in added:
        report.add("interfaces", "layer", note, "approximated", "Added to the conversion because the layers you chose cannot be written without it.")
    if len(text) > MAX_CHARS:
        return ConvertResult(False, "", report, None, source, target, chosen, f"The configuration is larger than {MAX_CHARS // 1_000_000} MB; split it or remove the logs and certificates first.")
    try:
        if source == "fortigate":
            from .forti_read import read
            from .pan_write import PanWriter
            model = read(text, report, vdom)
            lines = PanWriter(model, report, interface_map, disable_widened, set(chosen)).write()
        else:
            from .forti_write import FortiWriter
            from .pan_read import read
            model = read(text, report)
            lines = FortiWriter(model, report, interface_map, disable_widened, set(chosen)).write()
    except (ValueError, ET.ParseError) as exc:
        return ConvertResult(False, "", report, None, source, target, chosen, f"The configuration could not be read: {exc}")
    return ConvertResult(True, "\n".join(lines) + "\n", report, model, source, target, chosen)
