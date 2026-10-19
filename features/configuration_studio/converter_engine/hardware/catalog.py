"""Public lookups over the switch and router catalogs: detection, target choices and the data the UI shows."""

from __future__ import annotations

import re

from .models import HardwareModel, PortGroup, UplinkModule
from .routers import ROUTER_MODELS
from .switches import SWITCH_MODELS, UPLINK_MODULES

ALL_MODELS: tuple[HardwareModel, ...] = SWITCH_MODELS + ROUTER_MODELS
_BY_KEY = {m.key.upper(): m for m in ALL_MODELS}

_AUTHORITATIVE_PREFIX = re.compile(r"(?:PID:\s*|MODEL NUMBER\s*:\s*|^CISCO\s+|^\*?\s*\d+\s+\d+\s+|;\s*)$")
# "Platform: cisco WS-C2960X-24TS-L," in `show cdp neighbors detail` names the NEIGHBOUR, never the switch the capture was taken on.
_NEIGHBOUR_PREFIX = re.compile(r"PLATFORM:\s*(?:CISCO\s+)?$")
_MODULE_RE = re.compile(r"(?<![A-Z0-9])(C9300X?-NM-[0-9A-Z]+)(?![A-Z0-9])")


def get_model(key: str | None) -> HardwareModel | None:
    return _BY_KEY.get(str(key or "").strip().upper())


def _token_regex(token: str) -> re.Pattern[str]:
    return re.compile(r"(?<![A-Z0-9\-])" + re.escape(token.upper()) + r"(?![A-Z0-9])")


_DETECTORS = [(model, [_token_regex(token) for token in model.all_keys()]) for model in ALL_MODELS]


def detect_model(text: str, kind: str = "switch", vendor: str = "") -> tuple[HardwareModel | None, list[HardwareModel]]:
    """Return ``(best, others)``: the model named most often in ``text`` and any other catalog models seen about as often.

    Inventory output (``show inventory``, ``show version``) names the chassis several times per stack member, so a count is a good
    tie-break for a stack built with a spare of another type.  Lines that state the chassis outright (``PID:``, ``Model Number``,
    ``cisco <model> (...) processor``) weigh more than a neighbour table or a description that merely mentions another model.
    ``vendor`` (when the source vendor is known) limits the search to that vendor's models.
    """
    sample = (text or "")[:6_000_000].upper()
    scored: list[tuple[int, int, HardwareModel]] = []
    for model, patterns in _DETECTORS:
        if model.kind != kind:
            continue
        if vendor and model.vendor.lower() != vendor.lower():
            continue          # a Catalyst named in an Aruba file's neighbour table is not the Aruba switch itself
        weight = 0
        first = len(sample) + 1
        for pattern in patterns:
            for found in pattern.finditer(sample):
                first = min(first, found.start())
                line_start = sample.rfind("\n", 0, found.start()) + 1
                prefix = sample[line_start:found.start()]
                if _NEIGHBOUR_PREFIX.search(prefix):
                    continue
                authoritative = bool(_AUTHORITATIVE_PREFIX.search(prefix))
                weight += 5 if authoritative else 1
        if weight:
            scored.append((-weight, first, model))
    scored.sort(key=lambda row: (row[0], row[1]))
    if not scored:
        return None, []
    top = -scored[0][0]
    return scored[0][2], [row[2] for row in scored[1:] if -row[0] * 2 >= top]


def detect_modules(text: str, model: HardwareModel) -> list[UplinkModule]:
    found: list[UplinkModule] = []
    for key in dict.fromkeys(_MODULE_RE.findall((text or "")[:6_000_000].upper())):
        module = UPLINK_MODULES.get(key)
        if module and key in model.modules:
            found.append(module)
    return found


def split_target_key(value: str | None) -> tuple[str, str]:
    """``"C9300-48P+C9300-NM-8X"`` -> ``("C9300-48P", "C9300-NM-8X")``."""
    base, _, module = str(value or "").strip().partition("+")
    return base.strip(), module.strip()


def _switch_target_label(model: HardwareModel, module: UplinkModule | None) -> str:
    if module is None:
        return model.label
    head = model.label.split(" (")[0]
    front = model.label.split("(", 1)[1].split(" + uplink module")[0]
    return f"{head} + {module.key} ({front} + {module.ports}x {module.speed if module.speed != 'mGig' else 'mGig'} module)"


def target_models(vendor: str) -> list[dict[str, str]]:
    """Target Model dropdown entries for Cisco and Aruba switches (Huawei keeps its own list in the Huawei translator)."""
    wanted = str(vendor or "").strip().lower()
    rows: list[dict[str, str]] = []
    for model in SWITCH_MODELS:
        if not model.target_ok or model.vendor.lower() != wanted:
            continue
        if model.modules:
            ordered = sorted(model.modules, key=lambda key: key != model.default_module)
            for key in ordered:
                module = UPLINK_MODULES[key]
                rows.append({"model": f"{model.key}+{key}", "label": _switch_target_label(model, module)})
        else:
            rows.append({"model": model.key, "label": model.label})
    return rows


def _group_view(group: PortGroup) -> dict[str, object]:
    return {
        "role": group.role,
        "pattern": group.prefix + group.range_label(),
        "count": group.count,
        "speed": group.speed,
        "medium": group.medium,
        "poe": group.poe,
        "also_named": list(group.aliases),
        "note": group.note,
    }


def catalog_view(kind: str) -> list[dict[str, object]]:
    """JSON-ready catalog for the Convert pages."""
    rows = []
    for model in ALL_MODELS:
        if model.kind != kind:
            continue
        rows.append(
            {
                "key": model.key,
                "vendor": model.vendor,
                "platform": model.platform,
                "os": model.os_name,
                "label": model.label,
                "summary": model.summary,
                "groups": [_group_view(g) for g in model.groups],
                "modules": [
                    {"key": k, "label": UPLINK_MODULES[k].label, "default": k == model.default_module, **{"ports": UPLINK_MODULES[k].ports}}
                    for k in model.modules
                ],
                "slots": [{"name": s.name, "naming": s.naming, "accepts": s.accepts, "observed": s.observed} for s in model.slots],
                "max_members": model.max_members,
                "doc_title": model.doc_title,
                "doc_url": model.doc_url,
                "target_ok": model.target_ok,
                "samples": list(model.samples),
                "notes": list(model.notes),
            }
        )
    return rows


# Product lines for the catalog tree: vendor -> product line (+ OS) -> series -> model.  The platform text is "<line> <series>"
# ("Catalyst 9300X", "Nexus 9300", "CloudEngine S5735-S-V2", "CX 6200F"); "3800 ISR" is the one catalog entry written the other way round.
_LINE_OVERRIDES = {"3800 ISR": ("ISR", "3800")}


def split_platform(platform: str) -> tuple[str, str]:
    """``'Catalyst 9300X'`` -> ``('Catalyst', '9300X')``; a platform of one word is its own line and series."""
    text = str(platform or "").strip()
    if text in _LINE_OVERRIDES:
        return _LINE_OVERRIDES[text]
    line, _, series = text.partition(" ")
    return line, series or line


def catalog_tree(kind: str) -> list[dict[str, object]]:
    """The catalog as a tree for the Convert pages: vendors, their product lines (Catalyst, Nexus, CloudEngine, CX ...) with the
    operating system of each line, the series inside a line, and the models of a series.  Order of first appearance in the catalog."""
    vendors: dict[str, dict[str, object]] = {}
    for row in catalog_view(kind):
        line_name, series_name = split_platform(str(row["platform"]))
        vendor = vendors.setdefault(str(row["vendor"]), {"name": row["vendor"], "count": 0, "lines": {}})
        line = vendor["lines"].setdefault((line_name, row["os"]), {"name": line_name, "os": row["os"], "count": 0, "series": {}})
        series = line["series"].setdefault(series_name, {"name": row["platform"], "short": series_name, "models": []})
        series["models"].append(row)
        line["count"] += 1
        vendor["count"] += 1
    return [
        {
            "name": v["name"],
            "count": v["count"],
            "lines": [
                {"name": l["name"], "os": l["os"], "count": l["count"], "series": list(l["series"].values())}
                for l in v["lines"].values()
            ],
        }
        for v in vendors.values()
    ]
