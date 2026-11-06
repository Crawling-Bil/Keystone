from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .converter_engine.domains import DOMAINS, classify, get_domain
from .converter_engine.hardware.catalog import catalog_tree, catalog_view, target_models as catalog_target_models
from .converter_engine.engine import MigrationEngine
from .converter_engine.secret_mask import count_secret_lines, hide_secrets as hide_credentials
from .converter_engine.preflight import build_preflight
from .converter_engine.roundtrip import check_conversion
from .converter_engine.profiles import PROFILE_REGISTRY
from .converter_engine.session_capture import prepared as prepared_source
from .converter_engine.translators.switch.huawei import HUAWEI_TARGET_MODELS
from .converter_engine.translators.firewall.paloalto import PALOALTO_TARGET_MODELS

BASE_DIR = Path(__file__).resolve().parent
MAPPINGS_DIR = BASE_DIR / "mappings"
INVENTORY_FILE = MAPPINGS_DIR / "migration_inventory.csv"


def create_engine() -> MigrationEngine:
    return MigrationEngine(inventory_file=INVENTORY_FILE)


def available_profiles() -> list[dict[str, str]]:
    """
    Organizational config profiles available to apply on top of the
    generic conversion (see converter_engine/profiles/). Empty/omitted
    profile = fully generic output, unaffected by any project's
    standard — this list is additive, not a replacement for that
    default.
    """
    return [
        {"key": key, "name": profile.name, "description": profile.description}
        for key, profile in PROFILE_REGISTRY.items()
    ]


def available_target_models(target_vendor: str = "Huawei") -> list[dict[str, str]]:
    """
    Optional "Target Model" choices for the given target vendor —
    purely additive. For switches the choice drives the interface map
    (every source port -> a port that really exists on the chosen model,
    see converter_engine/hardware/); for Palo Alto it flags a real
    port-count mismatch (PaloAltoFirewallTranslator.
    resolve_target_ethernet_port_count). An empty selection is always
    valid; this never blocks a conversion. Huawei, Cisco (IOS-XE
    Catalyst, with the uplink module as part of the choice), Aruba CX
    and Palo Alto have confirmed model data; other vendors return an
    empty list.
    """
    vendor = str(target_vendor or "").strip().lower()
    if vendor == "huawei":
        return list(HUAWEI_TARGET_MODELS)
    if vendor == "palo alto":
        return list(PALOALTO_TARGET_MODELS)
    if vendor in ("cisco", "aruba"):
        return catalog_target_models(vendor)
    return []


def hardware_catalog(domain: str) -> list[dict[str, Any]]:
    """Hardware catalog rows shown on the Convert Switch and Convert Router pages."""
    if domain not in ("switch", "router"):
        return []
    return catalog_view(domain)


def hardware_tree(domain: str) -> list[dict[str, Any]]:
    """The same catalog grouped vendor -> product line / OS -> series -> model, for the collapsible tree."""
    if domain not in ("switch", "router"):
        return []
    return catalog_tree(domain)


# PaloAltoFirewallParser (models/paloalto_native.py's PaloAltoNativeConfig)
# exists for the Config Analyzer's read-only dashboard, not for
# Configuration Studio's convert flow -- no translator consumes that
# native-PAN-OS shape (PaloAltoFirewallTranslator's translate() expects
# the Mikrotik-shaped FirewallConfig instead, since Mikrotik is the
# only source that flow supports today). Excluded here so Configuration
# Studio's own Source Vendor dropdown keeps only vendors it can
# actually convert FROM; engine.parser_registry itself still carries
# it so engine.parse()/detect() work for the analyzer.
_SOURCES_WITHOUT_A_TRANSLATION_PATH = {("firewall", "palo alto")}


class DomainMismatchError(ValueError):
    """The file clearly belongs to another domain than the page it was sent to."""


class DomainUnavailableError(ValueError):
    """The domain has no registered converter yet."""


def supported_platforms(domain: str | None = None) -> dict[str, list[dict[str, str]]]:
    """Return only registries that contain an actual parser/translator class.

    With ``domain`` the lists are limited to that kind of device, which is what
    a Convert page offers; without it every domain is returned (engine-level
    callers and the analyzers use that form).
    """
    wanted = get_domain(domain).key if domain else None
    engine = create_engine()
    sources: list[dict[str, str]] = []
    targets: list[dict[str, str]] = []

    for (device_type, vendor), (module_path, class_name) in engine.parser_registry.items():
        if wanted and device_type != wanted:
            continue
        if (device_type, vendor) in _SOURCES_WITHOUT_A_TRANSLATION_PATH:
            continue
        try:
            parser_class = engine.load_class(module_path, class_name)
        except (RuntimeError, ValueError):
            continue
        if callable(getattr(parser_class, "parse_file", None)):
            sources.append({"device_type": device_type, "vendor": vendor})

    for (device_type, vendor), (module_path, class_name) in engine.translator_registry.items():
        if wanted and device_type != wanted:
            continue
        try:
            translator_class = engine.load_class(module_path, class_name)
        except (RuntimeError, ValueError):
            continue
        if callable(getattr(translator_class, "translate", None)):
            targets.append({"device_type": device_type, "vendor": vendor})

    if wanted in (None, "firewall"):
        # FortiGate <-> PAN-OS is converted by converter_engine/fwconvert (its own readers and writers, not the engine registries).
        for vendor, as_source, as_target in (("fortigate", True, True), ("palo alto", True, False)):
            entry = {"device_type": "firewall", "vendor": vendor}
            if as_source and entry not in sources:
                sources.append(entry)
            if as_target and entry not in targets:
                targets.append(entry)

    return {
        "sources": sorted(sources, key=lambda item: (item["device_type"], item["vendor"])),
        "targets": sorted(targets, key=lambda item: (item["device_type"], item["vendor"])),
    }


def domain_overview() -> list[dict[str, Any]]:
    """One entry per Convert domain, with what it can really do today.

    ``available`` needs both a source parser and a target translator in the
    registries; anything less is reported as not available rather than shown
    as a form that would fail on submit.
    """
    overview = []
    for key, spec in DOMAINS.items():
        platforms = supported_platforms(key)
        overview.append({
            "key": key,
            "label": spec.label,
            "icon": spec.icon,
            "summary": spec.summary,
            "capture": spec.capture,
            "needs": list(spec.needs),
            "analyzer_name": spec.analyzer_name,
            "analyzer_href": spec.analyzer_href,
            "href": f"/convert/{key.replace('_', '-')}",
            "sources": sorted({item["vendor"] for item in platforms["sources"]}),
            "targets": sorted({item["vendor"] for item in platforms["targets"]}),
            "available": bool(platforms["sources"] and platforms["targets"]),
        })
    return overview


def ensure_domain_available(domain: str) -> None:
    spec = get_domain(domain)
    entry = next(item for item in domain_overview() if item["key"] == spec.key)
    if not entry["available"]:
        raise DomainUnavailableError(
            f"Convert \u203a {spec.label} has no converter yet. Open {spec.analyzer_name} to read this "
            f"kind of file; a converter is added once a source parser and a target translator exist."
        )


def _resolve_source(
    engine: MigrationEngine,
    source_path: Path,
    domain: str | None,
    source_vendor: str,
    source_device_type: str,
):
    """Work out (vendor, device type, detection) for a source file.

    Without ``domain`` this is the original behaviour. With ``domain`` the page
    decides the device type, Auto Detect only picks the vendor, and a file that
    clearly belongs to another domain is refused instead of being parsed by the
    wrong parser. A vendor or type chosen by hand is trusted as given.
    """
    detection = engine.detect(source_path)
    auto_vendor = str(source_vendor).lower().startswith("auto")
    auto_type = str(source_device_type).lower().startswith("auto")

    if not domain:
        vendor = detection.vendor if auto_vendor else source_vendor
        device_type = detection.device_type if auto_type else source_device_type
        if str(vendor).lower() == "unknown" or str(device_type).lower() == "unknown":
            raise ValueError("The vendor or device type could not be detected. Choose the vendor and device type manually.")
        return vendor, device_type, detection

    spec = get_domain(domain)
    if auto_vendor and auto_type:
        guess = classify(source_path.read_text(encoding="utf-8", errors="ignore"))
        if guess.confidence == "high" and guess.domain != spec.key:
            other = DOMAINS[guess.domain]
            other_entry = next(item for item in domain_overview() if item["key"] == other.key)
            where = (
                f"Open Convert \u203a {other.label} instead."
                if other_entry["available"]
                else f"There is no {other.label.lower()} converter yet; open {other.analyzer_name} to read it."
            )
            raise DomainMismatchError(
                f"This file looks like a {other.label.lower()} configuration ({guess.vendor}), not a "
                f"{spec.label.lower()} one. {where}"
                + (f" Recognised by: {', '.join(guess.evidence)}." if guess.evidence else "")
            )

    own_names = {spec.key, spec.key.replace("_", " "), spec.label.lower()}
    if not auto_type and str(source_device_type).strip().lower() not in own_names:
        raise ValueError(f"Device type {source_device_type!r} does not belong to Convert \u203a {spec.label}.")

    device_type = spec.label if auto_type else source_device_type
    if auto_vendor:
        detected_here = str(detection.device_type).lower() in (spec.key, spec.label.lower()) or (
            spec.key == "wireless" and str(detection.device_type).lower() == "wlc"
        )
        vendor = detection.vendor if detected_here else "Unknown"
    else:
        vendor = source_vendor

    if str(vendor).lower() == "unknown":
        offered = ", ".join(sorted({v["vendor"] for v in supported_platforms(spec.key)["sources"]})) or "none yet"
        seen = f"{detection.vendor} {detection.device_type}".strip() if str(detection.vendor).lower() != "unknown" else "nothing it knows"
        raise ValueError(
            f"Keystone could not identify a {spec.label.lower()} vendor in this file (it matched {seen}). "
            f"Choose the source vendor by hand. Sources offered for {spec.label.lower()}: {offered}."
        )
    return vendor, device_type, detection


def safe_name(value: str, fallback: str = "converted-config") -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "").strip()).strip("._")
    return value or fallback


def _small_int(value: Any) -> int:
    """Form value to an int of 1 or more (blank or garbage is 1)."""
    try:
        return max(1, int(str(value).strip()))
    except (TypeError, ValueError):
        return 1


def convert_file(source_path: Path, **options: Any) -> dict[str, Any]:
    """Convert one uploaded file.  A switch file that is a whole terminal session (login banner, ``show version``, ``show running-config``) is
    reduced to its configuration block first (see ``converter_engine/session_capture.py``); the result says so under ``capture``."""
    with prepared_source(source_path, options.get("domain")) as (prepared_path, extracted):
        whole = source_path.read_text(encoding="utf-8", errors="ignore") if extracted is not None and extracted.cut else None
        result = _convert_prepared(prepared_path, identity_text=whole, **options)
    if extracted is not None and extracted.cut:
        result["capture"] = {
            "command": extracted.command,
            "total_lines": extracted.total_lines,
            "config_lines": extracted.kept_lines,
        }
    return result


def _convert_prepared(
    source_path: Path,
    *,
    source_vendor: str = "Auto Detect",
    source_device_type: str = "Auto Detect",
    target_vendor: str = "Huawei",
    target_device_type: str | None = None,
    profile_key: str | None = None,
    target_model: str | None = None,
    mapping: dict[str, Any] | None = None,
    domain: str | None = None,
    identity_text: str | None = None,
    stack_member: int | str | None = None,
    stack_members: int | str | None = None,
    layers: list[str] | None = None,
    vdom: str = "",
    disable_widened: bool = True,
    hide_secrets: bool = False,
) -> dict[str, Any]:
    if _panorama_flatten_requested(source_path, domain, source_vendor, target_vendor):
        return _convert_panorama_flatten(source_path, vdom)
    firewall_pair = _fortigate_pan_pair(source_path, domain, source_vendor, target_vendor)
    if firewall_pair is not None:
        return _convert_fortigate_pan(source_path, firewall_pair, mapping=mapping, layers=layers, vdom=vdom, disable_widened=disable_widened)

    engine = create_engine()
    resolved_vendor, resolved_device_type, detection = _resolve_source(
        engine, source_path, domain, source_vendor, source_device_type
    )

    profile = PROFILE_REGISTRY.get(profile_key) if profile_key else None

    resolved_target_type = target_device_type or resolved_device_type
    config, output_lines = engine.convert(
        filename=source_path,
        source_vendor=resolved_vendor,
        source_device_type=resolved_device_type,
        target_vendor=target_vendor,
        target_device_type=resolved_target_type,
        profile=profile,
        target_model=target_model or None,
        mapping=mapping or None,
        identity_text=identity_text,
        stack_member=_small_int(stack_member),
        stack_members=_small_int(stack_members),
    )

    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    output_text = "\n".join(str(line) for line in output_lines).rstrip() + "\n"
    secret_lines = count_secret_lines(output_text)
    hostname = str(getattr(config, "hostname", "") or source_path.stem)
    inventory = engine.inventory.get(hostname) or {}
    review_count = sum(1 for line in output_lines if "REVIEW" in str(line).upper())
    interface_map = (getattr(config, "metadata", None) or {}).get("interface_map")
    preflight = (
        build_preflight(output_text, target_vendor, (interface_map or {}).get("fit"))
        if interface_map is not None or str(resolved_device_type).strip().lower() == "switch"
        else None
    )

    roundtrip = None
    if str(resolved_device_type).strip().lower() == "switch":
        roundtrip = check_conversion(
            engine, source_path, source_vendor=resolved_vendor, target_vendor=target_vendor, output_text=output_text,
            port_map=(getattr(config, "metadata", None) or {}).get("port_map"),
        ) or None

    return {
        "source_text": source_text,
        # The checks above read the real output; only what is shown and downloaded has the credential values hidden.
        "output_text": hide_credentials(output_text, source_text) if hide_secrets else output_text,
        "hostname": hostname,
        "source_vendor": resolved_vendor,
        "source_device_type": resolved_device_type,
        "domain": domain or None,
        "target_vendor": target_vendor,
        "target_device_type": resolved_target_type,
        "target_model": target_model or None,
        "confidence": getattr(detection, "confidence", ""),
        "profile": profile.name if profile else None,
        "inventory": inventory,
        "review_count": review_count,
        "interface_map": interface_map,
        "preflight": preflight,
        "roundtrip": roundtrip,
        "stack": (getattr(config, "metadata", None) or {}).get("stack"),
        "secrets": {"lines": secret_lines, "hidden": bool(hide_secrets)},
        "source_lines": len(source_text.splitlines()),
        "output_lines": len(output_text.splitlines()),
        "download_name": f"{safe_name(hostname)}_{safe_name(target_vendor)}.cfg",
    }


_FW_VENDORS = {"fortigate": "fortigate", "fortinet": "fortigate", "palo alto": "panos", "palo alto networks": "panos", "pan-os": "panos", "panos": "panos"}
_FW_LABEL = {"fortigate": "FortiGate", "panos": "Palo Alto"}


def _fortigate_pan_pair(source_path: Path, domain: str | None, source_vendor: str, target_vendor: str) -> tuple[str, str] | None:
    """``("fortigate", "panos")`` or ``("panos", "fortigate")`` when this request is a FortiGate <-> PAN-OS conversion, else None (the engine handles it)."""
    if domain not in (None, "firewall"):
        return None
    target = _FW_VENDORS.get(str(target_vendor or "").strip().lower())
    if target is None:
        return None
    wanted = str(source_vendor or "").strip().lower()
    if wanted.startswith("auto") or not wanted:
        from .converter_engine.fwconvert.convert import detect as detect_firewall
        source = detect_firewall(source_path.read_text(encoding="utf-8", errors="ignore"))
    else:
        source = _FW_VENDORS.get(wanted, "")
    if source in ("fortigate", "panos") and source != target:
        return source, target
    if target == "fortigate":
        raise ValueError("FortiGate is a target for a PAN-OS configuration only; choose Palo Alto as the source vendor or leave it on Auto Detect.")
    return None


def _convert_fortigate_pan(
    source_path: Path,
    pair: tuple[str, str],
    *,
    mapping: dict[str, Any] | None,
    layers: list[str] | None,
    vdom: str,
    disable_widened: bool,
) -> dict[str, Any]:
    from .converter_engine.fwconvert import convert as fw_convert
    from .converter_engine.fwconvert.mask import mask_source

    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    shown = mask_source(source_text)                  # the source pane never shows the credentials of the upload (the conversion reads the real text)
    panorama = None
    if pair[0] == "panos":
        from .converter_engine.fwconvert import panorama as pano_conv
        if pano_conv.is_panorama(source_text):
            scoped = pano_conv.scope_xml(source_text, vdom)                 # the device group (or one firewall of it) becomes the XML of a standalone firewall
            source_text, vdom, panorama = scoped.xml, "", scoped.info()
    interface_map = {str(k): str(v) for k, v in mapping.items() if isinstance(v, str) and v.strip()} if isinstance(mapping, dict) else {}
    converted = fw_convert(source_text, pair[0], pair[1], layers=layers or None, interface_map=interface_map, disable_widened=disable_widened, vdom=str(vdom or "")[:64])
    if not converted.ok:
        raise ValueError(converted.error)
    hostname = str(getattr(converted.model, "hostname", "") or source_path.stem)
    counts = {status: sum(1 for item in converted.report.items if item.status == status) for status in ("converted", "approximated", "review", "not_converted")}
    output_text = converted.output
    return {
        "source_text": _display_source(shown if panorama is None else source_text),
        "output_text": output_text,
        "hostname": hostname,
        "source_vendor": _FW_LABEL[pair[0]],
        "source_device_type": "firewall",
        "domain": "firewall",
        "target_vendor": _FW_LABEL[pair[1]],
        "target_device_type": "firewall",
        "target_model": None,
        "confidence": "",
        "profile": None,
        "inventory": {},
        "review_count": counts["review"] + counts["not_converted"],
        "interface_map": None,
        "preflight": None,
        "roundtrip": None,
        "stack": None,
        "source_lines": len(source_text.splitlines()),
        "output_lines": len(output_text.splitlines()),
        "panorama": panorama,
        "download_name": f"{safe_name(hostname)}_{safe_name(_FW_LABEL[pair[1]])}.cfg",
        "fwconvert": {
            "summary": converted.report.summary(),
            "counts": counts,
            "rows": converted.report.to_rows(),
            "layers": converted.layers,
            "csv": converted.report.to_csv(),
        },
    }


_DISPLAY_LIMIT = 1_500_000


def _display_source(text: str) -> str:
    """The source pane of the page; a flattened Panorama scope can be many megabytes, which a browser text pane should not be asked to hold."""
    if len(text) <= _DISPLAY_LIMIT:
        return text
    cut = text.rfind("\n", 0, _DISPLAY_LIMIT)
    return text[: cut if cut > 0 else _DISPLAY_LIMIT] + f"\n<!-- ... {len(text) - cut:,} more characters not shown ... -->\n"


def _panorama_flatten_requested(source_path: Path, domain: str | None, source_vendor: str, target_vendor: str) -> bool:
    """A Panorama export converted to Palo Alto: the flatten conversion (one device group as the XML of a standalone firewall)."""
    if domain not in (None, "firewall") or _FW_VENDORS.get(str(target_vendor or "").strip().lower()) != "panos":
        return False
    wanted = str(source_vendor or "").strip().lower()
    if wanted and not wanted.startswith("auto") and _FW_VENDORS.get(wanted) != "panos":
        return False
    from .converter_engine.fwconvert import panorama as pano_conv
    with source_path.open("r", encoding="utf-8", errors="ignore") as handle:
        head = handle.read(2000).lstrip("\ufeff \t\r\n")
        if not head.startswith(("<?xml", "<config")):
            return False
        return pano_conv.is_panorama(head + handle.read())


def _convert_panorama_flatten(source_path: Path, scope: str) -> dict[str, Any]:
    from .converter_engine.fwconvert import panorama as pano_conv

    text = source_path.read_text(encoding="utf-8", errors="ignore")
    scoped = pano_conv.scope_xml(text, scope)
    report = pano_conv.flatten_report(scoped, text)
    counts = {status: sum(1 for item in report.items if item.status == status) for status in ("converted", "approximated", "review", "not_converted")}
    return {
        "source_text": _display_source(scoped.masked or scoped.xml),          # never the raw upload: a Panorama export holds password hashes and private keys
        "output_text": scoped.xml,
        "hostname": scoped.group,
        "source_vendor": "Palo Alto",
        "source_device_type": "Panorama",
        "domain": "firewall",
        "target_vendor": "Palo Alto",
        "target_device_type": "firewall",
        "target_model": None,
        "confidence": "",
        "profile": None,
        "inventory": {},
        "review_count": counts["review"] + counts["not_converted"],
        "interface_map": None,
        "preflight": None,
        "roundtrip": None,
        "stack": None,
        "source_lines": len(text.splitlines()),
        "output_lines": len(scoped.xml.splitlines()),
        "panorama": scoped.info(),
        "download_name": f"{safe_name(scoped.group)}_PAN-OS_flattened.xml",
        "fwconvert": {"summary": report.summary(), "counts": counts, "rows": report.to_rows(), "layers": list(report.summary()), "csv": report.to_csv()},
    }


def preview_mapping(
    source_path: Path,
    *,
    source_vendor: str = "Auto Detect",
    source_device_type: str = "Auto Detect",
    target_vendor: str = "Huawei",
    domain: str | None = None,
) -> dict[str, Any]:
    """
    Parse-only step for the "preview & edit interface/zone mapping
    before generating" flow (Configuration Studio's Mikrotik -> Palo
    Alto migration UI): runs just the source parser -- no translation
    -- and asks the target translator for its best-guess interface/zone
    mapping (see PaloAltoFirewallTranslator.build_interface_mapping_preview).
    Translators that don't support a mapping preview yet (everything
    except Palo Alto today) get `"supported": False` back rather than
    an error, so the caller can fall back to the plain one-shot
    convert flow.
    """
    if _fortigate_pan_pair(source_path, domain, source_vendor, target_vendor) is not None:
        # FortiGate <-> PAN-OS has no interface-mapping preview; the page falls back to the one-shot convert, which takes a mapping of its own.
        return {"supported": False, "source_vendor": source_vendor, "source_device_type": "firewall"}

    engine = create_engine()
    resolved_vendor, resolved_device_type, _detection = _resolve_source(
        engine, source_path, domain, source_vendor, source_device_type
    )

    config = engine.parse(
        filename=source_path,
        source_vendor=resolved_vendor,
        source_device_type=resolved_device_type,
    )

    try:
        translator = engine.get_translator(vendor=target_vendor, device_type=resolved_device_type)
    except (ValueError, RuntimeError):
        # No translator registered at all for this target -- convert()
        # itself would also fail for this combination, so this isn't a
        # preview-specific gap. Report it the same friendly way as "this
        # translator exists but has no mapping preview support yet" so
        # the UI can fall back to the plain convert flow either way,
        # rather than surfacing a raw error for what is really just an
        # unsupported target.
        return {
            "supported": False,
            "source_vendor": resolved_vendor,
            "source_device_type": resolved_device_type,
        }

    builder = getattr(translator, "build_interface_mapping_preview", None)
    if not callable(builder):
        return {
            "supported": False,
            "source_vendor": resolved_vendor,
            "source_device_type": resolved_device_type,
        }

    preview = builder(config)
    hostname = str(getattr(config, "hostname", "") or source_path.stem)
    return {
        "supported": True,
        "hostname": hostname,
        "source_vendor": resolved_vendor,
        "source_device_type": resolved_device_type,
        "target_vendor": target_vendor,
        **preview,
    }
