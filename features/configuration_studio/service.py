from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .converter_engine.domains import DOMAINS, classify, get_domain
from .converter_engine.engine import MigrationEngine
from .converter_engine.profiles import PROFILE_REGISTRY
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
    purely additive, used only to flag a real port-count mismatch on a
    physical interface (see HuaweiSwitchTranslator's own
    resolve_target_ge_port_count docstring, and
    PaloAltoFirewallTranslator.resolve_target_ethernet_port_count's
    equivalent). An empty selection is always valid; this never blocks
    a conversion, it only adds an extra safety check when the model is
    known. Huawei and Palo Alto have confirmed model data; other
    target vendors return an empty list until this project has
    equivalent confirmed model data for them too.
    """
    vendor = str(target_vendor or "").strip().lower()
    if vendor == "huawei":
        return list(HUAWEI_TARGET_MODELS)
    if vendor == "palo alto":
        return list(PALOALTO_TARGET_MODELS)
    return []


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
            raise ValueError("Vendor atau device type tidak dapat dideteksi. Pilih vendor dan device type secara manual.")
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


def convert_file(
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
) -> dict[str, Any]:
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
    )

    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    output_text = "\n".join(str(line) for line in output_lines).rstrip() + "\n"
    hostname = str(getattr(config, "hostname", "") or source_path.stem)
    inventory = engine.inventory.get(hostname) or {}
    review_count = sum(1 for line in output_lines if "REVIEW" in str(line).upper())

    return {
        "source_text": source_text,
        "output_text": output_text,
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
        "source_lines": len(source_text.splitlines()),
        "output_lines": len(output_text.splitlines()),
        "download_name": f"{safe_name(hostname)}_{safe_name(target_vendor)}.cfg",
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
