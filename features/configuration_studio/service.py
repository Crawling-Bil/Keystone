from __future__ import annotations

import re
from pathlib import Path
from typing import Any

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


def supported_platforms() -> dict[str, list[dict[str, str]]]:
    """Return only registries that contain an actual parser/translator class."""
    engine = create_engine()
    sources: list[dict[str, str]] = []
    targets: list[dict[str, str]] = []

    for (device_type, vendor), (module_path, class_name) in engine.parser_registry.items():
        if (device_type, vendor) in _SOURCES_WITHOUT_A_TRANSLATION_PATH:
            continue
        try:
            parser_class = engine.load_class(module_path, class_name)
        except (RuntimeError, ValueError):
            continue
        if callable(getattr(parser_class, "parse_file", None)):
            sources.append({"device_type": device_type, "vendor": vendor})

    for (device_type, vendor), (module_path, class_name) in engine.translator_registry.items():
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
) -> dict[str, Any]:
    engine = create_engine()
    detection = engine.detect(source_path)

    resolved_vendor = detection.vendor if str(source_vendor).lower().startswith("auto") else source_vendor
    resolved_device_type = detection.device_type if str(source_device_type).lower().startswith("auto") else source_device_type

    if str(resolved_vendor).lower() == "unknown" or str(resolved_device_type).lower() == "unknown":
        raise ValueError("Vendor atau device type tidak dapat dideteksi. Pilih vendor dan device type secara manual.")

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
    detection = engine.detect(source_path)

    resolved_vendor = detection.vendor if str(source_vendor).lower().startswith("auto") else source_vendor
    resolved_device_type = detection.device_type if str(source_device_type).lower().startswith("auto") else source_device_type

    if str(resolved_vendor).lower() == "unknown" or str(resolved_device_type).lower() == "unknown":
        raise ValueError("Vendor atau device type tidak dapat dideteksi. Pilih vendor dan device type secara manual.")

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
