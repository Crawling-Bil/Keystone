from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .converter_engine.engine import MigrationEngine

BASE_DIR = Path(__file__).resolve().parent
MAPPINGS_DIR = BASE_DIR / "mappings"
INVENTORY_FILE = MAPPINGS_DIR / "migration_inventory.csv"


def create_engine() -> MigrationEngine:
    return MigrationEngine(inventory_file=INVENTORY_FILE)


def supported_platforms() -> dict[str, list[dict[str, str]]]:
    """Return only registries that contain an actual parser/translator class."""
    engine = create_engine()
    sources: list[dict[str, str]] = []
    targets: list[dict[str, str]] = []

    for (device_type, vendor), (module_path, class_name) in engine.parser_registry.items():
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
) -> dict[str, Any]:
    engine = create_engine()
    detection = engine.detect(source_path)

    resolved_vendor = detection.vendor if str(source_vendor).lower().startswith("auto") else source_vendor
    resolved_device_type = detection.device_type if str(source_device_type).lower().startswith("auto") else source_device_type

    if str(resolved_vendor).lower() == "unknown" or str(resolved_device_type).lower() == "unknown":
        raise ValueError("Vendor atau device type tidak dapat dideteksi. Pilih vendor dan device type secara manual.")

    resolved_target_type = target_device_type or resolved_device_type
    config, output_lines = engine.convert(
        filename=source_path,
        source_vendor=resolved_vendor,
        source_device_type=resolved_device_type,
        target_vendor=target_vendor,
        target_device_type=resolved_target_type,
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
        "confidence": getattr(detection, "confidence", ""),
        "inventory": inventory,
        "review_count": review_count,
        "source_lines": len(source_text.splitlines()),
        "output_lines": len(output_text.splitlines()),
        "download_name": f"{safe_name(hostname)}_{safe_name(target_vendor)}.cfg",
    }
