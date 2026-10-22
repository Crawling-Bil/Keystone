"""LLD Index: inventory + configs + project form -> Index workbook."""

from __future__ import annotations

import io
import re
import time
import uuid
import zipfile
from pathlib import Path
from typing import Any

from . import builder, workbook
from .datasets import analyze_device
from .inventory import TECH_LABELS, TECHNOLOGIES, build_devices

CONFIG_EXTENSIONS = {".txt", ".cfg", ".conf", ".config", ".log", ".rsc", ".out", ".cap", ".xml"}
MAX_CONFIG_BYTES = 20 * 1024 * 1024
MAX_FILES = 300
EXPORT_TTL = 24 * 3600


def _decode(data: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-16", "latin-1"):
        try:
            text = data.decode(encoding)
            if encoding == "utf-16" and "\x00" in text:
                continue
            return text
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="ignore")


def read_config_uploads(uploads: list[tuple[str, bytes]]) -> dict[str, str]:
    """{file name: text}; ZIP archives are unpacked (text files only)."""
    files: dict[str, str] = {}
    for name, data in uploads:
        if len(files) >= MAX_FILES:
            break
        base = Path(name).name
        if base.lower().endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for info in archive.infolist():
                    member = Path(info.filename).name
                    if info.is_dir() or not member or member.startswith(".") or "__MACOSX" in info.filename:
                        continue
                    if Path(member).suffix.lower() not in CONFIG_EXTENSIONS or info.file_size > MAX_CONFIG_BYTES:
                        continue
                    files[member] = _decode(archive.read(info))
                    if len(files) >= MAX_FILES:
                        break
            continue
        if Path(base).suffix.lower() in CONFIG_EXTENSIONS and len(data) <= MAX_CONFIG_BYTES:
            files[base] = _decode(data)
    return files


def _clean_project(project: dict) -> dict:
    keys = ("customer", "project_name", "project_code", "company", "goals", "scope", "out_of_scope", "related_documents")
    out = {k: str(project.get(k) or "").strip()[:4000] for k in keys}
    out["company"] = out["company"] or "Multipolar Technology"
    return out


def build_index(project: dict, records: list[dict], technologies: list[str], files: dict[str, str]) -> dict[str, Any]:
    technologies = [t for t in TECHNOLOGIES if t in set(technologies or [])]
    if not technologies:
        raise ValueError("Pick at least one technology.")
    if not records:
        raise ValueError("Add at least one device to the inventory.")
    project = _clean_project(project)
    project["technologies"] = technologies
    devices = build_devices(records, files)
    datasets = {d.hostname: analyze_device(d) for d in devices}
    nodes = builder.build(project, devices, datasets, technologies)
    data = workbook.write(nodes, project)

    numbers = workbook._numbers(nodes)
    def block(n):
        return {"kind": n.kind, "rows": len(n.rows) if n.kind == "table" else 0,
                "placeholder": n.placeholder or n.kind == "image", "source": n.source}
    tree = [{"no": no, "title": n.title, "level": n.level, **block(n), "more": [block(m) for m in n.more]}
            for no, n in zip(numbers, nodes)]
    used_files = {d.config_name for d in devices if d.config_name}
    device_rows = []
    for device in devices:
        dataset = datasets.get(device.hostname)
        row = device.public()
        row["technology_label"] = TECH_LABELS.get(device.technology, "")
        row["in_scope"] = device.technology in technologies or (device.technology == "switch" and "wireless" in technologies)
        row["analyzed"] = bool(dataset and dataset.analyzed)
        row["notes"] = list(device.notes) + list(dataset.notes if dataset else [])
        if not row["in_scope"] and device.technology:
            row["notes"].append(f"{TECH_LABELS.get(device.technology)} is not selected; only in the common chapters.")
        device_rows.append(row)
    stats = {
        "chapters": sum(1 for n in nodes if n.level == 1),
        "headings": len(nodes),
        "tables": sum(1 for n in nodes for b in [n, *n.more] if b.kind == "table"),
        "from_config": sum(1 for n in nodes if n.kind == "table" and n.source == "config" and not n.placeholder),
        "to_fill": sum(1 for n in nodes if n.placeholder or n.kind == "image"),
        "devices": len(devices),
        "configs_read": sum(1 for r in device_rows if r["analyzed"]),
        "unused_files": sorted(set(files) - used_files),
    }
    return {"workbook": data, "tree": tree, "devices": device_rows, "stats": stats, "project": project}


def save_export(root: Path, data: bytes) -> str:
    root.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for old in root.glob("*.xlsx"):
        try:
            if now - old.stat().st_mtime > EXPORT_TTL:
                old.unlink()
        except OSError:
            pass
    export_id = uuid.uuid4().hex
    (root / f"{export_id}.xlsx").write_bytes(data)
    return export_id


def download_name(project: dict) -> str:
    base = " ".join(x for x in (project.get("project_code"), project.get("project_name")) if x) or "Project"
    base = re.sub(r"[^A-Za-z0-9 ._-]+", "", base).strip() or "Project"
    return f"LLD Content Index - {base}.xlsx"
