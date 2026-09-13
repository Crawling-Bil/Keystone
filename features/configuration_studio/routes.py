from __future__ import annotations

import json
import re
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from flask import Blueprint, jsonify, render_template, request, send_from_directory
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from core.database import log_activity
from .service import available_profiles, available_target_models, convert_file, preview_mapping, supported_platforms

bp = Blueprint("configuration", __name__, url_prefix="/configuration")
BASE_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BASE_DIR / "uploads" / "configuration"
EXPORT_DIR = BASE_DIR / "exports" / "configuration"
BATCH_PREVIEW_DIR = EXPORT_DIR / "batch_previews"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
BATCH_PREVIEW_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_CONFIG_EXTENSIONS = {".txt", ".cfg", ".conf", ".config", ".log", ".rsc"}
MAX_BATCH_FILES = 500
MAX_CONFIG_BYTES = 20 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 250 * 1024 * 1024
SAFE_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")


def _safe_source_name(value: str, fallback: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip()
    parts = [part for part in PurePosixPath(normalized).parts if part not in {"", ".", ".."}]
    cleaned = "/".join(secure_filename(part) or "unnamed" for part in parts)
    return cleaned or fallback


def _is_config_name(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_CONFIG_EXTENSIONS


def _unique_output_name(candidate: str, used_names: set[str]) -> str:
    output_name = candidate
    stem = Path(output_name).stem
    suffix = Path(output_name).suffix or ".cfg"
    counter = 2
    while output_name.lower() in used_names:
        output_name = f"{stem}_{counter}{suffix}"
        counter += 1
    used_names.add(output_name.lower())
    return output_name


def _write_preview(batch_id: str, preview_id: str, result: dict[str, Any], source_name: str, output_name: str) -> None:
    batch_dir = BATCH_PREVIEW_DIR / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        **result,
        "source_name": source_name,
        "output_name": output_name,
        "download_url": f"/configuration/download-batch-item/{batch_id}/{preview_id}?name={output_name}",
    }
    (batch_dir / f"{preview_id}.json").write_text(json.dumps(payload), encoding="utf-8")
    (batch_dir / f"{preview_id}.cfg").write_text(result["output_text"], encoding="utf-8")


def _collect_batch_sources(uploads: list[FileStorage], temp_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    sources: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    archive_total_bytes = 0

    for upload_index, uploaded in enumerate(uploads, start=1):
        raw_name = uploaded.filename or f"upload-{upload_index}"
        display_name = _safe_source_name(raw_name, f"upload-{upload_index}")
        extension = Path(display_name).suffix.lower()

        if extension == ".zip":
            archive_path = temp_dir / f"{uuid.uuid4().hex}_{secure_filename(Path(display_name).name) or 'batch.zip'}"
            uploaded.save(archive_path)
            try:
                with zipfile.ZipFile(archive_path) as archive:
                    config_members = []
                    for member in archive.infolist():
                        if member.is_dir() or member.filename.startswith("__MACOSX/"):
                            continue
                        member_name = _safe_source_name(member.filename, "")
                        if not member_name or not _is_config_name(member_name):
                            continue
                        if member.file_size > MAX_CONFIG_BYTES:
                            errors.append({
                                "source_name": f"{display_name}/{member_name}",
                                "status": "Failed",
                                "error": "Configuration file exceeds the 20 MB batch limit.",
                            })
                            continue
                        archive_total_bytes += member.file_size
                        if archive_total_bytes > MAX_ARCHIVE_TOTAL_BYTES:
                            raise ValueError("ZIP content exceeds the 250 MB uncompressed batch limit.")
                        config_members.append((member, member_name))

                    if not config_members:
                        errors.append({
                            "source_name": display_name,
                            "status": "Failed",
                            "error": "ZIP does not contain supported configuration files.",
                        })
                        continue

                    for member, member_name in config_members:
                        if len(sources) >= MAX_BATCH_FILES:
                            raise ValueError(f"A maximum of {MAX_BATCH_FILES} configuration files can be processed in one batch.")
                        local_path = temp_dir / f"{uuid.uuid4().hex}_{secure_filename(Path(member_name).name) or 'config.cfg'}"
                        with archive.open(member) as source, local_path.open("wb") as destination:
                            destination.write(source.read(MAX_CONFIG_BYTES + 1))
                        if local_path.stat().st_size > MAX_CONFIG_BYTES:
                            local_path.unlink(missing_ok=True)
                            errors.append({
                                "source_name": f"{display_name}/{member_name}",
                                "status": "Failed",
                                "error": "Configuration file exceeds the 20 MB batch limit.",
                            })
                            continue
                        sources.append({
                            "source_name": f"{display_name}/{member_name}",
                            "path": local_path,
                        })
            except (zipfile.BadZipFile, OSError, RuntimeError, ValueError) as exc:
                errors.append({
                    "source_name": display_name,
                    "status": "Failed",
                    "error": f"{type(exc).__name__}: {exc}",
                })
            continue

        if not _is_config_name(display_name):
            errors.append({
                "source_name": display_name,
                "status": "Failed",
                "error": "Unsupported file type. Use TXT, CFG, CONF, CONFIG, LOG, or ZIP.",
            })
            continue

        if len(sources) >= MAX_BATCH_FILES:
            raise ValueError(f"A maximum of {MAX_BATCH_FILES} configuration files can be processed in one batch.")

        local_path = temp_dir / f"{uuid.uuid4().hex}_{secure_filename(Path(display_name).name) or 'config.cfg'}"
        uploaded.save(local_path)
        if local_path.stat().st_size > MAX_CONFIG_BYTES:
            local_path.unlink(missing_ok=True)
            errors.append({
                "source_name": display_name,
                "status": "Failed",
                "error": "Configuration file exceeds the 20 MB batch limit.",
            })
            continue
        sources.append({"source_name": display_name, "path": local_path})

    return sources, errors


@bp.get("")
@bp.get("/")
def index():
    return render_template(
        "configuration.html",
        active_page="configuration",
        platforms=supported_platforms(),
        profiles=available_profiles(),
        # Target Vendor defaults to Huawei (see the template's own
        # "selected" logic). Huawei and Palo Alto both have confirmed
        # target-model data now, so the "Target Model" dropdown's
        # options depend on whichever target vendor is currently
        # selected in the browser -- rendered once here as a lookup by
        # vendor (see configuration.js's updateTargetModelVisibility)
        # rather than re-fetched from the server on every vendor
        # change, since this list is small and static.
        target_models_by_vendor={
            "huawei": available_target_models("Huawei"),
            "palo alto": available_target_models("Palo Alto"),
        },
    )


@bp.post("/api/convert")
def convert():
    uploaded = request.files.get("config_file")
    config_text = request.form.get("config_text", "")
    original_name = secure_filename(uploaded.filename) if uploaded and uploaded.filename else "pasted-config.cfg"

    if uploaded and uploaded.filename:
        if not _is_config_name(original_name):
            return jsonify({"ok": False, "error": "Unsupported configuration file type."}), 400
        token = uuid.uuid4().hex
        source_path = UPLOAD_DIR / f"{token}_{original_name}"
        uploaded.save(source_path)
    elif config_text.strip():
        token = uuid.uuid4().hex
        source_path = UPLOAD_DIR / f"{token}_pasted-config.cfg"
        source_path.write_text(config_text, encoding="utf-8")
    else:
        return jsonify({"ok": False, "error": "Upload file konfigurasi atau paste konfigurasi terlebih dahulu."}), 400

    mapping_raw = request.form.get("interface_mapping")
    mapping = None
    if mapping_raw:
        try:
            mapping = json.loads(mapping_raw)
        except json.JSONDecodeError:
            return jsonify({"ok": False, "error": "interface_mapping tidak valid (bukan JSON)."}), 400

    try:
        result = convert_file(
            source_path,
            source_vendor=request.form.get("source_vendor", "Auto Detect"),
            source_device_type=request.form.get("source_device_type", "Auto Detect"),
            target_vendor=request.form.get("target_vendor", "Huawei"),
            target_device_type=request.form.get("target_device_type") or None,
            profile_key=request.form.get("profile_key") or None,
            target_model=request.form.get("target_model") or None,
            mapping=mapping,
        )
        export_id = uuid.uuid4().hex
        export_path = EXPORT_DIR / f"{export_id}.cfg"
        export_path.write_text(result["output_text"], encoding="utf-8")
        result["download_url"] = f"/configuration/download/{export_id}?name={result['download_name']}"
        log_activity(
            "Configuration Studio",
            "Configuration converted",
            f"{result['hostname']} · {result['source_vendor']} to {result['target_vendor']}",
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        log_activity("Configuration Studio", "Conversion failed", f"{type(exc).__name__}: {exc}", "error")
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        try:
            source_path.unlink(missing_ok=True)
        except OSError:
            pass


@bp.post("/api/preview-mapping")
def preview_mapping_route():
    """
    Parse-only step for the interface/zone mapping preview: same
    upload/paste input as /api/convert, but stops after parsing and
    returns the target translator's best-guess interface/zone mapping
    for the UI to show and let the user edit before calling /api/convert
    again with that edited mapping as `interface_mapping` (JSON).
    """
    uploaded = request.files.get("config_file")
    config_text = request.form.get("config_text", "")
    original_name = secure_filename(uploaded.filename) if uploaded and uploaded.filename else "pasted-config.cfg"

    if uploaded and uploaded.filename:
        if not _is_config_name(original_name):
            return jsonify({"ok": False, "error": "Unsupported configuration file type."}), 400
        token = uuid.uuid4().hex
        source_path = UPLOAD_DIR / f"{token}_{original_name}"
        uploaded.save(source_path)
    elif config_text.strip():
        token = uuid.uuid4().hex
        source_path = UPLOAD_DIR / f"{token}_pasted-config.cfg"
        source_path.write_text(config_text, encoding="utf-8")
    else:
        return jsonify({"ok": False, "error": "Upload file konfigurasi atau paste konfigurasi terlebih dahulu."}), 400

    try:
        result = preview_mapping(
            source_path,
            source_vendor=request.form.get("source_vendor", "Auto Detect"),
            source_device_type=request.form.get("source_device_type", "Auto Detect"),
            target_vendor=request.form.get("target_vendor", "Huawei"),
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        try:
            source_path.unlink(missing_ok=True)
        except OSError:
            pass


@bp.post("/api/batch")
def batch_convert():
    uploads = [item for item in request.files.getlist("config_files") if item and item.filename]
    if not uploads:
        return jsonify({"ok": False, "error": "Select configuration files, a folder, or a ZIP archive."}), 400

    export_id = uuid.uuid4().hex
    archive_path = EXPORT_DIR / f"{export_id}.zip"
    results: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    used_names: set[str] = set()

    try:
        with tempfile.TemporaryDirectory(prefix="nes_batch_", dir=UPLOAD_DIR) as temp_name:
            sources, collection_errors = _collect_batch_sources(uploads, Path(temp_name))
            errors.extend(collection_errors)
            if not sources:
                return jsonify({
                    "ok": False,
                    "error": "No supported configuration files were found.",
                    "result": {"converted": [], "failed": errors},
                }), 400

            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for source in sources:
                    source_name = source["source_name"]
                    source_path = source["path"]
                    try:
                        result = convert_file(
                            source_path,
                            source_vendor=request.form.get("source_vendor", "Auto Detect"),
                            source_device_type=request.form.get("source_device_type", "Auto Detect"),
                            target_vendor=request.form.get("target_vendor", "Huawei"),
                            target_device_type=request.form.get("target_device_type") or None,
                            profile_key=request.form.get("profile_key") or None,
                            target_model=request.form.get("target_model") or None,
                        )
                        output_name = _unique_output_name(result["download_name"], used_names)
                        preview_id = uuid.uuid4().hex
                        archive.writestr(output_name, result["output_text"])
                        _write_preview(export_id, preview_id, result, source_name, output_name)
                        results.append({
                            "source_name": source_name,
                            "output_name": output_name,
                            "hostname": result["hostname"],
                            "source_vendor": result["source_vendor"],
                            "source_device_type": result["source_device_type"],
                            "target_vendor": result["target_vendor"],
                            "profile": result["profile"],
                            "review_count": result["review_count"],
                            "source_lines": result["source_lines"],
                            "output_lines": result["output_lines"],
                            "status": "Converted",
                            "preview_url": f"/configuration/api/batch/{export_id}/preview/{preview_id}",
                            "download_url": f"/configuration/download-batch-item/{export_id}/{preview_id}?name={output_name}",
                        })
                    except Exception as exc:
                        errors.append({
                            "source_name": source_name,
                            "status": "Failed",
                            "error": f"{type(exc).__name__}: {exc}",
                        })

                archive.writestr(
                    "NES_Batch_Summary.json",
                    json.dumps({"converted": results, "failed": errors}, indent=2),
                )
    except ValueError as exc:
        archive_path.unlink(missing_ok=True)
        return jsonify({"ok": False, "error": str(exc)}), 400

    if not results:
        archive_path.unlink(missing_ok=True)

    log_activity(
        "Configuration Studio",
        "Batch conversion completed",
        f"{len(results)} converted · {len(errors)} failed",
        "success" if results else "error",
    )
    return jsonify({
        "ok": bool(results),
        "result": {
            "converted": results,
            "failed": errors,
            "converted_count": len(results),
            "failed_count": len(errors),
            "download_url": f"/configuration/download-batch/{export_id}",
        },
        "error": "No files could be converted." if not results else None,
    }), 200 if results else 400


@bp.get("/api/batch/<batch_id>/preview/<preview_id>")
def batch_preview(batch_id: str, preview_id: str):
    if not SAFE_IDENTIFIER.fullmatch(batch_id) or not SAFE_IDENTIFIER.fullmatch(preview_id):
        return jsonify({"ok": False, "error": "Invalid batch preview identifier."}), 400
    preview_path = BATCH_PREVIEW_DIR / batch_id / f"{preview_id}.json"
    if not preview_path.is_file():
        return jsonify({"ok": False, "error": "Batch preview is no longer available."}), 404
    try:
        payload = json.loads(preview_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return jsonify({"ok": False, "error": "Batch preview could not be read."}), 500
    return jsonify({"ok": True, "result": payload})


@bp.get("/download-batch/<export_id>")
def download_batch(export_id: str):
    return send_from_directory(
        EXPORT_DIR,
        f"{export_id}.zip",
        as_attachment=True,
        download_name="NES_Batch_Converted_Configs.zip",
    )


@bp.get("/download-batch-item/<batch_id>/<preview_id>")
def download_batch_item(batch_id: str, preview_id: str):
    if not SAFE_IDENTIFIER.fullmatch(batch_id) or not SAFE_IDENTIFIER.fullmatch(preview_id):
        return jsonify({"ok": False, "error": "Invalid batch item identifier."}), 400
    name = secure_filename(request.args.get("name", "converted-config.cfg")) or "converted-config.cfg"
    return send_from_directory(
        BATCH_PREVIEW_DIR / batch_id,
        f"{preview_id}.cfg",
        as_attachment=True,
        download_name=name,
    )


@bp.get("/download/<export_id>")
def download(export_id: str):
    name = secure_filename(request.args.get("name", "converted-config.cfg")) or "converted-config.cfg"
    return send_from_directory(EXPORT_DIR, f"{export_id}.cfg", as_attachment=True, download_name=name)
