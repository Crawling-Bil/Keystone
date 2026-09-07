from __future__ import annotations

import re
import uuid
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core.database import log_activity
from .compare import compare as compare_results
from .exporters import SwitchExcelExporter, export_comparison
from .service import analyze
from .sizing import build_sizing_summary

bp = Blueprint("switch_analyzer", __name__, url_prefix="/switch-analyzer")
BASE_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BASE_DIR / "uploads" / "switch_analyzer"
EXPORT_DIR = BASE_DIR / "exports" / "switch_analyzer"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
SAFE_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")

# Restored from the pre-port Keystone baseline (this repo's own routes.py
# already enforced this before this port; the source project's expanded
# _read_config_from_request had dropped it while adding the two-device
# compare path). Applies to every route that goes through
# _read_config_from_request -- analyze and both sides of compare.
MAX_CONFIG_BYTES = 20 * 1024 * 1024


class ConfigTooLargeError(ValueError):
    """Raised by _read_config_from_request when the uploaded/pasted
    config exceeds MAX_CONFIG_BYTES, so callers can surface a clear
    400 instead of quietly reading an oversized file into memory."""


@bp.get("")
@bp.get("/")
def index():
    return render_template("switch_analyzer.html", active_page="switch_analyzer")


def _read_config_from_request(file_field: str, text_field: str) -> tuple[str, str] | None:
    """Read a config either from an uploaded file or a pasted-text
    field. Returns (content, source_name) or None if neither was given.
    Raises ConfigTooLargeError if the input exceeds MAX_CONFIG_BYTES.
    Shared by the single-device and two-device (compare) analyze routes.
    """
    config_upload = request.files.get(file_field)
    config_text = request.form.get(text_field, "")

    if config_upload and config_upload.filename:
        filename = secure_filename(config_upload.filename)
        path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"
        config_upload.save(path)
        if path.stat().st_size > MAX_CONFIG_BYTES:
            path.unlink(missing_ok=True)
            raise ConfigTooLargeError("Configuration file exceeds the 20 MB limit.")
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        finally:
            path.unlink(missing_ok=True)
        return content, filename

    if config_text.strip():
        if len(config_text.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ConfigTooLargeError("Pasted configuration exceeds the 20 MB limit.")
        return config_text, "pasted-switch-config.txt"

    return None


def _device_filename_stem(result: dict) -> str:
    """hostname_devicemodel, e.g. 'GTOPAS-SMG-SWCO-C3650_WS-C3650-24TS'
    — lets multiple single-device exports for the same hostname (a
    device re-analyzed after a config change, or the same hostname on
    different physical units) stay distinguishable by model, and
    matches how the device is already labeled in the analyzer's own
    toolbar. Falls back to hostname alone when the model wasn't parsed
    (e.g. an incomplete or partial capture).
    """
    hostname = secure_filename(str(result.get("hostname") or "switch")) or "switch"
    model = secure_filename(str((result.get("os_version") or {}).get("model") or ""))
    return f"{hostname}_{model}" if model else hostname


@bp.post("/api/analyze")
def analyze_route():
    try:
        read = _read_config_from_request("config_file", "config_text")
    except ConfigTooLargeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if read is None:
        return jsonify({"ok": False, "error": "Upload switch config atau paste konfigurasi terlebih dahulu."}), 400
    content, source_name = read
    vendor = request.form.get("vendor", "Auto Detect")

    try:
        result = analyze(content, filename=source_name, vendor=vendor)
        log_activity(
            "Switch Analyzer",
            "Switch config analyzed",
            f"{result['vendor']} · {result['hostname']} · {result['cards']['total_interfaces']} interfaces",
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400


@bp.post("/api/export")
def export_route():
    """Export one or more already-analyzed results (the same JSON the
    frontend is already holding) as a single multi-sheet .xlsx workbook
    — every sheet carries a Hostname column, so multiple devices land
    as more rows in the same sheets rather than duplicate sheet sets,
    ready for combining many devices into one sizing-assessment
    workbook. Accepts either `results: [...]` (a list, for combining
    devices) or the original single-device `result: {...}` for backward
    compatibility. Takes the parsed result(s) rather than re-uploading/
    re-parsing the configs, since the browser already has them from
    prior /api/analyze calls. Follows the same write-to-EXPORT_DIR /
    return-download_url pattern Configuration Studio's own downloads
    use, so the frontend just sets an anchor's href — no separate
    blob-download code path needed.
    """
    payload = request.get_json(silent=True) or {}
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        single = payload.get("result")
        results = [single] if isinstance(single, dict) else None
    if not results or not all(isinstance(item, dict) for item in results):
        return jsonify({"ok": False, "error": "No analysis result provided."}), 400

    if len(results) == 1:
        download_name = f"{_device_filename_stem(results[0])}.xlsx"
    else:
        download_name = f"combined-switch-analysis-{len(results)}-devices.xlsx"
    export_id = uuid.uuid4().hex

    SwitchExcelExporter(results).export(EXPORT_DIR / f"{export_id}.xlsx")

    log_activity(
        "Switch Analyzer",
        "Switch analysis exported",
        f"{len(results)} device(s) → {download_name}",
    )
    return jsonify({
        "ok": True,
        "download_url": f"/switch-analyzer/download/{export_id}?name={download_name}",
        "download_name": download_name,
    })


@bp.post("/api/sizing")
def sizing_route():
    """Roll up one or more already-analyzed results (same JSON shape
    /api/export takes) into the per-device + aggregate sizing numbers
    used by the Sizing Assessment view — physical port counts by
    speed, PoE budget, uplink/trunk count, VLAN/route/redundancy
    complexity, stacking. See sizing.py for what's derived vs. what's
    honestly reported as "can't tell from the name" (NX-OS bare
    Ethernet names and ArubaOS-Switch bare numeric port names don't
    encode speed, confirmed against real captures in this project).
    """
    payload = request.get_json(silent=True) or {}
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        single = payload.get("result")
        results = [single] if isinstance(single, dict) else None
    if not results or not all(isinstance(item, dict) for item in results):
        return jsonify({"ok": False, "error": "No analysis result provided."}), 400

    try:
        summary = build_sizing_summary(results)
        log_activity(
            "Switch Analyzer",
            "Sizing assessment built",
            f"{len(results)} device(s)",
        )
        return jsonify({"ok": True, "summary": summary})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400


@bp.get("/download/<export_id>")
def download_export(export_id: str):
    if not SAFE_IDENTIFIER.match(export_id):
        return jsonify({"ok": False, "error": "Invalid export id."}), 400
    name = secure_filename(request.args.get("name", "")) or f"{export_id}.xlsx"
    return send_from_directory(EXPORT_DIR, f"{export_id}.xlsx", as_attachment=True, download_name=name)


@bp.post("/api/compare")
def compare_route():
    """Analyze two configs (e.g. the old Cisco/Aruba switch and the new
    Huawei draft/implemented config for the same role) and return a
    migration-parity comparison: VLANs/routes/DNS servers present on
    one side but not the other, plus device info and interface/VLAN/
    route/neighbor counts side-by-side. See compare.py for why this is
    a set comparison rather than a per-interface diff.
    """
    try:
        read_a = _read_config_from_request("config_file_a", "config_text_a")
        read_b = _read_config_from_request("config_file_b", "config_text_b")
    except ConfigTooLargeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if read_a is None or read_b is None:
        return jsonify({"ok": False, "error": "Upload or paste both Device A and Device B configs."}), 400

    content_a, source_a = read_a
    content_b, source_b = read_b
    vendor_a = request.form.get("vendor_a", "Auto Detect")
    vendor_b = request.form.get("vendor_b", "Auto Detect")

    try:
        result_a = analyze(content_a, filename=source_a, vendor=vendor_a)
        result_b = analyze(content_b, filename=source_b, vendor=vendor_b)
        comparison = compare_results(result_a, result_b)
        log_activity(
            "Switch Analyzer",
            "Devices compared",
            f"{result_a['hostname']} vs {result_b['hostname']}",
        )
        return jsonify({"ok": True, "result_a": result_a, "result_b": result_b, "comparison": comparison})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400


@bp.post("/api/compare/export")
def compare_export_route():
    """Export a two-device comparison as .xlsx: a "Comparison" summary
    sheet (device info side-by-side, VLAN/route/DNS-server presence)
    plus the full combined per-device data sheets, same download_url
    pattern as the regular export.
    """
    payload = request.get_json(silent=True) or {}
    result_a = payload.get("result_a")
    result_b = payload.get("result_b")
    comparison = payload.get("comparison")
    if not all(isinstance(item, dict) for item in (result_a, result_b, comparison)):
        return jsonify({"ok": False, "error": "No comparison result provided."}), 400

    download_name = f"compare_{_device_filename_stem(result_a)}_vs_{_device_filename_stem(result_b)}.xlsx"
    export_id = uuid.uuid4().hex

    export_comparison(EXPORT_DIR / f"{export_id}.xlsx", result_a, result_b, comparison)

    log_activity(
        "Switch Analyzer",
        "Comparison exported",
        f"{result_a.get('hostname', '')} vs {result_b.get('hostname', '')} → {download_name}",
    )
    return jsonify({
        "ok": True,
        "download_url": f"/switch-analyzer/download/{export_id}?name={download_name}",
        "download_name": download_name,
    })
