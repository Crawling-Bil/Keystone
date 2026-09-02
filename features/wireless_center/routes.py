from __future__ import annotations

import json
import uuid
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core.database import log_activity
from .ap_role_diff import (
    AP_ROLE_PAIR_GUIDE,
    AP_STATUS_GUIDE,
    compare_ap_roles,
    read_ap_state,
    read_expected_allocation,
)
from .config_delta import compare_configs
from .exporters.ap_role_exporter import export_ap_role_diff
from .exporters.delta_exporter import export_delta_comparison
from .inventory_master import export_as_built, read_inventory, template_csv
from .service import analyze, export_excel

bp = Blueprint("wireless", __name__, url_prefix="/wireless")
BASE_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BASE_DIR / "uploads" / "wireless"
ANALYSIS_DIR = BASE_DIR / "data" / "wireless_analysis"
EXPORT_DIR = BASE_DIR / "exports" / "wireless"
COMPARISON_DIR = BASE_DIR / "data" / "wireless_comparison"
AP_ROLE_DIR = BASE_DIR / "data" / "wireless_ap_roles"
for directory in (UPLOAD_DIR, ANALYSIS_DIR, EXPORT_DIR, COMPARISON_DIR, AP_ROLE_DIR):
    directory.mkdir(parents=True, exist_ok=True)


@bp.get("")
@bp.get("/")
def index():
    return render_template(
        "wireless.html",
        active_page="wireless",
        ap_status_guide=AP_STATUS_GUIDE,
        ap_role_pair_guide=AP_ROLE_PAIR_GUIDE,
    )


@bp.get("/ap-role/template")
def download_ap_role_template():
    content = (
        "\ufeffAP Name,MAC Address,Serial Number,Expected Active WLC\r\n"
        "A-AP-001,0011-2233-4455,SERIAL-001,A\r\n"
        "B-AP-001,0011-2233-4466,SERIAL-002,B\r\n"
    )
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": 'attachment; filename="Keystone_AP_Expected_Allocation_Template.csv"'},
    )


@bp.get("/template/<vendor>")
def download_template(vendor: str):
    vendor = vendor.title()
    if vendor not in {"Cisco", "Huawei"}:
        return "Unsupported vendor", 400
    try:
        quantity = max(0, min(int(request.args.get("quantity", "0") or 0), 5000))
    except ValueError:
        return "quantity must be a number", 400
    content = template_csv(
        vendor,
        quantity=quantity,
        prefix=request.args.get("prefix", "AP"),
        site=request.args.get("site", ""),
        floor=request.args.get("floor", ""),
    )
    filename = f"NES_{vendor}_AP_Master_Template.csv"
    return Response(content, mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@bp.post("/api/validate-inventory")
def validate_inventory_route():
    upload = request.files.get("inventory_file")
    vendor = request.form.get("vendor", "Huawei").title()
    if vendor not in {"Cisco", "Huawei"}:
        return jsonify({"ok": False, "error": "Pilih vendor Cisco atau Huawei."}), 400
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "Upload AP Master Inventory terlebih dahulu."}), 400
    suffix = Path(upload.filename).suffix.lower()
    if suffix not in {".csv", ".xlsx", ".xlsm"}:
        return jsonify({"ok": False, "error": "Format inventory harus CSV atau XLSX."}), 400
    path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{secure_filename(upload.filename)}"
    upload.save(path)
    try:
        result = read_inventory(path, vendor)
        log_activity("Wireless Center", "AP master validated", f"{vendor} · {result['summary']['total_records']} AP records")
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        path.unlink(missing_ok=True)


@bp.post("/api/analyze")
def analyze_route():
    config_upload = request.files.get("config_file")
    config_text = request.form.get("config_text", "")
    inventory_upload = request.files.get("inventory_file")
    temp_files: list[Path] = []

    if config_upload and config_upload.filename:
        config_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{secure_filename(config_upload.filename)}"
        config_upload.save(config_path)
        temp_files.append(config_path)
        content = config_path.read_text(encoding="utf-8", errors="ignore")
        source_name = secure_filename(config_upload.filename)
    elif config_text.strip():
        content = config_text
        source_name = "pasted-wlc-config.txt"
    else:
        return jsonify({"ok": False, "error": "Upload WLC backup atau paste konfigurasi terlebih dahulu."}), 400

    inventory_path = None
    if inventory_upload and inventory_upload.filename:
        inventory_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{secure_filename(inventory_upload.filename)}"
        inventory_upload.save(inventory_path)
        temp_files.append(inventory_path)

    try:
        result = analyze(
            content,
            request.form.get("vendor", "Auto Detect"),
            inventory_path,
            request.form.get("deployment_mode", "existing"),
        )
        analysis_id = uuid.uuid4().hex
        payload_path = ANALYSIS_DIR / f"{analysis_id}.json"
        payload_path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        result["analysis_id"] = analysis_id
        result["source_name"] = source_name
        result["export_url"] = f"/wireless/export/{analysis_id}"
        if result.get("deployment_validation"):
            result["as_built_url"] = f"/wireless/as-built/{analysis_id}"
        summary = result["assessment"]["summary"]
        log_activity(
            "Wireless Center",
            "WLC analysis completed",
            f"{source_name} · {result['data'].get('vendor')} · {summary.get('total_aps', 0)} AP",
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        log_activity("Wireless Center", "Analysis failed", f"{type(exc).__name__}: {exc}", "error")
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        for path in temp_files:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


@bp.post("/api/compare")
def compare_route():
    source_upload = request.files.get("source_file")
    target_upload = request.files.get("target_file")
    if not source_upload or not source_upload.filename:
        return jsonify({"ok": False, "error": "Upload Source WLC configuration terlebih dahulu."}), 400
    if not target_upload or not target_upload.filename:
        return jsonify({"ok": False, "error": "Upload Target WLC configuration terlebih dahulu."}), 400

    uploads = [("Source", source_upload), ("Target", target_upload)]
    temp_files: list[Path] = []
    contents: dict[str, str] = {}
    names: dict[str, str] = {}
    try:
        for role, upload in uploads:
            suffix = Path(upload.filename).suffix.lower()
            if suffix not in {".txt", ".cfg", ".log"}:
                raise ValueError(f"Format {role} harus TXT, CFG, atau LOG.")
            safe_name = secure_filename(upload.filename)
            path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"
            upload.save(path)
            temp_files.append(path)
            contents[role] = path.read_text(encoding="utf-8", errors="ignore")
            if not contents[role].strip():
                raise ValueError(f"{role} configuration file kosong.")
            names[role] = safe_name

        result = compare_configs(
            contents["Source"],
            contents["Target"],
            request.form.get("vendor", "Auto Detect"),
        )
        comparison_id = uuid.uuid4().hex
        result.update({
            "comparison_id": comparison_id,
            "source_name": names["Source"],
            "target_name": names["Target"],
        })
        payload_path = COMPARISON_DIR / f"{comparison_id}.json"
        payload_path.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        result.update({
            "export_url": f"/wireless/compare/export/{comparison_id}",
            "delta_url": f"/wireless/compare/delta/{comparison_id}",
            "rollback_url": f"/wireless/compare/rollback/{comparison_id}",
        })
        log_activity(
            "Wireless Center",
            "WLC config delta generated",
            f"{names['Source']} → {names['Target']} · {result['vendor']} · "
            f"{result['summary']['generated_objects']} generated objects",
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        log_activity("Wireless Center", "WLC config comparison failed", f"{type(exc).__name__}: {exc}", "error")
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        for path in temp_files:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


@bp.post("/api/compare-ap-roles")
def compare_ap_roles_route():
    a_upload = request.files.get("a_inventory")
    b_upload = request.files.get("b_inventory")
    allocation_upload = request.files.get("allocation_file")
    if not a_upload or not a_upload.filename:
        return jsonify({"ok": False, "error": "Upload Controller A AP State terlebih dahulu."}), 400
    if not b_upload or not b_upload.filename:
        return jsonify({"ok": False, "error": "Upload Controller B AP State terlebih dahulu."}), 400

    a_name = (request.form.get("a_name") or "Controller A").strip()[:80]
    b_name = (request.form.get("b_name") or "Controller B").strip()[:80]
    temp_files: list[Path] = []
    try:
        state_paths: dict[str, Path] = {}
        for role, upload in (("A", a_upload), ("B", b_upload)):
            suffix = Path(upload.filename).suffix.lower()
            if suffix not in {".csv", ".xlsx", ".xlsm", ".txt", ".log"}:
                raise ValueError(f"Controller {role} AP State format must be CSV, XLSX, TXT, or LOG.")
            path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{secure_filename(upload.filename)}"
            upload.save(path)
            temp_files.append(path)
            if not path.stat().st_size:
                raise ValueError(f"Controller {role} AP State file is empty.")
            state_paths[role] = path

        allocation = None
        if allocation_upload and allocation_upload.filename:
            suffix = Path(allocation_upload.filename).suffix.lower()
            if suffix not in {".csv", ".xlsx", ".xlsm"}:
                raise ValueError("Expected allocation format must be CSV or XLSX.")
            allocation_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{secure_filename(allocation_upload.filename)}"
            allocation_upload.save(allocation_path)
            temp_files.append(allocation_path)
            if not allocation_path.stat().st_size:
                raise ValueError("Expected allocation file is empty.")
            allocation = read_expected_allocation(allocation_path, a_name, b_name)

        a_inventory = read_ap_state(state_paths["A"], a_name)
        b_inventory = read_ap_state(state_paths["B"], b_name)
        result = compare_ap_roles(a_inventory, b_inventory, allocation)
        comparison_id = uuid.uuid4().hex
        result.update({
            "comparison_id": comparison_id,
            "a_name": a_name,
            "b_name": b_name,
            "a_source_name": secure_filename(a_upload.filename),
            "b_source_name": secure_filename(b_upload.filename),
            "allocation_source_name": secure_filename(allocation_upload.filename) if allocation_upload and allocation_upload.filename else "",
        })
        (AP_ROLE_DIR / f"{comparison_id}.json").write_text(
            json.dumps(result, ensure_ascii=False), encoding="utf-8"
        )
        result["export_url"] = f"/wireless/ap-role/export/{comparison_id}"
        log_activity(
            "Wireless Center",
            "AP role comparison completed",
            f"{a_name} ↔ {b_name} · {result['summary']['total_aps']} AP · "
            f"{result['summary']['role_issues']} role issues",
        )
        return jsonify({"ok": True, "result": result})
    except Exception as exc:
        log_activity("Wireless Center", "AP role comparison failed", f"{type(exc).__name__}: {exc}", "error")
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    finally:
        for path in temp_files:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def _ap_role_payload(comparison_id: str) -> dict | None:
    if len(comparison_id) != 32 or not comparison_id.isalnum():
        return None
    path = AP_ROLE_DIR / f"{comparison_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@bp.get("/ap-role/export/<comparison_id>")
def export_ap_roles(comparison_id: str):
    payload = _ap_role_payload(comparison_id)
    if payload is None:
        return "AP role comparison not found", 404
    export_path = EXPORT_DIR / f"{comparison_id}_ap_role_diff.xlsx"
    export_ap_role_diff(payload, export_path)
    download_name = secure_filename(
        f"{payload.get('a_name', 'Controller A')}_to_{payload.get('b_name', 'Controller B')}_AP_Role_Diff.xlsx"
    )
    return send_from_directory(EXPORT_DIR, export_path.name, as_attachment=True, download_name=download_name)


def _comparison_payload(comparison_id: str) -> dict | None:
    if len(comparison_id) != 32 or not comparison_id.isalnum():
        return None
    path = COMPARISON_DIR / f"{comparison_id}.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


@bp.get("/compare/export/<comparison_id>")
def export_comparison(comparison_id: str):
    payload = _comparison_payload(comparison_id)
    if payload is None:
        return "Comparison result not found", 404
    export_path = EXPORT_DIR / f"{comparison_id}_wlc_delta.xlsx"
    export_delta_comparison(payload, export_path)
    download_name = secure_filename(
        f"{Path(payload.get('source_name', 'Source')).stem}_to_"
        f"{Path(payload.get('target_name', 'Target')).stem}_WLC_Config_Delta.xlsx"
    )
    return send_from_directory(EXPORT_DIR, export_path.name, as_attachment=True, download_name=download_name)


@bp.get("/compare/delta/<comparison_id>")
def download_delta(comparison_id: str):
    payload = _comparison_payload(comparison_id)
    if payload is None:
        return "Comparison result not found", 404
    target = Path(payload.get("target_name", "Target_WLC")).stem
    return Response(
        payload.get("implementation_config", ""),
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{secure_filename(target)}_Delta_Config.txt"'},
    )


@bp.get("/compare/rollback/<comparison_id>")
def download_rollback(comparison_id: str):
    payload = _comparison_payload(comparison_id)
    if payload is None:
        return "Comparison result not found", 404
    target = Path(payload.get("target_name", "Target_WLC")).stem
    return Response(
        payload.get("rollback_config", ""),
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{secure_filename(target)}_Rollback_Config.txt"'},
    )


@bp.get("/export/<analysis_id>")
def export(analysis_id: str):
    payload_path = ANALYSIS_DIR / f"{analysis_id}.json"
    if not payload_path.is_file():
        return "Analysis result not found", 404
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    export_path = EXPORT_DIR / f"{analysis_id}.xlsx"
    export_excel(payload["data"], export_path)
    hostname = payload.get("data", {}).get("wlc", {}).get("hostname", "WLC") or "WLC"
    download_name = secure_filename(f"{hostname}_Wireless_Analysis.xlsx")
    log_activity("Wireless Center", "Excel report exported", download_name)
    return send_from_directory(EXPORT_DIR, export_path.name, as_attachment=True, download_name=download_name)


@bp.get("/as-built/<analysis_id>")
def as_built(analysis_id: str):
    payload_path = ANALYSIS_DIR / f"{analysis_id}.json"
    if not payload_path.is_file():
        return "Analysis result not found", 404
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    validation = payload.get("deployment_validation")
    if not validation:
        return "No AP master comparison available", 404
    export_path = EXPORT_DIR / f"{analysis_id}_as_built.xlsx"
    export_as_built(validation, export_path)
    hostname = payload.get("data", {}).get("wlc", {}).get("hostname", "WLC") or "WLC"
    download_name = secure_filename(f"{hostname}_AP_As_Built.xlsx")
    log_activity("Wireless Center", "As-built inventory exported", download_name)
    return send_from_directory(EXPORT_DIR, export_path.name, as_attachment=True, download_name=download_name)
