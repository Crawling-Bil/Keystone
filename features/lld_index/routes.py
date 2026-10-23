"""Flask blueprint for the LLD Index builder (``/lld-index``)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from flask import Blueprint, Response, jsonify, render_template, request, send_from_directory

from core.database import log_activity
from .builder import available_templates
from .inventory import COLUMNS, read_inventory_file, template_workbook
from .service import build_index, download_name, read_config_uploads, save_export

bp = Blueprint("lld_index", __name__, url_prefix="/lld-index")
BASE_DIR = Path(__file__).resolve().parents[2]
EXPORT_DIR = BASE_DIR / "exports" / "lld_index"
SAFE_ID = re.compile(r"^[a-f0-9]{32}$")
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@bp.get("")
def page():
    return render_template("lld_index.html", active_page="lld_index", templates=available_templates(), columns=COLUMNS)


@bp.get("/inventory-template.xlsx")
def inventory_template():
    return Response(template_workbook(), mimetype=XLSX,
                    headers={"Content-Disposition": 'attachment; filename="LLD Inventory Template.xlsx"'})


@bp.post("/api/inventory")
def import_inventory():
    upload = request.files.get("inventory")
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "Choose a CSV or XLSX inventory file."}), 400
    try:
        rows = read_inventory_file(upload.filename, upload.read())
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "rows": rows})


@bp.post("/api/build")
def build():
    try:
        payload = json.loads(request.form.get("payload") or "{}")
    except json.JSONDecodeError:
        return jsonify({"ok": False, "error": "The form data could not be read."}), 400
    uploads = [(f.filename, f.read()) for f in request.files.getlist("configs") if f and f.filename]
    try:
        files = read_config_uploads(uploads)
        result = build_index(payload.get("project") or {}, payload.get("inventory") or [],
                             payload.get("technologies") or [], files)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        log_activity("LLD Index", "Index build failed", f"{type(exc).__name__}: {exc}", "error")
        return jsonify({"ok": False, "error": f"{type(exc).__name__}: {exc}"}), 400
    export_id = save_export(EXPORT_DIR, result.pop("workbook"))
    name = download_name(result["project"])
    log_activity("LLD Index", "Index built", f"{name} · {result['stats']['headings']} headings")
    result["download_url"] = f"/lld-index/download/{export_id}?name={name}"
    result["export_id"] = export_id
    result["download_name"] = name
    return jsonify({"ok": True, "result": result})


@bp.get("/download/<export_id>")
def download(export_id: str):
    if not SAFE_ID.match(export_id):
        return jsonify({"ok": False, "error": "Unknown file."}), 404
    name = re.sub(r"[^A-Za-z0-9 ._-]+", "", request.args.get("name") or "LLD Content Index.xlsx") or "LLD Content Index.xlsx"
    if not name.lower().endswith(".xlsx"):
        name += ".xlsx"
    return send_from_directory(EXPORT_DIR, f"{export_id}.xlsx", as_attachment=True, download_name=name, mimetype=XLSX)

