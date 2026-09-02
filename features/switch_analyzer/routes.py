from __future__ import annotations

import uuid
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request
from werkzeug.utils import secure_filename

from core.database import log_activity
from .service import analyze

bp = Blueprint("switch_analyzer", __name__, url_prefix="/switch-analyzer")
BASE_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BASE_DIR / "uploads" / "switch_analyzer"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_CONFIG_BYTES = 20 * 1024 * 1024


@bp.get("")
@bp.get("/")
def index():
    return render_template("switch_analyzer.html", active_page="switch_analyzer")


@bp.post("/api/analyze")
def analyze_route():
    config_upload = request.files.get("config_file")
    config_text = request.form.get("config_text", "")
    vendor = request.form.get("vendor", "Auto Detect")

    if config_upload and config_upload.filename:
        filename = secure_filename(config_upload.filename)
        path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{filename}"
        config_upload.save(path)
        if path.stat().st_size > MAX_CONFIG_BYTES:
            path.unlink(missing_ok=True)
            return jsonify({"ok": False, "error": "Configuration file exceeds the 20 MB limit."}), 400
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        finally:
            path.unlink(missing_ok=True)
        source_name = filename
    elif config_text.strip():
        if len(config_text.encode("utf-8")) > MAX_CONFIG_BYTES:
            return jsonify({"ok": False, "error": "Pasted configuration exceeds the 20 MB limit."}), 400
        content = config_text
        source_name = "pasted-switch-config.txt"
    else:
        return jsonify({"ok": False, "error": "Upload a switch config or paste a configuration first."}), 400

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
