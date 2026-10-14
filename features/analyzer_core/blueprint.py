"""Flask blueprint factory for result-shaped analyzers.

Every analyzer page needs the same four endpoints (page, analyze, export,
download) plus a collect-list listing; only the analysis function and the
text differ.  :func:`create_analyzer_blueprint` wires them up once so the
three new analyzers cannot drift apart in upload limits, error handling or
export behaviour.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from flask import Blueprint, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core.database import log_activity

from . import collect
from .compare import compare_results
from .export import export_results
from .result import validate_result

MAX_CONFIG_BYTES = 40 * 1024 * 1024
MAX_FILES = 16
SAFE_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")


def decode_bytes(data: bytes) -> str:
    """Terminal logs come out of PuTTY / SecureCRT / Tera Term / browser
    downloads in UTF-8, UTF-8-with-BOM or (rarely) UTF-16."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="replace")
    if b"\x00" in data[:4096]:
        try:
            return data.decode("utf-16-le", errors="replace")
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8-sig", errors="replace")


@dataclass
class AnalyzerSpec:
    key: str                      # "router"
    name: str                     # "Router Analyzer"
    url_prefix: str               # "/router-analyzer"
    template: str                 # "router_analyzer.html"
    analyze: Callable[..., dict[str, Any]]   # (content, filename=, platform=) -> result
    collect_prefix: str           # "collect-router"
    activity_module: str = ""     # label in the dashboard activity feed
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[2])
    page_context: dict[str, Any] = field(default_factory=dict)
    # Optional hook for binary uploads (e.g. an F5 .ucs archive): (filename, stream) -> text, or None to use the
    # normal text path. It may raise ValueError with a message written for the engineer.
    read_upload: Callable[[str, Any], "str | None"] | None = None
    max_upload_bytes: int = 1536 * 1024 * 1024      # request-size ceiling when read_upload is set


def create_analyzer_blueprint(spec: AnalyzerSpec) -> Blueprint:
    bp = Blueprint(f"{spec.key}_analyzer", __name__, url_prefix=spec.url_prefix)
    export_dir = spec.base_dir / "exports" / f"{spec.key}_analyzer"
    export_dir.mkdir(parents=True, exist_ok=True)
    module_label = spec.activity_module or spec.name

    @bp.get("")
    @bp.get("/")
    def index():
        return render_template(
            spec.template,
            active_page=f"{spec.key}_analyzer",
            collect_scripts=collect.discover(spec.collect_prefix),
            **spec.page_context,
        )

    @bp.get("/api/collect-scripts")
    def collect_scripts():
        return jsonify({"ok": True, "scripts": collect.discover(spec.collect_prefix)})

    @bp.post("/api/analyze")
    def analyze_route():
        sources: list[tuple[str, str]] = []
        read_errors: list[dict[str, str]] = []
        if spec.read_upload and (request.content_length or 0) > spec.max_upload_bytes:
            return jsonify({"ok": False, "error": f"The upload exceeds the {spec.max_upload_bytes // (1024 * 1024)} MB limit."}), 400
        for upload in request.files.getlist("config_files") + request.files.getlist("config_file"):
            if not upload or not upload.filename:
                continue
            if spec.read_upload:
                try:
                    special = spec.read_upload(upload.filename, upload.stream)
                except ValueError as exc:
                    read_errors.append({"source": secure_filename(upload.filename) or "upload", "error": str(exc)})
                    continue
                if special is not None:
                    sources.append((secure_filename(upload.filename) or "upload.ucs", special))
                    continue
                upload.stream.seek(0)
            data = upload.read(MAX_CONFIG_BYTES + 1)
            if len(data) > MAX_CONFIG_BYTES:
                return jsonify({"ok": False, "error": f"{secure_filename(upload.filename)} exceeds the {MAX_CONFIG_BYTES // (1024 * 1024)} MB limit."}), 400
            sources.append((secure_filename(upload.filename) or "capture.txt", decode_bytes(data)))
        pasted = request.form.get("config_text", "")
        if pasted.strip():
            if len(pasted.encode("utf-8")) > MAX_CONFIG_BYTES:
                return jsonify({"ok": False, "error": "Pasted capture exceeds the size limit."}), 400
            sources.append((f"pasted-{spec.key}-capture.txt", pasted))
        if not sources and read_errors:
            return jsonify({"ok": False, "error": read_errors[0]["error"], "errors": read_errors}), 400
        if not sources:
            return jsonify({"ok": False, "error": "Upload a capture file or paste the command output first."}), 400
        if len(sources) > MAX_FILES:
            return jsonify({"ok": False, "error": f"At most {MAX_FILES} files per analysis."}), 400

        platform = request.form.get("platform", "auto")
        results: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = list(read_errors)
        for filename, content in sources:
            try:
                result = spec.analyze(content, filename=filename, platform=platform)
                result["source_name"] = filename
                problems = validate_result(result)
                if problems:
                    raise ValueError("internal result error: " + "; ".join(problems[:3]))
                results.append(result)
            except Exception as exc:  # surface per-file, keep the others
                # ValueError carries a message written for the engineer (what was not recognised, which page to use); anything else is a bug worth naming
                errors.append({"source": filename, "error": str(exc) if type(exc) is ValueError else f"{type(exc).__name__}: {exc}"})
        if not results:
            return jsonify({"ok": False, "error": errors[0]["error"] if errors else "Nothing could be analyzed.", "errors": errors}), 400
        for result in results:
            log_activity(module_label, f"{spec.name} analysis", f"{result.get('hostname', '')} · {result.get('platform', '')} · {len(result.get('findings', []))} findings")
        return jsonify({"ok": True, "results": results, "errors": errors})

    @bp.post("/api/export")
    def export_route():
        payload = request.get_json(silent=True) or {}
        results = payload.get("results")
        if not isinstance(results, list) or not results or not all(isinstance(item, dict) for item in results):
            return jsonify({"ok": False, "error": "No analysis result provided."}), 400
        problems = [p for item in results for p in validate_result(item)]
        if problems:
            return jsonify({"ok": False, "error": "Result is malformed: " + "; ".join(problems[:3])}), 400
        export_id = uuid.uuid4().hex
        if len(results) == 1:
            stem = secure_filename(str(results[0].get("hostname") or spec.key)) or spec.key
            name = f"{stem}_{spec.key}-analysis.xlsx"
        else:
            name = f"combined-{spec.key}-analysis-{len(results)}-devices.xlsx"
        export_results(results, export_dir / f"{export_id}.xlsx", analyzer_label=spec.name)
        log_activity(module_label, f"{spec.name} exported", f"{len(results)} device(s) → {name}")
        return jsonify({"ok": True, "download_url": f"{spec.url_prefix}/download/{export_id}?name={name}", "download_name": name})

    @bp.post("/api/compare")
    def compare_route():
        payload = request.get_json(silent=True) or {}
        before, after = payload.get("before"), payload.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            return jsonify({"ok": False, "error": "Choose two analysed devices to compare."}), 400
        problems = [p for item in (before, after) for p in validate_result(item)]
        if problems:
            return jsonify({"ok": False, "error": "Result is malformed: " + "; ".join(problems[:3])}), 400
        if before.get("comparison") or after.get("comparison"):
            return jsonify({"ok": False, "error": "A comparison cannot be compared again; pick two devices."}), 400
        result = compare_results(before, after)
        problems = validate_result(result)
        if problems:
            return jsonify({"ok": False, "error": "internal result error: " + "; ".join(problems[:3])}), 500
        log_activity(module_label, f"{spec.name} comparison", f"{result['hostname']} · {result['subtitle']}")
        return jsonify({"ok": True, "result": result})

    @bp.get("/download/<export_id>")
    def download(export_id: str):
        if not SAFE_IDENTIFIER.match(export_id):
            return jsonify({"ok": False, "error": "Invalid export id."}), 400
        name = secure_filename(request.args.get("name", "")) or f"{export_id}.xlsx"
        return send_from_directory(export_dir, f"{export_id}.xlsx", as_attachment=True, download_name=name)

    return bp
