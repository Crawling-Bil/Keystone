"""Flask blueprint for the LLD Generator (``/lld-generator``).

The JSON API matches the Document Generator's FastAPI routes one to one
(same paths under ``/lld-generator/api``, same bodies, errors as
``{"detail": "..."}``), so the page script is a port, not a rewrite.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file

from core.database import log_activity
from . import service, store
from .service import GenError

bp = Blueprint("lld_generator", __name__, url_prefix="/lld-generator")
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

PROJECT_FIELDS = ("name", "client", "version", "template_id", "project_code", "company", "prepared_by", "doc_date", "logo")
TEMPLATE_FIELDS = ("name", "closing_heading", "auto_numbered_levels", "figure_seq_name", "table_seq_name")


@bp.errorhandler(GenError)
def _gen_error(exc: GenError):
    return jsonify({"detail": str(exc)}), exc.status


def _body() -> dict:
    return request.get_json(silent=True) or {}


def _need(row, what: str):
    if not row:
        raise GenError(f"{what} tidak ditemukan", 404)
    return row


def _fields(body: dict, allowed: tuple) -> dict:
    return {k: body[k] for k in allowed if k in body and body[k] is not None}


@bp.get("")
def page():
    return render_template("lld_generator.html", active_page="lld_generator")


# ----------------------------------------------------------------- templates
@bp.post("/api/templates")
def upload_template():
    upload = request.files.get("file")
    if not upload or not upload.filename:
        raise GenError("Pilih file template .docx")
    try:
        levels = json.loads(request.form.get("auto_numbered_levels") or "[1,2]")
    except ValueError:
        levels = [1, 2]
    row = service.add_template(request.form.get("name") or Path(upload.filename).stem, upload.filename, upload.read(),
                               request.form.get("closing_heading") or "", levels,
                               request.form.get("figure_seq_name") or "Gambar", request.form.get("table_seq_name") or "Tabel")
    log_activity("LLD Generator", "Template uploaded", row["name"])
    return jsonify(row)


@bp.get("/api/templates")
def list_templates():
    service.ensure_master_template()
    return jsonify(store.list_templates())


@bp.get("/api/templates/<int:template_id>")
def get_template(template_id: int):
    row = _need(store.get_template(template_id), "Template")
    path = service.template_path(row)
    from core.docgen import docgen
    row["analysis"] = docgen.analyze_template(str(path)) if path.exists() else None
    row["auto_numbered_levels"] = json.loads(row["auto_numbered_levels"])
    return jsonify(row)


@bp.put("/api/templates/<int:template_id>")
def edit_template(template_id: int):
    _need(store.get_template(template_id), "Template")
    return jsonify(store.update_template(template_id, **_fields(_body(), TEMPLATE_FIELDS)))


@bp.delete("/api/templates/<int:template_id>")
def remove_template(template_id: int):
    service.delete_template(template_id)
    return jsonify({"ok": True})


# ----------------------------------------------------------------- projects
@bp.post("/api/projects")
def create_project():
    body = _body()
    if not str(body.get("name") or "").strip():
        raise GenError("Nama project wajib diisi")
    template_id = body.get("template_id")
    if not template_id or not store.get_template(template_id):
        raise GenError("template_id tidak valid")
    row = store.create_project(body["name"].strip(), body.get("client") or "", body.get("version") or "0.1", int(template_id),
                               project_code=body.get("project_code") or "",
                               company=body.get("company") or "Multipolar Technology",
                               prepared_by=body.get("prepared_by") or "", doc_date=body.get("doc_date") or "")
    return jsonify(row)


@bp.get("/api/projects")
def list_projects():
    return jsonify(store.list_projects())


@bp.get("/api/projects/<int:project_id>")
def get_project(project_id: int):
    return jsonify(_need(store.get_project(project_id), "Project"))


@bp.put("/api/projects/<int:project_id>")
def edit_project(project_id: int):
    _need(store.get_project(project_id), "Project")
    fields = _fields(_body(), PROJECT_FIELDS)
    if "template_id" in fields and not store.get_template(fields["template_id"]):
        raise GenError("template_id tidak valid")
    if "logo" in fields:
        fields["logo"] = Path(str(fields["logo"])).name
    return jsonify(store.update_project(project_id, **fields))


@bp.delete("/api/projects/<int:project_id>")
def remove_project(project_id: int):
    _need(store.get_project(project_id), "Project")
    store.delete_project(project_id)
    return jsonify({"ok": True})


# ----------------------------------------------------------------- chapters
@bp.get("/api/projects/<int:project_id>/chapters")
def list_chapters(project_id: int):
    _need(store.get_project(project_id), "Project")
    return jsonify(store.list_chapters_flat(project_id))


@bp.post("/api/projects/<int:project_id>/chapters")
def add_chapter(project_id: int):
    _need(store.get_project(project_id), "Project")
    body = _body()
    title = str(body.get("title") or "").strip()
    if not title:
        raise GenError("Judul bab wajib diisi")
    try:
        return jsonify(store.create_chapter(project_id, body.get("parent_id"), title))
    except ValueError as exc:
        raise GenError(str(exc)) from None


@bp.put("/api/chapters/<int:chapter_id>")
def edit_chapter(chapter_id: int):
    _need(store.get_chapter(chapter_id), "Bab")
    return jsonify(store.update_chapter(chapter_id, **_fields(_body(), ("title",))))


@bp.post("/api/chapters/<int:chapter_id>/move")
def move_chapter(chapter_id: int):
    _need(store.get_chapter(chapter_id), "Bab")
    body = _body()
    try:
        return jsonify(store.move_chapter(chapter_id, body.get("parent_id"), int(body.get("order_index", 0))))
    except ValueError as exc:
        raise GenError(str(exc)) from None


@bp.delete("/api/chapters/<int:chapter_id>")
def remove_chapter(chapter_id: int):
    _need(store.get_chapter(chapter_id), "Bab")
    store.delete_chapter(chapter_id)
    return jsonify({"ok": True})


# ----------------------------------------------------------------- blocks
@bp.get("/api/chapters/<int:chapter_id>/blocks")
def list_blocks(chapter_id: int):
    _need(store.get_chapter(chapter_id), "Bab")
    return jsonify(store.list_blocks(chapter_id))


@bp.post("/api/chapters/<int:chapter_id>/blocks")
def add_block(chapter_id: int):
    _need(store.get_chapter(chapter_id), "Bab")
    body = _body()
    if body.get("block_type") not in ("paragraph", "table", "image"):
        raise GenError("block_type harus paragraph/table/image")
    return jsonify(store.create_block(chapter_id, body["block_type"], body.get("content") or {}))


@bp.put("/api/blocks/<int:block_id>")
def edit_block(block_id: int):
    _need(store.get_block(block_id), "Block")
    body = _body()
    return jsonify(store.update_block(block_id, content=body.get("content"), order_index=body.get("order_index")))


@bp.delete("/api/blocks/<int:block_id>")
def remove_block(block_id: int):
    _need(store.get_block(block_id), "Block")
    store.delete_block(block_id)
    return jsonify({"ok": True})


# ----------------------------------------------------------------- images, import, review, generate
@bp.post("/api/projects/<int:project_id>/upload-image")
def upload_image(project_id: int):
    _need(store.get_project(project_id), "Project")
    upload = request.files.get("file")
    if not upload or not upload.filename:
        raise GenError("Pilih file gambar")
    return jsonify(service.save_image(project_id, upload.filename, upload.read()))


@bp.get("/api/projects/<int:project_id>/images/<path:filename>")
def get_image(project_id: int, filename: str):
    path = service.image_path(project_id, filename)
    if not path.is_file():
        raise GenError("Gambar tidak ditemukan", 404)
    return send_file(path)


@bp.post("/api/projects/<int:project_id>/import-excel")
def import_excel(project_id: int):
    _need(store.get_project(project_id), "Project")
    upload = request.files.get("file")
    if not upload or not upload.filename.lower().endswith((".xlsx", ".xlsm")):
        raise GenError("File harus .xlsx")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "index.xlsx"
        upload.save(path)
        result = service.import_workbook(project_id, str(path), request.form.get("mode") or "append")
    log_activity("LLD Generator", "Index imported", f"project {project_id} · {result.get('chapters', 0)} new chapters")
    return jsonify(result)


@bp.get("/api/projects/<int:project_id>/review")
def review(project_id: int):
    _need(store.get_project(project_id), "Project")
    return jsonify(service.review(project_id))


@bp.post("/api/projects/<int:project_id>/generate")
def generate(project_id: int):
    result = service.generate(project_id)
    log_activity("LLD Generator", "Document generated", result["filename"])
    return jsonify(result)


@bp.get("/api/download/<stored_name>")
def download(stored_name: str):
    path = service.output_path(stored_name)
    if not re.fullmatch(r"\d+_[a-f0-9]{32}\.docx", path.name) or not path.is_file():
        raise GenError("File tidak ditemukan", 404)
    name = re.sub(r"[^A-Za-z0-9 ._\-\[\]]+", "", request.args.get("name") or "") or "LLD_generated.docx"
    return send_file(path, as_attachment=True, download_name=name, mimetype=DOCX)


# ----------------------------------------------------------------- LLD Index hand-off, legacy import
@bp.post("/api/from-index")
def from_index():
    """Open an LLD Index build as a document: the export the build saved is
    imported into the project with the same customer, name and code (update),
    or into a new project on the master template."""
    from features.lld_index.routes import EXPORT_DIR, SAFE_ID

    body = _body()
    export_id = str(body.get("export_id") or "")
    path = EXPORT_DIR / f"{export_id}.xlsx"
    if not SAFE_ID.match(export_id) or not path.exists():
        raise GenError("Build the index again: the file is no longer available.", 404)
    result = service.from_index(str(path), body.get("project") or {}, body.get("template_id"))
    log_activity("LLD Generator", "Opened from LLD Index", f"project {result['project_id']} · {result['mode']}")
    return jsonify({"ok": True, **result, "url": f"/lld-generator?project={result['project_id']}"})


@bp.get("/api/legacy")
def legacy_status():
    root = service.find_legacy_folder(request.args.get("folder"))
    return jsonify({"folder": str(root) if root else ""})


@bp.post("/api/legacy-import")
def legacy_import():
    stats = service.legacy_import(_body().get("folder"))
    log_activity("LLD Generator", "Legacy import", f"{stats['projects']} projects, {stats['templates']} templates")
    return jsonify({"ok": True, **stats})
