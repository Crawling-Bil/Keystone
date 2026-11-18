"""Flask blueprint of the Sizing Tool (``/sizing-tool``)."""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import date
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, render_template, request, send_file
import io

from core.database import log_activity
from features.topology.ingest import IngestError
from features.topology.retention import prune_runs

from . import capture_pack, demo, imports as csv_imports, project
from .catalog import PEAK_FIELDS, all_links
from .classify import DEVICE_TYPES, TYPE_LABELS
from .evidence import confidence_summary, evidence
from .excel import bom_csv, to_xlsx
from . import candidates, summary as summary_page
from .tiers import coterm, licence_tiers
from .plan import ADDITIVE_PEAK_UNITS, DEFAULT_EXPIRY_MONTHS, compare, enrich, expiry, licence_models, logical_units, replacement_plan
from .project import clean_options
from .rollup import DEFAULT_GROWTH, build
from .service import MAX_FILES, finish, read_uploads

bp = Blueprint("sizing_tool", __name__, url_prefix="/sizing-tool")
BASE_DIR = Path(__file__).resolve().parents[2]
EXPORT_DIR = BASE_DIR / "exports" / "sizing"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
SAFE_ID = re.compile(r"^[a-f0-9]{32}$")
MAX_UPLOAD_BYTES = 200 * 1024 * 1024
KEEP_RUNS = 20


def _growth(raw: Any) -> float:
    try:
        return max(0.0, min(float(raw), 500.0))
    except (TypeError, ValueError):
        return float(DEFAULT_GROWTH)


def apply_overrides(assets: list[dict[str, Any]], overrides: dict[str, Any]) -> list[dict[str, Any]]:
    """What the user changed in the table: leave a device out, give it another type or site, keep a capture flagged as a duplicate.  A type outside the six is ignored."""
    out = []
    for asset in assets:
        change = overrides.get(asset["id"])
        change = change if isinstance(change, dict) else {}
        if change.get("exclude") or (asset.get("duplicate_of") and not change.get("keep_duplicate")):
            continue
        item = dict(asset)
        if change.get("device_type") in DEVICE_TYPES:
            item["device_type"] = change["device_type"]
        if isinstance(change.get("site"), str):
            item["site"] = change["site"].strip()[:40]
        out.append(item)
    return out


def _store(run_id: str, payload: dict[str, Any]) -> None:
    folder = EXPORT_DIR / run_id
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "run.json").write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def _load(run_id: str) -> dict[str, Any] | None:
    if not SAFE_ID.fullmatch(run_id or ""):
        return None
    try:
        return json.loads((EXPORT_DIR / run_id / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _options(body: dict[str, Any]) -> dict[str, Any]:
    """The editable settings of one request: ``body["options"]``, or the older top-level ``growth`` / ``overrides`` keys."""
    raw = dict(body.get("options") if isinstance(body.get("options"), dict) else {})
    for key in ("growth", "overrides"):
        if key in body and key not in raw:
            raw[key] = body[key]
    options = clean_options(raw)
    options.setdefault("growth", float(DEFAULT_GROWTH))
    return options


def compose(run: dict[str, Any], options: dict[str, Any], today: date | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """``(every asset with the imports merged, the assets that count, the roll-up and plans)``."""
    growth = _growth(options.get("growth", DEFAULT_GROWTH))
    full = enrich(run["assets"], run.get("imports"), options)
    kept = apply_overrides(full, options.get("overrides") or {})
    rollup = build(kept, growth)
    rollup["plan"] = replacement_plan(kept, options, growth)
    rollup["expiry"] = expiry(kept, int(options.get("expiry_months") or DEFAULT_EXPIRY_MONTHS), today)
    rollup["licence_models"] = licence_models(kept)
    rollup["tiers"] = licence_tiers(kept)
    rollup["coterm"] = coterm(kept, today)
    rollup["units"] = logical_units(kept)
    rollup["confidence"] = confidence_summary(kept)
    rollup["peaks"] = peak_table(kept)
    rollup["lifecycle"] = [{"hostname": a["hostname"] or a["source"], "device_model": a["model"], **a["lifecycle"]} for a in kept if a.get("lifecycle")]
    rollup["summary"]["duplicates"] = sum(1 for a in full if a.get("duplicate_of"))
    return full, kept, rollup


def peak_table(assets: list[dict[str, Any]]) -> dict[str, Any]:
    """Peak figures per device type (sum where they add up, largest single device) and the devices of a type that have none."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for asset in assets:
        for label, peak in (asset.get("peaks") or {}).items():
            entry = rows.setdefault((asset["device_type"], label), {"device_type": asset["device_type"], "label": label, "unit": peak.get("unit", ""), "sum": 0.0, "max": 0.0, "devices": 0,
                                                                   "sources": set()})
            entry["sum"] += peak["value"]
            entry["max"] = max(entry["max"], peak["value"])
            entry["devices"] += 1
            entry["sources"].add(peak.get("source", ""))
    wanting = [a for a in assets if a["device_type"] in ("firewall", "load_balancer", "router") and not a.get("peaks")]
    return {"rows": [{**v, "sources": sorted(v["sources"]), "adds_up": v["unit"] in ADDITIVE_PEAK_UNITS} for v in sorted(rows.values(), key=lambda r: (r["device_type"], r["label"]))],
            "missing": [{"hostname": a["hostname"] or a["source"], "device_type": a["device_type"], "id": a["id"]} for a in wanting][:200], "missing_total": len(wanting)}


def _answer(run_id: str, run: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
    full, kept, rollup = compose(run, options)
    return {"ok": True, "run_id": run_id, "name": run.get("name", ""), "assets": kept, "all_assets": full, "skipped": run.get("skipped", []), "rollup": rollup,
            "type_labels": TYPE_LABELS, "sources": run.get("sources", []), "options": options, "imports_report": run.get("imports_report", {}),
            "evidence": {a["id"]: evidence(a) for a in full}, "peak_fields": PEAK_FIELDS}


@bp.get("")
@bp.get("/")
def page():
    return render_template("sizing_tool.html", active_page="sizing", max_files=MAX_FILES, default_growth=DEFAULT_GROWTH, type_labels=TYPE_LABELS, device_types=DEVICE_TYPES)


@bp.get("/api/demo")
def demo_route():
    return jsonify({"ok": True, "sets": demo.list_sets()})


@bp.get("/api/links")
def links_route():
    return jsonify({"ok": True, "links": all_links()})


def _uploads() -> tuple[list[tuple[str, bytes]], str]:
    uploads: list[tuple[str, bytes]] = []
    total = 0
    for item in request.files.getlist("files"):
        data = item.read()
        total += len(data)
        if total > MAX_UPLOAD_BYTES:
            return [], f"The files are larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB together. Upload fewer at a time."
        uploads.append((item.filename or "capture.txt", data))
    return uploads, ""


def _missing() -> Any:
    return jsonify({"ok": False, "error": "This run has been removed. Analyze the captures again, or open the project file you saved."}), 404


def _json_options(raw: str) -> dict[str, Any]:
    try:
        return _options({"options": json.loads(raw)}) if raw else _options({})
    except ValueError:
        return _options({})


@bp.post("/api/analyze")
def analyze_route():
    uploads, error = _uploads()
    if error:
        return jsonify({"ok": False, "error": error}), 400
    sources = []
    for set_id in [s for s in request.form.get("demo", "").split(",") if s.strip()]:
        files = demo.read_set(set_id.strip())
        if not files:
            return jsonify({"ok": False, "error": f"Unknown demo set: {set_id[:60]}"}), 400
        uploads.extend(files)
        sources.append(set_id.strip())
    if not uploads:
        return jsonify({"ok": False, "error": "Add device captures or choose a demo set first."}), 400
    try:
        assets, skipped = read_uploads(uploads)
    except IngestError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if not assets:
        return jsonify({"ok": False, "error": "No device could be read from these files.", "skipped": skipped}), 400
    run_id = uuid.uuid4().hex
    name = request.form.get("name", "").strip()[:60]
    run = {"name": name, "assets": assets, "skipped": skipped, "sources": sources, "imports": {}, "imports_report": {}}
    _store(run_id, run)
    prune_runs(EXPORT_DIR, keep=KEEP_RUNS, max_age_days=30, protect=run_id)
    log_activity("Sizing Tool", "Sizing run built", f"{len(assets)} device(s)")
    options = _options({"growth": _growth(request.form.get("growth"))})
    return jsonify(_answer(run_id, run, options))


@bp.post("/api/add")
def add_route():
    """More captures into a run that is already open: the new devices are numbered on, the same serial as a device already in the run is flagged, nothing is read again."""
    run = _load(request.form.get("run_id", ""))
    if run is None:
        return _missing()
    uploads, error = _uploads()
    if error:
        return jsonify({"ok": False, "error": error}), 400
    if not uploads:
        return jsonify({"ok": False, "error": "Add device captures first."}), 400
    try:
        assets, skipped = read_uploads(uploads)
    except IngestError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    if len(run["assets"]) + len(assets) > MAX_FILES * 5:
        return jsonify({"ok": False, "error": "The run would hold too many devices. Start a new run."}), 400
    renumbered = []
    numbers = [int(a["id"][1:]) for a in run["assets"] if re.fullmatch(r"d\d+", a["id"])]
    counter = max(numbers, default=0)
    for asset in assets:
        counter += 1
        asset["id"] = f"d{counter}"
        asset["duplicate_of"] = ""
        renumbered.append(asset)
    run["assets"] = run["assets"] + renumbered
    run["skipped"] = (run.get("skipped") or []) + skipped
    finish(run["assets"])
    _store(request.form.get("run_id", ""), run)
    answer = _answer(request.form.get("run_id", ""), run, _json_options(request.form.get("options", "")))
    answer["added"] = len(assets)
    return jsonify(answer)


@bp.post("/api/rollup")
def rollup_route():
    """The same run with other settings (growth, spare, redundancy, per-unit capacity, typed peaks, devices left out or retyped): nothing is read again."""
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    return jsonify(_answer(str(body["run_id"]), run, _options(body)))


@bp.post("/api/import")
def import_route():
    """A CSV the architect brings: ``kind`` is site_map, peaks, entitlements or lifecycle.  The answer says which column was taken for which field and how many rows matched."""
    run_id = request.form.get("run_id", "")
    run = _load(run_id)
    if run is None:
        return _missing()
    kind = request.form.get("kind", "")
    upload = request.files.get("file")
    if kind not in ("site_map", "peaks", "entitlements", "lifecycle") or upload is None:
        return jsonify({"ok": False, "error": "Choose what the file is (site map, peaks, licence entitlements, lifecycle) and a CSV file."}), 400
    data = upload.read(csv_imports.MAX_CSV_BYTES + 1)
    try:
        text = data.decode("utf-8-sig", errors="replace")
        importer = {"site_map": csv_imports.import_site_map, "peaks": csv_imports.import_peaks, "entitlements": csv_imports.import_entitlements, "lifecycle": csv_imports.import_lifecycle}[kind]
        found, report = importer(text, run["assets"])
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    stored = run.setdefault("imports", {})
    stored[kind] = found                                           # a second file of the same kind replaces the first
    run.setdefault("imports_report", {})[kind] = report
    _store(run_id, run)
    answer = _answer(run_id, run, _json_options(request.form.get("options", "")))
    answer["report"] = report
    return jsonify(answer)


@bp.post("/api/import/clear")
def import_clear_route():
    body = request.get_json(silent=True) or {}
    run_id = str(body.get("run_id", ""))
    run = _load(run_id)
    if run is None:
        return _missing()
    kind = str(body.get("kind", ""))
    (run.get("imports") or {}).pop(kind, None)
    (run.get("imports_report") or {}).pop(kind, None)
    _store(run_id, run)
    return jsonify(_answer(run_id, run, _options(body)))


@bp.post("/api/export")
def export_route():
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    options = _options(body)
    full, kept, rollup = compose(run, options)
    data = to_xlsx(kept, rollup, run.get("name", ""), evidence_rows={a["id"]: evidence(a) for a in kept})
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", run.get("name", "")).strip("-") or "sizing"
    return send_file(io.BytesIO(data), as_attachment=True, download_name=f"keystone-{stem}.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@bp.post("/api/export-bom")
def export_bom_route():
    """The bill of materials as a CSV a quoting tool can import: one line per part, quantity today and with growth, an empty column for the replacement part number."""
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    options = _options(body)
    full, kept, rollup = compose(run, options)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", run.get("name", "")).strip("-") or "sizing"
    return send_file(io.BytesIO(bom_csv(rollup["bom"], rollup["growth"]).encode("utf-8-sig")), as_attachment=True, download_name=f"keystone-{stem}-bom.csv", mimetype="text/csv")


@bp.post("/api/summary")
def summary_route():
    """The one-page summary for the customer (HTML, prints on A4)."""
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    full, kept, rollup = compose(run, _options(body))
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", run.get("name", "")).strip("-") or "sizing"
    html = summary_page.render(run.get("name", ""), kept, rollup)
    return send_file(io.BytesIO(html.encode("utf-8")), as_attachment=True, download_name=f"keystone-{stem}-summary.html", mimetype="text/html")


@bp.post("/api/candidates/export")
def candidates_export_route():
    body = request.get_json(silent=True) or {}
    text = candidates.dumps(body.get("library") if isinstance(body.get("library"), list) else [])
    return send_file(io.BytesIO(text.encode("utf-8")), as_attachment=True, download_name="keystone-candidates.json", mimetype="application/json")


@bp.post("/api/candidates/import")
def candidates_import_route():
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"ok": False, "error": "Choose a candidate library file."}), 400
    try:
        library = candidates.loads(upload.read(candidates.MAX_BYTES + 1))
    except candidates.LibraryError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "library": library})


@bp.post("/api/candidates/compare")
def candidates_compare_route():
    """One group of the replacement plan sized with each of two candidate models: the units, the limiting quantity and how full each unit is."""
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    entries = [candidates.clean_entry({**(c if isinstance(c, dict) else {}), "name": (c or {}).get("name") or f"Candidate {n}"}) for n, c in enumerate((body.get("candidates") or [])[:2], 1)] if isinstance(body.get("candidates"), list) else []
    key = str(body.get("group", ""))
    if len(entries) != 2 or None in entries or not key:
        return jsonify({"ok": False, "error": "Choose a group and two candidates that each have a name and at least one capacity."}), 400
    options = _options(body)
    full, kept, rollup = compose(run, options)
    growth = rollup["growth"]
    plans = []
    for entry in entries:
        trial = {**options, "profiles": {**(options.get("profiles") or {}), key: entry["capacity"]}}
        found = next((p for p in replacement_plan(kept, trial, growth) if p["key"] == key), None)
        if found is None:
            return jsonify({"ok": False, "error": "That group is not in this run."}), 404
        plans.append(found)
    return jsonify({"ok": True, "comparison": candidates.compare(plans, key, (entries[0]["name"], entries[1]["name"]))})


@bp.post("/api/project/save")
def project_save_route():
    body = request.get_json(silent=True) or {}
    run = _load(str(body.get("run_id", "")))
    if run is None:
        return _missing()
    text = project.dumps(run.get("name", ""), run["assets"], run.get("skipped", []), run.get("sources", []), run.get("imports", {}), _options(body))
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", run.get("name", "")).strip("-") or "sizing"
    return send_file(io.BytesIO(text.encode("utf-8")), as_attachment=True, download_name=f"keystone-{stem}.sizing.json", mimetype="application/json")


@bp.post("/api/project/open")
def project_open_route():
    upload = request.files.get("file")
    if upload is None:
        return jsonify({"ok": False, "error": "Choose a saved project file (.sizing.json)."}), 400
    try:
        data = project.loads(upload.read(project.MAX_BYTES + 1))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    run_id = uuid.uuid4().hex
    run = {"name": data["name"], "assets": data["assets"], "skipped": data["skipped"], "sources": data["sources"], "imports": data["imports"], "imports_report": {}}
    _store(run_id, run)
    prune_runs(EXPORT_DIR, keep=KEEP_RUNS, max_age_days=30, protect=run_id)
    options = data["options"]
    options.setdefault("growth", float(DEFAULT_GROWTH))
    return jsonify(_answer(run_id, run, options))


@bp.get("/api/runs")
def runs_route():
    out = []
    for folder in sorted(EXPORT_DIR.glob("*/run.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:KEEP_RUNS]:
        run = _load(folder.parent.name)
        if run:
            out.append({"run_id": folder.parent.name, "name": run.get("name", "") or "(unnamed)", "devices": len(run.get("assets", [])), "saved": time.strftime("%Y-%m-%d %H:%M", time.localtime(folder.stat().st_mtime))})
    return jsonify({"ok": True, "runs": out})


@bp.post("/api/compare")
def compare_route():
    """Two runs side by side (before and after a refresh, or last quarter and now): ``other_run_id`` of a run still kept, or an uploaded project file as ``project``."""
    run_id = request.form.get("run_id", "")
    run = _load(run_id)
    if run is None:
        return _missing()
    other_id = request.form.get("other_run_id", "")
    upload = request.files.get("project")
    if upload is not None:
        try:
            other = project.loads(upload.read(project.MAX_BYTES + 1))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        other_name = other["name"] or upload.filename or "project file"
    else:
        other = _load(other_id)
        if other is None or other_id == run_id:
            return jsonify({"ok": False, "error": "Choose another run or a project file to compare with."}), 400
        other_name = other.get("name", "") or "earlier run"
    options = _json_options(request.form.get("options", ""))
    _, kept_now, _ = compose(run, options)
    _, kept_other, _ = compose(other, options)
    result = compare(kept_other, kept_now)
    result.update(ok=True, before_name=other_name, after_name=run.get("name", "") or "this run")
    return jsonify(result)


@bp.get("/api/capture-packs")
def capture_packs_route():
    return jsonify({"ok": True, "packs": capture_pack.packs_for(), "documented_only": sorted(capture_pack.DOCUMENTED_ONLY)})


@bp.get("/api/capture-pack.txt")
def capture_pack_download_route():
    ids = [i for i in request.args.get("ids", "").split(",") if i.strip()]
    text = capture_pack.as_text(ids or None)
    return send_file(io.BytesIO(text.encode("utf-8")), as_attachment=True, download_name="keystone-sizing-capture-pack.txt", mimetype="text/plain")
