"""Flask blueprint for the Topology Builder (``/topology``)."""

from __future__ import annotations

import logging
import re
import datetime as _dt
import uuid
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core.database import log_activity
from .ingest import IngestError, to_captures
from .excel import to_xlsx
from .drawio import legend_rows
from .layout_io import read_layout
from .report import bundles_table, build_report, download_name, make_pack, safe_name, settings_text, slug
from .service import (GROUP_MODES, MAX_FILES, behind_table, build_topology, devices_table, hosts_table, links_table, to_csv, to_json)
from .state import StateError, read_state

log = logging.getLogger(__name__)
bp = Blueprint("topology", __name__, url_prefix="/topology")
BASE_DIR = Path(__file__).resolve().parents[2]
EXPORT_DIR = BASE_DIR / "exports" / "topology"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
SAFE_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")
MAX_UPLOAD_BYTES = 200 * 1024 * 1024    # one ZIP may hold many captures; every member is limited again in ingest.py
EXPORT_NAMES = {
    "keystone-topology-pack.zip": "application/zip",
    "topology-report.html": "text/html",
    "topology.drawio": "application/vnd.jgraph.mxfile",
    "topology.xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "links.csv": "text/csv",
    "devices.csv": "text/csv",
    "hosts.csv": "text/csv",
    "behind.csv": "text/csv",
    "bundles.csv": "text/csv",
    "findings.csv": "text/csv",
    "topology.json": "application/json",
    "run-settings.txt": "text/plain",
}
PACK_README = (
    "Keystone Topology Builder - documentation pack\r\n\r\n"
    "topology-report.html   Open in a browser. Print to PDF (landscape A4) for a document: diagrams, findings, inventory, bundles and one page per device.\r\n"
    "diagrams/              One SVG per diagram page (physical view, vPC view and IP view).\r\n"
    "topology.drawio        Editable diagram for diagrams.net. Move things, then upload it again under 'Keep my layout'.\r\n"
    "topology.xlsx          All tables in one workbook.\r\n"
    "tables/                The same tables as CSV.\r\n"
    "topology.json          Tables plus the saved state. Upload it under 'Add to a previous run' to continue with more captures.\r\n"
    "run-settings.txt       The options that were set on the page for this run (also in topology.json under 'build' and in the report). Send it with a question or a bug report.\r\n"
)
LINE_STYLES = ("state", "speed")
VIEWS = ("both", "physical", "logical", "ip")


@bp.get("")
def page():
    return render_template("topology.html", active_page="topology", group_modes=GROUP_MODES, max_files=MAX_FILES)


@bp.post("/api/build")
def build_route():
    try:
        return _build()
    except Exception as exc:    # a failure must reach the page as a readable message, not as an HTML error page
        log.exception("Topology build failed")
        return jsonify({"ok": False, "error": f"The topology could not be built ({exc.__class__.__name__}: {str(exc)[:300]}). "
                                              "The full details are in the Keystone terminal window."}), 500


def _topology_name() -> str:
    """The optional name typed on the page: letters, digits, dot, dash and underscore only, at most 60 characters ('' when empty)."""
    return safe_name(request.form.get("name", ""))


def _build():
    uploads = [u for u in request.files.getlist("files") if u and u.filename]
    saved = request.files.get("previous_state")
    carried = None
    if saved and saved.filename:
        try:
            carried = read_state(saved.read(120 * 1024 * 1024 + 1))
        except StateError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
    if not uploads and not carried:
        return jsonify({"ok": False, "error": "Select at least one device capture (.txt, .log, .cfg or a .zip of them)."}), 400
    if len(uploads) > MAX_FILES:
        return jsonify({"ok": False, "error": f"Upload at most {MAX_FILES} files at a time."}), 400
    try:
        payloads = [(secure_filename(u.filename) or "capture.txt", u.read(MAX_UPLOAD_BYTES + 1)) for u in uploads]
        too_big = next((n for n, d in payloads if len(d) > MAX_UPLOAD_BYTES), "")
        if too_big:
            raise IngestError(f"{too_big} is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        files = to_captures(payloads, MAX_FILES)
    except IngestError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    group = request.form.get("group", "none")
    if group not in {value for value, _ in GROUP_MODES}:
        group = "none"
    layout = None
    previous = request.files.get("previous")
    if previous and previous.filename:
        try:
            layout = read_layout(previous.read(30 * 1024 * 1024 + 1))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
    line_style = request.form.get("line_style", "speed") if request.form.get("line_style") in LINE_STYLES else "speed"
    name_text = request.form.get("name", "").strip()[:60]
    created = _dt.datetime.now()
    result = build_topology(
        files, group=group,
        collapse_endpoints=request.form.get("collapse_endpoints", "1") != "0",
        collapse_aps=request.form.get("collapse_aps", request.form.get("collapse_endpoints", "1")) != "0",
        exclude_endpoints=request.form.get("exclude_endpoints", "0") == "1",
        show_ports=request.form.get("show_ports", "1") != "0",
        infer_neighbors_from_arp=request.form.get("infer_neighbors", "1") != "0",
        name=name_text, created=created,
        include_hosts=request.form.get("include_hosts", "0") == "1",
        include_routed=request.form.get("include_routed", "1") != "0",
        layout=layout, previous=carried,
        line_style=line_style,
        view=request.form.get("view", "both") if request.form.get("view") in VIEWS else "both",
        hide_mgmt=request.form.get("hide_mgmt", "1") != "0",
    )
    graph = result["graph"]
    if not graph.nodes:
        return jsonify({"ok": False, "error": "No device could be read from these files.", "skipped": result["skipped"]}), 400
    export_id = uuid.uuid4().hex
    target = EXPORT_DIR / export_id
    target.mkdir(parents=True, exist_ok=True)
    devices, links, hosts, behind, bundles = devices_table(graph), links_table(graph), hosts_table(graph), behind_table(graph), bundles_table(graph)
    findings_rows = [{**{k: v for k, v in f.items() if k != "devices"}, "devices": ", ".join(f["devices"])} for f in result["findings"]]
    (target / "topology.drawio").write_text(result["drawio"], encoding="utf-8")
    (target / "devices.csv").write_text(to_csv(devices), encoding="utf-8-sig")
    (target / "links.csv").write_text(to_csv(links), encoding="utf-8-sig")
    (target / "findings.csv").write_text(to_csv(findings_rows), encoding="utf-8-sig")
    (target / "hosts.csv").write_text(to_csv(hosts), encoding="utf-8-sig")
    (target / "behind.csv").write_text(to_csv(behind), encoding="utf-8-sig")
    (target / "bundles.csv").write_text(to_csv(bundles), encoding="utf-8-sig")
    (target / "topology.xlsx").write_bytes(to_xlsx(result["summary"], devices, links, hosts, result["findings"], behind, bundles))
    (target / "topology.json").write_text(to_json(graph, result["findings"], result["devices"], result["settings"]), encoding="utf-8")
    report = build_report(graph, result["summary"], result["findings"], devices, links, hosts, behind, result["svgs"], result["skipped"],
                          title=name_text or "Network topology documentation", settings=result["settings"])
    (target / "run-settings.txt").write_text(settings_text(result["settings"], result["summary"]), encoding="utf-8")
    (target / "_name.txt").write_text(_topology_name(), encoding="utf-8")
    (target / "topology-report.html").write_text(report, encoding="utf-8")
    pack = {"README.txt": PACK_README, "topology-report.html": report}
    for name in ("topology.drawio", "topology.xlsx", "topology.json", "run-settings.txt", "links.csv", "devices.csv", "hosts.csv", "behind.csv", "bundles.csv", "findings.csv"):
        pack[("tables/" if name.endswith(".csv") else "") + name] = (target / name).read_bytes()
    for number, page in enumerate(result["svgs"], 1):
        pack[f"diagrams/{number:02d}-{slug(page['name'])}.svg"] = page["svg"]
    (target / "keystone-topology-pack.zip").write_bytes(make_pack(pack))
    log_activity("Topology Builder", "Topology built", f"{result['summary']['captured']} device(s) · {result['summary']['links']} link(s)")
    return jsonify({
        "ok": True, "export_id": export_id, "summary": result["summary"], "findings": result["findings"],
        "skipped": result["skipped"], "pages": result["svgs"], "devices": devices, "links": links, "hosts": hosts, "behind": behind, "bundles": bundles,
        "legend": {"physical": legend_rows(line_style, False), "logical": legend_rows(line_style, True), "ip": legend_rows(line_style, "ip")},
        "downloads": [{"name": name, "filename": download_name(name, _topology_name()), "url": f"/topology/api/export/{export_id}/{name}"} for name in EXPORT_NAMES],
    })


@bp.get("/api/export/<export_id>/<name>")
def export_file(export_id: str, name: str):
    if not SAFE_IDENTIFIER.match(export_id) or name not in EXPORT_NAMES:
        return jsonify({"ok": False, "error": "Unknown export."}), 404
    folder = EXPORT_DIR / export_id
    if not (folder / name).is_file():
        return jsonify({"ok": False, "error": "This export has been removed. Build the topology again."}), 404
    try:
        prefix = (folder / "_name.txt").read_text(encoding="utf-8")
    except OSError:
        prefix = ""
    return send_from_directory(folder, name, as_attachment=True, mimetype=EXPORT_NAMES[name], download_name=download_name(name, safe_name(prefix)))
