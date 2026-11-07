"""Flask blueprint for the Topology Builder (``/topology``)."""

from __future__ import annotations

import io
import json
import logging
import re
import datetime as _dt
import uuid
import zipfile
from pathlib import Path
from typing import Any

from flask import Blueprint, current_app, jsonify, render_template, request, send_from_directory
from werkzeug.utils import secure_filename

from core.database import log_activity
from . import demo, history, progress
from .ingest import IngestError, to_captures
from .anonymize import anonymize, find_leftovers
from .excel import to_xlsx
from .diff import DiffError, compare_runs, load_run
from .drawio import legend_rows
from .howto import html as howto_html
from .l3trace import trace
from .layout_io import read_layout
from .priority import COLUMNS as PRIORITY_COLUMNS, capture_priority
from .runbook import RunbookError, build_runbook
from . import evidence
from .report import build_print_set, bundles_table, build_report, download_name, make_pack, safe_name, settings_text, slug
from .retention import DEFAULT_KEEP, DEFAULT_MAX_AGE_DAYS, prune_runs
from .service import (GROUP_MODES, MAX_FILES, behind_table, build_topology, devices_table, hosts_table, links_table, read_devices, to_csv, to_json)
from .state import StateError, merge, read_state

log = logging.getLogger(__name__)
bp = Blueprint("topology", __name__, url_prefix="/topology")
BASE_DIR = Path(__file__).resolve().parents[2]
EXPORT_DIR = BASE_DIR / "exports" / "topology"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
SAFE_IDENTIFIER = re.compile(r"^[a-f0-9]{32}$")
MAX_DIFF_BYTES = 150 * 1024 * 1024        # one topology.json, or a pack ZIP that holds one
MAX_UPLOAD_BYTES = 200 * 1024 * 1024    # one ZIP may hold many captures; every member is limited again in ingest.py
ANON_ZIP = "keystone-topology-pack-anonymized.zip"
EXPORT_NAMES = {
    "keystone-topology-pack.zip": "application/zip",
    "topology-report.html": "text/html",
    "topology-print-a3.html": "text/html",
    ANON_ZIP: "application/zip",
    "anonymization-map.csv": "text/csv",
    "topology.drawio": "application/vnd.jgraph.mxfile",
    "topology.xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "links.csv": "text/csv",
    "devices.csv": "text/csv",
    "hosts.csv": "text/csv",
    "behind.csv": "text/csv",
    "capture-priority.csv": "text/csv",
    "bundles.csv": "text/csv",
    "findings.csv": "text/csv",
    "findings-by-device.csv": "text/csv",
    "l3-links.csv": "text/csv",
    "l3-routes.csv": "text/csv",
    "l3-sdwan-overlay.csv": "text/csv",
    "l3-sdwan-sites.csv": "text/csv",
    "topology.json": "application/json",
    "run-settings.txt": "text/plain",
}
PACK_README = (
    "Keystone Topology Builder - documentation pack\r\n\r\n"
    "topology-report.html   Open in a browser. Print to PDF (landscape A4) for a document: diagrams, findings, inventory, bundles and one page per device.\r\n"
    "topology-print-a3.html One sheet per diagram page, each scaled to one A3 landscape sheet. Open in a browser and print to PDF (A3, no scaling), or print a range of sheets for the wall and the folder.\r\n"
    "diagrams/              One SVG per diagram page (L3 over L2, L3 route view, IP view, physical view and vPC view, as far as the captures allow).\r\n"
    "topology.drawio        Editable diagram for diagrams.net, one page per view (with 'All views': L3 over L2, L3 route, IP, physical, vPC). Move things, then upload it again under 'Keep my layout'.\r\n"
    "topology.xlsx          All tables in one workbook.\r\n"
    "tables/                The same tables as CSV (findings-by-device.csv rolls the findings up per device; capture-priority.csv lists the captures to take next).\r\n"
    "topology.json          Tables plus the saved state. Upload it under 'Add to a previous run' to continue with more captures.\r\n"
    "run-settings.txt       The options that were set on the page for this run (also in topology.json under 'build' and in the report). Send it with a question or a bug report.\r\n"
    "MANIFEST.sha256        SHA-256 of every file of this pack (sha256sum format).\r\n"
    "audit/                 Audit evidence: the control table (CIS, NIST, PCI DSS, ISO 27001) and the hashes of the captures. Read audit/README.txt.\r\n"
)
ANON_README = (
    "Keystone Topology Builder - ANONYMIZED documentation pack\r\n\r\n"
    "Hostnames, domain names, file names, port descriptions, VRF and F5 object names, IP addresses, MAC addresses and serial numbers were replaced by pseudonyms,\r\n"
    "the same way everywhere in this pack. IP addresses keep their subnet structure, MAC addresses keep the vendor prefix, role words (FW, CORE, SW) and\r\n"
    "port names stay. Models, software versions, VLAN IDs, AS numbers, SD-WAN site IDs and states are original.\r\n"
    "The key (anonymization-map.csv) is a separate download. Keep it on this computer and do not send it with this pack.\r\n"
    "Read the pack once before you share it: names can hide in places no tool knows about.\r\n\r\n"
    "topology-report.html   Open in a browser. Print to PDF (landscape A4) for a document.\r\n"
    "diagrams/              One SVG per diagram page.\r\n"
    "topology.drawio        Editable diagram for diagrams.net.\r\n"
    "topology.xlsx          All tables in one workbook.\r\n"
    "tables/                The same tables as CSV.\r\n"
    "topology.json          Tables plus the saved state, with the pseudonyms; it can be uploaded under 'Add to a previous run'.\r\n"
    "run-settings.txt       The options of the run.\r\n"
    "MANIFEST.sha256        SHA-256 of every file of this pack (sha256sum format).\r\n"
    "audit/                 The control table (CIS, NIST, PCI DSS, ISO 27001). Read audit/README.txt.\r\n"
)
LINE_STYLES = ("state", "speed")
LINE_SHAPES = ("angled", "curved")
VIEWS = ("all", "both", "physical", "logical", "ip", "l3route", "l3over2", "f5map")
OVERLAY_SITES = ("captured", "all")
DEFAULT_VIEW = "all"


def _legend_extras(result) -> tuple:
    """The VRF colour rows of the L3 legends: every row once, whichever L3 page of the build carries it."""
    rows: list = []
    for page in list(result["l3_pages"]) + list(result.get("l3_extra_pages", [])):
        for extra in page.legend_extra:
            if tuple(extra) not in rows:
                rows.append(tuple(extra))
    return tuple(rows)


@bp.get("")
def page():
    return render_template("topology.html", active_page="topology", group_modes=GROUP_MODES, max_files=MAX_FILES)


@bp.post("/api/build")
def build_route():
    build = progress.start(request.form.get("progress_id", ""))      # the page polls /api/progress/<id> while this request runs
    try:
        return _build(build)
    except Exception as exc:    # a failure must reach the page as a readable message, not as an HTML error page
        log.exception("Topology build failed")
        return jsonify({"ok": False, "error": f"The topology could not be built ({exc.__class__.__name__}: {str(exc)[:300]}). "
                                              "The full details are in the Keystone terminal window."}), 500
    finally:
        if build is not None and not build.done:
            progress.finish(build, "Stopped")


@bp.get("/api/progress/<build_id>")
def progress_route(build_id: str):
    return jsonify(progress.status(build_id) if progress.ID_RE.fullmatch(build_id) else {"known": False, "percent": 0, "label": "", "detail": "", "done": False, "seconds": 0})


def _topology_name() -> str:
    """The optional name typed on the page: letters, digits, dot, dash and underscore only, at most 60 characters ('' when empty)."""
    return safe_name(request.form.get("name", ""))


def _write_run(target: Path, result: dict[str, Any], name_text: str, readme: str = PACK_README, inputs: list | None = None) -> dict[str, Any]:
    """Write every file of one build into ``target`` (CSVs, workbook, JSON, draw.io, report, settings, pack ZIP); returns the tables and the pack content."""
    graph = result["graph"]
    devices, links, hosts, behind, bundles = devices_table(graph), links_table(graph), hosts_table(graph), behind_table(graph), bundles_table(graph)
    progress.report("write", 0.0, "Tables")
    priority = capture_priority(graph)
    findings_rows = [{**{k: v for k, v in f.items() if k != "devices"}, "devices": ", ".join(f["devices"])} for f in result["findings"]]
    (target / "topology.drawio").write_text(result["drawio"], encoding="utf-8")
    (target / "devices.csv").write_text(to_csv(devices), encoding="utf-8-sig", newline="")
    (target / "links.csv").write_text(to_csv(links), encoding="utf-8-sig", newline="")
    (target / "findings.csv").write_text(to_csv(findings_rows), encoding="utf-8-sig", newline="")
    (target / "findings-by-device.csv").write_text(to_csv(result["findings_by_device"]), encoding="utf-8-sig", newline="")
    (target / "hosts.csv").write_text(to_csv(hosts), encoding="utf-8-sig", newline="")
    (target / "behind.csv").write_text(to_csv(behind), encoding="utf-8-sig", newline="")
    (target / "bundles.csv").write_text(to_csv(bundles), encoding="utf-8-sig", newline="")
    if priority:
        (target / "capture-priority.csv").write_text(to_csv(priority), encoding="utf-8-sig", newline="")
    l3 = {"links": result["l3_links"], "routes": result["l3_routes"], "unresolved": result["l3_unresolved"], "overlay": result["l3_overlay"], "sites": result["l3_sites"]}
    if result["l3_links"]:
        (target / "l3-links.csv").write_text(to_csv(result["l3_links"]), encoding="utf-8-sig", newline="")
        (target / "l3-routes.csv").write_text(to_csv(result["l3_routes"]), encoding="utf-8-sig", newline="")
        if result["l3_overlay"]:
            (target / "l3-sdwan-overlay.csv").write_text(to_csv(result["l3_overlay"]), encoding="utf-8-sig", newline="")
            (target / "l3-sdwan-sites.csv").write_text(to_csv(result["l3_sites"]), encoding="utf-8-sig", newline="")
        (target / "_trace.json").write_text(json.dumps(result["l3_trace"], separators=(",", ":")), encoding="utf-8")
    progress.report("write", 0.3, "Excel workbook")
    (target / "topology.xlsx").write_bytes(to_xlsx(result["summary"], devices, links, hosts, result["findings"], behind, bundles, result["findings_by_device"], l3, priority))
    (target / "topology.json").write_text(to_json(graph, result["findings"], result["devices"], result["settings"]), encoding="utf-8")
    progress.report("write", 0.6, "Report")
    report = build_report(graph, result["summary"], result["findings"], devices, links, hosts, behind, result["svgs"], result["skipped"],
                          title=name_text or "Network topology documentation", settings=result["settings"], l3=l3, notices=result["notices"], priority=priority)
    (target / "run-settings.txt").write_text(settings_text(result["settings"], result["summary"], result["notices"]), encoding="utf-8")
    (target / "topology-report.html").write_text(report, encoding="utf-8")
    print_set = build_print_set(result["svgs"], name_text or "Network topology documentation", result["settings"].get("created", ""))
    (target / "topology-print-a3.html").write_text(print_set, encoding="utf-8")
    pack = {"README.txt": readme, "topology-report.html": report, "topology-print-a3.html": print_set}
    for name in ("topology.drawio", "topology.xlsx", "topology.json", "run-settings.txt", "links.csv", "devices.csv", "hosts.csv", "behind.csv", "bundles.csv", "capture-priority.csv", "findings.csv", "findings-by-device.csv", "l3-links.csv", "l3-routes.csv", "l3-sdwan-overlay.csv", "l3-sdwan-sites.csv"):
        if not (target / name).is_file():
            continue
        pack[("tables/" if name.endswith(".csv") else "") + name] = (target / name).read_bytes()
    for number, page in enumerate(result["svgs"], 1):
        pack[f"diagrams/{number:02d}-{slug(page['name'])}.svg"] = page["svg"]
    progress.report("write", 0.9, "Pack (zip)")
    pack["audit/controls.csv"] = to_csv(evidence.control_rows(result["findings"], name_text or "Network topology")).encode("utf-8-sig")
    if inputs:
        pack["audit/inputs.sha256"] = evidence.inputs_text(inputs)
    pack["audit/README.txt"] = evidence.audit_readme(bool(inputs))
    pack["MANIFEST.sha256"] = evidence.manifest_text(pack)
    archive = make_pack(pack)
    (target / "keystone-topology-pack.zip").write_bytes(archive)
    (target / "keystone-topology-pack.zip.sha256").write_text(f"{evidence.sha256_hex(archive)}  keystone-topology-pack.zip\n", encoding="ascii")
    progress.report("write", 1.0, "")
    return {"devices": devices, "links": links, "hosts": hosts, "behind": behind, "bundles": bundles, "priority": priority, "pack": pack}


def _download_filename(name: str, topology_name: str) -> str:
    """The name a file is saved under. The anonymized pack never carries the topology name: the name is one of the things that was replaced."""
    return name if name == ANON_ZIP else download_name(name, topology_name)


def _pack_texts(pack: dict[str, Any]) -> dict[str, str]:
    """The text inside every file of a pack, for the leftover scan (the workbook is read from the strings it stores)."""
    texts: dict[str, str] = {}
    for name, content in pack.items():
        if name.endswith(".xlsx"):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as book:
                    texts[name] = " ".join(book.read(member).decode("utf-8", "replace") for member in book.namelist() if member.endswith(".xml"))
            except zipfile.BadZipFile:
                texts[name] = ""
        else:
            texts[name] = content.decode("utf-8", "replace") if isinstance(content, bytes) else content
    return texts


def _write_anonymized(target: Path, files: list, carried: list | None, options: dict[str, Any], created: _dt.datetime) -> dict[str, Any]:
    """The pseudonymized twin of the build: the same options, built again from the devices with every name and address replaced.
    Writes ``keystone-topology-pack-anonymized.zip`` and the key ``anonymization-map.csv`` (kept apart: it holds the originals) into ``target``."""
    devices, _ = read_devices(files)
    if carried:
        devices, _ = merge(carried, devices)
    anon = anonymize(devices, title=request.form.get("name", "").strip()[:60], hints=options["provider_hints"])
    twin = build_topology([], name=anon.title, created=created, devices=anon.devices, **{**options, "provider_hints": anon.hints, "site_rules": ""})
    folder = target / "_anonymized"
    folder.mkdir(parents=True, exist_ok=True)
    tables = _write_run(folder, twin, anon.title, ANON_README)
    leftovers = find_leftovers(anon, _pack_texts(tables["pack"]))
    (target / ANON_ZIP).write_bytes((folder / "keystone-topology-pack.zip").read_bytes())
    rows = anon.mapping + [{"kind": "LEFTOVER", "original": item["value"], "replacement": f"{item['kind']} still present in {item['file']}"} for item in leftovers]
    (target / "anonymization-map.csv").write_text(to_csv(rows), encoding="utf-8-sig", newline="")
    return {"leftovers": leftovers, "replaced": len(anon.mapping)}


def _build(build: progress.Build | None = None):
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
    options = dict(
        group=group,
        collapse_endpoints=request.form.get("collapse_endpoints", "1") != "0",
        collapse_aps=request.form.get("collapse_aps", request.form.get("collapse_endpoints", "1")) != "0",
        exclude_endpoints=request.form.get("exclude_endpoints", "0") == "1",
        group_endpoints=request.form.get("group_endpoints", "1") != "0",
        show_ports=request.form.get("show_ports", "1") != "0",
        infer_neighbors_from_arp=request.form.get("infer_neighbors", "1") != "0",
        include_hosts=request.form.get("include_hosts", "0") == "1",
        include_routed=request.form.get("include_routed", "1") != "0",
        line_style=line_style,
        view=request.form.get("view", DEFAULT_VIEW) if request.form.get("view") in VIEWS else DEFAULT_VIEW,
        overlay_sites=request.form.get("overlay_sites", "captured") if request.form.get("overlay_sites") in OVERLAY_SITES else "captured",
        focus_sites=request.form.get("focus_sites", "")[:4000],
        group_gateways=request.form.get("group_l3", "1") != "0",
        hide_mgmt=request.form.get("hide_mgmt", "1") != "0",
        show_link_ips=request.form.get("show_link_ips", "1") != "0",
        bundle_members=request.form.get("bundle_members", "1") != "0",
        provider_hints=request.form.get("provider_hints", "")[:4000],
        site_rules=request.form.get("site_rules", "")[:4000],
        line_shape=request.form.get("line_shape", "angled") if request.form.get("line_shape") in LINE_SHAPES else "angled",
    )
    anonymize_too = request.form.get("anonymize", "0") == "1"
    with progress.tracking(build, 0.0, 55.0 if anonymize_too else 100.0):         # with an anonymized copy the first pass owns the first part of the bar
        result = build_topology(files, name=name_text, created=created, layout=layout, previous=carried, **options)
        graph = result["graph"]
        if not graph.nodes:
            return jsonify({"ok": False, "error": "No device could be read from these files.", "skipped": result["skipped"]}), 400
        export_id = uuid.uuid4().hex
        target = EXPORT_DIR / export_id
        target.mkdir(parents=True, exist_ok=True)
        tables = _write_run(target, result, name_text, inputs=list(files))
    (target / "_name.txt").write_text(_topology_name(), encoding="utf-8")
    devices, links, hosts, behind, bundles, priority = (tables[k] for k in ("devices", "links", "hosts", "behind", "bundles", "priority"))
    history.write_meta(target, history.meta_from_tables(devices, links, hosts, result["findings"], result["settings"]))      # the small summary the Topology history panel lists
    anonymized = None
    if anonymize_too:
        with progress.tracking(build, 55.0, 100.0, "Anonymized copy: "):
            anonymized = _write_anonymized(target, files, carried, options, created)
    progress.finish(build)
    prune_runs(EXPORT_DIR, keep=current_app.config.get("TOPOLOGY_KEEP_RUNS", DEFAULT_KEEP),
               max_age_days=current_app.config.get("TOPOLOGY_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS), protect=export_id)    # the run just written always stays
    log_activity("Topology Builder", "Topology built", f"{result['summary']['captured']} device(s) · {result['summary']['links']} link(s)")
    payload = {
        "ok": True, "export_id": export_id, "summary": result["summary"], "findings": result["findings"],
        "skipped": result["skipped"], "notices": result["notices"], "group_reason": result["group_reason"], "group_used": result["settings"]["group_used"], "findings_by_device": result["findings_by_device"], "pages": result["svgs"], "devices": devices, "links": links, "hosts": hosts, "behind": behind, "bundles": bundles, "priority": priority, "priority_columns": list(PRIORITY_COLUMNS), "anonymized": anonymized,
        "legend": {"physical": legend_rows(line_style, False), "logical": legend_rows(line_style, True), "ip": legend_rows(line_style, "ip"), "f5map": legend_rows(line_style, "f5map"), "l3route": legend_rows(line_style, "l3route") + _legend_extras(result), "l3over2": legend_rows(line_style, "l3over2") + _legend_extras(result)},
        "l3_links": result["l3_links"], "l3_routes": result["l3_routes"], "l3_unresolved": result["l3_unresolved"], "l3_overlay": result["l3_overlay"], "l3_sites": result["l3_sites"],
        "howto": howto_html(bool(result["l3_pages"])),
        "trace": {"export_id": export_id, "devices": [{"key": k, "name": d["name"]} for k, d in sorted(result["l3_trace"].get("devices", {}).items(), key=lambda kv: kv[1]["name"])]},
        "downloads": [{"name": name, "filename": _download_filename(name, _topology_name()), "url": f"/topology/api/export/{export_id}/{name}"} for name in EXPORT_NAMES if (target / name).is_file()],
    }
    history.write_result(target, payload)          # "Open again" in the Topology history shows this answer without building again
    return jsonify(payload)


@bp.post("/api/trace")
def trace_route():
    """Path trace on the L3 model of an earlier build: ``{export_id, source, destination, vrf}`` -> hops and the lines to highlight."""
    body = request.get_json(silent=True) or {}
    export_id = str(body.get("export_id", ""))
    if not SAFE_IDENTIFIER.fullmatch(export_id):
        return jsonify({"ok": False, "error": "Unknown build."}), 404
    path = EXPORT_DIR / export_id / "_trace.json"
    if not path.is_file():
        return jsonify({"ok": False, "error": "This build has no L3 data. Build the topology again with an L3 view."}), 404
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return jsonify({"ok": False, "error": "The L3 data of this build is not readable. Build the topology again."}), 500
    return jsonify(trace(data, str(body.get("source", ""))[:80], str(body.get("destination", ""))[:64], str(body.get("vrf", ""))[:40]))


def _run_bytes(field: str) -> tuple[bytes | None, str]:
    """The topology.json of one side of a comparison: an uploaded file (``before`` / ``after``) or a run kept on this computer (``before_id`` / ``after_id``).
    Returns ``(bytes, "")`` or ``(None, message)``."""
    upload = request.files.get(field)
    if upload and upload.filename:
        data = upload.read(MAX_DIFF_BYTES + 1)
        return (data, "") if len(data) <= MAX_DIFF_BYTES else (None, f"The {field} file is larger than {MAX_DIFF_BYTES // (1024 * 1024)} MB.")
    run_id = request.form.get(f"{field}_id", "")
    if not run_id:
        return None, f"Choose the {field} run: a topology.json or keystone-topology-pack.zip, or one of the runs kept on this computer."
    if not SAFE_IDENTIFIER.fullmatch(run_id):
        return None, "Unknown run."
    path = EXPORT_DIR / run_id / "topology.json"
    try:
        return path.read_bytes(), ""
    except OSError:
        return None, "This run has been removed (Keystone keeps the newest runs only). Upload its topology.json instead."


@bp.get("/api/runs")
def runs_route():
    """The runs still kept in ``exports/topology`` (newest first), for the Compare two runs and Cutover runbook pickers."""
    rows = [{"id": r["id"], "built": r["built"], "name": r["name"], "devices": r["devices"], "links": r["links"], "pinned": r["pinned"]}
            for r in history.list_runs(EXPORT_DIR, _max_age_days()) if (EXPORT_DIR / r["id"] / "topology.json").is_file()]
    return jsonify({"ok": True, "runs": rows})


@bp.post("/api/diff")
def diff_route():
    """What changed between two runs: ``before`` and ``after`` are topology.json (or pack ZIP) uploads, or ``before_id`` / ``after_id`` name kept runs."""
    loaded = {}
    for side in ("before", "after"):
        data, problem = _run_bytes(side)
        if data is None:
            return jsonify({"ok": False, "error": problem}), 400
        try:
            loaded[side] = load_run(data)
        except DiffError as exc:
            return jsonify({"ok": False, "error": f"The {side} run: {exc}"}), 400
    result = compare_runs(loaded["before"], loaded["after"])
    log_activity("Topology Builder", "Topology runs compared", f"{result['summary']['differences']} difference(s) · {result['summary']['attention']} to read")
    return jsonify({"ok": True, **result, "csv": to_csv(result["rows"]) if result["rows"] else ""})


@bp.post("/api/runbook")
def runbook_route():
    """A cutover runbook from one run: ``source`` (upload of a topology.json or pack ZIP) or ``source_id`` (a run kept on this computer), plus
    ``title``, ``window``, ``reference``, ``change`` (replace / upgrade / config) and ``devices`` (names, one per line or comma separated; empty = every captured device)."""
    data, problem = _run_bytes("source")
    if data is None:
        return jsonify({"ok": False, "error": problem}), 400
    try:
        run = load_run(data)
    except DiffError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    names = [n for n in re.split(r"[\r\n,;]+", request.form.get("devices", "")[:4000]) if n.strip()]
    try:
        result = build_runbook(run, title=request.form.get("title", "").strip()[:80], window=request.form.get("window", "").strip()[:80],
                               reference=request.form.get("reference", "").strip()[:60], change=request.form.get("change", "replace").strip() or "replace", only=names)
    except RunbookError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_activity("Topology Builder", "Cutover runbook written", f"{result['summary']['devices']} device(s) · {result['summary']['outage']} with an expected outage")
    return jsonify({"ok": True, "summary": result["summary"], "devices": result["devices"], "html": result["html"], "csv": to_csv(result["steps"])})


@bp.get("/api/demo")
def demo_sets_route():
    """The demo capture sets of the "Load demo data" buttons."""
    return jsonify({"ok": True, "sets": demo.list_sets()})


@bp.get("/api/demo/<set_id>/<name>")
def demo_file_route(set_id: str, name: str):
    data = demo.read_file(set_id, name)
    if data is None:
        return jsonify({"ok": False, "error": "Unknown demo file."}), 404
    return current_app.response_class(data, mimetype="text/plain")


@bp.get("/api/export/<export_id>/<name>")
def export_file(export_id: str, name: str):
    if not SAFE_IDENTIFIER.fullmatch(export_id) or name not in EXPORT_NAMES:
        return jsonify({"ok": False, "error": "Unknown export."}), 404
    folder = EXPORT_DIR / export_id
    if not (folder / name).is_file():
        return jsonify({"ok": False, "error": "This export has been removed. Build the topology again."}), 404
    try:
        prefix = (folder / "_name.txt").read_text(encoding="utf-8")
    except OSError:
        prefix = ""
    return send_from_directory(folder, name, as_attachment=True, mimetype=EXPORT_NAMES[name], download_name=_download_filename(name, safe_name(prefix)))


# ---------------------------------------------------------------- topology history
# Every build kept in exports/topology, for the "Topology history" panel: list, details, pin, rename, delete, clear.
# Downloads use /api/export/<id>/<name>; comparing and the cutover runbook use /api/diff and /api/runbook with the run id.
HISTORY_FILES = {
    "keystone-topology-pack.zip": "Documentation pack (ZIP)",
    "topology-report.html": "Report (HTML, print to PDF)",
    "topology-print-a3.html": "A3 print set (HTML, one sheet per page)",
    "topology.drawio": "draw.io diagram",
    "topology.xlsx": "Excel workbook",
    ANON_ZIP: "Anonymized pack (ZIP, safe to share)",
    "anonymization-map.csv": "Anonymization key (private: it holds the real names)",
    "topology.json": "Tables (JSON)",
    "devices.csv": "Devices (CSV)",
    "links.csv": "Links (CSV)",
    "findings.csv": "Findings (CSV)",
    "run-settings.txt": "Run settings (text)",
}


def _max_age_days() -> float:
    return float(current_app.config.get("TOPOLOGY_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS))


def _keep_runs() -> int:
    return int(current_app.config.get("TOPOLOGY_KEEP_RUNS", DEFAULT_KEEP))


@bp.get("/api/history")
def history_route():
    """The runs kept on this computer, newest first, with the rules that keep them."""
    try:                                                    # Keystone can stay open for weeks: apply the rules whenever the list is read, not only after a build
        prune_runs(EXPORT_DIR, keep=_keep_runs(), max_age_days=_max_age_days())
    except Exception:                                       # noqa: BLE001 - housekeeping must not stop the list
        log.warning("The Topology history clean-up failed.", exc_info=True)
    runs = history.list_runs(EXPORT_DIR, _max_age_days())
    return jsonify({"ok": True, "runs": runs, "keep": _keep_runs(), "max_age_days": _max_age_days(), "max_pinned": history.MAX_PINNED,
                    "pinned": sum(1 for r in runs if r["pinned"]), "total_size": history.disk_usage(EXPORT_DIR)})


@bp.get("/api/baseline/<run_id>")
def baseline_route(run_id: str):
    """What changed between the baseline (the newest pinned run) and the run just built: a short summary for the banner under the build.
    ``baseline`` is null when nothing is pinned.  The full table is the Compare two runs panel (``/api/diff``)."""
    if not SAFE_IDENTIFIER.fullmatch(run_id):
        return jsonify({"ok": False, "error": "Unknown run."}), 404
    baseline = history.baseline_of(EXPORT_DIR, _max_age_days(), exclude=run_id)
    if baseline is None:
        return jsonify({"ok": True, "baseline": None})
    try:
        before = load_run((EXPORT_DIR / baseline["id"] / "topology.json").read_bytes())
        after = load_run((EXPORT_DIR / run_id / "topology.json").read_bytes())
    except (OSError, DiffError):
        return jsonify({"ok": True, "baseline": None})
    summary = compare_runs(before, after)["summary"]
    return jsonify({"ok": True, "baseline": {"id": baseline["id"], "name": baseline["name"] or "Unnamed topology", "built": baseline["built"]},
                    "differences": summary["differences"], "attention": summary["attention"], "areas": summary["areas"]})


@bp.get("/api/history/<run_id>")
def history_detail_route(run_id: str):
    detail = history.run_detail(EXPORT_DIR, run_id, _max_age_days(), HISTORY_FILES)
    if detail is None:
        return jsonify({"ok": False, "error": "This run is no longer kept."}), 404
    prefix = safe_name(detail["name"])
    for item in detail["files"]:
        item["url"] = f"/topology/api/export/{run_id}/{item['name']}"
        item["filename"] = _download_filename(item["name"], prefix)
    return jsonify({"ok": True, "run": detail})


@bp.get("/api/history/<run_id>/result")
def history_result_route(run_id: str):
    """The answer of a kept build exactly as the build returned it, for "Open again" in the Topology history."""
    if not SAFE_IDENTIFIER.fullmatch(run_id):
        return jsonify({"ok": False, "error": "Unknown run."}), 404
    payload = history.read_result(EXPORT_DIR, run_id)
    if payload is None:
        return jsonify({"ok": False, "error": "This run cannot be opened again (it was built before this was kept, or its files were removed). Build it again from the captures."}), 404
    return jsonify(payload)


@bp.post("/api/history/<run_id>/pin")
def history_pin_route(run_id: str):
    body = request.get_json(silent=True) or {}
    ok, message = history.set_pinned(EXPORT_DIR, run_id, bool(body.get("pinned", True)))
    if not ok:
        return jsonify({"ok": False, "error": message}), 404 if "no longer" in message else 409
    log_activity("Topology Builder", "Topology run pinned" if body.get("pinned", True) else "Topology run unpinned", "")
    return jsonify({"ok": True, "pinned": bool(body.get("pinned", True))})


@bp.post("/api/history/<run_id>/rename")
def history_rename_route(run_id: str):
    body = request.get_json(silent=True) or {}
    ok, message, saved = history.rename(EXPORT_DIR, run_id, body.get("name", ""))
    if not ok:
        return jsonify({"ok": False, "error": message}), 404 if "no longer" in message else 409
    return jsonify({"ok": True, "name": saved})


@bp.post("/api/history/<run_id>/note")
def history_note_route(run_id: str):
    body = request.get_json(silent=True) or {}
    ok, message, saved = history.set_note(EXPORT_DIR, run_id, body.get("note", ""))
    if not ok:
        return jsonify({"ok": False, "error": message}), 404 if "no longer" in message else 409
    return jsonify({"ok": True, "note": saved})


@bp.delete("/api/history/<run_id>")
def history_delete_route(run_id: str):
    ok, message = history.delete(EXPORT_DIR, run_id)
    if not ok:
        return jsonify({"ok": False, "error": message}), 404 if "no longer" in message else 409
    log_activity("Topology Builder", "Topology run deleted", "")
    return jsonify({"ok": True})


@bp.post("/api/history/clear")
def history_clear_route():
    """Delete every kept run. Pinned runs stay unless ``include_pinned`` is true; a build still writing its files stays."""
    body = request.get_json(silent=True) or {}
    removed = history.clear(EXPORT_DIR, keep_pinned=not bool(body.get("include_pinned", False)), grace_seconds=600)
    log_activity("Topology Builder", "Topology history cleared", f"{len(removed)} run(s)")
    return jsonify({"ok": True, "removed": len(removed)})
