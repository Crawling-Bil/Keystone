import hashlib
import json
import logging
import os
import tempfile
import uuid
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("nes.lifecycle")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[lifecycle] %(asctime)s %(message)s", "%H:%M:%S"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

from flask import (
    Blueprint,
    Response,
    jsonify,
    render_template,
    request,
    send_file,
    send_from_directory
)
from werkzeug.utils import secure_filename

from .core.discovery import scan_range, check_ssh_port

from .core.precheck_engine import PrecheckEngine
from .core.upgrade_engine import UpgradeEngine
from .core.config_push_engine import ConfigPushEngine
from .core.config_capture_engine import ConfigCaptureEngine, CONFIG_CAPTURE_COMMANDS
from .core.ssh_manager import SSHManager
from .core.device_detector import detect_driver

from features.ztp.core import store as ztp_store

# ============================================================
# APPLICATION PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "data"
FIRMWARE_DIR = BASE_DIR / "firmware"

SETTINGS_FILE = CONFIG_DIR / "settings.json"
DEVICES_FILE = DATA_DIR / "devices.json"
FIRMWARE_DB_FILE = DATA_DIR / "firmware.json"
JOBS_FILE = DATA_DIR / "jobs.json"
CONFIG_DRAFTS_FILE = DATA_DIR / "config_drafts.json"


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

CONFIG_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

for vendor in ["cisco", "huawei", "aruba"]:
    (FIRMWARE_DIR / vendor).mkdir(
        parents=True,
        exist_ok=True
    )


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Blueprint(
    "lifecycle",
    __name__,
    url_prefix="/lifecycle",
    template_folder="templates",
    static_folder="static"
)


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

DEFAULT_SETTINGS = {
    "application": {
        "name": "Switch Upgrade Tool",
        "version": "1.0.0"
    },
    "network": {
        "scan_start": "192.168.100.11",
        "scan_end": "192.168.100.50"
    },
    "ssh": {
        "username": "staging",
        "port": 22,
        "timeout": 10
    },
    "firmware_server": {
        "bind_address": "0.0.0.0",
        "port": 8080,
        "source_ip": "192.168.100.1"
    },
    "upgrade": {
        "max_parallel": 10,
        "reconnect_timeout": 600,
        "reconnect_interval": 10
    },
    "transfer": {
        "method": "sftp",
        "tftp_server_ip": "",
        "tftp_port": 69,
        "ftp_server_ip": "",
        "ftp_port": 21
    },
    "demo_mode": True
}


# ============================================================
# JSON HELPERS
#
# jobs.json / devices.json are read-modified-written both from Flask
# request threads (waitress runs several) and from the background
# upgrade-job worker thread (see execute_upgrade_job / update_device
# below). Without locking, two concurrent writers can interleave and
# leave a truncated/corrupt JSON file on disk; without an atomic
# write, a crash mid-write does the same. _lock_for()+write via a
# temp file + os.replace() close both gaps.
# ============================================================

_file_locks = {}
_file_locks_guard = threading.Lock()


def _lock_for(file_path):
    key = str(file_path)
    with _file_locks_guard:
        lock = _file_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _file_locks[key] = lock
        return lock


def _read_json_unlocked(file_path, default):
    try:
        if not file_path.exists():
            return default
        with open(file_path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def _write_json_unlocked(file_path, data):
    file_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(file_path.parent), prefix=f".{file_path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        os.replace(tmp_name, file_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def read_json(file_path, default):
    with _lock_for(file_path):
        return _read_json_unlocked(file_path, default)


def write_json(file_path, data):
    with _lock_for(file_path):
        _write_json_unlocked(file_path, data)


def update_json(file_path, default, mutate_fn):
    """Read, mutate, and write file_path as one atomic operation under
    a single lock acquisition — use this instead of separate
    read_json()/write_json() calls whenever the same file may be
    touched concurrently (e.g. job progress updates), so one caller's
    change can't be silently lost to another's in-between write.
    `mutate_fn(data)` mutates `data` in place and its return value is
    passed back to the caller."""
    with _lock_for(file_path):
        data = _read_json_unlocked(file_path, default)
        result = mutate_fn(data)
        _write_json_unlocked(file_path, data)
        return result


def _persist_job(job_id, target_job):
    """Write one job's current state into JOBS_FILE without touching
    any other job in it.

    This exists for callers like the Pre-Check functions below that
    build up a job's new state in a local `target_job` object across a
    loop spanning real per-device SSH round trips (seconds to minutes),
    calling this repeatedly as that state changes. Persisting that with
    plain write_json(JOBS_FILE, database) -- overwriting the WHOLE file
    with a `database` snapshot taken once at the top of the function --
    is a real, confirmed bug: any other job's background thread (e.g.
    execute_config_push_job() streaming live command results via
    update_json() while a *different* job's Pre-Check is running
    concurrently) has its writes silently discarded the moment this
    stale snapshot gets written back over them. Reproduced empirically:
    concurrent update_json() writers lost roughly half their entries to
    a simulated Pre-Check's repeated stale write_json() calls.

    _persist_job() instead re-reads the CURRENT file under the same
    lock update_json() uses, and replaces ONLY the entry whose id
    matches job_id with `target_job` -- every other job's most recent
    state (written by whoever last touched it, including a background
    job thread that ran concurrently with this Pre-Check) survives
    untouched. If the job was deleted concurrently, this is a no-op
    rather than resurrecting it.
    """
    def _apply(current_database):
        jobs = current_database.setdefault("jobs", [])
        for index, job in enumerate(jobs):
            if job.get("id") == job_id:
                jobs[index] = target_job
                return

    update_json(JOBS_FILE, {"jobs": []}, _apply)


# ============================================================
# INITIALIZE DATA FILES
# ============================================================

if not SETTINGS_FILE.exists():
    write_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

if not DEVICES_FILE.exists():
    write_json(
        DEVICES_FILE,
        {
            "devices": []
        }
    )

if not FIRMWARE_DB_FILE.exists():
    write_json(
        FIRMWARE_DB_FILE,
        {
            "firmwares": []
        }
    )

if not JOBS_FILE.exists():
    write_json(
        JOBS_FILE,
        {
            "jobs": []
        }
    )


# ============================================================
# DEMO DEVICES
# ============================================================

def get_demo_devices():

    return [
        {
            "ip": "192.168.100.11",
            "hostname": "STAGING-CISCO-01",
            "vendor": "Cisco",
            "platform": "IOS-XE",
            "model": "C9200L-24P-4G",
            "version": "17.06.05",
            "serial": "DEMO-CISCO-001",
            "status": "online"
        },
        {
            "ip": "192.168.100.12",
            "hostname": "STAGING-CISCO-02",
            "vendor": "Cisco",
            "platform": "IOS-XE",
            "model": "C9300-48P",
            "version": "17.09.04",
            "serial": "DEMO-CISCO-002",
            "status": "online"
        },
        {
            "ip": "192.168.100.13",
            "hostname": "STAGING-HUAWEI-01",
            "vendor": "Huawei",
            "platform": "VRP",
            "model": "S5735-L24P4X-A1",
            "version": "V200R022",
            "serial": "DEMO-HUAWEI-001",
            "status": "online"
        },
        {
            "ip": "192.168.100.14",
            "hostname": "STAGING-ARUBA-01",
            "vendor": "Aruba",
            "platform": "AOS-CX",
            "model": "6200F",
            "version": "10.13",
            "serial": "DEMO-ARUBA-001",
            "status": "online"
        }
    ]


# ============================================================
# FIRMWARE HELPERS
# ============================================================

ALLOWED_EXTENSIONS = {
    ".bin",
    ".tar",
    ".swi",
    ".img",
    ".cc",
    ".zip",
    ".pat"
}


def allowed_firmware(filename):

    extension = Path(
        filename
    ).suffix.lower()

    return extension in ALLOWED_EXTENSIONS


def get_firmware_database():

    return read_json(
        FIRMWARE_DB_FILE,
        {
            "firmwares": []
        }
    )


# ============================================================
# PAGE ROUTES
# ============================================================

@app.route("/")
def index():

    settings = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    return render_template(
        "index.html",
        settings=settings,
        active_page="lifecycle"
    )


@app.route("/config-push")
def config_push_page():

    settings = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    return render_template(
        "config_push.html",
        settings=settings,
        active_page="config_push"
    )


@app.route("/config-backup")
def config_backup_page():
    settings = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    return render_template(
        "config_backup.html",
        settings=settings,
        active_page="config_backup"
    )


@app.route("/live-logs")
def live_logs_page():
    # Suite-wide page, not scoped to one module -- shows Lifecycle
    # Manager's upgrade + config push jobs (this module's own
    # /api/jobs + /api/jobs/<id>/stream, unchanged) side by side with
    # ZTP's activity feed (fetched client-side straight from ZTP's own
    # /ztp/api/activity -- see live_logs.js). No new backend endpoints
    # needed for either source; this route only serves the page shell.
    settings = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    return render_template(
        "live_logs.html",
        settings=settings,
        active_page="live_logs"
    )


# ============================================================
# API - HEALTH
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "ok",
        "application": (
            "Switch Upgrade Tool"
        ),
        "time": datetime.now().isoformat()
    })


# ============================================================
# API - DASHBOARD
# ============================================================

@app.route(
    "/api/dashboard",
    methods=["GET"]
)
def dashboard():

    device_data = read_json(
        DEVICES_FILE,
        {
            "devices": []
        }
    )

    firmware_data = (
        get_firmware_database()
    )

    devices = [
        device
        for device in device_data.get(
            "devices",
            []
        )
        if device.get("status") == "online"
    ]

    online = len(devices)

    return jsonify({
        "total_devices": len(devices),
        "online_devices": online,
        "firmware_images": len(
            firmware_data.get(
                "firmwares",
                []
            )
        ),
        "active_jobs": len([
            job
            for job in read_json(
                JOBS_FILE,
                {"jobs": []}
            ).get("jobs", [])
            if job.get("status") not in {
                "completed",
                "failed",
                "cancelled"
            }
        ])
    })


# ============================================================
# API - GET DEVICES
# ============================================================

@app.route(
    "/api/devices",
    methods=["GET"]
)
def get_devices():

    data = read_json(
        DEVICES_FILE,
        {
            "devices": []
        }
    )

    devices = [
        device
        for device in data.get("devices", [])
        if device.get("status") == "online"
    ]

    if len(devices) != len(data.get("devices", [])):
        write_json(
            DEVICES_FILE,
            {
                "devices": devices
            }
        )

    return jsonify({
        "devices": devices
    })


# ============================================================
# API - CHECK DEVICE REACHABILITY
#
# A fast, credential-free TCP/SSH-port liveness probe -- deliberately
# NOT a full re-discovery (no login, no inventory pull). Discovery's
# own "online" status is a snapshot from whenever that IP range was
# last scanned, with no timestamp recorded alongside it, so there is
# no way to tell how stale it is just from the device list. This is
# the answer to that: an on-demand "is it actually up right now"
# check an operator can run right before starting something like a
# Config Capture job, instead of trusting a Discovery status that
# might be hours old. Stamps reachable + reachability_checked_at onto
# each device in DEVICES_FILE without touching anything else about it
# (hostname/vendor/model/etc. are left exactly as Discovery last saw
# them).
# ============================================================

@app.route(
    "/api/devices/check-reachability",
    methods=["POST"]
)
def check_devices_reachability():

    payload = request.get_json(silent=True) or {}
    requested_ips = payload.get("ips")

    database = read_json(DEVICES_FILE, {"devices": []})
    devices = database.get("devices", [])

    if requested_ips:
        wanted = set(requested_ips)
        targets = [device for device in devices if device.get("ip") in wanted]
    else:
        targets = devices

    if not targets:
        return jsonify({
            "success": False,
            "error": "No matching devices to check."
        }), 400

    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    ssh_port = settings.get("ssh", {}).get("port", 22)

    checked_at = datetime.now().isoformat()

    def _probe(device):
        return device.get("ip"), check_ssh_port(device.get("ip"), port=ssh_port, timeout=1.5)

    reachable_by_ip = {}
    max_workers = max(1, min(len(targets), 20))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_probe, device) for device in targets]
        for future in as_completed(futures):
            ip, is_reachable = future.result()
            reachable_by_ip[ip] = is_reachable

    for device in devices:
        ip = device.get("ip")
        if ip in reachable_by_ip:
            device["reachable"] = reachable_by_ip[ip]
            device["reachability_checked_at"] = checked_at

    write_json(DEVICES_FILE, {"devices": devices})

    return jsonify({
        "success": True,
        "checked_at": checked_at,
        "results": reachable_by_ip,
        "devices": devices,
    })


# ============================================================
# API - DISCOVERY
# ============================================================

@app.route(
    "/api/discovery",
    methods=["POST"]
)
def discovery():

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    settings = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    demo_mode = payload.get(
        "demo_mode",
        settings.get(
            "demo_mode",
            True
        )
    )

    if settings.get("demo_mode", True) != demo_mode:
        settings["demo_mode"] = demo_mode
        write_json(SETTINGS_FILE, settings)

    discovery_username = str(payload.get("username") or "").strip()
    if not demo_mode and discovery_username:
        ssh_settings = settings.setdefault("ssh", {})
        if ssh_settings.get("username") != discovery_username:
            ssh_settings["username"] = discovery_username
            write_json(SETTINGS_FILE, settings)
            logger.info(
                "Saved SSH username %r from Discovery into Settings — "
                "Pre-Check and Upgrade will now use the same username.",
                discovery_username,
            )

    logger.info(
        "Discovery requested — mode=%s",
        "DEMO" if demo_mode else "REAL",
    )

    if demo_mode:

        devices = get_demo_devices()

        write_json(
            DEVICES_FILE,
            {
                "devices": devices
            }
        )

        return jsonify({
            "success": True,
            "demo_mode": True,
            "devices": devices
        })

    start_ip = payload.get(
        "start_ip"
    )

    end_ip = payload.get(
        "end_ip"
    )

    username = payload.get(
        "username"
    )

    password = payload.get(
        "password"
    )

    if not all([
        start_ip,
        end_ip,
        username,
        password
    ]):

        return jsonify({
            "success": False,
            "error": (
                "Start IP, End IP, "
                "username and password "
                "are required."
            )
        }), 400

    try:

        scan_results = scan_range(
            start_ip=start_ip,
            end_ip=end_ip,
            username=username,
            password=password,
            max_workers=settings.get(
                "upgrade",
                {}
            ).get(
                "max_parallel",
                10
            )
        )

        # Real discovery results only show devices that were successfully
        # identified and inventoried. Unreachable IPs and failed login attempts
        # must not fill the discovered-device table, but we still surface
        # *why* each one failed so a partial scan isn't mistaken for a
        # single-device limitation.
        devices = [
            device
            for device in scan_results
            if device.get("status") == "online"
        ]

        failed_devices = [
            {
                "ip": device.get("ip"),
                "status": device.get("status"),
                "error": device.get("error")
                    or (device.get("discovery_log") or [{}])[-1].get("message", "Unknown error"),
            }
            for device in scan_results
            if device.get("status") != "online"
        ]

        newly_provisioned_esns = _ztp_auto_mark_provisioned(devices)

        write_json(
            DEVICES_FILE,
            {
                "devices": devices
            }
        )

        return jsonify({
            "success": True,
            "demo_mode": False,
            "devices": devices,
            "no_devices": not devices,
            "attempted_count": len(scan_results),
            "failed_count": len(scan_results) - len(devices),
            "failed_devices": failed_devices,
            "ztp_auto_provisioned": newly_provisioned_esns,
        })

    except Exception as exc:

        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


# ============================================================
# API - CLEAR DEVICES
# ============================================================

@app.route(
    "/api/devices",
    methods=["DELETE"]
)
def clear_devices():

    write_json(
        DEVICES_FILE,
        {
            "devices": []
        }
    )

    return jsonify({
        "success": True
    })


# ============================================================
# API - FIRMWARE LIST
# ============================================================

@app.route(
    "/api/firmware",
    methods=["GET"]
)
def get_firmware():

    return jsonify(
        get_firmware_database()
    )


# ============================================================
# API - FIRMWARE UPLOAD
# ============================================================

def _md5_of(path, chunk_size=1024 * 1024):
    digest = hashlib.md5()
    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


@app.route(
    "/api/firmware/upload",
    methods=["POST"]
)
def upload_firmware():

    if "file" not in request.files:

        return jsonify({
            "success": False,
            "error": (
                "Firmware file is required."
            )
        }), 400

    firmware_file = (
        request.files["file"]
    )

    vendor = (
        request.form.get(
            "vendor",
            ""
        )
        .strip()
        .lower()
    )

    platform = (
        request.form.get(
            "platform",
            ""
        )
        .strip()
    )

    version = (
        request.form.get(
            "version",
            ""
        )
        .strip()
    )

    model = (
        request.form.get(
            "model",
            ""
        )
        .strip()
    )

    if vendor not in {
        "cisco",
        "huawei",
        "aruba"
    }:

        return jsonify({
            "success": False,
            "error": (
                "Unsupported vendor."
            )
        }), 400

    if (
        not firmware_file.filename
        or not allowed_firmware(
            firmware_file.filename
        )
    ):

        return jsonify({
            "success": False,
            "error": (
                "Unsupported firmware "
                "file type."
            )
        }), 400

    filename = secure_filename(
        firmware_file.filename
    )

    destination = (
        FIRMWARE_DIR
        / vendor
        / filename
    )

    firmware_file.save(
        destination
    )
    # Computed from the exact bytes saved here, so verify_md5() during
    # a real upgrade has something to check the device's flash: copy
    # against — without this, a silently-truncated/corrupted transfer
    # would go undetected right before the device reloads onto it.
    checksum = _md5_of(destination)

    patch_filename = ""
    patch_size = 0
    patch_checksum = ""
    patch_file = request.files.get("patch_file")
    if patch_file and patch_file.filename:
        if not allowed_firmware(patch_file.filename):
            return jsonify({
                "success": False,
                "error": "Unsupported patch file type."
            }), 400
        patch_filename = secure_filename(patch_file.filename)
        patch_destination = FIRMWARE_DIR / vendor / patch_filename
        patch_file.save(patch_destination)
        patch_size = patch_destination.stat().st_size
        patch_checksum = _md5_of(patch_destination)

    firmware_database = (
        get_firmware_database()
    )

    record = {
        "id": str(uuid.uuid4()),
        "vendor": vendor.title(),
        "platform": platform,
        "model": model,
        "version": version,
        "filename": filename,
        "size": destination.stat().st_size,
        "checksum": checksum,
        "patch_filename": patch_filename,
        "patch_size": patch_size,
        "patch_checksum": patch_checksum,
        "uploaded_at": (
            datetime.now().isoformat()
        )
    }

    firmware_database[
        "firmwares"
    ].append(record)

    write_json(
        FIRMWARE_DB_FILE,
        firmware_database
    )

    return jsonify({
        "success": True,
        "firmware": record
    })


# ============================================================
# API - DELETE FIRMWARE
# ============================================================

@app.route(
    "/api/firmware/<firmware_id>",
    methods=["DELETE"]
)
def delete_firmware(
    firmware_id
):

    database = (
        get_firmware_database()
    )

    firmware = next(
        (
            item
            for item
            in database["firmwares"]
            if item["id"]
            == firmware_id
        ),
        None
    )

    if firmware is None:

        return jsonify({
            "success": False,
            "error": (
                "Firmware not found."
            )
        }), 404

    vendor_folder = (
        firmware["vendor"]
        .lower()
    )

    file_path = (
        FIRMWARE_DIR
        / vendor_folder
        / firmware["filename"]
    )

    if file_path.exists():
        file_path.unlink()

    patch_name = firmware.get("patch_filename")
    if patch_name:
        patch_path = FIRMWARE_DIR / vendor_folder / patch_name
        if patch_path.exists():
            patch_path.unlink()

    database["firmwares"] = [
        item
        for item
        in database["firmwares"]
        if item["id"]
        != firmware_id
    ]

    write_json(
        FIRMWARE_DB_FILE,
        database
    )

    return jsonify({
        "success": True
    })


# ============================================================
# FIRMWARE DOWNLOAD ENDPOINT
# Devices pull their firmware image from this endpoint.
#
# Example:
# http://192.168.100.1:8002/firmware/cisco/image.bin
# ============================================================

@app.route(
    "/firmware/<vendor>/<filename>",
    methods=["GET"]
)
def serve_firmware(
    vendor,
    filename
):

    vendor = vendor.lower()

    if vendor not in {
        "cisco",
        "huawei",
        "aruba"
    }:

        return jsonify({
            "error": "Invalid vendor"
        }), 404

    return send_from_directory(
        FIRMWARE_DIR / vendor,
        filename,
        as_attachment=True
    )



# ============================================================
# API - UPGRADE JOBS
# ============================================================

@app.route(
    "/api/jobs",
    methods=["GET"]
)
def get_jobs():

    return jsonify(
        read_json(
            JOBS_FILE,
            {
                "jobs": []
            }
        )
    )


@app.route(
    "/api/jobs/<job_id>/stream"
)
def stream_job(job_id):
    """Server-Sent Events feed for one job -- lets a job's detail view
    update the moment something happens (a command result, a new log
    line, a status change) instead of waiting out the client's poll
    interval. Requested specifically for config_push so the operator
    can watch commands land in something closer to real time ("kaya
    live ssh gitu"), but it works for any job type since it's just
    tailing the same jobs.json every other endpoint already reads.

    Deliberately reads JOBS_FILE from disk on a short interval rather
    than keeping an in-memory queue of events: job execution runs in
    its own background thread (see execute_config_push_job /
    execute_upgrade_job) and jobs.json is already the single source of
    truth those threads write through read_json()/update_json()'s
    locking -- reusing that instead of inventing a second, in-memory
    channel means this stays correct even if job execution and request
    handling ever end up in different processes, and it can't drift
    from what GET /api/jobs would show.

    This connection is held open for as long as the job keeps running,
    which is exactly why app.run() below is started with
    threaded=True: the dev server otherwise serves one request at a
    time, and a single open stream would stall every other page in the
    app until the job finished.
    """

    def event_stream():
        sent_log_count = 0
        sent_result_counts = {}
        last_status = None

        while True:
            # Every branch below that finds nothing new to send sets this
            # back to False. If we reach the bottom of the loop still
            # False, this tick yielded nothing at all -- which is exactly
            # the case where a disconnected client goes undetected (see
            # the heartbeat note below), so we force one small write.
            wrote_something = False

            database = read_json(JOBS_FILE, {"jobs": []})
            job = next((item for item in database.get("jobs", []) if item.get("id") == job_id), None)
            if not job:
                yield f"event: error\ndata: {json.dumps({'error': 'Job not found.'})}\n\n"
                return

            logs = job.get("logs", [])
            if len(logs) > sent_log_count:
                for entry in logs[sent_log_count:]:
                    yield f"event: log\ndata: {json.dumps(entry)}\n\n"
                    wrote_something = True
                sent_log_count = len(logs)

            for device in job.get("devices", []):
                ip = device.get("ip")
                results = device.get("live_command_results", [])
                already_sent = sent_result_counts.get(ip, 0)
                if len(results) > already_sent:
                    for result in results[already_sent:]:
                        payload = dict(result)
                        payload["ip"] = ip
                        yield f"event: command_result\ndata: {json.dumps(payload)}\n\n"
                        wrote_something = True
                    sent_result_counts[ip] = len(results)

            status = job.get("status")
            if status != last_status:
                last_status = status
                yield f"event: status\ndata: {json.dumps({'status': status})}\n\n"
                wrote_something = True

            if status in ("completed", "failed"):
                yield "event: done\ndata: {}\n\n"
                return

            # Heartbeat: a WSGI/Werkzeug server only discovers a client is
            # gone when a write to its socket actually FAILS -- there is
            # no separate "is this still connected" check. A job that
            # sits idle (no new log/command_result/status) for a long
            # stretch never performs a write during that stretch, so a
            # client that closed the tab or lost its connection is never
            # noticed: this generator (and the thread + socket behind it)
            # would otherwise keep running, polling jobs.json every 0.5s,
            # for as long as the job itself stays "running" -- which can
            # be indefinitely if the device push itself hangs. Sending an
            # SSE comment line (leading ":", no event name) on every tick
            # that had nothing else to send turns every poll interval
            # into a real socket write, so a dead connection is caught
            # within about one tick instead of never. Comment lines are
            # part of the SSE spec and are ignored by EventSource clients.
            if not wrote_something:
                yield ": keep-alive\n\n"

            time.sleep(0.5)

    return Response(
        event_stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.route(
    "/api/jobs",
    methods=["POST"]
)
def create_job():

    payload = request.get_json(silent=True) or {}

    # "upgrade" (default, backward compatible with clients that never
    # send "type") pushes firmware via an assignments map (ip ->
    # firmware_id). "config_push" pushes an operator-prepared draft
    # config via a configs map (ip -> raw CLI text) instead -- no
    # firmware involved at all. Devices don't need to have gone
    # through ZTP or an upgrade first; anything already in
    # DEVICES_FILE (i.e. it showed up in a Discovery scan at some
    # point) is eligible.
    job_type = payload.get("type") or "upgrade"
    selected_devices = payload.get("devices", [])

    if not selected_devices:
        return jsonify({
            "success": False,
            "error": "No devices selected."
        }), 400

    device_database = read_json(DEVICES_FILE, {"devices": []})
    devices_by_ip = {
        device.get("ip"): device
        for device in device_database.get("devices", [])
    }

    if job_type == "config_push":
        configs = payload.get("configs", {})
        job_devices = []

        for ip_address in selected_devices:
            device = devices_by_ip.get(ip_address)
            if not device:
                continue

            draft_config = (configs.get(ip_address) or "").strip()
            if not draft_config:
                return jsonify({
                    "success": False,
                    "error": f"No draft config provided for {ip_address}."
                }), 400

            job_devices.append({
                "ip": device.get("ip"),
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "platform": device.get("platform"),
                "model": device.get("model"),
                "current_version": device.get("version"),
                "draft_config": draft_config,
                "status": "pending",
                "progress": 0,
                "stage": "Pending"
            })

        if not job_devices:
            return jsonify({
                "success": False,
                "error": "Selected devices were not found."
            }), 400

        job = {
            "id": str(uuid.uuid4()),
            "type": "config_push",
            "name": (
                payload.get("name")
                or f"Config Push {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            ),
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "device_count": len(job_devices),
            "devices": job_devices
        }

    elif job_type == "config_capture":
        # Config Capture pulls a fixed set of read-only `display`
        # commands (CONFIG_CAPTURE_COMMANDS) and never mutates the
        # device, so there is nothing a Pre-Check stage would be
        # protecting against -- the job (and every device in it) is
        # created straight into "ready" rather than "pending", which
        # is what skips the Run Pre-Check step in the UI entirely
        # (canPrecheck only matches "pending"/"precheck_failed").
        job_devices = []

        for ip_address in selected_devices:
            device = devices_by_ip.get(ip_address)
            if not device:
                continue

            job_devices.append({
                "ip": device.get("ip"),
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "platform": device.get("platform"),
                "model": device.get("model"),
                "current_version": device.get("version"),
                "status": "ready",
                "progress": 0,
                "stage": "Ready"
            })

        if not job_devices:
            return jsonify({
                "success": False,
                "error": "Selected devices were not found."
            }), 400

        job = {
            "id": str(uuid.uuid4()),
            "type": "config_capture",
            "name": (
                payload.get("name")
                or f"Config Capture {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            ),
            "status": "ready",
            "created_at": datetime.now().isoformat(),
            "device_count": len(job_devices),
            "devices": job_devices
        }

    else:
        assignments = payload.get("assignments", {})

        firmware_database = read_json(FIRMWARE_DB_FILE, {"firmwares": []})
        firmware_by_id = {
            firmware.get("id"): firmware
            for firmware in firmware_database.get("firmwares", [])
        }

        job_devices = []

        for ip_address in selected_devices:
            device = devices_by_ip.get(ip_address)
            if not device:
                continue

            firmware_id = assignments.get(ip_address)
            firmware = firmware_by_id.get(firmware_id)
            if not firmware:
                return jsonify({
                    "success": False,
                    "error": f"No firmware selected for {ip_address}."
                }), 400

            job_devices.append({
                "ip": device.get("ip"),
                "hostname": device.get("hostname"),
                "vendor": device.get("vendor"),
                "platform": device.get("platform"),
                "model": device.get("model"),
                "current_version": device.get("version"),
                "target_version": firmware.get("version"),
                "firmware_id": firmware.get("id"),
                "firmware_filename": firmware.get("filename"),
                "status": "pending",
                "progress": 0,
                "stage": "Pending"
            })

        if not job_devices:
            return jsonify({
                "success": False,
                "error": "Selected devices were not found."
            }), 400

        job = {
            "id": str(uuid.uuid4()),
            "type": "upgrade",
            "name": (
                payload.get("name")
                or f"Upgrade Job {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            ),
            "status": "pending",
            "created_at": datetime.now().isoformat(),
            "device_count": len(job_devices),
            "devices": job_devices
        }

    def _insert_job(current_database):
        current_database.setdefault("jobs", []).insert(0, job)

    update_json(JOBS_FILE, {"jobs": []}, _insert_job)

    return jsonify({
        "success": True,
        "job": job
    })



def _precheck_config_push_job(target_job, database, demo_mode, username, password, ssh_settings):
    """Config-push jobs skip firmware entirely -- Pre-Check here just
    means: does the draft actually have command lines in it, and (real
    mode only) can Keystone reach the device over SSH at all. No
    storage/version/firmware-compatibility checks apply, because
    there's no firmware in this kind of job.
    """
    job_id = target_job.get("id")

    target_job["status"] = "prechecking"
    target_job["precheck_started_at"] = datetime.now().isoformat()
    target_job["logs"] = target_job.get("logs", [])
    target_job["logs"].append(UpgradeEngine.log_entry(
        "Demo Pre-Check started." if demo_mode else "Real Pre-Check started."
    ))
    logger.info(
        "Job %s: %s Config Push Pre-Check started for %d device(s) — mode=%s",
        job_id,
        "Demo" if demo_mode else "Real",
        len(target_job.get("devices", [])),
        "DEMO" if demo_mode else "REAL",
    )

    for device in target_job.get("devices", []):
        device.update({
            "status": "prechecking",
            "stage": "Running Demo Pre-Check" if demo_mode else "Running Pre-Check",
            "progress": 10
        })
    _persist_job(job_id, target_job)

    all_passed = True

    for device in target_job.get("devices", []):
        draft = device.get("draft_config") or ""
        non_empty = [ln for ln in draft.splitlines() if ln.strip() and not ln.strip().startswith("#")]

        if not non_empty:
            result = {
                "status": "failed",
                "checked_at": datetime.now().isoformat(),
                "mode": "demo" if demo_mode else "real",
                "checks": [{
                    "name": "Draft Config",
                    "status": "failed",
                    "message": "Draft config is empty (no command lines after stripping blank/comment lines)."
                }],
                "live_device_info": {},
            }
        elif demo_mode:
            result = {
                "status": "passed",
                "checked_at": datetime.now().isoformat(),
                "mode": "demo",
                "checks": [
                    {
                        "name": "SSH Connectivity",
                        "status": "passed",
                        "message": "Simulated connection successful (Demo Mode)."
                    },
                    {
                        "name": "Draft Config",
                        "status": "passed",
                        "message": f"{len(non_empty)} command line(s) ready to push."
                    },
                ],
                "live_device_info": {
                    "hostname": device.get("hostname"),
                    "vendor": device.get("vendor"),
                    "platform": device.get("platform"),
                    "model": device.get("model"),
                    "version": device.get("current_version") or device.get("version"),
                    "serial": device.get("serial", "DEMO-SERIAL"),
                },
            }
        else:
            def precheck_log_command(command, _device=device):
                logger.info("Job %s: %s $ %s", job_id, _device.get("ip"), command)
                target_job.setdefault("logs", []).append(
                    UpgradeEngine.log_entry(f"{_device.get('ip')} $ {command}", "command")
                )
                _persist_job(job_id, target_job)

            connection_result = SSHManager.connect(
                device.get("ip"), username, password,
                port=ssh_settings.get("port", 22), timeout=ssh_settings.get("timeout", 10),
                preferred_device_type="huawei",
            )
            connection = connection_result.get("connection") if connection_result.get("success") else None
            if not connection_result.get("success"):
                result = {
                    "status": "failed",
                    "checked_at": datetime.now().isoformat(),
                    "mode": "real",
                    "checks": [{
                        "name": "SSH Connectivity",
                        "status": "failed",
                        "message": connection_result.get("error"),
                    }],
                    "live_device_info": {},
                }
            else:
                try:
                    driver = detect_driver(
                        connection, connection_result["netmiko_device_type"], precheck_log_command
                    )
                    info = driver.get_device_info()
                    result = {
                        "status": "passed",
                        "checked_at": datetime.now().isoformat(),
                        "mode": "real",
                        "checks": [
                            {"name": "SSH Connectivity", "status": "passed", "message": "Connected successfully."},
                            {
                                "name": "Live Device Information",
                                "status": "passed",
                                "message": (
                                    f"{info.get('hostname', 'Unknown')} | "
                                    f"{info.get('model', 'Unknown')} | "
                                    f"{info.get('version', 'Unknown')}"
                                ),
                            },
                            {
                                "name": "Draft Config",
                                "status": "passed",
                                "message": f"{len(non_empty)} command line(s) ready to push.",
                            },
                        ],
                        "live_device_info": info,
                    }
                except Exception as exc:
                    result = {
                        "status": "failed",
                        "checked_at": datetime.now().isoformat(),
                        "mode": "real",
                        "checks": [{"name": "Pre-Check Engine", "status": "failed", "message": str(exc)}],
                        "live_device_info": {},
                    }
                finally:
                    try:
                        connection.disconnect()
                    except Exception:
                        pass

        device["precheck"] = result
        live = result.get("live_device_info") or {}
        for source, destination in [
            ("hostname", "live_hostname"),
            ("vendor", "live_vendor"),
            ("platform", "live_platform"),
            ("model", "live_model"),
            ("version", "live_version"),
            ("serial", "live_serial")
        ]:
            if live.get(source):
                device[destination] = live.get(source)

        passed = result.get("status") == "passed"
        device.update({
            "status": "ready" if passed else "failed",
            "stage": "Demo Pre-Check Passed" if (passed and demo_mode) else (
                "Pre-Check Passed" if passed else "Pre-Check Failed"
            ),
            "progress": 20 if passed else 0
        })
        target_job["logs"].append(UpgradeEngine.log_entry(
            f"{device.get('ip')}: {'Demo ' if demo_mode else ''}Pre-Check "
            f"{'passed' if passed else 'failed'}.",
            "info" if passed else "error"
        ))
        all_passed = all_passed and passed
        _persist_job(job_id, target_job)

    target_job["status"] = "ready" if all_passed else "precheck_failed"
    target_job["precheck_completed_at"] = datetime.now().isoformat()
    target_job["logs"].append(UpgradeEngine.log_entry(
        "Job is ready for config push." if (all_passed and demo_mode)
        else "Pre-Check completed."
    ))
    _persist_job(job_id, target_job)
    return jsonify({
        "success": True,
        "demo_mode": demo_mode,
        "job": target_job
    })


@app.route(
    "/api/jobs/<job_id>/precheck",
    methods=["POST"]
)
def run_job_precheck(job_id):
    payload = request.get_json(silent=True) or {}
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    demo_mode = settings.get("demo_mode", True)
    password = payload.get("password", "")
    ssh_settings = settings.get("ssh", {})
    username = payload.get("username") or ssh_settings.get("username") or ""

    # Credentials are required only for a real device Pre-Check.
    if not demo_mode:
        if not username:
            return jsonify({
                "success": False,
                "error": "SSH username is not configured in Settings."
            }), 400
        if not password:
            return jsonify({
                "success": False,
                "error": "SSH password is required."
            }), 400

    database = read_json(JOBS_FILE, {"jobs": []})
    target_job = next(
        (job for job in database.get("jobs", []) if job.get("id") == job_id),
        None
    )
    if not target_job:
        return jsonify({"success": False, "error": "Upgrade job not found."}), 404

    if target_job.get("type") == "config_push":
        return _precheck_config_push_job(
            target_job, database, demo_mode, username, password, ssh_settings
        )

    firmware_database = read_json(FIRMWARE_DB_FILE, {"firmwares": []})
    firmware_by_id = {
        item.get("id"): item
        for item in firmware_database.get("firmwares", [])
    }

    target_job["status"] = "prechecking"
    target_job["precheck_started_at"] = datetime.now().isoformat()
    target_job["logs"] = target_job.get("logs", [])
    target_job["logs"].append(UpgradeEngine.log_entry(
        "Demo Pre-Check started." if demo_mode else "Real Pre-Check started."
    ))
    logger.info(
        "Job %s: %s Pre-Check started for %d device(s) — mode=%s",
        job_id,
        "Demo" if demo_mode else "Real",
        len(target_job.get("devices", [])),
        "DEMO" if demo_mode else "REAL",
    )

    for device in target_job.get("devices", []):
        device.update({
            "status": "prechecking",
            "stage": "Running Demo Pre-Check" if demo_mode else "Running Pre-Check",
            "progress": 10
        })
    _persist_job(job_id, target_job)

    engine = None
    if not demo_mode:
        engine = PrecheckEngine(
            username=username,
            password=password,
            port=ssh_settings.get("port", 22),
            timeout=ssh_settings.get("timeout", 10)
        )

    all_passed = True

    for device in target_job.get("devices", []):
        firmware = firmware_by_id.get(device.get("firmware_id"))

        if demo_mode:
            firmware_name = (firmware or {}).get("filename", "Demo firmware")
            target_version = (
                (firmware or {}).get("version")
                or device.get("target_version")
                or "Unknown"
            )
            result = {
                "status": "passed",
                "checked_at": datetime.now().isoformat(),
                "mode": "demo",
                "checks": [
                    {
                        "name": "SSH Connectivity",
                        "status": "passed",
                        "message": "Simulated connection successful (Demo Mode)."
                    },
                    {
                        "name": "Driver Detection",
                        "status": "passed",
                        "message": f"Simulated driver for {device.get('vendor', 'Unknown')} {device.get('platform', '')}."
                    },
                    {
                        "name": "Live Device Information",
                        "status": "passed",
                        "message": (
                            f"{device.get('hostname', 'Unknown')} | "
                            f"{device.get('model', 'Unknown')} | "
                            f"Current version {device.get('current_version') or device.get('version', 'Unknown')}"
                        )
                    },
                    {
                        "name": "Firmware Compatibility",
                        "status": "passed",
                        "message": f"{firmware_name} is compatible with the simulated device."
                    },
                    {
                        "name": "Storage Capacity",
                        "status": "passed",
                        "message": "Simulated free storage is sufficient for firmware staging."
                    },
                    {
                        "name": "Upgrade Readiness",
                        "status": "passed",
                        "message": f"Device is ready for simulated upgrade to {target_version}."
                    }
                ],
                "live_device_info": {
                    "hostname": device.get("hostname"),
                    "vendor": device.get("vendor"),
                    "platform": device.get("platform"),
                    "model": device.get("model"),
                    "version": device.get("current_version") or device.get("version"),
                    "serial": device.get("serial", "DEMO-SERIAL")
                },
                "raw_outputs": {
                    "display_version": {
                        "command": "display version",
                        "status": "success",
                        "output": (
                            "Huawei Versatile Routing Platform Software\n"
                            f"VRP (R) software, Version {device.get('current_version') or device.get('version', 'V200R022')}\n"
                            f"{device.get('model', 'S5735')} uptime is 0 week, 1 day"
                        )
                    },
                    "display_startup": {
                        "command": "display startup",
                        "status": "success",
                        "output": (
                            "MainBoard:\n"
                            "  Configured startup system software: flash:/current_system.cc\n"
                            "  Startup saved-configuration file: flash:/vrpcfg.zip"
                        )
                    },
                    "display_device": {
                        "command": "display device",
                        "status": "success",
                        "output": f"Slot  Sub Type  Online  Power  Register  Status\n0     {device.get('model', 'S5735')}  Present  PowerOn  Registered  Normal"
                    },
                    "directory": {
                        "command": "dir",
                        "status": "success",
                        "output": "Directory of flash:/\n1,024,000 KB total (700,000 KB free)"
                    },
                    "display_patch_information": {
                        "command": "display patch-information",
                        "status": "success",
                        "output": "Patch Package Name: No patch package loaded (Demo Mode)"
                    }
                }
            }
        else:
            def precheck_log_command(command):
                logger.info("Job %s: %s $ %s", job_id, device.get("ip"), command)
                target_job.setdefault("logs", []).append(
                    UpgradeEngine.log_entry(f"{device.get('ip')} $ {command}", "command")
                )
                _persist_job(job_id, target_job)

            try:
                result = engine.run(device=device, firmware=firmware, log_fn=precheck_log_command)
            except Exception as exc:
                result = {
                    "status": "failed",
                    "checked_at": datetime.now().isoformat(),
                    "checks": [{
                        "name": "Pre-Check Engine",
                        "status": "failed",
                        "message": str(exc)
                    }],
                    "live_device_info": {}
                }

        device["precheck"] = result
        live = result.get("live_device_info") or {}
        for source, destination in [
            ("hostname", "live_hostname"),
            ("vendor", "live_vendor"),
            ("platform", "live_platform"),
            ("model", "live_model"),
            ("version", "live_version"),
            ("serial", "live_serial")
        ]:
            if live.get(source):
                device[destination] = live.get(source)

        passed = result.get("status") == "passed"
        device.update({
            "status": "ready" if passed else "failed",
            "stage": "Demo Pre-Check Passed" if (passed and demo_mode) else (
                "Pre-Check Passed" if passed else "Pre-Check Failed"
            ),
            "progress": 20 if passed else 0
        })
        target_job["logs"].append(UpgradeEngine.log_entry(
            f"{device.get('ip')}: {'Demo ' if demo_mode else ''}Pre-Check "
            f"{'passed' if passed else 'failed'}.",
            "info" if passed else "error"
        ))
        all_passed = all_passed and passed
        _persist_job(job_id, target_job)

    target_job["status"] = "ready" if all_passed else "precheck_failed"
    target_job["precheck_completed_at"] = datetime.now().isoformat()
    target_job["logs"].append(UpgradeEngine.log_entry(
        "Job is ready for simulated upgrade." if (all_passed and demo_mode)
        else "Pre-Check completed."
    ))
    _persist_job(job_id, target_job)
    return jsonify({
        "success": True,
        "demo_mode": demo_mode,
        "job": target_job
    })


@app.route(
    "/api/jobs/<job_id>",
    methods=["DELETE"]
)
def delete_job(job_id):

    database = read_json(
        JOBS_FILE,
        {
            "jobs": []
        }
    )


    original_count = len(
        database.get(
            "jobs",
            []
        )
    )


    database["jobs"] = [

        job

        for job in database.get(
            "jobs",
            []
        )

        if job.get("id")
        !=
        job_id

    ]


    if (
        len(
            database["jobs"]
        )
        ==
        original_count
    ):

        return jsonify({
            "success": False,
            "error": "Upgrade job not found."
        }), 404


    write_json(
        JOBS_FILE,
        database
    )


    return jsonify({
        "success": True
    })


@app.route(
    "/api/jobs/<job_id>/devices/<path:ip_address>/backup",
    methods=["GET"]
)
def download_capture_backup(job_id, ip_address):
    # Path comes from the job record itself (capture_bundle.path,
    # stamped by ConfigCaptureEngine under BASE_DIR / "backups"), never
    # from the request -- job_id/ip_address only select WHICH stored
    # path to serve, so there's no path-traversal surface here despite
    # the file living on disk outside static/.
    database = read_json(JOBS_FILE, {"jobs": []})
    target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
    if not target_job:
        return jsonify({"success": False, "error": "Job not found."}), 404

    target_device = next(
        (device for device in target_job.get("devices", []) if device.get("ip") == ip_address),
        None
    )
    if not target_device:
        return jsonify({"success": False, "error": "Device not found in this job."}), 404

    bundle = target_device.get("capture_bundle")
    if not bundle or not bundle.get("path"):
        return jsonify({"success": False, "error": "No backup captured for this device yet."}), 404

    bundle_path = Path(bundle["path"])
    if not bundle_path.is_file():
        return jsonify({"success": False, "error": "Backup file is missing on disk."}), 404

    hostname = target_device.get("hostname") or target_device.get("ip") or "device"
    captured_at = (bundle.get("captured_at") or "")[:19].replace(":", "").replace("-", "").replace("T", "_")
    download_name = f"{hostname}_{captured_at or 'backup'}.txt"

    return send_file(
        bundle_path,
        as_attachment=True,
        download_name=download_name,
        mimetype="text/plain",
    )


def execute_upgrade_job(job_id, password=""):
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    firmware_database = read_json(FIRMWARE_DB_FILE, {"firmwares": []})
    firmware_by_id = {item.get("id"): item for item in firmware_database.get("firmwares", [])}
    ssh_settings = settings.get("ssh", {})
    upgrade_settings = settings.get("upgrade", {})
    transfer_settings = settings.get("transfer", {})
    demo_mode = settings.get("demo_mode", True)
    logger.info(
        "Job %s: execute_upgrade_job starting — mode=%s, transfer_method=%s",
        job_id,
        "DEMO" if demo_mode else "REAL",
        transfer_settings.get("method", "sftp"),
    )
    engine = UpgradeEngine(
        demo_mode=demo_mode,
        stage_delay=2,
        username=ssh_settings.get("username", ""),
        password=password,
        port=ssh_settings.get("port", 22),
        timeout=ssh_settings.get("timeout", 10),
        reconnect_timeout=upgrade_settings.get("reconnect_timeout", 600),
        reconnect_interval=upgrade_settings.get("reconnect_interval", 10),
        firmware_by_id=firmware_by_id,
        firmware_dir=FIRMWARE_DIR,
        backup_dir=BASE_DIR / "backups",
        transfer_method=transfer_settings.get("method", "sftp"),
        tftp_server_ip=transfer_settings.get("tftp_server_ip") or None,
        tftp_port=transfer_settings.get("tftp_port", 69),
        ftp_server_ip=transfer_settings.get("ftp_server_ip") or None,
        ftp_port=transfer_settings.get("ftp_port", 21),
        max_parallel=upgrade_settings.get("max_parallel", 10),
    )

    try:
        database = read_json(JOBS_FILE, {"jobs": []})
        target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
        if not target_job:
            logger.warning("Job %s: not found when execution started.", job_id)
            return

        def update_device(device_reference, stage, progress, status):
            if status == "command":
                logger.info(
                    "Job %s: %s $ %s",
                    job_id, device_reference.get("ip"), stage,
                )

                def _apply_command(current_database):
                    current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                    if not current_job:
                        return
                    current_job.setdefault("logs", []).append(
                        UpgradeEngine.log_entry(f"{device_reference.get('ip')} $ {stage}", "command")
                    )

                update_json(JOBS_FILE, {"jobs": []}, _apply_command)
                return

            logger.info(
                "Job %s: %s -> %s (%s%%, %s)",
                job_id, device_reference.get("ip"), stage, progress, status,
            )

            def _apply_progress(current_database):
                current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                if not current_job:
                    return
                current_device = next((item for item in current_job.get("devices", []) if item.get("ip") == device_reference.get("ip")), None)
                if not current_device:
                    return
                current_device.update({"stage": stage, "progress": progress, "status": status})

                # A job is "done" once every device has reached a
                # TERMINAL state -- completed OR failed -- not just
                # once every device is "completed". Before this fix,
                # a device that ended up "failed" (which never used to
                # happen without also aborting the whole job, until
                # run_job() started isolating per-device failures
                # instead of propagating them) meant this condition
                # could never become true again: `all(... ==
                # "completed" ...)` stays false forever once one
                # device is "failed" and stops progressing, so the job
                # was stuck showing "RUNNING" indefinitely even though
                # every device had already finished (one way or
                # another).
                devices_in_job = current_job.get("devices", [])
                terminal_statuses = {"completed", "failed"}
                all_terminal = bool(devices_in_job) and all(
                    item.get("status") in terminal_statuses for item in devices_in_job
                )
                if all_terminal:
                    current_job["status"] = "completed" if all(
                        item.get("status") == "completed" for item in devices_in_job
                    ) else "failed"
                else:
                    current_job["status"] = "running"

                current_job.setdefault("logs", []).append(UpgradeEngine.log_entry(f"{current_device.get('ip')}: {stage}"))
                if current_job["status"] in ("completed", "failed"):
                    current_job["completed_at"] = datetime.now().isoformat()

            update_json(JOBS_FILE, {"jobs": []}, _apply_progress)

        engine.run_job(target_job.get("devices", []), update_device)
        logger.info("Job %s: execute_upgrade_job finished without raising.", job_id)

    except Exception as exc:
        logger.error("Job %s: FAILED — %s", job_id, exc)

        def _apply_failure(database):
            target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
            if target_job:
                target_job["status"] = "failed"
                target_job.setdefault("logs", []).append(UpgradeEngine.log_entry(str(exc), "error"))
                for device in target_job.get("devices", []):
                    if device.get("status") != "completed":
                        device.update({"status": "failed", "stage": "Upgrade Failed"})

        update_json(JOBS_FILE, {"jobs": []}, _apply_failure)


def execute_config_push_job(job_id, password=""):
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    ssh_settings = settings.get("ssh", {})
    upgrade_settings = settings.get("upgrade", {})
    demo_mode = settings.get("demo_mode", True)
    logger.info(
        "Job %s: execute_config_push_job starting — mode=%s",
        job_id,
        "DEMO" if demo_mode else "REAL",
    )
    engine = ConfigPushEngine(
        demo_mode=demo_mode,
        stage_delay=2,
        username=ssh_settings.get("username", ""),
        password=password,
        port=ssh_settings.get("port", 22),
        timeout=ssh_settings.get("timeout", 10),
        backup_dir=BASE_DIR / "backups",
        max_parallel=upgrade_settings.get("max_parallel", 10),
    )

    try:
        database = read_json(JOBS_FILE, {"jobs": []})
        target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
        if not target_job:
            logger.warning("Job %s: not found when execution started.", job_id)
            return

        def update_device(device_reference, stage, progress, status):
            if status == "command":
                logger.info(
                    "Job %s: %s $ %s",
                    job_id, device_reference.get("ip"), stage,
                )

                def _apply_command(current_database):
                    current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                    if not current_job:
                        return
                    current_job.setdefault("logs", []).append(
                        UpgradeEngine.log_entry(f"{device_reference.get('ip')} $ {stage}", "command")
                    )

                update_json(JOBS_FILE, {"jobs": []}, _apply_command)
                return

            if status == "command_result":
                # `stage` here is the {"line", "status", "output"} dict
                # push_config_lines() streamed via on_result -- persisted
                # right away (both as structured per-device data for a
                # live command table, and as a color-coded log line
                # reusing the existing Execution Log panel) instead of
                # waiting for device["config_push_result"] to be stamped
                # in one lump once the whole draft finishes below.
                result = stage
                logger.info(
                    "Job %s: %s %s $ %s",
                    job_id, device_reference.get("ip"),
                    "OK" if result.get("status") == "success" else "FAILED",
                    result.get("line"),
                )

                def _apply_command_result(current_database):
                    current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                    if not current_job:
                        return
                    current_device = next((item for item in current_job.get("devices", []) if item.get("ip") == device_reference.get("ip")), None)
                    if current_device is not None:
                        current_device.setdefault("live_command_results", []).append(result)
                    ok = result.get("status") == "success"
                    current_job.setdefault("logs", []).append(
                        UpgradeEngine.log_entry(
                            f"{device_reference.get('ip')} {'OK' if ok else 'FAILED'} $ {result.get('line')}",
                            "command-success" if ok else "command-failed",
                        )
                    )

                update_json(JOBS_FILE, {"jobs": []}, _apply_command_result)
                return

            logger.info(
                "Job %s: %s -> %s (%s%%, %s)",
                job_id, device_reference.get("ip"), stage, progress, status,
            )

            def _apply_progress(current_database):
                current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                if not current_job:
                    return
                current_device = next((item for item in current_job.get("devices", []) if item.get("ip") == device_reference.get("ip")), None)
                if not current_device:
                    return
                current_device.update({"stage": stage, "progress": progress, "status": status})

                # ConfigPushEngine stamps the per-line push audit trail
                # (which lines succeeded/failed) directly onto the
                # device dict it was handed -- device_reference here --
                # but update_json() always operates on a freshly
                # re-read copy of the job, not that same object. Copy
                # it across the first time it's there so it ends up
                # persisted in jobs.json instead of only living in the
                # worker thread's memory.
                if device_reference.get("config_push_result") and not current_device.get("config_push_result"):
                    current_device["config_push_result"] = device_reference["config_push_result"]

                devices_in_job = current_job.get("devices", [])
                terminal_statuses = {"completed", "failed"}
                all_terminal = bool(devices_in_job) and all(
                    item.get("status") in terminal_statuses for item in devices_in_job
                )
                if all_terminal:
                    current_job["status"] = "completed" if all(
                        item.get("status") == "completed" for item in devices_in_job
                    ) else "failed"
                else:
                    current_job["status"] = "running"

                current_job.setdefault("logs", []).append(UpgradeEngine.log_entry(f"{current_device.get('ip')}: {stage}"))
                if current_job["status"] in ("completed", "failed"):
                    current_job["completed_at"] = datetime.now().isoformat()

            update_json(JOBS_FILE, {"jobs": []}, _apply_progress)

        engine.run_job(target_job.get("devices", []), update_device)
        logger.info("Job %s: execute_config_push_job finished without raising.", job_id)

    except Exception as exc:
        logger.error("Job %s: FAILED — %s", job_id, exc)

        def _apply_failure(database):
            target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
            if target_job:
                target_job["status"] = "failed"
                target_job.setdefault("logs", []).append(UpgradeEngine.log_entry(str(exc), "error"))
                for device in target_job.get("devices", []):
                    if device.get("status") != "completed":
                        device.update({"status": "failed", "stage": "Config Push Failed"})

        update_json(JOBS_FILE, {"jobs": []}, _apply_failure)


def execute_config_capture_job(job_id, password=""):
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    ssh_settings = settings.get("ssh", {})
    upgrade_settings = settings.get("upgrade", {})
    demo_mode = settings.get("demo_mode", True)
    logger.info(
        "Job %s: execute_config_capture_job starting — mode=%s",
        job_id,
        "DEMO" if demo_mode else "REAL",
    )
    engine = ConfigCaptureEngine(
        demo_mode=demo_mode,
        stage_delay=2,
        username=ssh_settings.get("username", ""),
        password=password,
        port=ssh_settings.get("port", 22),
        timeout=ssh_settings.get("timeout", 10),
        backup_dir=BASE_DIR / "backups",
        max_parallel=upgrade_settings.get("max_parallel", 10),
    )

    try:
        database = read_json(JOBS_FILE, {"jobs": []})
        target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
        if not target_job:
            logger.warning("Job %s: not found when execution started.", job_id)
            return

        def update_device(device_reference, stage, progress, status):
            if status == "command":
                logger.info(
                    "Job %s: %s $ %s",
                    job_id, device_reference.get("ip"), stage,
                )

                def _apply_command(current_database):
                    current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                    if not current_job:
                        return
                    current_job.setdefault("logs", []).append(
                        UpgradeEngine.log_entry(f"{device_reference.get('ip')} $ {stage}", "command")
                    )

                update_json(JOBS_FILE, {"jobs": []}, _apply_command)
                return

            if status == "command_result":
                # Same reasoning as ConfigPushEngine's identically-named
                # branch: persisted the moment EACH command's result is
                # known (capture_config()'s on_result), both as
                # structured per-device data (reusing
                # live_command_results / the {"line","status","output"}
                # shape, so the existing Live Commands panel needs no
                # changes to render a capture job) and as a color-coded
                # Execution Log line.
                result = stage
                logger.info(
                    "Job %s: %s %s $ %s",
                    job_id, device_reference.get("ip"),
                    "OK" if result.get("status") == "success" else "FAILED",
                    result.get("line"),
                )

                def _apply_command_result(current_database):
                    current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                    if not current_job:
                        return
                    current_device = next((item for item in current_job.get("devices", []) if item.get("ip") == device_reference.get("ip")), None)
                    if current_device is not None:
                        current_device.setdefault("live_command_results", []).append(result)
                    ok = result.get("status") == "success"
                    current_job.setdefault("logs", []).append(
                        UpgradeEngine.log_entry(
                            f"{device_reference.get('ip')} {'OK' if ok else 'FAILED'} $ {result.get('line')}",
                            "command-success" if ok else "command-failed",
                        )
                    )

                update_json(JOBS_FILE, {"jobs": []}, _apply_command_result)
                return

            logger.info(
                "Job %s: %s -> %s (%s%%, %s)",
                job_id, device_reference.get("ip"), stage, progress, status,
            )

            def _apply_progress(current_database):
                current_job = next((job for job in current_database.get("jobs", []) if job.get("id") == job_id), None)
                if not current_job:
                    return
                current_device = next((item for item in current_job.get("devices", []) if item.get("ip") == device_reference.get("ip")), None)
                if not current_device:
                    return
                current_device.update({"stage": stage, "progress": progress, "status": status})

                # ConfigCaptureEngine stamps capture_bundle (where the
                # combined backup file landed) directly onto the device
                # dict it was handed -- device_reference here -- but
                # update_json() always operates on a freshly re-read
                # copy of the job. Copy it across the first time it's
                # there so it ends up persisted in jobs.json instead of
                # only living in the worker thread's memory.
                if device_reference.get("capture_bundle") and not current_device.get("capture_bundle"):
                    current_device["capture_bundle"] = device_reference["capture_bundle"]

                devices_in_job = current_job.get("devices", [])
                terminal_statuses = {"completed", "failed"}
                all_terminal = bool(devices_in_job) and all(
                    item.get("status") in terminal_statuses for item in devices_in_job
                )
                if all_terminal:
                    current_job["status"] = "completed" if all(
                        item.get("status") == "completed" for item in devices_in_job
                    ) else "failed"
                else:
                    current_job["status"] = "running"

                current_job.setdefault("logs", []).append(UpgradeEngine.log_entry(f"{current_device.get('ip')}: {stage}"))
                if current_job["status"] in ("completed", "failed"):
                    current_job["completed_at"] = datetime.now().isoformat()

            update_json(JOBS_FILE, {"jobs": []}, _apply_progress)

        engine.run_job(target_job.get("devices", []), update_device)
        logger.info("Job %s: execute_config_capture_job finished without raising.", job_id)

    except Exception as exc:
        logger.error("Job %s: FAILED — %s", job_id, exc)

        def _apply_failure(database):
            target_job = next((job for job in database.get("jobs", []) if job.get("id") == job_id), None)
            if target_job:
                target_job["status"] = "failed"
                target_job.setdefault("logs", []).append(UpgradeEngine.log_entry(str(exc), "error"))
                for device in target_job.get("devices", []):
                    if device.get("status") != "completed":
                        device.update({"status": "failed", "stage": "Config Capture Failed"})

        update_json(JOBS_FILE, {"jobs": []}, _apply_failure)


@app.route(
    "/api/jobs/<job_id>/start",
    methods=["POST"]
)
def start_upgrade_job(job_id):

    payload = request.get_json(silent=True) or {}
    settings = read_json(SETTINGS_FILE, DEFAULT_SETTINGS)
    demo_mode = settings.get("demo_mode", True)
    password = payload.get("password", "")
    logger.info(
        "Job %s: /start requested — mode=%s, password_provided=%s",
        job_id, "DEMO" if demo_mode else "REAL", bool(password),
    )
    if not demo_mode and not password:
        return jsonify({"success": False, "error": "SSH password is required for real upgrade mode."}), 400

    database = read_json(
        JOBS_FILE,
        {
            "jobs": []
        }
    )


    target_job = next(
        (
            job
            for job in database.get(
                "jobs",
                []
            )
            if job.get("id")
            ==
            job_id
        ),
        None
    )


    if not target_job:

        return jsonify({
            "success": False,
            "error": "Upgrade job not found."
        }), 404


    if target_job.get(
        "status"
    ) != "ready":

        return jsonify({
            "success": False,
            "error": (
                "Job must pass Pre-Check "
                "before starting."
            )
        }), 400

    job_type = target_job.get("type") or "upgrade"

    if not demo_mode:
        # Real (non-demo) upgrades AND config pushes are only
        # implemented end-to-end for Huawei VRP today (see
        # UpgradeEngine._run_huawei_device / ConfigPushEngine.
        # _push_huawei_device). The Cisco/Aruba drivers only
        # implement device-info/storage inspection. Reject here, up
        # front, instead of letting the job reach "running" and fail
        # partway through against a real device.
        unsupported = [
            device.get("ip")
            for device in target_job.get("devices", [])
            if "huawei" not in str(device.get("vendor") or device.get("live_vendor") or "").lower()
            and "vrp" not in str(device.get("platform") or device.get("live_platform") or "").lower()
        ]
        if unsupported:
            action = (
                "config pushes" if job_type == "config_push"
                else "config captures" if job_type == "config_capture"
                else "upgrades"
            )
            return jsonify({
                "success": False,
                "error": (
                    f"Real (non-demo) {action} currently support Huawei VRP only. "
                    f"Remove or switch to demo mode for: {', '.join(str(ip) for ip in unsupported)}."
                ),
            }), 400

    target_job["status"] = (
        "running"
    )

    target_job["started_at"] = (
        datetime.now().isoformat()
    )


    for device in target_job.get(
        "devices",
        []
    ):

        device["status"] = (
            "running"
        )

        device["stage"] = (
            "Starting Config Push" if job_type == "config_push"
            else "Starting Config Capture" if job_type == "config_capture"
            else "Starting Upgrade"
        )

        device["progress"] = 25


    write_json(
        JOBS_FILE,
        database
    )


    worker = threading.Thread(
        target=(
            execute_config_push_job if job_type == "config_push"
            else execute_config_capture_job if job_type == "config_capture"
            else execute_upgrade_job
        ),
        args=(job_id, password),
        daemon=True
    )


    worker.start()


    return jsonify({
        "success": True,
        "job": target_job
    })


# ============================================================
# API - CONFIG PUSH DRAFTS
#
# A "draft" is just operator-prepared CLI text for one device, saved
# so it can be picked (rather than re-pasted) when building a
# config_push job. It can come from pasting text directly, or from
# Configuration Studio's converter output ("source": "configuration_studio")
# via its own "Save as Config Push Draft" action -- either way it
# lands in the same store.
# ============================================================

@app.route(
    "/api/config-drafts",
    methods=["GET"]
)
def get_config_drafts():
    return jsonify(read_json(CONFIG_DRAFTS_FILE, {"drafts": []}))


@app.route(
    "/api/config-drafts",
    methods=["POST"]
)
def create_config_draft():
    payload = request.get_json(silent=True) or {}
    content = (payload.get("content") or "").strip()
    if not content:
        return jsonify({"success": False, "error": "Draft content is empty."}), 400

    non_empty = [ln for ln in content.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    draft = {
        "id": str(uuid.uuid4()),
        "hostname": (payload.get("hostname") or "").strip() or "unnamed",
        "vendor": (payload.get("vendor") or "").strip(),
        "source": payload.get("source") or "manual",
        "content": content,
        "line_count": len(non_empty),
        "created_at": datetime.now().isoformat(),
    }

    database = read_json(CONFIG_DRAFTS_FILE, {"drafts": []})
    database["drafts"].insert(0, draft)
    write_json(CONFIG_DRAFTS_FILE, database)

    return jsonify({"success": True, "draft": draft})


@app.route(
    "/api/config-drafts/<draft_id>",
    methods=["DELETE"]
)
def delete_config_draft(draft_id):
    database = read_json(CONFIG_DRAFTS_FILE, {"drafts": []})
    original_count = len(database.get("drafts", []))
    database["drafts"] = [d for d in database.get("drafts", []) if d.get("id") != draft_id]

    if len(database["drafts"]) == original_count:
        return jsonify({"success": False, "error": "Draft not found."}), 404

    write_json(CONFIG_DRAFTS_FILE, database)
    return jsonify({"success": True})


# ============================================================
# API - SETTINGS
# ============================================================

@app.route(
    "/api/settings",
    methods=["GET"]
)
def get_settings():

    return jsonify(
        read_json(
            SETTINGS_FILE,
            DEFAULT_SETTINGS
        )
    )


@app.route(
    "/api/settings",
    methods=["POST"]
)
def save_settings():

    payload = (
        request.get_json(
            silent=True
        )
        or {}
    )

    current = read_json(
        SETTINGS_FILE,
        DEFAULT_SETTINGS
    )

    current.update(
        payload
    )

    write_json(
        SETTINGS_FILE,
        current
    )

    return jsonify({
        "success": True,
        "settings": current
    })


# ============================================================
# ZTP (ZERO TOUCH PROVISIONING) -- hook into Discovery only
#
# ZTP itself (pre-registration, intermediate file, DHCP/SFTP staging
# servers, firmware push) moved to its own feature module/blueprint
# at features/ztp -- it's a genuinely different mechanism (the
# device initiates against Keystone, not the other way around) and
# doesn't belong folded into this blueprint. See features/ztp/routes.py.
#
# The one thing that stays here: once a device shows up in a real
# discovery scan, auto-mark its ZTP pre-registration "provisioned" --
# this has to live on Lifecycle's own /api/discovery route, so it
# needs ztp_store, imported from the new location below.
# ============================================================

def _ztp_auto_mark_provisioned(discovered_devices):
    """Correlate a real /api/discovery scan against the ZTP pre-registration
    store and mark any match "provisioned" automatically.

    Without this, marking a device provisioned was a manual click in the
    ZTP tab even after the device was already discovered and working --
    easy to forget, and a forgotten one keeps reappearing in every future
    /api/ztp/generate call and DHCP reservation list forever (the same
    failure mode the devices/<esn>/status endpoint itself was added to
    fix -- see routes history). The Huawei VRP driver already runs
    `display esn` during discovery and returns it as `serial`
    (drivers/huawei/vrp.py get_device_info), so a discovered device's ESN
    is directly comparable to a ztp_store entry's esn with no extra
    round-trip to the device.

    Best-effort and silent on any single device: a malformed/"Unknown"
    serial (non-Huawei vendors, or a Huawei device where `display esn`
    failed) must not break the discovery response for every other
    device in the same scan. Returns the list of ESNs actually flipped
    to "provisioned", for the caller to surface in the response.
    """
    newly_provisioned = []
    for device in discovered_devices:
        serial = device.get("serial")
        if not serial or serial == "Unknown":
            continue
        try:
            existing = ztp_store.get_device(serial)
        except ztp_store.ZtpStoreError:
            continue
        except ztp_store.ZtpStoreReadError:
            # Unlike a malformed serial (a per-device, expected, silently
            # skippable case), this means the WHOLE ZTP device store is
            # currently unreadable -- every other device in this scan
            # would hit the exact same error. Not worth chasing further:
            # log it once (unlike a bad serial, this is unexpected and an
            # operator should know about it) and stop trying for this
            # scan rather than logging the same failure once per device.
            logger.warning(
                "ZTP auto-mark-provisioned: device store unreadable, "
                "skipping auto-provisioning for the rest of this scan.",
                exc_info=True,
            )
            break
        if existing is None or existing.get("status") == "provisioned":
            continue
        try:
            ztp_store.mark_status(serial, "provisioned")
        except (ztp_store.ZtpStoreError, ztp_store.ZtpStoreReadError):
            continue
        newly_provisioned.append(existing["esn"])
        logger.info(
            "ZTP auto-provisioned: discovered device with ESN %s matched a "
            "pre-registered entry, marked provisioned.",
            existing["esn"],
        )
    return newly_provisioned




# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(413)
def file_too_large(error):

    return jsonify({
        "success": False,
        "error": (
            "Firmware file is too large."
        )
    }), 413


@app.errorhandler(404)
def not_found(error):

    return jsonify({
        "success": False,
        "error": "Not found"
    }), 404


# ============================================================
# START APPLICATION
# ============================================================
