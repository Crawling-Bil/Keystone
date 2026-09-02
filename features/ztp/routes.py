"""Zero Touch Provisioning (ZTP) -- bringing a factory-default Huawei
VRP switch onto the network without ever typing a console command,
and the Lifecycle Manager firmware/OS upgrade path for devices
already under management.

Split out from features.lifecycle_manager into its own feature
module/blueprint: this is a genuinely different mechanism (the
device initiates DHCP + SFTP against Keystone; nothing here assumes
the device already has credentials Keystone could log into), so it
does not belong folded into Lifecycle Manager's Discovery/Pre-Check/
Upgrade blueprint. See the module docstrings under core/ for exactly
what is and isn't validated against real hardware.

One real cross-feature dependency remains, deliberately: Lifecycle
Manager's real /api/discovery route auto-marks a pre-registered ZTP
device "provisioned" once it shows up in a scan (see
features.lifecycle_manager.routes._ztp_auto_mark_provisioned), so it
imports core.store from here. That's the only coupling in either
direction -- this module does not import anything from
lifecycle_manager.
"""

import logging
import threading
from pathlib import Path

from flask import Blueprint, jsonify, render_template, request, send_file

from .core import store as ztp_store
from .core import intermediate_file as ztp_intermediate_file
from .core import config_template as ztp_config_template
from .core import sftp_server as ztp_sftp_module
from .core import dhcp_server as ztp_dhcp_module
from .core import syslog_server as ztp_syslog_module
from .core import net_interfaces as ztp_net_interfaces
from .core import device_import as ztp_device_import
from .core import activity_log as ztp_activity_log

# Firmware pushed during ZTP comes from the SAME Firmware Repository
# Lifecycle Manager's own Pre-Check/Upgrade flow uses -- one shared
# source of truth for firmware files, not a second copy. Safe
# one-directional dependency: lifecycle_manager.routes only imports
# features.ztp.core (never features.ztp.routes), so this can't cycle.
import shutil
import features.lifecycle_manager.routes as lifecycle_routes
from features.lifecycle_manager.routes import get_firmware_database

logger = logging.getLogger("nes.ztp")
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[ztp] %(asctime)s %(message)s", "%H:%M:%S"))
    logger.addHandler(_handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

bp = Blueprint(
    "ztp",
    __name__,
    url_prefix="/ztp",
    template_folder="templates",
    static_folder="static"
)


# ============================================================
# ZTP DATA / STAGING PATHS
# ============================================================

ZTP_DATA_DIR = Path(__file__).resolve().parent / "data"
ZTP_STAGING_DIR = ZTP_DATA_DIR / "staging"
ZTP_STAGING_DIR.mkdir(parents=True, exist_ok=True)

_ztp_sftp_instance = None
_ztp_dhcp_instance = None
_ztp_syslog_instance = None
_ztp_servers_lock = threading.Lock()


# ============================================================
# PAGE ROUTE
# ============================================================

@bp.route("/")
def index():
    return render_template(
        "ztp/index.html",
        active_page="ztp"
    )


class ZtpFirmwareStagingError(ValueError):
    """A device's firmware_filename can't be staged for ZTP -- either
    it's not in the Firmware Repository, or the file backing that
    repository entry is missing from disk."""


def _stage_firmware_for_device(device):
    """Copy the firmware image a pre-registered device references
    (Firmware Repository, under Lifecycle Manager's FIRMWARE_DIR) into
    ZTP_STAGING_DIR so the ZTP SFTP server can actually serve it.

    Without this, a device registered with firmware_filename set gets
    a SOFTWARE line in the intermediate file (see
    core.intermediate_file._device_files) pointing at a file that was
    never copied anywhere near the staging directory -- the switch's
    SFTP GET for it fails partway through ZTP, and the whole
    deployment stalls on that device. build_intermediate_file()'s own
    ztp_root docstring already assumed this staging step existed
    ("used to compute SHA256 checksums for files that already exist
    there") -- it just never got wired up on the routes.py side.

    Skips the copy if the destination already has a same-size file
    (repeated Generate calls shouldn't re-copy a 200+MB image every
    time), so this is safe to call on every /api/generate.
    """
    firmware_filename = (device.get("firmware_filename") or "").strip()
    if not firmware_filename:
        return

    entry = next(
        (
            fw for fw in get_firmware_database().get("firmwares", [])
            if fw.get("filename") == firmware_filename
        ),
        None,
    )
    if entry is None:
        raise ZtpFirmwareStagingError(
            f"Device {device.get('esn')}: firmware file {firmware_filename!r} is not in the "
            "Firmware Repository -- upload it there first, or clear Firmware Filename on this "
            "device to deploy config only."
        )

    source = lifecycle_routes.FIRMWARE_DIR / str(entry.get("vendor") or "").lower() / firmware_filename
    if not source.is_file():
        raise ZtpFirmwareStagingError(
            f"Device {device.get('esn')}: firmware file {firmware_filename!r} is listed in the "
            f"Firmware Repository but missing on disk at {source} -- re-upload it."
        )

    destination = ZTP_STAGING_DIR / firmware_filename
    if destination.is_file() and destination.stat().st_size == source.stat().st_size:
        return

    shutil.copy2(source, destination)
    logger.info(
        "ZTP generate: staged firmware %s (%d bytes) into %s for device %s",
        firmware_filename, source.stat().st_size, ZTP_STAGING_DIR, device.get("esn"),
    )


def _esn_for_ip(client_ip):
    """Best-effort match of an SFTP client's IP back to a
    pre-registered device's ESN, so Activity feed entries can say
    "STR2-SWAC-OT-TASTI-S5735 downloaded ..." instead of just an IP.
    Matches on mgmt_ip, which is what a device's ZTP-pushed .cfg sets
    it to be -- but during the ZTP window itself a device is normally
    still on its temporary DHCP-leased IP, not mgmt_ip yet, so this
    frequently comes back None during the actual download phase and
    that's fine, the feed just shows the bare IP in that case."""
    for device in ztp_store.list_devices():
        if device.get("mgmt_ip") == client_ip:
            return device.get("esn")
    return None


def _record_sftp_file_request(client_ip, path, found):
    """on_file_request callback wired into ZtpSftpServer -- fires for
    every SFTP open() a connected switch makes against the staging
    dir, successful or not. This is Keystone's only network-visible
    signal of ZTP progress that doesn't depend on the still-unverified
    SYSLOG_INFO path (see syslog_server.py's docstring) -- it can show
    "which file is it fetching right now" even if the syslog forward
    never arrives."""
    filename = path.lstrip("/") or "/"
    esn = _esn_for_ip(client_ip)
    if found:
        message = f"{client_ip} downloaded {filename}"
    else:
        message = f"{client_ip} requested {filename} -- not found in staging"
    ztp_activity_log.record(
        "sftp", message, esn=esn, level="info" if found else "warning"
    )


def _redact_device(device):
    """Never echo the plaintext vrp_password back over the API --
    the caller already knows what it set, and there's no legitimate
    reason for a device listing to hand back live SSH credentials."""
    redacted = dict(device)
    redacted["has_password"] = bool(redacted.pop("vrp_password", ""))
    return redacted


@bp.route(
    "/api/interfaces",
    methods=["GET"]
)
def ztp_list_interfaces():
    """List this machine's local network interfaces, for the ZTP tab's
    SFTP bind-IP and DHCP interface dropdowns -- read-only, no
    elevated privileges required (see net_interfaces.py)."""
    try:
        interfaces = ztp_net_interfaces.list_interfaces()
    except Exception as exc:
        # Never let an interface-enumeration quirk on some platform
        # break the whole ZTP tab -- the dropdowns just fall back to a
        # manual text entry client-side if this comes back empty/failed.
        logger.warning("ZTP interface listing failed: %s", exc)
        return jsonify({"success": False, "error": str(exc), "interfaces": []})
    return jsonify({"success": True, "interfaces": interfaces})

@bp.route(
    "/api/devices/template",
    methods=["GET"]
)
def ztp_devices_template():
    """Download a blank .xlsx template for bulk pre-registering ZTP
    devices -- one column per core.store.upsert_device() field,
    with a filled-in example row so the expected format is obvious
    without needing separate written instructions."""
    workbook_path = ztp_device_import.build_template_workbook()
    return send_file(
        workbook_path,
        as_attachment=True,
        download_name="ztp_device_template.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

@bp.route(
    "/api/devices/import",
    methods=["POST"]
)
def ztp_devices_import():
    """Bulk pre-register devices from an uploaded .xlsx (same columns
    as ztp_devices_template()). Every row is attempted independently --
    one bad row (bad ESN, missing password) must not block the rest of
    a batch of otherwise-good rows."""
    if "file" not in request.files or not request.files["file"].filename:
        return jsonify({"success": False, "error": "An .xlsx file is required."}), 400

    upload = request.files["file"]
    if not upload.filename.lower().endswith((".xlsx", ".xlsm")):
        return jsonify({"success": False, "error": "Only .xlsx/.xlsm files are supported."}), 400

    try:
        rows = ztp_device_import.parse_workbook(upload.stream)
    except ztp_device_import.DeviceImportError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    registered = []
    failed = []
    for row_number, record in rows:
        try:
            device = ztp_store.upsert_device(record)
            registered.append(device["esn"])
        except ztp_store.ZtpStoreError as exc:
            failed.append({"row": row_number, "esn": record.get("esn", ""), "error": str(exc)})
        except ztp_store.ZtpStoreReadError as exc:
            return jsonify({
                "success": False,
                "error": f"Aborted at row {row_number}: {exc}",
                "registered_count": len(registered),
                "registered_esns": registered,
                "failed": failed,
            }), 500

    return jsonify({
        "success": True,
        "registered_count": len(registered),
        "registered_esns": registered,
        "failed": failed,
    })

@bp.route(
    "/api/devices",
    methods=["GET"]
)
def ztp_list_devices():
    try:
        devices = ztp_store.list_devices()
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
    return jsonify({
        "success": True,
        "devices": [_redact_device(d) for d in devices]
    })

@bp.route(
    "/api/devices",
    methods=["POST"]
)
def ztp_upsert_device():
    payload = request.get_json(silent=True) or {}
    try:
        device = ztp_store.upsert_device(payload)
    except ztp_store.ZtpStoreError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
    return jsonify({"success": True, "device": _redact_device(device)})

@bp.route(
    "/api/devices/<esn>",
    methods=["DELETE"]
)
def ztp_delete_device(esn):
    try:
        removed = ztp_store.delete_device(esn)
    except ztp_store.ZtpStoreError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
    if not removed:
        return jsonify({"success": False, "error": "Device not found."}), 404
    return jsonify({"success": True})

@bp.route(
    "/api/devices/<esn>/status",
    methods=["POST"]
)
def ztp_set_device_status(esn):
    """Mark a pre-registered device's ZTP status (pending / provisioned
    / failed). Call this with "provisioned" once the device shows up
    in the normal /api/discovery flow after completing ZTP -- without
    this, a device stays "pending" forever, which means every future
    /api/ztp/generate call keeps re-including it (and re-adding its
    DHCP reservation), growing the intermediate file and reservation
    list with devices that are already done."""
    payload = request.get_json(silent=True) or {}
    status = str(payload.get("status") or "").strip()
    if status not in ("pending", "provisioned", "failed"):
        return jsonify({
            "success": False,
            "error": "status must be one of: pending, provisioned, failed."
        }), 400

    try:
        device = ztp_store.mark_status(esn, status)
    except ztp_store.ZtpStoreError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500
    if device is None:
        return jsonify({"success": False, "error": "Device not found."}), 404
    return jsonify({"success": True, "device": _redact_device(device)})

@bp.route(
    "/api/generate",
    methods=["POST"]
)
def ztp_generate():
    """Render the ZTP intermediate file plus one bootstrap config per
    pending pre-registered device, and write them into
    ZTP_STAGING_DIR -- the directory the ZTP SFTP server serves."""
    payload = request.get_json(silent=True) or {}
    fileserver_url = payload.get("fileserver_url")
    if not fileserver_url:
        return jsonify({
            "success": False,
            "error": "fileserver_url (sftp://user:password@host:port/path) is required."
        }), 400
    # Optional "<ip>:<port>" (or bare "<ip>") for the switch to forward
    # its ZTP log to via SYSLOG_INFO -- see syslog_server.py's
    # docstring for the caveat on whether the format is right.
    syslog_target = (payload.get("syslog_target") or "").strip() or None

    try:
        all_devices = ztp_store.list_devices()
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

    devices = [device for device in all_devices if device.get("status") != "provisioned"]
    if not devices:
        return jsonify({
            "success": False,
            "error": "No pending pre-registered devices to generate deployment files for."
        }), 400

    # A fresh Generate click means a new test/deployment cycle from the
    # operator's point of view -- clear the feed so it doesn't open
    # with a screen full of the previous cycle's events.
    ztp_activity_log.clear()
    ztp_activity_log.record(
        "generate",
        f"Generating deployment files for {len(devices)} device(s): "
        f"{', '.join(d.get('esn', '?') for d in devices)}",
    )

    # Stage every referenced firmware file BEFORE writing anything else --
    # fail the whole request up front on a missing/unresolvable firmware
    # file rather than partially writing configs and only then telling
    # the switch, via a dead SFTP GET, that its firmware was never there.
    try:
        for device in devices:
            _stage_firmware_for_device(device)
    except ZtpFirmwareStagingError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    # IMPORTANT: config files must be rendered and written to
    # ZTP_STAGING_DIR *before* build_intermediate_file() runs, not
    # after. build_intermediate_file() computes each file's SHA256_n
    # by hashing whatever's already sitting in ZTP_STAGING_DIR at the
    # moment it's called (see intermediate_file.py's _device_files) --
    # so calling it first (as this used to do) hashes the *previous*
    # generate's leftover .cfg, and the freshly-rendered .cfg then
    # overwrites that file a few lines later without the .ini's hash
    # ever being updated to match. Confirmed against real hardware:
    # the two generates produce byte-identical .cfg content unless the
    # underlying device data or config_template.py itself changed in
    # between, which is exactly why this stayed hidden through many
    # regenerates and only surfaced as a real "Integrity check failed"
    # ZTP error the moment the .cfg content actually changed between
    # one generate and the next.
    written_configs = []
    for device in devices:
        try:
            config_text = ztp_config_template.render_bootstrap_config(device)
        except ztp_config_template.ConfigTemplateError as exc:
            return jsonify({
                "success": False,
                "error": f"Device {device.get('esn')}: {exc}"
            }), 400
        config_filename = ztp_intermediate_file._sanitize_config_filename(
            device.get("hostname") or device.get("esn")
        )
        config_path = ZTP_STAGING_DIR / config_filename
        config_path.write_text(config_text, encoding="utf-8")
        written_configs.append(config_path.name)

    try:
        ini_text, config_filenames = ztp_intermediate_file.build_intermediate_file(
            devices,
            fileserver_url,
            ztp_root=ZTP_STAGING_DIR,
            syslog_target=syslog_target,
        )
    except ztp_intermediate_file.IntermediateFileError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400

    intermediate_path = ZTP_STAGING_DIR / "ztp_script.ini"
    intermediate_path.write_text(ini_text, encoding="utf-8")

    logger.info(
        "ZTP generate: wrote intermediate file + %d bootstrap config(s) to %s",
        len(written_configs), ZTP_STAGING_DIR,
    )
    ztp_activity_log.record(
        "generate",
        f"Wrote {intermediate_path.name} + {len(written_configs)} bootstrap config(s): "
        f"{', '.join(written_configs)}",
    )

    return jsonify({
        "success": True,
        "intermediate_file": intermediate_path.name,
        "config_files": written_configs,
        "staging_dir": str(ZTP_STAGING_DIR),
    })

@bp.route(
    "/api/sftp/start",
    methods=["POST"]
)
def ztp_sftp_start():
    global _ztp_sftp_instance

    payload = request.get_json(silent=True) or {}
    username = str(payload.get("username") or "").strip()
    password = payload.get("password") or ""
    bind_ip = str(payload.get("bind_ip") or "0.0.0.0")
    try:
        port = int(payload.get("port", 2222))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "port must be an integer."}), 400

    if not username or not password:
        return jsonify({"success": False, "error": "username and password are required."}), 400

    with _ztp_servers_lock:
        if _ztp_sftp_instance is not None:
            return jsonify({"success": False, "error": "ZTP SFTP server is already running."}), 400

        server = ztp_sftp_module.ZtpSftpServer(
            root_dir=ZTP_STAGING_DIR,
            username=username,
            password=password,
            bind_ip=bind_ip,
            port=port,
            data_dir=ZTP_DATA_DIR,
            on_file_request=_record_sftp_file_request,
        )
        try:
            server.start()
        except ztp_sftp_module.SftpServerError as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

        _ztp_sftp_instance = server

    logger.info("ZTP SFTP server started on %s:%s", bind_ip, server.port)
    ztp_activity_log.record("sftp", f"SFTP server started on {bind_ip}:{server.port}")
    return jsonify({"success": True, "bind_ip": bind_ip, "port": server.port})

@bp.route(
    "/api/sftp/stop",
    methods=["POST"]
)
def ztp_sftp_stop():
    global _ztp_sftp_instance

    with _ztp_servers_lock:
        if _ztp_sftp_instance is not None:
            _ztp_sftp_instance.stop()
            _ztp_sftp_instance = None
            ztp_activity_log.record("sftp", "SFTP server stopped.")

    return jsonify({"success": True})

@bp.route(
    "/api/sftp/status",
    methods=["GET"]
)
def ztp_sftp_status():
    return jsonify({
        "success": True,
        "running": _ztp_sftp_instance is not None
    })

@bp.route(
    "/api/dhcp/start",
    methods=["POST"]
)
def ztp_dhcp_start():
    global _ztp_dhcp_instance

    payload = request.get_json(silent=True) or {}
    required_fields = ["interface", "range_start", "range_end", "subnet_mask", "option67_url"]
    missing = [field for field in required_fields if not payload.get(field)]
    if missing:
        return jsonify({
            "success": False,
            "error": f"Missing required field(s): {', '.join(missing)}"
        }), 400

    if not payload.get("confirm_isolated_segment"):
        return jsonify({
            "success": False,
            "error": (
                "confirm_isolated_segment must be true — this acknowledges that "
                "the named interface is on an isolated ZTP staging segment, not "
                "shared with your production network's DHCP. A DHCP server on "
                "the wrong interface will hand out leases to production devices."
            )
        }), 400

    # DHCP reservations (by MAC) for every pending device, so a given
    # switch gets a predictable staging IP across repeated ZTP attempts.
    try:
        all_devices = ztp_store.list_devices()
    except ztp_store.ZtpStoreReadError as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

    reservations = [
        {"mac": device.get("mac"), "ip": device.get("mgmt_ip")}
        for device in all_devices
        if device.get("mac") and device.get("status") != "provisioned"
    ]

    with _ztp_servers_lock:
        if _ztp_dhcp_instance is not None:
            return jsonify({"success": False, "error": "ZTP DHCP server is already running."}), 400

        server = ztp_dhcp_module.ZtpDhcpServer(
            interface=payload["interface"],
            range_start=payload["range_start"],
            range_end=payload["range_end"],
            subnet_mask=payload["subnet_mask"],
            option67_url=payload["option67_url"],
            gateway=payload.get("gateway"),
            dns_server=payload.get("dns_server"),
            lease_time=payload.get("lease_time") or "1h",
            reservations=reservations,
            data_dir=ZTP_DATA_DIR,
        )
        try:
            server.start(confirm_isolated_segment=True)
        except ztp_dhcp_module.DhcpValidationError as exc:
            # Caller supplied a bad value (wildcard interface, an
            # option67_url too long to survive on the wire) -- this is a
            # 400, not a 500: the DHCP server itself isn't broken, the
            # request was.
            return jsonify({"success": False, "error": str(exc)}), 400
        except ztp_dhcp_module.DhcpServerError as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

        _ztp_dhcp_instance = server

    logger.info(
        "ZTP DHCP server started on interface=%s (%d reservation(s))",
        payload["interface"], len(reservations),
    )
    ztp_activity_log.record(
        "dhcp",
        f"DHCP server started on {payload['interface']} "
        f"({len(reservations)} reservation(s))",
    )
    return jsonify({"success": True, "reservations": len(reservations)})

@bp.route(
    "/api/dhcp/stop",
    methods=["POST"]
)
def ztp_dhcp_stop():
    global _ztp_dhcp_instance

    with _ztp_servers_lock:
        was_running = _ztp_dhcp_instance is not None
        if _ztp_dhcp_instance is not None:
            _ztp_dhcp_instance.stop()
            _ztp_dhcp_instance = None

    # ZtpDhcpServer.stop() already logs its own pid-level detail; this
    # just closes the asymmetry where dhcp/start logged on success but
    # dhcp/stop logged nothing at all either way, making it impossible
    # to tell from the app's own log whether a Stop click did anything.
    logger.info(
        "ZTP DHCP server stop requested (%s)",
        "was running" if was_running else "was not running",
    )
    if was_running:
        ztp_activity_log.record("dhcp", "DHCP server stopped.")
    return jsonify({"success": True})

@bp.route(
    "/api/dhcp/status",
    methods=["GET"]
)
def ztp_dhcp_status():
    return jsonify({
        "success": True,
        "running": _ztp_dhcp_instance is not None and _ztp_dhcp_instance.is_running()
    })


# ============================================================
# ZTP SYSLOG SERVER + ACTIVITY FEED
#
# Real-time visibility into what an in-flight ZTP run is actually
# doing, without needing to console/SSH into the switch and manually
# `more flash:/ztp_*.log | include ...` -- see activity_log.py and
# syslog_server.py's module docstrings for what this can and can't
# see (SFTP transfer events are solid; the syslog half depends on
# SYSLOG_INFO's value format, which is NOT yet confirmed against real
# hardware).
# ============================================================

def _record_syslog_message(source_ip, parsed):
    esn = _esn_for_ip(source_ip)
    ztp_activity_log.record(
        "syslog",
        f"[{source_ip}] {parsed['message']}",
        esn=esn,
        level=parsed["level"],
    )


@bp.route(
    "/api/syslog/start",
    methods=["POST"]
)
def ztp_syslog_start():
    global _ztp_syslog_instance

    payload = request.get_json(silent=True) or {}
    bind_ip = str(payload.get("bind_ip") or "0.0.0.0")
    try:
        port = int(payload.get("port", 514))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "port must be an integer."}), 400

    with _ztp_servers_lock:
        if _ztp_syslog_instance is not None:
            return jsonify({"success": False, "error": "ZTP syslog receiver is already running."}), 400

        server = ztp_syslog_module.ZtpSyslogServer(
            bind_ip=bind_ip,
            port=port,
            on_message=_record_syslog_message,
        )
        try:
            server.start()
        except ztp_syslog_module.SyslogServerError as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

        _ztp_syslog_instance = server

    logger.info("ZTP syslog receiver started on %s:%s", bind_ip, server.port)
    ztp_activity_log.record("syslog", f"Syslog receiver started on {bind_ip}:{server.port}")
    return jsonify({"success": True, "bind_ip": bind_ip, "port": server.port})


@bp.route(
    "/api/syslog/stop",
    methods=["POST"]
)
def ztp_syslog_stop():
    global _ztp_syslog_instance

    with _ztp_servers_lock:
        if _ztp_syslog_instance is not None:
            _ztp_syslog_instance.stop()
            _ztp_syslog_instance = None
            ztp_activity_log.record("syslog", "Syslog receiver stopped.")

    return jsonify({"success": True})


@bp.route(
    "/api/syslog/status",
    methods=["GET"]
)
def ztp_syslog_status():
    return jsonify({
        "success": True,
        "running": _ztp_syslog_instance is not None and _ztp_syslog_instance.is_running()
    })


@bp.route(
    "/api/activity",
    methods=["GET"]
)
def ztp_activity():
    """Polling endpoint for the ZTP tab's Activity feed. Pass
    ?since_id=<last id you saw> to get only new events -- the
    frontend polls this every couple seconds while any ZTP support
    server is running."""
    try:
        since_id = int(request.args.get("since_id", 0))
    except (TypeError, ValueError):
        since_id = 0
    events = ztp_activity_log.recent(since_id=since_id, limit=300)
    return jsonify({"success": True, "events": events})


@bp.route(
    "/api/activity/clear",
    methods=["POST"]
)
def ztp_activity_clear():
    """Manually wipe the Activity feed -- the same clear ztp_generate()
    already does automatically at the start of a fresh cycle, exposed
    here for someone who just wants a clean view without regenerating
    deployment files (e.g. clearing yesterday's leftover events before
    starting today's session)."""
    ztp_activity_log.clear()
    return jsonify({"success": True})
