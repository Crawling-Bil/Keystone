"""Builds the ZTP "intermediate file" (.ini format) that Huawei VRP
devices download over SFTP during Zero Touch Provisioning and use to
figure out, by their own ESN, which deployment files (system software +
configuration file) to pull next.

Format verified against the vendor's own documentation: "CloudEngine
S3700, S5700, and S6700 V600R023C00 Configuration Guide - Basic
Configuration", chapter 6 ZTP Configuration, section 6.6.3
"Intermediate File in the INI Format" (Table 6-13) — this is the same
product family as the S5735/S5755 hardware this tool manages. Field
names, the ;BEGIN ZTP CONFIG / ;END ZTP CONFIG markers, and the
mandatory-field set below are taken directly from that table; do not
rename or reorder the marker lines, VRP parses this file by exact
field name.

NOT YET VALIDATED against a real device — the vendor doc is the source
of truth for the file format, but nobody has actually powered on an
S5735 against a file this module produced. Test against one spare unit
before relying on this for a real rollout.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

# Table 6-13: FILESERVER value must be an SFTP URL — TFTP/FTP are not
# valid for ZTP on this VRP family (confirmed in the doc: "Files can be
# obtained only in SFTP mode").
_SFTP_URL_RE = re.compile(r"^sftp://[^@]+@[^/]+(/.*)?$", re.IGNORECASE)

# File-type suffix -> ZTP TYPE_n enum value (Table 6-13).
FILE_TYPE_SOFTWARE = "SOFTWARE"
FILE_TYPE_CONFIG = "CFG"
FILE_TYPE_PATCH = "PAT"

# EFFECTIVE_MODE_n: 0 = effective on restart (software/config/patch),
# which is what every file we generate here needs.
EFFECTIVE_ON_RESTART = 0

_FILENAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# This INI is parsed by the switch's own ZTP engine field-by-field
# (confirmed against real hardware: its log literally names each
# option key it looks for while parsing each section). Every value
# below that reaches the file RAW -- fileserver_url, vrp_version,
# syslog_target, firmware_filename -- comes from a free-text field a
# person can paste into (a form, an .xlsx import, an API call), not
# from anything this module itself constrains. A stray embedded
# newline in any of them would inject an extra, unintended line into
# an INI the switch trusts implicitly -- the same "line-oriented
# format + unsanitized interpolation" class of bug fixed in
# config_template.py's render_bootstrap_config() for the .cfg file;
# this closes the same gap for the .ini.
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")


class IntermediateFileError(ValueError):
    pass


def _require_no_control_characters(field_name, value):
    if value and _CONTROL_CHAR_RE.search(value):
        raise IntermediateFileError(
            f"{field_name} contains a newline or control character, which "
            "would inject an extra line into the generated ZTP intermediate "
            f"file (it's a strictly line-oriented INI format). Remove it "
            f"from {field_name} and try again."
        )


def _sanitize_config_filename(hostname):
    """Config file name must be 5-64 chars, *.cfg or *.zip (Huawei doc,
    6.6.2 Preparing Deployment Files). Derive one from the hostname so
    files stay traceable to the device they belong to."""
    base = _FILENAME_SANITIZE_RE.sub("-", hostname).strip("-_.") or "device"
    name = f"{base}.cfg"
    if len(name) < 5:
        name = f"{base}-cfg.cfg"
    return name[:64]


def default_time_sn():
    """TIME_SN format is yyyymmddhhmmss (Table 6-13) — must be unique
    per (re)generation so a device doesn't think it already ran this
    exact deployment and skip it."""
    return time.strftime("%Y%m%d%H%M%S", time.gmtime())


def _sha256_of(path):
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _device_files(device, ztp_root):
    """Build the FILENAME_n/TYPE_n list for one pre-registered device:
    its bootstrap config always, plus system software if a
    firmware_filename was set on the registration (omit it if the
    device already reports the right VRPVER — see that field below —
    or if you only want ZTP to push config, not re-flash firmware)."""
    files = []

    firmware_filename = (device.get("firmware_filename") or "").strip()
    if firmware_filename:
        _require_no_control_characters(
            f"Device {device.get('esn')}: firmware_filename", firmware_filename
        )
        files.append((firmware_filename, FILE_TYPE_SOFTWARE))

    config_filename = _sanitize_config_filename(device.get("hostname") or device["esn"])
    files.append((config_filename, FILE_TYPE_CONFIG))

    if len(files) > 9:
        raise IntermediateFileError(
            f"Device {device.get('esn')}: {len(files)} deployment files, "
            "Huawei ZTP allows a maximum of 9 (FILETYPENUM)."
        )

    resolved = []
    for filename, file_type in files:
        sha256 = None
        if ztp_root is not None:
            candidate = Path(ztp_root) / filename
            if candidate.is_file():
                sha256 = _sha256_of(candidate)
        resolved.append((filename, file_type, sha256))
    return resolved, config_filename


def build_intermediate_file(devices, fileserver_url, ztp_root=None, time_sn=None, syslog_target=None):
    """Render a complete ZTP intermediate .ini file for one or more
    pre-registered devices.

    devices: list of dicts as returned by core.store.list_devices()
        (esn, mac, hostname, vrp_version, firmware_filename, ...).
    fileserver_url: "sftp://user:password@host[:port]/path" — the
        SAME URL that must also be pushed to the DHCP server as
        Option 67. One shared file server serves every device; per-
        device targeting happens via the ESN field below, not via the
        URL.
    ztp_root: optional path to the directory actually holding the
        deployment files, used to compute SHA256_n integrity
        checksums for files that already exist there. Files not yet
        present are left unchecksummed (SHA256 is optional per spec).
    time_sn: override the deployment identifier; defaults to "now" in
        the required yyyymmddhhmmss format.
    syslog_target: optional "<ip>:<port>" (or bare "<ip>") string to
        populate every device's SYSLOG_INFO field with, so the switch
        forwards its ZTP process log lines to core.syslog_server in
        real time during provisioning. Left blank (the pre-existing
        default) when not given, same as before this parameter
        existed. See syslog_server.py's module docstring: the exact
        value format SYSLOG_INFO expects is NOT confirmed against
        real hardware yet -- this passes whatever string the caller
        gives verbatim.

    Returns (ini_text, config_filenames) where config_filenames maps
    esn -> the .cfg filename this function chose for it, so the
    caller knows what to name the file it writes with
    config_template.render_bootstrap_config().
    """
    if not devices:
        raise IntermediateFileError("At least one device is required.")
    _require_no_control_characters("fileserver_url", fileserver_url or "")
    if not _SFTP_URL_RE.match(fileserver_url or ""):
        raise IntermediateFileError(
            f"fileserver_url must look like sftp://user:password@host/path, got {fileserver_url!r} "
            "— ZTP on this VRP family only supports SFTP for the intermediate/deployment file server."
        )
    if syslog_target:
        _require_no_control_characters("syslog_target", syslog_target)

    time_sn = time_sn or default_time_sn()

    lines = [
        ";BEGIN ZTP CONFIG",
        "[GLOBAL CONFIG]",
        f"*FILESERVER={fileserver_url}",
        f"*TIME_SN={time_sn}",
        f"*DEVICE_TYPE_NUM={len(devices)}",
        "SET_MASTER=",
        "CLEAR_MASTER=",
        "EXPORTCFG=",
        "",
    ]

    config_filenames = {}

    for index, device in enumerate(devices, start=1):
        esn = device.get("esn")
        if not esn:
            raise IntermediateFileError(f"Device at position {index} has no ESN.")

        files, config_filename = _device_files(device, ztp_root)
        config_filenames[esn] = config_filename

        mac = (device.get("mac") or "").strip() or "DEFAULT"
        vrp_version = (device.get("vrp_version") or "").strip()
        if vrp_version:
            _require_no_control_characters(f"Device {esn}: vrp_version", vrp_version)

        lines.append(f"[DEVICE_TYPE_{index} DESCRIPTION]")
        lines.append("DEVICE_TYPE=")
        lines.append(f"ESN={esn}")
        lines.append(f"MAC={mac}")
        lines.append(f"VRPVER={vrp_version}")
        lines.append(f"SYSLOG_INFO={syslog_target or ''}")
        lines.append("SPACE_CLEAR=")
        lines.append("DIRECTORY=")
        lines.append("ACTIVE_DELAYTIME=")
        lines.append("ACTIVE_INTIME=")
        lines.append(f"*FILETYPENUM={len(files)}")
        for file_index, (filename, file_type, sha256) in enumerate(files, start=1):
            lines.append(f"*FILENAME_{file_index}={filename}")
            lines.append(f"*TYPE_{file_index}={file_type}")
            lines.append(f"*EFFECTIVE_MODE_{file_index}={EFFECTIVE_ON_RESTART}")
            lines.append(f"ISBATCHPROCESS_{file_index}=0")
            if sha256:
                lines.append(f"SHA256_{file_index}={sha256}")
        lines.append("")

    lines.append(";END ZTP CONFIG")
    lines.append("")

    return "\n".join(lines), config_filenames
