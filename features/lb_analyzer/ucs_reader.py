"""Read an F5 UCS archive (``tmsh save sys ucs``) without extracting it to disk.

A UCS is a gzip-compressed tar archive holding ``/config``, parts of ``/var`` and ``/etc`` of the BIG-IP.  This
module streams through it once and keeps only what the Load Balancer Analyzer can use, by whitelist:

* the TMSH configuration files (``bigip.conf``, ``bigip_base.conf``, ``bigip_gtm.conf``, ``bigip_user.conf``, ``bigip_script.conf``;
  ``bigip_gtm.conf`` is where a BIG-IP DNS unit keeps its wide IPs, GTM pools, servers, data centers and listeners,
  and an administrative partition keeps its own ``config/partitions/<name>/bigip.conf`` and ``bigip_gtm.conf``);
* ``ucs_version``, ``.ucs_platform``, ``bigip.license`` (module list and dates only), ``BigDB.dat`` (customised
  ``sys db`` values) and ``/config/startup``                                   -> ``ucs_files``;
* the *public* certificates in the file store                                  -> ``ucs_x509``;
* the saved-configuration patches in ``/config/.diffVersions``                   -> ``ucs_history``;
* a few small operating-system files: ``hosts.allow`` / ``hosts.deny``, the account list (name and shell only),
  ``userrolepartitions``, SSH session limits, and the names of iApp LX packages, custom httpd configuration,
  external-monitor scripts and non-default failover scripts (names and sizes; their content is not kept).

Never read, kept or shown: private keys (``ssl.key``, ``*_key_d``), the master key store, ``/etc/shadow``, shell
histories, SSH keys, the license registration key and dossier, and the statistics/iHealth data that makes up most
of the archive's size.

Safety: the archive is read as a stream (``r|gz``) so it is never loaded into memory (peak ~30 MB for a 125 MB UCS); member names are only
compared with a fixed whitelist (nothing is written to disk, so path traversal cannot happen); each kept member
has a size cap; a hard limit on the member count, on the total expanded size and on the elapsed time stops tar and gzip bombs; an archive that is not gzip/tar - for
example one saved with a passphrase - gives a clear message instead of garbage.

Reference: F5, BIG-IP System: Essentials, "Archives",
https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-system-essentials-14-1-0/archives.html
"""

from __future__ import annotations

import re
import tarfile
import time
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from . import ucs_files, ucs_history
from .ucs_x509 import parse_certificate

MAX_MEMBERS = 200_000
MAX_UNCOMPRESSED_BYTES = 16 * 1024 ** 3     # a real UCS expands ~3x (125 MB -> ~340 MB); a gzip bomb expands ~1000x
MAX_SECONDS = 300                           # wall-clock budget for streaming one archive
MAX_CONFIG_BYTES = 64 * 1024 * 1024          # per config file
MAX_SMALL_BYTES = 8 * 1024 * 1024            # per small OS / license / db file
MAX_CERT_BYTES = 256 * 1024                  # per certificate file (bundles are skipped)
CONFIG_FILES = ("config/bigip.conf", "config/bigip_base.conf", "config/bigip_gtm.conf", "config/bigip_user.conf", "config/bigip_script.conf")
_PARTITION_CONFIG = re.compile(r"^config/partitions/[^/]+/bigip(?:_gtm)?\.conf$")      # objects of an administrative partition
CERT_DIRS = ("/certificate_d/", "/trust_certificate_d/")
DEFAULT_HTTPD_CONF = {"auth_pam.conf"}
SECRET_PATHS = ("/ssl.key/", "_key_d/", "config/bigip/kstore/", "etc/shadow", "etc/gshadow", "/.ssh/", "etc/ssh/ssh_host_")


class UcsError(ValueError):
    """Raised with a message meant for the engineer."""


@dataclass
class UcsBundle:
    text: str = ""                                     # bigip.conf + bigip_base.conf + bigip_user.conf (+ script) joined
    files: dict[str, int] = field(default_factory=dict)   # kept config file -> bytes
    version: dict[str, str] = field(default_factory=dict)
    platform: dict[str, str] = field(default_factory=dict)
    license: dict[str, Any] = field(default_factory=dict)
    db: dict[str, dict[str, str]] = field(default_factory=dict)       # modified sys db values: key -> {value, default}
    certs: dict[str, dict[str, Any]] = field(default_factory=dict)    # file-store basename -> parsed certificate
    history: list[dict[str, Any]] = field(default_factory=list)       # saved-configuration patches (ucs_history.parse_patch)
    history_skipped: int = 0                                          # patches too large to read or beyond the cap
    os_accounts: list[dict[str, Any]] = field(default_factory=list)   # /etc/passwd: name + shell
    role_partitions: list[dict[str, str]] = field(default_factory=list)
    session_limits: dict[str, str] = field(default_factory=dict)
    tcp_wrappers: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    packages: list[dict[str, str]] = field(default_factory=list)      # iApp LX RPMs, by file name
    custom_files: list[dict[str, Any]] = field(default_factory=list)  # {"path", "bytes", "kind"}: present, content not kept
    members: int = 0
    total_bytes: int = 0
    omitted: dict[str, int] = field(default_factory=dict)             # what was deliberately not read (label -> count)
    has_startup_additions: bool = False


# --------------------------------------------------------------------------- entry point
def is_ucs(filename: str, head: bytes) -> bool:
    return filename.lower().endswith(".ucs") or head[:2] == b"\x1f\x8b"


def read_ucs(stream: BinaryIO) -> UcsBundle:
    bundle = UcsBundle()
    texts: dict[str, str] = {}
    try:
        archive = tarfile.open(fileobj=stream, mode="r|gz")
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise UcsError(_not_ucs_message(exc)) from exc
    started = time.monotonic()
    try:
        for member in archive:
            bundle.members += 1
            if bundle.members > MAX_MEMBERS:
                raise UcsError("The archive has an unusually large number of entries and was not read completely.")
            name = member.name.lstrip("./")
            bundle.total_bytes += max(member.size, 0)
            if bundle.total_bytes > MAX_UNCOMPRESSED_BYTES:
                raise UcsError(f"The archive expands to more than {MAX_UNCOMPRESSED_BYTES // 1024 ** 3} GB, far beyond a normal UCS, and was not read.")
            if time.monotonic() - started > MAX_SECONDS:
                raise UcsError(f"Reading the archive took longer than {MAX_SECONDS} seconds and was stopped. Upload bigip.conf and bigip_base.conf instead.")
            if member.isfile():
                _dispatch(bundle, texts, archive, member, name)
    except (tarfile.TarError, OSError, EOFError) as exc:
        if not texts:
            raise UcsError(_not_ucs_message(exc)) from exc
        bundle.omitted["archive read stopped early (truncated file?)"] = 1
    if not any(n in texts for n in ("config/bigip.conf", "config/bigip_base.conf")):
        raise UcsError("This archive does not contain config/bigip.conf or config/bigip_base.conf, so there is no BIG-IP configuration to analyze. Check that it was created with 'tmsh save sys ucs'.")
    order = [n for n in CONFIG_FILES if n in texts] + sorted(n for n in texts if n not in CONFIG_FILES)
    bundle.text = "\n".join(texts[n] for n in order)
    return bundle


def _not_ucs_message(exc: Exception) -> str:
    return ("The file could not be read as a UCS archive (gzip-compressed tar). If it was saved with a passphrase "
            "('save sys ucs <name> passphrase ...') it is encrypted and cannot be read here: save it again without a passphrase, "
            f"or upload bigip.conf and bigip_base.conf instead. ({type(exc).__name__})")


def _text(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    handle = archive.extractfile(member)
    return (handle.read() if handle else b"").decode("utf-8", errors="replace")


def _omit(bundle: UcsBundle, label: str) -> None:
    bundle.omitted[label] = bundle.omitted.get(label, 0) + 1


# --------------------------------------------------------------------------- whitelist dispatch
def _dispatch(bundle: UcsBundle, texts: dict[str, str], archive: tarfile.TarFile, member: tarfile.TarInfo, name: str) -> None:
    size = member.size
    if any(part in "/" + name for part in SECRET_PATHS):                                   # checked first: nothing below may read these
        _omit(bundle, "private keys / password files")
        return
    if name in CONFIG_FILES or _PARTITION_CONFIG.match(name):
        if size <= MAX_CONFIG_BYTES:
            texts[name] = _text(archive, member)
            bundle.files[name] = size
        return
    if name.startswith("root/") or "/.bash_history" in name or "/.tmsh-history" in name:
        _omit(bundle, "shell histories")
        return
    if any(part in "/" + name for part in CERT_DIRS):
        if 0 < size <= MAX_CERT_BYTES:
            parsed = parse_certificate(archive.extractfile(member).read())                 # type: ignore[union-attr]
            if parsed:
                bundle.certs[name.rsplit("/", 1)[-1]] = parsed
        return
    patch = ucs_history.is_patch(name)
    if patch:
        if len(bundle.history) >= ucs_history.MAX_PATCHES or size > ucs_history.MAX_PATCH_BYTES:
            bundle.history_skipped += 1
            return
        raw = archive.extractfile(member).read()                                           # type: ignore[union-attr]
        change = ucs_history.parse_patch(patch["file"], int(patch["rev"]), member.mtime, raw)
        if change:
            bundle.history.append(change)
        return
    if name.startswith("config/.diffVersions/"):
        return                                                                             # BigDB.dat patches and bookkeeping: counters, not changes
    if size > MAX_SMALL_BYTES:
        return
    handler = _SMALL.get(name)
    if handler:
        handler(bundle, _text(archive, member))
        return
    base = name.rsplit("/", 1)[-1]
    if name.startswith("var/config/rest/iapps/RPMS.save/") and name.endswith(".rpm"):
        package = ucs_files.parse_rpm_name(base)
        if package:
            bundle.packages.append(package)
    elif name.startswith("config/httpd/conf.d/") and base not in DEFAULT_HTTPD_CONF:
        bundle.custom_files.append({"path": "/" + name, "bytes": size, "kind": "custom httpd configuration"})
    elif name.startswith("config/monitors/") and not name.startswith("config/monitors/builtins"):
        bundle.custom_files.append({"path": "/" + name, "bytes": size, "kind": "external monitor script"})
    elif name.startswith("config/failover/"):
        lines = ucs_files.active_script_lines(_text(archive, member))
        if lines:
            bundle.custom_files.append({"path": "/" + name, "bytes": size, "kind": f"failover script with {lines} active line(s)"})


def _startup(bundle: UcsBundle, text: str) -> None:
    bundle.has_startup_additions = ucs_files.active_script_lines(text) > 0


def _role_partitions(bundle: UcsBundle, text: str) -> None:
    bundle.role_partitions = ucs_files.parse_role_partitions(text)


def _limit(label: str):
    def handler(bundle: UcsBundle, text: str) -> None:
        bundle.session_limits[label] = ucs_files.parse_session_limit(text)
    return handler


def _wrappers(label: str):
    def handler(bundle: UcsBundle, text: str) -> None:
        bundle.tcp_wrappers[label] = ucs_files.parse_tcp_wrappers(text)
    return handler


def _set(attr: str, parse):
    def handler(bundle: UcsBundle, text: str) -> None:
        setattr(bundle, attr, parse(text))
    return handler


_SMALL = {
    "config/ucs_version": _set("version", lambda t: ucs_files.keyvalue(t, ":")),
    "config/.ucs_platform": _set("platform", lambda t: ucs_files.keyvalue(t, "=")),
    "config/bigip.license": _set("license", ucs_files.parse_license),
    "config/BigDB.dat": _set("db", ucs_files.parse_bigdb),
    "config/startup": _startup,
    "etc/passwd": _set("os_accounts", ucs_files.parse_passwd),
    "etc/hosts.allow": _wrappers("allow"),
    "etc/hosts.deny": _wrappers("deny"),
    "config/bigip/auth/userrolepartitions": _role_partitions,
    "config/bigip/auth/sshglobalsessionlimit": _limit("global"),
    "config/bigip/auth/sshuserlimit": _limit("per user"),
}
