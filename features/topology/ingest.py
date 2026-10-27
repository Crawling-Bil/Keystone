"""Turn uploaded bytes into (name, text) captures: ZIP archives are opened, multi-device files are split."""

from __future__ import annotations

import io
import posixpath
import zipfile

from features.analyzer_core.blueprint import decode_bytes

from .split import split_devices

MAX_CAPTURE_BYTES = 40 * 1024 * 1024
MAX_ZIP_ENTRIES = 500
MAX_ZIP_TOTAL = 400 * 1024 * 1024
TEXT_SUFFIXES = (".txt", ".log", ".cfg", ".conf", ".config", ".cap", ".out", ".csv")


class IngestError(ValueError):
    """A problem the user can fix (too big, unreadable archive)."""


def _safe_name(name: str) -> str:
    base = posixpath.basename(name.replace("\\", "/")).strip()
    return base or "capture.txt"


def _zip_members(name: str, data: bytes) -> list[tuple[str, bytes]]:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError(f"{name} is not a valid ZIP archive.") from exc
    infos = [i for i in archive.infolist() if not i.is_dir()]
    if len(infos) > MAX_ZIP_ENTRIES:
        raise IngestError(f"{name} holds {len(infos)} files; the limit is {MAX_ZIP_ENTRIES}.")
    if sum(i.file_size for i in infos) > MAX_ZIP_TOTAL:
        raise IngestError(f"{name} expands to more than {MAX_ZIP_TOTAL // (1024 * 1024)} MB.")
    members: list[tuple[str, bytes]] = []
    for info in infos:
        parts = info.filename.replace("\\", "/").split("/")
        base = parts[-1]
        if base.startswith(".") or "__MACOSX" in parts or not base.lower().endswith(TEXT_SUFFIXES):
            continue
        if info.flag_bits & 0x1:
            raise IngestError(f"{name} is password protected.")
        if info.file_size > MAX_CAPTURE_BYTES:
            raise IngestError(f"{base} inside {name} exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB limit.")
        with archive.open(info) as handle:
            payload = handle.read(MAX_CAPTURE_BYTES + 1)
        if len(payload) > MAX_CAPTURE_BYTES:
            raise IngestError(f"{base} inside {name} exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB limit.")
        members.append((_safe_name(info.filename), payload))
    return members


def _ucs(name: str, data: bytes) -> str | None:
    """A BIG-IP UCS archive (gzip tar) as its configuration text; None for any other file.  The archive is read as a stream, so its size is not held in memory twice."""
    if not name.lower().endswith(".ucs"):
        return None
    from features.lb_analyzer.bigip_ucs import read_upload
    try:
        return read_upload(name, io.BytesIO(data))
    except ValueError as exc:
        raise IngestError(f"{name}: {exc}") from exc


def to_captures(uploads: list[tuple[str, bytes]], max_devices: int) -> list[tuple[str, str]]:
    captures: list[tuple[str, str]] = []
    for name, data in uploads:
        name = _safe_name(name)
        archive = _ucs(name, data)
        if archive is not None:
            captures.append((name, archive))
            if len(captures) > max_devices:
                raise IngestError(f"More than {max_devices} device captures after opening the files. Upload fewer at a time.")
            continue
        if len(data) > MAX_CAPTURE_BYTES and not name.lower().endswith(".zip"):
            raise IngestError(f"{name} exceeds the {MAX_CAPTURE_BYTES // (1024 * 1024)} MB limit.")
        members = _zip_members(name, data) if name.lower().endswith(".zip") else [(name, data)]
        for member_name, payload in members:
            captures.extend(split_devices(member_name, decode_bytes(payload)))
        if len(captures) > max_devices:
            raise IngestError(f"More than {max_devices} device captures after opening the files. Upload fewer at a time.")
    return captures
