"""Glue between the upload route and the BIG-IP analyzer for ``.ucs`` archives.

``read_upload`` is the hook the analyzer blueprint calls for every uploaded file.  For a UCS it streams the archive
(see ``ucs_reader``) and returns the joined TMSH configuration as a ``UcsText`` - a ``str`` that also carries the
parsed archive, so ``service.analyze`` can add the certificate, license and ``sys db`` facts that ``bigip.conf``
does not contain.  Any other file returns ``None`` and takes the normal text path.

``merge_same_unit`` is the second hook: when one upload is a UCS and another is a prompted terminal capture (the output of the collect list)
of the same unit (same hostname), the two become ONE analysis - the archive supplies the complete configuration and the capture the live
``show`` state - instead of two results that each miss half of the picture.
"""

from __future__ import annotations

import re
from typing import Any

from .ucs_reader import UcsBundle, is_ucs, read_ucs

MAX_UCS_BYTES = 1536 * 1024 * 1024


class UcsText(str):
    """Configuration text plus the archive it came from."""

    bundle: UcsBundle | None = None
    live: str = ""                  # terminal capture of the same unit merged with this archive (see merge_same_unit)
    live_name: str = ""


def read_upload(filename: str, stream: Any) -> UcsText | None:
    head = stream.read(2)
    stream.seek(0)
    if not is_ucs(filename, head):
        return None
    bundle = read_ucs(stream)                    # raises UcsError (a ValueError) with a message for the engineer
    text = UcsText(bundle.text)
    text.bundle = bundle
    return text


def bundle_of(content: Any) -> UcsBundle | None:
    return getattr(content, "bundle", None)


_HOST_STANZA = re.compile(r"sys global-settings\s*\{[^}]*?\bhostname\s+(\S+)", re.S)
_PROMPT_HOST = re.compile(r"^\S*@\(([^)\s]+)\)\(|^\[\w+@([^:\]\s]+):", re.M)    # root@(bigip1)(cfg-sync In Sync)(Active)(/Common)(tmos)#   or   [admin@bigip1:Active:In Sync] ~ #


def _short(host: str) -> str:
    return host.strip().strip("{}").lower().split(".")[0]


def unit_hostname(text: str) -> str:
    """Short, lower-case hostname of the unit a configuration or capture belongs to ('' when it does not say)."""
    found = _HOST_STANZA.search(text)
    if found:
        return _short(found.group(1))
    found = _PROMPT_HOST.search(text)
    return _short(found.group(1) or found.group(2)) if found else ""


def merge_same_unit(sources: list[tuple[str, Any]]) -> list[tuple[str, Any]]:
    """Fold a prompted capture into the UCS of the same unit; everything else is returned unchanged and in order.

    A capture is merged only when it holds prompted commands (``root@(host)(...)(tmos)# show ...``) - a plain ``bigip.conf`` of the same
    host stays a separate analysis - and when exactly one capture and one archive carry that hostname."""
    from .bigip_runtime import gather

    archives = [i for i, (_, content) in enumerate(sources) if bundle_of(content) is not None and not getattr(content, "live", "")]
    if not archives:
        return sources
    captures: dict[int, str] = {}
    for j, (_, content) in enumerate(sources):
        if bundle_of(content) is None:
            prepared = gather(content)
            if prepared["capture"].blocks:
                captures[j] = _short(prepared["hostname"] or "") or unit_hostname(content)
    out = list(sources)
    dropped: set[int] = set()
    for i in archives:
        name, archive = sources[i]
        host = unit_hostname(archive)
        mates = [j for j, h in captures.items() if h and h == host and j not in dropped]
        if not host or len(mates) != 1 or sum(1 for k in archives if unit_hostname(sources[k][1]) == host) != 1:
            continue
        j = mates[0]
        merged = UcsText(str(archive))
        merged.bundle = archive.bundle
        merged.live, merged.live_name = sources[j][1], sources[j][0]
        out[i] = (f"{name} + {sources[j][0]}", merged)
        dropped.add(j)
    return [item for k, item in enumerate(out) if k not in dropped]
