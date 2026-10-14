"""Glue between the upload route and the BIG-IP analyzer for ``.ucs`` archives.

``read_upload`` is the hook the analyzer blueprint calls for every uploaded file.  For a UCS it streams the archive
(see ``ucs_reader``) and returns the joined TMSH configuration as a ``UcsText`` - a ``str`` that also carries the
parsed archive, so ``service.analyze`` can add the certificate, license and ``sys db`` facts that ``bigip.conf``
does not contain.  Any other file returns ``None`` and takes the normal text path.
"""

from __future__ import annotations

from typing import Any

from .ucs_reader import UcsBundle, is_ucs, read_ucs

MAX_UCS_BYTES = 1536 * 1024 * 1024


class UcsText(str):
    """Configuration text plus the archive it came from."""

    bundle: UcsBundle | None = None


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
