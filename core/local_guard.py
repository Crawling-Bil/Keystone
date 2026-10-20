"""Keep a login-free, this-computer-only Keystone from being driven by other web pages.

Keystone has no login.  It listens on 127.0.0.1, so only programs on the same
computer can connect, and a person who can use that computer can use Keystone.
That is the whole access model.

One gap remains with a localhost server that has no login: a web page you open
in the same browser can send requests to ``http://127.0.0.1:8002`` too.  Two
well-known attacks use that:

* DNS rebinding.  A hostile site makes its own name resolve to 127.0.0.1 and
  then talks to Keystone as if it were that site.  The request still carries
  the hostile name in its ``Host`` header, so Keystone answers only to the names
  of this computer (``localhost``, ``127.0.0.1``, ``[::1]``).
* Cross-site request forgery.  A hostile page submits a form or a ``fetch`` to
  ``http://127.0.0.1:8002/...``.  Keystone has routes that accept device
  addresses and SSH credentials, so every state-changing request (POST, PUT,
  PATCH, DELETE) must come from a Keystone page itself, judged by the
  ``Sec-Fetch-Site`` and ``Origin`` headers that browsers set and pages cannot
  forge.

Programs that are not browsers (curl, scripts, the test client) send neither
header and are let through, so nothing a person types in a terminal is blocked.

``NES_ALLOW_REMOTE=1`` (reaching Keystone from another machine) turns the Host
check off, because the name is then no longer fixed, and keeps the
cross-site check.  Extra names can be added with ``NES_ALLOWED_HOSTS``
(comma separated), for example a lab alias.
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit

from flask import Flask, Response, request

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Sec-Fetch-Site values a Keystone page produces itself: "same-origin" for its
# own scripts and forms, "none" for something the person typed or bookmarked.
OWN_PAGE_SITES = frozenset({"same-origin", "none"})


def remote_access_allowed() -> bool:
    return os.environ.get("NES_ALLOW_REMOTE", "").strip() == "1"


def allowed_host_names() -> frozenset[str]:
    extra = {name.strip().lower() for name in os.environ.get("NES_ALLOWED_HOSTS", "").split(",") if name.strip()}
    return LOOPBACK_HOSTS | extra


def host_name(host_header: str) -> str:
    """The name part of a Host header: ``localhost:8002`` -> ``localhost``, ``[::1]:8002`` -> ``::1``."""
    host = (host_header or "").strip().lower()
    if host.startswith("["):
        end = host.find("]")
        return host[1:end] if end != -1 else host
    if host.count(":") == 1:
        return host.split(":", 1)[0]
    return host


def refusal_reason(method: str, host_header: str, origin: str | None, fetch_site: str | None) -> str | None:
    """Why this request must be refused, or None when it may go ahead."""
    if not remote_access_allowed() and host_name(host_header) not in allowed_host_names():
        return (
            f"Keystone only answers on this computer's own addresses, not on '{host_name(host_header)}'. "
            "Open http://127.0.0.1:8002 in your browser."
        )
    if method.upper() in STATE_CHANGING_METHODS:
        if fetch_site is not None and fetch_site.lower() not in OWN_PAGE_SITES:
            return "Keystone refused a request that another website started. Use the Keystone page itself."
        if origin is not None:
            origin_host = urlsplit(origin).netloc.lower() if origin.lower() != "null" else ""
            if origin_host != (host_header or "").strip().lower():
                return "Keystone refused a request that another website started. Use the Keystone page itself."
    return None


def register(app: Flask) -> None:
    """Wire the guard into the given Flask app."""

    @app.before_request
    def _refuse_foreign_requests():
        reason = refusal_reason(
            request.method,
            request.host,
            request.headers.get("Origin"),
            request.headers.get("Sec-Fetch-Site"),
        )
        if reason is None:
            return None
        return Response(reason + "\n", status=403, mimetype="text/plain")
