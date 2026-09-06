"""Lightweight session-based login gate for Keystone.

Keystone has historically relied entirely on binding to 127.0.0.1 for
security (see README "Local security"). That's a reasonable first layer,
but there's an explicit escape hatch (NES_ALLOW_REMOTE) for teams that
want to reach it from another machine on the LAN, and this app pushes
firmware and configuration to production network devices and exposes a
live SSH console -- so "whoever can reach the port has full control" is
a real risk the moment that escape hatch is used, not a theoretical one.

This module adds a single shared password gate in front of every route.
It intentionally does NOT implement per-user accounts, RBAC, or password
reset flows -- this is a single-team internal tool, not a multi-tenant
product, and that complexity would add attack surface without adding
real protection for the actual threat model (an unauthenticated stranger
on the same network).

Password source, in priority order:
  1. NES_AUTH_PASSWORD environment variable, if set.
  2. data/.auth_password, generated once on first run and reused after
     (mirrors _get_or_create_secret_key in app.py). The generated value
     is also printed to the console on first run so the person who
     started the server can see it immediately.

Set NES_DISABLE_AUTH=1 to turn the gate off entirely (e.g. for local
development where the friction isn't wanted) -- off by default means
"protected by default", which is the point of this module.
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parents[1]
AUTH_PASSWORD_PATH = BASE_DIR / "data" / ".auth_password"

# Very small in-memory brute-force friction. This is a single-process,
# single-team local tool -- not worth a persisted/distributed rate
# limiter -- but a few failed guesses shouldn't be free either.
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60
_failed_attempts: dict[str, list[float]] = {}

# Routes reachable without a session -- the login page itself, its POST
# target, static assets (so the login page can render), and the health
# check (so an external monitor doesn't need credentials just to see
# the process is up).
_EXEMPT_ENDPOINTS = {"auth.login", "auth.login_submit", "auth.logout", "static", "health"}


def is_auth_disabled() -> bool:
    return os.environ.get("NES_DISABLE_AUTH", "").strip() == "1"


def _get_or_create_auth_password() -> str:
    env_password = os.environ.get("NES_AUTH_PASSWORD")
    if env_password:
        return env_password

    try:
        AUTH_PASSWORD_PATH.parent.mkdir(parents=True, exist_ok=True)
        if AUTH_PASSWORD_PATH.exists():
            existing = AUTH_PASSWORD_PATH.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_password = secrets.token_urlsafe(12)
        AUTH_PASSWORD_PATH.write_text(new_password, encoding="utf-8")
        print(
            "\n"
            "==============================================================\n"
            " Keystone login password (first run, saved to data/.auth_password):\n"
            f"   {new_password}\n"
            " Set NES_AUTH_PASSWORD to use your own instead.\n"
            "==============================================================\n"
        )
        return new_password
    except OSError:
        # Filesystem not writable -- fall back to a per-process random
        # password rather than no password at all. Sessions and the
        # password both reset on restart in this case.
        fallback = secrets.token_urlsafe(12)
        print(
            "\n[Keystone] data/ is not writable -- using a temporary login "
            f"password for this run only: {fallback}\n"
        )
        return fallback


def _client_key() -> str:
    return request.remote_addr or "unknown"


def _is_locked_out(key: str) -> bool:
    attempts = _failed_attempts.get(key, [])
    recent = [t for t in attempts if time.time() - t < LOCKOUT_SECONDS]
    _failed_attempts[key] = recent
    return len(recent) >= MAX_ATTEMPTS


def _record_failed_attempt(key: str) -> None:
    _failed_attempts.setdefault(key, []).append(time.time())


def _clear_failed_attempts(key: str) -> None:
    _failed_attempts.pop(key, None)


def register(app: Flask) -> None:
    """Wire the login gate into the given Flask app."""
    password = None if is_auth_disabled() else _get_or_create_auth_password()

    @app.route("/login", methods=["GET"], endpoint="auth.login")
    def _login_form():
        if is_auth_disabled() or session.get("authenticated"):
            return redirect(url_for("dashboard"))
        return render_template("login.html", error=None, locked_out=_is_locked_out(_client_key()))

    @app.route("/login", methods=["POST"], endpoint="auth.login_submit")
    def _login_submit():
        key = _client_key()
        if _is_locked_out(key):
            return render_template(
                "login.html",
                error=f"Too many attempts. Try again in under {LOCKOUT_SECONDS} seconds.",
                locked_out=True,
            ), 429

        submitted = request.form.get("password", "")
        if password is not None and secrets.compare_digest(submitted, password):
            _clear_failed_attempts(key)
            session["authenticated"] = True
            session.permanent = True
            return redirect(request.args.get("next") or url_for("dashboard"))

        _record_failed_attempt(key)
        return render_template("login.html", error="Incorrect password.", locked_out=_is_locked_out(key)), 401

    @app.route("/logout", endpoint="auth.logout")
    def _logout():
        session.clear()
        return redirect(url_for("auth.login"))

    @app.before_request
    def _require_login():
        if is_auth_disabled():
            return None
        if request.endpoint in _EXEMPT_ENDPOINTS:
            return None
        if session.get("authenticated"):
            return None
        return redirect(url_for("auth.login", next=request.path))
