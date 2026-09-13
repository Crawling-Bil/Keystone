from __future__ import annotations

import os
import secrets
import time
from pathlib import Path

from flask import Flask, jsonify, render_template

from core import auth
from core.database import initialize, recent_activity
from features.configuration_studio.routes import bp as configuration_bp
from features.lifecycle_manager.routes import app as lifecycle_bp
from features.wireless_center.routes import bp as wireless_bp
from features.switch_analyzer.routes import bp as switch_analyzer_bp
from features.ztp.routes import bp as ztp_bp

APP_NAME = "Keystone"
APP_VERSION = "1.10.0"
BASE_DIR = Path(__file__).resolve().parent

# Age (in days) after which generated files in the folders below are
# considered stale and swept on startup. Keeps exports/uploads/backups
# from growing unbounded on a long-running local install.
CLEANUP_MAX_AGE_DAYS = 30
CLEANUP_DIRS = [
    BASE_DIR / "exports",
    BASE_DIR / "uploads",
    BASE_DIR / "features" / "lifecycle_manager" / "backups",
]


def _get_or_create_secret_key() -> str:
    """Use NES_SECRET_KEY if set; otherwise generate a random key once
    and persist it under data/ so it stays stable across restarts
    instead of silently falling back to a hardcoded, guessable value."""
    env_key = os.environ.get("NES_SECRET_KEY")
    if env_key:
        return env_key

    key_path = BASE_DIR / "data" / ".secret_key"
    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if key_path.exists():
            existing = key_path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        new_key = secrets.token_hex(32)
        key_path.write_text(new_key, encoding="utf-8")
        return new_key
    except OSError:
        # Filesystem not writable for some reason — fall back to an
        # in-memory random key rather than a hardcoded default. Sessions
        # won't survive a restart, but the key is never guessable.
        return secrets.token_hex(32)


def _sweep_stale_files() -> None:
    """Best-effort startup cleanup of old generated files. Never raises —
    a failure here should not prevent the app from starting."""
    cutoff = time.time() - (CLEANUP_MAX_AGE_DAYS * 86400)
    for directory in CLEANUP_DIRS:
        try:
            if not directory.exists():
                continue
            for path in directory.rglob("*"):
                try:
                    if path.is_file() and path.stat().st_mtime < cutoff:
                        path.unlink(missing_ok=True)
                except OSError:
                    continue
        except OSError:
            continue


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=_get_or_create_secret_key(),
        MAX_CONTENT_LENGTH=4 * 1024 * 1024 * 1024,
        # Werkzeug 2.3+/Flask 3.1 caps non-file form FIELDS (as opposed
        # to file uploads, which stream to disk) at 500 KB by default,
        # returning a bare 413 before a route ever runs. Configuration
        # Studio and Switch Analyzer both accept a pasted configuration
        # up to 20 MB via a plain textarea field and have their own
        # friendlier "exceeds the 20 MB limit" error for that -- which
        # was unreachable for anything over ~500 KB because Werkzeug's
        # own limit fired first. 24 MB gives their 20 MB checks room to
        # actually run.
        MAX_FORM_MEMORY_SIZE=24 * 1024 * 1024,
        JSON_SORT_KEYS=False,
    )

    initialize()
    _sweep_stale_files()
    auth.register(app)
    app.register_blueprint(configuration_bp)
    app.register_blueprint(wireless_bp)
    app.register_blueprint(switch_analyzer_bp)
    app.register_blueprint(lifecycle_bp)
    app.register_blueprint(ztp_bp)

    @app.context_processor
    def inject_app_version():
        return {"app_version": APP_VERSION}

    @app.get("/")
    def dashboard():
        modules = [
            {
                "name": "Configuration Studio",
                "version": "Traditional Converter v1.8",
                "description": "Multi-vendor configuration conversion with automatic platform detection.",
                "href": "/configuration",
                "icon": "configuration",
                "status": "Ready",
            },
            {
                "name": "Wireless Analyzer",
                "version": "Wireless Analyzer v1.11.0",
                "description": "Wireless assessment, AP group mapping, AP role diff, and comprehensive Source-to-Target config delta.",
                "href": "/wireless",
                "icon": "wireless",
                "status": "Ready",
            },
            {
                "name": "Config Analyzer",
                "version": "Config Analyzer v1.1",
                "description": "Cisco/Huawei/Aruba switch dashboards, plus Mikrotik/Palo Alto firewall dashboards with best-practice/security findings.",
                "href": "/switch-analyzer",
                "icon": "switch",
                "status": "Ready",
            },
            {
                "name": "Lifecycle Manager",
                "version": "Switch Upgrade Tool v1.4",
                "description": "Device discovery, firmware repository, detailed pre-check, and upgrade jobs.",
                "href": "/lifecycle/",
                "icon": "lifecycle",
                "status": "Ready",
            },
            {
                "name": "ZTP Provisioning",
                "version": "Switch Upgrade Tool v1.4",
                "description": "Zero-touch bootstrap for factory-default switches — DHCP, SFTP file server, and per-device provisioning.",
                "href": "/ztp/",
                "icon": "console",
                "status": "Ready",
            },
            {
                "name": "Config Push",
                "version": "Switch Upgrade Tool v1.4",
                "description": "Push a prepared draft config to an already-discovered device over SSH — no firmware, no reload.",
                "href": "/lifecycle/config-push",
                "icon": "upload",
                "status": "Ready",
            },
            {
                "name": "Config Backup",
                "version": "Switch Upgrade Tool v1.4",
                "description": "Capture a full read-only snapshot of an already-configured device -- hardware, config, VLANs, LLDP/STP, licensing -- and download it as a backup bundle.",
                "href": "/lifecycle/config-backup",
                "icon": "folder",
                "status": "Ready",
            },
            {
                "name": "Live Logs",
                "version": "Switch Upgrade Tool v1.4",
                "description": "Watch upgrade jobs, config push jobs, and ZTP activity run in real time, across the whole suite.",
                "href": "/lifecycle/live-logs",
                "icon": "pulse",
                "status": "Ready",
            },
        ]
        return render_template(
            "dashboard.html",
            active_page="dashboard",
            modules=modules,
            activities=recent_activity(10),
            app_version=APP_VERSION,
        )

    @app.get("/about")
    def about():
        return render_template("about.html", active_page="about", app_version=APP_VERSION)

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "application": APP_NAME,
            "version": APP_VERSION,
            "modules": {
                "configuration": "ready",
                "wireless": "ready",
                "switch_analyzer": "ready",
                "lifecycle": "ready",
            },
        })

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify({"ok": False, "error": "File is too large to process."}), 413

    return app


app = create_app()

if __name__ == "__main__":
    # threaded=True matters now that Lifecycle Manager's job-stream
    # endpoint (Server-Sent Events, see features/lifecycle_manager
    # /routes.py stream_job()) holds a connection open for as long as
    # a job keeps running. Werkzeug's dev server serves one request at
    # a time by default -- without this, one open live-monitoring tab
    # would stall every other page in the app until that job finished.
    app.run(host="127.0.0.1", port=8002, debug=False, threaded=True)
