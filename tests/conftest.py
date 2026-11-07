"""Keep the test run away from the folders the app really uses.

Several tools keep their saved work in folders next to the code (``exports/``, ``uploads/``,
``data/``).  A test that builds a topology or an export used to write there, and the topology
retention rule (``prune_runs``) then deleted the oldest saved runs to make room.  Running
``pytest`` on a machine that also ran the app therefore cost the user real saved runs.

This file runs before the first test module is imported.  Every module-level ``Path`` that points
into one of those runtime folders is re-pointed at the same relative place under one temporary
folder, the analyzer blueprints (firewall, load balancer, router) export there too, and the Flask
secret key comes from the environment instead of ``data/.secret_key``.  Tests that set their own
folder (``monkeypatch.setattr(routes, "EXPORT_DIR", ...)``) still work, they simply override this
default.  The temporary folder is removed when the run ends.
"""
from __future__ import annotations

import dataclasses
import importlib
import os
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(tempfile.mkdtemp(prefix="keystone-tests-"))

# Folder names that hold what a user saved, as opposed to code or shipped samples.
RUNTIME_NAMES = {"exports", "uploads", "data", "config", "firmware", "staging", "logs"}

# Modules whose constants name those folders; core.database first, so nothing opens the real database.
MODULES = (
    "core.database",
    "features.topology.routes",
    "features.wireless_center.routes",
    "features.switch_analyzer.routes",
    "features.configuration_studio.routes",
    "features.lld_index.routes",
    "features.lld_generator.service",
    "features.ztp.routes",
    "features.ztp.core.store",
    "features.lifecycle_manager.routes",
)


def _runtime_relative(path: Path) -> Path | None:
    """The part of ``path`` below the repository when it sits in a runtime folder, else None."""
    try:
        relative = path.resolve().relative_to(ROOT)
    except (ValueError, OSError):
        return None
    parts = relative.parts
    if not parts:
        return None
    # exports/.., uploads/.., data/.. at the top, or <package>/data/.. (ztp, lifecycle_manager)
    if parts[0] in RUNTIME_NAMES:
        return relative
    if any(part in RUNTIME_NAMES for part in parts[:-1]) and parts[0] in {"features", "core"}:
        return relative
    return None


def _redirect_modules() -> None:
    for name in MODULES:
        try:
            module = importlib.import_module(name)
        except Exception:       # a module that cannot load is reported by its own tests
            continue
        for attribute, value in list(vars(module).items()):
            if isinstance(value, Path) and not attribute.startswith("__"):
                relative = _runtime_relative(value)
                if relative is not None:
                    target = SCRATCH / relative
                    (target if not target.suffix else target.parent).mkdir(parents=True, exist_ok=True)
                    setattr(module, attribute, target)


def _redirect_analyzer_exports() -> None:
    """The firewall, load balancer and router analyzers build their export folder when their blueprint is created (at import)."""
    try:
        blueprint = importlib.import_module("features.analyzer_core.blueprint")
    except Exception:
        return
    original = blueprint.create_analyzer_blueprint

    def create(spec):
        if Path(spec.base_dir).resolve() == ROOT:
            spec = dataclasses.replace(spec, base_dir=SCRATCH)
        return original(spec)

    blueprint.create_analyzer_blueprint = create


os.environ.setdefault("NES_SECRET_KEY", "test-run-key-not-used-outside-the-tests")
_redirect_modules()
_redirect_analyzer_exports()


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(SCRATCH, ignore_errors=True)
