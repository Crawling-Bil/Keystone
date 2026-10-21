"""Session handling for the guided firewall conversion (Convert Firewall wizard).

A wizard session is a folder under ``uploads/configuration/wizard/<token>``
holding the source file and ``state.json``. The source is parsed again on
every step (a RouterOS export parses in milliseconds), so the stored state
is only the user's choices. Sessions older than a day are removed when a
new one starts. Everything stays on this machine.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from .converter_engine.models.firewall import FirewallConfig
from .converter_engine.wizard import firewall_wizard
from .service import _resolve_source, create_engine, safe_name

SESSION_TTL_SECONDS = 24 * 3600
_TOKEN_RE = re.compile(r"^[a-f0-9]{32}$")


class WizardError(ValueError):
    """A request the wizard refuses; the message is shown to the user."""


def _session_dir(root: Path, token: str) -> Path:
    if not _TOKEN_RE.match(token or ""):
        raise WizardError("Unknown wizard session.")
    path = root / token
    if not path.is_dir():
        raise WizardError("This wizard session has expired. Start the guided conversion again.")
    return path


def _cleanup(root: Path) -> None:
    now = time.time()
    for child in root.glob("*"):
        try:
            if child.is_dir() and now - child.stat().st_mtime > SESSION_TTL_SECONDS:
                shutil.rmtree(child, ignore_errors=True)
        except OSError:
            continue


def _load(root: Path, token: str):
    folder = _session_dir(root, token)
    meta = json.loads((folder / "session.json").read_text(encoding="utf-8"))
    state = json.loads((folder / "state.json").read_text(encoding="utf-8"))
    engine = create_engine()
    config = engine.parse(
        filename=folder / meta["source_name"],
        source_vendor=meta["source_vendor"],
        source_device_type=meta["source_device_type"],
    )
    translator = engine.get_translator(vendor=meta["target_vendor"], device_type=meta["source_device_type"])
    return folder, meta, state, config, translator


def _save_state(folder: Path, state: dict) -> None:
    (folder / "state.json").write_text(json.dumps(state, indent=1), encoding="utf-8")
    # Expiry is measured from the last use, not from the start.
    try:
        os.utime(folder, None)
    except OSError:
        pass


def _public(meta: dict, token: str, result: dict) -> dict:
    return {
        "token": token,
        "hostname": meta["hostname"],
        "source_vendor": meta["source_vendor"],
        "target_vendor": meta["target_vendor"],
        "source_text": meta.get("source_text", ""),
        **result,
    }


def start(
    root: Path,
    source_path: Path,
    *,
    source_vendor: str = "Auto Detect",
    target_vendor: str = "Palo Alto",
    target_model: Optional[str] = None,
    domain: Optional[str] = "firewall",
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    _cleanup(root)
    if str(target_vendor).strip().lower() != "palo alto":
        raise WizardError("The guided conversion builds Palo Alto PAN-OS configuration only.")

    engine = create_engine()
    resolved_vendor, resolved_type, _detection = _resolve_source(engine, source_path, domain, source_vendor, "Auto Detect")
    config = engine.parse(filename=source_path, source_vendor=resolved_vendor, source_device_type=resolved_type)
    if not isinstance(config, FirewallConfig) or resolved_vendor.lower() != "mikrotik":
        raise WizardError(
            f"The guided conversion reads MikroTik RouterOS exports today (this file was detected as {resolved_vendor}). "
            "Use Convert Configuration for other sources."
        )
    translator = engine.get_translator(vendor="Palo Alto", device_type=resolved_type)

    token = uuid.uuid4().hex
    folder = root / token
    folder.mkdir(parents=True)
    source_name = "source" + (source_path.suffix if source_path.suffix else ".rsc")
    shutil.copyfile(source_path, folder / source_name)
    source_text = source_path.read_text(encoding="utf-8", errors="ignore")
    meta = {
        "source_name": source_name,
        "source_vendor": resolved_vendor,
        "source_device_type": resolved_type,
        "target_vendor": "Palo Alto",
        "hostname": str(getattr(config, "hostname", "") or source_path.stem),
        "source_text": source_text,
        "created": time.time(),
    }
    (folder / "session.json").write_text(json.dumps(meta), encoding="utf-8")
    state = firewall_wizard.initial_state(config, translator, target_model)
    _save_state(folder, state)
    return _public(meta, token, firewall_wizard.evaluate(config, translator, state))


def validate(root: Path, token: str, incoming_state: Optional[dict]) -> dict[str, Any]:
    folder, meta, state, config, translator = _load(root, token)
    state = firewall_wizard.merge_state(state, incoming_state)
    _save_state(folder, state)
    result = firewall_wizard.evaluate(config, translator, state)
    # The source text was sent once on start; later steps omit it.
    return _public({**meta, "source_text": ""}, token, result)


def export(root: Path, token: str, revision: Optional[str] = None) -> tuple[str, str]:
    """(file name, config text). Refused while any step has an open error or
    an unacknowledged warning, and when ``revision`` is not the state the
    user last had checked (an edit in the page that was never validated)."""
    folder, meta, state, config, translator = _load(root, token)
    if not revision or revision != firewall_wizard.state_revision(state):
        raise WizardError("The page has changes that were not checked yet. Re-check, then download.")
    result = firewall_wizard.evaluate(config, translator, state)
    if not result["ready"]:
        blocking = [s["label"] for s in result["steps"] if s["status"] != "ok"]
        raise WizardError("Not ready to export. Steps still open: " + ", ".join(blocking) + ".")
    header = [
        "# Generated by Keystone guided conversion (MikroTik RouterOS -> Palo Alto PAN-OS)",
        "# Every step passed Keystone's reference checks. Before cutover, load it on a lab or",
        "# the target firewall and run 'validate full' -- only PAN-OS can confirm a commit.",
        "",
    ]
    name = f"{safe_name(meta['hostname'])}_Palo-Alto_guided.cfg"
    return name, "\n".join(header) + result["output_text"]
