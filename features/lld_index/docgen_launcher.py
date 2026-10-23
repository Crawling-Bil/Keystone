"""Start the Document Generator (lld-generator) from Keystone.

The Document Generator is a separate FastAPI app with its own requirements
(fastapi, uvicorn, python-docx). Keystone finds its folder, picks a Python
that can run it (its own .venv first, then python3 on PATH), sets up a .venv
when nothing can, and starts it in the background on 127.0.0.1. The process
outlives the request and keeps running after Keystone stops, like starting it
by hand; its output goes to backend/storage/server.log.

Folder lookup, first match wins:
  1. KEYSTONE_DOCGEN_DIR (environment)
  2. the folder saved from the page (data/docgen.json)
  3. ../Document_Generator/lld_generator_v*/ next to Keystone (newest version)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import docgen_client

BASE_DIR = Path(__file__).resolve().parents[2]
CONFIG = BASE_DIR / "data" / "docgen.json"
REQUIRED = "import fastapi, uvicorn, docx, openpyxl, multipart"
MARKER = 'FastAPI(title="LLD Generator"'
WINDOWS = os.name == "nt"

_lock = threading.Lock()
_job = {"state": "idle", "message": "", "started": 0.0}


class LaunchError(Exception):
    pass


# ----------------------------------------------------------------- folder
def _app_root(path: Path) -> Path | None:
    """The lld_generator folder (holds backend/main.py), or None."""
    for root in (path, path.parent):
        main = root / "backend" / "main.py"
        try:
            if main.is_file() and MARKER in main.read_text(encoding="utf-8", errors="ignore"):
                return root
        except OSError:
            continue
    return None


def _version_key(path: Path):
    return [int(n) for n in re.findall(r"\d+", path.name)] or [0]


def _saved() -> str:
    try:
        return json.loads(CONFIG.read_text()).get("folder", "")
    except (OSError, ValueError):
        return ""


def find_app() -> Path | None:
    for candidate in (os.environ.get("KEYSTONE_DOCGEN_DIR", ""), _saved()):
        if candidate:
            root = _app_root(Path(candidate).expanduser())
            if root:
                return root
    parent = BASE_DIR.parent / "Document_Generator"
    if parent.is_dir():
        versions = sorted((p for p in parent.iterdir() if p.is_dir() and p.name.startswith("lld_generator")),
                          key=_version_key, reverse=True)
        for folder in versions:
            root = _app_root(folder)
            if root:
                return root
    return None


def save_folder(folder: str) -> Path:
    root = _app_root(Path(folder.strip()).expanduser())
    if root is None:
        raise LaunchError("That folder is not the Document Generator (backend/main.py with the LLD Generator app).")
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(json.dumps({"folder": str(root)}))
    return root


# ----------------------------------------------------------------- python
def _venv_python(root: Path) -> list[Path]:
    rel = Path("Scripts/python.exe") if WINDOWS else Path("bin/python")
    return [root / "backend" / ".venv" / rel, root / ".venv" / rel]


def _can_run(python: str) -> bool:
    try:
        return subprocess.run([python, "-c", REQUIRED], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def pick_python(root: Path) -> str | None:
    candidates = [str(p) for p in _venv_python(root) if p.exists()]
    for name in (("python", "py") if WINDOWS else ("python3", "python")):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for python in dict.fromkeys(candidates):
        if _can_run(python):
            return python
    return None


def _system_python() -> str:
    for name in (("python", "py") if WINDOWS else ("python3", "python")):
        found = shutil.which(name)
        if found:
            return found
    return sys.executable


# ----------------------------------------------------------------- start
def _running(url: str) -> bool:
    try:
        docgen_client.overview(url)
        return True
    except docgen_client.DocGenError:
        return False


def status(url: str | None) -> dict:
    root = find_app()
    url = docgen_client.base_url(url)
    with _lock:
        job = dict(_job)
    return {"running": _running(url), "folder": str(root) if root else "", "url": url,
            "job": job["state"], "message": job["message"]}


def _set(state: str, message: str) -> None:
    with _lock:
        _job.update(state=state, message=message)


def _spawn(root: Path, python: str, url: str) -> None:
    port = url.rsplit(":", 1)[-1] if url.count(":") > 1 else "8003"
    log_dir = root / "backend" / "storage"
    log_dir.mkdir(parents=True, exist_ok=True)
    log = open(log_dir / "server.log", "ab")
    kwargs = {"cwd": str(root / "backend"), "stdout": log, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL}
    if WINDOWS:
        kwargs["creationflags"] = 0x00000008 | 0x00000200 | 0x08000000  # DETACHED, NEW_GROUP, NO_WINDOW
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([python, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", port], **kwargs)


def _run_job(root: Path, url: str) -> None:
    try:
        python = pick_python(root)
        if python is None:
            _set("installing", "Setting up the Document Generator (first time, needs internet; a minute or two)…")
            venv = root / "backend" / ".venv"
            subprocess.run([_system_python(), "-m", "venv", str(venv)], check=True, capture_output=True, timeout=300)
            vpy = str(_venv_python(root)[0])
            pip = subprocess.run([vpy, "-m", "pip", "install", "-q", "-r", str(root / "backend" / "requirements.txt")],
                                 capture_output=True, text=True, timeout=900)
            if pip.returncode != 0:
                tail = (pip.stderr or pip.stdout or "").strip().splitlines()[-1:] or ["pip failed"]
                raise LaunchError(f"Installing the requirements failed: {tail[0]}")
            python = vpy
        _set("starting", "Starting the Document Generator…")
        _spawn(root, python, url)
        for _ in range(40):
            time.sleep(0.5)
            if _running(url):
                _set("running", f"Document Generator is running at {url}.")
                return
        raise LaunchError("It did not answer in 20 seconds. See backend/storage/server.log in the Document Generator folder.")
    except LaunchError as exc:
        _set("error", str(exc))
    except subprocess.CalledProcessError as exc:
        _set("error", f"Could not create the Python environment: {exc}")
    except Exception as exc:  # keep the page informed whatever happens
        _set("error", f"{type(exc).__name__}: {exc}")


def start(url: str | None) -> dict:
    url = docgen_client.base_url(url)
    if _running(url):
        _set("running", f"Document Generator is already running at {url}.")
        return status(url)
    root = find_app()
    if root is None:
        raise LaunchError("Document Generator folder not found. Enter its folder (the one with backend/main.py).")
    with _lock:
        busy = _job["state"] in ("installing", "starting")
        if not busy:
            _job.update(state="starting", message="Starting the Document Generator…", started=time.time())
    if busy:
        return status(url)
    threading.Thread(target=_run_job, args=(root, url), daemon=True).start()
    return status(url)
