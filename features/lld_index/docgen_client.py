"""Send an LLD Index straight into the Document Generator (lld-generator).

The Document Generator is a separate local app (FastAPI, default
http://127.0.0.1:8003). Keystone talks to its REST API from the server side,
so the browser never needs cross-origin access. Only loopback addresses are
accepted: the index can hold customer configuration data and must not be
sent to another machine by a typo in the URL.
"""

from __future__ import annotations

import json
import uuid
from urllib import error, request
from urllib.parse import urlparse

DEFAULT_URL = "http://127.0.0.1:8003"
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
TIMEOUT = 60


class DocGenError(Exception):
    pass


def base_url(url: str | None) -> str:
    url = (url or DEFAULT_URL).strip().rstrip("/")
    parsed = urlparse(url if "://" in url else f"http://{url}")
    if parsed.scheme not in ("http", "https") or parsed.hostname not in LOCAL_HOSTS:
        raise DocGenError("Document Generator URL must be on this computer (127.0.0.1 or localhost).")
    port = f":{parsed.port}" if parsed.port else ""
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}{port}"


def _call(method: str, url: str, body: bytes | None = None, headers: dict | None = None):
    req = request.Request(url, data=body, method=method, headers=headers or {})
    try:
        with request.urlopen(req, timeout=TIMEOUT) as response:  # noqa: S310 (loopback only, checked above)
            return json.loads(response.read() or b"null")
    except error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail")
        except Exception:
            detail = exc.reason
        raise DocGenError(f"Document Generator: {detail}") from None
    except (error.URLError, OSError) as exc:
        raise DocGenError("Document Generator is not running at this address. Start it (python main.py in "
                          "lld_generator/backend) and try again.") from exc


def _json(method: str, url: str, payload: dict):
    return _call(method, url, json.dumps(payload).encode(), {"Content-Type": "application/json"})


def _multipart(fields: dict, file_field: str, filename: str, data: bytes) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts = []
    for key, value in fields.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; filename="{filename}"\r\n'
                  "Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet\r\n\r\n").encode())
    parts.append(data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def overview(url: str | None) -> dict:
    """Projects and templates, for the picker on the page."""
    root = base_url(url)
    projects = _call("GET", f"{root}/api/projects") or []
    templates = _call("GET", f"{root}/api/templates") or []
    return {
        "url": root,
        "projects": [{"id": p["id"], "name": p.get("name", ""), "client": p.get("client", ""),
                      "version": p.get("version", "")} for p in projects],
        "templates": [{"id": t["id"], "name": t.get("name", "")} for t in templates],
    }


def send(url: str | None, workbook: bytes, filename: str, project_id: int | None = None,
         template_id: int | None = None, name: str = "", client: str = "", mode: str = "update") -> dict:
    """Import the workbook into a project; project_id None = create one first."""
    root = base_url(url)
    if mode not in ("update", "replace", "append"):
        raise DocGenError("Unknown import mode.")
    created = False
    if not project_id:
        if not template_id:
            raise DocGenError("Pick the master template for the new project.")
        project = _json("POST", f"{root}/api/projects",
                        {"name": name or "LLD", "client": client, "template_id": int(template_id)})
        project_id, created = project["id"], True
        mode = "replace"
    body, content_type = _multipart({"mode": mode}, "file", filename, workbook)
    result = _call("POST", f"{root}/api/projects/{int(project_id)}/import-excel", body, {"Content-Type": content_type})
    return {"project_id": project_id, "created": created, "mode": mode, "url": root, "import": result}
