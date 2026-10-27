"""Work Plan (FM-Impl-039) and Work Report (FM-HW-005) for an LLD Generator project.

The project holds what every document shares: description, Statement of Work,
service support, team, site. Each form keeps its own fields in
lld_gen_documents. A Work Report started after the Work Plan copies the plan
(schedule, deliverables) so only the actual dates and the closing notes are
left to type.
"""
from __future__ import annotations

import json
import uuid
from datetime import date
from urllib.parse import quote

from core.docgen import forms

from . import store
from .service import GenError, cleanup_outputs, folder

KINDS = {"wpd": "Work Plan", "wrd": "Work Report"}
BULAN = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September",
         "Oktober", "November", "Desember"]
SUPPORT_TYPES = {"hw": "Hardware Warranty", "silver": "Silver Maintenance", "gold": "Gold Maintenance"}
PLAN_TASKS = ("Planning / Design", "Implementation", "Closing")
DOC_TYPES = ("Low Level Design Document", "UAT Document", "Implementation Document")
SHARED_TEXT = ("site_address", "city", "description", "support_type", "support_period")


def today_id(today: date | None = None) -> str:
    today = today or date.today()
    return f"{today.day} {BULAN[today.month - 1]} {today.year}"


def _lines(value) -> list[str]:
    if isinstance(value, str):
        value = value.splitlines()
    return [str(v).strip() for v in (value or []) if str(v).strip()]


def _rows(value, keys) -> list[dict]:
    out = []
    for row in value or []:
        if not isinstance(row, dict):
            continue
        clean = {k: str(row.get(k) or "").strip() for k in keys}
        if any(clean.values()):
            out.append(clean)
    return out


# ----------------------------------------------------------------- shared project data
def shared(project: dict) -> dict:
    team = json.loads(project.get("team") or "{}")
    return {
        **{k: project.get(k) or "" for k in SHARED_TEXT},
        "sow": json.loads(project.get("sow") or "[]"),
        "team": {"pm_mlpt": team.get("pm_mlpt", ""), "pm_customer": team.get("pm_customer", ""),
                 "mlpt": _lines(team.get("mlpt")), "customer": _lines(team.get("customer")),
                 "ops_pic": team.get("ops_pic", "")},
    }


def save_shared(project: dict, body: dict) -> dict:
    fields = {k: str(body.get(k) or "").strip() for k in SHARED_TEXT if k in body}
    if "support_type" in fields and fields["support_type"] not in SUPPORT_TYPES:
        fields["support_type"] = ""
    if "sow" in body:
        fields["sow"] = json.dumps(_lines(body["sow"]))
    if "team" in body:
        t = body["team"] or {}
        fields["team"] = json.dumps({"pm_mlpt": str(t.get("pm_mlpt") or "").strip(),
                                     "pm_customer": str(t.get("pm_customer") or "").strip(),
                                     "mlpt": _lines(t.get("mlpt")), "customer": _lines(t.get("customer")),
                                     "ops_pic": str(t.get("ops_pic") or "").strip()})
    store.update_project(project["id"], **fields)
    return shared(store.get_project(project["id"]))


# ----------------------------------------------------------------- per-document data
def _signatures(project: dict, team: dict, day: str) -> dict:
    return {"prepared_name": project.get("prepared_by") or "", "prepared_title": "System Engineer", "prepared_date": day,
            "acknowledged_name": team["pm_mlpt"], "acknowledged_title": "Project Manager", "acknowledged_date": day,
            "customer_name": team["pm_customer"], "customer_title": "Project Manager", "customer_date": day}


def defaults(project: dict, kind: str) -> dict:
    data = shared(project)
    team, day = data["team"], today_id()
    if kind == "wpd":
        return {"doc_date": day, "assumption": [], "risk": [], "csf": [],
                "plan": [{"task": t, "start": "", "finish": ""} for t in PLAN_TASKS],
                "resource": [{"name": n, "skill": ""} for n in team["mlpt"]],
                **_signatures(project, team, day)}
    plan = (store.get_document(project["id"], "wpd") or {}).get("data", {}).get("plan") or \
        [{"task": t, "start": "", "finish": ""} for t in PLAN_TASKS]
    plan = _rows(plan, ("task", "start", "finish"))
    return {"doc_date": day,
            "start": plan[0]["start"] if plan else "", "completed": plan[-1]["finish"] if plan else "",
            "deliverables": list(data["sow"]), "lessons": [],
            "schedule": [{"task": p["task"].split(" /")[0], "plan_start": p["start"], "plan_finish": p["finish"],
                          "actual_start": p["start"], "actual_finish": p["finish"]} for p in plan],
            "notes": [{"task": p["task"].split(" /")[0], "text": "As scheduled"} for p in plan],
            "training_date": "", "attendees": [],
            "documents": [{"type": t, "date": "", "by": team["pm_customer"]} for t in DOC_TYPES],
            "support_signer": "", **_signatures(project, team, day)}


def load(project_id: int, kind: str) -> dict:
    project = _project(project_id, kind)
    doc = store.get_document(project_id, kind)
    base = defaults(project, kind)
    data = {**base, **(doc["data"] if doc else {})}
    return {"kind": kind, "label": KINDS[kind], "saved": bool(doc), "generated_at": (doc or {}).get("generated_at", ""),
            "data": data, "shared": shared(project)}


def save(project_id: int, kind: str, body: dict) -> dict:
    project = _project(project_id, kind)
    if "shared" in body:
        save_shared(project, body["shared"] or {})
    keep = set(defaults(project, kind))
    data = {k: v for k, v in (body.get("data") or {}).items() if k in keep}
    store.save_document(project_id, kind, data)
    return load(project_id, kind)


def _project(project_id: int, kind: str) -> dict:
    if kind not in KINDS:
        raise GenError("Unknown document type", 404)
    project = store.get_project(project_id)
    if not project:
        raise GenError("Project not found", 404)
    return project


# ----------------------------------------------------------------- render
def values_and_lists(project: dict, kind: str, data: dict) -> tuple[dict, dict]:
    sh = shared(project)
    team = sh["team"]
    box = {f"svc_{k}": "☑" if sh["support_type"] == k else "☐" for k in SUPPORT_TYPES}
    values = {
        "project_name": project.get("name") or "", "project_code": project.get("project_code") or "",
        "customer": project.get("client") or "", "city": sh["city"], "site_address": sh["site_address"],
        "description": sh["description"], "support_period": sh["support_period"],
        "pm_mlpt": team["pm_mlpt"], "pm_customer": team["pm_customer"], "ops_pic": team["ops_pic"] or "-",
        **box,
        **{k: str(v or "") for k, v in data.items() if isinstance(v, (str, int, float))},
    }
    # signatures left blank fall back to the people the form already names
    for key, fallback in (("prepared_name", project.get("prepared_by") or ""), ("acknowledged_name", team["pm_mlpt"]),
                          ("customer_name", team["pm_customer"])):
        if not values.get(key):
            values[key] = fallback
    n = max(len(team["mlpt"]), len(team["customer"]))
    team_rows = [{"label": "Team Member" if i == 0 else "",
                  "mlpt": f"{i + 1}. {team['mlpt'][i]}" if i < len(team["mlpt"]) else "",
                  "customer": f"{i + 1}. {team['customer'][i]}" if i < len(team["customer"]) else "-"}
                 for i in range(n)]
    lists = {"team": team_rows}
    if kind == "wpd":
        lists.update({
            "sow": sh["sow"],
            "assumption": _lines(data.get("assumption")),
            "risk": _rows(data.get("risk"), ("issue", "level", "mitigation", "owner")),
            "csf": _lines(data.get("csf")),
            "plan": _rows(data.get("plan"), ("task", "start", "finish")),
            "res": _rows(data.get("resource"), ("name", "skill")) or [{"name": m, "skill": ""} for m in team["mlpt"]],
        })
    else:
        attendees = _lines(data.get("attendees"))
        lists.update({
            "deliverable": _lines(data.get("deliverables")),
            "lesson": _lines(data.get("lessons")),
            "sched": _rows(data.get("schedule"), ("task", "plan_start", "plan_finish", "actual_start", "actual_finish")),
            "note": _rows(data.get("notes"), ("task", "text")),
            "att": [{"label": "Attendee List" if i == 0 else "", "name": f"{i + 1}. {a}"} for i, a in enumerate(attendees)],
            "docs": _rows(data.get("documents"), ("type", "date", "by")),
        })
    return values, lists


def generate(project_id: int, kind: str) -> dict:
    info = load(project_id, kind)
    project = store.get_project(project_id)
    values, lists = values_and_lists(project, kind, info["data"])
    data = forms.render(kind, values, lists)
    cleanup_outputs()
    out_path = folder("outputs") / f"{project_id}_{uuid.uuid4().hex}.docx"
    out_path.write_bytes(data)
    if not info["saved"]:
        store.save_document(project_id, kind, info["data"])
    store.mark_generated(project_id, kind)
    code = project.get("project_code") or ""
    title = {"wpd": "Work Plan Document", "wrd": "Work Report Document"}[kind]
    safe = "".join(ch if ch.isalnum() or ch in " -_" else "_" for ch in f"{code} - {title}" if ch)
    out_name = f"{safe.strip(' -')}.docx"
    warnings = []
    for field, label in (("description", "Project description"), ("city" if kind == "wpd" else "site_address", "Site")):
        if not values.get(field):
            warnings.append(f"{label} is empty.")
    if not lists["team"]:
        warnings.append("Project team is empty.")
    return {"download_url": f"/lld-generator/api/download/{out_path.name}?name={quote(out_name)}",
            "filename": out_name, "warnings": warnings}
