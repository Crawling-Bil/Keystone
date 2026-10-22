"""Narrative paragraphs written from the project form.

The wording follows the existing Multipolar LLDs (Introduction chapter:
Project Description, Scope of Work, Out of Scope, Document Scope, Related
Document). Bullet items become one paragraph each, prefixed with a bullet,
because the Document Generator imports a paragraph list as separate
paragraphs.
"""

from __future__ import annotations

from collections import Counter

from .inventory import TECH_LABELS

BULLET = "• "

DEFAULT_OUT_OF_SCOPE = [
    "Civil or construction works, including server room modifications, rack installation or other physical infrastructure.",
    "Provision of devices outside the agreed BoQ.",
    "Configuration of devices or services not listed in this document.",
]
DEFAULT_RELATED = ["Kick Off Meeting (KOM) document", "Bill of Quantity (BoQ)", "Implementation Plan / Method of Procedure (MoP)"]


def _lines(value) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = str(value or "").splitlines()
    return [str(i).strip().lstrip("-*•").strip() for i in items if str(i).strip().lstrip("-*•").strip()]


def _sentence(text: str) -> str:
    text = text.strip()
    return text if not text or text[-1] in ".!?:" else text + "."


def _device_summary(devices) -> str:
    if not devices:
        return ""
    by_model = Counter(d.model or TECH_LABELS.get(d.technology, "device") for d in devices)
    parts = [f"{count} x {model}" for model, count in by_model.most_common()]
    sites = len({d.site for d in devices})
    site_word = "site" if sites == 1 else "sites"
    return f"The design covers {len(devices)} devices across {sites} {site_word}: {', '.join(parts)}."


def paragraphs(key: str, project: dict, scope, datasets) -> list[str]:
    customer = project.get("customer") or "the customer"
    name = project.get("project_name") or "this project"
    company = project.get("company") or "Multipolar Technology"
    techs = ", ".join(TECH_LABELS.get(t, t) for t in project.get("technologies") or [])
    if key == "project_description":
        out = [f"This document describes the Low Level Design (LLD) in terms of concept, architecture and device "
               f"configuration at {customer}, for the {name} project" + (f" ({techs})." if techs else ".")]
        goals = _lines(project.get("goals"))
        if goals:
            out.append("The project aims to:")
            out += [BULLET + _sentence(g) for g in goals]
        summary = _device_summary(scope.devices)
        if summary:
            out.append(summary)
        return out
    if key == "scope_of_work":
        items = _lines(project.get("scope"))
        if not items:
            models = sorted({d.model for d in scope.devices if d.model})
            items = [f"Installation of {', '.join(models)}." if models else "Installation of the devices in the BoQ.",
                     "Configuration of the devices according to this document.",
                     "Migration and verification (UAT) of the services in scope."]
        return [f"{company} will implement this project to fulfil {customer}'s requirements. The scope of work is:"] + \
               [BULLET + _sentence(i) for i in items]
    if key == "out_of_scope":
        items = _lines(project.get("out_of_scope")) or DEFAULT_OUT_OF_SCOPE
        return ["The following items are not part of this project:"] + [BULLET + _sentence(i) for i in items]
    if key == "related_documents":
        items = _lines(project.get("related_documents")) or DEFAULT_RELATED
        return ["The documents below are closely related to this document as part of the project documentation:"] + \
               [BULLET + i for i in items]
    if key == "model_description":
        return [model_description(scope)]
    if key == "document_scope":
        return ["__DOCUMENT_SCOPE__"]  # filled once every chapter is known
    return []


def fill_document_scope(nodes: list, project: dict) -> None:
    chapters = [n.title for n in nodes if n.level == 1 and n.title.lower() not in ("introduction", "pendahuluan")]
    for node in nodes:
        if node.paragraphs == ["__DOCUMENT_SCOPE__"]:
            node.paragraphs = ["This document gives the reader an overview of the network design implemented in "
                               f"{project.get('customer') or 'the customer'}'s network. It explains the following:"] + \
                              [BULLET + c for c in chapters]
            node.placeholder = False


def model_description(scope) -> str:
    """'S5755-H24T4Y2CZ (Fixed 24x ... ) will be used as Core Switch at HO and BR.'"""
    model = scope.model
    detail = ""
    try:
        from features.configuration_studio.converter_engine.hardware.catalog import get_model

        hw = get_model(model)
        if hw is not None:
            detail = hw.summary or hw.label
    except Exception:
        hw = None
    if not detail:
        try:
            from features.configuration_studio.converter_engine.translators.firewall.paloalto import PALOALTO_TARGET_MODELS

            detail = next((m["label"].split("(", 1)[-1].rstrip(")") for m in PALOALTO_TARGET_MODELS
                           if m["model"].upper() == model.upper()), "")
        except Exception:
            detail = ""
    roles = list(dict.fromkeys(d.role or TECH_LABELS.get(d.technology, "device") for d in scope.devices))
    sites = list(dict.fromkeys(d.site for d in scope.devices))
    count = len(scope.devices)
    role_text = " and ".join(roles) if roles else "a network device"
    site_text = sites[0] if len(sites) == 1 else ", ".join(sites[:-1]) + " and " + sites[-1]
    head = f"{model} ({detail.rstrip('.')})" if detail else model
    unit = "unit" if count == 1 else "units"
    return f"{head}. {count} {unit} will be used as {role_text} at {site_text}."
