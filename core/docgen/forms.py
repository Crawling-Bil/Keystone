"""Fill a Word form template (Work Plan, Work Report).

Templates live in core/docgen/forms/ and are built by make_forms.py. They use
two kinds of placeholder:

- ``{{name}}`` anywhere: a single value (header fields, signatures).
- ``{{list.key}}`` or ``{{list}}`` inside a table row: that row repeats once
  per item of ``list``. When the row right below carries the same list, it is
  the continuation row (its first cell is merged into the first row's, as in
  "Team Member") and is used from the second item on.

An empty list keeps one blank row, so the printed form keeps its shape.
Missing values print as blank, never as the raw placeholder.
"""
from __future__ import annotations

import copy
import io
import re
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn

FORMS_DIR = Path(__file__).resolve().parent / "forms"
TEMPLATES = {
    "wpd": FORMS_DIR / "Work Plan Document.docx",
    "wrd": FORMS_DIR / "Work Report Document.docx",
}
TOKEN = re.compile(r"\{\{\s*([A-Za-z_][\w]*)(?:\.([A-Za-z_]\w*))?\s*\}\}")
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"


def _paragraphs(element):
    return element.iter(qn("w:p"))


def _fill_paragraph(p, lookup) -> None:
    texts = list(p.iter(qn("w:t")))
    if not texts:
        return
    full = "".join(t.text or "" for t in texts)
    if "{{" not in full:
        return
    new = TOKEN.sub(lambda m: str(lookup(m.group(1), m.group(2)) or ""), full)
    texts[0].text = new
    texts[0].set(XML_SPACE, "preserve")
    for t in texts[1:]:
        t.text = ""


def _row_list(tr, lists) -> str | None:
    text = "".join(t.text or "" for t in tr.iter(qn("w:t")))
    for m in TOKEN.finditer(text):
        if m.group(1) in lists:
            return m.group(1)
    return None


def _item_value(item, key):
    if isinstance(item, dict):
        return item.get(key or "", "")
    return item if key is None else ""


def _expand_lists(doc, lists: dict) -> None:
    for tbl in list(doc.element.body.iter(qn("w:tbl"))):
        rows = tbl.findall(qn("w:tr"))
        i = 0
        while i < len(rows):
            name = _row_list(rows[i], lists)
            if not name:
                i += 1
                continue
            first = rows[i]
            cont = rows[i + 1] if i + 1 < len(rows) and _row_list(rows[i + 1], lists) == name else None
            items = list(lists.get(name) or []) or [{}]
            anchor = first
            made = []
            for n, item in enumerate(items):
                source = first if n == 0 or cont is None else cont
                tr = copy.deepcopy(source)
                for p in _paragraphs(tr):
                    _fill_paragraph(p, lambda lst, key, item=item: _item_value(item, key) if lst == name else "{{%s%s}}" % (lst, "." + key if key else ""))
                anchor.addnext(tr)
                anchor = tr
                made.append(tr)
            for tr in (first, cont):
                if tr is not None:
                    tbl.remove(tr)
            rows = tbl.findall(qn("w:tr"))
            i = rows.index(made[-1]) + 1


def _parts(doc):
    yield doc.element.body
    for section in doc.sections:
        for part in (section.header, section.footer, section.first_page_header, section.first_page_footer):
            try:
                yield part._element
            except Exception:  # noqa: BLE001 - missing header parts are fine
                continue


SERVICE_KEYS = ("svc_hw", "svc_silver", "svc_gold")


def _service_boxes(doc, values: dict) -> None:
    """Work Plan prints the service boxes as list bullets: the sample's
    Hardware Warranty bullet is the ticked box, the others the empty box.
    Each cell gets the bullet that matches the choice, and loses the token."""
    paras = {}
    for p in _paragraphs(doc.element.body):
        text = "".join(t.text or "" for t in p.iter(qn("w:t")))
        num = p.find(f"{qn('w:pPr')}/{qn('w:numPr')}/{qn('w:numId')}")
        for key in SERVICE_KEYS:
            if "{{%s}}" % key in text and num is not None:
                paras[key] = (p, num)
    if len(paras) < 2 or "svc_hw" not in paras or "svc_silver" not in paras:
        return
    ticked, empty = paras["svc_hw"][1].get(qn("w:val")), paras["svc_silver"][1].get(qn("w:val"))
    for key, (p, num) in paras.items():
        num.set(qn("w:val"), ticked if values.get(key) == "\u2611" else empty)
        for t in p.iter(qn("w:t")):
            t.text = (t.text or "").replace("{{%s}} " % key, "").replace("{{%s}}" % key, "")


def render(kind: str, values: dict, lists: dict) -> bytes:
    """Fill the form ``kind`` ('wpd' or 'wrd') and return the .docx bytes."""
    doc = Document(str(TEMPLATES[kind]))
    _service_boxes(doc, values)
    _expand_lists(doc, lists)
    for root in _parts(doc):
        for p in _paragraphs(root):
            _fill_paragraph(p, lambda name, key: values.get(name, "") if key is None else "")
    props = doc.core_properties
    props.title = {"wpd": "Work Plan Document", "wrd": "Work Report"}[kind]
    props.subject = values.get("project_name", "")
    props.author = values.get("prepared_name", "")
    props.keywords = values.get("project_code", "")
    out = io.BytesIO()
    doc.save(out)
    return out.getvalue()


def leftover_tokens(data: bytes) -> list[str]:
    """Placeholders still in a rendered file (should be none)."""
    doc = Document(io.BytesIO(data))
    found = set()
    for root in _parts(doc):
        for p in _paragraphs(root):
            text = "".join(t.text or "" for t in p.iter(qn("w:t")))
            found.update(m.group(0) for m in TOKEN.finditer(text))
    return sorted(found)
