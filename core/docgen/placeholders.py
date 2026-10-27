"""Isi placeholder {{...}} di dokumen hasil generate.

Master template nulis teks yang beda per project sebagai placeholder:
{{project_name}}, {{customer}}, {{project_code}}, {{version}}, {{date}},
{{year}}, {{company}}, {{prepared_by}}. Placeholder bisa ada di body, tabel,
header, footer, footnote dan text box (cover). Word sering mecah satu teks
jadi beberapa run (mis. "{{project_" + "name}}"), jadi penggantian jalan di
level <w:t> per paragraf, bukan per run.
"""
import re
from datetime import date

from docx.oxml.ns import qn

PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
_PART_TYPES = ("document", "header", "footer", "footnotes", "endnotes")


def project_values(project, today=None):
    """Nilai placeholder dari record project Document Generator."""
    today = today or date.today()
    doc_date = (project.get("doc_date") or "").strip() or f"{today.day:02d} {MONTHS[today.month - 1]} {today.year}"
    return {
        "project_name": project.get("name") or "",
        "customer": project.get("client") or "",
        "project_code": project.get("project_code") or "",
        "version": project.get("version") or "",
        "company": project.get("company") or "Multipolar Technology",
        "prepared_by": project.get("prepared_by") or "",
        "date": doc_date,
        "year": str(today.year),
    }


def _xml_parts(doc):
    for part in doc.part.package.parts:
        name = str(part.partname)
        if name.startswith("/word/") and any(t in name for t in _PART_TYPES) and hasattr(part, "_element"):
            yield part._element


def _fill_paragraph(p, values, missing):
    texts = [t for t in p.iter(qn("w:t"))]
    if not texts:
        return
    full = "".join(t.text or "" for t in texts)
    if "{{" not in full:
        return
    # posisi awal tiap <w:t> di teks gabungan
    starts, pos = [], 0
    for t in texts:
        starts.append(pos)
        pos += len(t.text or "")
    edits = []
    for m in PATTERN.finditer(full):
        key = m.group(1).lower()
        value = values.get(key)
        if value is None or value == "":
            missing.add(key)
            continue
        edits.append((m.start(), m.end(), str(value)))
    # dari belakang supaya posisi depan nggak geser
    for start, end, value in reversed(edits):
        first = max(i for i, s in enumerate(starts) if s <= start)
        last = max(i for i, s in enumerate(starts) if s < end)
        for i in range(first, last + 1):
            t = texts[i]
            text = t.text or ""
            a = max(start - starts[i], 0)
            b = min(end - starts[i], len(text))
            if i == first:
                t.text = text[:a] + value + text[b:]
            else:
                t.text = text[b:]
            if t.text != t.text.strip():
                t.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        # panjang teks berubah: hitung ulang posisi buat edit berikutnya (yang di depan)
        starts, pos = [], 0
        for t in texts:
            starts.append(pos)
            pos += len(t.text or "")


def fill(doc, values):
    """Ganti placeholder di semua bagian dokumen. Return set nama placeholder
    yang nggak ada nilainya (dibiarkan apa adanya di dokumen)."""
    missing = set()
    for root in _xml_parts(doc):
        for p in root.iter(qn("w:p")):
            _fill_paragraph(p, values, missing)
    props = doc.core_properties
    if values.get("project_name"):
        props.title = f"LLD - {values['project_name']}"
    if values.get("customer"):
        props.subject = values["customer"]
    if values.get("prepared_by"):
        props.author = values["prepared_by"]
    if values.get("project_code"):
        props.keywords = values["project_code"]
    return missing


def remaining(doc):
    """Placeholder yang masih ada di dokumen (buat warning)."""
    found = set()
    for root in _xml_parts(doc):
        for p in root.iter(qn("w:p")):
            text = "".join(t.text or "" for t in p.iter(qn("w:t")))
            found.update(m.group(1).lower() for m in PATTERN.finditer(text))
    return found


LOGO_TAG = "{{customer_logo}}"
_A = "http://schemas.openxmlformats.org/drawingml/2006/main"


def fill_logo(doc, logo_path):
    """Gambar yang docPr descr-nya {{customer_logo}} diganti logo customer
    (ukuran dipas ke kotak aslinya, proporsi dijaga). Tanpa logo: gambarnya
    dihapus. Return True kalau ada slot logo di template."""
    import os
    from docx.image.image import Image

    found = False
    for root in _xml_parts(doc):
        for drawing in list(root.iter(qn("w:drawing"))):
            docpr = drawing.find(".//" + qn("wp:docPr"))
            if docpr is None or (docpr.get("descr") or "").strip() != LOGO_TAG:
                continue
            found = True
            run = drawing.getparent()
            if not logo_path or not os.path.exists(logo_path):
                run.getparent().remove(run)
                continue
            if root is not doc.element:
                continue  # logo cuma di body (cover)
            rid, image = doc.part.get_or_add_image(logo_path)
            blip = drawing.find(".//{%s}blip" % _A)
            blip.set(qn("r:embed"), rid)
            docpr.set("descr", "Customer logo")
            extent = drawing.find(".//" + qn("wp:extent"))
            box_w, box_h = int(extent.get("cx")), int(extent.get("cy"))
            ratio = min(box_w / image.width, box_h / image.height) if image.width and image.height else 1
            w, h = int(image.width * ratio), int(image.height * ratio)
            extent.set("cx", str(w))
            extent.set("cy", str(h))
            ext = drawing.find(".//{%s}xfrm/{%s}ext" % (_A, _A))
            if ext is not None:
                ext.set("cx", str(w))
                ext.set("cy", str(h))
    return found
