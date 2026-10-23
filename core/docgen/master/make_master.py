"""Bikin LLD Master Template dari LLD yang udah jadi.

python make_master.py "<LLD sumber>.docx" "LLD Master Template.docx" "<LLD dengan Document Acceptance>.docx"

Yang beda per project diganti placeholder yang diisi Document Generator pas
generate: {{project_name}}, {{customer}}, {{project_code}}, {{version}},
{{date}}, {{year}}, {{prepared_by}}; logo customer di cover jadi slot
{{customer_logo}}. Semua bab isi dibuang (datangnya dari Index Excel).
Index paragraf/tabel di bawah ngikutin LLD Wireless Network Improvement.
"""
import sys, copy, re, os, tempfile
import docx
import docx.table
import docx.text.paragraph
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from PIL import Image, ImageDraw, ImageFont

SRC, OUT = sys.argv[1], sys.argv[2]
# Document Acceptance diambil dari LLD lain yang punya (LLD Wireless sumber nggak punya)
ACCEPT_SRC = sys.argv[3] if len(sys.argv) > 3 else None
d = docx.Document(SRC)
W_T = qn('w:t')

def replace_text(p_el, old, new):
    texts = list(p_el.iter(W_T))
    full = "".join(t.text or "" for t in texts)
    if old not in full: return False
    while old in full:
        start = full.index(old); end = start + len(old)
        pos = 0; first = True
        for t in texts:
            text = t.text or ""; s, e = pos, pos + len(text); pos = e
            if e <= start or s >= end: continue
            a, b = max(start - s, 0), min(end - s, len(text))
            t.text = text[:a] + (new if first else "") + text[b:]; first = False
            t.set('{http://www.w3.org/XML/1998/namespace}space', 'preserve')
        full = "".join(t.text or "" for t in texts)
    return True

def set_text(p, value):
    runs = p.runs
    runs[0].text = value
    for r in runs[1:]: r.text = ""

ps = d.paragraphs
# Cover
set_text(ps[9], "{{project_name}}")
set_text(ps[10], "Version {{version}}")
# Confidentiality
for i in (67, 68):
    replace_text(ps[i]._p, "PT Toyota Astra Motor (TAM)", "{{customer}}")
    replace_text(ps[i]._p, "TAM", "{{customer}}")
replace_text(ps[70]._p, "2026", "{{year}}")
# Document Properties
t0 = d.tables[0]
vals = {"Writer": "{{prepared_by}}", "Client": "{{customer}}", "Project Name": "{{project_name}}",
        "Title": "Low Level Design - {{project_name}}", "Version": "{{version}}", "File Name": "LLD - {{project_name}}"}
for row in t0.rows:
    key = row.cells[0].text.strip()
    if key in vals:
        set_text(row.cells[1].paragraphs[0], vals[key])
# add Project Code row after Client
client_row = next(r for r in t0.rows if r.cells[0].text.strip() == "Client")
new_tr = copy.deepcopy(client_row._tr); client_row._tr.addnext(new_tr)
from docx.table import _Row
nr = _Row(new_tr, t0)
set_text(nr.cells[0].paragraphs[0], "Project Code"); set_text(nr.cells[1].paragraphs[0], "{{project_code}}")
# Release History
r1 = d.tables[1].rows[1]
for c, v in zip(r1.cells[:3], ("{{version}}", "{{date}}", "{{prepared_by}}")):
    set_text(c.paragraphs[0], v)
# Footers / headers
for part in d.part.package.parts:
    name = str(part.partname)
    if ('footer' in name or 'header' in name) and hasattr(part, '_element'):
        for p in part._element.iter(qn('w:p')):
            replace_text(p, "Toyota Astra Motor – [Nama Project]", "{{customer}} – {{project_name}}")
            replace_text(p, "Toyota Astra Motor", "{{customer}}")
            replace_text(p, "[Nama Project]", "{{project_name}}")
# Customer logo slot: neutral placeholder image, tagged for Document Generator
logo_drawing = None
for dr in ps[15]._p.iter(qn('w:drawing')):
    logo_drawing = dr
docpr = logo_drawing.find('.//' + qn('wp:docPr'))
docpr.set('descr', '{{customer_logo}}'); docpr.set('name', 'Customer Logo')
img = Image.new('RGB', (900, 380), 'white'); dr_ = ImageDraw.Draw(img)
dr_.rectangle([4, 4, 895, 375], outline=(170, 170, 170), width=6)
try: font = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf', 64)
except Exception: font = ImageFont.load_default()
dr_.text((450, 190), "CUSTOMER LOGO", fill=(150, 150, 150), font=font, anchor='mm')
logo_tmp = os.path.join(tempfile.mkdtemp(), 'logo_placeholder.png')
img.save(logo_tmp)
blip = logo_drawing.find('.//{http://schemas.openxmlformats.org/drawingml/2006/main}blip')
rid, _ = d.part.get_or_add_image(logo_tmp)
blip.set(qn('r:embed'), rid)
# Body: drop everything from the first Heading 1, keep one starter Heading 1
body = d.element.body
first_h1 = next(p for p in d.paragraphs if p.style.name == 'Heading 1')
# The front matter's section (header logo, footer, watermark, margins) ends at
# the first section break after it; that break is in the removed part, so its
# settings become the document's final section.
first_sect = None
for p_el in body.iter(qn('w:p')):
    sp = p_el.find(qn('w:pPr') + '/' + qn('w:sectPr'))
    if sp is not None:
        first_sect = copy.deepcopy(sp)
        break
el = first_h1._p.getnext()
while el is not None and el.tag != qn('w:sectPr'):
    nxt = el.getnext()
    body.remove(el); el = nxt
inner = first_h1._p.find(qn('w:pPr') + '/' + qn('w:sectPr'))
if inner is not None:
    inner.getparent().remove(inner)
if first_sect is not None:
    body.replace(body.find(qn('w:sectPr')), first_sect)
set_text(first_h1, "Introduction")
# Document Acceptance (closing heading): copied from ACCEPT_SRC, values as placeholders
def set_cell(cell, *lines):
    paras = cell.paragraphs
    for extra in paras[1:]:
        extra._p.getparent().remove(extra._p)
    p0 = paras[0]
    for r in p0.runs[1:]:
        r._r.getparent().remove(r._r)
    run = p0.runs[0] if p0.runs else p0.add_run()
    run.text = lines[0] if lines else ""
    for line in lines[1:]:
        run.add_break()
        run.add_text(line)

if ACCEPT_SRC:
    src = docx.Document(ACCEPT_SRC)
    sels = list(src.element.body)
    start = max(i for i, e in enumerate(sels) if e.tag == qn('w:p') and
                "".join(t.text or "" for t in e.iter(W_T)).strip() == "Document Acceptance")
    target_sect = body.find(qn('w:sectPr'))
    copied = []
    for e in sels[start:]:
        if e.tag == qn('w:sectPr'):
            continue
        e = copy.deepcopy(e)
        for dr in list(e.iter(qn('w:drawing'))):          # signature images: not carried over
            dr.getparent().remove(dr)
        for inner in list(e.iter(qn('w:sectPr'))):
            inner.getparent().remove(inner)
        target_sect.addprevious(e)
        copied.append(e)
    # Heading 1 tanpa nomor bab: Document Generator mengenalinya sebagai closing heading
    head = docx.text.paragraph.Paragraph(copied[0], d._body)
    head.style = d.styles['Heading 1']
    ppr = copied[0].get_or_add_pPr()
    num = ppr.find(qn('w:numPr'))
    if num is not None:
        ppr.remove(num)
    num = OxmlElement('w:numPr')
    for tag, val in (('w:ilvl', '0'), ('w:numId', '0')):
        el = OxmlElement(tag); el.set(qn('w:val'), val); num.append(el)
    pstyle = ppr.find(qn('w:pStyle'))
    if pstyle is not None:
        pstyle.addnext(num)
    else:
        ppr.insert(0, num)
    head.paragraph_format.page_break_before = True
    tables = [docx.table.Table(e, d._body) for e in copied if e.tag == qn('w:tbl')]
    info, _revision, customer, multipolar = tables[0], tables[1], tables[2], tables[3]
    values = {"Project Name": "{{project_name}}", "Title": "LLD - {{project_name}}", "Version": "{{version}}",
              "Status": "Initial"}
    for row in info.rows:
        key = row.cells[0].text.strip()
        if key in values:
            set_cell(row.cells[1], values[key])
    for row in list(customer.rows)[4:]:
        row._tr.getparent().remove(row._tr)
    for row in list(customer.rows)[1:]:
        set_cell(row.cells[0], "", "")
        set_cell(row.cells[1], "{{customer}}")
        set_cell(row.cells[2], "")
    mp_people = [("", "Section Head"), ("{{prepared_by}}", "Network Engineer"), ("", "Project Manager")]
    for row, (name, title) in zip(list(multipolar.rows)[1:], mp_people):
        set_cell(row.cells[0], name, title)
        set_cell(row.cells[1], "PT. Multipolar Technology Tbk.")
        set_cell(row.cells[2], "")
    from docx.shared import Pt
    from docx.enum.table import WD_ROW_HEIGHT_RULE
    for table in (customer, multipolar):
        for row in list(table.rows)[1:]:
            row.height = Pt(46)                      # room for a signature
            row.height_rule = WD_ROW_HEIGHT_RULE.AT_LEAST

# TOC: drop the stale project entries (Word rebuilds the TOC on open).
FLD = qn('w:fldChar')
for p in list(d.paragraphs):
    if not p.style.name.startswith('toc '):
        continue
    if not re.search(r'^(Bab \d|\d+\.\d)', p.text.strip()):
        continue
    kinds = [f.get(qn('w:fldCharType')) for f in p._p.iter(FLD)]
    if kinds.count('begin') == kinds.count('end'):
        p._p.getparent().remove(p._p)
    else:
        for t in p._p.iter(W_T):
            t.text = ""
# "Perjanjian Kerahasiaan" heading carries the stale result of the List of Table field
for p in d.paragraphs:
    if p.text.startswith("No table of figures entries found.") and "Perjanjian" in p.text:
        replace_text(p._p, "No table of figures entries found.", "")
d.core_properties.title = "LLD Master Template"
d.core_properties.subject = ""
d.core_properties.author = "Multipolar Technology"
d.save(OUT)
print("ok")
