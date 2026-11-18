"""Write layout.drawio for the multi-site demo: auto positions for the branch pages, a hand-tiered HQ page."""
import sys, os, glob
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != HERE]       # this folder has a core.py of its own: it must not hide the repository's core package
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))                    # the repository root: the real Topology Builder
os.environ.setdefault("NES_SECRET_KEY", "x"); os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
from xml.sax.saxutils import quoteattr
from features.topology import service as S

src, out = sys.argv[1], sys.argv[2]
files = [(os.path.basename(p), open(p, encoding="utf-8").read()) for p in sorted(glob.glob(src + "/*.txt"))]
b = S.build_topology(files, group="auto", collapse_endpoints=False, include_hosts=False, view="physical", line_shape="angled", group_endpoints=True, collapse_aps=False)
pages = {p.name: {k: (n.x, n.y) for k, n in p.nodes.items()} for p in b["pages"] if p.name != "Overview"}

W = 76
CX_E = 1338                                   # axis of the edge / core pairs
R = [80, 400, 720, 1040, 1320, 1620, 1920]     # rows, top to bottom
def pair(cx, y, a, b_, gap=230):
    return {a: (cx - gap / 2 - W / 2, y), b_: (cx + gap / 2 - W / 2, y)}
hq = {}
hq.update(pair(CX_E - 290, R[0], "HQ-WANR1", "HQ-WANR2"))        # provider routers and WAN firewalls on top, facing the outside
hq.update(pair(CX_E + 290, R[0], "HQ-FGWAN1", "HQ-FGWAN2"))
hq.update(pair(CX_E, R[1], "HQ-EDGE1", "HQ-EDGE2"))
hq.update(pair(CX_E, R[2], "HQ-CORE1", "HQ-CORE2"))
CX_L, CX_P = CX_E - 700, CX_E + 700
hq.update(pair(CX_L, R[3], "HQ-FGLAN1", "HQ-FGLAN2"))            # LAN zone left
hq.update(pair(CX_P, R[3], "HQ-PADC1", "HQ-PADC2"))              # data-center zone right
hq.update(pair(CX_P, R[4], "HQ-SF1", "HQ-SF2"))
hq.update(pair(CX_L, R[4], "HQ-DS1", "HQ-DS2"))                  # distribution pair: LAN firewalls above, access switches below
hq.update(pair(CX_L, R[5], "HQ-ACC1", "HQ-ACC2", 520))
hq.update(pair(CX_P, R[5], "HQ-TOR1", "HQ-TOR2", 520))
def under(acc, kids):
    ax = hq[acc][0]
    for i, k in enumerate(kids):
        hq[k] = (ax + (-115 if i == 0 else 115), R[6])
under("HQ-ACC1", ["HQ-PC1", "HQ-PC2"]); under("HQ-ACC2", ["HQ-PC3", "HQ-PC4"])
under("HQ-TOR1", ["HQ-SRV1", "HQ-SRV3"]); under("HQ-TOR2", ["HQ-SRV2", "HQ-SRV4"])
missing = set(pages["HQ"]) - set(hq); extra = set(hq) - set(pages["HQ"])
assert not missing and not extra, (missing, extra)
pages["HQ"] = hq

# Overview: the head quarter on top, the six branches in two rows below (their own page layouts, moved as one block)
def block(nodes, ox, oy):
    x0 = min(x for x, _ in nodes.values()); y0 = min(y for _, y in nodes.values())
    return {k: (x - x0 + ox, y - y0 + oy) for k, (x, y) in nodes.items()}
def size(nodes):
    return (max(x for x, _ in nodes.values()) - min(x for x, _ in nodes.values()) + W, max(y for _, y in nodes.values()) - min(y for _, y in nodes.values()) + W)
GAP_X, GAP_Y, PAD = 420, 420, 200
hq_w, hq_h = size(hq)
branches = ["JKT", "SBY", "YOG", "MKS", "MED", "BAL"]
bw = max(size(pages[n])[0] for n in branches); bh = max(size(pages[n])[1] for n in branches)
row_w = 3 * bw + 2 * GAP_X
total_w = max(hq_w, row_w)
overview = block(hq, PAD + (total_w - hq_w) / 2, PAD)
y = PAD + hq_h + GAP_Y
for r in range(2):
    for c in range(3):
        name = branches[r * 3 + c]
        w, h = size(pages[name])
        overview.update(block(pages[name], PAD + (total_w - row_w) / 2 + c * (bw + GAP_X) + (bw - w) / 2, y + r * (bh + GAP_Y)))
    
pages = {"Overview": overview, **pages}

lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<mxfile>"]
for name, nodes in pages.items():
    lines.append(f"  <diagram name={quoteattr(name)} id={quoteattr('page-' + name.lower().replace(' ', '-'))}>")
    lines.append('    <mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>')
    for key, (x, y) in sorted(nodes.items()):
        lines.append(f'      <object label={quoteattr(key)} node_key={quoteattr(key)} id={quoteattr("n-" + key)}><mxCell style="rounded=1;" vertex="1" parent="1"><mxGeometry x="{x:.0f}" y="{y:.0f}" width="{W}" height="{W}" as="geometry"/></mxCell></object>')
    lines.append("    </root></mxGraphModel>")
    lines.append("  </diagram>")
lines.append("</mxfile>")
open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
print(out, os.path.getsize(out), "bytes;", len(pages), "pages")
