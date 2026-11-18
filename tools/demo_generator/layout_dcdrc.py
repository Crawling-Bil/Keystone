"""layout.drawio of the "HQ DC DRC Branches" demo: the two sites drawn tier by tier with the same tiers, the branch pages as the builder places them, and an Overview with
the DC on the left, the DRC on the right and the six branches in two rows below."""
import sys, os, glob
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != HERE]       # this folder has a core.py of its own: it must not hide the repository's core package
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))                    # the repository root: the real Topology Builder
os.environ["NES_SECRET_KEY"] = "x"; os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
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


def site_page(p):
    hq = {}
    hq.update(pair(CX_E - 290, R[0], f"{p}WANR1", f"{p}WANR2"))        # provider routers and WAN firewalls on top, facing the outside
    hq.update(pair(CX_E + 290, R[0], f"{p}FGWAN1", f"{p}FGWAN2"))
    hq.update(pair(CX_E, R[1], f"{p}EDGE1", f"{p}EDGE2"))
    hq.update(pair(CX_E, R[2], f"{p}CORE1", f"{p}CORE2"))
    CX_L, CX_P = CX_E - 700, CX_E + 700
    hq.update(pair(CX_L, R[3], f"{p}FGLAN1", f"{p}FGLAN2"))            # LAN zone left
    hq.update(pair(CX_P, R[3], f"{p}PADC1", f"{p}PADC2"))              # data-center zone right
    hq.update(pair(CX_P, R[4], f"{p}SF1", f"{p}SF2"))
    hq.update(pair(CX_L, R[4], f"{p}DS1", f"{p}DS2"))                  # distribution pair: LAN firewalls above, access switches below
    hq.update(pair(CX_L, R[5], f"{p}ACC1", f"{p}ACC2", 520))
    hq.update(pair(CX_P, R[5], f"{p}TOR1", f"{p}TOR2", 520))

    def under(acc, kids):
        ax = hq[acc][0]
        for i, k in enumerate(kids):
            hq[k] = (ax + (-115 if i == 0 else 115), R[6])
    under(f"{p}ACC1", [f"{p}PC1", f"{p}PC2"]); under(f"{p}ACC2", [f"{p}PC3", f"{p}PC4"])
    under(f"{p}TOR1", [f"{p}SRV1", f"{p}SRV3"]); under(f"{p}TOR2", [f"{p}SRV2", f"{p}SRV4"])
    return hq


for page, prefix, far in (("HQ-DC", "HQ-DC-", "DRC-"), ("DRC", "DRC-", "HQ-DC-")):
    hq = site_page(prefix)
    # the other site's edge pair is only a neighbour on this page (the DCI): it stands beside the edge pair, on the side of the other site
    side = 1 if prefix == "HQ-DC-" else -1
    hq.update(pair(CX_E + side * 760, R[1], f"{far}EDGE1", f"{far}EDGE2"))
    missing = set(pages[page]) - set(hq); extra = set(hq) - set(pages[page])
    assert not missing and not extra, (page, missing, extra)
    pages[page] = hq


def block(nodes, ox, oy):
    x0 = min(x for x, _ in nodes.values()); y0 = min(y for _, y in nodes.values())
    return {k: (x - x0 + ox, y - y0 + oy) for k, (x, y) in nodes.items()}


def size(nodes):
    return (max(x for x, _ in nodes.values()) - min(x for x, _ in nodes.values()) + W, max(y for _, y in nodes.values()) - min(y for _, y in nodes.values()) + W)


GAP_X, GAP_Y, PAD, SITE_GAP = 420, 420, 200, 900
own = {name: {k: v for k, v in pages[name].items() if k.startswith(prefix)} for name, prefix in (("HQ-DC", "HQ-DC-"), ("DRC", "DRC-"))}      # without the neighbour edge pair of the other site
dc_w, dc_h = size(own["HQ-DC"])
branches = ["JKT", "SBY", "YOG", "MKS", "MED", "BAL"]
bw = max(size(pages[n])[0] for n in branches); bh = max(size(pages[n])[1] for n in branches)
row_w = 3 * bw + 2 * GAP_X
top_w = 2 * dc_w + SITE_GAP
total_w = max(top_w, row_w)
ox = PAD + (total_w - top_w) / 2
overview = block(own["HQ-DC"], ox, PAD)                                 # DC on the left, DRC on the right
overview.update(block(own["DRC"], ox + dc_w + SITE_GAP, PAD))
y = PAD + dc_h + GAP_Y
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
