"""Generate every capture of the multi-site demo into OUT (default: ./out)."""
import os, sys, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import core, r_cisco, r_fw
import plan_hq
try:
    import plan_branch
except ImportError:
    plan_branch = None
try:
    import routing
except ImportError:
    routing = None
try:
    import r_other
except ImportError:
    r_other = None

RENDER = {"nxos": r_cisco.render_nxos, "ios": r_cisco.render_ios, "iosrtr": r_cisco.render_ios, "forti": r_fw.render_forti, "pan": r_fw.render_pan}
if r_other:
    RENDER.update({"aoscx": r_other.render_aoscx, "vrp": r_other.render_vrp})


def main(out):
    plan_hq.build()
    if plan_branch:
        plan_branch.build()
    if routing:
        routing.compute()
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    for h, d in core.DEVICES.items():
        text = RENDER[d.os](d)
        with open(os.path.join(out, f"{h}.txt"), "w", newline="\n", encoding="utf-8") as fh:
            fh.write(text)
    return list(core.DEVICES)


if __name__ == "__main__":
    names = main(sys.argv[1] if len(sys.argv) > 1 else "out")
    print(len(names), "captures")
