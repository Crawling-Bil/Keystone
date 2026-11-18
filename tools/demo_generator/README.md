# Demo generator

Generates the invented captures of the two multi-site demo sets of the Topology Builder (`features/topology/demo/multisite`, 44 captures, and `features/topology/demo/dcdrc`, 64 captures) and the
hand-tiered pages of their `layout.drawio`.  Every name, address, serial number and MAC address is invented (documentation and benchmark ranges, private blocks, made-up serials).

    python tools/demo_generator/gen.py OUT_DIR                 # the multi-site set (HQ and six branches)
    python tools/demo_generator/gen_dcdrc.py OUT_DIR           # the DC / DRC set: the HQ-DC and DRC sites, a dedicated interconnect, six branches
    python tools/demo_generator/layout_dcdrc.py CAPTURES_DIR layout.drawio       # needs the captures of the DC / DRC set
    python tools/demo_generator/layout_multisite.py CAPTURES_DIR layout.drawio

A site plan (`plan_hq.py`, `plan_branch.py`) says which devices exist and how they are cabled, `routing.py` derives the routes and neighbors from it, `r_cisco.py`, `r_fw.py` and
`r_other.py` print each device as the commands the Topology Builder reads (NX-OS, IOS, FortiOS, PAN-OS, AOS-CX, VRP).  The DC / DRC set is the HQ plan read through a text transform
with its own address block, AS number and serial numbers, so the two sites cannot drift apart.

`tests/test_topology_demo_generator.py` regenerates both sets and compares them byte for byte with the shipped captures: change a plan, regenerate, copy the result into
`features/topology/demo/<set>/` and commit both.  The pages of `layout.drawio` that are placed by hand (the head quarter, HQ-DC and DRC) must stay as written; the branch pages come from the builder,
so a change of the placement engine may move them: regenerate the layout then, with the commands above, and look at the page before committing.
