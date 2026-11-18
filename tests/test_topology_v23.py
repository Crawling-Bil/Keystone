"""Topology v2.3: zone boxes on every kind of page, a centre found from the cables, one large block cut in two, two centres on one diagram, a reader that can be stopped.

Everything is built from the invented ``dcdrc`` demo set or from small synthetic networks (names ``ZZ-``, ``YY-``); no customer data.  The rules are about roles and cables, not names.

Standards for the shape: Cisco Campus LAN and Wireless LAN Design Guide https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-campus-lan-wlan-design-guide.html ;
Python multiprocessing https://docs.python.org/3/library/multiprocessing.html
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from features.topology import demo, isolate, layout, roles, scene, service, zonelayout, zones
from features.topology.extract import Device, HalfEdge
from features.topology.graph import build
from features.topology.service import build_topology


def _captures(setid: str = "dcdrc") -> list[tuple[str, str]]:
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((demo.DEMO_DIR / setid).glob("*.txt"))]


def _built(**more) -> dict:
    return build_topology(_captures(), group="auto", collapse_endpoints=False, include_hosts=False, view="all", group_endpoints=True, collapse_aps=False, **more)


@pytest.fixture(scope="module")
def built() -> dict:
    return _built()


# ---- synthetic networks -------------------------------------------------------------------------------------------------------------------------------

def _dev(name, model, neighbours, role="switch", hosts=0, function=""):
    halves = [HalfEdge(local_port=f"Eth1/{i}", remote_name=n, remote_port="Eth1/48", protocols={"LLDP"}) for i, n in enumerate(neighbours, 1)]
    halves += [HalfEdge(local_port=f"Gi1/0/{i}", remote_name=f"HOST{name.replace('-', '')}X{i}", remote_port="nic", protocols={"LLDP"}, remote_caps="Station") for i in range(1, hosts + 1)]
    device = Device(key=name, hostname=name, captured=True, role_hint=role, model=model, stack_members=1, halves=halves)
    if function:
        device.function = function
    return device


def _farm(prefix: str = "ZZ", tors: int = 8, single_core: bool = False, lan: int = 6):
    """A core pair (or one core), an edge router pair on the way out, a campus block (a distribution switch with ``lan`` access switches) and a server farm: an aggregation pair with ``tors`` top-of-rack switches that are each cabled to both."""
    p = prefix
    tor_names = [f"{p}-TOR{i}" for i in range(1, tors + 1)]
    core = [f"{p}-CORE1"] if single_core else [f"{p}-CORE1", f"{p}-CORE2"]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + [f"{p}-AGG1", f"{p}-AGG2", f"{p}-RT1", f"{p}-RT2", f"{p}-DIST1"]) for c in core]
    devices += [
        _dev(f"{p}-AGG1", "C9500-24Y4C", core + [f"{p}-AGG2"] + tor_names),
        _dev(f"{p}-AGG2", "C9500-24Y4C", core + [f"{p}-AGG1"] + tor_names),
        _dev(f"{p}-RT1", "ASR1002-X", core + [f"{p}-RT2"], role="router", function="wan"),
        _dev(f"{p}-RT2", "ASR1002-X", core + [f"{p}-RT1"], role="router", function="wan"),
        _dev(f"{p}-DIST1", "C9300-48P", core + [f"{p}-ACC{i}" for i in range(1, lan + 1)], hosts=3),
    ]
    devices += [_dev(f"{p}-ACC{i}", "C9200-48P", [f"{p}-DIST1"], hosts=3) for i in range(1, lan + 1)]
    devices += [_dev(t, "C9300-24T", [f"{p}-AGG1", f"{p}-AGG2"], hosts=2) for t in tor_names]
    graph = build(devices)
    roles.classify(graph)
    return graph


def _keys(graph):
    return list(graph.nodes)


# ---- zone boxes on every kind of page -----------------------------------------------------------------------------------------------------------------

def test_every_physical_page_of_the_multi_site_demo_has_zone_boxes(built):
    pages = [p for p in built["pages"] if p.view == "physical" and p.name not in ("Overview", "Other devices")]
    assert len(pages) >= 7
    for page in pages:
        assert len(page.zones) >= 2, page.name


def test_the_overview_of_several_sites_has_the_zone_boxes_of_every_site_inside_its_site_box(built):
    overview = next(p for p in built["pages"] if p.name == "Overview")
    site_boxes = {name: (x, y, x + w, y + h) for name, x, y, w, h in overview.boxes}
    assert len(site_boxes) >= 3 and overview.zones
    titles_per_site = sum(len(p.zones) for p in built["pages"] if p.name in site_boxes)
    assert len(overview.zones) >= titles_per_site - len(site_boxes) * 2          # the pages of the sites also show the other site's ghost block: the overview does not
    for title, kind, x, y, w, h in overview.zones:
        assert any(bx0 - 1 <= x and by0 - 1 <= y and x + w <= bx1 + 1 and y + h <= by1 + 1 for bx0, by0, bx1, by1 in site_boxes.values()), (title, kind)


def test_zones_of_two_sites_on_the_overview_never_share_an_id():
    result = _built()
    overview = next(p for p in result["pages"] if p.name == "Overview")
    ids = {n.zone_id for n in overview.nodes.values() if n.zone_id}
    assert any("/" in i for i in ids)
    by_site: dict[str, set[str]] = {}
    for ident in ids:
        site = ident.split(":", 1)[1].split("/", 1)[0]
        by_site.setdefault(site, set()).add(ident)
    assert len(by_site) >= 3
    assert not set.intersection(*[{i.split("/", 1)[1] for i in v} for v in by_site.values()]) or len(by_site) > 1


def test_a_page_laid_out_without_zones_says_why_in_its_note_and_in_the_page_list():
    result = _built(zone_layout="off")
    assert all(not p.zones for p in result["pages"])
    page = next(p for p in result["pages"] if p.name == "HQ-DC")
    assert page.zone_note == "Zone layout is set to Off."
    row = next(r for r in result["svgs"] if r["name"].startswith("HQ-DC") and "L3" not in r["name"])
    assert row["zones"] == 0 and "Off" in row["zone_note"]


def test_a_page_that_is_not_a_physical_picture_says_where_the_boxes_are_drawn(built):
    rows = [r for r in built["svgs"] if r["zones"] == 0]
    logical = [r for r in rows if r["name"].startswith("L3 - Logical") or r["name"] == "IP view"]
    assert logical and all("L2 Physical View" in r["zone_note"] for r in logical)


def test_a_page_whose_zones_cost_far_more_crossings_keeps_the_compact_rows_and_says_so(monkeypatch):
    monkeypatch.setattr(scene, "ZONE_SLACK", -0.9)
    monkeypatch.setattr(scene, "ZONE_SLACK_ABS", -10_000)
    result = _built()
    page = next(p for p in result["pages"] if p.name == "HQ-DC")
    assert not page.zones
    assert "line crossings" in page.zone_note and "Always" in page.zone_note


def test_the_button_is_disabled_with_the_reason_when_a_page_has_no_boxes():
    from pathlib import Path
    js = (Path(service.__file__).resolve().parents[2] / "static" / "js" / "topology.js").read_text(encoding="utf-8")
    assert "button.disabled = !boxes" in js and 'data-role="zone-note"' in js and "zone_note" in js


# ---- the centre found from the cables -------------------------------------------------------------------------------------------------------------------

def _fake(edges: dict[str, list[str]]):
    nodes = {k: SimpleNamespace(hostname=k) for k in edges}
    near = {k: set(v) for k, v in edges.items()}
    return SimpleNamespace(nodes=nodes), near


def test_the_centre_of_a_page_without_a_named_core_is_the_device_most_paths_go_through():
    graph, near = _fake({"RT": ["MID"], "MID": ["RT", "A", "B", "C"], "A": ["MID"], "B": ["MID"], "C": ["MID"]})
    assert zones.virtual_centre(graph, set(near), near, set()) == frozenset({"MID"})


def test_a_leaf_is_never_the_centre_and_two_devices_alone_have_none():
    graph, near = _fake({"A": ["B"], "B": ["A"]})
    assert zones.virtual_centre(graph, set(near), near, set()) is None
    graph, near = _fake({"A": ["B"], "B": ["A"], "C": ["D"], "D": ["C"]})
    assert zones.virtual_centre(graph, set(near), near, set()) is None                # no path goes through anything
    graph, near = _fake({"A": ["B", "C"], "B": ["A"], "C": ["A"]})
    assert zones.virtual_centre(graph, set(near), near, set()) is None                # fewer than four devices


def test_the_centre_takes_its_vpc_peer_with_it():
    edges = {"X1": ["X2", "R", "A", "B"], "X2": ["X1", "R", "A", "B"], "R": ["X1", "X2"], "A": ["X1", "X2"], "B": ["X1", "X2"]}
    graph, near = _fake(edges)
    assert zones.virtual_centre(graph, set(near), near, {frozenset(("X1", "X2"))}) == frozenset({"X1", "X2"})


def test_a_network_with_no_centre_from_the_hierarchy_still_gets_zones_round_a_central_device():
    graph = _farm("YY", tors=3, single_core=True)
    graph.centres = []                                                            # as if infer_hierarchy had found none
    why: list[str] = []
    found = zones.plan(graph, _keys(graph), why=why)
    assert found is not None, why
    assert found.centre and found.centre <= set(graph.nodes)                      # the device most paths go through (here the distribution switch with its access switches)
    assert len([z for z in found.zones if z.kind not in ("management", "ghost")]) >= 2


def test_a_page_with_nothing_in_the_middle_gives_a_reason_not_just_none():
    graph, _ = _fake({"A": []})
    graph.centres = []
    graph.vpc_pairs = []
    graph.connections = []
    graph.hidden_kinds = set()
    graph.nodes["A"].role_hint = "switch"
    why: list[str] = []
    assert zones.plan(graph, ["A"], why=why) is None
    assert why and "core" in why[0]


# ---- blocks: heads together, a large tall block cut in two, tall blocks beside the core -----------------------------------------------------------------------

def test_the_units_of_a_head_pair_stand_side_by_side_in_the_middle_of_the_switches_below():
    graph = _farm("ZZ", tors=8)
    placed, _, _ = layout.layered(graph, _keys(graph), zoned=True)
    one, two = placed["ZZ-AGG1"], placed["ZZ-AGG2"]
    assert one.y == two.y
    assert abs(one.x - two.x) <= zonelayout.HEAD_GAP + 1
    tors = [placed[f"ZZ-TOR{i}"].x for i in range(1, 9)]
    assert min(tors) < min(one.x, two.x) and max(one.x, two.x) < max(tors)


def test_the_head_pair_is_not_packed_without_the_rule(monkeypatch):
    monkeypatch.setattr(zonelayout, "_pack_heads", lambda *args: None)
    graph = _farm("ZZ", tors=8)
    placed, _, _ = layout.layered(graph, _keys(graph), zoned=True)
    assert abs(placed["ZZ-AGG1"].x - placed["ZZ-AGG2"].x) > zonelayout.HEAD_GAP + 1


def _big_tall():
    """A core pair with a campus block (a distribution switch, ten access switches) and a firewall pair under it; behind the firewalls: three extranet routers and a large DMZ of twenty-two switches (one block with its own way out)."""
    dmz = [f"YY-SW{i}" for i in range(1, 23)]
    acc = [f"YY-ACC{i}" for i in range(1, 11)]
    fw = ["YY-FWD1", "YY-FWD2"]
    devices = [
        _dev("YY-CORE1", "N9K-C93180YC-FX3", ["YY-CORE2", "YY-DIST1"] + fw),
        _dev("YY-CORE2", "N9K-C93180YC-FX3", ["YY-CORE1", "YY-DIST1"] + fw),
        _dev("YY-DIST1", "C9300-48P", ["YY-CORE1", "YY-CORE2"] + acc),
        _dev("YY-FWD1", "FortiGate-600F", ["YY-CORE1", "YY-CORE2", "YY-FWD2", "YY-XRT1", "YY-XRT2", "YY-XRT3"] + dmz, role="firewall"),
        _dev("YY-FWD2", "FortiGate-600F", ["YY-CORE1", "YY-CORE2", "YY-FWD1", "YY-XRT1", "YY-XRT2", "YY-XRT3"] + dmz, role="firewall"),
    ]
    devices += [_dev(a, "C9200-48P", ["YY-DIST1"], hosts=3) for a in acc]
    devices += [_dev(f"YY-XRT{i}", "ISR4331/K9", fw, role="router") for i in (1, 2, 3)]
    devices += [_dev(n, "C9300-24T", fw, hosts=1) for n in dmz]
    graph = build(devices)
    roles.classify(graph)
    return graph


def test_a_server_farm_with_the_extranet_routers_behind_its_own_firewall_is_cut_in_a_way_out_and_an_inside():
    graph = _big_tall()
    found = zones.plan(graph, _keys(graph))
    assert found is not None
    kinds = sorted(z.kind for z in found.zones)
    assert "tall" not in kinds and kinds.count("external") >= 1 and kinds.count("internal") >= 1
    outer = next(z for z in found.zones if z.kind == "external")
    assert {graph.nodes[k].hostname for k in outer.members} >= {"YY-XRT1", "YY-XRT2", "YY-XRT3"}


def test_without_the_cut_the_large_block_is_one_tall_zone_that_is_no_picture_of_zones(monkeypatch):
    graph = _big_tall()
    cut = zones.plan(graph, _keys(graph))
    assert cut is not None and max(len(z.members) for z in cut.zones) < 0.65 * sum(len(z.members) for z in cut.zones)
    monkeypatch.setattr(zones, "TALL_MIN_SPLIT", 10_000)
    monkeypatch.setattr(zones, "split_big", lambda graph, zs, near, ghosts: zs)      # v2.5 cuts such a block a second way (``split_big``): the routers of a way-out block; both cuts off here
    why: list[str] = []
    assert zones.plan(graph, _keys(graph), why=why) is None and why                  # one block with nearly everything: the page keeps its rows, and says why


# ---- two centres on one diagram -------------------------------------------------------------------------------------------------------------------------

def test_two_centres_on_one_page_are_two_zone_pictures_side_by_side():
    a = _farm_devices("AA", 4)
    b = _farm_devices("BB", 4)
    graph = build(a + b)
    roles.classify(graph)
    assert len(getattr(graph, "centres", [])) == 2
    placed, width, height = layout.layered(graph, _keys(graph), zoned=True)
    ids = {n.zone_id.split(":", 1)[1].split("/", 1)[0] for n in placed.values() if n.zone_id}
    assert ids == {"c0", "c1"}
    left = [p.x for k, p in placed.items() if k.startswith("AA-") or k.startswith("BB-")]
    xs_a = [p.x for k, p in placed.items() if k.startswith("AA-") and not k.startswith("HOST")]
    xs_b = [p.x for k, p in placed.items() if k.startswith("BB-") and not k.startswith("HOST")]
    assert max(xs_a) < min(xs_b) or max(xs_b) < min(xs_a)                            # one page left of the other
    assert width > 0 and height > 0 and left


def _farm_devices(prefix: str, tors: int):
    p = prefix
    tor_names = [f"{p}-TOR{i}" for i in range(1, tors + 1)]
    core = [f"{p}-CORE1", f"{p}-CORE2"]
    devices = [_dev(c, "N9K-C93180YC-FX3", [x for x in core if x != c] + [f"{p}-AGG1", f"{p}-AGG2", f"{p}-RT1", f"{p}-RT2", f"{p}-DIST1"]) for c in core]
    devices += [
        _dev(f"{p}-AGG1", "C9500-24Y4C", core + [f"{p}-AGG2"] + tor_names),
        _dev(f"{p}-AGG2", "C9500-24Y4C", core + [f"{p}-AGG1"] + tor_names),
        _dev(f"{p}-RT1", "ASR1002-X", core + [f"{p}-RT2"], role="router", function="wan"),
        _dev(f"{p}-RT2", "ASR1002-X", core + [f"{p}-RT1"], role="router", function="wan"),
        _dev(f"{p}-DIST1", "C9300-48P", core + [f"{p}-ACC{i}" for i in range(1, 7)], hosts=3),
    ]
    devices += [_dev(f"{p}-ACC{i}", "C9200-48P", [f"{p}-DIST1"], hosts=3) for i in range(1, 7)]
    devices += [_dev(t, "C9300-24T", [f"{p}-AGG1", f"{p}-AGG2"], hosts=2) for t in tor_names]
    return devices


def test_two_centres_without_the_rule_fall_back_to_one_picture_round_one_virtual_centre(monkeypatch):
    monkeypatch.setattr(zonelayout, "centres_on", lambda graph, members: [])
    a = _farm_devices("AA", 4)
    b = _farm_devices("BB", 4)
    graph = build(a + b)
    roles.classify(graph)
    placed, _, _ = layout.layered(graph, _keys(graph), zoned=True)
    ids = {n.zone_id for n in placed.values() if n.zone_id}
    assert ids and not any(":c0/" in i or ":c1/" in i for i in ids)


# ---- the core gets its own box when no frame is drawn round it ------------------------------------------------------------------------------------------

def test_a_single_core_gets_a_core_zone_box():
    graph = _farm("ZZ", tors=4, single_core=True)
    placed, width, height = layout.layered(graph, _keys(graph), zoned=True)
    page = scene.Page("trial", placed)
    page.connections = scene._connections_for(graph, set(placed))
    boxes = scene.zone_boxes(graph, page)
    assert "core" in {kind for _, kind, *_ in boxes}


def test_a_pair_of_cores_with_its_frame_gets_no_second_box(built):
    page = next(p for p in built["pages"] if p.name == "HQ-DC" and p.view == "physical")
    assert page.centers and "core" not in {kind for _, kind, *_ in page.zones}


# ---- a reader that can be stopped -------------------------------------------------------------------------------------------------------------------------

def test_a_function_that_runs_too_long_is_stopped_and_the_next_call_works():
    with isolate.Isolated() as helper:
        started = time.monotonic()
        kind, _ = helper.call(time.sleep, (60,), 1.5)
        assert kind == isolate.TIMEOUT and time.monotonic() - started < 20
        assert helper.call(len, ("abc",), 60) == (isolate.OK, 3)


def test_a_function_that_raises_is_reported_not_fatal():
    with isolate.Isolated() as helper:
        kind, text = helper.call(int, ("x",), 60)
        assert kind == "error" and "ValueError" in text


def test_a_large_capture_read_by_the_helper_is_the_same_device_as_one_read_here(monkeypatch):
    name, text = _captures()[3]
    here = service._read_one(name, text)
    monkeypatch.setattr(service, "ISOLATE_MIN_CHARS", 0)
    got, cacheable, helper = service._read_one_guarded(name, text, None, 120)
    try:
        assert cacheable and got[1] == here[1]
        assert got[0].hostname == here[0].hostname and len(got[0].halves) == len(here[0].halves)
    finally:
        helper.__exit__()


def test_a_capture_that_never_ends_is_skipped_with_the_reason_and_the_others_are_read(monkeypatch):
    files = _captures()[:3]
    real = service._read_one
    monkeypatch.setattr(service, "ISOLATE_MIN_CHARS", 0)
    monkeypatch.setattr(service, "READ_CAPTURE_SECONDS", 1)
    calls = {"n": 0}

    class Fake:
        def call(self, func, args, limit):
            calls["n"] += 1
            if calls["n"] == 2:
                return isolate.TIMEOUT, limit
            return isolate.OK, real(*args)

        def __exit__(self, *a):
            return None

    monkeypatch.setattr(isolate, "Isolated", Fake)
    service._CACHE.clear()
    devices, skipped = service.read_devices(files)
    assert len(devices) == 2 and len(skipped) == 1
    assert "took longer than 1 seconds" in skipped[0]["reason"] and skipped[0]["file"] == files[1][0]
    service._CACHE.clear()
    devices_again, skipped_again = service.read_devices(files[1:2])
    assert len(devices_again) == 1 and not skipped_again                 # the skipped capture was not cached as a failure


def test_a_small_capture_is_read_in_the_run_itself():
    name, text = _captures()[0]
    got, cacheable, helper = service._read_one_guarded(name, text, None, 120)
    assert helper is None and cacheable and got[0] is not None


# ---- cables of one bundle keep their own track ------------------------------------------------------------------------------------------------------------

def _bundle(count: int = 10) -> list[float]:
    """Ten cables between two devices of one row with a third device standing between them: every cable has to bend round it.  Returns the sideways position of each cable's bend."""
    from features.topology.graph import Connection, Link
    from features.topology.layout import Placed
    page = scene.Page("T", {"A": Placed(0, 0, 0.0, ""), "B": Placed(1500, 0, 0.0, ""), "M": Placed(740, 0, 0.0, "")})
    page.connections = [Connection("A", "B", [Link("A", f"Gi{i}", "B", "Gi0", "confirmed", {"CDP"}, "")]) for i in range(count)]
    scene._route(page)
    return sorted(round(route[0][1], 1) for route in page.routes.values() if route)


def test_the_cables_of_a_bundle_that_bend_round_a_device_keep_their_own_track():
    tracks = _bundle()
    assert len(tracks) == 10
    assert min(b - a for a, b in zip(tracks, tracks[1:])) >= 14.0


def test_the_cables_of_a_bundle_lie_on_one_another_without_the_rule(monkeypatch):
    monkeypatch.setattr(scene, "SIBLING_APART", 0.0)
    tracks = _bundle()
    assert min(b - a for a, b in zip(tracks, tracks[1:])) < 4              # a lift of 70 px next to a spread of 34 px: two cables 2 px apart (12,999 px of overlay on a real DRC page)


def test_the_limits_of_the_isolated_reader_are_set():
    assert service.ISOLATE_MIN_CHARS == 400_000 and 60 <= service.READ_CAPTURE_SECONDS <= 600
