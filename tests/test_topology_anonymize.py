"""Anonymized copy of a topology (Topology Builder 1.6): names, addresses, MACs and serials replaced, the picture and the tables unchanged.
Synthetic estate only (tests/topology_anon_samples.py); the structural checks on real captures were run locally and are not part of the repository."""

from __future__ import annotations

import io
import ipaddress
import random
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from topology_anon_samples import MACS, SECRET_WORDS, SERIALS, estate  # noqa: E402

from features.topology.anonymize import Anonymizer, anonymize, find_leftovers, own_words  # noqa: E402
from features.topology.extract import Device  # noqa: E402
from features.topology.service import build_topology  # noqa: E402


def _devices():
    return build_topology(list(estate().items()), group="none")["devices"]


def _fresh(salt: bytes = b"unit") -> Anonymizer:
    return Anonymizer(salt)


# ---------------------------------------------------------------------------------------------------------------- addresses
def test_addresses_keep_their_prefixes_and_stay_in_their_range():
    a = _fresh()
    rng = random.Random(7)
    seen: dict[str, str] = {}
    for _ in range(3000):
        ip = f"{rng.choice([10, 172, 192, 100, 8, 45, 123, 203])}.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        out = a.ipv4(ip)
        seen[ip] = out
        assert out.split(".")[3] == ip.split(".")[3], "the host octet stays, so .1 is still .1 and /30 peers stay peers"
        before, after = ipaddress.ip_address(ip), ipaddress.ip_address(out)
        assert before.is_private == after.is_private, (ip, out)
        assert before.is_global == after.is_global, (ip, out)
        assert before.is_loopback == after.is_loopback and before.is_multicast == after.is_multicast
    assert any(k != v for k, v in seen.items())
    by_24 = {}
    for ip, out in seen.items():
        by_24.setdefault(ip.rsplit(".", 1)[0], set()).add(out.rsplit(".", 1)[0])
    assert all(len(v) == 1 for v in by_24.values()), "one /24 stays one /24"
    reverse = {}
    for ip24, outs in by_24.items():
        reverse.setdefault(next(iter(outs)), set()).add(ip24)
    assert all(len(v) == 1 for v in reverse.values()), "two /24s never merge"
    # shorter prefixes: addresses that share a /16 or /12 still share it
    two = [a.ipv4("10.20.30.5"), a.ipv4("10.20.99.6")]
    assert two[0].split(".")[:2] == two[1].split(".")[:2]
    assert ipaddress.ip_address(a.ipv4("172.20.5.1")) in ipaddress.ip_network("172.16.0.0/12")
    assert a.ipv4("192.168.7.9").startswith("192.168.")


def test_peers_of_a_point_to_point_link_stay_peers():
    a = _fresh()
    one, two = a.ipv4("203.0.113.9"), a.ipv4("203.0.113.10")
    network = ipaddress.ip_network(one + "/30", strict=False)
    assert ipaddress.ip_address(two) in network and one.rsplit(".", 1)[0] == two.rsplit(".", 1)[0]
    assert {int(one.split(".")[3]), int(two.split(".")[3])} == {9, 10}


def test_masks_wildcards_special_addresses_and_networks():
    a = _fresh()
    for same in ("255.255.255.0", "255.255.255.252", "255.255.255.255", "0.0.0.0", "0.0.0.255", "0.0.3.255", "127.0.0.1", "224.0.0.5", "239.1.1.1", "255.255.0.0"):
        assert a.text(same) == same, same
    assert a.text("ip address 10.1.2.3 255.255.255.0") != "ip address 10.1.2.3 255.255.255.0"
    assert a.text("ip address 10.1.2.3 255.255.255.0").endswith(" 255.255.255.0")
    net = a.text("10.1.0.0/16 and 10.1.2.0/24 and 10.1.2.5/24")
    first, second, third = re.findall(r"[\d.]+/\d+", net)
    assert ipaddress.ip_network(first)                          # strict parse: no host bits set in a network
    assert ipaddress.ip_network(second)
    assert ipaddress.ip_network(second).subnet_of(ipaddress.ip_network(first))
    assert ipaddress.ip_interface(third).network == ipaddress.ip_network(second), "a host with a length stays in its network"
    assert a.text("0.0.0.0/0") == "0.0.0.0/0" and a.text("10.1.2.3/32").endswith("/32")


def test_version_numbers_are_not_addresses_and_dashed_names_follow_the_dotted_address():
    a = _fresh()
    dev = Device(key="X", hostname="SBY-KANTOR-CORE-1", os_version="9.1.12.3", model="N9K-C93180YC-FX3")
    dev.mgmt_ip = "10.77.0.11"
    dev.l3facts = {"release": "IOS-XE 17.9.4.1", "interfaces": [{"name": "Loopback0", "ip": "10.77.0.11", "prefix_len": 32}]}
    out = anonymize([dev], salt=b"v").devices[0]
    assert out.os_version == "9.1.12.3" and out.model == "N9K-C93180YC-FX3" and out.l3facts["release"] == "IOS-XE 17.9.4.1"
    assert out.mgmt_ip != "10.77.0.11" and out.l3facts["interfaces"][0]["ip"] == out.mgmt_ip
    dotted = a.ipv4("172.17.171.2")
    assert a.text("172-17-171-2") == dotted.replace(".", "-")
    assert a.text("ip-10-1-2-3-node").startswith("ip-")


def test_ipv6_is_prefix_preserving_and_keeps_the_special_ranges():
    a = _fresh()
    one, two = a.text("2a02:1234:10:1::5"), a.text("2a02:1234:10:1::6")
    assert one != "2a02:1234:10:1::5" and ipaddress.ip_address(one).is_global and ipaddress.ip_address("2a02:1234:10:1::5").is_global
    assert one.rsplit(":", 1)[0] == two.rsplit(":", 1)[0] and one.endswith("5") and two.endswith("6")
    for same in ("::1", "::", "ff02::5", "12:34:56"):
        assert a.text(same) == same
    assert a.text("fe80::1") != "fe80::1" and a.text("fe80::1").startswith("fe80:")
    assert ipaddress.ip_network(a.text("2a02:1234:10::/48"))


def test_a_different_key_gives_other_addresses_the_same_key_gives_the_same():
    assert _fresh(b"one").ipv4("10.77.0.11") == _fresh(b"one").ipv4("10.77.0.11")
    assert _fresh(b"one").ipv4("10.77.0.11") != _fresh(b"two").ipv4("10.77.0.11")


# ---------------------------------------------------------------------------------------------------------------- MAC, serial, words
def test_mac_keeps_the_vendor_prefix_and_the_format():
    a = _fresh()
    dotted, colon, hyphen, bare = a.text("0050.5611.2233"), a.text("00:50:56:11:22:33"), a.text("00-50-56-11-22-33"), a.text("005056112233")
    assert dotted.startswith("0050.56") and colon.startswith("00:50:56:") and hyphen.startswith("00-50-56-") and bare.startswith("005056")
    assert dotted != "0050.5611.2233"
    huawei = a.text("0050-5611-2233")
    assert huawei.startswith("0050-56") and huawei != "0050-5611-2233" and huawei.replace("-", "") == bare, "Huawei notation is a MAC too"
    assert a.text("10-1-2-3 and 00-50-56-11-22-33").split(" and ")[1] == hyphen, "six decimal-looking groups are a MAC, not a dashed address"
    assert dotted.replace(".", "") == colon.replace(":", "") == hyphen.replace("-", "") == bare, "one MAC, one pseudonym, whatever the notation"
    assert a.text("00AA.BB11.2233") == a.text("00aa.bb11.2233").upper()
    for same in ("ffff.ffff.ffff", "0100.5e00.0005", "0180.c200.0000", "0000.0c07.ac0a", "0000.5e00.0101", "0000.0000.0000"):
        assert a.text(same) == same, same


def test_serial_numbers_keep_length_and_pattern_and_are_replaced_everywhere():
    dev = Device(key="X", hostname="A-B-C", serials={"FOC2322WXYZ"})
    dev.descriptions = {"Gi1/0/1": "spare from FOC2322WXYZ rack"}
    out = anonymize([dev], salt=b"s").devices[0]
    (new,) = out.serials
    assert new != "FOC2322WXYZ" and len(new) == 11 and re.fullmatch(r"[A-Z]{3}\d{4}[A-Z]{4}", new)
    assert new in out.descriptions["Gi1/0/1"] and "FOC2322WXYZ" not in out.descriptions["Gi1/0/1"]
    short = Device(key="Y", hostname="D-E-F", serials={"NA", "stack"})
    assert anonymize([short], salt=b"s").devices[0].serials == {"NA", "stack"}      # too short or without a digit to be a serial: ordinary words stay


def test_words_keep_length_digit_pattern_case_and_order_of_roles():
    result = anonymize(_devices(), title="Bank Kantor Mawar", salt=b"w")
    names = {d.hostname for d in result.devices}
    assert all(re.fullmatch(r"[A-Z]{3}-[A-Z]{6}-(CORE-1|LAN-SW-2)", n) for n in names) and len(names) == 2
    for row in result.mapping:
        if row["kind"] == "word":
            assert len(row["original"]) == len(row["replacement"])
            assert [c.isdigit() for c in row["original"]] == [c.isdigit() for c in row["replacement"]]
            assert row["replacement"].upper() == row["replacement"] and row["replacement"] != row["original"].upper()
    originals = {r["original"] for r in result.mapping if r["kind"] == "word"}
    assert {"sby", "kantor", "akunting", "lantai", "telkomxyz", "gudang", "mawar"} <= originals
    assert not originals & {"core", "lan", "sw", "uplink"}
    # the same word gives the same pseudonym in the hostname, the description and the title
    mapping = {r["original"]: r["replacement"] for r in result.mapping if r["kind"] == "word"}
    core = next(d for d in result.devices if d.hostname.endswith("CORE-1"))
    assert mapping["sby"] in core.hostname and mapping["kantor"] in core.hostname
    descriptions = " ".join(v.lower() for d in result.devices for v in d.descriptions.values())
    assert mapping["akunting"].lower() in descriptions and "akunting" not in descriptions, "the same word gets the same pseudonym in a description"
    assert result.title.split()[0].lower() != "bank" and len(result.title.split()) == 3


def test_a_pseudonym_is_never_a_role_word_or_a_word_of_the_data():
    words = " ".join(f"{a}{b}" for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[:3])
    dev = Device(key="X", hostname="ZZ-" + "-".join(w.lower() for w in words.split()[:60]))
    result = anonymize([dev], salt=b"r")
    pseudonyms = {r["replacement"].lower() for r in result.mapping if r["kind"] == "word"}
    assert not pseudonyms & {"ap", "fw", "sw", "lb", "ce", "pe", "rt", "cr", "ds", "as", "fi", "wc"}


def test_program_words_survive_so_descriptions_still_work_for_the_neighbor_inference():
    a = _fresh()
    a._collect("Link to Lintasarta MPLS uplink spare printer", free=True)
    a._number_words()
    text = a.text("Link to Lintasarta MPLS uplink spare printer", free=True)
    assert text == "Link to Lintasarta MPLS uplink spare printer"


# ---------------------------------------------------------------------------------------------------------------- the whole build
def _signature(result):
    graph = result["graph"]
    return (dict(result["summary"]), sorted(f["id"] for f in result["findings"]), len(result["svgs"]), len(result["l3_links"]), len(result["l3_routes"]),
            len(graph.nodes), len(graph.links), len(graph.connections), sorted(n.role_hint for n in graph.nodes.values()),
            sorted((link.state, sorted(link.protocols)) for link in graph.links), [p["view"] for p in result["svgs"]])


def test_the_twin_has_the_same_structure_as_the_original():
    devices = _devices()
    original = build_topology([], devices=[d for d in _devices()], group="none")
    for d in original["devices"]:
        d.carried = False
    anon = anonymize(devices, title="Bank Kantor Mawar", salt=b"t")
    twin = build_topology([], devices=anon.devices, group="none", name=anon.title)
    assert _signature(original) == _signature(twin)
    roles = {n.hostname: n.role_hint for n in twin["graph"].nodes.values()}
    assert sorted(roles.values()) == sorted(n.role_hint for n in original["graph"].nodes.values())
    assert any(link.state == "single" for link in twin["graph"].links) == any(link.state == "single" for link in original["graph"].links)


def test_no_original_name_address_serial_or_mac_is_left_in_the_twin():
    anon = anonymize(_devices(), title="Bank Kantor Mawar", salt=b"t")
    twin = build_topology([], devices=anon.devices, group="none", name=anon.title)
    blob = " ".join([p["svg"] for p in twin["svgs"]] + [twin["drawio"]]).lower()
    for word in SECRET_WORDS + tuple(s.lower() for s in SERIALS) + tuple(m.replace(".", "") for m in MACS) + ("10.77.", "203.0.113", "bank"):
        assert word not in blob, word
    assert find_leftovers(anon, {"svg": blob}) == []
    # the program's own words are not flagged
    assert "example" in own_words() and "report" in own_words()


def test_leftover_scan_finds_what_a_run_missed_and_ignores_derived_addresses():
    anon = anonymize(_devices(), title="Bank Kantor Mawar", salt=b"t")
    texts = {"a.svg": "<text>SBY-KANTOR-CORE-1</text>", "b.csv": f"serial,{SERIALS[0]}\r\nmac,{MACS[0]}", "c.json": "no secrets here"}
    found = {(item["kind"], item["file"]) for item in find_leftovers(anon, texts)}
    assert ("word", "a.svg") in found and ("serial", "b.csv") in found and ("mac", "b.csv") in found
    original_ip = next(r["original"] for r in anon.mapping if r["kind"] == "address")
    assert find_leftovers(anon, {"x": f"subnet {original_ip}/30"}) == []                  # a computed network may equal an original address
    leaky = anon.state_text + f' "{original_ip}"'
    anon.state_text = leaky
    assert any(item["kind"] == "address" and item["value"] == original_ip for item in find_leftovers(anon, {}))


def test_a_value_that_is_also_a_pseudonym_is_not_reported():
    a = _fresh(b"p")
    first = a.ipv4("10.1.1.1")
    original = first                    # the pseudonym of 10.1.1.1 is, by construction, written by the program ...
    a.ips[original] = a.ipv4("10.2.2.2")           # ... and the same string as the *original* of another address
    sensitive = a._sensitive()
    assert original not in sensitive["address"]


# ---------------------------------------------------------------------------------------------------------------- through the page
def _client():
    from app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _post(client, **fields):
    files = [(io.BytesIO(text.encode()), name) for name, text in estate().items()]
    return client.post("/topology/api/build", data={"files": files, "group": "none", **fields}, content_type="multipart/form-data")


def _all_text(archive: zipfile.ZipFile) -> dict[str, str]:
    out = {}
    for name in archive.namelist():
        data = archive.read(name)
        if name.endswith(".xlsx"):
            book = zipfile.ZipFile(io.BytesIO(data))
            data = b" ".join(book.read(member) for member in book.namelist())
        out[name] = data.decode("utf-8", "replace")
    return out


def test_without_the_option_nothing_is_made():
    body = _post(_client(), name="Bank Kantor Mawar").get_json()
    assert body["ok"] and body["anonymized"] is None
    assert not {"keystone-topology-pack-anonymized.zip", "anonymization-map.csv"} & {d["name"] for d in body["downloads"]}


def test_the_option_makes_a_second_pack_and_a_key_file_and_leaves_the_first_untouched():
    client = _client()
    body = _post(client, anonymize="1", name="Bank Kantor Mawar", provider_hints="SBY-KANTOR-CORE-1 Eth1/20 = internet TelkomXYZ").get_json()
    assert body["ok"] and body["anonymized"]["leftovers"] == [] and body["anonymized"]["replaced"] > 10
    downloads = {d["name"]: d for d in body["downloads"]}
    assert downloads["keystone-topology-pack-anonymized.zip"]["filename"] == "keystone-topology-pack-anonymized.zip", "the topology name is not in the file name"
    assert downloads["anonymization-map.csv"]["filename"].startswith("Bank-Kantor-Mawar-")
    assert [d["name"] for d in body["downloads"]][0] == "keystone-topology-pack.zip"
    original = _all_text(zipfile.ZipFile(io.BytesIO(client.get(downloads["keystone-topology-pack.zip"]["url"]).data)))
    assert any("sby-kantor" in t.lower() for t in original.values()), "the normal pack keeps the real names"
    safe = zipfile.ZipFile(io.BytesIO(client.get(downloads["keystone-topology-pack-anonymized.zip"]["url"]).data))
    texts = _all_text(safe)
    names = set(texts)
    assert {"keystone-topology-pack/README.txt", "keystone-topology-pack/topology-report.html", "keystone-topology-pack/topology.xlsx", "keystone-topology-pack/topology.json",
            "keystone-topology-pack/tables/links.csv", "keystone-topology-pack/topology.drawio"} <= names
    assert texts["keystone-topology-pack/README.txt"].startswith("Keystone Topology Builder - ANONYMIZED")
    blob = " ".join(texts.values()).lower()
    for word in SECRET_WORDS + tuple(s.lower() for s in SERIALS) + tuple(m.replace(".", "") for m in MACS) + ("10.77.", "203.0.113", "bank", "mawar"):
        assert word not in blob, word
    key = client.get(downloads["anonymization-map.csv"]["url"]).data.decode("utf-8-sig")
    assert key.splitlines()[0] == "kind,original,replacement" and "word,sby," in key and f"serial,{SERIALS[0]}," in key and "address,10.77.0.11," in key and "LEFTOVER" not in key
    assert "sby" not in texts["keystone-topology-pack/run-settings.txt"].lower() and "Topology name" in texts["keystone-topology-pack/run-settings.txt"]


def test_the_anonymized_pack_has_the_same_numbers_as_the_normal_pack():
    client = _client()
    body = _post(client, anonymize="1").get_json()
    urls = {d["name"]: d["url"] for d in body["downloads"]}
    real = zipfile.ZipFile(io.BytesIO(client.get(urls["keystone-topology-pack.zip"]).data))
    safe = zipfile.ZipFile(io.BytesIO(client.get(urls["keystone-topology-pack-anonymized.zip"]).data))
    for table in ("links", "devices", "bundles", "findings", "l3-links", "l3-routes"):
        path = f"keystone-topology-pack/tables/{table}.csv"
        if path not in real.namelist():
            assert path not in safe.namelist()
            continue
        assert len(real.read(path).splitlines()) == len(safe.read(path).splitlines()), table
    real_svgs = [n for n in real.namelist() if n.endswith(".svg")]
    safe_svgs = [n for n in safe.namelist() if n.endswith(".svg")]
    assert len(real_svgs) == len(safe_svgs)


def test_the_anonymized_topology_json_can_be_added_to_in_a_later_run():
    client = _client()
    body = _post(client, anonymize="1").get_json()
    urls = {d["name"]: d["url"] for d in body["downloads"]}
    safe = zipfile.ZipFile(io.BytesIO(client.get(urls["keystone-topology-pack-anonymized.zip"]).data))
    saved = safe.read("keystone-topology-pack/topology.json")
    again = client.post("/topology/api/build", data={"group": "none", "previous_state": (io.BytesIO(saved), "topology.json")}, content_type="multipart/form-data").get_json()
    assert again["ok"] and again["summary"]["captured"] == 2
    assert not any(word in str(again["devices"]).lower() for word in SECRET_WORDS)
