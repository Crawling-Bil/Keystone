"""Load Balancer Analyzer (F5 BIG-IP) tests.

Fixture provenance: every file under tests/fixtures/loadbalancer is SYNTHETIC -
hand-written from the TMSH stanza syntax that F5 documents, with documentation
addresses (10/8, 160.19.5.0/24 stands in for "public") and made-up secrets.
No real BIG-IP capture has been available yet.  When one is, add its masked copy
next to these and a regression test like test_real_captures_*.
"""

from __future__ import annotations

import io
import json
import os
import unittest
from datetime import date
from pathlib import Path

import pytest

from features.analyzer_core.result import section_by_id, validate_result
from features.lb_analyzer import bigip_extract, bigip_rules, bigip_runtime, service
from features.lb_analyzer.bigip_resolve import Resolver
from features.lb_analyzer.netutil import is_public_ip, parse_destination
from features.lb_analyzer.refs import F5
from features.lb_analyzer.tmsh_tree import parse_tmsh

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "loadbalancer"
TODAY = date(2026, 10, 9)
SECRETS = ("notarealencryptedvalue", "thisIsNotARealHashButLooksLikeOne", "anotherFakeHashValue", "secretforthemonitor", "Sup3rSecretRW", "syntheticvalue", "hashvalue")


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _ids(result: dict) -> set[str]:
    return {f["id"] for f in result["findings"]}


def _by_id(result: dict, rule_id: str) -> list[dict]:
    return [f for f in result["findings"] if f["id"] == rule_id]


def _objects(result: dict, rule_id: str) -> set[str]:
    return {f["object"] for f in _by_id(result, rule_id)}


@pytest.fixture(scope="module")
def weak():
    return service.analyze(_read("bigip_synthetic_weak.conf"), "lb.conf", today=TODAY)


@pytest.fixture(scope="module")
def hardened():
    return service.analyze(_read("bigip_synthetic_hardened.conf"), "lb-h.conf", today=TODAY)


@pytest.fixture(scope="module")
def capture():
    return service.analyze(_read("bigip_capture_synthetic.txt"), "lb-cap.txt", today=TODAY)


@pytest.fixture(scope="module")
def weak_data():
    tree = parse_tmsh(_read("bigip_synthetic_weak.conf"))
    return tree, bigip_extract.extract(tree)


def _snippet(text: str, **kw) -> dict:
    return service.analyze(text, "snippet.conf", today=TODAY, **kw)


VS_PUBLIC = """\
ltm virtual /Common/vs_pub {
    destination /Common/160.19.5.10:443
    ip-protocol tcp
    mask 255.255.255.255
    pool /Common/p1
    profiles {
        /Common/tcp { }
    }
    source 0.0.0.0/0
}
ltm pool /Common/p1 {
    members {
        /Common/10.0.0.1:80 {
            address 10.0.0.1
        }
    }
}
"""


# -------------------------------------------------------------------------- TMSH tree
def test_nested_blocks_inline_lists_and_quotes():
    tree = parse_tmsh(
        '#TMSH-VERSION: 15.1.8.2\n'
        'ltm pool /Common/p1 {\n    members {\n        /Common/10.0.0.1:80 {\n            address 10.0.0.1\n            ratio 3\n        }\n    }\n'
        '    monitor /Common/http and /Common/tcp\n    description "a { odd } name"\n}\n'
        'sys snmp {\n    allowed-addresses { 10.0.0.0/8 192.168.1.0/24 }\n}\n')
    assert tree.version == "15.1.8.2" and tree.warnings == []
    pool = tree.named("ltm", "pool")[0]
    assert pool.name == "/Common/p1"
    assert pool.val("monitor") == "/Common/http and /Common/tcp"
    assert pool.val("description") == "a { odd } name"                      # braces inside quotes do not open a block
    assert [c.key for c in pool.children] == ["members", "monitor", "description"]
    assert tree.single("sys", "snmp").child("allowed-addresses").names() == ["10.0.0.0/8", "192.168.1.0/24"]


def test_irule_body_is_kept_raw_and_braces_are_counted_like_tcl():
    tree = parse_tmsh(
        'ltm rule /Common/r1 {\n    when HTTP_REQUEST {\n        log local0. "x \\{"\n        if {[HTTP::uri] eq "/"} { pool p1 }\n    }\n}\n'
        'ltm pool /Common/p1 {\n}\n')
    rule = tree.named("ltm", "rule")[0]
    assert 'if {[HTTP::uri] eq "/"} { pool p1 }' in rule.raw
    assert tree.named("ltm", "pool")[0].name == "/Common/p1"               # the escaped brace did not swallow the next stanza


def test_secrets_are_replaced_while_parsing():
    tree = parse_tmsh(
        'auth user admin {\n    encrypted-password $6$abc$def\n    shell bash\n}\n'
        'sys snmp {\n    communities {\n        c1 {\n            community-name public\n            community-name Sup3rSecretRW\n        }\n    }\n}\n')
    user = tree.named("auth", "user")[0]
    assert user.val("encrypted-password") == "<hidden>" and user.val("shell") == "bash"
    assert any(n.guess for n in tree.single("sys", "snmp").walk())          # 'public' is flagged as guessable, not stored


def test_the_same_object_listed_twice_keeps_the_fuller_listing():
    tree = parse_tmsh(
        'ltm profile http /Common/h1 {\n    defaults-from /Common/http\n}\n'
        'ltm profile http /Common/h1 {\n    defaults-from /Common/http\n    insert-xforwarded-for enabled\n}\n')
    profiles = tree.named("ltm", "profile", "http")
    assert len(profiles) == 1 and profiles[0].val("insert-xforwarded-for") == "enabled"


def test_netutil():
    assert parse_destination("/Common/10.1.1.1:443") == ("10.1.1.1", 443, "")
    assert parse_destination("/Common/10.1.1.1%2:80") == ("10.1.1.1", 80, "2")   # route domain suffix is split off
    assert parse_destination("/Common/any:any") == ("any", 0, "")
    assert parse_destination("/Common/2001:db8::1.443") == ("2001:db8::1", 443, "")  # IPv6 uses a dot before the port
    assert is_public_ip("160.19.5.10") and not is_public_ip("10.1.1.1") and not is_public_ip("192.168.0.1")


# -------------------------------------------------------------------------- extraction
def test_virtual_servers_resolve_pool_profiles_and_destination(weak_data):
    _, data = weak_data
    vs = {v["short"]: v for v in data["virtuals"]}
    assert len(vs) == 13
    web = vs["vs_web_443"]
    assert web["destination"] == "160.19.5.10" and web["port"] == 443 and web["public"] is True
    assert web["pool"].endswith("pool_web")
    assert any(p["name"].endswith("clientssl_legacy") for p in web["profiles"])
    assert vs["vs_retired"]["enabled"] is False


def test_pool_members_carry_state_ratio_and_priority(weak_data):
    _, data = weak_data
    pool = next(p for p in data["pools"] if p["short"] == "pool_web")
    assert len(pool["members"]) == 3
    ratios = {m["address"]: m["ratio"] for m in pool["members"]}
    assert ratios["10.10.30.11"] == 3
    assert any(m["forced_down"] for m in pool["members"])


def test_system_objects_are_marked_and_unused_ones_ignore_them(weak_data):
    _, data = weak_data
    assert data["sys"]["has_base"] and data["sys"]["has_ltm"]
    assert next(c for c in data["certs"] if c["short"] == "default.crt")["system"]
    assert all(m["builtin"] for m in data["monitors"] if m["short"] in ("http", "tcp"))


def test_extractor_survives_an_empty_tree():
    data = bigip_extract.extract(parse_tmsh("ltm node /Common/10.0.0.1 {\n    address 10.0.0.1\n}\n"))
    assert data["virtuals"] == [] and data["pools"] == [] and len(data["nodes"]) == 1


# --------------------------------------------------------------------------- resolver
def test_inheritance_chain_and_effective_value(weak_data):
    tree, data = weak_data
    res = Resolver(data)
    chain, root = res.chain(res.profiles, "/Common/clientssl_legacy")
    assert [c["short"] for c in chain] == ["clientssl_legacy"] and root == "/Common/clientssl"      # ends at the built-in parent
    assert res.profile_attr("/Common/clientssl_legacy", "ciphers") == ("ALL:RC4:3DES:!aNULL", "explicit")
    value, origin = res.profile_attr("/Common/clientssl_inherit", "ciphers")
    assert value is None and origin == "builtin:clientssl"                                         # nothing stated: the documented default applies


def test_builtin_names_are_never_reported_as_dangling(weak_data):
    _, data = weak_data
    res = Resolver(data)
    assert res.is_builtin_profile("/Common/tcp") and res.is_builtin_monitor("/Common/http")
    assert not res.is_builtin_profile("/Common/my_custom_profile")
    dangling = [f["object"] for f in bigip_rules.evaluate(*weak_data, TODAY) if f["id"] == "LB-REF-001"]
    assert dangling and not any(name in obj for obj in dangling for name in ("tcp", "http", "clientssl"))


# ------------------------------------------------------------------------------ rules
def test_result_is_schema_valid_and_has_the_tabs(weak):
    assert validate_result(weak) == []
    assert weak["analyzer"] == "lb" and weak["vendor"] == "F5"
    assert weak["hostname"] == "lb-hq-01.corp.example.com"
    ids = [s["id"] for s in weak["sections"]]
    for needed in ("virtuals", "service_map", "pools", "members", "ssl_profiles", "certificates", "irules", "device_groups", "management_access", "snmp", "hardening"):
        assert needed in ids, needed
    assert len(ids) == len(set(ids))
    groups = {s["group"] for s in weak["sections"]}
    assert {"Virtual servers", "Pools & nodes", "System", "Hardening"} <= groups


@pytest.mark.parametrize("rule_id", [
    "LB-CRT-001", "LB-CRT-002", "LB-CRT-003", "LB-CRT-004", "LB-MGT-001", "LB-MGT-002", "LB-MGT-003", "LB-MGT-004", "LB-MGT-006", "LB-MGT-007", "LB-MGT-008",
    "LB-SNMP-001", "LB-SNMP-002", "LB-SNMP-003", "LB-SNMP-004", "LB-SSL-001", "LB-SSL-002", "LB-SSL-003", "LB-SSL-005", "LB-SSL-006", "LB-SSL-007",
    "LB-AUTH-001", "LB-AUTH-004", "LB-HTTP-001", "LB-HTTP-002", "LB-HTTP-003", "LB-HA-003", "LB-HA-004", "LB-HA-005", "LB-HA-006", "LB-HA-007",
    "LB-MON-001", "LB-MON-002", "LB-MON-004", "LB-POOL-001", "LB-POOL-002", "LB-POOL-003", "LB-POOL-004", "LB-POOL-005", "LB-POOL-006", "LB-POOL-007", "LB-POOL-008",
    "LB-VS-001", "LB-VS-003", "LB-VS-004", "LB-VS-005", "LB-VS-006", "LB-VS-007", "LB-VS-009", "LB-VS-010", "LB-VS-011", "LB-VS-013",
    "LB-IRL-001", "LB-IRL-002", "LB-NET-001", "LB-NET-002", "LB-REF-001", "LB-OBJ-001", "LB-OBJ-003", "LB-OBJ-004", "LB-OBJ-005", "LB-OBJ-006",
])
def test_weak_config_trips_rule(weak, rule_id):
    assert rule_id in _ids(weak), rule_id


def test_findings_name_the_right_objects(weak):
    assert _objects(weak, "LB-CRT-001") == {"old.example.com.crt"}                        # expired relative to TODAY
    assert _objects(weak, "LB-CRT-002") == {"app.example.com.crt"}                        # 11 days left
    assert _objects(weak, "LB-CRT-003") == {"weak.example.com.crt"}                       # 1024-bit RSA
    assert _objects(weak, "LB-POOL-001") == {"pool_nomon"}
    assert _objects(weak, "LB-POOL-003") == {"pool_empty"}
    assert _objects(weak, "LB-POOL-002") == {"pool_icmp"}
    assert _objects(weak, "LB-SSL-001") == {"client-ssl clientssl_legacy"}
    assert _objects(weak, "LB-VS-001") == {"vs_empty"}
    assert _objects(weak, "LB-MON-002") == {"mon_fast"}
    assert _objects(weak, "LB-SNMP-002") == {"comm-rw"}
    assert {"vs_dup_a, vs_dup_b"} == _objects(weak, "LB-VS-009")
    assert _objects(weak, "LB-OBJ-001") == {"pool_unused"} and _objects(weak, "LB-OBJ-003") == {"mon_unused"}


def test_dangling_references_are_found_but_builtin_ones_are_not(weak):
    refs = _objects(weak, "LB-REF-001")
    assert {"vs_broken_refs -> pool_missing", "vs_broken_refs -> does_not_exist", "rule_debug_log -> pool_ghost"} == refs


def test_severity_follows_the_blast_radius(weak):
    severities = {f["id"]: f["severity"] for f in weak["findings"]}
    assert severities["LB-MGT-001"] == "high" and severities["LB-SSL-001"] == "high" and severities["LB-CRT-001"] == "high"
    assert severities["LB-CRT-002"] == "medium"
    assert severities["LB-POOL-001"] == "medium"                     # pool_nomon has a default node monitor behind it
    assert severities["LB-OBJ-001"] == "low"


def test_aggregated_findings_list_the_members(weak):
    vs013 = _by_id(weak, "LB-VS-013")[0]
    assert vs013["severity"] == "info" and "vs_web_443" in vs013["object"]


def test_every_finding_is_complete_and_documented(weak, capture):
    known = set(F5.values())
    for result in (weak, capture):
        for f in result["findings"]:
            assert f["id"].startswith("LB-") and f["title"] and f["detail"] and f["severity"] in ("high", "medium", "low", "info")
            if f["severity"] != "info":
                assert f["recommendation"], f["id"]
            assert f["reference"] in known, (f["id"], f["reference"])


def test_findings_are_sorted_most_severe_first(weak):
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    ranks = [order[f["severity"]] for f in weak["findings"]]
    assert ranks == sorted(ranks)


def test_hardened_config_has_no_actionable_findings(hardened):
    assert validate_result(hardened) == []
    assert {f["severity"] for f in hardened["findings"]} <= {"low", "info"}
    assert _ids(hardened) <= {"LB-OBJ-003"}                         # the one deliberately unused monitor
    rows = {r["check"]: r["result"] for r in section_by_id(hardened, "hardening")["rows"]}
    assert set(rows.values()) <= {"pass", "n/a"}


def test_hardening_checklist_follows_the_findings(weak):
    rows = {r["check"]: r["result"] for r in section_by_id(weak, "hardening")["rows"]}
    assert rows["GUI / REST API limited to management networks"] == "fail"
    assert rows["SSH limited to management networks"] == "fail"
    assert rows["Idle sessions end within 15 minutes"] == "fail"


def test_certificate_age_is_relative_to_the_given_date():
    early = service.analyze(_read("bigip_synthetic_weak.conf"), "lb.conf", today=date(2026, 1, 1))
    assert not _ids(early) & {"LB-CRT-001", "LB-CRT-002"}           # nothing has expired or is close to expiry on 2026-01-01
    late = service.analyze(_read("bigip_synthetic_weak.conf"), "lb.conf", today=date(2027, 6, 1))
    assert {"app.example.com.crt", "old.example.com.crt", "weak.example.com.crt"} <= _objects(late, "LB-CRT-001")


# ---------------------------------------------------------------------- inline cases
def test_public_virtual_server_without_vlan_scope_and_pool_without_monitor():
    result = _snippet(VS_PUBLIC)
    ids = _ids(result)
    assert {"LB-VS-004", "LB-POOL-001", "LB-POOL-004", "LB-VS-007"} <= ids
    pool = _by_id(result, "LB-POOL-001")[0]
    assert pool["severity"] == "high" and pool["object"] == "p1"     # no service monitor and no default node monitor


def test_default_node_monitor_downgrades_the_missing_pool_monitor():
    result = _snippet(VS_PUBLIC + "ltm default-node-monitor {\n    rule /Common/icmp\n}\n")
    assert _by_id(result, "LB-POOL-001")[0]["severity"] == "medium"


def test_pool_monitor_none_is_not_a_monitor():
    result = _snippet(VS_PUBLIC.replace("ltm pool /Common/p1 {", "ltm pool /Common/p1 {\n    monitor none"))
    assert "LB-POOL-001" in _ids(result)


def test_pool_with_http_monitor_has_no_monitor_finding():
    text = VS_PUBLIC.replace("ltm pool /Common/p1 {", "ltm pool /Common/p1 {\n    monitor /Common/http_app") + (
        'ltm monitor http /Common/http_app {\n    defaults-from /Common/http\n    interval 5\n    recv "200 OK"\n    send "GET /health HTTP/1.1\\r\\nHost: app\\r\\nConnection: close\\r\\n\\r\\n"\n    timeout 16\n}\n')
    ids = _ids(_snippet(text))
    assert "LB-POOL-001" not in ids and "LB-MON-001" not in ids and "LB-MON-002" not in ids


def test_management_rules_are_skipped_when_the_base_file_is_absent():
    result = _snippet(VS_PUBLIC)
    assert not [i for i in _ids(result) if i.startswith(("LB-MGT", "LB-SNMP", "LB-AUTH"))]
    assert any("bigip_base.conf" in w for w in result["warnings"])
    cov = {c["command"]: c for c in result["coverage"]}
    assert cov["net / sys / auth (bigip_base.conf)"]["status"] == "missing"


def test_base_file_alone_is_enough_for_the_management_rules():
    base = "sys httpd {\n    allow { all }\n    auth-pam-validate-ip on\n}\nsys sshd {\n    allow { ALL }\n}\nsys snmp {\n    agent-addresses { tcp6:161 udp6:161 }\n}\n"
    result = _snippet(base)
    assert {"LB-MGT-001", "LB-MGT-002"} <= _ids(result)
    assert not [f for f in result["findings"] if f["id"].startswith("LB-POOL")]


def test_private_virtual_server_is_not_reported_as_public():
    text = VS_PUBLIC.replace("160.19.5.10", "10.20.30.40")
    result = _snippet(text)
    assert "LB-VS-013" not in _ids(result)
    assert not [f for f in result["findings"] if f["id"] == "LB-VS-004" and f["severity"] == "medium"]


def test_stock_client_ssl_profile_on_a_virtual_server_is_flagged():
    text = VS_PUBLIC.replace("/Common/tcp { }", "/Common/tcp { }\n        /Common/clientssl {\n            context clientside\n        }")
    hits = _by_id(_snippet(text), "LB-SSL-005")
    assert hits and hits[0]["object"].startswith("vs_pub")


def test_http_to_https_redirect_virtual_is_not_called_clear_text_forwarding():
    text = (
        "ltm virtual /Common/vs_https {\n    destination /Common/10.20.30.40:443\n    ip-protocol tcp\n    pool /Common/p1\n    profiles {\n        /Common/tcp { }\n        /Common/clientssl {\n            context clientside\n        }\n    }\n}\n"
        "ltm virtual /Common/vs_redirect {\n    destination /Common/10.20.30.40:80\n    ip-protocol tcp\n    profiles {\n        /Common/http { }\n        /Common/tcp { }\n    }\n    rules {\n        /Common/_sys_https_redirect\n    }\n}\n"
        "ltm pool /Common/p1 {\n    members {\n        /Common/10.0.0.1:80 {\n            address 10.0.0.1\n        }\n    }\n    monitor /Common/http\n}\n")
    ids = _ids(_snippet(text))
    assert "LB-VS-005" not in ids and "LB-REF-001" not in ids


def test_irule_that_logs_credentials_is_flagged_and_a_clean_one_is_not():
    bad = 'ltm rule /Common/r_bad {\n    when HTTP_REQUEST {\n        log local0. "auth=[HTTP::header Authorization] cookie=[HTTP::cookie value JSESSIONID]"\n    }\n}\n'
    good = 'ltm rule /Common/r_ok {\n    when HTTP_REQUEST {\n        if { [HTTP::uri] starts_with "/health" } { HTTP::respond 200 content ok }\n    }\n}\n'
    assert "LB-IRL-001" in _ids(_snippet(bad))
    assert "LB-IRL-001" not in _ids(_snippet(good))


@pytest.mark.parametrize("text, hint", [
    ("hello world", ""),
    ("config firewall policy\n    edit 1\n    next\nend\n", "Firewall Analyzer"),
    ("set deviceconfig system hostname fw1\nset rulebase security rules r1 action allow\n", "Firewall Analyzer"),
    ("hostname r1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\nrouter bgp 65000\n", "Router Analyzer"),
    ("sysname SW1\nvlan batch 10 20\ninterface Vlan-interface10\n", "Switch Analyzer"),
])
def test_unrecognised_input_is_rejected_with_a_pointer(text, hint):
    with pytest.raises(ValueError) as caught:
        service.analyze(text, "x.txt")
    assert hint in str(caught.value)


def test_looks_like_bigip():
    assert service.looks_like_bigip(_read("bigip_synthetic_weak.conf"))
    assert service.looks_like_bigip("ltm virtual /Common/vs {\n}\n")
    assert not service.looks_like_bigip("interface Gi0/1\n ip address 1.1.1.1 255.255.255.0\n")


# ------------------------------------------------------------------------- secrets
def test_secrets_never_leave_the_analyzer(weak, hardened, capture):
    for result in (weak, hardened, capture):
        blob = json.dumps(result)
        for secret in SECRETS:
            assert secret not in blob, secret
    assert "$6$" not in json.dumps(weak)


def test_snmp_community_names_are_not_echoed_but_the_problem_is_reported(weak):
    blob = json.dumps(section_by_id(weak, "snmp"))
    assert "Sup3rSecretRW" not in blob
    assert _by_id(weak, "LB-SNMP-001") and _by_id(weak, "LB-SNMP-002")


# ------------------------------------------------------------------------- runtime
def test_capture_is_split_by_prompt_and_config_comes_from_tmsh_list(capture):
    assert validate_result(capture) == []
    assert capture["hostname"] == "lb-hq-01.corp.example.com"
    assert capture["capture"]["commands"] >= 5
    live = {s["id"] for s in capture["sections"] if s["group"] == "Live state"}
    assert live == {"status_live", "virtuals_live", "pools_live"}


def test_live_virtual_and_pool_state_is_tabulated(capture):
    vs = {r["name"]: r for r in section_by_id(capture, "virtuals_live")["rows"]}
    assert vs["vs_web_443"]["availability"] == "available" and vs["vs_web_443"]["connections"] == 412
    assert vs["vs_app_8443"]["availability"] == "offline"
    pools = {r["name"]: r for r in section_by_id(capture, "pools_live")["rows"]}
    assert pools["pool_web"]["members"] == "2/3" and pools["pool_app"]["members"] == "0/2"


def test_runtime_findings(capture):
    rt = {(f["id"], f["object"]): f["severity"] for f in capture["findings"] if f["id"].startswith("LB-RT")}
    assert rt[("LB-RT-001", "cm sync-status")] == "high"             # Changes Pending
    assert rt[("LB-RT-003", "vs_app_8443")] == "high"                # enabled but offline
    assert rt[("LB-RT-004", "pool_app")] == "high"                   # no member available
    assert rt[("LB-RT-004", "pool_web")] == "medium"                 # 2 of 3 available
    assert ("LB-RT-003", "vs_retired") not in rt                     # disabled on purpose


def test_runtime_parsers_on_their_own():
    assert bigip_runtime.parse_version("Sys::Version\nMain Package\n  Product     BIG-IP\n  Version     16.1.4\n  Build       0.0.5\n  Edition     Point Release 4\n")["version"] == "16.1.4"
    sync = bigip_runtime.parse_sync_status("CM::Sync-Status\nStatus    In Sync\nSummary   All devices in the device group are in sync\nColor     green\n")
    assert sync["status"] == "In Sync"
    failover = bigip_runtime.parse_failover_status("CM::Failover-Status\nColor     green\nStatus    STANDBY\nSummary   1/1 standby\n")
    assert failover["status"] == "STANDBY"


def test_in_sync_and_standby_raise_no_runtime_finding():
    text = (
        "[admin@lb1:Standby:In Sync] ~ # tmsh show cm sync-status\nCM::Sync-Status\nStatus    In Sync\nSummary   All devices in the device group are in sync\nColor     green\n\n"
        "[admin@lb1:Standby:In Sync] ~ # tmsh show cm failover-status\nCM::Failover-Status\nColor     green\nStatus    STANDBY\nSummary   1/1 standby\n\n"
        "[admin@lb1:Standby:In Sync] ~ # tmsh list ltm pool\n" + VS_PUBLIC)
    result = _snippet(text)
    assert not [i for i in _ids(result) if i.startswith("LB-RT")]
    live = {c["label"]: c["tone"] for c in result["cards"]}
    assert live["Config sync"] == "ok"


def test_coverage_lists_missing_runtime_commands(weak):
    missing = [c["command"] for c in weak["coverage"] if c["status"] == "missing"]
    assert "show cm sync-status" in missing and "show ltm pool" in missing


def test_unvalidated_runtime_parsers_are_declared(capture, weak):
    assert any("not yet validated" in w for w in capture["warnings"])
    assert any("synthetic" in w for w in weak["warnings"])


def test_collect_commands_are_documented_and_read_only():
    root = Path(__file__).resolve().parents[1] / "static" / "collect-scripts"
    commands = [l.strip() for l in (root / "collect-lb-f5-bigip.txt").read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    assert commands
    for command in commands:
        words = command.split()
        assert words[0] in ("tmsh", "cat", "show", "list") or words[0] == "bash", command
        assert not any(w in command.split() for w in ("modify", "create", "delete", "save", "load", "reboot", "restart", "install")), command


# ---------------------------------------------------------------------------- refs
def test_reference_links_are_https_f5_or_standards_documentation():
    allowed = ("clouddocs.f5.com", "techdocs.f5.com", "community.f5.com", "csrc.nist.gov", "pcisecuritystandards.org", "www.f5.com", "my.f5.com")
    assert F5
    for key, url in F5.items():
        assert url.startswith("https://"), key
        assert any(host in url for host in allowed), (key, url)
    assert "my.f5.com" not in " ".join(F5.values())                  # JavaScript-only; unverifiable from here


# ----------------------------------------------------------------------- app wiring
class LoadBalancerRouteTests(unittest.TestCase):
    def setUp(self):
        os.environ["NES_DISABLE_AUTH"] = "1"
        self.addCleanup(os.environ.pop, "NES_DISABLE_AUTH", None)
        import app as nes_app

        self.client = nes_app.create_app().test_client()

    def test_page_loads_and_is_in_navigation(self):
        page = self.client.get("/load-balancer-analyzer/")
        self.assertEqual(page.status_code, 200)
        self.assertIn('data-analyzer="lb"', page.get_data(as_text=True))
        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("/load-balancer-analyzer", home)
        self.assertIn("Load Balancer Analyzer", home)

    @unittest.skipUnless((Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").exists(), "this edition has no single-page router")
    def test_spa_router_knows_the_route(self):
        text = (Path(__file__).resolve().parents[1] / "static" / "js" / "spa-router.js").read_text(encoding="utf-8")
        self.assertIn('"/load-balancer-analyzer"', text)

    def test_analyze_and_export_roundtrip(self):
        body = (FIXTURES / "bigip_synthetic_weak.conf").read_bytes()
        response = self.client.post("/load-balancer-analyzer/api/analyze", data={"config_files": (io.BytesIO(body), "lb.conf")}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["results"][0]["hostname"], "lb-hq-01.corp.example.com")
        export = self.client.post("/load-balancer-analyzer/api/export", json={"results": payload["results"]}).get_json()
        self.assertTrue(export["ok"])
        download = self.client.get(export["download_url"])
        self.assertEqual(download.data[:2], b"PK")

    def test_base_and_ltm_files_are_analyzed_separately(self):
        text = (FIXTURES / "bigip_synthetic_hardened.conf").read_bytes()
        response = self.client.post("/load-balancer-analyzer/api/analyze", data={"config_files": [(io.BytesIO(text), "a.conf"), (io.BytesIO((FIXTURES / "bigip_capture_synthetic.txt").read_bytes()), "b.txt")]}, content_type="multipart/form-data")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["results"]), 2)

    def test_firewall_capture_returns_400_with_hint(self):
        response = self.client.post("/load-balancer-analyzer/api/analyze", data={"config_text": "config firewall policy\n    edit 1\n    next\nend\n"})
        self.assertEqual(response.status_code, 400)
        self.assertIn("Firewall Analyzer", response.get_json()["error"])

    def test_collect_scripts_endpoint_lists_load_balancer_files_only(self):
        body = self.client.get("/load-balancer-analyzer/api/collect-scripts").get_json()
        files = {s["file"] for s in body["scripts"]}
        self.assertEqual(files, {"collect-lb-f5-bigip.txt"})

    def test_other_analyzers_do_not_list_the_load_balancer_collect_file(self):
        for prefix in ("/firewall-analyzer", "/router-analyzer"):
            body = self.client.get(prefix + "/api/collect-scripts").get_json()
            self.assertNotIn("collect-lb-f5-bigip.txt", {s["file"] for s in body["scripts"]}, prefix)

    def test_health_lists_the_module(self):
        self.assertEqual(self.client.get("/api/health").get_json()["modules"]["lb_analyzer"], "ready")
