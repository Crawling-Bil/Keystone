"""A BIG-IP capture that holds only ``show`` commands has no ``ltm virtual { pool ... }`` stanza.  ``show ltm virtual detail`` nests the pool and its members under each
virtual server, so the analyzer rebuilds the binding from it, and refuses to judge the rules that need ``tmsh list``.  The capture here is synthetic (documentation addresses)."""

from __future__ import annotations

from datetime import date

from features.lb_analyzer import bigip_runtime, service

PROMPT = "ops@(LAB-LTM1)(cfg-sync In Sync)(Active)(/Common)(tmos)# "

CAPTURE = f"""{PROMPT}show ltm virtual field-fmt
ltm virtual VS_WEB {{
    destination 192.0.2.10:443
    enabled
}}
ltm virtual VS_FWD {{
    destination any:any
    enabled
}}
{PROMPT}show ltm virtual detail

------------------------------------------------------------------
Ltm::Virtual Server: VS_WEB
------------------------------------------------------------------
Status
  Availability     : available
  State            : enabled
  Destination      : 192.0.2.10:443

  -----------------------------------------------------------------------------------------
  | Ltm::Pool: PL_WEB
  -----------------------------------------------------------------------------------------
  | Status
  |   Availability           : available
  |   Monitor                : tcp
  |   Total Members          : 2
  |
     --------------------------------------------------------------
     | Ltm::Pool Member: 198.51.100.11:443
     --------------------------------------------------------------
     | Status
     |   Availability   : available
     |   Monitor        : tcp (pool monitor)
     |   IP Address     : 198.51.100.11
     --------------------------------------------------------------
     | Ltm::Pool Member: 198.51.100.12:443
     --------------------------------------------------------------
     | Status
     |   Availability   : offline
     |   Monitor        : tcp (pool monitor)
     |   IP Address     : 198.51.100.12

------------------------------------------------------------------
Ltm::Virtual Server: VS_FWD
------------------------------------------------------------------
Status
  Availability     : unknown
  Destination      : any:any
{PROMPT}"""

NO_POOL = f"""{PROMPT}show ltm virtual field-fmt
ltm virtual VS_ONLY {{
    destination 192.0.2.20:80
}}
{PROMPT}"""


def test_parse_virtual_detail_reads_pool_and_members():
    block = CAPTURE.split("show ltm virtual detail", 1)[1]
    bindings = bigip_runtime.parse_virtual_detail(block)
    assert [b["virtual"] for b in bindings] == ["VS_WEB"]      # VS_FWD has no pool
    pool = bindings[0]["pools"][0]
    assert pool["name"] == "PL_WEB" and pool["monitor"] == "tcp"
    assert [(m["member"], m["address"]) for m in pool["members"]] == [("198.51.100.11:443", "198.51.100.11"), ("198.51.100.12:443", "198.51.100.12")]


def test_gather_rebuilds_configuration():
    data = bigip_runtime.gather(CAPTURE)
    assert data["config_derived"] is True
    text = data["config_text"]
    assert "ltm virtual VS_WEB {\n    pool /Common/PL_WEB\n" in text
    assert "ltm pool PL_WEB {" in text and "monitor /Common/tcp" in text
    assert "198.51.100.12:443" in text
    assert "pool /Common/" not in text.split("ltm virtual VS_FWD", 1)[1].split("}")[0]


def test_analyze_warns_and_does_not_judge_what_it_cannot_see():
    result = service.analyze(CAPTURE, "show.txt", today=date(2026, 11, 1))
    assert any("rebuilt from 'show ltm virtual detail'" in w for w in result["warnings"])
    assert not {f["id"] for f in result["findings"]} & set(service.DERIVED_UNJUDGEABLE)
    pool_rules = [f for f in result["findings"] if f["id"] == "LB-POOL-002"]            # needs the rebuilt pool and its monitor
    assert pool_rules and "PL_WEB" in pool_rules[0]["detail"]


def test_without_virtual_detail_nothing_is_invented():
    data = bigip_runtime.gather(NO_POOL)
    assert not data.get("config_derived")
    assert "ltm pool" not in data["config_text"]
    assert "virtual_pools" not in data


def test_a_full_listing_wins_over_the_rebuild():
    listing = f"{PROMPT}list ltm virtual\nltm virtual VS_WEB {{\n    destination 192.0.2.10:443\n    pool /Common/PL_REAL\n}}\n"
    data = bigip_runtime.gather(listing + CAPTURE)
    assert not data.get("config_derived")
    assert "PL_REAL" in data["config_text"]


def test_local_accounts_section_says_the_capture_cannot_show_them():
    result = service.analyze(CAPTURE, "show.txt", today=date(2026, 11, 1))
    users = next(s for s in result["sections"] if s["id"] == "users")
    assert users["rows"] == [] and "tmsh list auth user" in users["empty"]


def test_coverage_row_says_the_objects_were_rebuilt():
    result = service.analyze(CAPTURE, "show.txt", today=date(2026, 11, 1))
    row = next(r for r in result["coverage"] if r["command"].startswith("ltm ("))
    assert "rebuilt from 'show ltm virtual detail'" in row["note"]
