"""A vCMP host lists its guests and its physical ports; both must be shown, and the guest's sym-unit-key (a secret) must never be read.

The configuration is invented (documentation addresses, example names).
"""

from __future__ import annotations

import json
from datetime import date

from features.lb_analyzer import service

TODAY = date(2026, 11, 1)
SECRET = "FAKE-SYM-UNIT-KEY-DO-NOT-SHOW"

HOST_BASE = f"""#TMSH-VERSION: 15.1.5
sys global-settings {{
    hostname host1.example.test
}}
net interface 1.1 {{
    bundle enabled
    bundle-speed 25G
    description uplink-a
    lldp-admin txrx
}}
net interface 1.2 {{
    disabled
}}
net vlan /Common/ext {{
    interfaces {{
        1.1 {{ }}
    }}
    tag 100
}}
vcmp guest /Common/guest-a {{
    allowed-slots {{ 1 2 }}
    assigned-slots {{ 1 }}
    cores-per-slot 4
    hostname guest-a.example.test
    initial-image BIGIP-15.1.5.iso
    management-gw 192.0.2.1
    management-ip 192.0.2.50/24
    preferred-slots {{ 1 }}
    ssl-mode shared
    state deployed
    sym-unit-key {SECRET}
    virtual-disk guest-a.img
    vlans {{
        /Common/ext
    }}
}}
"""


def _sections():
    result = service.analyze(HOST_BASE, "bigip_base.conf", today=TODAY)
    return result, {s["id"]: s for s in result["sections"]}


def test_vcmp_guests_table_shows_the_guest():
    result, secs = _sections()
    rows = secs["vcmp_guests"]["rows"]
    assert len(rows) == 1
    row = rows[0]
    assert row["hostname"] == "guest-a.example.test" and row["management_ip"] == "192.0.2.50/24"
    assert row["virtual_disk"] == "guest-a.img" and row["state"] == "deployed" and row["ssl_mode"] == "shared"
    assert row["assigned_slots"] == ["1"] and row["cores_per_slot"] == "4"


def test_interfaces_table_shows_state_and_bundling():
    _, secs = _sections()
    rows = {r["short"]: r for r in secs["interfaces"]["rows"]}
    assert rows["1.1"]["enabled"] == "enabled" and rows["1.1"]["bundle_speed"] == "25G" and rows["1.1"]["lldp_admin"] == "txrx"
    assert rows["1.2"]["enabled"] == "disabled"


def test_sym_unit_key_never_reaches_the_result():
    result, _ = _sections()
    assert SECRET not in json.dumps(result, default=str)
