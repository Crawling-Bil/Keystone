"""Router Analyzer: OMP summary, installed certificates, per-tunnel counters, BFD history and the classic ``show license detail``.

All values are synthetic (RFC 5737 addresses, generic names); the column layout and the order of the lines are copied from real output
of two cEdge routers (C8200 on IOS-XE 17.09, C8300) and of an ASR1002-X.  Numbers asserted here were counted by hand from the text of each case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from features.analyzer_core.result import validate_result
from features.router_analyzer import runtime_health as rh
from features.router_analyzer import runtime_sdwan_extra as rse
from features.router_analyzer.refs import REFS
from features.router_analyzer.service import analyze

ROOT = Path(__file__).resolve().parents[1]
CLOCK = "20:21:00.123 WIB Mon Oct 12 2026"


def lines(text: str) -> list[str]:
    return text.strip("\n").split("\n")


def capture(*blocks: tuple[str, str]) -> str:
    out = []
    for command, body in blocks:
        out.append(f"EDGE-A#{command}")
        out.append(body.strip("\n"))
        out.append("")
    return "\n".join(out) + "\n"


def run(*blocks: tuple[str, str], clock: str | None = CLOCK) -> dict:
    head = (("show clock", clock),) if clock else ()
    return analyze(capture(*head, *blocks), filename="edge.txt")


def ids(result: dict) -> list[str]:
    return [f["id"] for f in result["findings"]]


def finding(result: dict, rule_id: str) -> dict:
    return next(f for f in result["findings"] if f["id"] == rule_id)


def section(result: dict, section_id: str) -> dict:
    return next(s for s in result["sections"] if s["id"] == section_id)


# ---------------------------------------------------------------------------
# show sdwan omp summary
# ---------------------------------------------------------------------------

OMP_SUMMARY = """
oper-state             UP
admin-state            UP
personality            vedge
device-role            Edge-Router
omp-uptime             17:03:03:46
routes-received        22554
routes-installed       2188
routes-sent            20
tlocs-received         6
tlocs-installed        4
tlocs-sent             4
services-received      2
services-installed     0
services-sent          4
mcast-routes-received  0
mcast-routes-installed 0
mcast-routes-sent      0
hello-sent             147630
hello-received         147574
handshake-sent         9
handshake-received     9
alert-sent             7
alert-received         0
inform-sent            117
inform-received        117
update-sent            904
update-received        36449
policy-sent            0
policy-received        52
total-packets-sent     148667
total-packets-received 184219
vsmart-peers           2
"""


def omp_summary(**changes: str) -> str:
    text = OMP_SUMMARY
    for key, value in changes.items():
        key = key.replace("_", "-")
        text = "\n".join(f"{key:<22} {value}" if line.startswith(key + " ") else line for line in text.split("\n"))
    return text


def test_omp_summary_reads_state_counters_and_peers_as_numbers():
    row = rse.parse_omp_summary(lines(OMP_SUMMARY))
    assert (row["oper_state"], row["admin_state"], row["omp_uptime"], row["vsmart_peers"]) == ("UP", "UP", "17:03:03:46", 2)
    assert (row["routes_received"], row["routes_installed"], row["routes_sent"], row["hello_sent"], row["alert_sent"]) == (22554, 2188, 20, 147630, 7)


def test_omp_summary_without_a_state_is_not_a_summary():
    assert rse.parse_omp_summary(lines("% Invalid input detected at '^' marker.")) == {}


def test_healthy_omp_summary_has_a_section_and_no_finding():
    result = run(("show sdwan omp summary", OMP_SUMMARY))
    pairs = {p["label"]: p for p in section(result, "sdwan_omp_counters")["pairs"]}
    assert pairs["OMP operational state"]["tone"] == "ok" and pairs["vSmart controllers connected"]["value"] == 2
    assert pairs["Routes received / installed / sent"]["value"] == "22,554 / 2,188 / 20"
    assert pairs["OMP alert sent / received"]["tone"] == "warn"           # 7 alerts sent
    assert not [i for i in ids(result) if i.startswith("RTR-SDW-08")]


def test_omp_down_is_high_and_no_vsmart_is_high():
    down = run(("show sdwan omp summary", omp_summary(oper_state="DOWN")))
    assert finding(down, "RTR-SDW-083")["severity"] == "high" and "DOWN" in finding(down, "RTR-SDW-083")["title"]
    none = run(("show sdwan omp summary", omp_summary(vsmart_peers="0")))
    assert finding(none, "RTR-SDW-083")["severity"] == "high" and "no vSmart" in finding(none, "RTR-SDW-083")["title"]


def test_single_vsmart_is_low_and_received_routes_without_installed_ones_is_medium():
    one = run(("show sdwan omp summary", omp_summary(vsmart_peers="1")))
    assert finding(one, "RTR-SDW-084")["severity"] == "low"
    bare = run(("show sdwan omp summary", omp_summary(routes_installed="0")))
    assert finding(bare, "RTR-SDW-086")["severity"] == "medium" and "22,554" in finding(bare, "RTR-SDW-086")["title"]


PEERS_ONE_UP = """
TENANT                             DOMAIN    OVERLAY   SITE      REGION
ID        PEER             TYPE    ID        ID        ID        ID        STATE    UPTIME           R/I/S
-----------------------------------------------------------------------------------------------------------------
0         192.0.2.10       vsmart  1         1         900001    None      up       37:03:21:21      12708/2175/8
0         192.0.2.11       vsmart  1         1         900002    None      down     0:00:00:00       0/0/0
"""


def test_vsmart_count_is_checked_against_the_omp_session_table():
    result = run(("show sdwan omp summary", OMP_SUMMARY), ("show sdwan omp peers", PEERS_ONE_UP))
    pairs = {p["label"]: p for p in section(result, "sdwan_omp_counters")["pairs"]}
    assert pairs["vSmart sessions up in 'show sdwan omp peers'"]["value"] == 1 and pairs["vSmart sessions up in 'show sdwan omp peers'"]["tone"] == "warn"
    assert "RTR-SDW-084" in ids(result) and "differs" in finding(result, "RTR-SDW-084")["title"]


# ---------------------------------------------------------------------------
# show sdwan certificate installed
# ---------------------------------------------------------------------------

BOARD_ID = """
Board-id certificate
--------------------

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            08:27:18:67:86:55:25:62:5f:c1
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=High Assurance SUDI CA, O=Cisco
        Validity
            Not Before: Jul  2 02:09:07 2025 GMT
            Not After : Aug  9 20:58:26 2099 GMT
        Subject: serialNumber=PID:C8200-1N-4T SN:FVT0000X0X0, O=Cisco, OU=ACT-2 Lite SUDI, CN=C8200-1N-4T
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:f1:0b:f5:3a:92:62:d6:49:98:10:c0:f0:be:83:
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
    Signature Algorithm: sha256WithRSAEncryption
         97:d0:46:06:3b:3e:aa:86:bd:a3:1e:2d:74:c4:ef:4f:d4:d1:
"""

NO_DEVICE_CERT = """
Installed device certificates
-----------------------------

"""


def device_cert(not_after: str) -> str:
    return f"""
Installed device certificates
-----------------------------

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4660 (0x1234)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Example Corp, CN=Example Enterprise Root CA
        Validity
            Not Before: Oct 12 08:00:00 2024 GMT
            Not After : {not_after}
        Subject: C=ID, O=Example Corp, OU=SDWAN, CN=edge-a.example.test
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
"""


def certificate_block(not_after: str | None = None) -> str:
    return BOARD_ID + (device_cert(not_after) if not_after else NO_DEVICE_CERT)


def test_certificates_are_read_without_the_device_serial():
    data = rse.parse_certificates(lines(certificate_block("Dec  1 08:00:00 2026 GMT")))
    board, device = data["certificates"]
    assert board["section"] == "Board-id certificate" and board["subject"] == {"O": "Cisco", "OU": "ACT-2 Lite SUDI", "CN": "C8200-1N-4T"}
    assert "FVT0000X0X0" not in repr(data) and "serialNumber" not in repr(data["certificates"])
    assert board["not_before"] == "2025-07-02T02:09:07" and board["not_after"] == "2099-08-09T20:58:26" and board["key_bits"] == 2048 and board["ca"] is False
    assert board["serial"] == "08:27:18:67:86:55:25:62:5f:c1"
    assert device["section"] == "Installed device certificates" and device["serial"] == "4660 (0x1234)" and device["key_bits"] == 4096
    assert device["subject"]["CN"] == "edge-a.example.test" and device["issuer"]["CN"] == "Example Enterprise Root CA"
    assert data["empty_sections"] == []


def test_a_router_that_uses_the_board_id_certificate_has_an_empty_device_section():
    data = rse.parse_certificates(lines(certificate_block()))
    assert len(data["certificates"]) == 1 and data["empty_sections"] == ["Installed device certificates"]


def test_certificate_table_counts_days_from_the_capture_clock_and_hides_the_serial():
    result = run(("show sdwan certificate installed", certificate_block("Dec  1 08:00:00 2026 GMT")))
    rows = {r["subject"]: r for r in section(result, "sdwan_certificates")["rows"]}
    assert rows["edge-a.example.test"]["days"] == 49 and rows["edge-a.example.test"]["_tones"]["days"] == "warn"
    assert rows["C8200-1N-4T"]["_tones"]["days"] == "ok"
    assert "FVT0000X0X0" not in repr(result["sections"])


@pytest.mark.parametrize("not_after, severity, fragment", [
    ("Dec  1 08:00:00 2026 GMT", "medium", "expires in 49 day"),
    ("Oct 30 08:00:00 2026 GMT", "high", "expires in 17 day"),
    ("Oct  1 08:00:00 2026 GMT", "high", "expired 11 day"),
    ("Mar 10 08:00:00 2027 GMT", "low", "expires in 148 day"),
])
def test_certificate_expiry_severity_follows_the_days_left(not_after, severity, fragment):
    result = run(("show sdwan certificate installed", certificate_block(not_after)))
    item = finding(result, "RTR-SDW-085")
    assert item["severity"] == severity and fragment in item["title"] and item["reference"] == REFS["sdwan_troubleshoot_common"]
    assert "CERTEXPRD" in item["detail"]


def test_a_certificate_far_in_the_future_and_a_missing_clock_raise_nothing():
    assert "RTR-SDW-085" not in ids(run(("show sdwan certificate installed", certificate_block("Dec  1 08:00:00 2029 GMT"))))
    assert "RTR-SDW-085" not in ids(run(("show sdwan certificate installed", certificate_block("Oct  1 08:00:00 2020 GMT")), clock=None))


# ---------------------------------------------------------------------------
# show sdwan tunnel statistics
# ---------------------------------------------------------------------------


def tunnel(src: str, dst: str, sport: int, dport: int, system_ip: str, local: str, remote: str, tx: int, rx: int, mtu: int = 1438) -> str:
    return f"""tunnel stats ipsec {src} {dst} {sport} {dport}
 system-ip            {system_ip}
 local-color          {local}
 remote-color         {remote}
 tunnel-mtu           {mtu}
 tx_pkts              {tx}
 tx_octets            {tx * 100}
 rx_pkts              {rx}
 rx_octets            {rx * 100}
 tcp-mss-adjust       1358
 ipv6_tx_pkts         0
 ipv6_tx_octets       0
 ipv6_rx_pkts         0
 ipv6_rx_octets       0
 tx_ipv4_mcast_pkts   0
 tx_ipv4_mcast_octets 0
 rx_ipv4_mcast_pkts   0
 rx_ipv4_mcast_octets 0"""


def tunnels(*rows: str) -> str:
    return "\n".join(rows)


HEALTHY = [
    tunnel("192.0.2.1", "198.51.100.6", 12366, 12426, "10.255.0.1", "custom1", "mpls", 229095543, 242934814),
    tunnel("192.0.2.1", "198.51.100.14", 12366, 12346, "10.255.0.2", "custom1", "mpls", 3155678, 3155653),
    tunnel("192.0.2.5", "198.51.100.6", 12366, 12426, "10.255.0.1", "custom2", "mpls", 400000, 380000),
]


def test_tunnel_statistics_keep_endpoints_colors_mtu_and_ipv4_counters():
    rows = rse.parse_tunnel_statistics(lines(tunnels(*HEALTHY)))
    assert len(rows) == 3
    first = rows[0]
    assert (first["protocol"], first["src_ip"], first["dst_ip"], first["src_port"], first["dst_port"]) == ("ipsec", "192.0.2.1", "198.51.100.6", "12366", "12426")
    assert (first["system_ip"], first["local_color"], first["remote_color"], first["mtu"], first["tcp_mss"]) == ("10.255.0.1", "custom1", "mpls", 1438, 1358)
    assert (first["tx_pkts"], first["rx_pkts"], first["tx_octets"], first["rx_octets"]) == (229095543, 242934814, 22909554300, 24293481400)


def test_healthy_tunnels_raise_no_one_way_finding_and_summarize_by_color_pair():
    result = run(("show sdwan tunnel statistics", tunnels(*HEALTHY)))
    assert "RTR-SDW-082" not in ids(result) and "RTR-SDW-087" not in ids(result)
    pairs = {(r["local_color"], r["remote_color"]): r for r in section(result, "sdwan_tunnel_pairs")["rows"]}
    assert pairs[("custom1", "mpls")]["tunnels"] == 2 and pairs[("custom2", "mpls")]["tunnels"] == 1 and pairs[("custom1", "mpls")]["one_way"] == 0
    assert section(result, "sdwan_tunnel_traffic")["total"] == 3


def test_a_tunnel_that_sends_and_never_receives_is_a_medium_finding_with_the_bfd_state():
    bfd = """
                                      SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
SYSTEM IP        SITE ID     STATE       COLOR            COLOR            SOURCE IP                                       IP                                              PORT        ENCAP  MULTIPLIER  INTERVAL(msec) UPTIME      TRANSITIONS
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
10.255.0.9       900009      down        custom1          private4         192.0.2.1                                       203.0.113.9                                     12346       ipsec  7           1000           0:00:00:00  2
"""
    rows = HEALTHY + [tunnel("192.0.2.1", "203.0.113.9", 12366, 12346, "10.255.0.9", "custom1", "private4", 15200316, 0)]
    result = run(("show sdwan bfd sessions", bfd), ("show sdwan tunnel statistics", tunnels(*rows)))
    item = finding(result, "RTR-SDW-082")
    assert item["severity"] == "medium" and item["title"].startswith("1 of 4 overlay tunnel")
    assert "sends only, 15,200,316 sent / 0 received, BFD down" in item["detail"]
    traffic = {r["remote"]: r for r in section(result, "sdwan_tunnel_traffic")["rows"] if r["remote_color"] == "private4"}
    assert traffic["10.255.0.9"]["flag"] == "sends only" and traffic["10.255.0.9"]["_tones"]["flag"] == "bad"


def test_a_quiet_new_tunnel_is_not_one_way():
    result = run(("show sdwan tunnel statistics", tunnels(*HEALTHY, tunnel("192.0.2.1", "203.0.113.9", 12366, 12346, "10.255.0.9", "custom1", "mpls", 12, 0))))
    assert "RTR-SDW-082" not in ids(result)


def test_tunnels_with_a_far_lower_mtu_are_information():
    rows = HEALTHY + [tunnel("192.0.2.1", "203.0.113.9", 12366, 12346, "10.255.0.9", "custom1", "mpls", 5000, 5000, mtu=514)]
    result = run(("show sdwan tunnel statistics", tunnels(*rows)))
    item = finding(result, "RTR-SDW-087")
    assert item["severity"] == "info" and "514" in item["detail"] and "median" in item["detail"] and item["reference"] == REFS["sdwan_mtu_community"]


# ---------------------------------------------------------------------------
# show sdwan bfd history
# ---------------------------------------------------------------------------

HISTORY_HEAD = """
                                                       DST PUBLIC       DST PUBLIC                                  RX      TX
SYSTEM IP        SITE ID     COLOR            STATE       IP                                              PORT        ENCAP  TIME                     PKTS    PKTS    DEL
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
"""


def row(system_ip: str, state: str, when: str, rx: int = 0, tx: int = 0, deleted: int = 0, dst: str = "198.51.100.6", port: int = 12426, color: str = "mpls", site: str = "910000") -> str:
    return f"{system_ip:<16} {site:<11} {color:<16} {state:<11} {dst:<47} {port:<11} ipsec  {when:<24} {rx:<7} {tx:<7} {deleted}"


def history(*rows: str) -> str:
    return HISTORY_HEAD + "\n".join(rows)


def test_history_rows_read_the_date_month_first_and_the_deletion_marker():
    parsed = rse.parse_bfd_history(lines(history(row("10.255.0.1", "down", "09/26/26 17:53:49", 4043, 4044), row("10.255.0.1", "down", "09/26/26 17:53:49", deleted=1), row("10.255.0.1", "up", "09/27/26 09:45:59"))))
    assert [(r["state"], r["time"], r["rx_pkts"], r["tx_pkts"], r["deleted"]) for r in parsed] == [
        ("down", "2026-09-26T17:53:49", 4043, 4044, 0), ("down", "2026-09-26T17:53:49", 0, 0, 1), ("up", "2026-09-27T09:45:59", 0, 0, 0)]
    assert parsed[0]["system_ip"] == "10.255.0.1" and parsed[0]["site_id"] == "910000" and parsed[0]["dst_ip"] == "198.51.100.6" and parsed[0]["dst_port"] == "12426" and parsed[0]["encap"] == "ipsec"


def test_history_accepts_an_ipv6_destination_and_skips_the_header_and_the_ruler():
    text = history(row("10.255.0.1", "up", "09/26/26 16:23:41", dst="2001:db8::6"))
    parsed = rse.parse_bfd_history(lines(text))
    assert len(parsed) == 1 and parsed[0]["dst_ip"] == "2001:db8::6"


def test_a_drop_is_a_down_record_with_counters_and_the_deletion_marker_is_not_a_second_drop():
    rows = [
        row("10.255.0.1", "down", "09/26/26 16:23:40"), row("10.255.0.1", "up", "09/26/26 16:23:41"),              # came up
        row("10.255.0.1", "down", "09/26/26 17:53:49", 4043, 4044), row("10.255.0.1", "down", "09/26/26 17:53:49", deleted=1),   # carried traffic, then dropped
        row("10.255.0.1", "up", "09/26/26 18:05:02"),
    ]
    summary = rse.summarize_bfd_history(rse.parse_bfd_history(lines(history(*rows))))
    (one,) = summary["sessions"]
    assert (one["ups"], one["drops"], one["attempts"], one["teardowns"], one["records"]) == (2, 1, 1, 1, 5)
    assert one["last_drop"] == "2026-09-26T17:53:49" and summary["drops"] == 1 and summary["first"] == "2026-09-26T16:23:40" and summary["last"] == "2026-09-26T18:05:02"


def test_a_remote_that_returns_on_another_port_is_still_one_remote_tlocs():
    rows = [row("10.255.0.1", "up", "09/26/26 16:23:41", port=12426), row("10.255.0.1", "down", "09/29/26 13:56:33", 138440, 140046, port=12426), row("10.255.0.1", "up", "09/29/26 13:56:40", port=12406)]
    (one,) = rse.summarize_bfd_history(rse.parse_bfd_history(lines(history(*rows))))["sessions"]
    assert one["ports"] == ["12426", "12406"] and one["last_state"] == "up" and one["drops"] == 1


def test_drops_toward_different_remotes_within_ten_seconds_are_one_burst():
    rows = [
        row("10.255.0.1", "down", "09/26/26 17:53:42", 100, 100), row("10.255.0.2", "down", "09/26/26 17:53:48", 100, 100, dst="198.51.100.14"),     # 6 s apart: one burst of 2
        row("10.255.0.1", "down", "09/27/26 09:00:00", 100, 100),                                                                                   # alone
        row("10.255.0.2", "down", "09/28/26 09:00:00", 100, 100, dst="198.51.100.14"), row("10.255.0.2", "down", "09/28/26 09:00:05", 100, 100, dst="198.51.100.14"),    # same remote twice: not a burst
    ]
    summary = rse.summarize_bfd_history(rse.parse_bfd_history(lines(history(*rows))))
    assert len(summary["bursts"]) == 1
    burst = summary["bursts"][0]
    assert (burst["time"], burst["sessions"], burst["seconds"], burst["remotes"], burst["colors"]) == ("2026-09-26T17:53:42", 2, 6, ["10.255.0.1", "10.255.0.2"], ["mpls"])


def flapping(times: list[str], dst: str = "198.51.100.6", system_ip: str = "10.255.0.1") -> list[str]:
    out = []
    for when in times:
        out += [row(system_ip, "down", when, 500, 500, dst=dst), row(system_ip, "down", when, deleted=1, dst=dst), row(system_ip, "up", when[:-2] + "59", dst=dst)]
    return out


def test_one_drop_is_information_and_a_few_are_low():
    one = run(("show sdwan bfd history", history(*flapping(["10/10/26 09:00:00"]))))
    assert finding(one, "RTR-SDW-080")["severity"] == "info"
    few = run(("show sdwan bfd history", history(*flapping(["10/10/26 09:00:00", "10/10/26 11:00:00"]))))
    assert finding(few, "RTR-SDW-080")["severity"] == "low"


def test_many_recent_drops_are_medium_and_old_ones_are_low():
    recent = run(("show sdwan bfd history", history(*flapping([f"10/{d:02d}/26 09:00:00" for d in (6, 7, 8, 9, 10)]))))
    item = finding(recent, "RTR-SDW-080")
    assert item["severity"] == "medium" and "5 time(s)" in item["title"] and "BFD tunnels toward 1 remote TLOC(s)" in item["title"]
    old = run(("show sdwan bfd history", history(*flapping([f"09/{d:02d}/26 09:00:00" for d in (6, 7, 8, 9, 10)]))))
    assert finding(old, "RTR-SDW-080")["severity"] == "low"


BFD_LIVE = """
                                      SOURCE TLOC      REMOTE TLOC                                      DST PUBLIC                      DST PUBLIC         DETECT      TX
SYSTEM IP        SITE ID     STATE       COLOR            COLOR            SOURCE IP                                       IP                                              PORT        ENCAP  MULTIPLIER  INTERVAL(msec) UPTIME      TRANSITIONS
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
10.255.0.1       910000      {state}          custom1          mpls             192.0.2.1                                       198.51.100.6                                    12426       ipsec  7           1000           0:00:00:00  2
"""


def test_a_tunnel_that_is_down_in_the_live_table_makes_old_drops_medium_and_the_last_history_record_alone_does_not():
    old = history(*flapping(["09/06/26 09:00:00", "09/07/26 09:00:00"]))
    down = run(("show sdwan bfd sessions", BFD_LIVE.format(state="down")), ("show sdwan bfd history", old))
    assert finding(down, "RTR-SDW-080")["severity"] == "medium" and "down in 'show sdwan bfd sessions'" in finding(down, "RTR-SDW-080")["detail"]
    up = run(("show sdwan bfd sessions", BFD_LIVE.format(state="up  ")), ("show sdwan bfd history", old))
    assert finding(up, "RTR-SDW-080")["severity"] == "low"
    rows = {r["remote"]: r for r in section(up, "sdwan_bfd_history_sessions")["rows"]}
    assert rows["10.255.0.1"]["live"] == "1 up" and rows["10.255.0.1"]["_tones"]["live"] == "ok"


def test_drops_that_hit_several_remotes_together_are_reported_with_their_colors():
    rows = []
    for day in (7, 8, 9):
        when = f"10/{day:02d}/26 09:00:00"
        rows += flapping([when]) + flapping([when], dst="198.51.100.14", system_ip="10.255.0.2")
    result = run(("show sdwan bfd history", history(*rows)))
    item = finding(result, "RTR-SDW-081")
    assert item["severity"] == "medium" and "3 time(s)" in item["title"] and "mpls" in item["object"]
    bursts = section(result, "sdwan_bfd_history_bursts")["rows"]
    assert len(bursts) == 3 and bursts[0]["sessions"] == 2


def test_empty_history_is_a_result_not_a_gap():
    result = run(("show sdwan bfd history", HISTORY_HEAD))
    row_ = next(c for c in result["coverage"] if c["command"] == "show sdwan bfd history")
    assert row_["status"] == "analyzed" and "no BFD session has changed state" in row_["note"]
    assert not [i for i in ids(result) if i.startswith(("RTR-SDW-080", "RTR-SDW-081"))]


# ---------------------------------------------------------------------------
# show license detail
# ---------------------------------------------------------------------------

LICENSE_DETAIL = """
Index: 1        Feature: adventerprise                     Version: 1.0
        License Type: Permanent
        License State: Active, In Use
        License Count: Non-Counted
        License Priority: Medium
        Store Index: 1
        Store Name: Primary License Storage
Index: 2        Feature: adventerprise                     Version: 1.0
        License Type: EvalRightToUse
        License State: Inactive
            Evaluation total period: 8  weeks 4  days
            Evaluation period left: 8  weeks 4  days
            Period used: 0  minute  0  second
        License Count: Non-Counted
        License Priority: None
        Store Index: 0
        Store Name: Built-In License Storage
Index: 3        Feature: advipservices                     Version: 1.0
        License Type: EvalRightToUse
        License State: Active, In Use
            Evaluation total period: 8  weeks 4  days
            Evaluation period left: 2  weeks 1  days
            Period used: 6  weeks 3  days
        License Count: Non-Counted
        License Priority: None
        Store Index: 1
        Store Name: Built-In License Storage
"""


def test_license_detail_reads_the_store_name_from_each_entry():
    data = rh.parse_license_detail(lines(LICENSE_DETAIL))
    assert data["command"] == "show license detail" and len(data["store"]) == 3
    first, second, third = data["store"]
    assert (first["store"], first["feature"], first["type"], first["state"]) == ("Primary License Storage", "adventerprise", "Permanent", "Active, In Use")
    assert (second["store"], second["eval_left"], second["eval_total"]) == ("Built-In License Storage", "8 weeks 4 days", "8 weeks 4 days")
    assert third["state"] == "Active, In Use" and third["eval_left"] == "2 weeks 1 days"


def test_license_detail_feeds_the_classic_licence_table_and_the_evaluation_finding():
    result = run(("show license detail", LICENSE_DETAIL))
    rows = section(result, "license_store")["rows"]
    assert len(rows) == 3 and {r["store"] for r in rows} == {"Primary License Storage", "Built-In License Storage"}
    item = finding(result, "RTR-HLT-054")
    assert item["severity"] == "low" and item["object"] == "advipservices" and "2 weeks 1 days" in item["detail"] and item["reference"] == REFS["classic_rtu_license"]


def test_an_evaluation_licence_that_is_not_in_use_raises_nothing():
    quiet = "\n".join(LICENSE_DETAIL.split("\n")[:15])
    assert "RTR-HLT-054" not in ids(run(("show license detail", quiet)))


# ---------------------------------------------------------------------------
# whole capture, collect lists, references
# ---------------------------------------------------------------------------


def test_a_whole_capture_is_analyzed_without_warnings_and_validates():
    result = run(("show sdwan omp summary", OMP_SUMMARY), ("show sdwan certificate installed", certificate_block()), ("show sdwan tunnel statistics", tunnels(*HEALTHY)),
                 ("show sdwan bfd history", history(*flapping(["10/10/26 09:00:00"]))), ("show license detail", LICENSE_DETAIL))
    assert not result["warnings"]
    validate_result(result)
    rows = {c["command"]: c["status"] for c in result["coverage"]}
    for command in ("show sdwan omp summary", "show sdwan certificate installed", "show sdwan tunnel statistics", "show sdwan bfd history", "show license detail"):
        assert rows[command] == "analyzed", command
    assert "SD-WAN overlay" in {s["group"] for s in result["sections"]}


def test_every_new_reference_is_a_cisco_page():
    for key in ("sdwan_troubleshoot_common", "sdwan_omp_summary_api", "sdwan_bfd_history_api", "sdwan_mtu_community", "classic_rtu_license"):
        assert REFS[key].startswith("https://") and "cisco.com" in REFS[key], key


def test_the_sdwan_collect_list_asks_for_the_new_commands_and_no_longer_calls_them_unverified():
    text = (ROOT / "static" / "collect-scripts" / "collect-router-cisco-sdwan.txt").read_text(encoding="utf-8")
    commands = [line.strip() for line in text.splitlines() if line.strip() and not line.startswith(("!", "#"))]
    for command in ("show sdwan omp summary", "show sdwan certificate installed", "show sdwan bfd history", "show sdwan tunnel statistics"):
        assert command in commands, command
    assert "UNVERIFIED" not in text
    classic = (ROOT / "static" / "collect-scripts" / "collect-router-cisco-ios-xe.txt").read_text(encoding="utf-8")
    assert "show license detail" in [line.strip() for line in classic.splitlines()]
