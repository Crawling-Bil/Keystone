"""Sizing Tool: the throughput figure a replacement firewall is sized on follows what the rules do to the traffic.  Invented configurations only."""

from __future__ import annotations

from features.sizing_tool import fwprofile, plan
from features.sizing_tool.common import new_asset

FORTI_PLAIN = """config firewall policy
    edit 1
        set name "lan-out"
        set action accept
    next
end
"""
FORTI_UTM = FORTI_PLAIN.replace("end\n", "") + """    edit 2
        set name "web"
        set ips-sensor "default"
        set av-profile "default"
        set ssl-ssh-profile "certificate-inspection"
    next
end
"""
FORTI_DEEP = """config firewall ssl-ssh-profile
    edit "corp-deep"
        set https deep-inspection
    next
    edit "certificate-inspection"
        set https certificate-inspection
    next
end
""" + FORTI_UTM.replace("end\n", "") + """    edit 3
        set name "decrypted"
        set application-list "default"
        set ssl-ssh-profile "corp-deep"
    next
end
"""
FORTI_APP = FORTI_PLAIN.replace("    next\nend\n", "        set application-list \"default\"\n    next\nend\n")
PAN_SET = """set rulebase security rules allow-web application web-browsing
set rulebase security rules allow-web profile-setting profiles virus default
set rulebase security rules allow-dns application dns
set rulebase security rules block-all action deny
"""
PAN_DECRYPT = PAN_SET + "set rulebase decryption rules outbound action decrypt\nset rulebase decryption rules skip-bank action no-decrypt\n"
PAN_XML = """<config><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"><rulebase><security><rules>
<entry name="r1"><from><member>a</member></from><profile-setting><group><member>strict</member></group></profile-setting></entry>
<entry name="r2"><from><member>a</member></from><application><member>dns</member></application></entry>
</rules></security><decryption><rules><entry name="d1"><action>decrypt</action></entry><entry name="d2"><action>no-decrypt</action></entry></rules></decryption></rulebase></entry></vsys></entry></devices></config>"""


def fw(vendor, counts, **kw):
    asset = new_asset(hostname="TEST-FW", device_type="firewall", vendor=vendor, model="X", serial="S123456789")
    asset["inspection"] = counts
    asset.update(kw)
    return asset


def test_fortigate_without_profiles_is_sized_on_the_headline_figure():
    counts = fwprofile.read_inspection(FORTI_PLAIN, "Fortinet")
    assert counts == {"policies": 1, "threat": 0, "application": 0, "decrypt": 0} and fwprofile.level_of(counts) == "firewall"


def test_fortigate_with_ips_and_antivirus_is_sized_on_threat_protection():
    counts = fwprofile.read_inspection(FORTI_UTM, "Fortinet")
    assert counts["threat"] == 1 and counts["decrypt"] == 0 and fwprofile.level_of(counts) == "threat"


def test_a_policy_with_application_control_only_is_the_ngfw_level():
    assert fwprofile.level_of(fwprofile.read_inspection(FORTI_APP, "Fortinet")) == "application"


def test_deep_inspection_wins_over_threat_but_certificate_inspection_does_not_count():
    counts = fwprofile.read_inspection(FORTI_DEEP, "Fortinet")
    assert counts["decrypt"] == 1 and counts["policies"] == 3 and fwprofile.level_of(counts) == "decrypt"
    assert fwprofile.read_inspection(FORTI_UTM, "Fortinet")["decrypt"] == 0


def test_pan_os_set_format_counts_profiles_applications_and_decrypt_rules():
    counts = fwprofile.read_inspection(PAN_SET, "Palo Alto")
    assert counts == {"policies": 3, "threat": 1, "application": 1, "decrypt": 0} and fwprofile.level_of(counts) == "threat"
    deep = fwprofile.read_inspection(PAN_DECRYPT, "Palo Alto")
    assert deep["decrypt"] == 1 and fwprofile.level_of(deep) == "decrypt"


def test_pan_os_xml_format_reads_the_decryption_rulebase_and_profile_groups():
    counts = fwprofile.read_inspection(PAN_XML, "Palo Alto")
    assert counts["decrypt"] == 1 and counts["threat"] == 1 and counts["application"] == 1


def test_an_unreadable_capture_leaves_the_level_undecided_instead_of_failing():
    assert fwprofile.read_inspection("garbage ((( {{{", "Palo Alto")["decrypt"] == 0
    assert fwprofile.read_inspection("anything", "Cisco") == {}
    assert fwprofile.recommend(new_asset(hostname="X", device_type="firewall", vendor="Cisco"))["level"] == ""


def test_the_recommendation_names_the_datasheet_column_and_the_peak_figure_to_enter():
    rec = fwprofile.recommend(fw("Fortinet", {"policies": 3, "threat": 2, "application": 0, "decrypt": 0}))
    assert rec["label"] == "Peak threat-prevention throughput (Mbit/s)" and rec["datasheet"] == "Threat Protection Throughput" and not rec["have_peak"]
    assert any("No peak figure for this level" in w for w in rec["why"])
    rec = fw("Palo Alto", {"policies": 3, "threat": 2, "application": 0, "decrypt": 1})
    assert fwprofile.recommend(rec)["label"] == "Peak SSL-inspected throughput (Mbit/s)"


def test_a_headline_peak_is_flagged_when_the_rules_inspect():
    asset = fw("Fortinet", {"policies": 3, "threat": 2, "application": 0, "decrypt": 0}, peaks={"Peak throughput (Mbit/s)": {"value": 900, "unit": "Mbit/s", "source": "manual", "window": ""}})
    assert any("plain 'Peak throughput'" in w for w in fwprofile.recommend(asset)["why"])
    asset["peaks"]["Peak threat-prevention throughput (Mbit/s)"] = {"value": 400, "unit": "Mbit/s", "source": "manual", "window": ""}
    rec = fwprofile.recommend(asset)
    assert rec["have_peak"] and not any("plain" in w for w in rec["why"])


def test_the_plan_of_a_group_uses_the_highest_level_of_any_member():
    plain, deep = fw("Fortinet", {"policies": 1, "threat": 0, "application": 0, "decrypt": 0}), fw("Fortinet", {"policies": 3, "threat": 1, "application": 0, "decrypt": 1})
    plain["id"], deep["id"] = "d1", "d2"
    plan_rows = plan.replacement_plan([plain, deep], {}, 0)
    basis = plan_rows[0]["sizing_basis"]
    assert basis["level"] == "decrypt" and basis["devices"] == 2


def test_new_peak_fields_are_offered_for_a_firewall_and_import_from_a_csv_header():
    from features.sizing_tool.catalog import PEAK_FIELDS
    from features.sizing_tool.imports import _peak_label
    assert _peak_label("Threat prevention throughput (Gbps)")[0] == "Peak threat prevention throughput (Mbit/s)"
    assert _peak_label("Peak threat-prevention throughput (Gbps)")[0] == "Peak threat-prevention throughput (Mbit/s)"
    assert "Peak threat-prevention throughput (Mbit/s)" in PEAK_FIELDS["firewall"] and "Peak SSL-inspected throughput (Mbit/s)" in PEAK_FIELDS["firewall"]


def test_a_differently_spelled_imported_column_is_recognised_for_its_level():
    asset = fw("Palo Alto", {"policies": 2, "threat": 1, "application": 0, "decrypt": 1}, peaks={"Peak SSL decryption throughput (Mbit/s)": {"value": 300, "unit": "Mbit/s", "source": "csv", "window": ""}})
    rec = fwprofile.recommend(asset)
    assert rec["have_peak"] and rec["label"] == "Peak SSL decryption throughput (Mbit/s)"
    asset["inspection"] = {"policies": 2, "threat": 1, "application": 0, "decrypt": 0}
    assert not fwprofile.recommend(asset)["have_peak"]               # an SSL figure is not the threat-prevention figure
