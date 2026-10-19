"""Target-fit check: does the chosen target model have a port for every port the source really uses?

Synthetic fixtures only (NM8X is an invented C9300-48P + 8x10G module config).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from features.configuration_studio.service import convert_file

FIXTURES = Path(__file__).parent / "fixtures" / "switch"
NM8X = FIXTURES / "c9300_48p_nm8x_synthetic.txt"


CONFIG = """hostname SW-FIT-LAB
!
interface GigabitEthernet1/0/2
 description lab-host
 switchport mode access
 switchport access vlan 10
!
interface GigabitEthernet1/0/30
 description lab-host-2
 switchport mode access
 switchport access vlan 10
!
interface TenGigabitEthernet1/1/1
 description lab-uplink
 switchport mode trunk
!
vlan 10
 name LAB
!
end
"""


@pytest.fixture()
def lab(tmp_path):
    path = tmp_path / "SW-FIT-LAB.txt"
    path.write_text(CONFIG, encoding="utf-8")
    return path


def _fit(target_model, vendor="Huawei", source=None):
    result = convert_file(source or NM8X, target_vendor=vendor, target_model=target_model, domain="switch")
    return result["interface_map"]["fit"]


def test_fit_counts_add_up_and_name_the_ports_that_do_not_fit(lab):
    fit = _fit("S5735-S24T4XE-V2", source=lab)
    assert fit["verdict"] in ("partial", "does-not-fit")
    assert fit["used"] == fit["mapped"] + fit["missing"] and fit["missing"] >= 1
    assert fit["missing_ports"] and all({"source", "note"} <= set(p) for p in fit["missing_ports"])
    assert sum(fit["needs"].values()) == fit["used"]


def test_a_model_with_enough_ports_reports_alternatives_that_really_fit(lab):
    fit = _fit("S5735-S24T4XE-V2", source=lab)
    names = {a["model"] for a in fit["alternatives"]}
    assert names and "S5735-S24T4XE-V2" not in names
    for model in names:                       # every suggested model must itself report 'fits'
        assert _fit(model, source=lab)["verdict"] == "fits"


def test_no_target_model_means_unknown_not_a_guess(lab):
    fit = _fit("", source=lab)
    assert fit["verdict"] == "unknown" and fit["alternatives"] == []


def test_fitting_target_has_no_missing_ports(lab):
    fits = [a["model"] for a in _fit("S5735-S24T4XE-V2", source=lab)["alternatives"]]
    fit = _fit(fits[0], source=lab)
    assert fit["missing"] == 0 and fit["missing_ports"] == [] and fit["alternatives"] == []


def test_the_banner_renderer_is_in_the_page_script():
    root = Path(__file__).parent.parent
    assert "renderTargetFit" in (root / "static/js/configuration.js").read_text(encoding="utf-8")
    assert 'id="interface-map-fit"' in (root / "templates/configuration.html").read_text(encoding="utf-8")
