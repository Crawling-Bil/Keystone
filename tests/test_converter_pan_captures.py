"""Convert side of the PAN-OS terminal captures: detection, domain classification and which parser reads which shape.

Both captures are synthetic and shared with the analyzer tests (documentation address space, dummy serials).
"""

from __future__ import annotations

import os
import tempfile

import pytest

from features.configuration_studio.converter_engine import domains
from features.configuration_studio.converter_engine.detector import DeviceDetector
from features.configuration_studio.converter_engine.parsers.firewall.paloalto import PaloAltoFirewallParser
from tests import test_pan_cli_capture as curly
from tests import test_panos_runtime_capture as runtime


def _parse(text: str):
    handle = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, newline="", encoding="utf-8")
    try:
        handle.write(text)
        handle.close()
        return PaloAltoFirewallParser().parse_file(handle.name)
    finally:
        os.unlink(handle.name)


@pytest.fixture(scope="module")
def runtime_log() -> str:
    return runtime.build_log()


def test_detector_reads_both_captures_as_palo_alto_firewall(runtime_log):
    for text in (curly.CAPTURE, runtime_log):
        result = DeviceDetector().detect_text(text)
        assert (result.vendor, result.device_type) == ("Palo Alto", "Firewall")
        assert result.confidence >= 60


def test_domain_is_firewall_for_both_captures(runtime_log):
    for text in (curly.CAPTURE, runtime_log):
        guess = domains.classify(text)
        assert (guess.domain, guess.vendor) == ("firewall", "Palo Alto")


def test_curly_running_config_is_converted_not_read_as_runtime_state():
    """The capture also contains `show system info`, which looks like a runtime log; the configuration must win."""
    config = _parse(curly.CAPTURE)
    assert len(config.interfaces) == 2
    assert len(config.security_rules) == 2
    assert config.metadata["model"] == "PA-440"


def test_runtime_only_log_yields_identity_and_interfaces_but_no_policy(runtime_log):
    config = _parse(runtime_log)
    assert config.metadata["model"] == "PA-3020"
    assert config.metadata["sw_version"] == "9.0.5"
    assert len(config.interfaces) == 4
    assert config.security_rules == []


def test_terminal_log_with_crlf_and_redraws_parses_like_the_clean_text(runtime_log):
    clean = runtime_log.replace("\r\n", "\n")
    assert len(_parse(clean).interfaces) == len(_parse(runtime_log).interfaces)
