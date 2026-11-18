"""Uploaded XML is read with entity expansion and external references refused (core/safe_xml.py).

Every file here is an invented attack document: a "billion laughs" expansion, an external entity that names a local file, and
a plain DOCTYPE.  The standard parser would expand the first, so the test also pins that each reader answers quickly with its
own clean "not readable" result instead of hanging or filling memory.
"""
from __future__ import annotations

import time
from xml.etree.ElementTree import ParseError

import pytest

from core import safe_xml

BILLION_LAUGHS = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
]>
<config version="10.1"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>&lol6;</hostname></system></deviceconfig></entry></devices></config>
"""

EXTERNAL_ENTITY = """<?xml version="1.0"?>
<!DOCTYPE config [ <!ENTITY secret SYSTEM "file:///etc/hostname"> ]>
<config version="10.1"><devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>&secret;</hostname></system></deviceconfig></entry></devices></config>
"""

PLAIN_DOCTYPE = """<?xml version="1.0"?>
<!DOCTYPE config>
<config version="10.1"><devices><entry name="localhost.localdomain"/></devices></config>
"""

CLEAN = '<config version="10.1"><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1"/></vsys></entry></devices></config>'
ATTACKS = {"billion-laughs": BILLION_LAUGHS, "external-entity": EXTERNAL_ENTITY, "plain-doctype": PLAIN_DOCTYPE}


def test_a_clean_document_parses_to_the_standard_element():
    root = safe_xml.fromstring(CLEAN)
    assert root.tag == "config" and root.get("version") == "10.1"
    assert root.find("devices/entry").get("name") == "localhost.localdomain"
    assert type(root).__module__ == "xml.etree.ElementTree"


def test_bytes_are_accepted_like_text():
    assert safe_xml.fromstring(CLEAN.encode("utf-8")).tag == "config"


@pytest.mark.parametrize("name", ATTACKS)
def test_an_attack_document_is_refused_quickly_as_a_parse_error(name):
    started = time.perf_counter()
    with pytest.raises(ParseError):
        safe_xml.fromstring(ATTACKS[name])
    assert time.perf_counter() - started < 2


def test_an_unclosed_document_is_still_an_ordinary_parse_error():
    with pytest.raises(ParseError):
        safe_xml.fromstring("<config><devices>")


# ---------------------------------------------------------------- each reader answers with its own clean result

@pytest.mark.parametrize("name", ATTACKS)
def test_the_panorama_reader_refuses_an_attack_document(name):
    from features.firewall_analyzer import panorama_parse
    with pytest.raises(ValueError, match="Not well-formed XML"):
        panorama_parse.parse(ATTACKS[name])


@pytest.mark.parametrize("name", ATTACKS)
def test_the_pan_os_converter_reader_refuses_an_attack_document(name):
    from features.configuration_studio.converter_engine.parsers.firewall.paloalto_xml import PaloAltoXmlConfigParser, PaloAltoXmlParseError
    with pytest.raises(PaloAltoXmlParseError):
        PaloAltoXmlConfigParser().parse_text(ATTACKS[name])


@pytest.mark.parametrize("name", ATTACKS)
def test_the_extra_readers_treat_an_attack_document_as_not_pan_os(name):
    from features.firewall_analyzer import panorama_fusion, panos_xml_extra
    from features.topology import panolink
    assert panos_xml_extra.extract(ATTACKS[name]) is None
    assert panorama_fusion._pan_device(ATTACKS[name]) is None
    assert panolink._xml_root(ATTACKS[name]) is None


@pytest.mark.parametrize("name", ATTACKS)
def test_the_secret_hider_does_not_expand_an_attack_document(name):
    from features.configuration_studio.converter_engine.fwconvert import mask
    started = time.perf_counter()
    text = mask.mask_source(ATTACKS[name])
    assert time.perf_counter() - started < 2
    assert "lollollol" not in text and "root:" not in text


@pytest.mark.parametrize("name", ATTACKS)
def test_the_two_readers_that_looked_for_a_doctype_first_still_refuse_it(name):
    from features.configuration_studio.converter_engine.fwconvert import pan_read
    from features.topology import layout_io
    with pytest.raises(ValueError):
        pan_read.tree_from_xml(ATTACKS[name])
    with pytest.raises(ValueError):
        layout_io.read_layout(ATTACKS[name].encode("utf-8"))
