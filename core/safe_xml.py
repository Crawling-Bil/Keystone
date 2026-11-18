"""XML from a file somebody uploaded is read here, never with the standard parser directly.

The standard-library parser can be made to expand an entity declaration into gigabytes ("billion laughs") or to read a local
file through an external entity.  Current expat limits some of that, but a safety rule that depends on the interpreter version
is not a rule.  :func:`fromstring` refuses any DOCTYPE or entity declaration (a PAN-OS or Panorama configuration export and a
draw.io file never contain one) and otherwise returns the same ``xml.etree.ElementTree.Element`` the standard parser returns.

A refusal is raised as ``xml.etree.ElementTree.ParseError``, the exception every caller already handles for a file that is not
well-formed, so a hostile file becomes the same clean "not readable" message as a truncated one.

Docs: https://docs.python.org/3/library/xml.html#xml-vulnerabilities and https://pypi.org/project/defusedxml/
"""
from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as _defused

__all__ = ["fromstring", "ParseError"]


def fromstring(text: str | bytes) -> Element:
    """Parse ``text`` (str or bytes) into an Element; refuse DOCTYPE, entity declarations and external references."""
    try:
        return _defused.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as error:
        raise ParseError(f"XML with a DOCTYPE or entity declaration is refused ({type(error).__name__}).") from error
