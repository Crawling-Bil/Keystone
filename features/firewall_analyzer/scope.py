"""Scope filter for the Firewall Analyzer tables: VDOM (FortiGate) or vsys (Palo Alto).

A FortiGate with several VDOMs - or a Palo Alto with several virtual systems - is really several firewalls in one
file: the same object name, rule number or route can exist in each of them.  Every table that carries a scope column
(``vdom`` / ``vsys``) gets a row of filter buttons built from the values in that table, with the number of rows for
each.  The selection is shared: choose ``CORP`` in the Policies tab and the Addresses, NAT and Routing tabs follow it
(``static/js/analyzer_kit.js``, facet option ``shared``).  The free-text filter box searches the scope column as well.

References: Fortinet, "Virtual Domains" in the FortiOS Administration Guide
https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/109991 ;
Palo Alto Networks, "Virtual Systems" https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/virtual-systems
"""

from __future__ import annotations

from typing import Any


def apply(sections: list[dict[str, Any]], key: str, label: str) -> int:
    """Add the shared scope filter to every table that has a ``key`` column; returns how many tables got it."""
    count = 0
    for section in sections:
        if section.get("kind") != "table" or not any(col["key"] == key for col in section.get("columns", [])):
            continue
        if any(f.get("key") == key for f in section.get("facets") or []):
            continue
        section["facets"] = [{"key": key, "label": label, "shared": True}] + list(section.get("facets") or [])
        for col in section["columns"]:
            if col["key"] == key and col.get("kind", "text") == "text":
                col["kind"] = "mono"                                           # names such as HQ-DL-FG must not wrap at the hyphens
        count += 1
    return count
