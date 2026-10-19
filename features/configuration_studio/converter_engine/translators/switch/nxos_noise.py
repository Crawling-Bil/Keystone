"""NX-OS global lines that carry no configuration for a converted device.

These are skipped instead of being listed as review items, because every item in a review list costs a person a look:

* ``!Command:`` / ``!Running configuration`` / ``!Time:`` / ``version 10.4(5) Bios:version ...`` are the banner of ``show running-config`` itself;
* ``vdc NAME id 1`` and ``limit-resource ...`` describe the virtual-device carve-up of a Nexus chassis (a fixed Nexus 9300 has one VDC,
  and resource limits have no target equivalent);
* ``feature interface-vlan`` / ``lacp`` / ``vpc`` / ``hsrp`` only switch a function on.  The function's own configuration (SVIs, LACP bundles,
  vPC domain, HSRP groups) is converted separately, so the enabler adds nothing a person must decide.  Features without a conversion
  (``feature ospf``, ``feature bgp``, ``feature sla`` ...) stay in the review list.
"""
from __future__ import annotations

_BANNER_PREFIXES = ("!Command:", "!Running configuration", "!Time:", "version ", "vdc ", "limit-resource ")
_ENABLERS = {"feature interface-vlan", "feature lacp", "feature vpc", "feature hsrp"}


def is_noise(command: str, converted_features: tuple[str, ...] = ()) -> bool:
    """True for a global line that needs no review.  ``converted_features`` adds target-specific enablers (``"feature netflow"`` where flow export converts)."""
    text = command.strip()
    return text.startswith(_BANNER_PREFIXES) or text in _ENABLERS or text in converted_features
