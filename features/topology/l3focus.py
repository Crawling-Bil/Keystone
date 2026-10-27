"""Which SD-WAN sites the L3 pages draw.

A hub router's BFD table lists every site of the fabric (hundreds of branches).  Drawing all of them makes the page unreadable for
someone who wants to look at three branches.  The default therefore draws only the sites the engineer **provided** (captured), and
summarises the others in one cloud ("+520 SD-WAN sites, not drawn") that still counts their BFD sessions.

Two controls:

* ``mode``: ``captured`` (default) draws the captured sites; ``all`` also draws a node for every site that only appears in a BFD table.
* ``sites``: a typed list (site ID, system IP, or a part of a host name).  When it is not empty only the sites it names are drawn, captured
  or not, and the hub sides they connect to; every other site is counted in the summary cloud.

The tables (SD-WAN overlay) always list every session, with a column that says whether the site is on the picture.

Cisco SD-WAN BFD, site ID and system IP: https://www.cisco.com/c/en/us/td/docs/routers/sdwan/configuration/sdwan-xe-gs-book/system-interface-profiles.html
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

MODES = ("captured", "all")
MORE_KEY = "SDWAN:more"
MAX_TOKENS = 200


def parse_sites(text: str) -> list[str]:
    """Tokens typed by the user: separated by commas, semicolons, spaces or new lines; duplicates and over-long words dropped."""
    seen: list[str] = []
    for token in re.split(r"[\s,;]+", text or ""):
        token = token.strip().strip("\"'")
        if token and len(token) <= 64 and token.lower() not in {t.lower() for t in seen}:
            seen.append(token)
    return seen[:MAX_TOKENS]


@dataclass
class Focus:
    mode: str = "captured"
    sites: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, mode: str = "captured", sites: str | list[str] | None = None) -> "Focus":
        tokens = parse_sites(sites) if isinstance(sites, str) else list(sites or [])
        return cls(mode if mode in MODES else "captured", tokens)

    @property
    def narrowed(self) -> bool:
        return bool(self.sites)

    def names(self, system_ip: str = "", site_id: str = "", host: str = "") -> bool:
        """Does the typed list name this site?  Site ID and system IP must be equal; a host name matches by part (3 letters or more)."""
        if not self.sites:
            return False
        for token in self.sites:
            low = token.lower()
            if low == str(system_ip).lower() or low == str(site_id).lower():
                return True
            if host and len(low) >= 3 and low in host.lower():
                return True
        return False

    def draws(self, system_ip: str, site_id: str, host: str, captured: bool, local: tuple[str, str, str] = ("", "", "")) -> bool:
        """Is the remote end of a session drawn?  ``captured``: the remote system IP belongs to a captured device; ``local``: (system IP, site ID, host) of the end that reported it."""
        if self.narrowed:
            return self.names(system_ip, site_id, host) or (captured and self.names(*local))
        return captured or self.mode == "all"

    def text(self) -> str:
        return f"{'every site in the BFD tables' if self.mode == 'all' else 'captured sites only'}" + (f"; listed: {', '.join(self.sites)}" if self.sites else "")
