"""Port-based network access control (802.1X and MAC authentication bypass) read from Cisco IOS / IOS-XE interface commands.

A campus access switch carries the same dozen ``authentication ...`` / ``mab`` / ``dot1x ...`` lines on every user port (the OJK Catalyst 9300L
captures have them on 91 of 105 ports).  Translating them one line at a time buries the reader in hundreds of identical review markers, so the
lines of one port are read into a :class:`NacSettings` first; ports with identical settings share one target profile.

Target: Huawei CloudEngine S-series NAC (V600R025C00).  Every mapping below was checked in the Huawei documentation set the project keeps in
``Huawei Official Reference`` (Configuration Guide - User Access and Authentication, chapter NAC Configuration; the Command Reference .chm):

====================================================  ===========================================================================
Cisco                                                 Huawei VRP (view)
====================================================  ===========================================================================
``dot1x pae authenticator`` / ``order ... dot1x``     ``dot1x-access-profile`` bound with ``dot1x-access-profile <n>`` (authentication profile)
``mab``                                               ``mac-access-profile`` bound with ``mac-access-profile <n>``
``authentication order dot1x mab``                    ``authentication dot1x-mac-bypass`` (authentication profile): MAC authentication after
                                                      the 802.1X timeout (``dot1x timer mac-bypass-delay``, default 30 s)
``host-mode multi-auth``                              ``authentication mode multi-authen``
``host-mode multi-domain``                            ``authentication mode single-voice-with-data`` (one data + one voice user)
``host-mode multi-host``                              ``authentication mode multi-share``
``host-mode single-host``                             ``authentication mode single-terminal``
``authentication periodic``                           ``dot1x reauthenticate`` / ``mac-authen reauthenticate`` (access profiles)
``authentication timer reauthenticate <s>``           ``dot1x timer reauthenticate-period <s>`` (802.1X access profile)
``dot1x timeout tx-period <s>``                       ``dot1x timer tx-period <s>`` (system view: one value for the whole switch)
``event server alive action reinitialize``            ``authentication event authen-server-up action re-authen``
``event server dead action authorize``                ``authentication event authen-server-down action authorize vlan <port VLAN>``
====================================================  ===========================================================================

Not mapped, listed once per profile as a review item: ``timer reauthenticate server`` (period taken from the RADIUS Session-Timeout),
``event server dead action authorize voice``, ``order mab dot1x`` (MAB first), open authentication, violation, control-direction and anything unknown.

Documents: Huawei CloudEngine S3700, S5700 and S6700 V600R025C00 Configuration Guide - User Access and Authentication, "NAC Configuration":
https://support.huawei.com/enterprise/en/doc/EDOC1100333463  (the 802.1X + MAC examples also appear at
https://support.huawei.com/enterprise/en/doc/EDOC1000141870/c5852f72/example-for-configuring-mac-address-authentication-to-control-user-access).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

HOST_MODE = {
    "multi-auth": "multi-authen",
    "multi-domain": "single-voice-with-data",
    "multi-host": "multi-share",
    "single-host": "single-terminal",
}

# interface commands that belong to port authentication; matched on the whole command (``dot1x timeout tx-period 7``)
_NAC_PREFIXES = ("authentication ", "dot1x ", "mab")


@dataclass(frozen=True)
class NacSettings:
    dot1x: bool = False
    mab: bool = False
    host_mode: str = ""
    port_control: str = ""
    mab_fallback: bool = False          # order dot1x then mab: 802.1X first, MAC authentication when it fails or times out
    periodic: bool = False
    reauth_period: str = ""             # seconds, "" when the period comes from the server or is not set
    tx_period: str = ""                 # dot1x timeout tx-period (a switch-wide value on Huawei)
    server_dead: bool = False           # event server dead action authorize
    server_alive: bool = False          # event server alive action reinitialize
    access_vlan: int | None = None      # only part of the key when ``server_dead`` needs it
    notes: tuple[str, ...] = field(default_factory=tuple)    # lines with no generated equivalent, in source order

    @property
    def key(self) -> tuple:
        return (self.dot1x, self.mab, self.host_mode, self.port_control, self.mab_fallback, self.periodic, self.reauth_period,
                self.server_dead, self.server_alive, self.access_vlan if self.server_dead else None, self.notes)

    def mode(self) -> str:
        """The Huawei ``authentication mode`` keyword, or ``""`` when the source set no host mode (the Huawei default, multi-authen, applies)."""
        return HOST_MODE.get(self.host_mode, "")


def is_nac_command(command: str) -> bool:
    low = command.strip().lower()
    return low == "mab" or low.startswith(_NAC_PREFIXES)


def extract(commands: list[str], access_vlan: int | None = None) -> tuple[NacSettings | None, list[str]]:
    """``(settings, remaining_commands)``: the authentication lines of one interface read into settings, the others returned untouched.

    ``None`` when the interface has no port authentication at all.  A port with ``dot1x`` housekeeping only (no ``pae``, no ``mab``, no
    ``port-control auto``) gets settings with both methods off and the translator leaves its lines as review items."""
    remaining: list[str] = []
    seen = False
    dot1x = mab = periodic = server_dead = server_alive = False
    host_mode = port_control = reauth_period = tx_period = ""
    order: list[str] = []
    notes: list[str] = []
    for command in commands:
        low = re.sub(r"\s+", " ", command.strip().lower())
        if not is_nac_command(low):
            remaining.append(command)
            continue
        seen = True
        if low == "mab" or low.startswith("mab "):
            mab = True
            if low != "mab":
                notes.append(command.strip())        # mab eap / mab logging
        elif low.startswith("dot1x pae"):
            dot1x = dot1x or "authenticator" in low or low.endswith("both")
        elif low.startswith("dot1x timeout tx-period "):
            tx_period = low.split()[-1]
        elif low.startswith("authentication host-mode "):
            host_mode = low.split()[-1]
        elif low.startswith("authentication port-control "):
            port_control = low.split()[-1]
        elif low.startswith("authentication order "):
            order = low.split()[2:]
        elif low.startswith("authentication priority "):
            pass                                   # restates the order for the mab fallback; carried by "order"
        elif low == "authentication periodic":
            periodic = True
        elif low == "authentication timer reauthenticate server":
            notes.append(command.strip())          # the period comes from the server: reported once, no command
        elif re.fullmatch(r"authentication timer reauthenticate \d+", low):
            reauth_period = low.split()[-1]
        elif low == "authentication event server dead action authorize":
            server_dead = True
        elif re.fullmatch(r"authentication event server dead action authorize vlan \d+", low):
            server_dead = True
            access_vlan = int(low.split()[-1])         # the VLAN named in the command wins over the port's access VLAN
        elif low == "authentication event server alive action reinitialize":
            server_alive = True
        elif low == "authentication event fail action next-method":
            pass                                   # what the 802.1X-to-MAB fallback does: carried by "order dot1x mab"
        else:
            notes.append(command.strip())
    if not seen:
        return None, remaining
    if "dot1x" in order and port_control in ("", "auto"):
        dot1x = True
    if "mab" in order:
        mab = True
    mab_fallback = dot1x and mab and order[:2] == ["dot1x", "mab"] if order else (dot1x and mab)
    if order and order[:2] == ["mab", "dot1x"]:
        notes.append("authentication order mab dot1x")
    return NacSettings(dot1x=dot1x, mab=mab, host_mode=host_mode, port_control=port_control, mab_fallback=mab_fallback, periodic=periodic,
                       reauth_period=reauth_period, tx_period=tx_period, server_dead=server_dead, server_alive=server_alive,
                       access_vlan=access_vlan, notes=tuple(notes)), remaining


def compact_ports(names: list[str]) -> str:
    """``['Gi1/0/1', 'Gi1/0/2', 'Gi1/0/3', 'Gi2/0/1']`` -> ``Gi1/0/1-3, Gi2/0/1`` (consecutive numbers of the last field of one prefix)."""
    parsed: list[tuple[str, int, str]] = []
    for name in names:
        match = re.match(r"^(.*?)(\d+)$", name)
        parsed.append((match.group(1), int(match.group(2)), name) if match else (name, -1, name))
    out: list[str] = []
    index = 0
    while index < len(parsed):
        prefix, number, name = parsed[index]
        end = index
        while number >= 0 and end + 1 < len(parsed) and parsed[end + 1][0] == prefix and parsed[end + 1][1] == parsed[end][1] + 1:
            end += 1
        out.append(name if end == index else f"{name}-{parsed[end][1]}")
        index = end + 1
    return ", ".join(out)
