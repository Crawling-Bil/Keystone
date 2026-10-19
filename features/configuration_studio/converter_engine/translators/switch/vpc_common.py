"""vPC role helper shared by the switch translators.

NX-OS elects the vPC primary peer by the *lower* ``role priority`` (default 32667): Cisco, "Understand the vPC Election Process"
(https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/212589-understanding-vpc-election-process.html).
Huawei M-LAG elects the DFS-group master by the *higher* ``priority`` (default 100), so the number cannot be copied across:
only the direction (primary or secondary) is derived from the source and the number is chosen on the target's own scale.
"""
from __future__ import annotations

NXOS_DEFAULT_ROLE_PRIORITY = 32667


def vpc_role(priority):
    """``"primary"`` / ``"secondary"`` from an NX-OS ``role priority`` value; ``None`` when unset or left at the default."""
    if priority is None:
        return None
    if priority < NXOS_DEFAULT_ROLE_PRIORITY:
        return "primary"
    if priority > NXOS_DEFAULT_ROLE_PRIORITY:
        return "secondary"
    return None
