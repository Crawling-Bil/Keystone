"""Renders the per-device VRP bootstrap config (.cfg) pushed as the CFG
deployment file during ZTP.

WHY THIS FILE MATTERS: Huawei's own doc is explicit that "the
configuration file for deployment [must] contain the console password
or an AAA user name that can be used to log in to the device remotely.
Otherwise, the configuration file cannot be successfully set, causing a
deployment failure." In other words this is the one artifact that
actually replaces the manual console step — everything else in the ZTP
pipeline just gets this file onto the device. If it's wrong, the
device deploys "successfully" but stays unreachable, which is worse
than an outright ZTP failure because it looks fine in the logs.

IMPORTANT CAVEAT — read before trusting this in production:
Huawei's own documented workflow for preparing the deployment config
file is NOT "hand-write VRP CLI text like this module does" — it's
"configure one real device fully via console/SSH the way you want
every unit to end up, then run `save shareable-configuration
<file> [password]` on it and export that file." That matters because
things like RSA key-pair material and AAA password hashing are
version- and platform-sensitive.

CONFIRMED against real hardware (S5735, V600R024C00SPC500): `rsa
local-key-pair create` does NOT apply cleanly from a ZTP-pushed batch
config. It is a runtime ACTION (an interactive Y/N + key-length
prompt on a live CLI), not a persisted config directive, and it
re-attempts key generation every time it appears in an applied config
-- even when a key pair already exists on the device. When ZTP applies
it, VRP surfaces `<error-tag>invalid-value</error-tag>` from the YANG
apply step, and the device then refuses to accept the whole file as
next-startup config at all ("The configuration file will cause the
next startup login failure."), even though the rest of the file
(telnet, AAA, VTY) would otherwise be fine on its own. Because of
this, this module deliberately does NOT emit `rsa local-key-pair
create` — see the comment above `stelnet server enable` below. SSH
only becomes usable after someone runs that command interactively,
once, at the console — that's a real per-device manual step, not
something ZTP can do for you on this platform.

Treat the output of this module as a starting draft to validate against
one spare/lab switch, not as a config to push to production hardware
sight-unseen. The more reliable path for anything this module gets
wrong on your specific VRP build is: configure one reference unit by
hand once, `save shareable-configuration` it, and adapt THAT exported
file per device (swap sysname/IP/local-user) instead of generating
from scratch here.
"""

from __future__ import annotations

import ipaddress
import re

_HOSTNAME_SANITIZE_RE = re.compile(r"[^A-Za-z0-9_-]+")
# VRP startup-configs are strictly line-oriented -- one directive per
# line, "#" as a section separator, "return" as the terminator. Every
# field below gets interpolated RAW into an f-string line (see the
# lines list further down); a value containing a newline or carriage
# return would inject extra, fat-finger- (or attacker-) controlled
# lines into the generated config -- e.g. a password field containing
# "x" followed by a newline and "telnet server enable" would silently
# add a real command. hostname is already immune (run through
# _sanitize_sysname's alnum/-/_ allowlist below) but
# mgmt_ip/mgmt_mask/gateway/username/password are not, and previously
# had NO validation at all -- confirmed by reading render_bootstrap_
# config() end to end, not from any real hardware symptom, but this
# is exactly the class of bug ("state that's correct in isolation but
# wrong given how it's used downstream") that turns into a multi-hour
# mystery ZTP failure days later when a pasted password happens to
# carry a stray newline.
_CONTROL_CHAR_RE = re.compile(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f]")


class ConfigTemplateError(ValueError):
    pass


def _sanitize_sysname(hostname):
    name = _HOSTNAME_SANITIZE_RE.sub("-", hostname).strip("-")
    if not name:
        raise ConfigTemplateError(f"Could not derive a valid sysname from hostname {hostname!r}.")
    return name[:64]


def _require_no_control_characters(field_name, value):
    if value and _CONTROL_CHAR_RE.search(value):
        raise ConfigTemplateError(
            f"device.{field_name} contains a newline or control character, which "
            "would inject extra lines into the generated VRP config file (VRP "
            "startup-configs are line-oriented -- one directive per line). "
            f"Remove it from {field_name} and try again."
        )


def _require_valid_ipv4(field_name, value):
    _require_no_control_characters(field_name, value)
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise ConfigTemplateError(
            f"device.{field_name} = {value!r} is not a valid IPv4 address."
        ) from exc


def render_bootstrap_config(device, mgmt_vlan=1, vty_count=5):
    """Build a VRP startup-config text for one pre-registered device.

    device: a dict as returned by core.store.list_devices() —
        requires hostname, mgmt_ip, mgmt_mask, vrp_username,
        vrp_password; gateway is optional (added as a static route
        if present).
    mgmt_vlan: the VLANIF used for management. Defaults to 1 because
        that's the VLAN ZTP itself uses for its own temporary DHCP
        request (confirmed in the vendor doc), so the config that
        replaces the temporary DHCP lease keeps using the same
        VLANIF rather than introducing a new one the device has no
        route to yet.
    vty_count: how many VTY lines (0..vty_count-1) to open for SSH.

    Returns the config text, ending with a bare `return` as VRP
    startup-configs conventionally do.
    """
    hostname = (device.get("hostname") or "").strip()
    mgmt_ip = (device.get("mgmt_ip") or "").strip()
    mgmt_mask = (device.get("mgmt_mask") or "255.255.255.0").strip()
    username = (device.get("vrp_username") or "").strip()
    password = device.get("vrp_password") or ""
    gateway = (device.get("gateway") or "").strip()

    if not hostname:
        raise ConfigTemplateError("device.hostname is required.")
    if not mgmt_ip:
        raise ConfigTemplateError("device.mgmt_ip is required.")
    if not username:
        raise ConfigTemplateError("device.vrp_username is required.")
    if not password:
        raise ConfigTemplateError(
            "device.vrp_password is required — without it the device has no way "
            "to be logged into remotely after ZTP (see module docstring)."
        )

    # Every field below is interpolated raw into a config line -- see
    # the _CONTROL_CHAR_RE comment above. hostname doesn't need this
    # (it only ever reaches the config through _sanitize_sysname's
    # alnum/-/_ allowlist, which already strips anything dangerous).
    _require_valid_ipv4("mgmt_ip", mgmt_ip)
    _require_valid_ipv4("mgmt_mask", mgmt_mask)
    if gateway:
        _require_valid_ipv4("gateway", gateway)
    _require_no_control_characters("vrp_username", username)
    _require_no_control_characters("vrp_password", password)

    sysname = _sanitize_sysname(hostname)

    lines = [
        "#",
        f"sysname {sysname}",
        "#",
        # Local AAA user used for both stelnet (SSH) login and as the
        # fallback account for NES's own SSH-based discovery afterward.
        #
        # `local-aaa-user user-name complexity-check disable` is a
        # deliberate choice, not an oversight: Huawei's default AAA
        # local-user complexity check rejects short usernames (this
        # was confirmed against real hardware -- a 4-character
        # username like "mlpt" is refused with it enabled). Disabling
        # it is a real, if small, security trade-off (VRP's complexity
        # rules exist to push toward stronger local accounts) -- it's
        # accepted here because short, consistent ZTP usernames were
        # an explicit choice, and this is a staging-bootstrap account,
        # not the production credential the device may end up using
        # once actual operations takes it over. Command order below
        # matches a set already verified against real hardware rather
        # than a from-scratch guess.
        "aaa",
        " local-aaa-user user-name complexity-check disable",
        # `irreversible-cipher` IS the correct keyword here, and it
        # DOES take a plaintext password (VRP hashes it itself,
        # irreversibly, at rest) -- confirmed against real hardware:
        # `local-user <name> password ?` on this VRP build (S5735,
        # V600R024C00SPC500) offers ONLY `irreversible-cipher`, no
        # `cipher` keyword exists at all here. An earlier version of
        # this module used `password cipher`, on the theory that
        # `irreversible-cipher` expected an already-hashed value --
        # that theory was wrong, and `cipher` isn't even valid syntax
        # on this platform. The real, confirmed root cause of ZTP
        # config-apply failures was `rsa local-key-pair create` (see
        # module docstring and the comment above `stelnet server
        # enable` below), not this line.
        f" local-user {username} password irreversible-cipher {password}",
        f" local-user {username} password-force-change disable",
        f" local-user {username} privilege level 3",
        f" local-user {username} service-type ssh telnet",  # telnet fallback -- see comment above stelnet server enable
        " quit",
        "#",
        # stelnet (SSH server) is OFF by default on a factory device.
        # Declared here so it's ready to go the moment someone runs
        # `rsa local-key-pair create` for real at the console -- but
        # note that command is deliberately NOT included below (see
        # module docstring): it's a runtime action, not a config
        # directive, and pushing it through ZTP was confirmed on real
        # hardware to make VRP reject the ENTIRE deployment file
        # ("The configuration file will cause the next startup login
        # failure."), even though everything else in the file
        # (telnet, AAA, VTY) is fine on its own. So until someone
        # does that one manual step per device, this local-user has
        # NO working SSH login -- telnet, below, is the actual
        # ZTP-provisioned login path.
        "stelnet server enable",
        # telnet is the login path ZTP can actually deliver
        # end-to-end, for the SAME local-user, since SSH needs an RSA
        # key this module can't safely generate (see above). VRP also
        # requires the WEAKEA feature-software package to be installed
        # before `telnet server enable` will even take effect
        # (confirmed on real hardware: without it, this command is
        # rejected outright with "This protocol is insecure. To use
        # it, please execute the command install feature-software
        # WEAKEA.") -- like the RSA key, that's a one-time, per-device
        # manual bootstrap step (`install feature-software WEAKEA` at
        # the console) this module can't perform through a config
        # file.
        #
        # CORRECTION (confirmed against real hardware, a later test
        # session on the same unit): an earlier version of this
        # comment claimed the RSA key pair and WEAKEA installation
        # "persist across `reset saved-configuration`... so ZTP
        # re-provisioning that SAME unit afterward is unaffected."
        # That is NOT reliable. On this exact device, after several
        # `reset saved-configuration` + reboot cycles, `display rsa
        # local-key-pair public` came back "Local key pair is not
        # generated" -- the key was gone, and ZTP failed at exactly
        # this same "next startup login failure" check as a result,
        # even with `rsa local-key-pair create` correctly absent from
        # the pushed config. Whether it was `reset
        # saved-configuration` itself, an intervening factory reset,
        # or something else in the reboot path that cleared it was
        # not isolated. Bottom line: do NOT assume RSA key-pair /
        # WEAKEA state survives between ZTP test cycles on the same
        # unit -- re-verify both (`display rsa local-key-pair public`,
        # and probing `telnet server enable` for the WEAKEA error)
        # before every reset+reboot test, not just the first time.
        "telnet server enable",
        f"ssh user {username} authentication-type password",
        f"ssh user {username} service-type stelnet",
        "#",
        f"interface Vlanif{mgmt_vlan}",
        f" ip address {mgmt_ip} {mgmt_mask}",
        "#",
    ]

    if gateway:
        lines += [
            f"ip route-static 0.0.0.0 0.0.0.0 {gateway}",
            "#",
        ]

    lines += [
        f"user-interface vty 0 {max(0, vty_count - 1)}",
        " authentication-mode aaa",
        " protocol inbound all",  # ssh + telnet fallback -- see comment above stelnet server enable
        " user privilege level 3",
        "#",
        "return",
        "",
    ]

    return "\n".join(lines)
