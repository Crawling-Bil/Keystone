"""Router findings.

Each rule is a small function ``rule(ctx) -> list[finding]`` registered with
:func:`rule`.  A rule only fires on evidence present in the capture: a rule
that needs ``show ip route`` stays silent when the route table was not
collected (the Coverage tab says what is missing), it never guesses.

Severity guide
  high    a security exposure or a service that is down / mis-configured
  medium  weak practice or a defect that will bite under failure
  low     hygiene / cleanup
  info    worth knowing, no action required
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Callable

from ..analyzer_core.findings import dedupe_findings, finding as F, sort_findings
from . import xref as xr
from .context import Ctx, bgp_sessions as bgp_runtime
from .netutil import is_ipv4
from .refs import REFS as R

RULES: list[Callable[[Ctx], list[dict[str, Any]]]] = []


def rule(func: Callable[[Ctx], list[dict[str, Any]]]):
    RULES.append(func)
    return func


def evaluate(ctx: Ctx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for func in RULES:
        try:
            out.extend(func(ctx) or [])
        except Exception as exc:  # one broken rule must not hide the others
            ctx.warnings.append(f"Findings rule {func.__name__} failed ({type(exc).__name__}: {exc}).")
    return sort_findings(dedupe_findings(out))


def _names(items: list[str], limit: int = 8) -> str:
    items = list(items)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" … (+{len(items) - limit} more)"


_ORDER = ["low", "medium", "high"]


def _worse(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def _cfg(ctx: Ctx) -> dict[str, Any]:
    return ctx.cfg or {}


# ---------------------------------------------------------------------------
# Management plane
# ---------------------------------------------------------------------------


@rule
def mgmt_privileged_secrets(ctx: Ctx):
    if ctx.cfg is None:
        return []
    system = ctx.cfg["system"]
    out = []
    if system["enable_password"] and not system["enable_secret"]:
        out.append(F("RTR-SEC-001", "high", "Credentials", "Only a reversible 'enable password' protects privileged mode",
                     detail="'enable password' is stored in clear text or as a type 7 string that can be decoded in seconds.",
                     recommendation="Configure 'enable algorithm-type scrypt secret <pw>' (type 9) or at least 'enable secret', then remove 'enable password'.",
                     reference=R["password_types"]))
    elif system["enable_password"]:
        out.append(F("RTR-SEC-002", "medium", "Credentials", "Legacy 'enable password' is still configured next to 'enable secret'",
                     detail="The enable secret takes precedence, but the reversible password remains in the configuration and backups.",
                     recommendation="Remove it with 'no enable password'.", reference=R["password_types"]))
    if system["enable_secret"] and system["enable_secret_strength"] == "weak":
        out.append(F("RTR-SEC-003", "medium", "Credentials", f"Enable secret uses {system['enable_secret_type']}",
                     detail="Type 5 is a salted MD5 hash. Cisco recommends type 8 (PBKDF2-SHA256) or type 9 (scrypt) where the release supports it.",
                     recommendation="'enable algorithm-type scrypt secret <new-password>' (IOS 15.3(3)/IOS-XE 3.9 and later).",
                     reference=R["passwords_privileges"]))
    if not system["enable_secret"] and not system["enable_password"]:
        out.append(F("RTR-SEC-004", "medium", "Credentials", "No enable secret configured",
                     detail="Privileged mode is not protected by a local secret; it then depends entirely on AAA or line privilege 15.",
                     recommendation="Configure an enable secret as a break-glass credential.", reference=R["passwords_privileges"]))
    return out


@rule
def mgmt_local_users(ctx: Ctx):
    out = []
    for user in _cfg(ctx).get("users", []):
        if user["credential"] == "none":
            out.append(F("RTR-SEC-005", "high", "Credentials", f"Local user '{user['user']}' has no password", obj=user["user"],
                         recommendation="Remove the user or set a type 8/9 secret.", reference=R["passwords_privileges"]))
            continue
        storage = user["storage"]
        if storage.startswith("clear") or storage.startswith("Vigenere"):
            out.append(F("RTR-SEC-006", "high", "Credentials", f"Local user '{user['user']}' stored as {storage}", obj=user["user"],
                         detail=f"Privilege {user['privilege']}, credential keyword '{user['credential']}'. Clear text and type 7 are recoverable by anyone who can read the config or a backup.",
                         recommendation="Re-create the user with 'username <u> algorithm-type scrypt secret <pw>'.", reference=R["password_types"]))
        elif user["strength"] == "weak":
            out.append(F("RTR-SEC-007", "medium", "Credentials", f"Local user '{user['user']}' stored as {storage}", obj=user["user"],
                         detail=f"Privilege {user['privilege']}.", recommendation="Prefer type 8 or 9 ('algorithm-type sha256|scrypt secret').",
                         reference=R["passwords_privileges"]))
    return out


@rule
def mgmt_password_encryption(ctx: Ctx):
    if ctx.cfg is None:
        return []
    cleartext_lines = [l["line"] for l in ctx.cfg["lines"] if l.get("password") and "clear" in l["password"]]
    if cleartext_lines and not ctx.cfg["system"]["service_password_encryption"]:
        return [F("RTR-SEC-008", "medium", "Credentials", "Line passwords are in clear text and service password-encryption is off",
                  obj=", ".join(cleartext_lines), recommendation="Use AAA / local users with secrets; 'service password-encryption' is only a minimum.",
                  reference=R["harden_ios"])]
    return []


@rule
def mgmt_vty(ctx: Ctx):
    out = []
    for line in _cfg(ctx).get("lines", []):
        name = line["line"]
        if not name.startswith("vty"):
            # console / aux: only the idle-session check applies (physical access is the threat, so it is a low finding)
            timeout = line["exec_timeout"].split()
            if name.startswith(("con", "aux")) and timeout and all(item == "0" for item in timeout):
                out.append(F("RTR-MGT-003", "low", "Management access", f"No exec-timeout on {name}", obj=name,
                             detail="'exec-timeout 0 0' keeps an unattended console session logged in, including privileged mode.",
                             recommendation="'exec-timeout 10 0' (console) so an abandoned session is closed.", reference=R["harden_ios"]))
            continue
        transport = line["transport_input"].split()
        if "telnet" in transport or "all" in transport or transport == ["(default)"]:
            out.append(F("RTR-MGT-001", "high", "Management access", f"Telnet is allowed on {name}", obj=name,
                         detail=f"transport input = {line['transport_input']}. The default on vty lines is every protocol, including clear-text Telnet.",
                         recommendation="'transport input ssh' on every vty range, plus 'ip ssh version 2'.", reference=R["ssh"]))
        if not line["access_class"]:
            out.append(F("RTR-MGT-002", "medium", "Management access", f"No access-class on {name}", obj=name,
                         detail="Any source address that can reach the router can attempt to log in.",
                         recommendation="'access-class <mgmt-acl> in' (with 'vrf-also' if management is in a VRF).", reference=R["harden_ios"]))
        timeout = line["exec_timeout"].split()
        if timeout and all(item == "0" for item in timeout):
            out.append(F("RTR-MGT-003", "medium", "Management access", f"No exec-timeout on {name}", obj=name,
                         detail="'exec-timeout 0 0' leaves abandoned sessions open indefinitely.",
                         recommendation="'exec-timeout 10 0' or shorter.", reference=R["harden_ios"]))
    return out


@rule
def mgmt_ssh(ctx: Ctx):
    out = []
    if ctx.cfg is not None:
        vty_ssh = any("ssh" in l["transport_input"].split() or l["transport_input"] in ("all", "(default)") for l in ctx.cfg["lines"] if l["line"].startswith("vty"))
        version = ctx.cfg["system"]["ssh_version"]
        if vty_ssh and version != "2":
            out.append(F("RTR-MGT-004", "medium", "Management access", "SSH version 2 is not enforced",
                         detail=f"'ip ssh version' = {version or 'not set'}. Without it IOS accepts SSHv1 clients in compatibility mode.",
                         recommendation="'ip ssh version 2' (requires an RSA key of at least 768 bits; use 2048).", reference=R["ssh"]))
    ssh = ctx.get("ip_ssh")
    if ssh and ssh.get("enabled") and ssh.get("dh_min_bits") and ssh["dh_min_bits"] < 2048:
        out.append(F("RTR-MGT-013", "low", "Management access", f"SSH key exchange accepts a Diffie-Hellman group as small as {ssh['dh_min_bits']} bits",
                     obj=f"{ssh['dh_min_bits']} bits",
                     detail="'show ip ssh' reports the smallest DH modulus the device will still negotiate for key exchange. A 1024-bit finite-field DH group "
                            "(diffie-hellman-group1-sha1 / group14 at 1024 bits) is below what NIST SP 800-56A now treats as an adequate security strength.",
                     recommendation="'ip ssh dh min size 2048' so only Diffie-Hellman groups of at least 2048 bits are accepted.", reference=R["ssh"]))
    return out


@rule
def mgmt_http(ctx: Ctx):
    if ctx.cfg is None:
        return []
    system = ctx.cfg["system"]
    out = []
    if system["http_server"]:
        out.append(F("RTR-MGT-005", "medium", "Management access", "Clear-text HTTP server is enabled",
                     recommendation="'no ip http server'; keep 'ip http secure-server' only if needed and restrict it with 'ip http access-class'.",
                     reference=R["harden_ios"]))
    if system["http_secure_server"]:
        out.append(F("RTR-MGT-006", "info", "Management access", "HTTPS management server is enabled",
                     recommendation="Confirm it is needed (RESTCONF/web UI) and restricted with 'ip http access-class'.", reference=R["harden_ios"]))
    return out


@rule
def mgmt_legacy_services(ctx: Ctx):
    if ctx.cfg is None:
        return []
    system = ctx.cfg["system"]
    enabled = [name for name, key in (("tcp-small-servers", "tcp_small_servers"), ("udp-small-servers", "udp_small_servers"),
                                       ("finger", "finger"), ("bootp server", "bootp_server"), ("pad", "pad")) if system.get(key)]
    out = []
    if enabled:
        out.append(F("RTR-MGT-007", "medium", "Management access", "Legacy services are enabled: " + ", ".join(enabled),
                     recommendation="Disable each with the 'no' form of the command.", reference=R["harden_ios"]))
    if system["source_route"] is not False:
        out.append(F("RTR-MGT-008", "low", "Management access", "IP source routing is not disabled",
                     detail="'ip source-route' is on by default; 'no ip source-route' does not appear in the configuration.",
                     recommendation="'no ip source-route'.", reference=R["harden_ios"]))
    if system["domain_lookup"] and not system["name_servers"]:
        out.append(F("RTR-MGT-009", "low", "Management access", "DNS lookup is enabled but no name server is configured",
                     detail="A mistyped command is treated as a host name and the console hangs while broadcasting.",
                     recommendation="'no ip domain-lookup' or configure 'ip name-server'.", reference=R["harden_ios"]))
    if system["cdp_run"] is not False:
        out.append(F("RTR-MGT-010", "info", "Management access", "CDP is enabled globally",
                     detail="CDP advertises model, software and addresses to anything that listens on a link.",
                     recommendation="'no cdp run' or 'no cdp enable' on interfaces facing carriers, DMZ or end users.", reference=R["harden_ios"]))
    return out


@rule
def mgmt_aaa(ctx: Ctx):
    if ctx.cfg is None:
        return []
    aaa = ctx.cfg["aaa"]
    out = []
    if not aaa["new_model"]:
        out.append(F("RTR-AAA-001", "medium", "AAA", "AAA is not enabled ('aaa new-model' missing)",
                     detail="Logins use line passwords or local users only; no central accounting of who changed what.",
                     recommendation="Enable AAA with TACACS+/RADIUS and a 'local' fallback.", reference=R["aaa"]))
        return out
    kinds = {m["kind"] for m in aaa["methods"]}
    if "aaa authentication login" not in kinds:
        out.append(F("RTR-AAA-002", "medium", "AAA", "No 'aaa authentication login' method list", recommendation="Define a login list with TACACS+/RADIUS then local.", reference=R["aaa"]))
    for method in aaa["methods"]:
        text = method["methods"]
        if method["kind"].startswith("aaa authentication") and text and ("group" in text) and "local" not in text and "none" not in text:
            out.append(F("RTR-AAA-003", "low", "AAA", f"Method list '{method['list'] or 'default'}' has no local fallback", obj=method["list"],
                         detail="If every AAA server is unreachable nobody can log in (console included unless it uses a different list).",
                         recommendation="Append 'local' to the method list and keep one break-glass local user.", reference=R["aaa"]))
    if not any(kind.startswith("aaa accounting") for kind in kinds):
        out.append(F("RTR-AAA-004", "low", "AAA", "No AAA accounting configured", recommendation="'aaa accounting exec' and 'aaa accounting commands 15' to a TACACS+ group.", reference=R["aaa"]))
    for server in aaa["servers"]:
        if server["key"] and server["key_type"] in ("0", "7"):
            out.append(F("RTR-AAA-005", "low", "AAA", f"AAA server {server['address'] or server['name']} key stored as type {server['key_type']}",
                         obj=server["address"] or server["name"], recommendation="Use 'key 6' with 'key config-key password-encrypt' and 'password encryption aes'.",
                         reference=R["harden_ios"]))
    return out


@rule
def mgmt_snmp(ctx: Ctx):
    if ctx.cfg is None:
        return []
    snmp = ctx.cfg["snmp"]
    out = []
    for community in snmp["communities"]:
        label = f"community #{community['index']} ({community['mode']})"
        if community["guessable"]:
            out.append(F("RTR-SNMP-001", "high", "SNMP", f"SNMP {label} uses a guessable name", obj=label,
                         recommendation="Remove it; use SNMPv3 with authPriv.", reference=R["snmp"]))
        if community["mode"] == "RW":
            out.append(F("RTR-SNMP-002", "high", "SNMP", f"SNMP {label} allows write access", obj=label,
                         detail="Write access over SNMPv1/v2c lets a sniffed or guessed string change the configuration.",
                         recommendation="Remove the RW community; manage with SSH/NETCONF or SNMPv3.", reference=R["snmp"]))
        if not community["acl"]:
            out.append(F("RTR-SNMP-003", "medium", "SNMP", f"SNMP {label} is not restricted by an ACL", obj=label,
                         recommendation="Append the NMS ACL to the community statement.", reference=R["snmp"]))
    if snmp["communities"]:
        out.append(F("RTR-SNMP-004", "low", "SNMP", f"{len(snmp['communities'])} SNMPv1/v2c community string(s) in use",
                     detail="Community strings travel in clear text and are not authenticated per user.",
                     recommendation="Migrate to SNMPv3 (auth + priv) and remove the communities.", reference=R["snmp"]))
    for group in snmp["groups"]:
        if group["version"] == "v3" and group["level"] == "noauth":
            out.append(F("RTR-SNMP-005", "high", "SNMP", f"SNMPv3 group '{group['name']}' uses noAuthNoPriv", obj=group["name"],
                         recommendation="Use 'v3 priv' for read and write groups.", reference=R["snmp"]))
        elif group["version"] == "v3" and group["level"] == "auth":
            out.append(F("RTR-SNMP-006", "info", "SNMP", f"SNMPv3 group '{group['name']}' authenticates but does not encrypt", obj=group["name"],
                         recommendation="'v3 priv' adds encryption of the payload.", reference=R["snmp"]))
    return out


@rule
def mgmt_logging_ntp(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    logging = ctx.cfg["logging"]
    ntp = ctx.cfg["ntp"]
    if not logging["hosts"]:
        out.append(F("RTR-LOG-001", "low", "Logging", "No remote syslog server",
                     detail="Local buffers are lost on reload and are small on busy routers.",
                     recommendation="'logging host <ip>' with 'logging source-interface' and 'logging trap informational'.", reference=R["harden_ios"]))
    if not ctx.cfg["system"]["timestamps_log"]:
        out.append(F("RTR-LOG-002", "low", "Logging", "Log timestamps are not configured",
                     recommendation="'service timestamps log datetime msec localtime show-timezone year'.", reference=R["harden_ios"]))
    if not ntp["servers"]:
        out.append(F("RTR-NTP-001", "medium", "Time", "No NTP server configured",
                     detail="Log correlation, certificate validity, Kerberos and IPsec lifetimes need a correct clock.",
                     recommendation="Configure at least two 'ntp server' entries and 'ntp source'.", reference=R["ntp"]))
    elif len(ntp["servers"]) == 1:
        out.append(F("RTR-NTP-002", "low", "Time", "Only one NTP server configured", recommendation="Add a second server (three is the usual minimum for a majority).", reference=R["ntp"]))
    if ntp["servers"] and not ntp["authenticate"]:
        out.append(F("RTR-NTP-003", "low", "Time", "NTP authentication is not enabled",
                     recommendation="'ntp authenticate' with 'ntp authentication-key' / 'ntp trusted-key' where the servers support it.", reference=R["ntp"]))
    return out


@rule
def ntp_live_health(ctx: Ctx):
    """'show ntp status' / 'show ntp associations' are judged on their own, independent of
    whether ctx.cfg exists — a redacted or partial capture that still has the live NTP
    commands should still get these findings."""
    out = []
    status = ctx.get("ntp_status")
    if status and status.get("synchronized") is False:
        out.append(F("RTR-NTP-004", "medium", "Time", "NTP is configured but the clock is not synchronised",
                     detail=status.get("raw", ""), recommendation="Check reachability to the servers ('show ntp associations') and ACLs.", reference=R["ntp"]))
    assoc = ctx.get("ntp_associations") or []
    unreachable = [a for a in assoc if a["configured"] and not a["reachable"]]
    if unreachable:
        all_down = len(unreachable) == len(assoc)
        out.append(F("RTR-NTP-005", "medium" if all_down else "low", "Time",
                     "No configured NTP server has ever been reached" if all_down else f"{len(unreachable)} of {len(assoc)} configured NTP server(s) have never been reached",
                     obj=", ".join(a["address"] for a in unreachable),
                     detail="; ".join(f"{a['address']}: stratum {a['stratum']}, reach {a['reach']} (octal reachability register — 0 means not one poll in the last 8 has succeeded)" for a in unreachable),
                     recommendation="Confirm the address, routing/VRF reachability and any 'ntp access-group' toward it." +
                                    ("" if all_down else " The clock is still synchronised through the other server(s) for now, so this is a lost-redundancy finding, not an outage, until the remaining server also fails."),
                     reference=R["ntp"]))
    return out


@rule
def mgmt_banner_copp(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    system = ctx.cfg["system"]
    if not system["has_banner"]:
        out.append(F("RTR-MGT-011", "low", "Management access", "No login banner", recommendation="'banner login' with an authorised-use notice.", reference=R["harden_ios"]))
    if not system["control_plane_policy"]:
        out.append(F("RTR-MGT-012", "low", "Management access", "No control-plane policy (CoPP) configured",
                     detail="The route processor is reachable by any traffic addressed to the router.",
                     recommendation="Attach a policy to 'control-plane' that rate-limits management, routing-protocol and ICMP traffic.", reference=R["copp"]))
    return out


_STAMP = re.compile(r"(\d{1,2}:\d{2}:\d{2})(?:\.\d+)?\s+\S+\s+(?:\w{3}\s+)?(\w{3})\s+(\d{1,2})\s+(\d{4})")


def _parse_stamp(text: str) -> datetime | None:
    match = _STAMP.search(text or "")
    if not match:
        return None
    try:
        return datetime.strptime(f"{match.group(1)} {match.group(2)} {match.group(3)} {match.group(4)}", "%H:%M:%S %b %d %Y")
    except ValueError:
        return None


@rule
def sys_unsaved(ctx: Ctx):
    if ctx.cfg is None:
        return []
    system = ctx.cfg["system"]
    changed, saved = _parse_stamp(system["last_change"]), _parse_stamp(system["nvram_updated"])
    if changed and saved and changed > saved:
        return [F("RTR-SYS-001", "medium", "Configuration", "Running-config has changes that are not saved to startup-config",
                  detail=f"Last configuration change: {system['last_change']}. NVRAM last updated: {system['nvram_updated']}.",
                  recommendation="Review 'show archive config differences' and 'write memory' once verified; a reload would lose them.", reference=R["harden_ios"])]
    return []


# ---------------------------------------------------------------------------
# Interfaces
# ---------------------------------------------------------------------------


def _iface_label(rec: dict[str, Any]) -> str:
    return rec["name"]


@rule
def if_health(ctx: Ctx):
    out = []
    for rec in ctx.interfaces:
        stats = rec.get("stats")
        if not stats:
            continue
        name = rec["name"]
        cleared = stats.get("counters_cleared") or "never"
        in_packets = stats.get("in_packets") or 0
        errors = stats.get("input_errors") or 0
        if errors >= 100:
            ratio = errors / in_packets * 100 if in_packets else 0
            parts = [f"{label} {stats[key]:,}" for key, label in (("crc", "CRC"), ("frame", "frame"), ("overrun", "overrun"), ("ignored", "ignored"), ("runts", "runts"), ("giants", "giants")) if stats.get(key)]
            breakdown = ("Breakdown: " + ", ".join(parts) + ". ") if parts else "No CRC/frame/overrun/ignored breakdown is non-zero. "
            out.append(F("RTR-IF-001", "medium", "Interface health", f"{name}: {errors:,} input errors", obj=name,
                         detail=f"{ratio:.4f}% of {in_packets:,} input packets. {breakdown}Counters cleared: {cleared}. CRC/frame errors point at cabling, optics, or a duplex/speed mismatch; 'ignored' means the input queue was full.",
                         recommendation="Check optics/cable, compare duplex and speed on both ends, clear counters and watch whether they still grow.",
                         reference=R["interface_troubleshooting"]))
        drops = stats.get("output_drops") or 0
        if drops >= 100:
            out.append(F("RTR-IF-002", "low", "Interface health", f"{name}: {drops:,} output drops", obj=name,
                         detail=f"Counters cleared: {cleared}. Output drops mean egress congestion or a too-small queue/shaper.",
                         recommendation="Review QoS/shaping on this link and the 'show policy-map interface' counters.", reference=R["interface_troubleshooting"]))
        if (stats.get("duplex") or "").lower().startswith("half"):
            out.append(F("RTR-IF-003", "medium", "Interface health", f"{name}: half duplex", obj=name,
                         recommendation="Fix the duplex/speed mismatch ('speed'/'duplex' on both ends, or auto on both).", reference=R["interface_troubleshooting"]))
        busiest = max(stats.get("in_util_pct") or 0, stats.get("out_util_pct") or 0)
        if busiest >= 80:
            out.append(F("RTR-IF-004", "medium", "Interface health", f"{name}: {busiest:.0f}% utilised (5-minute average)", obj=name,
                         recommendation="Plan capacity or shaping; sustained load above 80% causes queueing delay.", reference=R["qos"]))
    return out


@rule
def if_state(ctx: Ctx):
    out = []
    down = []
    for rec in ctx.interfaces:
        cfg, brief = rec.get("config"), rec.get("brief")
        if not cfg or not brief:
            continue
        if not cfg["shutdown"] and (cfg["ip_address"] or cfg["description"]) and brief.get("protocol") == "down" and brief.get("status") != "administratively down":
            down.append(f"{rec['name']} ({brief['status']}/{brief['protocol']})")
    if down:
        out.append(F("RTR-IF-005", "medium", "Interface health", f"{len(down)} enabled interface(s) with an address or description are down", obj=_names(down),
                     detail="Not shut down administratively, yet no carrier / no keepalive.", recommendation="Confirm the circuit/peer state, or 'shutdown' unused interfaces.",
                     reference=R["interface_troubleshooting"]))
    return out


@rule
def if_addressing(ctx: Ctx):
    interfaces = [r["config"] for r in ctx.interfaces if r.get("config") and r["config"]["ip_address"] and not r["config"]["shutdown"]]
    out = []
    seen: dict[tuple[str, str], str] = {}
    networks = []
    for iface in interfaces:
        try:
            interface = ipaddress.ip_interface(iface["ip_address"])
        except ValueError:
            continue
        key = (iface["vrf"], str(interface.ip))
        if key in seen:
            out.append(F("RTR-IF-006", "high", "Addressing", f"Duplicate IP address {interface.ip} on {seen[key]} and {iface['name']}", obj=iface["name"],
                         detail="VRF " + (iface["vrf"] or "global") + ".", recommendation="Re-address one interface.", reference=R["harden_ios"]))
        else:
            seen[key] = iface["name"]
        if interface.network.prefixlen < 32:
            networks.append((iface["vrf"], interface.network, iface["name"]))
    for index, (vrf, net, name) in enumerate(networks):
        for vrf2, net2, name2 in networks[index + 1:]:
            if vrf == vrf2 and net != net2 and net.overlaps(net2):
                out.append(F("RTR-IF-007", "medium", "Addressing", f"Overlapping subnets: {name} {net} and {name2} {net2}", obj=f"{name} / {name2}",
                             detail="VRF " + (vrf or "global") + ". Overlapping connected subnets make routing ambiguous.", recommendation="Renumber or move one into its own VRF.",
                             reference=R["harden_ios"]))
    return out


@rule
def if_tunnel_protection(ctx: Ctx):
    out = []
    for iface in _cfg(ctx).get("interfaces", []):
        tunnel = iface["tunnel"]
        if iface["name"].startswith("Tunnel") and tunnel and tunnel.get("mode") not in ("sdwan",) and not iface["tunnel_protection"] and "ipsec" not in (tunnel.get("mode") or ""):
            out.append(F("RTR-IF-008", "low", "VPN", f"{iface['name']}: tunnel has no IPsec protection", obj=iface["name"],
                         detail=f"Tunnel mode '{tunnel.get('mode') or 'gre (default)'}' source {tunnel.get('source') or '?'}; payload crosses the transport in clear text.",
                         recommendation="'tunnel protection ipsec profile <name>' unless the underlay is private and trusted.", reference=R["ipsec"]))
    return out


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


def _rib_index(ctx: Ctx) -> dict[tuple[str, str, str], dict[str, Any]]:
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for route in ctx.routes:
        vrf = "" if route["vrf"] == "global" else route["vrf"]
        index[(vrf, route["prefix"], route["protocol"])] = route
    return index


@rule
def route_static_installed(ctx: Ctx):
    if ctx.cfg is None or not ctx.has("routes"):
        return []
    index = _rib_index(ctx)
    vrfs_with_table = {("" if t["vrf"] == "global" else t["vrf"]) for t in ctx.route_tables}
    out = []
    for route in ctx.cfg["static_routes"]:
        if route["vrf"] not in vrfs_with_table or route["discard"]:
            continue
        key = (route["vrf"], route["prefix"], "Static")
        if key in index:
            continue
        if (route["vrf"], route["prefix"], "Connected") in index:
            continue
        distance = int(route["distance"]) if str(route["distance"]).isdigit() else 1
        target = route["next_hop"] or route["interface"]
        label = f"{route['prefix']} via {target}" + (f" (vrf {route['vrf']})" if route["vrf"] else "")
        extra = f" Tracked by object {route['track']}." if route["track"] else ""
        if distance > 1:
            out.append(F("RTR-RTE-001", "info", "Routing", f"Backup static route not installed: {label} (AD {distance})", obj=label,
                         detail="A floating static route is expected to stay out of the RIB while a better route exists." + extra,
                         recommendation="Nothing to do unless this route is meant to carry traffic now.", reference=R["bgp"]))
        else:
            out.append(F("RTR-RTE-002", "medium", "Routing", f"Static route configured but not in the routing table: {label}", obj=label,
                         detail="Its next hop is unreachable, the outgoing interface is down, a track object is down, or a more specific/lower-AD route wins." + extra,
                         recommendation="Check 'show ip route <next-hop>' and the interface/track state.", reference=R["bgp"]))
    return out


@rule
def route_default(ctx: Ctx):
    if not ctx.has("routes"):
        return []
    glob = next((t for t in ctx.route_tables if t["vrf"] == "global"), None)
    if glob is None:
        return []
    if not glob.get("gateway_of_last_resort") and not any(r["prefix"] == "0.0.0.0/0" for r in glob["routes"]):
        return [F("RTR-RTE-003", "info", "Routing", "No default route in the global routing table",
                  detail="'Gateway of last resort is not set'.", recommendation="Expected on a core/transit router; unusual on a branch or edge router.", reference=R["bgp"])]
    return []


@rule
def bgp_sessions(ctx: Ctx):
    out = []
    runtime = {(n["neighbor"], n.get("vrf", "")): n for n in bgp_runtime(ctx)}
    cfg_neighbors = {}
    for process in _cfg(ctx).get("bgp", []):
        for neighbor in process["neighbors"]:
            if not neighbor["is_peer_group"]:
                cfg_neighbors[(neighbor["neighbor"], neighbor.get("vrf", ""))] = (process, neighbor)
    for key, session in runtime.items():
        label = f"neighbor {key[0]} (AS {session['remote_as']})"
        cfg = cfg_neighbors.get(key, (None, {}))[1]
        shut = session.get("admin_shutdown") or cfg.get("shutdown")
        if session["state"] != "Established":
            if shut:
                out.append(F("RTR-BGP-001", "info", "BGP", f"{label} is administratively shut down", obj=key[0],
                             detail=f"State {session['state']}; last reset: {session.get('last_reset') or 'n/a'}.",
                             recommendation="Remove the neighbor if it is permanently retired.", reference=R["bgp"]))
            else:
                out.append(F("RTR-BGP-002", "high", "BGP", f"{label} is not Established ({session['state']})", obj=key[0],
                             detail=f"Last reset: {session.get('last_reset') or 'n/a'}. Description: {session.get('description') or cfg.get('description') or 'none'}.",
                             recommendation="Check reachability to the peer, TCP/179, AS number, MD5 password and the neighbor's side.", reference=R["bgp"]))
        elif session.get("prefixes_received") == 0:
            out.append(F("RTR-BGP-003", "low", "BGP", f"{label} is Established but sends no prefixes", obj=key[0],
                         recommendation="Confirm the peer should advertise nothing, or check its outbound policy.", reference=R["bgp"]))
    return out


@rule
def bgp_hygiene(ctx: Ctx):
    out = []
    for process in _cfg(ctx).get("bgp", []):
        asn = process["asn"]
        for neighbor in process["neighbors"]:
            if neighbor["shutdown"]:
                continue
            name = neighbor["neighbor"]
            kind = neighbor["type"]
            label = f"{'peer-group' if neighbor['is_peer_group'] else 'neighbor'} {name}"
            if kind == "eBGP" or (neighbor["is_peer_group"] and neighbor["remote_as"] and neighbor["remote_as"] != asn):
                if not any(neighbor.get(k) for k in ("route_map_in", "prefix_list_in", "filter_list_in", "distribute_list_in")):
                    out.append(F("RTR-BGP-010", "high", "BGP policy", f"eBGP {label} has no inbound route filter", obj=name,
                                 detail="Everything the peer announces is accepted: a leak or hijack propagates straight into your routing table.",
                                 recommendation="Attach a prefix-list / route-map (or at least a maximum-prefix) inbound.", reference=R["bgp_protect"]))
                if not any(neighbor.get(k) for k in ("route_map_out", "prefix_list_out", "filter_list_out", "distribute_list_out")):
                    out.append(F("RTR-BGP-011", "medium", "BGP policy", f"eBGP {label} has no outbound route filter", obj=name,
                                 detail="Anything in the BGP table, including routes learned from other peers, is advertised to this neighbor.",
                                 recommendation="Advertise only your own prefixes with an outbound prefix-list / filter-list.", reference=R["bgp_protect"]))
                if not neighbor["maximum_prefix"]:
                    out.append(F("RTR-BGP-012", "medium", "BGP policy", f"eBGP {label} has no maximum-prefix limit", obj=name,
                                 recommendation="'neighbor <ip> maximum-prefix <n> 80 [restart <min>]'.", reference=R["bgp_neighbor_options"]))
                if not neighbor["password"] and not neighbor["ttl_security"]:
                    out.append(F("RTR-BGP-013", "medium", "BGP policy", f"eBGP {label} session is not protected (no MD5 / TTL security)", obj=name,
                                 detail="A spoofed TCP RST or OPEN can reset the session.",
                                 recommendation="'neighbor <ip> password <key>' (or TCP-AO where supported) and 'neighbor <ip> ttl-security hops 1' for directly connected peers.",
                                 reference=R["bgp_neighbor_options"]))
            elif kind == "iBGP" and not neighbor["update_source"] and not neighbor["is_peer_group"]:
                out.append(F("RTR-BGP-014", "low", "BGP policy", f"iBGP {label} has no update-source", obj=name,
                             detail="Sessions sourced from a physical interface drop when that interface fails.",
                             recommendation="'neighbor <ip> update-source Loopback0'.", reference=R["bgp_neighbor_options"]))
        if process["synchronization"] is True:
            out.append(F("RTR-BGP-015", "low", "BGP policy", f"BGP {asn}: synchronization is enabled", recommendation="'no synchronization' (obsolete outside special designs).", reference=R["bgp"]))
        if process["auto_summary"] is True:
            out.append(F("RTR-BGP-016", "medium", "BGP policy", f"BGP {asn}: auto-summary is enabled", detail="Networks are summarised to classful boundaries and attract traffic for addresses you do not own.",
                         recommendation="'no auto-summary'.", reference=R["bgp"]))
        if not process["log_neighbor_changes"]:
            out.append(F("RTR-BGP-017", "low", "BGP policy", f"BGP {asn}: neighbor changes are not logged", recommendation="'bgp log-neighbor-changes'.", reference=R["bgp"]))
    return out


@rule
def bgp_rib_failures(ctx: Ctx):
    table = ctx.get("bgp_table")
    if not table:
        return []
    failed = [p for p in table["paths"] if p["rib_failure"]]
    if not failed:
        return []
    prefixes = sorted({p["network"] for p in failed})
    return [F("RTR-BGP-020", "medium", "BGP", f"{len(prefixes)} BGP prefix(es) are in RIB-failure", obj=_names(prefixes, 6),
              detail="BGP selected a best path, but the routing table did not install it, usually because another protocol has a lower administrative distance for the same prefix "
                     "(for example OSPF 110 against iBGP 200), or a more specific route already exists.",
              recommendation="Compare 'show ip bgp <prefix>' with 'show ip route <prefix>'; adjust distance/weight or remove the competing route.",
              reference=R["bgp_rib_failure"])]


@rule
def bgp_redistribution(ctx: Ctx):
    cfg = _cfg(ctx)
    out = []
    bgp_into_igp = []
    igp_into_bgp = []
    for process in cfg.get("ospf", []):
        for redistribute in process["redistribute"]:
            if redistribute.startswith("bgp"):
                bgp_into_igp.append((f"ospf {process['process']}", redistribute))
    for process in cfg.get("bgp", []):
        for redistribute in process["redistribute"]:
            if redistribute.split()[0] in ("ospf", "eigrp", "isis", "rip"):
                igp_into_bgp.append((f"bgp {process['asn']}", redistribute))
            if "route-map" not in redistribute:
                out.append(F("RTR-BGP-021", "medium", "Redistribution", f"bgp {process['asn']}: 'redistribute {redistribute}' has no route-map", obj=redistribute,
                             detail="Every route of that source enters BGP unfiltered.", recommendation="Redistribute through a route-map with a prefix-list.", reference=R["bgp"]))
    for process in cfg.get("ospf", []):
        for redistribute in process["redistribute"]:
            if "route-map" not in redistribute and not redistribute.startswith("connected") and not redistribute.startswith("static"):
                out.append(F("RTR-OSPF-010", "medium", "Redistribution", f"ospf {process['process']}: 'redistribute {redistribute}' has no route-map", obj=redistribute,
                             recommendation="Redistribute through a route-map that filters and tags.", reference=R["ospf"]))
    if bgp_into_igp and igp_into_bgp:
        guarded = all("route-map" in text for _, text in bgp_into_igp + igp_into_bgp)
        out.append(F("RTR-BGP-022", "info" if guarded else "medium", "Redistribution", "Mutual redistribution between BGP and an IGP",
                     detail="Routes can be re-injected into the protocol they came from and loop or flap. "
                            + ("Both directions use route-maps; verify they match on tags or prefixes that break the loop." if guarded else "At least one direction has no route-map."),
                     obj="; ".join(f"{a}: {b}" for a, b in bgp_into_igp + igp_into_bgp)[:300],
                     recommendation="Tag routes at the first redistribution point and deny that tag at the reverse point.", reference=R["bgp"]))
    return out


@rule
def ospf_hygiene(ctx: Ctx):
    cfg = _cfg(ctx)
    out = []
    iface_auth = any((i["ospf"] or {}).get("authentication") or (i["ospf"] or {}).get("message-digest-key") for i in cfg.get("interfaces", []))
    fastest = max([int(i["bandwidth_kbps"]) for i in cfg.get("interfaces", []) if str(i["bandwidth_kbps"]).isdigit()] + [0])
    for process in cfg.get("ospf", []):
        name = f"ospf {process['process']}"
        if not process["router_id"]:
            out.append(F("RTR-OSPF-001", "low", "OSPF", f"{name}: router-id is not set explicitly", detail="The ID follows the highest loopback/interface address and can change on a reload.",
                         recommendation="'router-id <loopback-address>'.", reference=R["ospf"]))
        if not process["authentication"] and not iface_auth:
            out.append(F("RTR-OSPF-002", "low", "OSPF", f"{name}: no OSPF authentication", detail="Any router that can join a segment can form an adjacency and inject routes.",
                         recommendation="'area <n> authentication message-digest' or HMAC-SHA via key-chains (IOS-XE 16+: 'ospfv2 authentication').", reference=R["ospf"]))
        if any(n["network"].startswith("0.0.0.0/0") for n in process["networks"]):
            out.append(F("RTR-OSPF-003", "low", "OSPF", f"{name}: 'network 0.0.0.0 255.255.255.255' enables OSPF on every interface", recommendation="Enable OSPF per interface ('ip ospf <p> area <n>').", reference=R["ospf"]))
        if not process["auto_cost"] and fastest >= 1_000_000:
            out.append(F("RTR-OSPF-004", "low", "OSPF", f"{name}: default reference bandwidth with Gigabit-or-faster links",
                         detail="With the default 100 Mbps reference every link of 100 Mbps and above gets cost 1, so OSPF cannot prefer the faster path.",
                         recommendation="'auto-cost reference-bandwidth <Mbps>' identically on every router.", reference=R["ospf"]))
        # The running-config does not print the default, and a real IOS-XE 17.12 router (JKT-DCIRTR-01) logs %OSPF-5-ADJCHG without the line:
        # only an explicit 'no log-adjacency-changes' turns it off.
        if process["log_adjacency"] is False:
            out.append(F("RTR-OSPF-005", "low", "OSPF", f"{name}: adjacency changes are not logged ('no log-adjacency-changes')", recommendation="Remove 'no log-adjacency-changes'; add 'log-adjacency-changes detail' to see the reason for each drop.", reference=R["ospf"]))
    for neighbor in ctx.get("ospf_neighbors", []) or []:
        if not neighbor.get("state", "").upper().startswith("FULL") and not neighbor.get("state", "").upper().startswith("2WAY"):
            out.append(F("RTR-OSPF-006", "high", "OSPF", f"OSPF neighbor {neighbor.get('neighbor_id', '?')} is {neighbor.get('state', '?')}", obj=neighbor.get("neighbor_id", ""),
                         recommendation="Check MTU, area, authentication, hello/dead timers.", reference=R["ospf"]))
    return out


# ---------------------------------------------------------------------------
# Policy objects
# ---------------------------------------------------------------------------

_KIND_LABEL = {"acl": "ACL", "route-map": "route-map", "prefix-list": "prefix-list", "as-path": "AS-path list",
               "community-list": "community list", "class-map": "class-map", "policy-map": "policy-map"}
_KIND_REF = {"acl": R["acl"], "route-map": R["bgp"], "prefix-list": R["bgp"], "as-path": R["bgp"], "community-list": R["bgp"], "class-map": R["qos"], "policy-map": R["qos"]}


@rule
def objects_undefined(ctx: Ctx):
    if ctx.xref is None:
        return []
    out = []
    for item in ctx.xref["undefined"]:
        label = _KIND_LABEL[item["kind"]]
        near = f" A {label} named '{item['near']}' exists — IOS names are case-sensitive." if item["near"] else ""
        high = item["effect"] in ("interface ACL", "management ACL", "BGP policy")
        out.append(F("RTR-OBJ-001", "high" if high else "medium", "Policy objects", f"{label} '{item['name']}' is referenced but not defined", obj=item["name"],
                     detail=f"Referenced by {item['where']} ({item['effect']}).{near} What an undefined object does depends on the release and the context "
                            "(a missing interface ACL permits everything on most releases), so treat it as a defect.",
                     recommendation="Define the object, or correct the name (check upper/lower case).", reference=_KIND_REF[item["kind"]]))
    return out


@rule
def objects_unused(ctx: Ctx):
    if ctx.xref is None:
        return []
    out = []
    sdwan = ctx.dialect.get("sdwan")
    for kind in ("acl", "route-map", "prefix-list", "as-path", "community-list", "class-map", "policy-map"):
        unused = sorted(name for name in ctx.xref["defined"][kind] if not xr.is_used(ctx.xref, kind, name))
        if not unused:
            continue
        # class-maps that exist only for a policy the router no longer uses are the same cleanup item; keep the list short
        severity = "info" if (sdwan and kind in ("route-map", "prefix-list")) else "low"
        note = (" On an SD-WAN router the controller-pushed policy can reference these; verify in vManage before deleting."
                if sdwan and kind in ("route-map", "prefix-list") else "")
        out.append(F("RTR-OBJ-002", severity, "Policy objects", f"{len(unused)} {_KIND_LABEL[kind]}(s) are defined but never referenced", obj=_names(unused, 10),
                     detail="No other line of this configuration uses them. References that live outside the router (an AAA-downloaded ACL, a controller policy) cannot be seen." + note,
                     recommendation="Remove after confirming, so the configuration only holds what is in use.", reference=_KIND_REF[kind]))
    return out


@rule
def acl_quality(ctx: Ctx):
    out = []
    for acl in _cfg(ctx).get("acls", []):
        entries = acl["entries"]
        catch = None
        for index, entry in enumerate(entries):
            if entry["action"] in ("permit", "deny") and entry["source"] == "any" and entry["destination"] in ("any", "") and entry["protocol"] in ("ip", ""):
                catch = index
                break
        if catch is not None and catch < len(entries) - 1:
            out.append(F("RTR-ACL-001", "medium", "ACL", f"ACL {acl['name']}: {len(entries) - catch - 1} entr{'y' if len(entries) - catch - 1 == 1 else 'ies'} after '{entries[catch]['text']}' can never match",
                         obj=acl["name"], detail="IOS evaluates entries top-down and stops at the first match.", recommendation="Move the catch-all to the end or delete the unreachable lines.",
                         reference=R["acl"]))
        texts = [re.sub(r"^\d+\s+", "", e["text"]) for e in entries]
        duplicates = sorted({t for t in texts if texts.count(t) > 1})
        if duplicates:
            out.append(F("RTR-ACL-002", "low", "ACL", f"ACL {acl['name']} contains duplicate entries", obj=acl["name"], detail="; ".join(duplicates[:3]),
                         recommendation="Delete the duplicates.", reference=R["acl"]))
    hits = ctx.get("access_lists")
    if hits and ctx.xref is not None:
        quiet = []
        for acl in _cfg(ctx).get("acls", []):
            name = str(acl["name"])
            counters = hits.get(name)
            if not counters or not counters["entries"] or not xr.is_used(ctx.xref, "acl", name):
                continue
            if not any(entry.get("hits") for entry in counters["entries"]):
                quiet.append(name)
        if quiet:
            out.append(F("RTR-ACL-003", "info", "ACL", f"{len(quiet)} referenced ACL(s) have not matched a single packet", obj=_names(quiet, 10),
                         detail="Counters are since boot or the last 'clear access-list counters'; an ACL applied to rarely used traffic (DR, backup) is normal.",
                         recommendation="Confirm each is still required.", reference=R["acl"]))
    return out


# ---------------------------------------------------------------------------
# VPN / crypto
# ---------------------------------------------------------------------------


@rule
def vpn_ike_policy(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    for policy in ctx.cfg["crypto"]["isakmp_policies"]:
        weak = []
        severity = "low"
        enc = (policy["encryption"] or "").lower()
        if enc.startswith("des") or enc == "":
            weak.append("DES encryption")
            severity = "high"
        elif enc.startswith("3des"):
            weak.append("3DES encryption")
            severity = "medium"
        if (policy["hash"] or "").lower() == "md5":
            weak.append("MD5 hash")
            severity = _worse(severity, "medium")
        group = str(policy["group"] or "1")
        if group == "1":
            weak.append("DH group 1 (768-bit)")
            severity = "high"
        elif group in ("2", "5"):
            weak.append(f"DH group {group}")
            severity = _worse(severity, "medium")
        if weak:
            defaulted = ", ".join(policy.get("defaults") or [])
            out.append(F("RTR-VPN-001", severity, "VPN", f"ISAKMP policy {policy['priority']} uses {', '.join(weak)}", obj=f"isakmp policy {policy['priority']}",
                         detail=("Values taken from IOS defaults because they are not in the configuration: " + defaulted + ". " if defaulted else "")
                                + "Cisco lists DES, 3DES, MD5 and DH groups 1, 2 and 5 as not recommended (Next Generation Encryption).",
                         recommendation="Use AES-256, SHA-256 or better, and DH group 19 or 20 (or 15/16).", reference=R["ngc"]))
    return out


@rule
def vpn_psk(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    for key in ctx.cfg["crypto"]["isakmp_keys"]:
        peer = key["peer"]
        if key["storage"].startswith("clear"):
            out.append(F("RTR-VPN-002", "high", "VPN", f"Pre-shared key for {peer} is stored in clear text", obj=peer,
                         recommendation="'key config-key password-encrypt' + 'password encryption aes' stores it as type 6.", reference=R["harden_ios"]))
        elif key["storage"].startswith("Vigenere"):
            out.append(F("RTR-VPN-003", "medium", "VPN", f"Pre-shared key for {peer} is stored as type 7 (reversible)", obj=peer,
                         recommendation="Re-enter it with the AES key-encryption feature (type 6).", reference=R["harden_ios"]))
        if peer.split() and peer.split()[0] == "0.0.0.0":
            out.append(F("RTR-VPN-004", "high", "VPN", "Wildcard pre-shared key (0.0.0.0)", obj=peer,
                         detail="Any peer that knows the key can establish a tunnel.", recommendation="Use per-peer keys or certificates.", reference=R["ipsec"]))
    return out


@rule
def vpn_transform_sets(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    tunnels = (ctx.models.get("ipsec") or {}).get("tunnels", [])
    for transform in ctx.cfg["crypto"]["transform_sets"]:
        text = transform["transforms"].lower()
        weak = [item for item in ("esp-des", "esp-3des", "esp-md5-hmac", "ah-md5-hmac", "esp-null") if item in text]
        if weak:
            users = [t for t in tunnels if any(ts["name"] == transform["name"] for ts in t["transform_sets"])]
            peers = sorted({p for t in users for p in t["peers"]})
            if tunnels:
                where = (f" Used by {len(users)} tunnel(s) with {len(peers)} peer(s): {_names(peers, 6)}." if users else " No tunnel uses this transform set, so it can be removed.")
            else:
                where = ""
            out.append(F("RTR-VPN-005", "high" if ("esp-des" in text or "esp-null" in text) else ("medium" if users or not tunnels else "low"), "VPN",
                         f"Transform set {transform['name']} uses {', '.join(weak)}", obj=transform["name"],
                         detail="Cisco lists DES, 3DES and MD5 as not recommended (Next Generation Encryption)." + where,
                         recommendation="Use 'esp-gcm 256' or 'esp-aes 256 esp-sha256-hmac' on both ends of each tunnel; change the peers together.", reference=R["ngc"]))
    return out


@rule
def vpn_runtime(ctx: Ctx):
    out = []
    for session in ctx.get("crypto_session", []) or []:
        status = session.get("status", "")
        if status and status != "UP-ACTIVE":
            out.append(F("RTR-VPN-010", "high", "VPN", f"Crypto session on {', '.join(session.get('interfaces', []))} is {status}",
                         obj=", ".join(session.get("interfaces", [])), recommendation="'show crypto isakmp sa', 'debug crypto isakmp' (carefully) and the peer's side.", reference=R["ipsec"]))
    gdoi = ctx.get("gdoi")
    if gdoi is not None and not gdoi.get("active_ks"):
        out.append(F("RTR-VPN-011", "high", "VPN", "GETVPN group member is not registered to a key server", obj=gdoi.get("group", ""),
                     detail="No active key server in 'show crypto gdoi'; traffic is not encrypted or is dropped depending on fail-close.",
                     recommendation="Check reachability to the key servers, ISAKMP policy, and 'show crypto gdoi gm'.", reference=R["getvpn"]))
    if gdoi and gdoi.get("kek_sig_len") and str(gdoi["kek_sig_len"]).isdigit() and int(gdoi["kek_sig_len"]) < 2048:
        out.append(F("RTR-VPN-012", "medium", "VPN", f"GETVPN rekey signature key is {gdoi['kek_sig_len']} bits", obj=gdoi.get("group", ""),
                     detail="The KS signs rekey messages with an RSA key; Cisco recommends at least 2048 bits.",
                     recommendation="Regenerate the KS rekey RSA key at 2048 bits.", reference=R["getvpn"]))
    for sa in ctx.get("ipsec_sa", []) or []:
        errors = (sa.get("send_errors") or 0) + (sa.get("recv_errors") or 0)
        if errors >= 100:
            out.append(F("RTR-VPN-013", "medium", "VPN", f"IPsec SA on {sa.get('interface', '?')} shows {errors:,} send/receive errors", obj=sa.get("interface", ""),
                         recommendation="Check MTU/fragmentation, anti-replay window and ESP drops.", reference=R["ipsec"]))
    return out


# ---------------------------------------------------------------------------
# SD-WAN
# ---------------------------------------------------------------------------

_PRIVATE_COLORS = {"mpls", "metro-ethernet", "private1", "private2", "private3", "private4", "private5", "private6"}


@rule
def sdwan_health(ctx: Ctx):
    out = []
    status = ctx.get("sdwan_status")
    if status:
        state = status.get("System state", "")
        if state and not state.upper().startswith("GREEN"):
            out.append(F("RTR-SDW-001", "high", "SD-WAN", f"SD-WAN system state is not GREEN ({state})", recommendation="'show sdwan system status' and 'show sdwan control local-properties'; check daemons.", reference=R["sdwan_design"]))
    connections = ctx.get("sdwan_control")
    if connections is not None:
        down = [c for c in connections if c.get("state") != "up"]
        for c in down:
            out.append(F("RTR-SDW-002", "high", "SD-WAN", f"Control connection to {c.get('type', '?')} {c.get('system_ip', '?')} on color {c.get('local_color', '?')} is {c.get('state', '?')}", obj=c.get("system_ip", ""),
                         recommendation="Check reachability, certificates, clock and the transport color; 'show sdwan control connection-history' says why it dropped.", reference=R["sdwan_control_troubleshoot"]))
        if not connections or not any(c.get("state") == "up" for c in connections):
            out.append(F("RTR-SDW-003", "high", "SD-WAN", "No control connection is up", recommendation="The router is running on its last known policy only.", reference=R["sdwan_design"]))
    bfd = ctx.get("sdwan_bfd")
    if bfd is not None:
        down = [b for b in bfd if b.get("state") != "up"]
        if down:
            out.append(F("RTR-SDW-004", "high" if len(down) == len(bfd) else "medium", "SD-WAN", f"{len(down)} of {len(bfd)} BFD overlay sessions are down",
                         obj=_names([f"{b['system_ip']} {b['source_color']}→{b['remote_color']}" for b in down], 6),
                         recommendation="Check the underlay path and firewall rules for the remote color.", reference=R["sdwan_bfd_troubleshoot"]))
    cfg = ctx.sdwan_cfg
    if cfg:
        for tunnel in cfg.get("tunnel_interfaces", []):
            color = tunnel.get("color", "")
            public = color not in _PRIVATE_COLORS
            if tunnel.get("allow_all"):
                out.append(F("RTR-SDW-010", "high" if public else "medium", "SD-WAN", f"{tunnel['interface']}: 'allow-service all' on a {color or '?'} tunnel interface",
                             obj=tunnel["interface"], detail="Every service (ssh, netconf, https, snmp, dns, …) is reachable from the transport.",
                             recommendation="Allow only the services the transport needs (dhcp, dns, icmp; bgp/ospf if used).", reference=R["sdwan_tunnel"]))
            elif public:
                exposed = [s for s in tunnel.get("allow_services", []) if s in ("sshd", "netconf", "https", "snmp", "ssh")]
                if exposed:
                    out.append(F("RTR-SDW-011", "medium", "SD-WAN", f"{tunnel['interface']} ({color}): management services allowed from the transport: {', '.join(exposed)}",
                                 obj=tunnel["interface"], recommendation="Remove sshd/netconf/https/snmp from internet-facing colors; use the TLOC/overlay for management.",
                                 reference=R["sdwan_tunnel"]))
    return out


# ---------------------------------------------------------------------------
# QoS / SLA / ZBF / FHRP
# ---------------------------------------------------------------------------


@rule
def sla_track(ctx: Ctx):
    if ctx.cfg is None:
        return []
    out = []
    sla = ctx.cfg["sla_track"]
    for entry in sla["ip_sla"]:
        if not entry["scheduled"]:
            out.append(F("RTR-SLA-001", "medium", "IP SLA", f"IP SLA {entry['id']} ({entry['operation']}) is defined but not scheduled", obj=entry["id"],
                         detail="Without 'ip sla schedule' the probe never runs; any track/static route that depends on it never reacts.",
                         recommendation=f"'ip sla schedule {entry['id']} life forever start-time now'.", reference=R["ipsla"]))
    track_ids = {t["id"] for t in sla["tracks"]}
    sla_ids = {e["id"] for e in sla["ip_sla"]}
    for route in ctx.cfg["static_routes"]:
        if route["track"] and route["track"] not in track_ids:
            out.append(F("RTR-SLA-002", "high", "IP SLA", f"Static route {route['prefix']} is tracked by object {route['track']}, which is not defined", obj=route["prefix"],
                         recommendation="Define the track object or remove 'track'.", reference=R["ipsla"]))
    for track in sla["tracks"]:
        words = track["object"].split()
        if "ip" in words and "sla" in words:
            ident = words[words.index("sla") + 1] if words.index("sla") + 1 < len(words) else ""
            if ident and ident not in sla_ids:
                out.append(F("RTR-SLA-003", "high", "IP SLA", f"Track {track['id']} follows IP SLA {ident}, which is not defined", obj=track["id"], recommendation="Define the IP SLA operation.", reference=R["ipsla"]))
    return out


@rule
def sla_live_failures(ctx: Ctx):
    """'show ip sla statistics' is the device's own lifetime success/failure tally for each
    probe — independent of whether the config was captured at all, so this does not need
    ctx.cfg the way sla_track() does. A probe with 0 successes has never once completed,
    whatever depends on it never got a reason to act on a real result."""
    stats = ctx.get("ip_sla_stats") or []
    if not stats:
        return []
    tracked_by: dict[str, list[str]] = {}
    if ctx.cfg:
        for track in ctx.cfg["sla_track"]["tracks"]:
            words = track["object"].split()
            if "ip" in words and "sla" in words:
                idx = words.index("sla") + 1
                if idx < len(words):
                    tracked_by.setdefault(words[idx], []).append(track["id"])
    out = []
    for s in stats:
        if s["successes"] == 0 and s["failures"] > 0:
            tracks = tracked_by.get(s["id"], [])
            out.append(F("RTR-SLA-004", "high" if s["failures"] >= 100 else "medium", "IP SLA",
                         f"IP SLA {s['id']} has never once succeeded ({s['failures']:,} failure(s) logged, 0 successes)", obj=s["id"],
                         detail=f"Return code: {s['return_code'] or 'not reported'}." +
                                (f" Feeds track object {', '.join(tracks)}." if tracks else
                                 " No track object in this capture currently depends on it, so nothing is failing over because of it — but the probe itself is dead and worth fixing or removing."),
                         recommendation="Check the probe's source-interface/VRF and that its target is actually reachable from this router; 'Socket set option error' in particular "
                                        "usually means the configured source address/interface does not exist or is down, not that the target is unreachable.",
                         reference=R["ipsla"]))
    return out


@rule
def zbf_coverage(ctx: Ctx):
    if ctx.cfg is None:
        return []
    zbf = ctx.cfg["zbf"]
    if not zbf["zones"]:
        return []
    loose = [i["name"] for i in ctx.cfg["interfaces"] if i["ip_address"] and not i["shutdown"] and not i["zone_member"] and not i["name"].startswith(("Loopback", "Null"))]
    if loose:
        return [F("RTR-ZBF-001", "medium", "Zone firewall", f"{len(loose)} routed interface(s) are not in any security zone", obj=_names(loose, 10),
                  detail="With a zone-based firewall active, traffic between a zone member and a non-member interface is dropped, so these interfaces can only talk to each other (and to the router itself).",
                  recommendation="Assign them with 'zone-member security <zone>', or confirm that the isolation is intended.", reference=R["zbf"])]
    return []


@rule
def fhrp_auth(ctx: Ctx):
    out = []
    for iface in _cfg(ctx).get("interfaces", []):
        for group in iface["hsrp"] + iface["vrrp"]:
            kind = "HSRP" if group in iface["hsrp"] else "VRRP"
            if not group["auth"]:
                out.append(F("RTR-FHRP-001", "low", "FHRP", f"{iface['name']}: {kind} group {group['group']} has no authentication", obj=iface["name"],
                             recommendation="Add MD5/key-chain authentication so a rogue host cannot become the gateway.", reference=R["fhrp"]))
            if kind == "HSRP" and not group["preempt"]:
                out.append(F("RTR-FHRP-002", "low", "FHRP", f"{iface['name']}: HSRP group {group['group']} has no preempt", obj=iface["name"],
                             detail="After a failover the higher-priority router does not take the role back.", recommendation="'standby <g> preempt' (with delay).", reference=R["fhrp"]))
    return out


# Rule modules that build on this one (they import ``rule`` from here, so they load last).

@rule
def sdwan_management(ctx: Ctx):
    """vManaged and Commit pending from ``show sdwan system status``."""
    status = ctx.get("sdwan_status")
    if not status:
        return []
    out = []
    managed = str(status.get("vManaged", "")).strip().lower()
    template = status.get("Configuration template", "")
    if managed == "false":
        out.append(F("RTR-SDW-030", "info", "SD-WAN", "This router is in CLI mode (vManaged: false): no template is attached",
                     detail=f"'show sdwan system status' prints vManaged: false and Configuration template: {template or 'n/a'}. Cisco states that when the vManaged field is false no template is attached, so the local configuration is the source of truth and a change in vManage templates does not reach this router.",
                     recommendation="Expected for a router that is deliberately managed from the CLI or still being onboarded; otherwise attach the device template in SD-WAN Manager so the configuration is controlled centrally.", reference=R["sdwan_vmanaged"]))
    elif managed == "true" and template.strip().lower() in ("", "none", "n/a"):
        out.append(F("RTR-SDW-032", "low", "SD-WAN", "vManaged is true but no configuration template name is reported",
                     detail=f"Configuration template: {template or 'empty'}. A router managed from SD-WAN Manager normally reports the template that built its configuration.",
                     recommendation="Check the device in SD-WAN Manager (Configuration > Devices) for the attached template or configuration group.", reference=R["sdwan_vmanaged"]))
    if str(status.get("Commit pending", "")).strip().lower() == "true":
        out.append(F("RTR-SDW-031", "low", "SD-WAN", "The router reports Commit pending: true",
                     detail="'show sdwan system status' prints Commit pending: true. Cisco's page for this command lists the field without defining it, so treat it as 'a configuration change has not been committed yet' and confirm in SD-WAN Manager.",
                     recommendation="Check whether a configuration push or a manual commit is still in progress or stuck.", reference=R["sdwan_vmanaged"]))
    return out


_ERROR_ADVICE = {
    "unreachable": "The DTLS connection could not be established (DCONFAIL: DTLS connection failure). Check the route to the controller, the firewall and ACLs for the DTLS/TLS ports on that transport, and the controller's own reachability.",
    "timeout": "The peer stopped answering (a *_TMO code). Check packet loss on that transport and whether the controller was reachable at the time.",
    "certificate": "A certificate or identity check failed. Check the device certificate and the root CA chain, the router clock (NTP) and the organization name; this does not clear by itself.",
    "identity": "The controller refused the device identity (serial, chassis or system-IP problem). Check the device list and the system-IP in SD-WAN Manager.",
}


@rule
def sdwan_history(ctx: Ctx):
    """``show sdwan control connection-history`` joined with the live control table and the BFD sessions."""
    from . import runtime_vpn as rv

    history = ctx.get("sdwan_history")
    if not history or not history.get("rows"):
        return []
    rows, legend = history["rows"], history.get("legend", {})
    connections = ctx.get("sdwan_control")
    live = connections is not None
    up_colors = {c.get("local_color") for c in connections or [] if c.get("state") == "up"}
    by_color: dict[str, dict[str, Any]] = {}
    for r in rows:
        klass = rv.control_error_class(r["local_error"])
        if klass in ("unreachable", "timeout", "certificate", "identity"):
            entry = by_color.setdefault(r["local_color"], {"classes": {}, "codes": {}, "last": "", "peers": set(), "repeat": 0})
            entry["classes"][klass] = entry["classes"].get(klass, 0) + 1
            entry["codes"][r["local_error"]] = entry["codes"].get(r["local_error"], 0) + max(r["repeat"], 1)
            entry["last"] = max(entry["last"], r["downtime"])
            entry["peers"].add(f"{r['type']} {r['system_ip']}" if r["type"] != "vbond" else "vbond")
            entry["repeat"] += r["repeat"]
    out = []
    shut = {i.get("name") for i in (ctx.cfg or {}).get("interfaces", []) if i.get("shutdown")}
    configured = {t.get("color") for t in (ctx.sdwan_cfg or {}).get("tunnel_interfaces", []) if t.get("interface") not in shut} if ctx.sdwan_cfg else None
    stale = sorted(color for color in by_color if configured is not None and color not in configured)
    if stale:
        out.append(F("RTR-SDW-024", "info", "SD-WAN", f"The connection history mentions color {', '.join(stale)}, which no active tunnel interface uses now", obj=", ".join(stale),
                     detail="No tunnel interface with this color is configured and not shut down, so these history rows are from before a color change or from an interface that is switched off; they are not judged as a live fault.",
                     recommendation="No action unless a tunnel interface is missing its color; the history clears when the control connections restart.", reference=R["sdwan_control_troubleshoot"]))
    for color, entry in sorted(by_color.items()):
        if color in stale:
            continue
        worst = next(k for k in ("certificate", "identity", "unreachable", "timeout") if k in entry["classes"])
        codes = ", ".join(f"{code} ×{n}" + (f" ({legend[code]})" if code in legend else "") for code, n in sorted(entry["codes"].items(), key=lambda kv: -kv[1])[:4])
        recovered = live and color in up_colors
        if recovered and worst in ("unreachable", "timeout") and entry["repeat"] < 10:
            continue
        if live and not recovered:
            severity = "high" if not up_colors or worst in ("certificate", "identity") else "medium"
            title = f"No control connection is up on color {color}; history shows {', '.join(sorted(entry['codes']))}"
        elif recovered:
            severity = "high" if worst in ("certificate", "identity") else "low"
            title = f"Control connections on color {color} failed before and are up now ({', '.join(sorted(entry['codes']))})"
        else:
            severity = "medium"
            title = f"Control connections on color {color} failed in the history ({', '.join(sorted(entry['codes']))})"
        out.append(F("RTR-SDW-020", severity, "SD-WAN", title, obj=color,
                     detail=f"Errors on this color: {codes}. Peers: {_names(sorted(entry['peers']), 4)}. Last event {entry['last'] or 'n/a'}."
                            + (" Another color is up, so the router still has a control plane." if live and not recovered and up_colors else "")
                            + (" The current table shows this color up again, so this is a past outage." if recovered else "")
                            + ("" if live else " 'show sdwan control connections' was not captured, so the current state is unknown."),
                     recommendation=_ERROR_ADVICE[worst], reference=R["sdwan_control_troubleshoot"]))
    local = [r for r in rows if rv.control_error_class(r["local_error"]) == "local"]
    if local:
        seen = {}
        for r in local:
            seen.setdefault((r["local_error"], r["local_color"]), r)
        out.append(F("RTR-SDW-021", "info", "SD-WAN", f"{len(local)} control-connection history entries show a local change ({', '.join(sorted({r['local_error'] for r in local}))})",
                     obj=_names([f"{code} on {color}" for code, color in seen], 4),
                     detail=_names([f"{r['local_error']} {r['type']} {r['local_color']} at {r['downtime']} ({legend.get(r['local_error'], '')})" for r in seen.values()], 4)
                            + ". Cisco describes DISTLOC as the TLOC being disabled, for example by 'clear sdwan control connections' or a change to the TLOC color, system-IP or tunnel interface.",
                     recommendation="Match the time with the configuration changes and with any manual 'clear' or interface shutdown; no action if it was planned.", reference=R["sdwan_control_troubleshoot"]))
    bfd = ctx.get("sdwan_bfd")
    cfg = ctx.sdwan_cfg
    if bfd and cfg:
        bfd_colors = {b.get("source_color") for b in bfd}
        for tunnel in cfg.get("tunnel_interfaces", []):
            if tunnel.get("color") and tunnel["color"] not in bfd_colors and not tunnel.get("last_resort") and tunnel.get("interface") not in shut:
                out.append(F("RTR-SDW-023", "medium", "SD-WAN", f"{tunnel['interface']} ({tunnel['color']}) has no BFD session while other colors do", obj=tunnel["interface"],
                             detail=f"The tunnel interface is configured with color {tunnel['color']}, but none of the {len(bfd)} captured BFD sessions uses it as the local color. That transport carries no overlay traffic.",
                             recommendation="Check the control-connection history for this color (DCONFAIL = the DTLS connection to the controller fails) and the underlay reachability of the controllers from that interface.", reference=R["sdwan_bfd_troubleshoot"]))
    return out


from . import rules_health, rules_net, rules_sdwan  # noqa: E402,F401
