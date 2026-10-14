"""Findings for the management plane (GUI / SSH access, SNMP, NTP, syslog, accounts, password policy, self IP lockdown) and the data-plane network."""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_extract import short
from .netutil import is_public_ip
from .refs import F5
from .bigip_context import LCtx, listing

_EXTERNAL_VLAN = re.compile(r"ext|internet|wan|outside|untrust|public|dmz|isp|edge|inet", re.I)


# ===================================================================== management plane
def _external_self(s: dict[str, Any]) -> bool:
    return s["public"] or bool(_EXTERNAL_VLAN.search(short(s["vlan"])))


def management_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    if not ctx.has_base:
        return []
    d, sysd = ctx.data, ctx.sysd
    out: list[dict[str, Any]] = []
    httpd, sshd = sysd["httpd"], sysd["sshd"]
    http_any = (not httpd["present"]) or (not httpd.get("allow_explicit")) or "all" in httpd["allow"] or any(a in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "any") for a in httpd["allow"])
    if http_any:
        explicit = httpd["present"] and httpd.get("allow_explicit")
        out.append(finding("LB-MGT-001", "high" if explicit else "medium", "Management", "Configuration utility (HTTPS) is reachable from any address", obj="sys httpd allow",
                           detail=("sys httpd allow lists ALL." if explicit else "The export has no 'sys httpd allow' list; the TMSH reference documents the default as All.") + " Any host that can reach a management or self IP can open the GUI/iControl REST login.",
                           recommendation="Restrict it to the management networks: 'modify sys httpd allow replace-all-with { 10.10.0.0/16 }', and keep the management port off untrusted networks.", reference=F5["httpd"]))
    ssh_any = (not sshd["present"]) or (not sshd.get("allow_explicit")) or "all" in sshd["allow"] or any(a in ("0.0.0.0/0", "any") for a in sshd["allow"])
    if ssh_any:
        explicit = sshd["present"] and sshd.get("allow_explicit")
        out.append(finding("LB-MGT-002", "high" if explicit else "medium", "Management", "SSH is reachable from any address", obj="sys sshd allow",
                           detail=("sys sshd allow lists ALL." if explicit else "The export has no 'sys sshd allow' list; the TMSH reference documents the default as all.") + " The advanced shell is one login away from the network.",
                           recommendation="Restrict it to the management networks: 'modify sys sshd allow replace-all-with { 10.10.0.0/16 }'.", reference=F5["sshd"]))
    idle = []
    http_idle = httpd.get("idle_timeout", 1200) if httpd["present"] else 1200
    if http_idle > 900:
        idle.append(f"GUI auth-pam-idle-timeout {http_idle} s" + ("" if httpd["present"] and httpd.get("idle_timeout") != 1200 else " (the documented default is 1200)"))
    ssh_idle = sshd.get("inactivity_timeout", 0) if sshd["present"] else 0
    if ssh_idle == 0 or ssh_idle > 900:
        idle.append("SSH inactivity-timeout " + (f"{ssh_idle} s" if ssh_idle else "0 (disabled, the documented default)"))
    console = int(sysd["global"].get("console-inactivity-timeout", "0") or 0)
    if console == 0 or console > 900:
        idle.append("console-inactivity-timeout " + (f"{console} s" if console else "0 (disabled, the documented default)"))
    if idle:
        out.append(finding("LB-MGT-003", "low", "Management", "Administrative sessions stay open longer than 15 minutes", obj="sys httpd / sshd / global-settings",
                           detail="; ".join(idle) + ". PCI DSS requirement 8.2.8 expects users to re-authenticate after 15 minutes of idle time.",
                           recommendation="Set auth-pam-idle-timeout 900, 'sys sshd inactivity-timeout 900' and console-inactivity-timeout 900 (or the shorter value your policy requires).", reference=F5["pci_8_2_8"]))
    for s in d["selfs"]:
        ext = _external_self(s)
        if s["allow"] == "all":
            out.append(finding("LB-MGT-004", "high" if ext else "medium", "Management", "Self IP port lockdown allows all ports" + (" on an internet-facing VLAN" if ext else ""), obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) has allow-service all, so every TCP/UDP service on the BIG-IP (SSH, GUI, SNMP, routing, iQuery) answers on that address.",
                               recommendation="Use allow-service none, or list only the ports the address needs (for example tcp:179 for BGP or udp:1026/tcp:4353 for HA on the HA VLAN). The F5 guide describes Allow None as blocking administrative access to the self IP.", reference=F5["selfip_lockdown"]))
        elif s["allow"] == "custom" and ext and {c.lower() for c in s["allow_custom"]} & {"tcp:22", "tcp:443", "tcp:80", "tcp:8443", "tcp:ssh", "tcp:https"}:
            out.append(finding("LB-MGT-004", "medium", "Management", "Management port is open on an external self IP", obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) allows {', '.join(s['allow_custom'])}, which exposes SSH or the GUI on an external-facing address.", recommendation="Remove the management ports from the external self IP; manage the device from the management network.", reference=F5["selfip_lockdown"]))
        elif s["allow"] == "default" and ext:
            out.append(finding("LB-MGT-004", "low", "Management", "Self IP on an external VLAN uses the default port-lockdown list", obj=s["short"],
                               detail=f"{s['short']} ({s['address']}, VLAN {short(s['vlan'])}) uses allow-service default, a predefined list of protocols for typical deployments. Show it with 'tmsh list net self-allow' and confirm it contains nothing the external network should reach.",
                               recommendation="Set allow-service none on external self IPs, and open individual ports only where a service needs them.", reference=F5["net_self_allow"]))
    snmp = sysd["snmp"]
    if snmp["present"]:
        for c in snmp["communities"]:
            if c["guessable"]:
                out.append(finding("LB-SNMP-001", "high", "SNMP", "SNMP community is a well-known default", obj=c["name"], detail=f"Community entry {c['name']} uses a guessable name (public, private, or similar). The value is hidden in this report.",
                                   recommendation="Replace it with SNMPv3 (authPriv) or at least a long random community restricted to the monitoring servers.", reference=F5["snmp"]))
            if c["access"] == "rw":
                out.append(finding("LB-SNMP-002", "high", "SNMP", "SNMP community has write access", obj=c["name"], detail=f"Community {c['name']} is read-write; a holder can change device settings over SNMP.", recommendation="Use access ro, or SNMPv3 with a restricted view.", reference=F5["snmp"]))
        allowed = snmp["allowed"]
        if snmp["communities"] and any(a in ("0.0.0.0/0", "0.0.0.0/0.0.0.0", "all", "any") for a in allowed):
            out.append(finding("LB-SNMP-003", "high" if any(c["guessable"] for c in snmp["communities"]) else "medium", "SNMP", "SNMP agent accepts queries from any address", obj="sys snmp allowed-addresses",
                               detail="allowed-addresses includes 0.0.0.0/0. The TMSH reference documents the default as 127.0.0.0/8 (local only).", recommendation="List only the monitoring servers in allowed-addresses.", reference=F5["snmp"]))
        if snmp["communities"] and not snmp["users"]:
            out.append(finding("LB-SNMP-004", "medium", "SNMP", "SNMP uses community strings only", obj="sys snmp communities",
                               detail=f"{len(snmp['communities'])} v1/v2c community entries and no SNMPv3 user. Community strings cross the network in clear text.", recommendation="Move monitoring to SNMPv3 with authentication and privacy, then remove the communities.", reference=F5["snmp"]))
    ntp = sysd["ntp"]
    if not ntp["servers"]:
        out.append(finding("LB-MGT-006", "medium", "Operations", "No NTP server is configured", obj="sys ntp",
                           detail="The export has no NTP servers (documented default: none). Wrong time breaks log correlation, certificate validity checks and configuration sync between HA peers.",
                           recommendation="Add at least two NTP servers: 'modify sys ntp servers replace-all-with { 10.0.0.10 10.0.0.11 }'.", reference=F5["ntp"]))
    sl = sysd["syslog"]
    if not sl["remote"] and not sl["hsl_destinations"]:
        out.append(finding("LB-MGT-007", "medium", "Operations", "Logs are not sent to a remote server", obj="sys syslog remote-servers",
                           detail="There is no remote syslog server (documented default: none) and no remote-syslog or high-speed-logging destination, so audit evidence stays on the device that an attacker or a failure can wipe.",
                           recommendation="Send syslog to your log collector: 'modify sys syslog remote-servers add { siem { host 10.0.0.20 remote-port 514 } }' or define a log-config destination and publisher.", reference=F5["syslog"]))
    a = d["auth"]
    policy = a["password_policy"]
    enforced = policy.get("policy-enforcement", "disabled").lower() == "enabled"
    if not enforced:
        out.append(finding("LB-MGT-008", "medium", "Management", "Password policy is not enforced", obj="auth password-policy",
                           detail="policy-enforcement is disabled (the documented default; minimum length 6 and no complexity or lockout). Local accounts can have weak passwords and unlimited failed logins.",
                           recommendation="Enable policy-enforcement with a minimum length of 12, complexity, password-memory and max-login-failures.", reference=F5["password_policy"]))
    elif int(policy.get("minimum-length", "6") or 6) < 8:
        out.append(finding("LB-MGT-008", "low", "Management", "Password policy allows short passwords", obj="auth password-policy", detail=f"minimum-length is {policy.get('minimum-length')}.", recommendation="Raise the minimum length to 12 or more.", reference=F5["password_policy"]))
    for ldap in a["ldap"]:
        if ldap["ssl"] != "enabled":
            out.append(finding("LB-AUTH-001", "medium", "Authentication", "LDAP authentication is not encrypted", obj=ldap["name"],
                               detail=f"LDAP profile {ldap['name']} has ssl {ldap['ssl']} (documented default: disabled), so the bind and user passwords cross the network in clear text.", recommendation="Enable ssl (LDAPS/StartTLS), set the port accordingly and load the directory CA.", reference=F5["auth_ldap"]))
        elif ldap["check_peer"] != "enabled":
            out.append(finding("LB-AUTH-002", "low", "Authentication", "LDAP server certificate is not verified", obj=ldap["name"],
                               detail=f"LDAP profile {ldap['name']} has ssl enabled but ssl-check-peer {ldap['check_peer']} (documented default: disabled), so a man in the middle can present any certificate.", recommendation="Enable ssl-check-peer and set ssl-ca-cert-file.", reference=F5["auth_ldap"]))
    for t in a["tacacs"]:
        if t["encryption"].lower() == "disabled":
            out.append(finding("LB-AUTH-003", "high", "Authentication", "TACACS+ packet encryption is disabled", obj=t["name"], detail=f"TACACS+ profile {t['name']} has encryption disabled (documented default: enabled; F5 recommends keeping it on), so the session, including the user's password, is sent unprotected.", recommendation="Enable encryption.", reference=F5["auth_tacacs"]))
    bash_users = [u["name"] for u in a["users"] if u["shell"] == "bash"]
    if bash_users:
        out.append(finding("LB-AUTH-004", "low", "Authentication", "Local accounts have advanced-shell (bash) access", obj=listing(bash_users, 4), detail="Users with shell bash can run any Linux command as their role permits: " + listing(bash_users, 10) + ".",
                           recommendation="Give routine administrators the tmsh shell (or none for GUI-only users); keep bash, which the TMSH reference limits to the Administrator role, for the few accounts that need it.", reference=F5["auth_user"]))
    if a["source"] == "local" and not (a["ldap"] or a["radius"] or a["tacacs"]) and a["users"]:
        out.append(finding("LB-AUTH-005", "low", "Authentication", "Administrators authenticate locally only", obj="auth source",
                           detail=f"{len(a['users'])} local account(s) and no LDAP, RADIUS or TACACS+ configuration. Leavers and password rotation must be handled on every device.", recommendation="Use central authentication with role mapping and keep one break-glass local account (auth source type ldap/radius/tacacs with fallback true).", reference=F5["auth_source"]))
    for ip in sysd["management_ip"]:
        if is_public_ip(ip):
            out.append(finding("LB-MGT-012", "high", "Management", "Management interface has a public address", obj=ip, detail=f"sys management-ip {ip} is a routable address; the management plane should sit on a private, access-controlled network.",
                               recommendation="Move the management interface to a private management network.", reference=F5["global_settings"]))
    return out


# ===================================================================== network
def network_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d = ctx.data
    out: list[dict[str, Any]] = []
    for t in d["trunks"]:
        if len(t["interfaces"]) > 1 and t["lacp"] != "enabled":
            out.append(finding("LB-NET-001", "low", "Network", "Trunk without LACP", obj=t["short"], detail=f"{t['short']} bundles {len(t['interfaces'])} interfaces with LACP {t['lacp']} (documented default: disabled); a miswired or half-failed link is not detected.",
                               recommendation="Enable LACP (lacp-mode active) on the trunk and on the switch port-channel.", reference=F5["net_trunk"]))
    if ctx.has_base and d["selfs"] and not any(r["default"] for r in d["routes"]):
        out.append(finding("LB-NET-002", "low", "Network", "No default route", obj="net route", detail="There are self IPs but no default route in the data plane, so the BIG-IP can only reach directly connected networks (management routes are separate).",
                           recommendation="Add a default route towards the upstream gateway, or confirm that every needed network has a specific route.", reference=F5["net_self"]))
    return out
