"""Extra Palo Alto information read straight from a PAN-OS XML export.

Configuration Studio's PAN-OS parser maps interfaces, zones, rules, NAT, routing and
VPN into a vendor-neutral model.  A running-config export carries much more that this
model has no field for: high availability, the management permitted-IP list, SNMP,
NTP authentication, the login banner, content-update schedules, certificates (with
expiry), SSL/TLS service profiles, server and authentication profiles and the
administrator list.  This module reads those from the raw XML.

Privacy: nothing secret is ever copied out.  Password hashes (``phash``), SNMPv3
``authpwd``/``privpwd``, server ``secret`` values, SNMP community names and the
``public-key``/``private-key`` blobs of certificates are not read at all; the output
only says whether a credential exists.

Reference for the XML layout: PAN-OS Administrator's Guide and the XML API,
https://docs.paloaltonetworks.com/pan-os
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any
from xml.etree import ElementTree as ET

from ..analyzer_core.findings import finding
from ..analyzer_core.result import kv_section, table_section
from . import panos_xml_network
from .refs import PALO

WEAK_TLS = {"tls1-0": "TLS 1.0", "tls1-1": "TLS 1.1", "sslv3": "SSL 3.0"}
MAX_IDLE_MINUTES = 30
EXPIRY_WARN_DAYS = 60
SUPER_ROLES = {"superuser", "deviceadmin", "vsysadmin"}


# ----------------------------------------------------------------------- helpers
def _t(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def _has(node: ET.Element | None, path: str) -> bool:
    return node is not None and node.find(path) is not None


def _members(node: ET.Element | None, path: str) -> list[str]:
    if node is None:
        return []
    found = node.find(path)
    if found is None:
        return []
    return [(m.text or "").strip() for m in found.findall("member") if (m.text or "").strip()]


def _entries(node: ET.Element | None, path: str) -> list[ET.Element]:
    if node is None:
        return []
    found = node.find(path)
    return found.findall("entry") if found is not None else []


def _yes(node: ET.Element | None, path: str) -> bool | None:
    value = _t(node, path).lower()
    if value in ("yes", "true", "enable", "enabled"):
        return True
    if value in ("no", "false", "disable", "disabled"):
        return False
    return None


def _children_tags(node: ET.Element | None) -> list[str]:
    return [child.tag for child in node] if node is not None else []


def _parse_cert_date(text: str) -> date | None:
    match = re.match(r"([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+(\d{4})", text.strip())
    if not match:
        return None
    try:
        return datetime.strptime(f"{match[1]} {match[2]} {match[3]}", "%b %d %Y").date()
    except ValueError:
        return None


# ----------------------------------------------------------------------- extract
def extract(content: str) -> dict[str, Any] | None:
    """Return the extra data, or None when ``content`` is not PAN-OS XML."""
    text = content.lstrip()
    if not text.startswith("<"):
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    device = root.find("devices/entry")
    shared = root.find("shared")
    out: dict[str, Any] = {
        "system": _system(device), "ha": _ha(device), "certificates": _certificates(root), "tls_profiles": _tls_profiles(root),
        "server_profiles": _server_profiles(root), "auth_profiles": _auth_profiles(root), "admins": _admins(root), "syslog": _syslog(root),
        "vsys": _vsys(device), "globalprotect": _globalprotect(root),
    }
    out["log_forwarding"] = _log_forwarding(shared)
    net = panos_xml_network.extract(root, device)
    out["network"] = net
    if out["system"] and net["updates"]:                                    # readable schedule instead of the bare element names
        out["system"]["update_schedule"] = [f"{u['content']} {u['frequency']} {u['at']}".strip() for u in net["updates"]]
    return out


def _system(device: ET.Element | None) -> dict[str, Any]:
    sysnode = device.find("deviceconfig/system") if device is not None else None
    setting = device.find("deviceconfig/setting/management") if device is not None else None
    if sysnode is None:
        return {}
    permitted = [{"address": e.get("name", ""), "description": _t(e, "description")} for e in _entries(sysnode, "permitted-ip")]
    ntp = []
    for label, tag in (("primary", "primary-ntp-server"), ("secondary", "secondary-ntp-server")):
        node = sysnode.find(f"ntp-servers/{tag}")
        if node is not None:
            auth = _children_tags(node.find("authentication-type"))
            ntp.append({"role": label, "server": _t(node, "ntp-server-address"), "auth": auth[0] if auth else "none"})
    snmp = sysnode.find("snmp-setting")
    v3_users = [{"name": e.get("name", ""), "view": _t(e, "view"), "has_auth": _has(e, "authpwd"), "has_priv": _has(e, "privpwd")} for e in _entries(snmp, "access-setting/version/v3/users")] if snmp is not None else []
    v2c = snmp.find("access-setting/version/v2c") if snmp is not None else None
    updates = sysnode.find("update-schedule")
    return {
        "hostname": _t(sysnode, "hostname"), "mgmt_ip": _t(sysnode, "ip-address"), "netmask": _t(sysnode, "netmask"), "gateway": _t(sysnode, "default-gateway"),
        "domain": _t(sysnode, "domain"), "timezone": _t(sysnode, "timezone"), "update_server": _t(sysnode, "update-server"),
        "banner": _t(sysnode, "login-banner"), "permitted_ip": permitted, "ssl_tls_profile": _t(sysnode, "ssl-tls-service-profile"),
        "dns": [v for v in (_t(sysnode, "dns-setting/servers/primary"), _t(sysnode, "dns-setting/servers/secondary")) if v], "ntp": ntp,
        "snmp_v2c": v2c is not None, "snmp_v3_users": v3_users, "snmp_location": _t(snmp, "snmp-system/location"), "snmp_contact": _t(snmp, "snmp-system/contact"),
        "services": {k.replace("disable-", ""): _t(sysnode, f"service/{k}") for k in ("disable-telnet", "disable-http", "disable-https", "disable-ssh", "disable-snmp", "disable-icmp") if _has(sysnode, f"service/{k}")},
        "update_schedule": _children_tags(updates), "update_schedule_present": updates is not None,
        "panorama": [v for v in (_t(sysnode, "panorama-server"), _t(sysnode, "panorama-server-2")) if v],
        "idle_timeout": _t(setting, "idle-timeout"), "ip_type": (_children_tags(sysnode.find("type")) or [""])[0],
    }


def _ha(device: ET.Element | None) -> dict[str, Any]:
    node = device.find("deviceconfig/high-availability") if device is not None else None
    if node is None:
        return {}
    group = node.find("group")
    mode_tags = _children_tags(group.find("mode")) if group is not None else []
    link_groups = [{"name": e.get("name", ""), "interfaces": _members(e, "interface"), "condition": _t(e, "failure-condition", "any"), "enabled": _yes(e, "enabled") is not False}
                   for e in _entries(group, "monitoring/link-monitoring/link-group")] if group is not None else []
    paths = [{"name": e.get("name", ""), "condition": _t(e, "failure-condition", "any"), "enabled": _yes(e, "enabled") is not False}
             for e in _entries(group, "monitoring/path-monitoring/path-group/virtual-wire") + _entries(group, "monitoring/path-monitoring/path-group/vlan") + _entries(group, "monitoring/path-monitoring/path-group/virtual-router")] if group is not None else []
    ha1 = node.find("interface/ha1")
    ha2 = node.find("interface/ha2")
    return {
        "enabled": _yes(node, "enabled") is not False, "group_id": _t(group, "group-id"), "mode": (mode_tags[0] if mode_tags else "") or "", "peer_ip": _t(group, "peer-ip"),
        "peer_ip_backup": _t(group, "peer-ip-backup"), "description": _t(group, "description"), "priority": _t(group, "election-option/device-priority"),
        "preemptive": _yes(group, "election-option/preemptive"), "heartbeat_backup": _yes(group, "election-option/heartbeat-backup"),
        "state_sync": _yes(group, "state-synchronization/enabled"), "ha2_keepalive": _yes(group, "state-synchronization/ha2-keep-alive/enabled"),
        "link_monitoring": _yes(group, "monitoring/link-monitoring/enabled"), "path_monitoring": _yes(group, "monitoring/path-monitoring/enabled"),
        "link_groups": link_groups, "path_groups": paths,
        "ha1_port": _t(ha1, "port"), "ha1_ip": _t(ha1, "ip-address"), "ha1_encryption": _yes(ha1, "encryption/enabled"), "ha2_port": _t(ha2, "port"),
        "ha1_backup": _has(node, "interface/ha1-backup/port"), "ha2_backup": _has(node, "interface/ha2-backup/port"),
        "passive_link_state": _t(group, "mode/active-passive/passive-link-state"),
    }


def _certificates(root: ET.Element) -> list[dict[str, Any]]:
    """Certificates with validity; the key material elements are deliberately never read."""
    today = date.today()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for scope_name, holder in _cert_holders(root):
        for entry in _entries(holder, "certificate"):
            name = entry.get("name", "")
            if (scope_name, name) in seen:
                continue
            seen.add((scope_name, name))
            not_after_text = _t(entry, "not-valid-after")
            expiry = None
            epoch = _t(entry, "expiry-epoch")
            if epoch.isdigit():
                try:
                    expiry = datetime.fromtimestamp(int(epoch), tz=timezone.utc).date()
                except (OverflowError, OSError, ValueError):
                    expiry = None
            expiry = expiry or _parse_cert_date(not_after_text)
            issuer = _t(entry, "issuer")
            subject = _t(entry, "subject")
            out.append({
                "name": name, "scope": scope_name, "common_name": _t(entry, "common-name"), "issuer": issuer, "subject": subject, "not_before": _t(entry, "not-valid-before"),
                "not_after": not_after_text, "expiry": expiry.isoformat() if expiry else "", "days_left": (expiry - today).days if expiry else None,
                "algorithm": _t(entry, "algorithm"), "ca": _yes(entry, "ca") is True, "self_signed": bool(issuer and subject and issuer == subject),
                "has_private_key": _has(entry, "private-key"),
            })
    return out


def _cert_holders(root: ET.Element):
    shared = root.find("shared")
    if shared is not None:
        yield "shared", shared
    for dev in root.findall("devices/entry"):
        for vsys in dev.findall("vsys/entry"):
            yield f"vsys {vsys.get('name', '')}", vsys
        yield "device", dev


def _tls_profiles(root: ET.Element) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    holders = [root.find("shared")] + [v for dev in root.findall("devices/entry") for v in dev.findall("vsys/entry")] + root.findall("devices/entry")
    for holder in holders:
        for entry in _entries(holder, "ssl-tls-service-profile"):
            minimum = _t(entry, "protocol-settings/min-version") or "tls1-0"
            out.append({"name": entry.get("name", ""), "certificate": _t(entry, "certificate"), "min_version": minimum, "min_is_default": not _has(entry, "protocol-settings/min-version"),
                        "max_version": _t(entry, "protocol-settings/max-version") or "max", "sha1": _yes(entry, "protocol-settings/auth-algo-sha1"), "rsa_kex": _yes(entry, "protocol-settings/keyxchg-algo-rsa"),
                        "cbc": any(_yes(entry, f"protocol-settings/{k}") for k in ("enc-algo-aes-128-cbc", "enc-algo-aes-256-cbc", "enc-algo-3des"))})
    return out


def _server_profiles(root: ET.Element) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    holders = [root.find("shared")] + root.findall("devices/entry")
    for holder in holders:
        base = holder.find("server-profile") if holder is not None else None
        if base is None:
            continue
        for kind in ("tacplus", "radius", "ldap", "kerberos", "saml-idp"):
            for entry in _entries(base, kind):
                servers = [{"name": s.get("name", ""), "address": _t(s, "address") or _t(s, "host") or _t(s, "server"), "port": _t(s, "port")} for s in _entries(entry, "server")]
                if kind == "kerberos":
                    servers = [{"name": entry.get("name", ""), "address": _t(entry, "host"), "port": _t(entry, "port")}]
                out.append({"kind": {"tacplus": "TACACS+", "radius": "RADIUS", "ldap": "LDAP", "kerberos": "Kerberos", "saml-idp": "SAML IdP"}[kind], "name": entry.get("name", ""), "servers": servers,
                            "protocol": _t(entry, "protocol"), "admin_only": _yes(entry, "admin-use-only"), "ssl": _yes(entry, "ssl"), "verify_cert": _yes(entry, "verify-server-certificate"),
                            "timeout": _t(entry, "timeout")})
    return out


def _auth_profiles(root: ET.Element) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    holders = [root.find("shared")] + root.findall("devices/entry")
    for holder in holders:
        for entry in _entries(holder, "authentication-profile"):
            method = (_children_tags(entry.find("method")) or [""])[0]
            sp = _t(entry, f"method/{method}/server-profile") if method else ""
            out.append({"name": entry.get("name", ""), "method": method, "server_profile": sp, "failed_attempts": _t(entry, "lockout/failed-attempts"), "lockout_time": _t(entry, "lockout/lockout-time")})
    return out


def _admins(root: ET.Element) -> list[dict[str, Any]]:
    out = []
    for entry in root.findall("mgt-config/users/entry"):
        role_node = entry.find("permissions/role-based")
        tags = _children_tags(role_node)
        role = tags[0] if tags else ""
        profile = ""
        if role == "custom":
            profile = _t(role_node, "custom/profile")
        out.append({"name": entry.get("name", ""), "role": role or "(none)", "role_profile": profile, "auth_profile": _t(entry, "authentication-profile"), "local_password": _has(entry, "phash"),
                    "client_cert_only": _yes(entry, "client-certificate-only") is True, "superuser": role.startswith("superuser")})
    return out


def _syslog(root: ET.Element) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    holders = [root.find("shared")] + root.findall("devices/entry")
    for holder in holders:
        for entry in _entries(holder, "server-profile/syslog") + _entries(holder, "log-settings/syslog"):
            for srv in _entries(entry, "server"):
                out.append({"profile": entry.get("name", ""), "server": _t(srv, "server"), "transport": _t(srv, "transport", "UDP"), "port": _t(srv, "port", "514"), "format": _t(srv, "format", "BSD"), "facility": _t(srv, "facility")})
    return out


def _log_forwarding(shared: ET.Element | None) -> dict[str, Any]:
    ls = shared.find("log-settings") if shared is not None else None
    if ls is None:
        return {}
    kinds = {}
    for kind in ("system", "config", "hipmatch", "iptag", "userid", "globalprotect", "correlation"):
        entries = _entries(ls, f"{kind}/match-list")
        if entries:
            kinds[kind] = [{"name": e.get("name", ""), "filter": _t(e, "filter"), "panorama": _yes(e, "send-to-panorama") is True, "syslog": _members(e, "send-syslog")} for e in entries]
    return {"match_lists": kinds, "profiles": [e.get("name", "") for e in _entries(ls, "profiles")]}


def _vsys(device: ET.Element | None) -> list[dict[str, Any]]:
    if device is None:
        return []
    return [{"name": e.get("name", ""), "display_name": _t(e, "display-name"), "zones": len(_entries(e, "zone")), "interfaces": len(_members(e, "import/network/interface"))}
            for e in device.findall("vsys/entry")]


def _globalprotect(root: ET.Element) -> list[dict[str, Any]]:
    out = []
    for kind, tag in (("gateway", "global-protect-gateway"), ("portal", "global-protect-portal"), ("site-to-site", "global-protect-site-to-site")):
        for holder in root.iter(tag):
            for entry in holder.findall("entry"):
                out.append({"kind": kind, "name": entry.get("name", ""), "tunnel_interface": _t(entry, "tunnel-interface")})
    return out


# --------------------------------------------------------------------- findings
def evaluate(extra: dict[str, Any], today: date | None = None) -> list[dict[str, Any]]:
    today = today or date.today()
    out: list[dict[str, Any]] = []
    s, ha = extra.get("system") or {}, extra.get("ha") or {}
    managed = bool(s.get("panorama"))
    used_certs = {p["certificate"] for p in extra.get("tls_profiles", []) if p["certificate"]}

    for cert in extra.get("certificates", []):
        days = cert["days_left"]
        if days is None:
            continue
        used = cert["name"] in used_certs
        if days < 0:
            out.append(finding("PAN-CRT-001", "high" if used else "low", "Certificates", f"Certificate expired {-days} days ago" + (" and is used by a service profile" if used else ""), obj=f"certificate {cert['name']} (CN {cert['common_name'] or '—'})",
                               detail=f"Valid until {cert['not_after']}." + (" An SSL/TLS service profile presents it, so administrators or portal users get certificate errors and may be trained to click through warnings." if used else " Nothing in this export references it."),
                               recommendation="Issue a new certificate from the enterprise or a public CA, import it, select it in the SSL/TLS service profile, commit, and delete the expired one." if used else "Delete certificates that are no longer needed.", reference=PALO["replace_mgmt_cert"]))
        elif days <= EXPIRY_WARN_DAYS:
            out.append(finding("PAN-CRT-002", "medium" if used else "low", "Certificates", f"Certificate expires in {days} days", obj=f"certificate {cert['name']} (CN {cert['common_name'] or '—'})",
                               detail=f"Valid until {cert['not_after']}.", recommendation="Renew it before expiry and update the SSL/TLS service profile that uses it.", reference=PALO["replace_mgmt_cert"]))
        if cert["algorithm"].upper() == "RSA" and cert["self_signed"] and used:
            out.append(finding("PAN-CRT-003", "low", "Certificates", "Management certificate is self-signed", obj=f"certificate {cert['name']}",
                               detail="Administrators cannot verify the firewall identity and learn to accept certificate warnings.", recommendation="Use a certificate from the enterprise CA for the management and portal profiles.", reference=PALO["replace_mgmt_cert"]))

    for prof in extra.get("tls_profiles", []):
        if prof["min_version"] in WEAK_TLS:
            suffix = " (the default when min-version is not set)" if prof["min_is_default"] else ""
            out.append(finding("PAN-TLS-001", "medium", "Management", f"SSL/TLS service profile allows {WEAK_TLS[prof['min_version']]}", obj=f"ssl-tls-service-profile {prof['name']}",
                               detail=f"min-version is {prof['min_version']}{suffix}, so clients can negotiate a protocol with known weaknesses to the management GUI or portal.",
                               recommendation="Set the minimum version to TLS 1.2 (or 1.3 where all clients support it).", reference=PALO["ssl_tls_profile"]))
        elif prof["sha1"] is True:
            out.append(finding("PAN-TLS-002", "low", "Management", "SSL/TLS service profile allows SHA-1 authentication", obj=f"ssl-tls-service-profile {prof['name']}",
                               detail="auth-algo-sha1 is enabled.", recommendation="Disable SHA-1 and keep SHA-256 or SHA-384.", reference=PALO["ssl_tls_profile"]))

    if s:
        if not s["permitted_ip"] and s["mgmt_ip"]:
            out.append(finding("PAN-ADM-001", "medium", "Management", "No permitted-IP list on the management interface", obj="deviceconfig/system/permitted-ip",
                               detail="Without a permitted-IP list the management interface accepts connections from any address that can reach it.", recommendation="List only the administrator subnets and jump hosts under Device > Setup > Interfaces > Management > Permitted IP Addresses.", reference=PALO["admin_access"]))
        wide = [p["address"] for p in s["permitted_ip"] if p["address"] in ("0.0.0.0/0", "any") or re.search(r"/([0-7])$", p["address"])]
        if wide:
            out.append(finding("PAN-ADM-001", "medium", "Management", "Permitted-IP list contains a very wide range", obj=", ".join(wide), detail="A prefix of /7 or shorter admits a huge address space to the management plane.",
                               recommendation="Replace it with the specific management subnets.", reference=PALO["admin_access"]))
        if not s["banner"]:
            out.append(finding("PAN-ADM-004", "low", "Management", "No login banner is configured", obj="deviceconfig/system/login-banner",
                               detail="A legal warning banner supports prosecution of unauthorised access and is required by many security baselines.", recommendation="Set a login banner under Device > Setup > Management > General Settings.", reference=PALO["admin_access"]))
        if s["idle_timeout"].isdigit() and int(s["idle_timeout"]) > MAX_IDLE_MINUTES:
            out.append(finding("PAN-ADM-005", "low", "Management", f"Administrator idle timeout is {s['idle_timeout']} minutes", obj="deviceconfig/setting/management/idle-timeout",
                               detail="Long idle sessions on an unattended workstation give anyone nearby administrator access.", recommendation=f"Use {MAX_IDLE_MINUTES} minutes or less.", reference=PALO["admin_access"]))
        if not s["ntp"] and not managed:
            out.append(finding("PAN-NTP-001", "medium", "Operations", "No NTP server is configured", obj="deviceconfig/system/ntp-servers",
                               detail="Log timestamps, certificate validation and HA state depend on correct time.", recommendation="Configure primary and secondary NTP servers.", reference=PALO["admin_access"]))
        elif s["ntp"] and all(n["auth"] == "none" for n in s["ntp"]):
            out.append(finding("PAN-NTP-002", "info", "Operations", "NTP servers are not authenticated", obj=", ".join(n["server"] for n in s["ntp"]),
                               detail="authentication-type is none, so a spoofed NTP reply can shift the clock.", recommendation="Use symmetric-key or autokey NTP authentication where the time source supports it.", reference=PALO["admin_access"]))
        if s["snmp_v2c"]:
            out.append(finding("PAN-SNMP-001", "medium", "Management", "SNMPv2c is enabled", obj="deviceconfig/system/snmp-setting",
                               detail="The v2c community string is sent in clear text and anyone who learns it can read device state.", recommendation="Use SNMPv3 with authentication and privacy, and limit the poller addresses in the permitted-IP list.", reference=PALO["snmp"]))
        if s["update_schedule_present"] and not s["update_schedule"]:
            out.append(finding("PAN-UPD-001", "low", "Operations", "No content update schedule is configured", obj="deviceconfig/system/update-schedule",
                               detail="Application, threat and antivirus content is only updated when somebody installs it by hand, so signatures can fall behind.", recommendation="Schedule recurring downloads and installs under Device > Dynamic Updates (or confirm Panorama pushes them).", reference=PALO["admin_access"]))

    if ha and ha["enabled"]:
        if ha["ha1_encryption"] is False:
            out.append(finding("PAN-HA-001", "low", "High availability", "HA1 control link is not encrypted", obj=f"HA1 {ha['ha1_port'] or ''} {ha['ha1_ip']}".strip(),
                               detail="Configuration sync and heartbeats between the peers travel unencrypted. On a direct back-to-back cable the exposure is small; over a switch or routed path it is not.", recommendation="Enable HA1 encryption (requires exporting/importing the HA key) or keep the link a dedicated cable.", reference=PALO["ha_config"]))
        if not ha["peer_ip"]:
            out.append(finding("PAN-HA-002", "medium", "High availability", "HA is enabled but no peer IP is set", obj="high-availability/group/peer-ip", detail="The firewall cannot find its HA peer on the control link.", recommendation="Set the peer HA1 IP address.", reference=PALO["ha_config"]))
        live_links = [g for g in ha["link_groups"] if g["enabled"]]
        if ha["link_monitoring"] is not True or not live_links:
            out.append(finding("PAN-HA-003", "medium", "High availability", "No active HA link monitoring", obj="high-availability/group/monitoring/link-monitoring",
                               detail="Link monitoring is " + ("off" if ha["link_monitoring"] is not True else "on, but every link group is disabled") + ", so a failed data-plane uplink does not trigger failover by itself.",
                               recommendation="Enable link monitoring on the uplink and downlink interfaces and add path monitoring for the upstream gateway.", reference=PALO["ha_failover"]))
        disabled = [g["name"] for g in ha["link_groups"] if not g["enabled"]]
        if disabled and live_links:
            out.append(finding("PAN-HA-005", "info", "High availability", f"{len(disabled)} HA link group(s) are disabled", obj=", ".join(disabled), detail="Interfaces in these groups do not influence failover.",
                               recommendation="Remove groups that are no longer used so the monitoring configuration reflects what is actually protected.", reference=PALO["ha_failover"]))
        if ha["state_sync"] is False:
            out.append(finding("PAN-HA-004", "low", "High availability", "Session synchronisation is disabled", obj="high-availability/group/state-synchronization",
                               detail="Established sessions are dropped at failover.", recommendation="Enable state synchronization on the HA2 link.", reference=PALO["ha_config"]))
        if not ha["ha1_backup"] and ha["heartbeat_backup"] is not True:
            out.append(finding("PAN-HA-006", "low", "High availability", "No backup HA1 path", obj="high-availability/interface/ha1-backup",
                               detail="Neither HA1-backup nor heartbeat backup (over the management port) is set, so a single cable fault can split the cluster.", recommendation="Enable heartbeat backup or add an HA1 backup link.", reference=PALO["ha_config"]))

    admins = extra.get("admins", [])
    supers = [a for a in admins if a["superuser"]]
    if len(supers) >= 4:
        out.append(finding("PAN-ADM-003", "low", "Management", f"{len(supers)} accounts hold the superuser role", obj=", ".join(a["name"] for a in supers),
                           detail="Every superuser can change or erase the whole configuration.", recommendation="Use custom admin roles with least privilege and keep few superusers.", reference=PALO["admin_accounts"]))
    local_super = [a["name"] for a in supers if a["local_password"]]
    if local_super:
        out.append(finding("PAN-ADM-002", "low", "Management", f"{len(local_super)} local superuser account(s) with a stored password", obj=", ".join(local_super),
                           detail="Local accounts bypass the central TACACS+/RADIUS policy and accounting. (Their password hashes are not shown in this report.)", recommendation="Keep one break-glass local account with a vaulted password, authenticate everyone else through an authentication profile.", reference=PALO["admin_accounts"]))
    defined = {p["name"] for p in extra.get("auth_profiles", [])}
    missing = sorted({a["auth_profile"] for a in admins if a["auth_profile"] and a["auth_profile"] not in defined})
    if missing:
        out.append(finding("PAN-AUTH-001", "info", "Management", "Administrators use authentication profiles that are not defined in this file", obj=", ".join(missing),
                           detail="The profile is probably pushed from a Panorama template or lives in another scope, so the TACACS+/RADIUS settings behind it could not be checked here.", recommendation="Export the template or the running configuration of the firewall to review the full authentication chain.", reference=PALO["auth_profile"]))
    for srv in extra.get("server_profiles", []):
        if srv["kind"] == "LDAP" and srv["ssl"] is not True:
            out.append(finding("PAN-AUTH-002", "medium", "Management", "LDAP server profile does not use TLS", obj=f"ldap {srv['name']}", detail="Bind credentials and directory data cross the network in clear text.",
                               recommendation="Enable SSL/StartTLS and verify the server certificate.", reference=PALO["auth_profile"]))
        if srv["kind"] == "LDAP" and srv["ssl"] is True and srv["verify_cert"] is False:
            out.append(finding("PAN-AUTH-003", "low", "Management", "LDAP server certificate is not verified", obj=f"ldap {srv['name']}", detail="A rogue server could impersonate the directory.",
                               recommendation="Enable verify-server-certificate and import the CA.", reference=PALO["auth_profile"]))
    out += panos_xml_network.evaluate(extra.get("network") or {})
    return out


# --------------------------------------------------------------------- sections
def sections(extra: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    s, ha = extra.get("system") or {}, extra.get("ha") or {}
    if s:
        pairs = [("Management IP", f"{s['mgmt_ip']} / {s['netmask']}" if s["mgmt_ip"] else "—"), ("Default gateway", s["gateway"] or "—"), ("Domain", s["domain"] or "—"), ("Time zone", s["timezone"] or "—"),
                 ("DNS servers", ", ".join(s["dns"]) or "—"), ("NTP servers", ", ".join(f"{n['server']} (auth {n['auth']})" for n in s["ntp"]) or "—", "" if s["ntp"] else "warn"),
                 ("Login banner", "set" if s["banner"] else "not set", "" if s["banner"] else "warn"), ("Idle timeout (min)", s["idle_timeout"] or "default"),
                 ("Management SSL/TLS profile", s["ssl_tls_profile"] or "—"), ("Content update server", s["update_server"] or "—"),
                 ("Content update schedule", ", ".join(s["update_schedule"]) or "none", "" if s["update_schedule"] else "warn"),
                 ("Panorama", ", ".join(s["panorama"]) or "not managed"), ("SNMP", "v2c enabled" if s["snmp_v2c"] else (f"v3 ({len(s['snmp_v3_users'])} user(s))" if s["snmp_v3_users"] else "not configured"), "warn" if s["snmp_v2c"] else ""),
                 ("SNMP location / contact", " / ".join(v for v in (s["snmp_location"], s["snmp_contact"]) if v) or "—")]
        for svc, value in s["services"].items():
            pairs.append((f"Management service {svc}", "disabled" if value == "yes" else "ENABLED", "" if value == "yes" else ("bad" if svc in ("telnet", "http") else "")))
        out.append(kv_section("mgmt_plane", "Management plane", pairs, group="System", hint="Read from deviceconfig/system of the XML export."))
        out.append(table_section("permitted_ip", "Management permitted IP addresses", [("address", "Address", "mono"), ("description", "Description", "wrap")], s["permitted_ip"], group="System",
                                 empty="No permitted-IP list: the management interface accepts any source."))
        if s["snmp_v3_users"]:
            out.append(table_section("snmp_v3", "SNMPv3 users", [("name", "User", "mono"), ("view", "View"), ("has_auth", "Auth password"), ("has_priv", "Privacy password")],
                                     [dict(u, has_auth="set" if u["has_auth"] else "not set", has_priv="set" if u["has_priv"] else "not set") for u in s["snmp_v3_users"]], group="System", hint="Passwords are never displayed."))
    if ha:
        out.append(kv_section("ha", "High availability", [("Enabled", "yes" if ha["enabled"] else "no"), ("Mode", ha["mode"] or "—"), ("Group ID", ha["group_id"] or "—"), ("Description", ha["description"] or "—"), ("Device priority", ha["priority"] or "—"),
                                                          ("Preemptive", {True: "yes", False: "no", None: "default"}[ha["preemptive"]]), ("Peer HA1 IP", ha["peer_ip"] or "—", "" if ha["peer_ip"] else "warn"),
                                                          ("HA1", f"{ha['ha1_port'] or '—'} {ha['ha1_ip']}".strip()), ("HA1 encryption", {True: "on", False: "off", None: "default (off)"}[ha["ha1_encryption"]], "warn" if ha["ha1_encryption"] is not True else ""),
                                                          ("HA2", ha["ha2_port"] or "—"), ("State synchronisation", {True: "on", False: "off", None: "default"}[ha["state_sync"]]),
                                                          ("Link monitoring", {True: "on", False: "off", None: "default (off)"}[ha["link_monitoring"]], "" if ha["link_monitoring"] else "warn"),
                                                          ("Path monitoring", {True: "on", False: "off", None: "default (off)"}[ha["path_monitoring"]]), ("Heartbeat backup", {True: "on", False: "off", None: "default"}[ha["heartbeat_backup"]]),
                                                          ("Passive link state", ha["passive_link_state"] or "—")], group="System"))
        if ha["link_groups"]:
            out.append(table_section("ha_links", "HA link monitoring groups", [("name", "Group", "mono"), ("interfaces", "Interfaces", "list"), ("condition", "Failure condition"), ("enabled", "Enabled")],
                                     [dict(g, enabled="yes" if g["enabled"] else "no", _tones={"enabled": "" if g["enabled"] else "mute"}) for g in ha["link_groups"]], group="System"))
    if extra.get("certificates"):
        rows = []
        for c in extra["certificates"]:
            days = c["days_left"]
            state = "unknown" if days is None else ("EXPIRED" if days < 0 else f"{days} days")
            rows.append(dict(c, state=state, ca="yes" if c["ca"] else "no", self_signed="yes" if c["self_signed"] else "no",
                             _tones={"state": "bad" if days is not None and days < 0 else ("warn" if days is not None and days <= EXPIRY_WARN_DAYS else "ok")}))
        out.append(table_section("pan_certificates", "Certificates", [("name", "Name", "mono"), ("scope", "Scope"), ("common_name", "Common name"), ("expiry", "Expires"), ("state", "Remaining", "status"), ("algorithm", "Algorithm"),
                                                                      ("ca", "CA"), ("self_signed", "Self-signed")], rows, group="System", hint="Private and public key material is never shown."))
    if extra.get("tls_profiles"):
        out.append(table_section("tls_profiles", "SSL/TLS service profiles", [("name", "Profile", "mono"), ("certificate", "Certificate"), ("min_version", "Min version"), ("max_version", "Max version")],
                                 [dict(p, _tones={"min_version": "bad" if p["min_version"] in WEAK_TLS else "ok"}) for p in extra["tls_profiles"]], group="System"))
    if extra.get("server_profiles"):
        out.append(table_section("server_profiles", "Authentication server profiles", [("kind", "Type"), ("name", "Profile", "mono"), ("servers", "Servers", "list"), ("protocol", "Protocol"), ("admin_only", "Admin only")],
                                 [dict(p, servers=[f"{s['name']} {s['address']}:{s['port']}".strip() if s["port"] else f"{s['name']} {s['address']}".strip() for s in p["servers"]], admin_only={True: "yes", False: "no", None: "—"}[p["admin_only"]])
                                  for p in extra["server_profiles"]], group="System", hint="Shared secrets are never shown."))
    if extra.get("auth_profiles"):
        out.append(table_section("auth_profiles", "Authentication profiles", [("name", "Profile", "mono"), ("method", "Method"), ("server_profile", "Server profile"), ("failed_attempts", "Failed attempts"), ("lockout_time", "Lockout (min)")],
                                 extra["auth_profiles"], group="System"))
    if extra.get("admins"):
        defined = {p["name"] for p in extra.get("auth_profiles", [])}
        out.append(table_section("pan_admins", "Administrator accounts", [("name", "User", "mono"), ("role", "Role"), ("role_profile", "Role profile"), ("auth_profile", "Authentication profile"), ("local_password", "Local password")],
                                 [dict(a, local_password="stored" if a["local_password"] else "none", _tones={"role": "warn" if a["superuser"] else "", "auth_profile": "mute" if a["auth_profile"] and a["auth_profile"] not in defined else ""}) for a in extra["admins"]],
                                 group="System", hint="Password hashes are never displayed. A muted profile name is not defined in this file (probably pushed by Panorama)."))
    if extra.get("syslog"):
        out.append(table_section("pan_syslog", "Syslog server profiles", [("profile", "Profile", "mono"), ("server", "Server", "mono"), ("transport", "Transport"), ("port", "Port"), ("format", "Format"), ("facility", "Facility")], extra["syslog"], group="System"))
    lf = extra.get("log_forwarding") or {}
    if lf.get("match_lists"):
        rows = [{"kind": kind, "name": e["name"], "filter": e["filter"], "panorama": "yes" if e["panorama"] else "no", "syslog": e["syslog"]} for kind, entries in lf["match_lists"].items() for e in entries]
        out.append(table_section("log_forwarding", "System log forwarding", [("kind", "Log type"), ("name", "Match list", "mono"), ("filter", "Filter", "wrap"), ("panorama", "To Panorama"), ("syslog", "Syslog profiles", "list")], rows, group="System"))
    if len(extra.get("vsys") or []) > 0:
        out.append(table_section("vsys_list", "Virtual systems", [("name", "ID", "mono"), ("display_name", "Display name"), ("zones", "Zones", "num"), ("interfaces", "Imported interfaces", "num")], extra["vsys"], group="System"))
    if extra.get("globalprotect"):
        out.append(table_section("globalprotect", "GlobalProtect / large-scale VPN objects", [("kind", "Kind"), ("name", "Name", "mono"), ("tunnel_interface", "Tunnel interface")], extra["globalprotect"], group="VPN"))
    out += panos_xml_network.sections(extra.get("network") or {})
    return out
