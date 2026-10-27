"""Findings from the live system, network and traffic ``show`` output (``bigip_runtime_sys``): HA conditions, licence, TLS versions, ports, ARP, load.

Silent without that output.  Counters such as interface errors and iRule failures are cumulative since the last reset, so they are
reported as evidence to look at, not as a current fault.
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_context import LCtx
from .refs import F5

_NAMES = {"SSL Protocol Version 2": "SSLv2", "SSL Protocol Version 3": "SSLv3", "TLS Protocol Version 1.0": "TLS 1.0", "TLS Protocol Version 1.1": "TLS 1.1",
          "DTLS Protocol Version 1": "DTLS 1.0"}
_BUILD_DATE = re.compile(r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?:\d\d:\d\d:\d\d\s+\S+\s+)?(?P<year>\d{4})")
EXPIRY_WARNING_DAYS = 90
CPU_BUSY = 80


def _build_date(text: str) -> date | None:
    """'Wed Oct  8 14:16:07 PDT 2025' -> date(2025, 10, 8)."""
    found = _BUILD_DATE.search(text or "")
    if not found:
        return None
    try:
        return datetime.strptime(f"{found['mon']} {found['day']} {found['year']}", "%b %d %Y").date()
    except ValueError:
        return None


def _performance(rt: dict[str, Any], group: str, metric: str) -> dict[str, Any] | None:
    return next((r for r in rt.get("performance") or [] if r["group"] == group and r["metric"] == metric), None)


def sys_runtime_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    rt = ctx.runtime
    out: list[dict[str, Any]] = []

    for row in rt.get("ha_status") or []:                              # LB-RT-005: a high-availability condition has triggered
        if row["failed"]:
            out.append(finding("LB-RT-005", "high", "Live state", f"HA condition '{row['feature']}' has triggered", obj=f"sys ha-status {row['feature']} {row['key']}",
                               detail=f"'show sys ha-status' reports Fail = yes for {row['feature']} / {row['key']}; the configured action is '{row['action']}'.",
                               recommendation="Find what raised the condition (daemon, interface, license or provisioning) in /var/log/ltm, clear it, and confirm the unit returns to Active or Standby.", reference=F5["sys_ha_status"]))

    for link in (rt.get("failover") or {}).get("connections") or []:   # LB-RT-006: a failover heartbeat path is not Ok
        if link["status"].lower() != "ok":
            out.append(finding("LB-RT-006", "high", "Live state", f"Failover connection to {link['remote']} is {link['status']}", obj=f"cm failover-status {link['local']}",
                               detail=f"The failover link from {link['local']} to {link['remote']} reports '{link['status']}' (last packet {link['last']}, {link['transitions']} transitions).",
                               recommendation="Check the network-failover address, the VLAN and the port-lockdown for UDP 1026 / TCP 1026 between the peers. With only one path left the pair can split-brain.", reference=F5["dsc_failover"]))

    devices = rt.get("cm_devices") or []
    active = [d["hostname"] for d in devices if d["state"].lower() == "active"]
    if len(devices) > 1 and len(active) > 1:                          # LB-RT-007
        out.append(finding("LB-RT-007", "high", "Live state", "More than one device claims to be active", obj="cm device",
                           detail=f"'show cm device' lists {', '.join(active)} as active in the same view: a split-brain, or traffic groups spread over both units on purpose.",
                           recommendation="If this is not an active-active design, check the failover links, then force one unit to standby.", reference=F5["device"]))

    lic = rt.get("license") or {}
    version = rt.get("version") or {}
    built = _build_date(version.get("date", ""))
    checked = lic.get("service_check_date")
    if built and checked and checked < built:                          # LB-RT-008: the licence does not cover this software release
        out.append(finding("LB-RT-008", "high", "Live state", "Licence service check date is older than the installed software", obj="sys license",
                           detail=f"The licence was last checked on {checked.isoformat()}, but TMOS {version.get('version', '')} was built on {built.isoformat()}. A release newer than the service check date needs the licence to be re-activated, otherwise 'license-invalid' can take the unit offline at the next restart.",
                           recommendation="Re-activate the licence (System > License > Re-activate, or 'tmsh install sys license'), then confirm 'show sys license' shows a newer Service Check Date.", reference=F5["sys_license"]))
    for item in lic.get("limited") or []:                              # LB-RT-009: a time-limited module has expired or is about to
        end = item.get("end_date")
        if not end:
            continue
        days = (end - ctx.today).days
        if days < 0:
            out.append(finding("LB-RT-009", "medium", "Live state", f"Time-limited licence module expired: {item['name']}", obj=f"sys license {item['name']}",
                               detail=f"{item['name']} ended on {end.isoformat()} ({-days} days ago).", recommendation="Renew the subscription and re-activate the licence; the feature it enabled stops updating.", reference=F5["sys_license"]))
        elif days <= EXPIRY_WARNING_DAYS:
            out.append(finding("LB-RT-009", "low", "Live state", f"Time-limited licence module expires in {days} days: {item['name']}", obj=f"sys license {item['name']}",
                               detail=f"{item['name']} ends on {end.isoformat()}.", recommendation="Plan the renewal and the licence re-activation before that date.", reference=F5["sys_license"]))

    for profile in (rt.get("client_ssl") or []) + (rt.get("server_ssl") or []):   # LB-RT-010: handshakes were negotiated with a deprecated protocol
        legacy = {_NAMES[k]: v for k, v in (profile.get("protocols") or {}).items() if k in _NAMES}
        if legacy:
            side = "client-side" if profile["kind"] == "client" else "server-side"
            used = ", ".join(f"{name}: {count}" for name, count in legacy.items())
            out.append(finding("LB-RT-010", "medium", "Live state", f"{profile['name']} negotiated a deprecated TLS version", obj=f"ltm profile {profile['kind']}-ssl {profile['name']}",
                               detail=f"The {side} profile {profile['name']} completed handshakes with {used}. TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS and NIST SP 800-52r2 expectations for strong cryptography.",
                               recommendation="Find the clients that still connect that way (capture the handshakes or log them with an iRule on CLIENTSSL_HANDSHAKE), move them to TLS 1.2 or later, then disable the old versions in the profile's options (no-tlsv1, no-tlsv1.1) or its cipher string.",
                               reference=F5["nist_800_52"]))

    for row in rt.get("interfaces") or []:                             # LB-RT-011: a port that counts drops or errors
        if row["status"].lower() == "up" and (row["errors_n"] or row["drops_n"]):
            severity = "medium" if row["errors_n"] else "low"
            out.append(finding("LB-RT-011", severity, "Live state", f"Interface {row['name']} has {'errors' if row['errors_n'] else 'drops'}", obj=f"net interface {row['name']}",
                               detail=f"{row['name']}: errors {row['errors']}, drops {row['drops']} (media {row['media']}). The counters are cumulative since the last reset.",
                               recommendation="Clear the counters ('reset-stats net interface'), watch whether they grow, and check cable, optic, duplex and the switch port.", reference=F5["net_interface"]))

    incomplete = [r for r in rt.get("arp") or [] if r["mac"] == "incomplete"]
    for row in incomplete:                                             # LB-RT-012: the BIG-IP asked for a neighbor and nobody answered
        out.append(finding("LB-RT-012", "low", "Live state", f"ARP entry for {row['address']} is incomplete", obj=f"net arp {row['address']}",
                           detail=f"{row['address']} on VLAN {row['vlan']} has no MAC address ({row['status']}). A pool member, gateway or peer there is not answering.",
                           recommendation="Check that the host is up and in the VLAN, and that the pool member's address belongs to a self IP subnet of that VLAN.", reference=F5["net_arp"]))

    cpu = _performance(rt, "System CPU Usage", "Utilization")
    if cpu and cpu["current_n"] is not None and cpu["current_n"] >= CPU_BUSY:   # LB-RT-013
        out.append(finding("LB-RT-013", "medium", "Live state", f"CPU utilisation is {cpu['current']}%", obj="sys performance system",
                           detail=f"Current {cpu['current']}%, average {cpu['average']}%, maximum {cpu['maximum']}% since {cpu['since']}.",
                           recommendation="Look at connection and throughput peaks, SSL TPS and the busiest virtual servers; consider adding capacity before the next peak.", reference=F5["sys_performance"]))
    swap = _performance(rt, "Memory Used", "Swap Used")
    if swap and (swap["maximum_n"] or 0) > 0:
        out.append(finding("LB-RT-013", "medium", "Live state", f"The system has used swap ({swap['maximum']}%)", obj="sys performance memory",
                           detail=f"Swap use reached {swap['maximum']}% since {swap['since']}. A BIG-IP that swaps has too little memory for its provisioned modules.",
                           recommendation="Review 'show sys provision' and reduce the modules or their footprint ('tmsh modify sys provision ... level minimum').", reference=F5["sys_provision"]))

    for rule in rt.get("rules") or []:                                 # LB-RT-014: iRule events that fail or abort
        if rule["failures"] or rule["aborts"]:
            out.append(finding("LB-RT-014", "medium", "Live state", f"iRule {rule['rule']} fails or aborts in {rule['event'] or 'an event'}", obj=f"ltm rule {rule['rule']}",
                               detail=f"{rule['rule']} {rule['event']}: {rule['total']} executions, {rule['failures']} failures, {rule['aborts']} aborts. A TCL error resets or drops the connection that triggered it.",
                               recommendation="Look for 'TCL error' in /var/log/ltm with this rule name and fix the script.", reference=F5["rule"]))
    return out
