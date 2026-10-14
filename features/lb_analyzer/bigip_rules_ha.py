"""Findings for high availability (device groups, traffic groups, sync, failover) and for the live state of a terminal capture."""

from __future__ import annotations

from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .refs import F5
from .bigip_context import LCtx




# ===================================================================== HA
def ha_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d = ctx.data
    out: list[dict[str, Any]] = []
    devices = d["devices"]
    groups = [g for g in d["device_groups"] if not g["system_group"] and g["type"] == "sync-failover"]
    if not devices and not d["device_groups"]:
        return out
    paired = len(devices) > 1 or any(len(g["devices"]) > 1 for g in groups)
    if not groups:
        out.append(finding("LB-HA-001", "low", "High availability", "No sync-failover device group", obj="cm device-group",
                           detail=f"{len(devices) or 1} device(s) and no sync-failover device group: this BIG-IP is a single point of failure for every virtual server.", recommendation="Build an active-standby pair (device trust, sync-failover group, traffic group) for production services.", reference=F5["dsc_failover"]))
    for g in groups:
        if len(g["devices"]) == 1:
            out.append(finding("LB-HA-008", "low", "High availability", "Sync-failover group has one member", obj=g["short"], detail=f"{g['short']} lists only {g['devices'][0]}.", recommendation="Add the peer device or document that the service is not redundant.", reference=F5["device_group"]))
        if g["network_failover"] == "disabled":
            out.append(finding("LB-HA-002", "medium", "High availability", "Network failover is disabled", obj=g["short"], detail=f"{g['short']} has network-failover disabled; failover then depends on a hard-wired serial cable, which virtual editions do not have.", recommendation="Enable network-failover and list unicast addresses on the HA VLAN and the management network.", reference=F5["dsc_failover"]))
        if len(g["devices"]) > 1 and g["auto_sync"] != "enabled":
            out.append(finding("LB-HA-003", "low", "High availability", "Configuration sync is manual", obj=g["short"], detail=f"{g['short']} has auto-sync {g['auto_sync']} (documented default: disabled). A change made on one unit stays there until someone runs a sync, and an unsynced standby fails over with an old configuration.",
                               recommendation="Enable auto-sync, or make 'config-sync' part of every change procedure and monitor the sync status.", reference=F5["device_group"]))
    for dev in devices:
        if paired and len(dev["unicast"]) < 2:
            out.append(finding("LB-HA-004", "low", "High availability", "Fewer than two network-failover addresses", obj=dev["short"],
                               detail=f"{dev['short']} lists {len(dev['unicast'])} failover unicast address(es). The F5 failover guide says to configure unicast self IPs, preferably on the HA VLAN, plus management IPs, so a single link loss does not split the pair.",
                               recommendation="Add both an HA-VLAN self IP and the management address as failover unicast addresses.", reference=F5["dsc_failover"]))
    if paired:
        for va in d["virtual_addresses"]:
            if "local-only" in va["traffic_group"] and any(v["destination"] == va["address"] for v in d["virtuals"] if v["enabled"]):
                out.append(finding("LB-HA-005", "medium", "High availability", "Virtual address is pinned to this device", obj=va["short"],
                                   detail=f"{va['short']} is in traffic-group-local-only, which never fails over; after a failover the virtual server stays on the failed unit.", recommendation="Move the virtual address to a floating traffic group (traffic-group-1).", reference=F5["dsc_failover"]))
        floating = any(s["floating"] for s in d["selfs"])
        if not floating and any(v["snat"] == "automap" for v in d["virtuals"] if v["enabled"]) and d["selfs"]:
            out.append(finding("LB-HA-006", "low", "High availability", "SNAT automap in an HA pair without a floating self IP", obj="net self",
                               detail="Virtual servers use SNAT automap and no self IP is in a floating traffic group, so the source address of server-side connections changes on failover and mirrored connections cannot continue.", recommendation="Add a floating self IP (traffic-group-1) on each server-side VLAN.", reference=F5["dsc_failover"]))
        if (any(v["mirror"] for v in d["virtuals"]) or any(p["attrs"].get("mirror", "disabled") == "enabled" for p in d["persistence"])) and not any(dev["mirror_ip"] for dev in devices):
            out.append(finding("LB-HA-007", "medium", "High availability", "Connection or persistence mirroring is requested but no mirror address exists", obj="cm device",
                               detail="At least one virtual server or persistence profile has mirror enabled, yet no device has a mirror-ip, so the mirrored state cannot reach the peer.", recommendation="Set mirror-ip (and mirror-secondary-ip) on every device, on a dedicated VLAN.", reference=F5["device"]))
    return out


# ===================================================================== live state
def runtime_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    rt = ctx.runtime
    out: list[dict[str, Any]] = []
    sync = rt.get("sync")
    if sync and sync.get("status") and sync["status"].lower() not in ("in sync", "standalone"):
        out.append(finding("LB-RT-001", "high", "Live state", f"Configuration sync status is '{sync['status']}'", obj="cm sync-status", detail=sync.get("summary", "") or "The device group is not in sync.",
                           recommendation="Review the pending changes and sync from the device that holds the correct configuration ('run cm config-sync to-group <group>').", reference=F5["device_group"]))
    fo = rt.get("failover")
    if fo and fo.get("status") and fo["status"].lower() not in ("active", "standby", "standalone"):
        out.append(finding("LB-RT-002", "high", "Live state", f"Failover state is {fo['status']}", obj="cm failover-status", detail=fo.get("summary", "") or "The unit is neither active nor standby.", recommendation="Check the failover daemon, network failover addresses and the HA VLAN.", reference=F5["dsc_failover"]))
    for v in rt.get("virtuals", []):
        avail = v.get("availability", "").lower()
        if avail == "offline":
            out.append(finding("LB-RT-003", "high", "Live state", "Virtual server is offline", obj=v["name"], detail=f"{v['name']}: {v.get('reason') or 'availability offline'}.", recommendation="Look at the pool members and monitors behind it ('show ltm pool <name> members').", reference=F5["monitors_concepts"]))
        elif avail == "unavailable":
            out.append(finding("LB-RT-003", "medium", "Live state", "Virtual server is unavailable", obj=v["name"], detail=f"{v['name']}: {v.get('reason') or 'availability unavailable'}.", recommendation="Check whether it was disabled or whether its pool is empty.", reference=F5["virtual"]))
    for p in rt.get("pools", []):
        total, avail = p.get("total"), p.get("available")
        if total and avail == 0:
            out.append(finding("LB-RT-004", "high", "Live state", "Pool has no available members", obj=p["name"], detail=f"{p['name']}: 0 of {total} members available ({p.get('reason') or p.get('availability', '')}).", recommendation="Check the monitors and the servers.", reference=F5["monitors_concepts"]))
        elif total and avail is not None and avail < total:
            out.append(finding("LB-RT-004", "medium", "Live state", "Pool is running with fewer members than configured", obj=p["name"], detail=f"{p['name']}: {avail} of {total} members available.", recommendation="Find the members that are down and why.", reference=F5["monitors_concepts"]))
    return out
