"""Router health and log findings (CPU, memory, forwarding plane, power, storage, licensing, ``show logging``).

Every rule reads only parsed command output (``show process cpu``, ``show platform
resources``, ``show logging`` ...), so each one stays silent when its command was not
collected; the Coverage tab says what is missing.  Thresholds are Keystone
heuristics unless the finding says that Cisco states a value: the device's own
warning/critical thresholds (``show platform resources``) are used wherever the
platform prints them.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..analyzer_core.findings import finding as F
from .context import Ctx
from .refs import REFS as R
from .netutil import human_bytes as _size
from .rules import _cfg, _names, _parse_stamp, rule


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _version_key(text: str) -> tuple[str, ...]:
    """'17.03.03' and '17.3.3' compare equal; a trailing letter ('17.09.03a') is kept."""
    parts = re.findall(r"\d+|[a-z]+", (text or "").lower())
    return tuple(str(int(p)) if p.isdigit() else p for p in parts)


def _capture_time(ctx: Ctx) -> datetime | None:
    return _parse_stamp(str(ctx.get("clock") or ""))


_UPTIME_UNITS = {"year": 365 * 24, "week": 7 * 24, "day": 24, "hour": 1, "minute": 1 / 60}


def uptime_hours(text: str) -> float | None:
    if not text:
        return None
    total = 0.0
    found = False
    for number, unit in re.findall(r"(\d+)\s+(year|week|day|hour|minute)s?", text):
        total += int(number) * _UPTIME_UNITS[unit]
        found = True
    return total if found else None


def _model(ctx: Ctx) -> str:
    version = ctx.get("version") or {}
    return str(version.get("model") or "")


def _throughput_ref(ctx: Ctx) -> str:
    return R["isr4000_license"] if _model(ctx).upper().startswith("ISR4") else R["cat8000_throughput"]


# ---------------------------------------------------------------------------
# CPU, memory, forwarding plane
# ---------------------------------------------------------------------------


@rule
def health_cpu(ctx: Ctx):
    cpu = ctx.get("cpu")
    out = []
    if cpu and cpu.get("five_min") is not None:
        five = cpu["five_min"]
        if five >= 70:
            top = [p for p in cpu.get("processes", []) if p.get("five_min", 0) >= 1][:3]
            busy = ", ".join(f"{p['process']} {p['five_min']:.1f}%" for p in top) or "no single process stands out"
            out.append(F("RTR-HLT-001", "high" if five >= 85 else "medium", "Device health", f"Control-plane CPU is {five}% over five minutes",
                         detail=f"5 s {cpu.get('five_sec')}% (interrupt {cpu.get('interrupt')}%), 1 min {cpu.get('one_min')}%, 5 min {five}%. Busiest processes: {busy}. "
                                "Thresholds are Keystone heuristics, not a Cisco limit.",
                         recommendation="Find the process and the cause (routing churn, SNMP polling, logging, punted traffic) with 'show processes cpu sorted' and "
                                        "'show processes cpu platform sorted'; for forwarding load see 'show platform hardware qfp active datapath utilization'.",
                         reference=R["tac_high_cpu"]))
    history = ctx.get("cpu_history")
    if history and history.get("hour"):
        hour = history["hour"]
        if hour.get("peak", 0) >= 80:
            sustained = hour.get("mean_of_maxima", 0) >= 50
            out.append(F("RTR-HLT-002", "medium" if sustained else "low", "Device health", f"CPU reached {hour['peak']}% during the last 72 hours",
                         detail=f"Hourly maxima: peak {hour['peak']}%, average {hour.get('mean_of_maxima')}% over {hour.get('samples')} samples. "
                                + ("The average is high, so this is not a single spike." if sustained else "The average is low, so this looks like short spikes."),
                         recommendation="Correlate the peak time with the log ('show logging') and with routing or tunnel events at that moment.", reference=R["tac_high_cpu"]))
    return out


@rule
def health_memory(ctx: Ctx):
    out = []
    pools = (ctx.get("process_memory") or {}).get("pools") or (ctx.get("memory_statistics") or {}).get("pools") or []
    for pool in pools:
        # The lsmpi_io pool is always close to 100% on IOS-XE (packet I/O buffers); only the Processor pool says anything.
        if pool.get("pool") != "Processor":
            continue
        used = pool.get("used_pct", 0)
        if used >= 80:
            out.append(F("RTR-HLT-010", "high" if used >= 90 else "medium", "Device health", f"IOS Processor memory is {used}% used",
                         detail=f"{_size(pool.get('used'))} of {_size(pool.get('total'))} in use. A leak shows as one process whose 'Holding' value keeps growing between captures.",
                         recommendation="'show processes memory platform sorted' twice, some hours apart, and compare the top holders; check the release notes for memory defects.", reference=R["iosxe_memory"]))
    stats = ctx.get("memory_statistics")
    if stats:
        for pool in stats.get("pools", []):
            if pool.get("pool") == "Processor" and pool.get("lowest_free_pct") is not None and pool["lowest_free_pct"] <= 10:
                out.append(F("RTR-HLT-012", "medium", "Device health", f"Processor memory once dropped to {pool['lowest_free_pct']}% free",
                             detail="'Lowest' in 'show memory statistics' is the low-water mark since the last reload, so the router has been this close to exhaustion before.",
                             recommendation="Identify what allocated the memory at that time (BGP/route table growth, NAT or crypto sessions).", reference=R["iosxe_memory"]))
    return out


@rule
def health_platform_resources(ctx: Ctx):
    """The platform prints its own warning / critical thresholds; a row in W or C state is the device saying so."""
    rows = ctx.get("platform_resources")
    if not rows:
        return []
    have_fs = bool(ctx.get("file_systems"))
    out = []
    for row in rows:
        state = row.get("state")
        if state not in ("W", "C"):
            continue
        if row.get("resource") == "bootflash" and have_fs:
            continue  # reported from 'show file systems' with real byte counts
        out.append(F("RTR-HLT-011", "high" if state == "C" else "medium", "Device health", f"{row['scope']} {row['resource']} is in {'critical' if state == 'C' else 'warning'} state ({row['usage']})",
                     obj=f"{row['scope']} {row['resource']}",
                     detail=f"Maximum {row.get('max')}; the platform warns at {row.get('warning')} and is critical at {row.get('critical')}.",
                     recommendation="Check the matching 'show processes cpu platform sorted' / 'show processes memory platform sorted' output and the Cisco guidance for this resource.",
                     reference=R["tac_high_cpu"] if "CPU" in row["resource"] else R["iosxe_memory"]))
    return out


@rule
def health_forwarding_plane(ctx: Ctx):
    """QFP is the forwarding ASIC of ASR1000 / ISR4000 / Catalyst 8000.  The control-plane CPU can be idle while it is saturated."""
    out = []
    util = ctx.get("qfp_utilization")
    if util:
        five = util.get("processing_5min", 0)
        peak = util.get("processing_peak", 0)
        if peak >= 70:
            load = util["processing"]
            out.append(F("RTR-HLT-020", "high" if five >= 85 else "medium", "Forwarding plane", f"QFP packet-processing load reached {peak}%",
                         detail=f"Load by window (5 s / 1 min / 5 min / 60 min): {' / '.join(str(v) + '%' for v in load)}. Input {util['input_pps'][2]:,} pps and output {util['output_pps'][2]:,} pps over 5 minutes. "
                                "Thresholds are Keystone heuristics: there is no fixed Cisco limit, the headroom depends on features (NAT, IPsec, QoS, ACLs).",
                         recommendation="Check what the load is made of ('show platform hardware qfp active feature ...' per feature), the licensed throughput and the drop counters.",
                         reference=R["asr1000_high_cpu"]))
    mem = ctx.get("qfp_exmem")
    rows = ctx.get("platform_resources") or []
    if mem and not any(r.get("scope", "").startswith("ESP") and r.get("resource") == "DRAM" for r in rows):
        for memory in mem["memories"]:
            if memory["type"] == "DRAM" and memory["used_pct"] >= 80:
                out.append(F("RTR-HLT-021", "high" if memory["used_pct"] >= 90 else "medium", "Forwarding plane", f"QFP DRAM is {memory['used_pct']}% used",
                             detail=f"{_size(memory.get('used'))} of {_size(memory['total'])}; lowest free so far {memory['lowest_free_pct']}%.",
                             recommendation="NAT translations, ACL/QoS policy size and IPsec state are the usual consumers: see 'show platform hardware qfp active infrastructure exmem statistics user'.",
                             reference=R["asr1000_high_cpu"]))
    return out


# ---------------------------------------------------------------------------
# Chassis: power, fans, temperature, redundancy
# ---------------------------------------------------------------------------

_NORMAL_STATES = {"normal", "ok", "good", "green", "online"}


_POWER_SENSOR = re.compile(r"^(V|I|P):", re.I)
# Cisco TechNote 221177: a 0 mV reading on ISR4431/4451 with a CPLD revision of 38 or lower is a known cosmetic defect (ISR4461: 40 or lower).
_CPLD_COSMETIC = {"ISR4431": 38, "ISR4451": 38, "ISR4461": 40}


def _cpld_note(ctx: Ctx) -> str:
    chassis = (ctx.get("platform_slots") or {}).get("chassis", "")
    model = next((m for m in _CPLD_COSMETIC if m in chassis.upper().replace("-", "")), "")
    firmware = (ctx.get("platform_slots") or {}).get("firmware") or []
    cpld = next((f["cpld"] for f in firmware if f["slot"] in ("0", "R0")), "")
    if not model or not cpld.isdigit():
        return ""
    revision = int(cpld[-2:])
    limit = _CPLD_COSMETIC[model]
    if revision <= limit:
        return f" The CPLD revision is {revision} (…{cpld}), at or below {limit}, the range in which Cisco describes a 0 mV reading as a known cosmetic defect fixed by a CPLD upgrade."
    return f" The CPLD revision is {revision} (…{cpld}), above {limit}, so the cosmetic CPLD defect that Cisco describes for 0 mV readings does not explain it."


@rule
def health_environment(ctx: Ctx):
    out = []
    env = ctx.get("environment") or {}
    slots = (ctx.get("platform_slots") or {}).get("slots", [])
    alarms = env.get("alarms", {})
    failed = [s for s in slots if re.search(r"fail|fault|critical|problem|badinput", s["state"], re.I)]
    abnormal = [s for s in env.get("sensors", []) if s["state"].lower() not in _NORMAL_STATES]
    power_slots = [s for s in failed if re.match(r"^P\d", s["slot"])]
    power_sensors = [s for s in abnormal if _POWER_SENSOR.match(s["sensor"])]
    temp_sensors = [s for s in abnormal if s["unit"] == "Celsius"]
    other = [s for s in abnormal if s not in power_sensors and s not in temp_sensors]
    other_slots = [s for s in failed if s not in power_slots]
    counts = ", ".join(f"{n} {k}" for k, n in alarms.items() if n)

    if power_slots or power_sensors:
        parts = [f"slot {s['slot']} ({s['type']}) is '{s['state']}'" for s in power_slots]
        parts += [f"{s['slot']} {s['sensor']} is {s['state']} ({s['value']:g} {s['unit']})" for s in power_sensors[:4]]
        if counts:
            parts.append(f"alarm counters: {counts}")
        zero = any(s["value"] == 0 and s["sensor"].startswith("V:") for s in power_sensors)
        label = power_slots[0]["slot"] if power_slots else power_sensors[0]["slot"]
        out.append(F("RTR-HLT-030", "high" if any(re.search(r"crit|shut", s["state"], re.I) for s in power_sensors) or alarms.get("critical") else "medium", "Chassis",
                     f"Power supply {label} is not delivering power" if zero or power_slots else f"Power supply {label} reports {power_sensors[0]['state']}",
                     obj=_names(sorted({s["slot"] for s in power_slots} | {s["slot"] for s in power_sensors})),
                     detail="; ".join(parts) + (". The chassis runs on the remaining supply and has lost its power redundancy; a second failure or a power cut on the feed that still works takes the router down."
                                               if power_slots else ". If the reading is real the chassis has lost its power redundancy; Cisco rates this log message as a warning with no service impact, because several of the causes are cosmetic.")
                            + " Cisco lists these causes for a 'V: PEM Out' warning: a CPLD defect, a supply that is inserted but not connected to active power, a stalled monitor, or a hardware fault." + _cpld_note(ctx),
                     recommendation="Check the power feed and cable of that supply first, then reseat it; after a hard power cycle of the chassis (all supplies off for 30 s or more) replace it if the warning stays.",
                     reference=R["power_supply_voltage"]))
    if temp_sensors:
        out.append(F("RTR-HLT-031", "high" if any(re.search(r"crit", s["state"], re.I) for s in temp_sensors) else "medium", "Chassis", f"{len(temp_sensors)} temperature sensor(s) are not normal",
                     obj=_names([f"{s['slot']} {s['sensor']}" for s in temp_sensors]), detail=_names([f"{s['slot']} {s['sensor']} {s['state']} at {s['value']:g} °C" for s in temp_sensors], 6),
                     recommendation="Check airflow, filters, rack temperature and fan state.", reference=R["isr4000_temperature"]))
    hot = [s for s in env.get("sensors", []) if s["unit"] == "Celsius" and s.get("critical") and s["value"] >= s["critical"] - 5 and s not in temp_sensors]
    if hot:
        out.append(F("RTR-HLT-031", "medium", "Chassis", "Temperature is within 5 °C of the critical threshold", obj=_names([f"{s['slot']} {s['sensor']}" for s in hot]),
                     detail=_names([f"{s['slot']} {s['sensor']} {s['value']:g} °C (critical {s['critical']})" for s in hot]),
                     recommendation="Check airflow, filters, rack temperature and fan state.", reference=R["isr4000_temperature"]))
    if other or other_slots or ((alarms.get("critical") or alarms.get("major") or alarms.get("minor")) and not (power_slots or power_sensors or temp_sensors)):
        parts = [f"slot {s['slot']} ({s['type']}) is '{s['state']}'" for s in other_slots] + [f"{s['slot']} {s['sensor']} is {s['state']}" for s in other[:6]]
        if counts:
            parts.append(f"alarm counters: {counts}")
        out.append(F("RTR-HLT-032", "high" if alarms.get("critical") else "medium", "Chassis", "Hardware alarm reported by the chassis", obj=_names(sorted({s["slot"] for s in other_slots} | {s["slot"] for s in other})),
                     detail="; ".join(parts) + ".", recommendation="'show environment all', 'show platform' and 'show logging' show when it started; raise an RMA if it persists after a reseat."))
    return out


@rule
def health_redundancy(ctx: Ctx):
    out = []
    states = ctx.get("redundancy_states")
    history = ctx.get("redundancy_history")
    if states:
        configured = (states.get("configured_mode") or "").lower()
        if configured and "non-redundant" not in configured and "simplex" not in (states.get("mode") or "").lower() and "STANDBY HOT" not in (states.get("peer_state") or "").upper():
            out.append(F("RTR-HLT-033", "high", "Chassis", "Redundant route processor is not in STANDBY HOT", detail=f"Configured mode {states.get('configured_mode')}; peer state {states.get('peer_state')}; redundancy state {states.get('redundancy_state')}.",
                         recommendation="'show redundancy' and 'show platform' on the active unit."))
    if history and history.get("switchovers"):
        out.append(F("RTR-HLT-034", "medium", "Chassis", f"{history['switchovers']} redundancy switchover(s) recorded", detail="; ".join(str(e) for e in history.get("switchover_events", [])[:5]),
                     recommendation="Find the reason in 'show redundancy history' and the logs around the time."))
    stacks = ctx.get("stacks")
    if stacks and stacks.get("crash_mentioned"):
        out.append(F("RTR-HLT-035", "medium", "Device health", "'show stacks' reports a crash stack trace", recommendation="Keep the output and the crashinfo/core files for TAC.", reference=R["crash_reason"]))
    return out


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------


@rule
def health_storage(ctx: Ctx):
    out = []
    current = next((f for f in ctx.get("file_systems") or [] if f.get("current")), None)
    if current and current.get("size"):
        free = current["free_pct"]
        if free < 20:
            out.append(F("RTR-HLT-040", "high" if free < 10 else "medium", "Storage", f"{current['prefixes'][0]} has only {free}% free ({_size(current['free'])})",
                         detail="An image upgrade needs room for the new image plus the packages it unpacks; a full bootflash also stops crash files and trace logs from being written.",
                         recommendation="Remove inactive packages ('install remove inactive'), old .bin images and old trace files after confirming the rollback image is not needed.", reference=R["install_remove_inactive"]))
    flash = ctx.get("bootflash")
    version = ctx.get("version") or {}
    if flash:
        running = _version_key(version.get("version", ""))
        old = []
        for image in flash.get("images", []):
            match = re.search(r"\.(\d+\.\d+\.\d+[a-z]?)\.SPA", image["path"], re.I)
            if match and running and _version_key(match.group(1)) != running:
                old.append((image["path"].rsplit("/", 1)[-1], image["size"]))
        stale = [v for v in flash.get("package_versions", []) if running and _version_key(v) != running]
        if old or stale:
            total = sum(size for _, size in old)
            low = bool(current and current.get("free_pct", 100) < 30)
            detail = []
            if old:
                detail.append(f"{len(old)} image file(s) other than the running {version.get('version')}: " + _names([f"{n} ({_size(s)})" for n, s in old]) + f" = {_size(total)}.")
            if stale:
                detail.append("Package files of other releases are also present: " + ", ".join(stale) + ".")
            out.append(F("RTR-HLT-041", "medium" if low else "low", "Storage", "Old software images or packages are kept on bootflash",
                         detail=" ".join(detail) + " Keep one known-good rollback image on purpose; the rest only uses space. Deleting the previous image makes a rollback to it fail.",
                         recommendation="In install mode: 'install remove inactive'. In bundle mode: 'delete bootflash:<image>.bin' for images you will not roll back to.", reference=R["install_remove_inactive"]))
        if flash.get("cores"):
            out.append(F("RTR-HLT-042", "medium", "Storage", f"{len(flash['cores'])} crash/core file(s) on the router", obj=_names(flash["cores"]),
                         detail="Core files exist only after a process or the system crashed.", recommendation="Open a TAC case with the cores and 'show tech-support' before deleting them.", reference=R["crash_reason"]))
    return out


# ---------------------------------------------------------------------------
# Licensing and throughput
# ---------------------------------------------------------------------------

_ACK = re.compile(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\d{4})")


@rule
def health_license(ctx: Ctx):
    out = []
    lic = ctx.get("license_all")
    logs = ctx.get("logging") or {}
    now = _capture_time(ctx)
    if lic and lic.get("using_policy"):
        deadline = None
        match = _ACK.search(lic.get("next_ack_deadline", ""))
        if match:
            try:
                deadline = datetime.strptime(" ".join(match.groups()), "%b %d %H:%M:%S %Y")
            except ValueError:
                deadline = None
        never = lic.get("last_ack", "").strip("<> ").lower() == "none"
        failures = logs.get("smart_license_failures", 0)
        if deadline and now and deadline < now and never:
            months = round((now - deadline).days / 30.4)
            out.append(F("RTR-HLT-050", "low", "Licensing", "Smart Licensing usage has never been acknowledged",
                         detail=f"'{lic.get('command', 'show license all')}': last ACK none, next ACK deadline {lic['next_ack_deadline']} ({months} months before this capture), transport {lic.get('transport', '?')}, policy {str(lic.get('policy', '?')).rstrip('.')}."
                                + (f" The log holds {failures} %SMART_LIC-3-COMM_FAILED message(s): the router cannot reach its licence server." if failures else "")
                                + " Under Smart Licensing Using Policy the router must report usage and receive an acknowledgement; this is a compliance and audit exposure, not an outage.",
                         recommendation="Fix the transport (CSLU address, DNS/reachability, or offline report upload) and force a report; Cisco's troubleshooting guide lists the checks per transport.",
                         reference=R["smart_lic_troubleshoot"]))
        elif failures >= 5:
            out.append(F("RTR-HLT-050", "low", "Licensing", f"{failures} Smart Licensing communication failures in the log",
                         recommendation="Check the licence transport and reachability; see the Cisco troubleshooting guide.", reference=R["smart_lic_troubleshoot"]))
    bandwidth = [e for e in logs.get("license_bandwidth", []) if e["level"] == "max"]
    if bandwidth:
        limit = bandwidth[-1]["limit"]
        periods = sum(e["periods"] for e in bandwidth)
        out.append(F("RTR-HLT-052", "medium" if len(bandwidth) >= 3 else "low", "Licensing", f"Traffic reached the licensed throughput of {limit} ({len(bandwidth)} event(s) in the log)",
                     detail=f"%BW_LICENSE max-level messages from {bandwidth[0]['time']} to {bandwidth[-1]['time']}, {periods} sampling periods in total. Cisco documents that traffic above the licensed rate is shaped, which adds delay and drops.",
                     recommendation="Confirm the traffic is legitimate, then raise the throughput licence for this platform (see the Cisco guide) or move traffic to another router.", reference=_throughput_ref(ctx)))
    version = ctx.get("version") or {}
    crypto = version.get("crypto_throughput_kbps")
    ipsec = ctx.models.get("ipsec") or {}
    hsec = any("hsec" in (item.get("name", "") + item.get("tag", "")).lower() and item.get("status", "").upper() == "IN USE" for item in (ctx.get("license_usage") or {}).get("licenses", []))
    if crypto and crypto <= 500_000 and ipsec.get("tunnels") and not hsec:
        out.append(F("RTR-HLT-053", "info", "Licensing", f"IPsec throughput on this router is limited to {crypto // 1000} Mbps",
                     detail=f"'show version' prints 'current crypto throughput level is {crypto} kbps' while {len(ipsec['tunnels'])} IPsec tunnel(s) are configured. "
                            "On Catalyst 8000 routers Cisco ties encrypted throughput above 250 Mbps and more than 1000 tunnels to the HSECK9 licence; ISR4000 follows the performance licence.",
                     recommendation="Compare the peak encrypted traffic with this limit ('show platform hardware throughput crypto' on Catalyst 8000, 'show platform hardware throughput level' on ISR4000).",
                     reference=_throughput_ref(ctx)))
    return out


# ---------------------------------------------------------------------------
# Logging configuration and the log itself
# ---------------------------------------------------------------------------


@rule
def logs_settings(ctx: Ctx):
    logging = ctx.get("logging")
    if not logging:
        return []
    out = []
    settings = logging.get("settings", {})
    console = settings.get("console") or {}
    if console.get("level") == "debugging":
        out.append(F("RTR-LOG-010", "low", "Logging", f"Console logging is at level debugging ({console['logged']:,} messages sent to the console)",
                     detail="Every log message is also written to the console line, and 'debug' output goes there as well. Cisco warns that excessive debug output on the console can make a router hang.",
                     recommendation="'logging console critical' (or 'no logging console'); read logs from the buffer or the syslog server.", reference=R["debug_console"]))
    hosts = settings.get("hosts") or []
    size = settings.get("buffer_bytes")
    if size and size < 32_000 and not hosts:
        out.append(F("RTR-LOG-011", "medium", "Logging", f"Log buffer is only {size:,} bytes and there is no syslog server",
                     detail=f"The buffer holds about {logging.get('message_count', 0)} messages ({logging.get('first', '?')} to {logging.get('last', '?')}); older evidence of flaps, logins and configuration changes is overwritten.",
                     recommendation="'logging buffered 1024000 informational' and 'logging host <ip>' so events survive the buffer and a reload.", reference=R["harden_ios"]))
    for host in hosts:
        if host.get("dropped"):
            out.append(F("RTR-LOG-012", "low", "Logging", f"Syslog server {host['host']} dropped {host['dropped']:,} message lines", obj=host["host"],
                         recommendation="Check the path and the server capacity.", reference=R["harden_ios"]))
    if settings.get("rate_limited", 0) > 100:
        out.append(F("RTR-LOG-013", "low", "Logging", f"{settings['rate_limited']:,} log messages were rate-limited", recommendation="Review 'logging rate-limit' and find the chatty source.", reference=R["harden_ios"]))
    return out


@rule
def logs_login_flood(ctx: Ctx):
    logging = ctx.get("logging")
    if not logging:
        return []
    out = []
    logins = logging.get("logins", {})
    total = logging.get("message_count", 0)
    if logins.get("count", 0) >= 500 and total and logins["count"] / total >= 0.3:
        sources = ", ".join(f"{s} ({n:,})" for s, n in list(logins["sources"].items())[:3])
        users = ", ".join(f"{u} ({n:,})" for u, n in list(logins["users"].items())[:3])
        out.append(F("RTR-LOG-020", "low", "Logging", f"Successful logins make up {100 * logins['count'] // total}% of the log buffer ({logins['count']:,} messages)",
                     detail=f"Top sources: {sources}. Top users: {users}. Repeated logins from one address are typically a monitoring system that opens an SSH session per poll; "
                            "they push real events (flaps, configuration changes) out of the buffer and are sent to every syslog server.",
                     recommendation="Move that polling to SNMPv3 or an API with a persistent session. Keep 'login on-success log' (the DISA STIG check requires it) but enlarge the buffer and forward logs to a syslog server.",
                     reference=R["stig_login"]))
    failures = logging.get("login_failures", [])
    if failures:
        by_source: dict[str, int] = {}
        for row in failures:
            by_source[row["source"]] = by_source.get(row["source"], 0) + row["count"]
        top_source, top_count = max(by_source.items(), key=lambda kv: kv[1])
        out.append(F("RTR-LOG-021", "medium" if top_count >= 10 else "low", "Logging", f"{sum(by_source.values())} failed login(s) in the log; most from {top_source} ({top_count})", obj=top_source,
                     detail=_names([f"{r['source']} as '{r['user']}': {r['count']} ({r['reason']})" for r in failures], 6),
                     recommendation="Confirm the sources are administrators; restrict vty access with an access-class, and use 'login block-for' against password guessing.", reference=R["harden_ios"]))
    return out


@rule
def logs_flaps(ctx: Ctx):
    logging = ctx.get("logging")
    if not logging:
        return []
    out = []
    flaps = logging.get("flaps", {})
    window = f"{logging.get('first', '?')} to {logging.get('last', '?')}"
    noisy = {name: row for name, row in flaps.get("interfaces", {}).items() if row["down"] >= 3}
    if noisy:
        worst = sorted(noisy.items(), key=lambda kv: -kv[1]["down"])
        out.append(F("RTR-LOG-030", "medium" if worst[0][1]["down"] >= 10 else "low", "Link stability", f"{len(noisy)} interface(s) went down 3 or more times in the log", obj=_names([n for n, _ in worst], 6),
                     detail=_names([f"{n}: {r['down']} down / {r['up']} up ({r['first']} to {r['last']})" for n, r in worst], 6) + f". Log window {window}.",
                     recommendation="For physical links check optics, cabling and counters; for tunnels see the tunnel source, keepalives and the underlay path.", reference=R["interface_troubleshooting"]))
    for name, row in flaps.get("tracks", {}).items():
        if row["down"] >= 2:
            out.append(F("RTR-LOG-031", "medium", "Link stability", f"{name} went down {row['down']} times", obj=name,
                         detail=f"{row['down']} down / {row['up']} up between {row['first']} and {row['last']}. A tracked object drives failover (static route, HSRP or policy), so every flap moves traffic.",
                         recommendation="Check the probe target and path; add 'delay down/up' on the track so a short loss does not trigger failover.", reference=R["ipsla"]))
    for name, row in flaps.get("ospf", {}).items():
        if row["down"] >= 1:
            reasons = ", ".join(f"{r} ×{n}" for r, n in row["reasons"].items()) or "no reason in the message"
            out.append(F("RTR-LOG-032", "medium" if row["down"] >= 2 else "low", "OSPF", f"OSPF adjacency {name} dropped {row['down']} time(s)", obj=name,
                         detail=f"Reasons: {reasons}. First {row['first']}, last {row['last']}. 'Dead timer expired' means Hellos stopped arriving (link loss, congestion, filtering); "
                                "'Interface down or detached' means the local interface or circuit went away.",
                         recommendation="Correlate with the interface and tunnel events at the same time and with the neighbour's own log.", reference=R["ospf"]))
    for name, row in flaps.get("bgp", {}).items():
        reasons = row["reasons"]
        admin_only = reasons and all("admin" in reason.lower() for reason in reasons)
        if row["down"] >= 1:
            out.append(F("RTR-LOG-033", "info" if admin_only else "medium", "BGP", f"BGP neighbor {name} went down {row['down']} time(s)", obj=name,
                         detail="Reasons: " + (", ".join(f"{r} ×{n}" for r, n in reasons.items()) or "none in the message") + f". First {row['first']}, last {row['last']}."
                                + (" An administrative shutdown is an operator action, not a fault." if admin_only else ""),
                         recommendation="" if admin_only else "Check 'show ip bgp neighbors' for the last reset reason, hold-timer settings and the underlay path.", reference=R["bgp"]))
    for name, row in flaps.get("omp", {}).items():
        if row["down"] >= 1:
            states = ", ".join(f"{r} ×{n}" for r, n in row["reasons"].items())
            out.append(F("RTR-LOG-034", "medium" if row["down"] >= 3 else "low", "SD-WAN", f"OMP session to the {name} was lost {row['down']} time(s)", obj=name,
                         detail=f"The log shows the peer leaving Up ({states}) and {row['up']} time(s) coming back Up between {row['first']} and {row['last']}. While no vSmart is connected the router keeps its last policy and routes but receives no updates. "
                                "The control connection to the same vSmart usually drops at the same moment; compare with the connection history.",
                         recommendation="Read 'show sdwan control connection-history' for the same time and check the transport that carried the connection.", reference=R["sdwan_control_troubleshoot"]))
    if (logging.get("omp_vsmarts") or {}).get("min") == 0:
        out.append(F("RTR-LOG-035", "high", "SD-WAN", "The log reports 0 vSmarts connected at some point",
                     detail="OMP logged 'Number of vSmarts connected : 0', so for that period the router had no OMP peer and could not learn routes, TLOCs or policy.",
                     recommendation="Find the time in the log and check the control connections and the transport at that time.", reference=R["sdwan_control_troubleshoot"]))
    return out


@rule
def logs_restarts(ctx: Ctx):
    """Restart messages and crash / fault indicators that are still in the log buffer."""
    logging = ctx.get("logging")
    if not logging:
        return []
    out = []
    restarts = logging.get("restarts") or []
    if restarts:
        out.append(F("RTR-LOG-060", "low", "Device health", f"The log holds {len(restarts)} restart or reload message(s)",
                     detail=_names([f"{r['time']}: {r['message'][:80]}" for r in restarts], 3) + ". The log buffer is cleared by a reload, so these lines are from after the last one, or from a buffer that survived (persistent logging).",
                     recommendation="Compare with the reload reason in 'show version' and with change records; an unplanned restart needs the crashinfo and core files.", reference=R["syslog_xe_17_9"]))
    crashes = logging.get("crashes") or []
    if crashes:
        kinds: dict[str, list[dict[str, str]]] = {}
        for item in crashes:
            kinds.setdefault(item["kind"], []).append(item)
        serious = any(k in kinds for k in ("process failure", "memory allocation failure", "watchdog"))
        out.append(F("RTR-LOG-061", "medium" if serious else "low", "Device health", f"{len(crashes)} fault indicator(s) in the log: " + ", ".join(f"{k} ×{len(v)}" for k, v in kinds.items()),
                     detail=_names([f"{v[0]['time']} {v[0]['tag']}: {v[0]['message'][:90]}" for v in kinds.values()], 4)
                            + ". These are message patterns (PMAN process failures, memory allocation failures, CPU hogs, tracebacks); a message alone does not prove the router crashed.",
                     recommendation="Check 'show version' for an unexpected reload, 'dir' of bootflash: for crashinfo and core files, and open a TAC case with 'show tech-support' if the message repeats.", reference=R["router_crashes_xe"]))
    return out


@rule
def logs_changes(ctx: Ctx):
    logging = ctx.get("logging")
    if not logging or not logging.get("config_changes"):
        return []
    changes = logging["config_changes"]
    users: dict[str, int] = {}
    for change in changes:
        users[change["user"]] = users.get(change["user"], 0) + 1
    return [F("RTR-LOG-040", "info", "Change audit", f"{len(changes)} configuration change(s) in the log buffer",
              detail="By user: " + ", ".join(f"{u} ×{n}" for u, n in sorted(users.items(), key=lambda kv: -kv[1])) + f". First {changes[0]['time']}, last {changes[-1]['time']}"
                     + (f" (from {changes[-1]['source']})" if changes[-1].get("source") else "") + ".",
              recommendation="Compare with the change records; enable 'archive' with 'log config' for command-level history.", reference=R["harden_ios"])]


@rule
def logs_ipsec_events(ctx: Ctx):
    logging = ctx.get("logging")
    if not logging:
        return []
    out = []
    spi = logging.get("invalid_spi") or {}
    if spi.get("count"):
        model = ctx.models.get("ipsec") or {}
        peers = {p for t in model.get("tunnels", []) for p in t.get("peers", [])}
        known = [s for s in spi["sources"] if s in peers]
        unknown = [s for s in spi["sources"] if s not in peers]
        if known:
            out.append(F("RTR-LOG-050", "low", "VPN", f"ESP packets with an unknown SPI arrived from a configured peer ({_names(known)})", obj=_names(known),
                         detail=f"{spi['count']} %CRYPTO-4-RECVD_PKT_INV_SPI message(s) in total. The peer is still encrypting with a security association this router no longer has, "
                                "typically after this router or the peer cleared its SAs or reloaded and the other side has not noticed.",
                         recommendation="Normally the peer recovers on its own (DPD or the next rekey). If it persists, clear the SA on both sides ('clear crypto session').", reference=R["invalid_spi"]))
        if unknown:
            out.append(F("RTR-LOG-051", "info", "VPN", f"{len(unknown)} source(s) sent ESP packets with an unknown SPI and are not configured peers", obj=_names(unknown, 4),
                         detail=f"{spi['count']} message(s) in total, addressed to {_names(list(spi['targets']))} on {_names(list(spi['interfaces']))}. The router discards them. "
                                "A source that is not a peer cannot have a valid SA with this router.",
                         recommendation="No action is needed for stray traffic; if the same sources appear constantly, filter ESP (protocol 50) at the edge to the peers you have.", reference=R["invalid_spi"]))
    deletes = logging.get("ike_deletes") or {}
    if deletes:
        out.append(F("RTR-LOG-052", "info", "VPN", f"IKE SAs were cleared manually {sum(deletes.values())} time(s)", obj=_names(list(deletes)),
                     detail="%CRYPTO-6-ISAKMP_MANUAL_DELETE: " + _names([f"{peer} ×{n}" for peer, n in deletes.items()], 8) + ". Each clear drops the tunnel until it renegotiates.",
                     recommendation="Make sure these clears were deliberate troubleshooting, not a workaround for a recurring problem.", reference=R["invalid_spi"]))
    return out


_NORMAL_RELOAD = ("reload command", "poweron", "power-on", "power on", "image install", "reload", "install")


@rule
def health_restart(ctx: Ctx):
    version = ctx.get("version") or {}
    out = []
    reason = (version.get("last_reload_reason") or "").strip()
    if reason and not reason.lower().startswith(_NORMAL_RELOAD):
        out.append(F("RTR-HLT-060", "high", "Device health", f"The router last restarted because of: {reason}",
                     detail=f"Uptime {version.get('uptime', '?')}; 'System returned to ROM by' = {version.get('last_reload', 'n/a')}. Anything other than a reload command, a power cycle or an install is an unplanned restart.",
                     recommendation="Collect 'show tech-support', the crashinfo and core files before the next reload and open a TAC case.", reference=R["crash_reason"]))
    hours = uptime_hours(version.get("uptime", ""))
    if hours is not None and hours < 48:
        out.append(F("RTR-HLT-061", "info", "Device health", f"The router has been up only {version.get('uptime')}",
                     detail=f"Last reload: {version.get('last_reload', 'n/a')}. Counters, NAT/IPsec statistics, the log and BGP/OSPF uptimes cover this short period only, so rates and 'never' statements are weak evidence.",
                     recommendation="If this was not planned, find the reload reason first; otherwise repeat the capture after a few days."))
    return out
