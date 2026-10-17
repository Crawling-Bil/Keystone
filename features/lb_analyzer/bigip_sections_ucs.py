"""Tabs built from the UCS archive: archive facts, timeline, license, module resources, customised ``sys db`` values, the
saved-configuration history, accounts and operating-system access rules, installed packages and custom files.

Everything is read from ``data["ucs"]`` (see ``bigip_enrich``); a plain configuration upload yields no tab from this module.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from ..analyzer_core.result import kv_section, table_section
from .bigip_extract import short

GROUP = "UCS archive"
HISTORY = "Change history"
WIB = timedelta(hours=7)          # Western Indonesia Time, UTC+7 (no daylight saving)
LOCAL_ROLES_NOTE = "Role id as stored in /config/bigip/auth/userrolepartitions."


def _tone_days(days: int | None) -> str:
    return "" if days is None else "bad" if days < 0 else "warn" if days <= 30 else "info" if days <= 90 else "ok"


def ucs_sections(data: dict[str, Any], today: date) -> list[dict[str, Any]]:
    ucs = data.get("ucs")
    if not ucs:
        return []
    bundle, facts, history = ucs["bundle"], ucs["facts"], ucs["history"]
    out = _archive(bundle, facts, today)
    out += _license(bundle, today)
    out += _resources(bundle)
    out += _accounts(bundle, data)
    out += _packages_and_files(bundle)
    out += _changes(history, data, today)
    return out


def _archive(bundle: Any, facts: dict[str, Any], today: date) -> list[dict[str, Any]]:
    v = bundle.version
    pairs = [("Product / version", f"{v.get('Product', 'BIG-IP')} {v.get('Version', '')} build {v.get('Build', '')}".strip()), ("Edition / built", f"{v.get('Edition', '')} · {v.get('Date', '')}".strip(" ·")), ("Platform code", bundle.platform.get("platform", "")),
             ("Archive entries", f"{bundle.members:,} ({bundle.total_bytes / 1048576:,.0f} MB uncompressed)"), ("Configuration files read", ", ".join(f"{n.split('/')[-1]} ({size / 1024:,.0f} KB)" for n, size in bundle.files.items())),
             ("Public certificates read", len(bundle.certs)), ("Customised sys db values", len(bundle.db)), ("Saved-configuration patches read", len(bundle.history)),
             ("Custom /config/startup commands", "yes - review" if bundle.has_startup_additions else "none", "warn" if bundle.has_startup_additions else "")]
    for label, count in bundle.omitted.items():
        pairs.append((f"Deliberately not read: {label}", count))
    out = [kv_section("ucs_archive", "UCS archive", pairs, group=GROUP, hint="Read as a stream; private keys, password files, the master key store, shell histories and the license registration key are skipped.")]
    stamps = [("Last configuration change", facts["last_config_change"]), ("Last config sync (local)", facts["last_sync"]), ("Last time this unit became active", facts["last_active"]), ("Last time this unit became standby", facts["last_standby"]), ("Last UCS load / restore", facts["last_ucs_load"])]
    rows = [{"event": label, "when": when.strftime("%Y-%m-%d %H:%M UTC"), "age": f"{(today - when.date()).days} days ago"} for label, when in stamps if when]
    out.append(table_section("ucs_timeline", "Change and failover timeline", [("event", "Event"), ("when", "When (UTC)", "mono"), ("age", "Age")], rows, group=GROUP,
                             hint="From the sys db counters that mcpd and the failover daemon maintain; an old 'last active' time on a unit means it has been standby since."))
    return out


def _license(bundle: Any, today: date) -> list[dict[str, Any]]:
    lic = bundle.license
    if not lic:
        return []
    rows = []
    for m in lic["timelimited"]:
        days = (m["end"] - today).days if m["end"] else None
        rows.append({"module": m["module"], "kind": m["kind"] or "time-limited", "start": str(m["start"] or ""), "end": str(m["end"] or ""), "days": days if days is not None else "", "_tones": {"days": _tone_days(days)}})
    rows += [{"module": m, "kind": "active", "start": "", "end": "", "days": ""} for m in lic["active"]]
    out = [table_section("license_modules", "License: active and time-limited modules", [("module", "Module"), ("kind", "Type"), ("start", "Start", "mono"), ("end", "End", "mono"), ("days", "Days left", "num")], rows, group=GROUP)]
    fields = list(lic["fields"].items()) + [("Optional modules licensed (not necessarily provisioned)", len(lic["optional"]))]
    out.append(kv_section("license_info", "License", fields, group=GROUP, hint="The registration key and dossier are never read."))
    return out


def _resources(bundle: Any) -> list[dict[str, Any]]:
    modules: dict[str, dict[str, str]] = {}
    for key, entry in bundle.db.items():
        if key.startswith("Provision.") and entry["value"] not in ("0", ""):
            _, kind, mod = (key.split(".", 2) + [""])[:3]
            modules.setdefault(mod, {})[kind] = entry["value"]
    out = []
    if modules:
        out.append(table_section("resource_split", "Module resource allocation", [("module", "Module", "mono"), ("cpu", "CPU cores", "num"), ("memory", "Memory (MB)", "num"), ("disk", "Disk (MB)", "num")],
                                 [{"module": m, "cpu": v.get("CPU", ""), "memory": v.get("Memory", ""), "disk": v.get("Disk", "")} for m, v in sorted(modules.items())], group=GROUP,
                                 hint="Taken from the Provision.* values of the tenant (what the hypervisor or r-Series host gave each module)."))
    keep = [(k, e) for k, e in bundle.db.items() if not k.startswith(("Provision", "Provisioned", "Failover.ActiveTime", "Failover.StandbyTime", "LTM.ConfigTime", "UCS.LoadTime", "Configsync.LocalConfigTime"))]
    out.append(table_section("sys_db", "Customised system settings (sys db)", [("key", "Variable", "mono"), ("value", "Value", "wrap"), ("default", "Default", "wrap")], [{"key": k, "value": e["value"], "default": e["default"]} for k, e in sorted(keep)], group=GROUP,
                             hint="Only values that differ from the factory default. The GUI and SSH allow lists, SNMP allow list, NTP and failover settings show here as the device actually runs them."))
    return out


def _accounts(bundle: Any, data: dict[str, Any]) -> list[dict[str, Any]]:
    local = {u["name"]: u for u in data["auth"]["users"]}
    roles = {r["user"]: r for r in bundle.role_partitions}
    shells = {a["name"]: a for a in bundle.os_accounts}
    names = list(dict.fromkeys(list(local) + list(roles) + [a["name"] for a in bundle.os_accounts if a["login"]]))
    rows = []
    for name in names:
        cfg, role, osa = local.get(name), roles.get(name), shells.get(name)
        rows.append({"user": name, "defined": "yes" if cfg else "no (remote or removed)", "config_roles": (cfg or {}).get("roles") or ["-"], "config_shell": (cfg or {}).get("shell", "") or "-", "role_id": role["role_id"] if role else "-",
                     "partitions": role["partitions"] if role else "-", "os": ("login shell " + osa["shell"]) if osa and osa["login"] else ("no login" if osa else "-"),
                     "_tones": {"defined": "" if cfg else "warn", "os": "warn" if osa and osa["login"] and name not in ("root", "admin") else ""}})
    out = []
    if rows:
        out.append(table_section("accounts", "Accounts known to the device", [("user", "Account", "mono"), ("defined", "In the configuration"), ("config_roles", "Role in configuration", "list"), ("config_shell", "Shell (tmsh/bash)"), ("role_id", "Role id (UCS)"),
                                                                              ("partitions", "Partitions"), ("os", "Operating-system account")], rows, group=GROUP, page_size=100,
                                 hint=f"Combines auth user (bigip_user.conf), the role map and the operating-system account list. A user that is in the role map but not defined locally normally authenticates remotely (LDAP, RADIUS, TACACS+) and logged in at least once. {LOCAL_ROLES_NOTE}"))
    wrappers = [dict(r, source=label) for label in ("allow", "deny") for r in bundle.tcp_wrappers.get(label, [])]
    if wrappers:
        out.append(table_section("tcp_wrappers", "Operating-system access rules (hosts.allow / hosts.deny)", [("source", "File"), ("daemon", "Service", "mono"), ("clients", "Clients", "wrap")], wrappers, group=GROUP,
                                 hint="BIG-IP writes these from the sshd / snmp allow lists in the configuration; 'ALL : ALL' in hosts.deny is the default-deny that makes the allow list effective."))
    if bundle.session_limits:
        out.append(kv_section("session_limits", "SSH session limits", [(k.title(), v) for k, v in bundle.session_limits.items()], group=GROUP, hint="As stored in /config/bigip/auth/sshglobalsessionlimit and sshuserlimit."))
    return out


def _packages_and_files(bundle: Any) -> list[dict[str, Any]]:
    out = []
    if bundle.packages:
        out.append(table_section("packages", "iApp LX packages saved on the unit", [("name", "Package", "mono"), ("version", "Version"), ("release", "Release")], sorted(bundle.packages, key=lambda p: p["name"]), group=GROUP,
                                 hint="From the package file names in /var/config/rest/iapps (the packages are not opened). They install with the software image, so custom packages such as AS3 or Declarative Onboarding stand out."))
    if bundle.custom_files:
        out.append(table_section("custom_files", "Custom files outside the TMSH configuration", [("path", "Path", "mono"), ("kind", "Kind"), ("bytes", "Bytes", "num")], bundle.custom_files, group=GROUP,
                                 hint="Files that are part of the UCS but are not tmsh objects: they survive an upgrade only because the UCS carries them. Their content is not read."))
    return out


def _changes(history: dict[str, Any], data: dict[str, Any], today: date) -> list[dict[str, Any]]:
    if not history["count"]:
        return []
    out: list[dict[str, Any]] = []
    first, last = history["first"], history["last"]
    out.append(kv_section("change_summary", "Change history", [("Configuration saves recorded", history["count"]), ("First recorded", f"{first:%Y-%m-%d %H:%M UTC}"), ("Last recorded", f"{last:%Y-%m-%d %H:%M UTC} ({(today - last.date()).days} days ago)"),
                                                                ("Saves in the last 30 days", history["last_30_days"]), ("Pool members / virtual servers still disabled", len(history["disabled_since"]))], group=HISTORY,
                          hint="Built from the reverse-diff patches BIG-IP keeps in /config/.diffVersions: the time is when the configuration was saved, the lines are what that save added or removed. BIG-IP does not record who made a change, and the history is limited to the retained patches. Automatic ASM sync timestamps are left out."))
    out.append(table_section("change_months", "Saves per month", [("month", "Month", "mono"), ("saves", "Configuration saves", "num")], [{"month": m, "saves": c} for m, c in history["per_month"]], group=HISTORY))
    out.append(table_section("change_hot", "Most frequently changed objects", [("object", "Object", "mono"), ("changes", "Saves touching it", "num"), ("last", "Last changed (UTC)", "mono")],
                             [{"object": h["object"], "changes": h["changes"], "last": f"{h['last']:%Y-%m-%d %H:%M}"} for h in history["hot_objects"]], group=HISTORY))
    still = []
    pools = {p["name"]: p for p in data["pools"]}
    for (obj, member), st in sorted(history["disabled_since"].items()):
        when = st["disabled"] or st["offline"]
        kind = ("virtual server disabled" if not member else "member disabled" if st["disabled"] else "member forced offline")
        current = False
        if member and obj in pools:
            current = any(m["name"] == member and (m["disabled"] or m["forced_down"]) for m in pools[obj]["members"])
        elif not member:
            current = any(v["name"] == obj and not v["enabled"] for v in data["virtuals"])
        still.append({"object": short(obj), "member": short(member) if member else "(virtual server)", "state": kind, "since": f"{when:%Y-%m-%d}", "days": (today - when.date()).days, "current": "yes" if current else "no (changed since)",
                      "_tones": {"days": "warn" if (today - when.date()).days >= 30 else "", "current": "" if current else "mute"}})
    if still:
        out.append(table_section("change_still_disabled", "Still disabled or forced offline", [("object", "Pool / virtual server", "mono"), ("member", "Member", "mono"), ("state", "State"), ("since", "Since", "mono"), ("days", "Days", "num"), ("current", "Matches current config")], still, group=HISTORY,
                                 hint="Members and virtual servers that the history shows were disabled or forced offline and never re-enabled afterwards, checked against the configuration in this archive."))
    rows = []
    for c in reversed(history["changes"][-600:]):
        events = [f"{e['kind'].replace('-', ' ')}: {short(e['object'])}" + (f" → {short(e['member'])}" if e.get("member") else "") for e in c["events"]]
        rows.append({"when": f"{c['when']:%Y-%m-%d %H:%M}", "when_wib": f"{c['when'] + WIB:%Y-%m-%d %H:%M}", "file": c["file"], "revision": c["revision"], "objects": [short(o) if o.count(" ") < 3 else o for o in c["objects"][:12]], "events": events[:8], "added": c["added"], "removed": c["removed"],
                     "sample": "  ·  ".join(" ".join(s.split()) for s in c["sample"][:5])})
    out.append(table_section("change_log", "Configuration saves (newest first)", [("when", "Saved (UTC)", "mono"), ("when_wib", "Saved (WIB, UTC+7)", "mono"), ("file", "File"), ("revision", "Rev", "id"), ("objects", "Objects touched", "list"), ("events", "What happened", "list"), ("added", "Lines added", "num"),
                                                                                  ("removed", "Lines removed", "num"), ("sample", "Changed lines (sample)", "wrap")], rows, group=HISTORY, page_size=100,
                             hint="The newest 600 saves. 'What happened' is derived for pool-member state, virtual-server enable/disable and object create/delete; everything else is in the sample lines. Secrets in changed lines are hidden."))
    return out
