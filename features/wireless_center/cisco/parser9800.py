"""Cisco Catalyst 9800 parser: running-config plus the show commands of
`show tech-support wireless` (or a capture with the same commands).

Everything works from a plain `show running-config` too; the show commands
add runtime state (join status, serial, software, uptime, radios).
"""
from __future__ import annotations

import re
import shlex
from typing import Any

from .showtech import fixed_table, key_values, running_config, split_commands


def _mac(value: str) -> str:
    hexes = re.sub(r"[^0-9a-f]", "", (value or "").lower())
    return ".".join(hexes[i:i + 4] for i in (0, 4, 8)) if len(hexes) == 12 else (value or "").strip()


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


def blocks(config: str, prefix: str) -> list[tuple[list[str], list[str]]]:
    """Top-level blocks whose first line starts with `prefix`: (header words
    after the prefix, child lines stripped)."""
    out = []
    current = None
    for raw in config.splitlines():
        if not raw.strip() or raw.strip() == "!":
            if current is not None and raw.strip() == "!":
                current = None
            continue
        if not raw.startswith(" "):
            current = None
            if raw.startswith(prefix):
                current = (_words(raw[len(prefix):]), [])
                out.append(current)
        elif current is not None:
            current[1].append(raw.strip())
    return out


def _first(lines: list[str], pattern: str) -> str:
    for line in lines:
        m = re.match(pattern, line)
        if m:
            return m.group(1).strip().strip('"')
    return ""


def _has(lines: list[str], text: str) -> bool:
    return any(line == text or line.startswith(text + " ") for line in lines)


# ----------------------------------------------------------------- config objects
def wlans(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wlan "):
        if len(head) < 3 or not head[1].isdigit():
            continue
        profile, wlan_id, ssid = head[0], int(head[1]), head[2]
        no_wpa = "no security wpa" in lines
        psk = _has(lines, "security wpa akm psk")
        sae = _has(lines, "security wpa akm sae")
        dot1x = not _has(lines, "no security wpa akm dot1x") and not no_wpa
        wpa3 = _has(lines, "security wpa wpa3")
        wpa2 = not _has(lines, "no security wpa wpa2") and not no_wpa
        akm = [name for name, on in (("802.1X", dot1x), ("PSK", psk), ("SAE", sae)) if on]
        if no_wpa:
            security = "Open"
        else:
            security = "/".join(v for v, on in (("WPA2", wpa2), ("WPA3", wpa3)) if on) or "WPA"
            security += " " + "+".join(akm) if akm else ""
        mac_filter = _first(lines, r"mac-filtering\s+(\S+)")
        web_auth = _has(lines, "security web-auth")
        out.append({
            "id": wlan_id, "profile": profile, "ssid": ssid,
            "status": "UP" if _has(lines, "no shutdown") else "DOWN",
            "security": security.strip(),
            "auth_list": _first(lines, r"security dot1x authentication-list\s+(\S+)"),
            "mac_filtering": mac_filter,
            "web_auth": web_auth,
            "psk": _first(lines, r"security wpa psk set-key \S+ \d+\s+(.+)"),
            "broadcast": not _has(lines, "no broadcast-ssid"),
            "radio_policy": ", ".join(re.sub(r"^radio policy dot11\s+", "", l) for l in lines if l.startswith("radio policy dot11")) or "All",
            "ft": "Disabled" if _has(lines, "no security ft adaptive") else ("Enabled" if _has(lines, "security ft") else "Adaptive"),
            "config": lines,
        })
    return sorted(out, key=lambda w: w["id"])


def policy_profiles(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wireless profile policy "):
        if not head:
            continue
        local_switching = _has(lines, "no central switching")
        out.append({
            "name": head[0],
            "description": _first(lines, r"description\s+(.+)"),
            "status": "Enabled" if _has(lines, "no shutdown") else "Disabled",
            "vlan": _first(lines, r"vlan\s+(.+)") or "",
            "switching": "Local (Flex)" if local_switching else "Central",
            "dhcp": "Local" if _has(lines, "no central dhcp") else "Central",
            "auth": "Local" if _has(lines, "no central authentication") else "Central",
            "aaa_override": _has(lines, "aaa-override"),
            "nac": _has(lines, "nac"),
            "accounting": _first(lines, r"accounting-list\s+(\S+)"),
            "session_timeout": _first(lines, r"session-timeout\s+(\d+)"),
            "idle_timeout": _first(lines, r"idle-timeout\s+(\d+)"),
            "acl": _first(lines, r"ipv4 acl\s+(\S+)"),
            "qos": ", ".join(re.sub(r"^service-policy\s+", "", l) for l in lines if l.startswith("service-policy")),
            "config": lines,
        })
    return out


def policy_tags(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wireless tag policy "):
        if not head:
            continue
        maps = []
        for line in lines:
            if line.startswith("wlan "):
                w = _words(line)
                if len(w) >= 4 and w[2] == "policy":
                    maps.append({"wlan": w[1], "policy": w[3]})
        out.append({"name": head[0], "description": _first(lines, r"description\s+(.+)"), "mappings": maps})
    return out


def site_tags(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wireless tag site "):
        if head:
            out.append({"name": head[0], "description": _first(lines, r"description\s+(.+)"),
                        "ap_profile": _first(lines, r"ap-profile\s+(.+)") or "default-ap-profile",
                        "flex_profile": _first(lines, r"flex-profile\s+(.+)") or "default-flex-profile",
                        "local_site": not _has(lines, "no local-site")})
    return out


def rf_tags(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wireless tag rf "):
        if head:
            out.append({"name": head[0], "description": _first(lines, r"description\s+(.+)"),
                        "rf_24": _first(lines, r"24ghz-rf-policy\s+(.+)") or "default",
                        "rf_5": _first(lines, r"5ghz-rf-policy\s+(.+)") or "default",
                        "rf_6": _first(lines, r"6ghz-rf-policy\s+(.+)") or "default"})
    return out


def ap_join_profiles(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "ap profile "):
        if head:
            out.append({"name": head[0], "description": _first(lines, r"description\s+(.+)"),
                        "country": _first(lines, r"country\s+(.+)"),
                        "mgmt_user": _first(lines, r"mgmtuser username\s+(\S+)"),
                        "ssh": _has(lines, "ssh"), "telnet": _has(lines, "telnet"),
                        "ntp": _first(lines, r"ntp ip\s+(\S+)"),
                        "syslog": _first(lines, r"syslog host\s+(\S+)"),
                        "primary": _first(lines, r"capwap backup primary\s+(.+)"),
                        "secondary": _first(lines, r"capwap backup secondary\s+(.+)"),
                        "config": lines})
    return out


def flex_profiles(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "wireless profile flex "):
        if not head:
            continue
        vlans, acls, name = [], [], None
        for line in lines:
            m = re.match(r"vlan-name\s+(.+)", line)
            if m:
                name = m.group(1).strip().strip('"')
                continue
            m = re.match(r"vlan-id\s+(\d+)", line)
            if m and name:
                vlans.append(f"{name} ({m.group(1)})")
                name = None
            m = re.match(r"acl-policy\s+(\S+)", line)
            if m:
                acls.append(m.group(1))
        out.append({"name": head[0], "description": _first(lines, r"description\s+(.+)"),
                    "native_vlan": _first(lines, r"native-vlan-id\s+(\d+)"),
                    "vlans": vlans, "acls": acls, "config": lines})
    return out


def rf_profiles(config: str) -> list[dict[str, Any]]:
    out = []
    for band, label in (("24ghz", "2.4 GHz"), ("5ghz", "5 GHz"), ("6ghz", "6 GHz")):
        for head, lines in blocks(config, f"ap dot11 {band} rf-profile "):
            if head:
                out.append({"name": head[0], "band": label, "description": _first(lines, r"description\s+(.+)"),
                            "tx_min": _first(lines, r"tx-power min\s+(-?\d+)"),
                            "tx_max": _first(lines, r"tx-power max\s+(-?\d+)"),
                            "rx_sop": _first(lines, r"high-density rx-sop threshold\s+(\S+)"),
                            "mandatory": ", ".join(re.findall(r"rate RATE_(\S+) mandatory", "\n".join(lines))),
                            "status": "Enabled" if _has(lines, "no shutdown") else "Disabled",
                            "config": lines})
    return out


def local_users(config: str) -> list[dict[str, Any]]:
    out = []
    for line in config.splitlines():
        m = re.match(r"^username\s+(\S+)(.*)$", line)
        if not m:
            continue
        rest = m.group(2)
        kind = re.search(r"\b(password|secret)\s+(\d+)", rest)
        out.append({"username": m.group(1), "privilege": _first([rest.strip()], r".*privilege\s+(\d+)") or "1",
                    "credential": f"{kind.group(1)} type {kind.group(2)}" if kind else "",
                    "plaintext": bool(kind and kind.group(2) == "0")})
    return out


def aaa_servers(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "radius server "):
        if head:
            out.append({"name": head[0], "type": "RADIUS", "address": _first(lines, r"address ipv4\s+(\S+)"),
                        "ports": " / ".join(filter(None, [_first(lines, r"address ipv4 \S+ auth-port\s+(\d+)"),
                                                          _first(lines, r".*acct-port\s+(\d+)")]))})
    for head, lines in blocks(config, "tacacs server "):
        if head:
            out.append({"name": head[0], "type": "TACACS+", "address": _first(lines, r"address ipv4\s+(\S+)"), "ports": ""})
    groups = []
    for kind in ("radius", "tacacs+"):
        for head, lines in blocks(config, f"aaa group server {kind} "):
            if head:
                groups.append({"name": head[0], "type": kind.upper(), "servers": [l.split()[-1] for l in lines if l.startswith("server name")]})
    methods = [line for line in config.splitlines() if re.match(r"^aaa (authentication|authorization|accounting) ", line)]
    return {"servers": out, "groups": groups, "methods": methods}


def interfaces(config: str) -> list[dict[str, Any]]:
    out = []
    for head, lines in blocks(config, "interface "):
        if not head:
            continue
        ip = re.search(r"ip address\s+(\S+)\s+(\S+)", "\n".join(lines))
        out.append({"name": " ".join(head), "description": _first(lines, r"description\s+(.+)"),
                    "ip": ip.group(1) if ip else "", "mask": ip.group(2) if ip else "",
                    "mode": "trunk" if _has(lines, "switchport mode trunk") else ("access" if _has(lines, "switchport mode access") else ""),
                    "allowed_vlans": _first(lines, r"switchport trunk allowed vlan\s+(.+)"),
                    "shutdown": _has(lines, "shutdown")})
    return out


def static_ap_tags(config: str) -> dict[str, dict[str, str]]:
    out = {}
    for head, lines in blocks(config, "ap "):
        if head and re.fullmatch(r"[0-9a-fA-F.:\-]{12,17}", head[0]):
            out[_mac(head[0])] = {"policy_tag": _first(lines, r"policy-tag\s+(.+)"),
                                  "site_tag": _first(lines, r"site-tag\s+(.+)"),
                                  "rf_tag": _first(lines, r"rf-tag\s+(.+)")}
    return out


# ----------------------------------------------------------------- runtime (show commands)
AP_SUMMARY = re.compile(
    r"^(?P<name>\S+)\s+(?P<slots>\d+)\s+(?P<model>\S+)\s+(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
    r"(?P<radio>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+(?P<cc>\S+)\s+(?P<rd>\S+)\s+(?P<ip>\S+)\s+"
    r"(?P<state>\S+)\s*(?P<location>.*)$", re.I)


def _ap_summary(body: str) -> list[dict[str, str]]:
    out = []
    for line in body.splitlines():
        m = AP_SUMMARY.match(line.strip())
        if m:
            out.append({k: v.strip() for k, v in m.groupdict().items()})
    return out


def _ap_config_general(body: str) -> dict[str, dict[str, str]]:
    out = {}
    for chunk in re.split(r"^Cisco AP Name\s*:\s*", body, flags=re.M)[1:]:
        name = chunk.splitlines()[0].strip()
        out[name] = key_values(chunk)
    return out


def _wlc(config: str, cmd: dict[str, str]) -> dict[str, Any]:
    def one(pattern, text):
        m = re.search(pattern, text, re.M | re.I)
        return m.group(1).strip() if m else ""

    version_txt = cmd.get("show version", "")
    inventory = cmd.get("show inventory", "")
    chassis = re.findall(r'NAME: "Chassis \d+".*\n\s*PID:\s*(\S+)\s*,.*SN:\s*(\S+)', inventory)
    redundancy = {" ".join(k.split()): v.strip() for k, _, v in
                  (line.partition("=") for line in cmd.get("show redundancy", "").splitlines() if "=" in line)}
    mobility = key_values(cmd.get("show wireless mobility summary", ""))
    summary = cmd.get("show wireless summary", "")
    radios = []
    for band in ("2.4GHz", "5GHz", "6GHz"):
        m = re.search(rf"802\.11 {re.escape(band)}\s+(\d+)\s+(\d+)\s+(\d+)", summary)
        if m:
            radios.append({"band": band, "total": int(m.group(1)), "up": int(m.group(2)), "down": int(m.group(3))})
    licenses = [dict(zip(("license", "entitlement", "count", "status"), m))
                for m in re.findall(r"^\s*(\S+)\s+\(([^)]+)\)\s+(\d+)\s+(.+?)\s*$", cmd.get("show license summary", ""), re.M)]
    mgmt_if = one(r"^wireless management interface\s+(\S+)", config)
    mgmt_ip = mobility.get("Wireless Management IP Address", "")
    if not mgmt_ip and mgmt_if:
        m = re.search(rf"^interface {re.escape(mgmt_if)}\n(?: .*\n)*? ip address\s+(\S+)", config, re.M)
        mgmt_ip = m.group(1) if m else ""
    return {
        "hostname": one(r"^hostname\s+(\S+)", config),
        "model": (chassis[0][0] if chassis else "") or one(r"^license udi pid\s+(\S+)", config),
        "serials": [sn for _, sn in chassis] or [s for s in [one(r"^license udi pid\s+\S+\s+sn\s+(\S+)", config)] if s],
        "software_version": one(r"Cisco IOS XE Software, Version\s+([^\s,]+)", version_txt) or one(r"^version\s+(\S+)", config),
        "uptime": one(r"uptime is\s+(.+)", version_txt),
        "management_interface": mgmt_if,
        "management_ip": mgmt_ip,
        "mobility_group": mobility.get("Mobility Group Name", ""),
        "country": one(r"^wireless country\s+(\S+)", config),
        "ha_mode": redundancy.get("Operating Redundancy Mode", ""),
        "ha_hardware": redundancy.get("Hardware Mode", ""),
        "switchovers": redundancy.get("Switchovers system experienced", ""),
        "max_aps": one(r"Max APs supported\s*:\s*(\d+)", summary),
        "max_clients": one(r"Max clients supported\s*:\s*(\d+)", summary),
        "radios": radios,
        "licenses": licenses,
    }


def _status(value: str) -> str:
    v = (value or "").strip().lower()
    return {"registered": "Registered", "joined": "Joined", "not joined": "Not Joined"}.get(v, (value or "").strip() or "Unknown")


def parse(text: str) -> dict[str, Any]:
    cmd = split_commands(text)
    config = running_config(text, cmd)
    model = {
        "vendor": "Cisco", "platform": "Catalyst 9800",
        "source_kind": "show tech-support wireless" if "show ap summary" in cmd else ("capture" if cmd else "running-config"),
        "wlc": _wlc(config, cmd),
        "wlans": wlans(config), "policy_profiles": policy_profiles(config),
        "policy_tags": policy_tags(config), "site_tags": site_tags(config), "rf_tags": rf_tags(config),
        "ap_join_profiles": ap_join_profiles(config), "flex_profiles": flex_profiles(config),
        "rf_profiles": rf_profiles(config), "local_users": local_users(config),
        "aaa": aaa_servers(config), "interfaces": interfaces(config),
    }
    # WLAN runtime status/security text from `show wlan summary` when present
    summary = {r["ID"]: r for r in fixed_table(cmd.get("show wlan summary", ""), ["ID", "Profile Name", "SSID", "Status", "Security"]) if r["ID"].isdigit()}
    for w in model["wlans"]:
        row = summary.get(str(w["id"]))
        if row:
            w["status"] = row["Status"] or w["status"]
            w["security_summary"] = row["Security"]

    statics = static_ap_tags(config)
    tags = {_mac(r["AP Mac"]): r for r in fixed_table(cmd.get("show ap tag summary", ""),
            ["AP Name", "AP Mac", "Site Tag Name", "Policy Tag Name", "RF Tag Name", "Misconfigured", "Tag Source"])}
    joins = {_mac(r["Ethernet MAC"]): r for r in fixed_table(cmd.get("show wireless stats ap join summary", ""),
             ["Base MAC", "Ethernet MAC", "AP Name", "IP Address", "Status", "Last Failure Phase", "Last Disconnect Reason"])}
    general = _ap_config_general(cmd.get("show ap config general", ""))

    aps: dict[str, dict[str, Any]] = {}
    for r in _ap_summary(cmd.get("show ap summary", "")):
        aps[_mac(r["mac"])] = {"name": r["name"], "model": r["model"], "mac": _mac(r["mac"]), "radio_mac": _mac(r["radio"]),
                               "ip": r["ip"], "state": _status(r["state"]), "location": r["location"], "country": r["cc"]}
    for mac, j in joins.items():                                   # joined before, not up now
        aps.setdefault(mac, {"name": j["AP Name"], "mac": mac, "ip": j["IP Address"], "state": "Not Registered", "model": ""})
    for mac, t in statics.items():                                 # configured by MAC only
        aps.setdefault(mac, {"name": "", "mac": mac, "ip": "", "state": "Not joined", "model": ""})
    for mac, ap in aps.items():
        t, s, j, g = tags.get(mac, {}), statics.get(mac, {}), joins.get(mac, {}), general.get(ap.get("name", ""), {})
        ap.update({
            "site_tag": t.get("Site Tag Name") or s.get("site_tag") or g.get("Site Tag Name") or "",
            "policy_tag": t.get("Policy Tag Name") or s.get("policy_tag") or g.get("Policy Tag Name") or "",
            "rf_tag": t.get("RF Tag Name") or s.get("rf_tag") or g.get("RF Tag Name") or "",
            "misconfigured": t.get("Misconfigured", ""),
            "tag_source": t.get("Tag Source", "Static" if s else ""),
            "join_status": j.get("Status", ""),
            "last_failure": j.get("Last Failure Phase", ""),
            "disconnect_reason": j.get("Last Disconnect Reason", ""),
            "serial": g.get("AP Serial Number", ""),
            "version": g.get("Software Version", ""),
            "mode": g.get("AP Mode", ""),
            "join_profile": g.get("AP join Profile", ""),
            "flex_profile": g.get("Flex Profile", ""),
            "primary_wlc": g.get("Primary Cisco Controller Name", ""),
            "secondary_wlc": g.get("Secondary Cisco Controller Name", ""),
            "uptime": g.get("AP Up Time", ""),
            "power": g.get("Power Type/Mode", ""),
        })
        ap.setdefault("model", g.get("AP Model", ""))
        if not ap["model"]:
            ap["model"] = g.get("AP Model", "")
    model["aps"] = sorted(aps.values(), key=lambda a: (a.get("name") or "~", a["mac"]))
    return model
