"""PAN-OS network and policy-adjacent settings that the vendor-neutral model has no field for.

Read from the raw XML (the CLI curly capture is converted to the same XML first):

* IKE gateways, IKE crypto profiles, IPsec crypto profiles and the IPsec tunnel settings behind the tunnel table;
* QoS profiles and interface bindings, tunnel/path monitor profiles;
* the administrator password policy (``mgt-config/password-complexity``);
* the botnet report configuration (``shared/botnet``);
* the content-update schedule in readable form and the generic ``deviceconfig/setting`` flags.

Privacy: ``pre-shared-key``, ``phash``, ``secret`` and similar elements are never read.  A gateway row only says whether a key exists.

References: https://docs.paloaltonetworks.com/network-security/ipsec-vpn/administration/set-up-site-to-site-vpn/set-up-an-ike-gateway ,
https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-web-interface-help/device/device-password-profiles/username-and-password-requirements
"""

from __future__ import annotations

import re
from typing import Any
from xml.etree import ElementTree as ET

from ..analyzer_core.findings import finding
from ..analyzer_core.result import kv_section, table_section
from .refs import PALO

WEAK_ENCRYPTION = {"des", "3des"}
WEAK_HASH = {"md5"}
WEAK_DH = {"group1", "group2", "group5"}
MIN_PASSWORD_LENGTH = 12
SECRET_TAG = re.compile(r"(?i)(pass|secret|key|phash|community|token|pwd)")


# ----------------------------------------------------------------------- helpers
def _t(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def _list(node: ET.Element | None, path: str) -> list[str]:
    """Members of a list element; PAN-OS writes a single value as ``<member>`` in XML but the CLI converter can yield bare text."""
    if node is None:
        return []
    found = node.find(path)
    if found is None:
        return []
    members = [(m.text or "").strip() for m in found.findall("member") if (m.text or "").strip()]
    if members:
        return members
    return [found.text.strip()] if found.text and found.text.strip() else []


def _entries(node: ET.Element | None, path: str) -> list[ET.Element]:
    if node is None:
        return []
    found = node.find(path)
    return found.findall("entry") if found is not None else []


def _flag(node: ET.Element | None, path: str) -> bool | None:
    value = _t(node, path).lower()
    if value in ("yes", "true", "enable", "enabled"):
        return True
    if value in ("no", "false", "disable", "disabled"):
        return False
    return None


def _lifetime(node: ET.Element | None) -> str:
    life = node.find("lifetime") if node is not None else None
    if life is None:
        return ""
    for unit, short in (("days", "d"), ("hours", "h"), ("minutes", "min"), ("seconds", "s")):
        value = _t(life, unit)
        if value:
            return f"{value} {short}"
    return ""


def _yn(value: bool | None, default: str = "default") -> str:
    return {True: "yes", False: "no", None: default}[value]


def _weak(enc: list[str], hashes: list[str], dh: list[str]) -> list[str]:
    bits = [f"{x}" for x in enc if x.lower() in WEAK_ENCRYPTION or x.lower() == "null"]
    bits += [x for x in hashes if x.lower() in WEAK_HASH]
    bits += [x for x in dh if x.lower() in WEAK_DH]
    return bits


# ----------------------------------------------------------------------- extract
def extract(root: ET.Element, device: ET.Element | None) -> dict[str, Any]:
    net = device.find("network") if device is not None else None
    out: dict[str, Any] = {"ike_profiles": [], "ipsec_profiles": [], "gateways": [], "tunnels": [], "qos_profiles": [], "qos_interfaces": [], "monitor_profiles": []}
    if net is not None:
        out.update(_vpn(net))
        out["qos_profiles"] = _qos_profiles(net)
        out["qos_interfaces"] = _qos_interfaces(net)
        out["monitor_profiles"] = [{"name": e.get("name", ""), "interval": _t(e, "interval"), "threshold": _t(e, "threshold"), "action": _t(e, "action")} for e in _entries(net, "profiles/monitor-profile")]
    out["password_policy"] = _password_policy(root)
    out["botnet"] = _botnet(root.find("shared"))
    out["device_settings"] = _device_settings(device)
    out["updates"] = _updates(device)
    out["url_categories"] = _url_categories(root)
    out["log_profiles"] = _log_profiles(root)
    return out


def _holders(root: ET.Element) -> list[tuple[str, ET.Element]]:
    """Where objects live: ``shared`` and every vsys (or the device itself on a non-vsys export)."""
    found: list[tuple[str, ET.Element]] = []
    if root.find("shared") is not None:
        found.append(("shared", root.find("shared")))
    for dev in root.findall("devices/entry"):
        vsys = dev.findall("vsys/entry")
        found += [(v.get("name", "vsys1"), v) for v in vsys] if vsys else [("device", dev)]
    return found


def _url_categories(root: ET.Element) -> list[dict[str, Any]]:
    out = []
    for scope, holder in _holders(root):
        for e in _entries(holder, "profiles/custom-url-category"):
            members = _list(e, "list")
            out.append({"scope": scope, "name": e.get("name", ""), "type": _t(e, "type") or "URL List", "count": len(members), "entries": members[:12], "more": max(0, len(members) - 12), "description": _t(e, "description")})
    return out


def _log_profiles(root: ET.Element) -> list[dict[str, Any]]:
    out = []
    for scope, holder in _holders(root):
        for prof in _entries(holder, "log-settings/profiles"):
            for m in _entries(prof, "match-list"):
                out.append({"scope": scope, "profile": prof.get("name", ""), "name": m.get("name", ""), "log_type": _t(m, "log-type"), "filter": _t(m, "filter") or "All Logs",
                            "panorama": _flag(m, "send-to-panorama") is True, "syslog": _list(m, "send-syslog"), "email": _list(m, "send-email"), "http": _list(m, "send-http"), "action": [a.get("name", "") for a in _entries(m, "actions")]})
    return out


def _vpn(net: ET.Element) -> dict[str, Any]:
    ike_profiles = [{"kind": "IKE", "name": e.get("name", ""), "encryption": _list(e, "encryption"), "hash": _list(e, "hash"), "dh": _list(e, "dh-group"), "lifetime": _lifetime(e), "protocol": "IKE phase 1"}
                    for e in _entries(net, "ike/crypto-profiles/ike-crypto-profiles")]
    ipsec_profiles = []
    for e in _entries(net, "ike/crypto-profiles/ipsec-crypto-profiles"):
        proto = "esp" if e.find("esp") is not None else ("ah" if e.find("ah") is not None else "")
        ipsec_profiles.append({"kind": "IPsec", "name": e.get("name", ""), "encryption": _list(e, "esp/encryption"), "hash": _list(e, "esp/authentication") or _list(e, "ah/authentication"),
                               "dh": _list(e, "dh-group"), "lifetime": _lifetime(e), "protocol": f"IPsec {proto.upper()}".strip()})
    gateways = []
    for e in _entries(net, "ike/gateway"):
        version = _t(e, "protocol/version") or "ikev1"
        v2, v1 = e.find("protocol/ikev2"), e.find("protocol/ikev1")
        node = v2 if v2 is not None and version != "ikev1" else v1
        peer = _t(e, "peer-address/ip") or _t(e, "peer-address/fqdn") or ("dynamic" if e.find("peer-address/dynamic") is not None else "")
        dpd_on = _flag(node, "dpd/enable")
        gateways.append({
            "name": e.get("name", ""), "version": version, "ike_profile": _t(node, "ike-crypto-profile"), "exchange_mode": _t(v1, "exchange-mode") if v1 is not None else "",
            "local_interface": _t(e, "local-address/interface"), "local_ip": _t(e, "local-address/ip") or _t(e, "local-address/floating-ip"), "peer": peer,
            "auth": "pre-shared key" if e.find("authentication/pre-shared-key") is not None else ("certificate" if e.find("authentication/certificate") is not None else "—"),
            "nat_t": _flag(e, "protocol-common/nat-traversal/enable"), "dpd": dpd_on, "dpd_interval": _t(node, "dpd/interval"), "dpd_retry": _t(node, "dpd/retry"),
            "passive": _flag(e, "passive-mode"), "fragmentation": _flag(e, "protocol-common/fragmentation/enable"), "liveness": _flag(v2, "liveness-check/enable") if v2 is not None else None,
            "local_id": _t(e, "local-id/id"), "peer_id": _t(e, "peer-id/id"), "tunnels": [],
        })
    tunnels = []
    by_gw = {g["name"]: g for g in gateways}
    for e in _entries(net, "tunnel/ipsec"):
        auto = e.find("auto-key")
        gw_names = [x.get("name", "") for x in auto.findall("ike-gateway/entry")] if auto is not None else []
        kind = "auto-key" if auto is not None else ("manual-key" if e.find("manual-key") is not None else ("global-protect-satellite" if e.find("global-protect-satellite") is not None else ""))
        monitor = e.find("tunnel-monitor")
        row = {
            "name": e.get("name", ""), "type": kind, "tunnel_interface": _t(e, "tunnel-interface"), "gateways": gw_names, "ipsec_profile": _t(auto, "ipsec-crypto-profile") if auto is not None else "",
            "disabled": _flag(e, "disabled") is True, "anti_replay": _flag(e, "anti-replay"), "copy_tos": _flag(e, "copy-tos"), "proxy_ids": len(auto.findall("proxy-id/entry")) if auto is not None else 0,
            "monitor": (f"{_t(monitor, 'destination-ip') or '—'} ({_t(monitor, 'tunnel-monitor-profile') or _t(monitor, 'profile') or 'default'})" if monitor is not None and _flag(monitor, "enable") is not False else "off"),
        }
        tunnels.append(row)
        for gw in gw_names:
            if gw in by_gw:
                by_gw[gw]["tunnels"].append(row["name"])
    return {"ike_profiles": ike_profiles, "ipsec_profiles": ipsec_profiles, "gateways": gateways, "tunnels": tunnels}


def _qos_profiles(net: ET.Element) -> list[dict[str, Any]]:
    out = []
    for e in _entries(net, "qos/profile"):
        classes = []
        for unit in ("mbps", "percentage"):
            for c in _entries(e, f"class-bandwidth-type/{unit}/class"):
                limit = f"{_t(c, 'class-bandwidth/egress-guaranteed')}/{_t(c, 'class-bandwidth/egress-max')} {'Mbps' if unit == 'mbps' else '%'}" if c.find("class-bandwidth") is not None else ""
                classes.append(f"{c.get('name', '')}: {_t(c, 'priority') or '—'}" + (f" ({limit})" if limit.strip("/ ") else ""))
        out.append({"name": e.get("name", ""), "classes": classes, "egress_max": _t(e, "aggregate-bandwidth/egress-max"), "egress_guaranteed": _t(e, "aggregate-bandwidth/egress-guaranteed")})
    return out


def _qos_interfaces(net: ET.Element) -> list[dict[str, Any]]:
    out = []
    for e in _entries(net, "qos/interface"):
        out.append({"interface": e.get("name", ""), "enabled": _flag(e, "enabled"), "max": _t(e, "interface-bandwidth/egress-max"), "guaranteed": _t(e, "interface-bandwidth/egress-guaranteed"),
                    "default_profile": _t(e, "regular-traffic/default-group/qos-profile")})
    return out


def _password_policy(root: ET.Element) -> dict[str, Any]:
    node = root.find("mgt-config/password-complexity")
    if node is None:
        return {}
    keys = ("minimum-length", "minimum-uppercase-letters", "minimum-lowercase-letters", "minimum-numeric-letters", "minimum-special-characters", "block-username-inclusion", "password-history-count", "new-password-differs-by-characters", "password-change/expire-after-days", "password-change/expiration-warning-period", "password-change/post-expiration-admin-login-count", "password-change/post-expiration-grace-period")
    values = {k: _t(node, k) for k in keys}
    return {"enabled": _flag(node, "enabled"), "values": {k: v for k, v in values.items() if v}}


def _botnet(shared: ET.Element | None) -> dict[str, Any]:
    cfg = shared.find("botnet/configuration") if shared is not None else None
    if cfg is None:
        return {}
    http = []
    for e in cfg.find("http") if cfg.find("http") is not None else []:
        http.append({"indicator": e.tag.replace("-", " "), "enabled": _flag(e, "enabled"), "threshold": _t(e, "threshold")})
    unknown = []
    for proto in ("unknown-tcp", "unknown-udp"):
        n = cfg.find(f"unknown-applications/{proto}")
        if n is not None:
            unknown.append({"protocol": proto.split("-")[1].upper(), "destinations": _t(n, "destinations-per-hour"), "sessions": _t(n, "sessions-per-hour"),
                            "min_bytes": _t(n, "session-length/minimum-bytes"), "max_bytes": _t(n, "session-length/maximum-bytes")})
    report = shared.find("botnet/report")
    return {"http": http, "irc": _flag(cfg, "other-applications/irc"), "unknown": unknown, "topn": _t(report, "topn"), "scheduled": _flag(report, "scheduled")}


def _device_settings(device: ET.Element | None) -> list[tuple[str, str]]:
    node = device.find("deviceconfig/setting") if device is not None else None
    out: list[tuple[str, str]] = []

    def walk(el: ET.Element, trail: list[str]) -> None:
        for child in el:
            if SECRET_TAG.search(child.tag):
                continue
            if len(child):
                walk(child, trail + [child.tag])
            elif (child.text or "").strip():
                out.append(("/".join(trail + [child.tag]), child.text.strip()))
    if node is not None:
        walk(node, [])
    return out


def _updates(device: ET.Element | None) -> list[dict[str, str]]:
    node = device.find("deviceconfig/system/update-schedule") if device is not None else None
    rows: list[dict[str, str]] = []
    if node is None:
        return rows
    for kind in node:
        rec = kind.find("recurring")
        if rec is None:
            rows.append({"content": kind.tag, "frequency": "—", "at": "", "action": ""})
            continue
        for freq in rec:
            at = _t(freq, "at") or (f"minute {_t(freq, 'at')}" if freq.tag.startswith("hourly") else "")
            day = _t(freq, "day-of-week")
            rows.append({"content": kind.tag, "frequency": freq.tag + (f" ({day})" if day else ""), "at": at, "action": _t(freq, "action"), "threshold": _t(freq, "threshold"), "sync": _t(freq, "sync-to-peer")})
    return rows


# ----------------------------------------------------------------------- findings
def evaluate(extra: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    tunnels, gateways = extra.get("tunnels", []), extra.get("gateways", [])
    gw_by = {g["name"]: g for g in gateways}
    live_ike, live_ipsec = set(), set()
    used_ike, used_ipsec = set(), set()
    for t in tunnels:
        used_ipsec.add(t["ipsec_profile"])
        for g in t["gateways"]:
            used_ike.add(gw_by.get(g, {}).get("ike_profile", ""))
            if not t["disabled"]:
                live_ike.add(gw_by.get(g, {}).get("ike_profile", ""))
        if not t["disabled"]:
            live_ipsec.add(t["ipsec_profile"])

    # profiles: the per-tunnel check (FW-VPN-001) reads the first algorithm of each list; this one reads every proposal and also unused profiles
    unused_weak = []
    for prof in extra.get("ike_profiles", []) + extra.get("ipsec_profiles", []):
        bits = _weak(prof["encryption"], prof["hash"], prof["dh"])
        if prof["kind"] == "IPsec" and prof["encryption"] and not any(("gcm" in e.lower()) for e in prof["encryption"]) and any(h.lower() == "none" for h in prof["hash"]):
            bits.append("no ESP authentication with a non-GCM cipher")
        if not bits:
            continue
        used = prof["name"] in (live_ike if prof["kind"] == "IKE" else live_ipsec)
        parked = prof["name"] in (used_ike if prof["kind"] == "IKE" else used_ipsec)
        first = [prof["encryption"][:1], prof["hash"][:1], prof["dh"][:1]]
        beyond_first = [b for b in bits if not any(b in f for f in first)]
        if used and beyond_first:
            out.append(finding("PAN-VPN-001", "medium", "VPN", f"{prof['kind']} crypto profile '{prof['name']}' also offers weak proposals: {', '.join(beyond_first)}",
                               obj=f"{prof['kind'].lower()}-crypto-profile {prof['name']}", detail="A peer can negotiate the weakest algorithm in the list, so a single legacy entry lowers the strength of the whole tunnel.",
                               recommendation="Remove DES/3DES, MD5 and DH group 1/2/5 from the profile and keep AES-256 (or AES-GCM), SHA-256 or better and DH group 14 or higher.",
                               reference=PALO["ike_crypto_profile"] if prof["kind"] == "IKE" else PALO["ipsec_crypto"]))
        elif not used:
            unused_weak.append(f"{prof['name']} ({prof['kind']}: {', '.join(bits)})" + ("" if not parked else " - only on disabled tunnels"))
    if unused_weak:
        out.append(finding("PAN-VPN-002", "info", "VPN", f"{len(unused_weak)} crypto profile(s) with weak algorithms are not used by an enabled tunnel", obj="; ".join(unused_weak),
                           detail="Nothing negotiates them today. PAN-OS ships a 'default' IKE and IPsec profile that includes 3DES and DH group 2, so these often are the factory profiles. They become a risk if someone selects them later.",
                           recommendation="Delete the profiles you do not use, or leave the factory 'default' profiles unreferenced and build tunnels on a custom AES/SHA-256/DH14+ profile.", reference=PALO["ike_crypto_profile"]))

    for g in gateways:
        live = any(not t["disabled"] for t in tunnels if g["name"] in t["gateways"]) if g["tunnels"] else False
        if g["version"] == "ikev1" and g["auth"] == "pre-shared key" and g["exchange_mode"] in ("aggressive", "auto") and live:
            out.append(finding("PAN-VPN-003", "medium", "VPN", f"IKE gateway '{g['name']}' allows IKEv1 aggressive mode with a pre-shared key", obj=f"ike gateway {g['name']}",
                               detail="Aggressive mode exposes a hash of the pre-shared key that can be attacked offline.", recommendation="Use main mode, or move to IKEv2 with a strong key or certificates.", reference=PALO["ike_gateway"]))
        if live and g["dpd"] is not True and g["liveness"] is not True:
            out.append(finding("PAN-VPN-004", "low", "VPN", f"IKE gateway '{g['name']}' has no dead-peer detection", obj=f"ike gateway {g['name']}",
                               detail="Without DPD (or the IKEv2 liveness check) the firewall keeps a dead SA until it expires, so traffic is black-holed after a peer failure.", recommendation="Enable dead peer detection with the default interval and retry.", reference=PALO["ike_gateway"]))
        if live and g["version"] == "ikev1":
            out.append(finding("PAN-VPN-005", "info", "VPN", f"IKE gateway '{g['name']}' uses IKEv1", obj=f"ike gateway {g['name']}",
                               detail="IKEv2 gives stronger negotiation, built-in NAT-T and faster rekeying.", recommendation="Move the gateway to IKEv2 when the peer supports it.", reference=PALO["ikev2"]))
    for t in tunnels:
        if not t["disabled"] and t["anti_replay"] is False:
            out.append(finding("PAN-VPN-006", "low", "VPN", f"IPsec tunnel '{t['name']}' has anti-replay disabled", obj=f"tunnel ipsec {t['name']}", detail="Anti-replay stops an attacker re-sending captured ESP packets.",
                               recommendation="Leave anti-replay enabled unless the peer is known to reorder packets.", reference=PALO["ipsec_tunnel"]))
    parked = [t["name"] for t in tunnels if t["disabled"]]
    if parked:
        out.append(finding("PAN-VPN-007", "info", "VPN", f"{len(parked)} IPsec tunnel(s) are disabled", obj=", ".join(parked),
                           detail="Disabled tunnels carry no traffic but keep their gateways, keys and crypto profiles in the configuration.", recommendation="Delete tunnels that are retired so their peers, pre-shared keys and weak profiles do not linger.", reference=PALO["ipsec_tunnel"]))

    policy = extra.get("password_policy")
    if policy is not None:
        if not policy:
            out.append(finding("PAN-PWD-001", "medium", "Management", "No administrator password complexity policy is configured", obj="mgt-config/password-complexity",
                               detail="Local administrator passwords are accepted with any length and character mix.", recommendation="Enable password complexity under Device > Setup > Management > Minimum Password Complexity.", reference=PALO["password_requirements"]))
        elif policy["enabled"] is not True:
            out.append(finding("PAN-PWD-001", "medium", "Management", "Administrator password complexity is turned off", obj="mgt-config/password-complexity/enabled",
                               detail="The configured minimums are not enforced while the policy is disabled.", recommendation="Set enabled to yes.", reference=PALO["password_requirements"]))
        else:
            length = policy["values"].get("minimum-length", "")
            if length.isdigit() and int(length) < MIN_PASSWORD_LENGTH:
                out.append(finding("PAN-PWD-002", "low", "Management", f"Administrator minimum password length is {length}", obj="mgt-config/password-complexity/minimum-length",
                                   detail=f"Short passwords fall quickly to guessing. Common hardening baselines ask for {MIN_PASSWORD_LENGTH} or more characters for administrator accounts.",
                                   recommendation=f"Raise the minimum length to {MIN_PASSWORD_LENGTH} or more and require upper case, lower case, digits and a special character.", reference=PALO["password_requirements"]))
            missing = [label for key, label in (("minimum-uppercase-letters", "upper case"), ("minimum-lowercase-letters", "lower case"), ("minimum-numeric-letters", "digit"), ("minimum-special-characters", "special character")) if not policy["values"].get(key, "").strip("0")]
            if len(missing) >= 3:
                out.append(finding("PAN-PWD-003", "low", "Management", "Password policy sets only a length, no character-class minimums", obj="mgt-config/password-complexity",
                                   detail=f"No minimum for: {', '.join(missing)}.", recommendation="Add at least one character of each class, or use long passphrases with a password manager.", reference=PALO["password_requirements"]))

    for upd in extra.get("updates", []):
        if upd["action"] == "download-only":
            out.append(finding("PAN-UPD-002", "low", "Operations", f"{upd['content']} content is downloaded but not installed automatically", obj=f"update-schedule/{upd['content']}",
                               detail="download-only leaves new signatures waiting until an administrator installs them.", recommendation="Use download-and-install for threat, antivirus and WildFire content.", reference=PALO["content_updates"]))
    return out


# ----------------------------------------------------------------------- sections
def _tone_algo(values: list[str], weak: set[str]) -> str:
    return "bad" if any(v.lower() in weak for v in values) else ""


def sections(extra: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    gateways = extra.get("gateways", [])
    if gateways:
        rows = []
        for g in gateways:
            rows.append(dict(g, nat_t=_yn(g["nat_t"]), dpd=_yn(g["dpd"], "default (off)"), local=f"{g['local_interface']} {g['local_ip']}".strip(), tunnels=g["tunnels"] or ["unused"],
                             _tones={"dpd": "" if g["dpd"] else "warn", "version": "warn" if g["version"] == "ikev1" else "", "tunnels": "mute" if not g["tunnels"] else ""}))
        out.append(table_section("ike_gateways", "IKE gateways", [("name", "Gateway", "mono"), ("version", "Version"), ("peer", "Peer", "mono"), ("local", "Local interface / IP", "mono"), ("auth", "Authentication"), ("ike_profile", "IKE crypto profile"),
                                                                 ("nat_t", "NAT-T"), ("dpd", "DPD"), ("tunnels", "Tunnels", "list")], rows, group="VPN", empty="No IKE gateways.",
                                 hint="Pre-shared keys are never shown; the column only says that one is configured."))
    profiles = extra.get("ike_profiles", []) + extra.get("ipsec_profiles", [])
    if profiles:
        used_ike = {g["ike_profile"] for g in gateways}
        used_ipsec = {t["ipsec_profile"] for t in extra.get("tunnels", [])}
        rows = []
        for p in profiles:
            used = p["name"] in (used_ike if p["kind"] == "IKE" else used_ipsec)
            rows.append(dict(p, used="yes" if used else "no", _tone="" if used else "mute", _tones={"encryption": _tone_algo(p["encryption"], WEAK_ENCRYPTION), "hash": _tone_algo(p["hash"], WEAK_HASH), "dh": _tone_algo(p["dh"], WEAK_DH)}))
        out.append(table_section("vpn_crypto_profiles", "VPN crypto profiles", [("kind", "Type"), ("name", "Profile", "mono"), ("encryption", "Encryption", "list"), ("hash", "Hash / authentication", "list"), ("dh", "DH group", "list"), ("lifetime", "Lifetime"), ("used", "In use")],
                                 rows, group="VPN", hint="A dimmed row is not referenced by any gateway or tunnel. Red marks DES/3DES, MD5 and DH group 1/2/5."))
    if extra.get("tunnels"):
        rows = [dict(t, state="disabled" if t["disabled"] else "enabled", anti_replay=_yn(t["anti_replay"]), gateways=t["gateways"], _tone="mute" if t["disabled"] else "") for t in extra["tunnels"]]
        out.append(table_section("vpn_tunnel_settings", "IPsec tunnel settings", [("name", "Tunnel", "mono"), ("state", "State"), ("type", "Type"), ("tunnel_interface", "Tunnel interface", "mono"), ("gateways", "IKE gateway", "list"), ("ipsec_profile", "IPsec crypto profile"),
                                                                              ("anti_replay", "Anti-replay"), ("proxy_ids", "Proxy IDs", "num"), ("monitor", "Tunnel monitor")], rows, group="VPN"))
    if extra.get("qos_profiles"):
        out.append(table_section("qos_profiles", "QoS profiles", [("name", "Profile", "mono"), ("classes", "Classes (priority)", "list"), ("egress_max", "Egress max"), ("egress_guaranteed", "Egress guaranteed")], extra["qos_profiles"], group="Network",
                                 hint="Profiles that no interface or rule uses have no effect."))
    if extra.get("qos_interfaces"):
        out.append(table_section("qos_interfaces", "QoS interface bindings", [("interface", "Interface", "mono"), ("enabled", "Enabled"), ("max", "Egress max"), ("guaranteed", "Egress guaranteed"), ("default_profile", "Default profile")],
                                 [dict(i, enabled=_yn(i["enabled"])) for i in extra["qos_interfaces"]], group="Network"))
    if extra.get("monitor_profiles"):
        out.append(table_section("monitor_profiles", "Monitor profiles", [("name", "Profile", "mono"), ("interval", "Interval (s)"), ("threshold", "Threshold"), ("action", "Action")], extra["monitor_profiles"], group="Network",
                                 hint="Tunnel and policy-based-forwarding monitors use these to decide when a path is down."))
    policy = extra.get("password_policy")
    if policy is not None:
        values = policy.get("values", {}) if policy else {}
        pairs = [("Policy enabled", _yn(policy.get("enabled") if policy else None, "not configured"), "" if policy and policy.get("enabled") else "warn")]
        for key, label in (("minimum-length", "Minimum length"), ("minimum-uppercase-letters", "Minimum upper case"), ("minimum-lowercase-letters", "Minimum lower case"), ("minimum-numeric-letters", "Minimum digits"), ("minimum-special-characters", "Minimum special characters"),
                           ("block-username-inclusion", "Block username in password"), ("password-history-count", "Password history"), ("new-password-differs-by-characters", "New password differs by (characters)"),
                           ("password-change/expire-after-days", "Expires after (days)"), ("password-change/expiration-warning-period", "Expiry warning (days)")):
            if key in values:
                tone = "warn" if key == "minimum-length" and values[key].isdigit() and int(values[key]) < MIN_PASSWORD_LENGTH else ""
                pairs.append((label, values[key], tone))
        out.append(kv_section("password_policy", "Administrator password policy", pairs, group="System", hint="From mgt-config/password-complexity. It applies to local administrator accounts only."))
    if extra.get("updates"):
        out.append(table_section("update_schedule", "Content update schedule", [("content", "Content"), ("frequency", "Frequency"), ("at", "Time"), ("action", "Action"), ("threshold", "Threshold (h)")],
                                 [dict(u, _tones={"action": "warn" if u["action"] == "download-only" else ""}) for u in extra["updates"]], group="System"))
    if extra.get("url_categories"):
        out.append(table_section("url_categories", "Custom URL categories", [("scope", "Scope"), ("name", "Category", "mono"), ("type", "Type"), ("count", "Entries", "num"), ("entries", "Sample entries", "list"), ("description", "Description", "wrap")],
                                 [dict(c, entries=c["entries"] + ([f"... +{c['more']} more"] if c["more"] else [])) for c in extra["url_categories"]], group="Objects", hint="Used in URL-filtering profiles and as a match criterion in security rules."))
    if extra.get("log_profiles"):
        rows = [dict(m, panorama="yes" if m["panorama"] else "no", forward=m["syslog"] + m["email"] + m["http"]) for m in extra["log_profiles"]]
        out.append(table_section("log_profiles", "Log forwarding profiles", [("profile", "Profile", "mono"), ("name", "Match list", "mono"), ("log_type", "Log type"), ("filter", "Filter", "wrap"), ("panorama", "To Panorama"), ("forward", "Syslog / email / HTTP", "list")],
                                 rows, group="Logging", hint="A rule only forwards logs when it names one of these profiles."))
    botnet = extra.get("botnet")
    if botnet:
        rows = [{"indicator": h["indicator"], "setting": _yn(h["enabled"]), "threshold": h["threshold"]} for h in botnet["http"]]
        rows.append({"indicator": "IRC traffic", "setting": _yn(botnet["irc"]), "threshold": ""})
        for u in botnet["unknown"]:
            rows.append({"indicator": f"Unknown {u['protocol']}", "setting": f"{u['sessions']} sessions / {u['destinations']} destinations per hour", "threshold": f"{u['min_bytes']}-{u['max_bytes']} bytes per session"})
        out.append(table_section("botnet", "Botnet report settings", [("indicator", "Indicator"), ("setting", "Enabled / limit"), ("threshold", "Threshold")], rows, group="Security",
                                 hint=f"Daily report: top {botnet['topn'] or '—'}, scheduled {_yn(botnet['scheduled'])}. Botnet reports are log analytics, not prevention."))
    if extra.get("device_settings"):
        out.append(kv_section("device_settings", "Device settings", [(k.replace("-", " "), v) for k, v in extra["device_settings"]], group="System", hint="Flags under deviceconfig/setting (for example policy rematch, advanced routing engine, session and management options)."))
    return out
