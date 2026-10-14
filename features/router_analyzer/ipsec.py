"""IPsec site-to-site VPNs on a Cisco router: the configured tunnels, what each
one negotiates, what is wrong with it, and (when the commands were captured)
what the device reports for it.

The module has two halves.

* ``extract_*`` read the crypto configuration out of the parsed running-config.
  They keep **no secret**: a pre-shared key is reduced to its storage type and a
  short keyed-hash token that is only good for answering "is the same key used
  on two peers?" inside one analysis (the key for the hash is random per run).
* :func:`build` turns the configuration into one record per tunnel (a
  crypto-map entry or a VTI/``tunnel protection`` interface) and the list of
  defects the rules module reports.

Grammar followed (Cisco IOS XE Security Configuration Guide, *Configuring
Security for VPNs with IPsec* and *Configuring Internet Key Exchange Version 2*):
``crypto map NAME SEQ ipsec-isakmp`` with ``set peer``, ``set transform-set``,
``set pfs``, ``set security-association lifetime``, ``match address``,
``set ikev2-profile``; ``crypto ikev2 proposal|policy|profile|keyring``;
``crypto ipsec profile``; ``interface TunnelN`` + ``tunnel protection ipsec
profile``.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from typing import Any

from .config_tree import ConfigTree, Node
from .netutil import is_ipv4

WEAK_DH = {"1", "2", "5"}
GOOD_DH = {"14", "15", "16", "19", "20", "21", "24"}
_DH_NAME = {"1": "768-bit MODP", "2": "1024-bit MODP", "5": "1536-bit MODP", "14": "2048-bit MODP", "15": "3072-bit MODP", "16": "4096-bit MODP",
            "19": "256-bit ECP", "20": "384-bit ECP", "21": "521-bit ECP", "24": "2048-bit MODP with 256-bit subgroup"}


def dh_label(group: str) -> str:
    group = str(group).replace("group", "").strip()
    return f"group {group} ({_DH_NAME[group]})" if group in _DH_NAME else (f"group {group}" if group else "")


def psk_token(salt: bytes, key: str) -> str:
    """Opaque equality token for a pre-shared key (keyed hash, random salt per analysis)."""
    return hmac.new(salt, key.encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Extraction helpers (called by config_extract.extract_crypto)
# ---------------------------------------------------------------------------


def _storage(type_code: str | None) -> tuple[str, str]:
    from features.analyzer_core.redaction import secret_strength

    if type_code in (None, "0", ""):
        return ("clear text", "weak")
    return secret_strength(type_code)


def parse_psk_tokens(tokens: list[str], salt: bytes) -> dict[str, str]:
    """``[local|remote] [0|6|7] KEY`` (IKEv2 keyring) → storage/strength/token; the key itself is dropped."""
    tokens = list(tokens)
    direction = ""
    if tokens and tokens[0] in ("local", "remote"):
        direction = tokens.pop(0)
    type_code = None
    if len(tokens) >= 2 and tokens[0] in ("0", "6", "7"):
        type_code = tokens.pop(0)
    key = tokens[0] if tokens else ""
    storage, strength = _storage(type_code)
    return {"direction": direction, "storage": storage, "strength": strength, "token": psk_token(salt, key) if key else ""}


def extract_ikev2(tree: ConfigTree, salt: bytes) -> dict[str, Any]:
    proposals = []
    for node in tree.top("crypto ikev2 proposal"):
        proposals.append({"name": node.text.split()[-1], "encryption": node.get("encryption").split(), "integrity": node.get("integrity").split(), "group": node.get("group").split(), "prf": node.get("prf").split()})
    policies = []
    for node in tree.top("crypto ikev2 policy"):
        policies.append({"name": node.text.split()[-1], "proposals": node.all("proposal"), "match": [c.text for c in node.find("match")]})
    profiles = []
    for node in tree.top("crypto ikev2 profile"):
        match_remote = []
        for child in node.find("match identity remote"):
            match_remote.append(child.text.replace("match identity remote", "", 1).strip())
        keyrings = []
        for child in node.find("keyring"):
            keyrings.append(child.text.replace("keyring", "", 1).strip())
        profiles.append({
            "name": node.text.split()[-1], "match_remote": match_remote, "match_fvrf": node.get("match fvrf"), "match_address_local": node.all("match address local"),
            "auth_remote": node.all("authentication remote"), "auth_local": node.all("authentication local"), "keyrings": keyrings, "lifetime": node.get("lifetime"),
            "dpd": node.get("dpd"), "pki": node.all("pki trustpoint"), "virtual_template": node.get("virtual-template"), "ivrf": node.get("ivrf"),
        })
    keyrings = []
    for node in tree.top("crypto ikev2 keyring"):
        peers = []
        for peer in node.find("peer"):
            addresses = [c.text.replace("address", "", 1).strip() for c in peer.find("address")]
            hostnames = [c.text.replace("hostname", "", 1).strip() for c in peer.find("hostname")]
            identities = [c.text.replace("identity", "", 1).strip() for c in peer.find("identity")]
            keys = []
            for c in peer.find("pre-shared-key"):
                keys.append(parse_psk_tokens(c.text.split()[1:], salt))
            peers.append({"name": peer.text.split(None, 1)[1] if " " in peer.text else "", "addresses": addresses, "hostnames": hostnames, "identities": identities, "keys": keys})
        keyrings.append({"name": node.text.split()[-1], "peers": peers})
    return {
        "proposals": proposals, "policies": policies, "profiles": profiles, "keyrings": keyrings,
        "dpd": tree.get("crypto ikev2 dpd"), "fragmentation": tree.has("crypto ikev2 fragmentation"),
    }


def extract_map_entry(node: Node, parts: list[str]) -> dict[str, Any]:
    """One ``crypto map NAME SEQ ipsec-isakmp`` block."""
    lifetime_s = lifetime_kb = ""
    for child in node.find("set security-association lifetime"):
        tokens = child.text.split()
        if "seconds" in tokens and tokens.index("seconds") + 1 < len(tokens):
            lifetime_s = tokens[tokens.index("seconds") + 1]
        if "kilobytes" in tokens and tokens.index("kilobytes") + 1 < len(tokens):
            lifetime_kb = tokens[tokens.index("kilobytes") + 1]
    peers = []
    for text in node.all("set peer"):
        peers.append(text.split()[0] if text.split() else "")
    return {
        "seq": parts[3], "type": parts[4], "group": node.get("set group"), "peers": peers, "transform_sets": " ".join(node.all("set transform-set")).split(),
        "acl": node.get("match address"), "pfs": node.get("set pfs"), "lifetime": node.get("set security-association lifetime"), "lifetime_seconds": lifetime_s, "lifetime_kilobytes": lifetime_kb,
        "description": node.get("description"), "ikev2_profile": node.get("set ikev2-profile"), "isakmp_profile": node.get("set isakmp-profile"), "reverse_route": node.has("reverse-route"),
        "dynamic": parts[6] if len(parts) > 6 and parts[5] == "dynamic" else "", "nat_keepalive": node.get("set nat"), "df_bit": node.get("set df-bit"),
    }


# ---------------------------------------------------------------------------
# Algorithms
# ---------------------------------------------------------------------------


def analyse_transform(text: str) -> dict[str, Any]:
    """Cipher, integrity and what is weak about an IOS transform set (``esp-aes 256 esp-sha256-hmac``)."""
    tokens = text.lower().split()
    cipher = integrity = ""
    weak: list[str] = []
    legacy: list[str] = []
    ah = False
    i = 0
    while i < len(tokens):
        token = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if token == "esp-aes":
            bits = nxt if nxt in ("128", "192", "256") else "128"
            cipher = f"AES-{bits}"
            i += 1 if nxt in ("128", "192", "256") else 0
        elif token == "esp-gcm":
            bits = nxt if nxt in ("128", "192", "256") else "128"
            cipher = f"AES-GCM-{bits}"
            integrity = integrity or "AEAD"
            i += 1 if nxt in ("128", "192", "256") else 0
        elif token == "esp-gmac":
            cipher = "GMAC (authentication only)"
            weak.append("no encryption (GMAC)")
        elif token == "esp-3des":
            cipher = "3DES"
            weak.append("3DES")
        elif token == "esp-des":
            cipher = "DES"
            weak.append("DES")
        elif token == "esp-null":
            cipher = "NULL (no encryption)"
            weak.append("ESP-NULL")
        elif token == "esp-seal":
            cipher = "SEAL"
        elif token in ("esp-sha-hmac", "ah-sha-hmac"):
            integrity = "HMAC-SHA1"
            legacy.append("SHA-1")
            ah = ah or token.startswith("ah")
        elif token in ("esp-sha256-hmac", "ah-sha256-hmac"):
            integrity = "HMAC-SHA-256"
        elif token in ("esp-sha384-hmac", "ah-sha384-hmac"):
            integrity = "HMAC-SHA-384"
        elif token in ("esp-sha512-hmac", "ah-sha512-hmac"):
            integrity = "HMAC-SHA-512"
        elif token in ("esp-md5-hmac", "ah-md5-hmac"):
            integrity = "HMAC-MD5"
            weak.append("MD5")
        elif token == "comp-lzs":
            pass
        i += 1
    return {"cipher": cipher or "?", "integrity": integrity or ("none" if cipher.startswith("AES-GCM") else "?"), "weak": sorted(set(weak)), "legacy": sorted(set(legacy)), "ah": ah}


def _ike2_proposal_weak(proposal: dict[str, Any]) -> list[str]:
    weak: list[str] = []
    for value in proposal.get("encryption", []):
        if value.lower() in ("3des", "des"):
            weak.append(value.upper())
    for value in proposal.get("integrity", []):
        if value.lower() == "md5":
            weak.append("MD5")
    for value in proposal.get("group", []):
        if value in WEAK_DH:
            weak.append(f"DH group {value}")
    return weak


# ---------------------------------------------------------------------------
# The model
# ---------------------------------------------------------------------------


def _net(text: str) -> ipaddress.IPv4Network | None:
    try:
        parts = text.split()
        if len(parts) == 2:
            return ipaddress.IPv4Network((parts[0], parts[1]), strict=False)
        if "/" in text:
            return ipaddress.IPv4Network(text, strict=False)
        return ipaddress.IPv4Network(text + "/32")
    except ValueError:
        return None


def _key_covers(key_peer: str, peer: str) -> bool:
    """Does ``crypto isakmp key … address A [mask]`` apply to the peer IP?"""
    if not key_peer or not is_ipv4(peer):
        return False
    if key_peer.startswith("host ") or key_peer.startswith("hostname "):
        return False
    tokens = key_peer.split()
    spec = " ".join(tokens[:2]) if len(tokens) >= 2 and is_ipv4(tokens[1]) else (tokens[0] if tokens else "")
    network = _net(spec)
    return network is not None and ipaddress.IPv4Address(peer) in network


def _acl_summary(acl: dict[str, Any] | None) -> dict[str, Any]:
    if acl is None:
        return {"defined": False, "entries": 0, "permits": 0, "any_any": False, "text": []}
    permits = [e for e in acl["entries"] if e.get("action") == "permit"]
    any_any = any(e.get("source") == "any" and e.get("destination") == "any" and e.get("protocol") in ("ip", "") for e in permits)
    text = [f"{e.get('protocol', '')} {e.get('source', '')} → {e.get('destination', '')}".strip() for e in permits[:6]]
    return {"defined": True, "entries": len(acl["entries"]), "permits": len(permits), "any_any": any_any, "text": text}


def build(cfg: dict[str, Any] | None, live: dict[str, Any] | None = None) -> dict[str, Any]:
    """Tunnel inventory and defects.  ``live`` may carry ``crypto_session``, ``ipsec_sa`` and ``isakmp_sa`` lists."""
    if not cfg:
        return {}
    crypto = cfg.get("crypto") or {}
    interfaces = cfg.get("interfaces") or []
    maps = crypto.get("crypto_maps") or []
    profiles_v1 = crypto.get("ipsec_profiles") or []
    vti = [i for i in interfaces if i.get("tunnel_protection")]
    if not (maps or vti or crypto.get("isakmp_policies") or crypto.get("isakmp_keys") or (crypto.get("ikev2") or {}).get("profiles")):
        return {}
    live = live or {}

    transform_sets = {t["name"]: t for t in crypto.get("transform_sets", [])}
    acls = {a["name"]: a for a in cfg.get("acls", [])}
    ikev2 = crypto.get("ikev2") or {}
    ike2_profiles = {p["name"]: p for p in ikev2.get("profiles", [])}
    keyrings = {k["name"]: k for k in ikev2.get("keyrings", [])}
    keys_v1 = crypto.get("isakmp_keys") or []
    ipsec_profiles = {p["name"]: p for p in profiles_v1}
    applied: dict[str, list[str]] = {}
    for iface in interfaces:
        if iface.get("crypto_map"):
            applied.setdefault(iface["crypto_map"].split()[0], []).append(iface["name"])
    pre_share_policy = any((p.get("authentication") or "rsa-sig") == "pre-share" for p in crypto.get("isakmp_policies", []))

    sessions_by_peer: dict[str, dict[str, Any]] = {}
    for s in live.get("crypto_session") or []:
        sessions_by_peer.setdefault(s.get("peer", ""), s)
    sa_by_peer: dict[str, list[dict[str, Any]]] = {}
    for sa in live.get("ipsec_sa") or []:
        sa_by_peer.setdefault(sa.get("peer", ""), []).append(sa)
    ike_by_peer: dict[str, dict[str, Any]] = {}
    for row in live.get("isakmp_sa") or []:
        ike_by_peer.setdefault(row.get("dst", ""), row)

    tunnels: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    used_transform: set[str] = set()
    used_ike2_profiles: set[str] = set()
    used_acls: set[str] = set()

    def issue(kind: str, severity: str, tunnel: str, text: str, **extra: Any) -> None:
        issues.append({"kind": kind, "severity": severity, "tunnel": tunnel, "text": text, **extra})

    def transform_info(names: list[str]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        rows: list[dict[str, Any]] = []
        weak: list[str] = []
        missing: list[str] = []
        for name in names:
            used_transform.add(name)
            item = transform_sets.get(name)
            if item is None:
                missing.append(name)
                continue
            info = analyse_transform(item["transforms"])
            info["name"] = name
            info["mode"] = item.get("mode") or "tunnel"
            rows.append(info)
            weak += info["weak"]
        return rows, sorted(set(weak)), missing

    def v1_key_for(peer: str) -> dict[str, Any] | None:
        specific = [k for k in keys_v1 if _key_covers(k.get("address", ""), peer) and not k.get("address", "").startswith("0.0.0.0")]
        if specific:
            return specific[0]
        wildcard = [k for k in keys_v1 if k.get("address", "").startswith("0.0.0.0")]
        return wildcard[0] if wildcard else None

    def v2_key_for(profile: dict[str, Any], peer: str) -> tuple[dict[str, Any] | None, str]:
        """(key, reason) for a peer under an IKEv2 profile: the keyring peer whose address covers it."""
        if not profile["keyrings"]:
            return None, "profile has no keyring"
        for entry in profile["keyrings"]:
            name = entry.split()[-1]
            ring = keyrings.get(name)
            if ring is None:
                return None, f"keyring {name} is not defined"
            for ring_peer in ring["peers"]:
                for address in ring_peer["addresses"]:
                    network = _net(address)
                    if network is not None and is_ipv4(peer) and ipaddress.IPv4Address(peer) in network:
                        return (ring_peer["keys"][0] if ring_peer["keys"] else {"storage": "none", "strength": "weak", "token": ""}), ""
        return None, "no keyring entry covers the peer address"

    unapplied_reported: set[str] = set()
    for cmap in maps:
        for entry in cmap["entries"]:
            if not str(entry.get("type", "")).startswith("ipsec"):
                continue   # 'crypto map NAME N gdoi' is GETVPN, reported by its own tables
            label = f"{cmap['name']} {entry['seq']}"
            peers = [p for p in entry["peers"] if p]
            ike_version = "IKEv2" if entry.get("ikev2_profile") else "IKEv1"
            ts_rows, weak_ts, missing_ts = transform_info(entry["transform_sets"])
            if entry["acl"]:
                used_acls.add(entry["acl"])
            acl = _acl_summary(acls.get(entry["acl"])) if entry["acl"] else {"defined": False, "entries": 0, "permits": 0, "any_any": False, "text": []}
            pfs = (entry.get("pfs") or "").replace("group", "").strip()
            auth = "pre-shared"
            key_info = None
            key_note = ""
            profile = None
            if entry.get("ikev2_profile"):
                used_ike2_profiles.add(entry["ikev2_profile"])
                profile = ike2_profiles.get(entry["ikev2_profile"])
                if profile is None:
                    issue("undefined", "high", label, f"IKEv2 profile {entry['ikev2_profile']} is not defined", obj=entry["ikev2_profile"])
                else:
                    methods = " ".join(profile["auth_remote"] + profile["auth_local"])
                    auth = "certificate" if "rsa-sig" in methods or "ecdsa-sig" in methods else ("pre-shared" if "pre-share" in methods else "?")
                    if auth == "pre-shared" and peers:
                        key_info, key_note = v2_key_for(profile, peers[0])
                        if key_info is None:
                            issue("no_psk", "high", label, f"no pre-shared key for {peers[0]} ({key_note})", peers=peers)
                    identities = " ".join(profile["match_remote"])
                    if peers and profile["match_remote"] and not any(p in identities for p in peers):
                        issue("profile_mismatch", "medium", label, f"IKEv2 profile {profile['name']} matches {identities} but the map's peer is {', '.join(peers)}", peers=peers)
            elif entry.get("isakmp_profile"):
                auth = "isakmp profile"
            else:
                if peers and pre_share_policy:
                    key_info = v1_key_for(peers[0])
                    if key_info is None:
                        issue("no_psk", "high", label, f"no 'crypto isakmp key' covers {peers[0]}", peers=peers)
            if missing_ts:
                issue("undefined", "high", label, "transform-set not defined: " + ", ".join(missing_ts), obj=", ".join(missing_ts))
            if entry["acl"] and not acl["defined"]:
                issue("undefined", "high", label, f"'match address {entry['acl']}' names an ACL that is not defined", obj=entry["acl"])
            elif entry["acl"] and acl["permits"] == 0:
                issue("empty_acl", "high", label, f"crypto ACL {entry['acl']} has no permit entry, so no traffic is protected", obj=entry["acl"])
            elif entry["acl"] and acl["any_any"]:
                issue("any_any", "high", label, f"crypto ACL {entry['acl']} permits 'ip any any': every packet leaving the interface is sent into this tunnel", obj=entry["acl"])
            if not entry["acl"] and not entry["dynamic"]:
                issue("no_acl", "high", label, "no 'match address': the entry selects no traffic")
            if not entry["transform_sets"] and not entry["dynamic"]:
                issue("undefined", "high", label, "no 'set transform-set'")
            if not pfs:
                issue("pfs", "low", label, "no PFS: a compromised session key exposes later rekeys", peers=peers)
            elif pfs in WEAK_DH:
                issue("pfs", "medium", label, f"PFS {dh_label(pfs)} is a DH group Cisco advises against (groups 1, 2 and 5)", peers=peers)
            if weak_ts:
                issue("weak_transform", "medium" if "DES" not in weak_ts and "ESP-NULL" not in weak_ts else "high", label, "transform set uses " + ", ".join(weak_ts), peers=peers, sets=[r["name"] for r in ts_rows if r["weak"]])
            if cmap["name"] not in applied and cmap["name"] not in unapplied_reported:
                unapplied_reported.add(cmap["name"])   # one finding per map, not per entry
                issue("not_applied", "medium", label, f"crypto map {cmap['name']} is not applied to any interface", obj=cmap["name"])
            if not peers and not entry["dynamic"]:
                issue("no_peer", "high", label, "no 'set peer'")

            live_row: dict[str, Any] = {}
            for peer in peers:
                session = sessions_by_peer.get(peer)
                sas = sa_by_peer.get(peer) or []
                ike = ike_by_peer.get(peer)
                if session or sas or ike:
                    live_row = {
                        "status": (session or {}).get("status") or ((ike or {}).get("state") or ""),
                        "uptime": (session or {}).get("uptime", ""),
                        "encaps": sum(max(s.get("encaps") or 0, 0) for s in sas), "decaps": sum(max(s.get("decaps") or 0, 0) for s in sas),
                        "errors": sum((s.get("send_errors") or 0) + (s.get("recv_errors") or 0) for s in sas),
                        "ike_state": (ike or {}).get("state", ""),
                    }
                    break
            tunnels.append({
                "kind": "crypto map", "name": label, "map": cmap["name"], "seq": entry["seq"], "description": entry.get("description") or "", "peers": peers or (["dynamic " + entry["dynamic"]] if entry["dynamic"] else []),
                "ike": ike_version, "profile": entry.get("ikev2_profile") or entry.get("isakmp_profile") or "", "auth": auth, "transform_sets": ts_rows, "pfs": dh_label(pfs) if pfs else "none",
                "pfs_value": pfs, "lifetime": ("%ss" % entry["lifetime_seconds"] if entry["lifetime_seconds"] else "") + (f" / {entry['lifetime_kilobytes']} KB" if entry["lifetime_kilobytes"] else ""),
                "acl": entry["acl"], "acl_permits": acl["permits"], "proxy": acl["text"], "applied_on": applied.get(cmap["name"], []),
                "key": key_info or {}, "key_note": key_note, "live": live_row,
                "weak": weak_ts, "legacy": sorted({x for r in ts_rows for x in r["legacy"]}),
            })

    for iface in vti:
        profile_name = iface["tunnel_protection"].replace("ipsec profile", "").split()[0] if "ipsec profile" in iface["tunnel_protection"] else ""
        profile = ipsec_profiles.get(profile_name)
        label = iface["name"]
        peer = (iface.get("tunnel") or {}).get("destination", "")
        if profile is None:
            issue("undefined", "high", label, f"tunnel protection names IPsec profile {profile_name or '?'} which is not defined", obj=profile_name)
            ts_rows, weak_ts = [], []
        else:
            ts_rows, weak_ts, missing_ts = transform_info(profile["transform_sets"])
            if missing_ts:
                issue("undefined", "high", label, "transform-set not defined: " + ", ".join(missing_ts), obj=", ".join(missing_ts))
            if weak_ts:
                issue("weak_transform", "medium", label, "transform set uses " + ", ".join(weak_ts), peers=[peer] if peer else [], sets=[r["name"] for r in ts_rows if r["weak"]])
            pfs = (profile.get("pfs") or "").replace("group", "").strip()
            if not pfs:
                issue("pfs", "low", label, "no PFS", peers=[peer] if peer else [])
            elif pfs in WEAK_DH:
                issue("pfs", "medium", label, f"PFS {dh_label(pfs)} is a DH group Cisco advises against (groups 1, 2 and 5)", peers=[peer] if peer else [])
            if profile.get("ikev2_profile"):
                used_ike2_profiles.add(profile["ikev2_profile"])
                if profile["ikev2_profile"] not in ike2_profiles:
                    issue("undefined", "high", label, f"IKEv2 profile {profile['ikev2_profile']} is not defined", obj=profile["ikev2_profile"])
        tunnels.append({
            "kind": "VTI", "name": label, "map": "", "seq": "", "description": iface.get("description") or "", "peers": [peer] if peer else [], "ike": "IKEv2" if (profile or {}).get("ikev2_profile") else "IKEv1",
            "profile": profile_name, "auth": "?", "transform_sets": ts_rows, "pfs": dh_label((profile or {}).get("pfs", "").replace("group", "").strip()) if (profile or {}).get("pfs") else "none",
            "pfs_value": ((profile or {}).get("pfs") or "").replace("group", "").strip(), "lifetime": "", "acl": "", "acl_permits": 0, "proxy": [], "applied_on": [label], "key": {}, "key_note": "",
            "live": {}, "weak": weak_ts, "legacy": sorted({x for r in ts_rows for x in r["legacy"]}),
        })

    # pre-shared key reuse (token equality; the keys themselves never leave the extractor)
    by_token: dict[str, list[str]] = {}
    for key in keys_v1:
        if key.get("token"):
            by_token.setdefault(key["token"], []).append(key.get("address") or key.get("peer", ""))
    for ring in keyrings.values():
        for ring_peer in ring["peers"]:
            for key in ring_peer["keys"]:
                if key.get("token"):
                    by_token.setdefault(key["token"], []).append((ring_peer["addresses"] or [ring_peer["name"]])[0])
    same_entry = [set(t["peers"]) for t in tunnels if len(t["peers"]) > 1]
    tunnel_peers = {p for t in tunnels for p in t["peers"]}
    reuse = []
    for peers in by_token.values():
        group = set(peers) & tunnel_peers          # GETVPN key servers share one key by design: only real tunnel peers count
        if len(group) > 1 and not any(group <= entry for entry in same_entry):
            reuse.append(sorted(group))

    # IKEv2 policies / proposals that are actually offered
    offered: list[dict[str, Any]] = []
    proposals = {p["name"]: p for p in ikev2.get("proposals", [])}
    if ikev2.get("policies"):
        for policy in ikev2["policies"]:
            for name in policy["proposals"]:
                proposal = proposals.get(name)
                if proposal is None:
                    issue("undefined", "high", f"ikev2 policy {policy['name']}", f"proposal {name} is not defined", obj=name)
                    continue
                offered.append(dict(proposal, policy=policy["name"], weak=_ike2_proposal_weak(proposal)))
    elif "default" in proposals:
        offered.append(dict(proposals["default"], policy="default", weak=_ike2_proposal_weak(proposals["default"])))

    # defined but unused objects
    unused = {
        "transform_sets": sorted(set(transform_sets) - used_transform - {n for p in profiles_v1 for n in p["transform_sets"]}),
        "ikev2_profiles": sorted(set(ike2_profiles) - used_ike2_profiles),
        "keyrings": sorted(set(keyrings) - {k.split()[-1] for p in ikev2.get("profiles", []) for k in p["keyrings"]}),
        "ikev2_proposals": sorted(set(proposals) - {n for pol in ikev2.get("policies", []) for n in pol["proposals"]} - {"default"}),
        "crypto_maps": sorted(name for name in (m["name"] for m in maps) if name not in applied),
        "acls": [],
    }
    # IKEv2 profile → keyring dangling / wildcard
    for profile in ikev2.get("profiles", []):
        for entry in profile["keyrings"]:
            name = entry.split()[-1]
            if name not in keyrings:
                issue("undefined", "high", f"ikev2 profile {profile['name']}", f"keyring {name} is not defined", obj=name)
    for ring in keyrings.values():
        for ring_peer in ring["peers"]:
            if any(a.startswith("0.0.0.0") for a in ring_peer["addresses"]):
                issue("wildcard", "high", f"keyring {ring['name']}", f"peer {ring_peer['name']} accepts any address with a shared key", obj=ring["name"])
            if not ring_peer["keys"]:
                issue("no_psk", "medium", f"keyring {ring['name']}", f"peer {ring_peer['name']} has no pre-shared-key line", obj=ring["name"])

    dpd = bool(crypto.get("isakmp_keepalive")) or bool(ikev2.get("dpd")) or any(p.get("dpd") for p in ikev2.get("profiles", []))
    return {
        "tunnels": tunnels, "issues": issues, "reuse": reuse, "unused": unused, "offered_ikev2": offered, "dpd": dpd,
        "ikev1_policies": crypto.get("isakmp_policies", []), "ikev2": ikev2, "aggressive_mode_disabled": bool(crypto.get("aggressive_mode_disabled")),
        "peer_count": len({p for t in tunnels for p in t["peers"]}), "ikev1_keys": len(keys_v1), "pre_share_policy": pre_share_policy,
        "live": {"sessions": len(live.get("crypto_session") or []), "ipsec_sa": len(live.get("ipsec_sa") or []), "isakmp_sa": len(live.get("isakmp_sa") or [])},
    }
