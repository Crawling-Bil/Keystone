"""Security modules, global settings and a configuration inventory for a BIG-IP configuration.

``bigip_extract`` covers LTM, net, sys, auth and cm.  A real BIG-IP also carries Advanced WAF (ASM) policies, DoS and
logging profiles, AFM address/port lists, APM policies, application services and tunnels.  This module reads those
from the same TMSH tree, ties them to the virtual servers that use them, and builds the inventory that proves
nothing was silently skipped.

What a UCS (or ``bigip.conf``) does *not* hold: ASM keeps the body of each policy (enforcement mode, signatures,
learning state) in its own database, so the configuration only names the policy, its template and whether it is
active.  The analyzer reports whether a policy exists, is active and is attached to a virtual server, and asks for
the policy XML export for the rest - it does not guess an enforcement mode.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from .bigip_extract import short
from .tmsh_tree import TNode, TmshTree

# object types the main extractor already turns into tables (first two words of the stanza)
ANALYZED = {
    ("ltm", "virtual"), ("ltm", "virtual-address"), ("ltm", "pool"), ("ltm", "node"), ("ltm", "monitor"), ("ltm", "profile"), ("ltm", "persistence"), ("ltm", "rule"), ("ltm", "policy"), ("ltm", "data-group"),
    ("ltm", "snat"), ("ltm", "snatpool"), ("ltm", "snat-translation"), ("ltm", "default-node-monitor"), ("ltm", "global-settings"), ("net", "vlan"), ("net", "self"), ("net", "self-allow"), ("net", "route"), ("net", "route-domain"),
    ("net", "trunk"), ("cm", "device"), ("cm", "device-group"), ("cm", "traffic-group"), ("cm", "trust-domain"), ("cm", "cert"), ("cm", "key"), ("sys", "httpd"), ("sys", "sshd"), ("sys", "snmp"), ("sys", "ntp"), ("sys", "dns"),
    ("sys", "syslog"), ("sys", "provision"), ("sys", "folder"), ("sys", "global-settings"), ("sys", "management-ip"), ("sys", "management-route"), ("sys", "file"), ("auth", "user"), ("auth", "ldap"), ("auth", "radius"),
    ("gtm", "wideip"), ("gtm", "pool"), ("gtm", "server"), ("gtm", "datacenter"), ("gtm", "listener"), ("gtm", "topology"), ("gtm", "region"),
    ("auth", "tacacs"), ("auth", "source"), ("auth", "password-policy"), ("auth", "remote-user"), ("auth", "remote-role"),
}
# exact object-type keys shown in their own table (Security tab)
SHOWN_HERE = {
    ("asm", "policy"), ("security", "dos", "profile"), ("security", "log", "profile"), ("security", "firewall", "address-list"), ("security", "firewall", "port-list"), ("security", "firewall", "rule-list"),
    ("net", "address-list"), ("net", "port-list"), ("apm", "policy", "access-policy"), ("sys", "application", "service"), ("net", "tunnels", "tunnel"),
}
THREE_WORD_TYPES = {"profile", "monitor", "persistence", "data-group", "dos", "firewall", "bot-defense", "shared-objects", "tunnels", "ipsec", "log-config", "application", "icall", "software", "log", "daemon-log-settings", "datasync", "protocol-inspection", "device-id", "global-settings"}
MODULES = {"ltm", "net", "sys", "security", "asm", "apm", "cm", "auth", "gtm", "wom", "pem", "ilx", "analytics", "cli", "ecm", "ip", "cmi", "wam", "vcmp"}
MAX_GLOBAL_PAIRS = 8
MAX_GLOBAL_ROWS = 90
NAMES_PREVIEW = 6


# ============================================================================ extraction
def _asm_actions(policy: TNode) -> list[dict[str, str]]:
    """LTM policy actions that touch ASM: ``asm`` + ``enable`` / ``disable`` (+ ``policy /Common/x``)."""
    out = []
    rules = policy.child("rules")
    for rule in (rules.children if rules else []):
        actions = rule.child("actions")
        for act in (actions.children if actions else []):
            keys = {c.key for c in act.children}
            if "asm" in keys:
                out.append({"rule": rule.key, "mode": "enable" if "enable" in keys else "disable" if "disable" in keys else "", "policy": act.val("policy")})
    return out


def _features(node: TNode, wanted: tuple[str, ...]) -> list[str]:
    found: list[str] = []
    for item in node.walk():
        if item.key in wanted:
            mode = item.val("mode")
            label = f"{item.key} ({mode})" if mode else item.key
            if label not in found:
                found.append(label)
    return found


def extract(tree: TmshTree, data: dict[str, Any]) -> dict[str, Any]:
    ltm_asm = {short(p.name): acts for p in tree.named("ltm", "policy") if (acts := _asm_actions(p))}
    dos_names = {short(n.name) for n in tree.named("security", "dos", "profile")}
    log_names = {short(n.name) for n in tree.named("security", "log", "profile")}
    uses: dict[str, dict[str, list[str]]] = {"dos": {}, "log": {}, "policy": {}}
    for vs in tree.named("ltm", "virtual"):
        vname = short(vs.name)
        for prof in vs.names("profiles"):
            if short(prof) in dos_names:
                uses["dos"].setdefault(short(prof), []).append(vname)
        for prof in vs.names("security-log-profiles"):
            uses["log"].setdefault(short(prof), []).append(vname)
        for pol in vs.names("policies"):
            uses["policy"].setdefault(short(pol), []).append(vname)

    attached: dict[str, list[str]] = {}
    for ltm_policy, actions in ltm_asm.items():
        for act in actions:
            if act["mode"] == "enable" and act["policy"]:
                attached.setdefault(short(act["policy"]), []).extend(uses["policy"].get(ltm_policy, []))
    asm_policies = []
    for n in tree.named("asm", "policy"):
        name = short(n.name)
        via = sorted(lp for lp, acts in ltm_asm.items() if any(short(a["policy"]) == name and a["mode"] == "enable" for a in acts))
        asm_policies.append({"name": name, "active": any(c.key == "active" and not c.args for c in n.children), "template": n.val("policy-template"), "encoding": n.val("encoding"),
                             "attached_to": sorted(set(attached.get(name, []))), "ltm_policies": via, "orphan_ltm": [lp for lp in via if not uses["policy"].get(lp)]})

    dos = [{"name": short(n.name), "used_by": sorted(uses["dos"].get(short(n.name), [])),
            "features": _features(n, ("bot-signatures", "tps-based", "stress-based", "proactive-bot-defense", "behavioral-analysis", "mobile-detection", "single-page-application", "heavy-urls", "geolocations", "ip-intelligence"))}
           for n in tree.named("security", "dos", "profile")]
    logs = []
    for n in tree.named("security", "log", "profile"):
        kinds = [c.key for c in n.children if c.block and c.key in ("application", "network", "protocol-dns", "protocol-sip", "bot-defense", "ip-intelligence", "dos-application", "dos-network-publisher")]
        remote = sorted({i.val("protocol") or "remote" for i in n.walk() if i.key == "remote-storage" or (i.key == "logger-type" and i.value == "remote")})
        local = any(i.key == "local-storage" and i.value == "enabled" or (i.key == "logger-type" and i.value == "local") for i in n.walk())
        logs.append({"name": short(n.name), "kinds": kinds, "local": "yes" if local else "no", "remote": ", ".join(remote) or "no", "used_by": sorted(set(uses["log"].get(short(n.name), [])))})
    lists = []
    for kind, prefix in (("address list", ("net", "address-list")), ("port list", ("net", "port-list")), ("AFM address list", ("security", "firewall", "address-list")), ("AFM port list", ("security", "firewall", "port-list")),
                         ("AFM rule list", ("security", "firewall", "rule-list")), ("shared address list", ("security", "shared-objects", "address-list")), ("shared port list", ("security", "shared-objects", "port-list"))):
        for n in tree.named(*prefix):
            members = n.names("addresses") + n.names("ports") + n.names("geo") + n.names("fqdns") + n.names("address-lists") + n.names("port-lists") + n.names("rules")
            lists.append({"kind": kind, "name": short(n.name), "members": members[:12] + ([f"… +{len(members) - 12}"] if len(members) > 12 else []), "count": len(members) or len(n.children)})
    apm = [{"name": short(n.name), "items": len(n.child("items").children) if n.child("items") else 0, "default_ending": short(n.val("default-ending"))} for n in tree.named("apm", "policy", "access-policy")]
    apps = [{"name": n.name, "template": short(n.val("template")), "group": n.val("device-group")} for n in tree.named("sys", "application", "service")]
    tunnels = [{"name": short(n.name), "profile": short(n.val("profile")), "local": n.val("local-address"), "remote": n.val("remote-address"), "mtu": n.val("mtu")} for n in tree.named("net", "tunnels", "tunnel")]

    by_vs: dict[str, dict[str, list[str]]] = {}
    for p in asm_policies:
        for vs in p["attached_to"]:
            by_vs.setdefault(vs, {}).setdefault("asm", []).append(p["name"])
    return {
        "asm_policies": asm_policies, "ltm_asm_actions": ltm_asm, "dos": dos, "log_profiles": logs, "lists": lists, "apm": apm, "apps": apps, "tunnels": tunnels,
        "virtual_security": _virtual_security(data, by_vs, dos_names, log_names), "globals": _globals(tree), "inventory": _inventory(tree),
        "icall": [n.tokens[-1] for n in tree.root if n.tokens[:2] == ["sys", "icall"] and n.block],
        "daemon_log": {n.tokens[-1]: {c.key: c.value for c in n.children if c.args} for n in tree.root if n.block and n.tokens[:2] == ["sys", "daemon-log-settings"]},
        "software_update": next(({c.key: c.value for c in n.children if c.args} for n in tree.root if n.block and n.tokens == ["sys", "software", "update"]), {}),
        "provisioned": {m["module"]: m["level"] for m in data["sys"]["provision"] if m["level"] != "none"},
    }


def _virtual_security(data: dict[str, Any], by_vs: dict[str, dict[str, list[str]]], dos_names: set[str], log_names: set[str]) -> list[dict[str, Any]]:
    rows = []
    for v in data["virtuals"]:
        profiles = [short(p["name"]) for p in v["profiles"]]
        http = any("http" in p.lower() for p in profiles)
        tls = any(p["kind"] == "client-ssl" for p in data["profiles"] if short(p["name"]) in profiles)
        rows.append({"virtual": v["short"], "destination": f"{v['destination']}:{v['port_label']}", "public": v["public"], "enabled": v["enabled"], "http": http, "tls": tls,
                     "asm": by_vs.get(v["short"], {}).get("asm", []), "dos": [p for p in profiles if p in dos_names], "log": [short(p) for p in v["security_log_profiles"]],
                     "afm": short(v["fw_policy"]) if v["fw_policy"] else "", "ip_intel": short(v["ip_intelligence"]) if v["ip_intelligence"] else ""})
    return rows


# ---------------------------------------------------------------------------- inventory and globals
def _type_key(tokens: list[str]) -> tuple[str, ...]:
    if not tokens:
        return ()
    if tokens[0] not in MODULES or len(tokens) < 2:
        return tuple(tokens[:1])
    if tokens[:2] == ["apm", "policy"] and len(tokens) >= 3:
        return tuple(tokens[:3])
    if tokens[1] in THREE_WORD_TYPES and len(tokens) >= 3 and tokens[1] != "file":
        return tuple(tokens[:3])
    return tuple(tokens[:2])


def _inventory(tree: TmshTree) -> list[dict[str, Any]]:
    counts: Counter = Counter()
    names: dict[tuple[str, ...], list[str]] = {}
    for node in tree.root:
        if not node.tokens:
            continue
        key = _type_key(node.tokens)
        counts[key] += 1
        label = node.tokens[-1] if len(node.tokens) > len(key) else ""
        if len(names.setdefault(key, [])) < 400:
            names[key].append(short(label) if label else "(singleton)")
    rows = []
    for key, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        status = "analyzed" if key[:2] in ANALYZED else "listed on the Security tab" if key in SHOWN_HERE else "counted only"
        listed = names[key]
        rows.append({"type": " ".join(key), "count": count, "status": status, "objects": listed[:NAMES_PREVIEW] + ([f"… +{count - NAMES_PREVIEW}"] if count > NAMES_PREVIEW else []),
                     "_tones": {"status": "ok" if status == "analyzed" else "info" if status.startswith("listed") else "mute"}})
    return rows


def _globals(tree: TmshTree) -> list[dict[str, Any]]:
    """Single-instance objects not covered elsewhere (``sys software update``, ``sys state-mirroring``, ``net stp`` ...) with their
    first settings, so a global switch such as ``auto-phonehome enabled`` is visible without opening the raw file."""
    counts = Counter(_type_key(n.tokens) for n in tree.root if n.tokens)
    rows = []
    for node in tree.root:
        if not node.block or not node.tokens or node.raw:
            continue
        key = _type_key(node.tokens)
        if counts[key] != 1 or key[:2] in ANALYZED or key in SHOWN_HERE or node.tokens[0] not in MODULES:
            continue
        pairs = [(c.key, c.value if c.args else ("{ " + " ".join(c.names())[:80] + " }" if c.inline and c.children else "(set)" if not c.block else "{ … }")) for c in node.children]
        if not pairs and not node.children:
            pairs = [("", "(defaults)")]
        shown = [f"{k} {v}".strip() for k, v in pairs[:MAX_GLOBAL_PAIRS]]
        if len(pairs) > MAX_GLOBAL_PAIRS:
            shown.append(f"… +{len(pairs) - MAX_GLOBAL_PAIRS}")
        rows.append({"object": " ".join(node.tokens), "settings": shown})
        if len(rows) >= MAX_GLOBAL_ROWS:
            break
    return rows
