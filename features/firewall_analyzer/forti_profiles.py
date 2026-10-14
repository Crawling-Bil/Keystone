"""FortiGate security profiles: what each one actually does and which policies use it.

A policy that says ``set av-profile "default"`` only proves that a profile is attached.  Whether it blocks or merely
logs, and whether HTTPS payloads are decrypted so that antivirus and IPS can see them, is decided inside the profile:

* SSL/SSH inspection profile - ``certificate-inspection`` reads the server certificate and SNI only; antivirus, IPS,
  file filter and DLP cannot see inside the TLS session.  Only ``deep-inspection`` decrypts it.
* IPS sensor - entries with an explicit ``action pass`` / ``monitor`` log but never block.
* Antivirus - per protocol ``av-scan`` is ``disable``, ``monitor`` or ``block``.
* Web filter / DNS filter / application control - the FortiGuard category and application actions.

Read from the configuration export only; ``show`` omits values that equal the default, so a missing key is reported
as ``default`` and never as "disabled".

References: FortiOS Administration Guide - Certificate inspection
https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/505842 , Deep inspection
https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/122078 , Configuring an IPS sensor
https://docs.fortinet.com/document/fortigate/7.4.7/administration-guide/583477 , Configuring an antivirus profile
https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/922423 , FortiGuard filter
https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/675558
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .forti_tree import FNode, FortiTree
from .refs import FORTI

LABELS = {"antivirus": "Antivirus", "ips": "IPS sensor", "webfilter": "Web filter", "dnsfilter": "DNS filter", "application": "Application control", "ssl_ssh": "SSL/SSH inspection"}
PATHS = {"antivirus": "antivirus profile", "ips": "ips sensor", "webfilter": "webfilter profile", "dnsfilter": "dnsfilter profile", "application": "application list", "ssl_ssh": "firewall ssl-ssh-profile"}
POLICY_KEYS = {"av-profile": "antivirus", "ips-sensor": "ips", "webfilter-profile": "webfilter", "dnsfilter-profile": "dnsfilter", "application-list": "application", "ssl-ssh-profile": "ssl_ssh"}
# attachments that read the *content* of a session: they need decrypted traffic to do their job
PAYLOAD_KINDS = ("antivirus", "ips")
OTHER_KEYS = ("file-filter-profile", "emailfilter-profile", "dlp-profile", "dlp-sensor", "casb-profile", "waf-profile", "videofilter-profile", "voip-profile", "profile-group")
BUILTIN_SSL = {"certificate-inspection": "certificate", "deep-inspection": "deep", "custom-deep-inspection": "deep", "no-inspection": "off"}
SSL_PROTOCOLS = ("https", "ftps", "imaps", "pop3s", "smtps", "ssh", "dot")
AV_PROTOCOLS = ("http", "ftp", "imap", "pop3", "smtp", "mapi", "cifs", "ssh", "nntp")
PASSIVE = {"pass", "monitor"}


def _entries(node: FNode | None) -> list[FNode]:
    return node.entries() if node is not None else []


# --------------------------------------------------------------------------- one summariser per profile type
def _ssl(node: FNode) -> tuple[str, str, list[str]]:
    modes = {}
    for proto in SSL_PROTOCOLS:
        block = node.config(proto)
        if block is not None and block.get("status"):
            modes[proto] = block.get("status")
    https = modes.get("https", "")
    level = {"deep-inspection": "deep", "certificate-inspection": "certificate"}.get(https, "off")
    notes = []
    if any((node.config(p) is not None and node.config(p).get("unsupported-ssl-version") == "allow") for p in SSL_PROTOCOLS):
        notes.append("allows unsupported SSL/TLS versions")
    exempt = len(_entries(node.config("ssl-exempt")))
    detail = ", ".join(f"{p} {m}" for p, m in modes.items() if m != "disable") or "no protocol inspected"
    if exempt:
        detail += f" · {exempt} exemption(s)"
    return level, detail, notes


def _ips(node: FNode) -> tuple[str, str, list[str]]:
    entries = [e for e in _entries(node.config("entries")) if e.get("status", "enable") != "disable"]
    actions = Counter(e.get("action", "default") for e in entries)
    if not entries:
        return "off", "no signature entries", []
    passive = sum(n for a, n in actions.items() if a in PASSIVE)
    level = "monitor" if passive == len(entries) else "block"
    parts = [f"{n} {a}" for a, n in actions.most_common()]
    botnet = node.get("scan-botnet-connections")
    if botnet:
        parts.append(f"botnet {botnet}")
    notes = ["every entry only logs (pass/monitor)"] if level == "monitor" else []
    return level, f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'}: " + ", ".join(parts), notes


def _av(node: FNode) -> tuple[str, str, list[str]]:
    scan = {}
    for proto in AV_PROTOCOLS:
        block = node.config(proto)
        if block is not None and block.get("av-scan"):
            scan[proto] = block.get("av-scan")
    if not scan:
        return "off", "no protocol scanned", []
    level = "block" if any(v == "block" for v in scan.values()) else ("monitor" if any(v == "monitor" for v in scan.values()) else "off")
    notes = []
    if scan.get("http") not in ("block", None):
        notes.append(f"HTTP is {scan['http']}, not block")
    return level, ", ".join(f"{p} {v}" for p, v in scan.items()), notes


def _filters(node: FNode | None) -> Counter:
    return Counter(e.get("action", "monitor") for e in _entries(node))


def _web(node: FNode) -> tuple[str, str, list[str]]:
    ftgd = node.config("ftgd-wf")
    actions = _filters(ftgd.config("filters") if ftgd is not None else None)
    web = node.config("web")
    table = web.get("urlfilter-table") if web is not None else ""
    blocking = actions.get("block", 0) > 0 or bool(table)
    parts = [f"{n} categor{'y' if n == 1 else 'ies'} {a}" for a, n in actions.most_common()]
    if table:
        parts.append(f"URL filter table {table}")
    level = "block" if blocking else ("monitor" if actions else "off")
    return level, ", ".join(parts) or "no category or URL rule", ["nothing is blocked"] if level == "monitor" else []


def _dns(node: FNode) -> tuple[str, str, list[str]]:
    ftgd = node.config("ftgd-dns")
    actions = _filters(ftgd.config("filters") if ftgd is not None else None)
    botnet = node.get("block-botnet") == "enable"
    domain_table = node.get("domain-filter") or (node.config("domain-filter").get("domain-filter-table") if node.config("domain-filter") is not None else "")
    parts = [f"{n} categor{'y' if n == 1 else 'ies'} {a}" for a, n in actions.most_common()]
    if botnet:
        parts.append("botnet C&C blocked")
    if domain_table:
        parts.append(f"domain filter {domain_table}")
    level = "block" if (actions.get("block") or botnet or domain_table) else ("monitor" if actions else "off")
    return level, ", ".join(parts) or "no category rule", []


def _app(node: FNode) -> tuple[str, str, list[str]]:
    entries = _entries(node.config("entries"))
    actions = Counter(e.get("action", "pass") for e in entries)
    other = node.get("other-application-action", "pass")
    unknown = node.get("unknown-application-action", "pass")
    blocking = any(a in ("block", "reset") for a in actions) or other == "block" or unknown == "block"
    parts = [f"{n} {a}" for a, n in actions.most_common()]
    if other != "pass":
        parts.append(f"other apps {other}")
    if unknown != "pass":
        parts.append(f"unknown apps {unknown}")
    return ("block" if blocking else "monitor"), ", ".join(parts) or "no entries (all traffic passes)", [] if blocking else ["nothing is blocked"]


SUMMARISE = {"ssl_ssh": _ssl, "ips": _ips, "antivirus": _av, "webfilter": _web, "dnsfilter": _dns, "application": _app}
LEVEL_TEXT = {"deep": "deep inspection", "certificate": "certificate inspection only", "off": "off", "block": "blocks", "monitor": "monitor only"}
LEVEL_TONE = {"deep": "ok", "block": "ok", "certificate": "warn", "monitor": "warn", "off": "mute"}


# --------------------------------------------------------------------------- extraction
def extract(tree: FortiTree) -> dict[str, Any]:
    """``profiles``: one row per profile; ``policy_utm``: {(vdom, policy id): {kind: profile name}}."""
    policy_utm: dict[tuple[str, str], dict[str, str]] = {}
    usage: Counter = Counter()
    policies_using: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for vdom, node in tree.entries("firewall policy"):
        attached = {kind: node.get(key) for key, kind in POLICY_KEYS.items() if node.get(key)}
        attached["_other"] = [key for key in OTHER_KEYS if node.get(key)]
        attached["_status"] = node.get("status", "enable")
        policy_utm[(vdom, node.name)] = attached
        if attached["_status"] == "disable":
            continue
        for kind, name in attached.items():
            if kind in LABELS:
                usage[(kind, name, vdom)] += 1
                policies_using[(kind, name, vdom)].append(node.name)
    rows = []
    for kind, path in PATHS.items():
        for scope, node in tree.entries(path):
            level, detail, notes = SUMMARISE[kind](node)
            if scope == "global":
                used = sum(n for (k, name, _), n in usage.items() if k == kind and name == node.name)
                sample = [p for (k, name, _), ids in policies_using.items() if k == kind and name == node.name for p in ids]
            else:
                used = usage.get((kind, node.name, scope), 0)
                sample = policies_using.get((kind, node.name, scope), [])
            rows.append({"kind": LABELS[kind], "key": kind, "name": node.name, "vdom": scope, "level": level, "mode": LEVEL_TEXT[level], "detail": detail, "notes": "; ".join(notes),
                         "used_by": used, "policies": [f"#{p}" for p in sample[:8]] + ([f"+{len(sample) - 8}"] if len(sample) > 8 else [])})
    rows.sort(key=lambda r: (-r["used_by"], r["kind"], r["name"]))
    return {"profiles": rows, "policy_utm": policy_utm}


def section_rows(detail: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for row in detail["profiles"]:
        tone = LEVEL_TONE[row["level"]]
        out.append(dict(row, _tones={"mode": tone if row["used_by"] or tone != "mute" else "mute", "notes": "warn" if row["notes"] and row["used_by"] else ""}))
    return out


# --------------------------------------------------------------------------- rules
def _levels(detail: dict[str, Any]) -> dict[tuple[str, str, str], str]:
    return {(r["key"], r["name"], r["vdom"]): r["level"] for r in detail["profiles"]}


def utm_rules(ctx: Any) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    detail = d.get("profile_detail") or {"profiles": [], "policy_utm": {}}
    levels = _levels(detail)

    def ssl_level(vdom: str, name: str) -> str:
        return levels.get(("ssl_ssh", name, vdom)) or levels.get(("ssl_ssh", name, "global")) or BUILTIN_SSL.get(name) or ("off" if not name else "certificate")

    out: list[dict[str, Any]] = []
    # 1. payload scanners behind an SSL profile that does not decrypt, on traffic leaving for the internet
    exposed: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    for policy in d["policies"]:
        if policy["status"] != "enable" or policy["action"] != "accept":
            continue
        attached = detail["policy_utm"].get((policy["vdom"], policy["id"]), {})
        scanners = [kind for kind in PAYLOAD_KINDS if attached.get(kind)] + [k for k in attached.get("_other", []) if k in ("file-filter-profile", "dlp-profile", "dlp-sensor", "emailfilter-profile")]
        if not scanners or policy["learning"]:
            continue
        outbound = any(res.is_wan(n) for n in policy["dstintf"]) and not any(res.is_wan(n) for n in policy["srcintf"])
        if outbound and ssl_level(policy["vdom"], attached.get("ssl_ssh", "")) != "deep":
            exposed[policy["vdom"]].append((policy["id"], bool(policy["users"] or policy["groups"])))
    for vdom, items in exposed.items():
        ids = ", ".join(f"#{pid}" for pid, _ in items[:12]) + (f" and {len(items) - 12} more" if len(items) > 12 else "")
        out.append(finding("FGT-UTM-001", "medium", "Security profile", "Antivirus / IPS cannot see inside HTTPS: SSL inspection is not 'deep'", obj=f"VDOM {vdom}: {len(items)} outbound polic{'y' if len(items) == 1 else 'ies'}",
                           detail=f"Accept polic{'y' if len(items) == 1 else 'ies'} in VDOM {vdom} ({ids}) send traffic to the internet and attach antivirus, IPS, file filter or DLP, but the SSL/SSH inspection profile "
                                  f"is not deep inspection. With certificate inspection FortiGate only reads the server certificate and SNI, so malware, exploits and data leaving inside TLS pass these scanners unseen.",
                           recommendation="Use a deep-inspection profile (with the inspection CA installed on clients) for user traffic, and keep exemptions for banking, health, pinned or privacy-sensitive categories. Where deep inspection is not wanted, record that decision.",
                           reference=FORTI["ssl_deep"]))
    # 2. profiles that are attached to policies but do not enforce
    for row in detail["profiles"]:
        if not row["used_by"]:
            continue
        where = f"profile {row['name']}" + (f" (VDOM {row['vdom']})" if row["vdom"] != "global" else " (global)")
        if row["key"] == "ips" and row["level"] == "monitor":
            out.append(finding("FGT-UTM-002", "medium", "Security profile", "IPS sensor is attached but only logs", obj=where,
                               detail=f"IPS sensor {row['name']} is used by {row['used_by']} polic{'y' if row['used_by'] == 1 else 'ies'} but every enabled entry has action pass or monitor ({row['detail']}), so attacks are recorded and still delivered.",
                               recommendation="Set action block (or default, which applies each signature's own action) on the entries for critical and high severity.", reference=FORTI["ips"]))
        elif row["key"] == "antivirus" and row["level"] != "block":
            out.append(finding("FGT-UTM-003", "medium", "Security profile", "Antivirus profile does not block", obj=where,
                               detail=f"Antivirus profile {row['name']} is used by {row['used_by']} polic{'y' if row['used_by'] == 1 else 'ies'} and scans in monitor mode or not at all ({row['detail']}).",
                               recommendation="Set av-scan block for http, ftp, smtp, imap and pop3.", reference=FORTI["antivirus"]))
        elif row["key"] == "antivirus" and "HTTP is" in row["notes"]:
            out.append(finding("FGT-UTM-003", "low", "Security profile", "Antivirus profile does not block web downloads", obj=where,
                               detail=f"Antivirus profile {row['name']} blocks some protocols but HTTP is not set to block ({row['detail']}). Web downloads are the most common malware path.",
                               recommendation="Set av-scan block under config http.", reference=FORTI["antivirus"]))
        elif row["key"] == "webfilter" and row["level"] != "block":
            out.append(finding("FGT-UTM-004", "low", "Security profile", "Web filter profile blocks nothing", obj=where,
                               detail=f"Web filter {row['name']} is used by {row['used_by']} polic{'y' if row['used_by'] == 1 else 'ies'} but no FortiGuard category and no URL filter table is set to block ({row['detail']}).",
                               recommendation="Block at least the security-risk categories (malicious websites, phishing, spam URLs) and adult content as policy requires.", reference=FORTI["webfilter"]))
        elif row["key"] == "ssl_ssh" and "allows unsupported SSL/TLS versions" in row["notes"] and row["level"] == "deep":
            out.append(finding("FGT-UTM-005", "low", "Security profile", "SSL inspection lets unsupported SSL/TLS versions through", obj=where,
                               detail=f"Deep-inspection profile {row['name']} (used by {row['used_by']} polic{'y' if row['used_by'] == 1 else 'ies'}) has unsupported-ssl-version allow: sessions FortiGate cannot decrypt are passed uninspected instead of blocked.",
                               recommendation="Set unsupported-ssl-version block where clients and servers support TLS 1.2 or later, or accept the gap knowingly.", reference=FORTI["ssl_deep"]))
    return out
