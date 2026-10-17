"""FortiOS configuration areas that carry security-relevant settings and were not read before this module.

Found by diffing the ``config`` paths of two real FortiGate backups (FortiOS 7.0 FG6H1E multi-VDOM HA, FortiOS 7.2 FG201F
multi-VDOM) against the paths the analyzer reads:

* ``firewall proxy-policy``            explicit/transparent web proxy rules -- a second rule base next to ``firewall policy``
* ``webfilter urlfilter``              static URL lists attached to web-filter profiles
* ``system external-resource``         threat feeds (IP, domain, malware hash) pulled from a URL
* ``system dns-server`` / ``dns-database``   the FortiGate acting as a DNS server for a segment
* ``system virtual-wire-pair`` / ``virtual-switch`` / ``physical-switch``   Layer-2 topology that bypasses routing
* ``firewall profile-protocol-options``   which ports each protocol is inspected on

Everything is read from the :mod:`forti_tree` tree, so secrets are already hidden.  References: FortiOS Administration Guide,
https://docs.fortinet.com/document/fortigate/7.2.5/administration-guide/300428/explicit-web-proxy
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core.findings import finding
from ..analyzer_core.result import table_section
from .forti_resolve import Resolver

# Every page below was returned by a docs.fortinet.com search on 2026-10-17 (the search returns the page's own URL; they were not all opened).
REF = {
    "proxy": "https://docs.fortinet.com/document/fortigate/7.2.5/administration-guide/300428/explicit-web-proxy",
    "urlfilter": "https://docs.fortinet.com/document/fortigate/7.2.10/administration-guide/371670/static-url-filter",
    "external": "https://docs.fortinet.com/document/fortigate/7.2.5/administration-guide/379433/configuring-a-threat-feed",
    "dns": "https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/960561/fortigate-dns-server",
    "vwp": "https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/166804/virtual-wire-pair",
    "protocol": "https://docs.fortinet.com/document/fortigate/7.2.4/administration-guide/5347/protocol-options",
}
_ANY = {"all", "any", "ALL", "ANY"}


def _scope_rows(tree: Any, path: str) -> list[tuple[str, FNode]]:
    return tree.entries(path)


def _join(values: list[str], limit: int = 6) -> str:
    shown = ", ".join(values[:limit])
    return shown + (f" +{len(values) - limit} more" if len(values) > limit else "")


def _proxy_rows(tree: Any) -> list[dict[str, Any]]:
    rows = []
    for scope, entry in _scope_rows(tree, "firewall proxy-policy"):
        disabled = entry.get("status") == "disable"
        rows.append({"vdom": scope, "id": entry.name, "name": entry.get("name"), "proxy": entry.get("proxy"), "src": entry.values("srcaddr") or entry.values("srcintf"), "dst": entry.values("dstaddr"),
                     "service": entry.values("service"), "action": entry.get("action", "deny"), "utm": "on" if entry.get("utm-status") == "enable" else "off", "ssl": entry.get("ssl-ssh-profile"),
                     "log": entry.get("logtraffic") or "(default)", "status": "disabled" if disabled else "enabled", "_tone": "mute" if disabled else ""})
    return rows


def sections(tree: Any, data: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    multi = bool(data.get("multi_vdom"))

    def cols(*spec: Any) -> list[Any]:
        return list(spec) if multi else [c for c in spec if c[0] != "vdom"]

    proxy = _proxy_rows(tree)
    if proxy:
        out.append(table_section("proxy_policies", "Proxy policies", cols(("vdom", "VDOM"), ("id", "ID", "mono"), ("name", "Name"), ("proxy", "Proxy"), ("src", "Source", "list"), ("dst", "Destination", "list"), ("service", "Service", "list"), ("action", "Action", "status"),
                                                                          ("utm", "UTM"), ("ssl", "SSL inspection"), ("log", "Log"), ("status", "State")), proxy, group="Policies",
                                 hint="Explicit and transparent web-proxy rules (config firewall proxy-policy). They are evaluated for proxy traffic before or beside the ordinary firewall policy, so a review of 'firewall policy' alone misses them."))
    lists = []
    for scope, entry in _scope_rows(tree, "webfilter urlfilter"):
        items = [item for cfg in entry.configs("entries") for item in cfg.entries()]
        actions: dict[str, int] = {}
        for item in items:
            actions[item.get("action", "exempt")] = actions.get(item.get("action", "exempt"), 0) + 1
        types: dict[str, int] = {}
        for item in items:
            types[item.get("type", "simple")] = types.get(item.get("type", "simple"), 0) + 1
        lists.append({"vdom": scope, "id": entry.name, "name": entry.get("name"), "entries": len(items), "actions": ", ".join(f"{n} {a}" for a, n in sorted(actions.items())), "types": ", ".join(f"{n} {t}" for t, n in sorted(types.items())),
                      "ips": sum(1 for item in items if re.match(r"^\d+\.\d+\.\d+\.\d+$", item.get("url"))), "comment": entry.get("comment")})
    if lists:
        out.append(table_section("urlfilters", "Web filter URL lists", cols(("vdom", "VDOM"), ("id", "ID", "mono"), ("name", "Name"), ("entries", "Entries", "num"), ("actions", "Actions"), ("types", "Entry types"), ("ips", "IP entries", "num"), ("comment", "Comment")), lists, group="Objects"))
    feeds = []
    for scope, entry in _scope_rows(tree, "system external-resource"):
        feeds.append({"vdom": scope, "name": entry.name, "type": entry.get("type"), "resource": entry.get("resource"), "refresh": entry.get("refresh-rate") or "(default 5 min)", "status": entry.get("status") or "enable",
                      "scheme": (entry.get("resource").split(":", 1)[0] if ":" in entry.get("resource") else ""), "_tones": {"scheme": "bad" if entry.get("resource").lower().startswith("http:") else ""}})
    if feeds:
        out.append(table_section("external_resources", "External threat feeds", cols(("vdom", "VDOM"), ("name", "Name"), ("type", "Type"), ("resource", "Resource", "mono"), ("scheme", "Transport"), ("refresh", "Refresh (min)"), ("status", "Status")), feeds, group="Objects",
                                 hint="Lists the FortiGate downloads and enforces (IP, domain, malware hash). A feed fetched over plain http can be altered on the path."))
    dns_rows = []
    for scope, entry in _scope_rows(tree, "system dns-server"):
        dns_rows.append({"vdom": scope, "kind": "DNS server", "name": entry.name, "detail": f"mode {entry.get('mode') or 'recursive (default)'}" + (f" · DNS filter {entry.get('dnsfilter-profile')}" if entry.get("dnsfilter-profile") else "")})
    for scope, entry in _scope_rows(tree, "system dns-database"):
        dns_rows.append({"vdom": scope, "kind": "DNS zone", "name": entry.name, "detail": f"{entry.get('domain')} · {entry.get('type') or 'primary'} · view {entry.get('view') or 'shadow'} · "
                         + ("authoritative" if entry.get("authoritative") != "disable" else "non-authoritative") + (f" · forwarders {', '.join(entry.values('forwarder'))}" if entry.values("forwarder") else "")})
    if dns_rows:
        out.append(table_section("dns_service", "DNS service on the FortiGate", cols(("vdom", "VDOM"), ("kind", "Kind"), ("name", "Interface / zone"), ("detail", "Detail", "wrap")), dns_rows, group="System",
                                 hint="'config system dns-server' makes an interface answer DNS queries; 'dns-database' defines the zones it serves."))
    l2 = []
    for scope, entry in _scope_rows(tree, "system virtual-wire-pair"):
        l2.append({"vdom": scope, "kind": "virtual wire pair", "name": entry.name, "detail": " ↔ ".join(entry.values("member")) + (" · VLAN filter " + entry.get("vlan-filter") if entry.get("vlan-filter") else "") + (" · wildcard VLAN" if entry.enabled("wildcard-vlan", False) else "")})
    for scope, entry in _scope_rows(tree, "system virtual-switch"):
        ports = [p.name for cfg in entry.configs("port") for p in cfg.entries()]
        l2.append({"vdom": scope, "kind": "virtual switch", "name": entry.name, "detail": f"{len(ports)} port(s): {_join(ports, 10)}" + (f" · VLAN {entry.get('vlan')}" if entry.get("vlan") else "") + (f" · {entry.get('physical-switch')}" if entry.get("physical-switch") else "")})
    for scope, entry in _scope_rows(tree, "system physical-switch"):
        l2.append({"vdom": scope, "kind": "physical switch", "name": entry.name, "detail": entry.get("age-enable") and f"MAC ageing {entry.get('age-val') or 'default'}" or ""})
    if l2:
        out.append(table_section("l2_topology", "Layer-2 topology (virtual wire, virtual / physical switch)", cols(("vdom", "VDOM"), ("kind", "Kind"), ("name", "Name", "mono"), ("detail", "Detail", "wrap")), l2, group="Interfaces",
                                 hint="Traffic between members of a virtual wire pair or virtual switch is switched, not routed: policy applies, but routing and NAT decisions on those paths are not visible in the routing table."))
    protos = []
    for scope, entry in _scope_rows(tree, "firewall profile-protocol-options"):
        bits = []
        for cfg in entry.children:
            if cfg.kind == "config" and (cfg.get("ports") or cfg.get("options")):
                bits.append(f"{cfg.name} {','.join(cfg.values('ports')) or '-'}" + (f" ({','.join(cfg.values('options'))})" if cfg.values("options") else ""))
        protos.append({"vdom": scope, "name": entry.name, "protocols": "; ".join(bits), "oversize": ", ".join(f"{cfg.name}:{cfg.get('oversize-limit')}MB" for cfg in entry.children if cfg.kind == "config" and cfg.get("oversize-limit")), "comment": entry.get("comment")})
    if protos:
        out.append(table_section("protocol_options", "Protocol options profiles", cols(("vdom", "VDOM"), ("name", "Name"), ("protocols", "Inspected protocols and ports", "wrap"), ("oversize", "Oversize limits"), ("comment", "Comment")), protos, group="Objects", page_size=50))
    return out


def evaluate(tree: Any, data: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    res = Resolver(data)
    multi = bool(data.get("multi_vdom"))
    for scope, entry in _scope_rows(tree, "firewall proxy-policy"):
        if entry.get("status") == "disable":
            continue
        label = f"proxy policy {entry.name}" + (f" '{entry.get('name')}'" if entry.get("name") else "") + (f" (VDOM {scope})" if multi else "")
        src, dst, svc = entry.values("srcaddr"), entry.values("dstaddr"), entry.values("service")
        accept = entry.get("action", "deny") == "accept"
        any_src, any_dst = bool(set(src) & _ANY), bool(set(dst) & _ANY)
        utm_off = entry.get("utm-status") != "enable"
        if accept and not dst and not svc:
            out.append(finding("FGT-PXY-004", "low", "Proxy policy", "Proxy policy has no destination and no service", obj=label, detail="An accept rule with empty destination/service fields cannot match the traffic it was written for; it is either unfinished or was emptied when an object was deleted.",
                               recommendation="Complete or delete the rule.", reference=REF["proxy"]))
            continue
        if accept and any_src and any_dst:
            out.append(finding("FGT-PXY-001", "high", "Proxy policy", "Proxy policy accepts any source to any destination", obj=label, detail=f"srcaddr all, dstaddr all, service {', '.join(svc) or 'n/a'}" + (", no UTM" if utm_off else "") +
                               ". Every client that can reach the explicit-proxy port can browse anywhere through the FortiGate.", recommendation="Restrict the source to the client networks and the destination to the categories/addresses that are intended; require authentication.", reference=REF["proxy"]))
        elif accept and any_dst and utm_off:
            out.append(finding("FGT-PXY-002", "medium", "Proxy policy", "Proxy policy allows any destination without security profiles", obj=label, detail=f"Sources: {_join(src)}. dstaddr all with utm-status disabled: no antivirus, IPS, web-filter or SSL inspection is applied to this web traffic.",
                               recommendation="Attach a security profile group or restrict the destination.", reference=REF["proxy"]))
        elif accept and any_src and not any_dst:
            out.append(finding("FGT-PXY-003", "low", "Proxy policy", "Proxy policy accepts any source", obj=label, detail=f"Destination limited to {_join(dst, 4)} but srcaddr is all; whoever reaches the proxy port can use it for those destinations.", recommendation="Limit the source to the intended client networks.", reference=REF["proxy"]))
        if accept and entry.get("logtraffic") == "disable":
            out.append(finding("FGT-PXY-005", "low", "Proxy policy", "Proxy policy does not log traffic", obj=label, detail="logtraffic disable: allowed web sessions leave no record.", recommendation="Set logtraffic utm or all.", reference=REF["proxy"]))
    for scope, entry in _scope_rows(tree, "webfilter urlfilter"):
        for cfg in entry.configs("entries"):
            for item in cfg.entries():
                url, action = item.get("url"), item.get("action", "exempt")
                if action != "block" and (url in ("*", "*.*", ".*") or (item.get("type") == "regex" and url in (".*", ".+"))):
                    out.append(finding("FGT-URL-001", "high", "Web filter", f"URL list '{entry.get('name') or entry.name}' contains a catch-all {action} entry", obj=f"urlfilter {entry.name} entry {item.name}" + (f" (VDOM {scope})" if multi else ""),
                                       detail=f"url '{url}' with action {action} matches every site, so everything after it in the list (and in 'exempt' cases the rest of the web-filter profile) is bypassed.", recommendation="Remove the entry or replace it with the specific domains that must be allowed.", reference=REF["urlfilter"]))
    for scope, entry in _scope_rows(tree, "system external-resource"):
        resource = entry.get("resource")
        if resource.lower().startswith("http:") and entry.get("status") != "disable":
            out.append(finding("FGT-EXT-001", "medium", "Threat feed", f"Threat feed '{entry.name}' is downloaded over plain HTTP", obj=f"external-resource {entry.name}", detail=f"{resource}. An attacker on the path can change the list (empty it, or add the firewall's own management addresses to a block list).",
                               recommendation="Serve the feed over HTTPS and install the CA that signs it on the FortiGate.", reference=REF["external"]))
    for scope, entry in _scope_rows(tree, "system dns-server"):
        mode = entry.get("mode") or "recursive"
        if mode == "recursive" and res.is_wan(entry.name):
            out.append(finding("FGT-DNS-001", "medium", "DNS service", f"Recursive DNS server enabled on internet-facing interface {entry.name}", obj=f"dns-server {entry.name}", detail="Mode recursive on an interface that faces the internet can make the FortiGate an open resolver (abused for DNS amplification) unless a local-in policy blocks DNS from outside.",
                               recommendation="Use forward-only/non-recursive mode, bind the service to internal interfaces, or deny DNS in the local-in policy for that interface.", reference=REF["dns"]))
    for scope, entry in _scope_rows(tree, "system virtual-wire-pair"):
        if entry.enabled("wildcard-vlan", False):
            out.append(finding("FGT-VWP-001", "low", "Layer 2", f"Virtual wire pair {entry.name} passes every VLAN", obj=f"virtual-wire-pair {entry.name}", detail="wildcard-vlan enable: all VLAN tags cross the pair, so policy decisions cannot distinguish them by VLAN.", recommendation="List the VLANs that should cross (vlan-filter).", reference=REF["vwp"]))
    return out
