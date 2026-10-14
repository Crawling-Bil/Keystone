"""Cross-reference of policy objects: who uses which ACL / route-map / ...

Two questions an engineer asks before touching a router config:

* "Is this object still used?"   -> reference scan over the *whole* config
* "Does anything point at an object that does not exist?" -> structured
  references taken from the places a missing object actually matters
  (interface ACLs, BGP neighbor policy, redistribution, PBR, ...).

The reference scan is deliberately generous: a name counts as used when it
appears as a token on any configuration line that is not the definition of
that same kind of object.  Numbered objects (``access-list 10``) only count
when the number follows a keyword that takes an ACL / list number, because a
bare ``10`` appears in countless unrelated places.  The effect is that
"unused" is reported only when nothing in the capture refers to the object,
which keeps false positives low; it cannot see references that live outside
the router (an AAA server downloading an ACL name, for example), so the
finding wording says "no reference found in this configuration".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .config_tree import ConfigTree, Node

KINDS = ("acl", "route-map", "prefix-list", "as-path", "community-list", "class-map", "policy-map")
# keywords that may directly precede a *number* naming an ACL / list
_NUMBER_KEYWORDS = {
    "access-group", "access-class", "list", "address", "ro", "rw", "peer", "serve", "serve-only", "query-only",
    "filter-list", "distribute-list", "acl", "as-path", "community", "match-address", "group",
}
_IGNORE_NAMES = {"class-default", "any", "default", "in", "out", "permit", "deny"}


def _definition(text: str) -> tuple[str, str] | None:
    parts = text.split()
    if len(parts) < 2:
        return None
    head = parts[0]
    if head == "access-list" and len(parts) >= 2:
        return "acl", parts[1]
    if head == "ip" and len(parts) >= 3 and parts[1] == "access-list":
        if parts[2] in ("standard", "extended", "resequence") and len(parts) >= 4:
            return "acl", parts[3]
        return "acl", parts[2]
    if head == "ipv6" and len(parts) >= 3 and parts[1] == "access-list":
        return "acl", parts[2]
    if head == "route-map":
        return "route-map", parts[1]
    if head in ("ip", "ipv6") and len(parts) >= 3 and parts[1] == "prefix-list" and parts[2] not in ("sequence-number", "sequence"):
        return "prefix-list", parts[2]
    if head == "ip" and len(parts) >= 4 and parts[1] == "as-path" and parts[2] == "access-list":
        return "as-path", parts[3]
    if head == "ip" and len(parts) >= 3 and parts[1] == "community-list":
        if parts[2] in ("standard", "expanded") and len(parts) >= 4:
            return "community-list", parts[3]
        return "community-list", parts[2]
    if head == "class-map":
        return "class-map", parts[-1]
    if head == "policy-map":
        return "policy-map", parts[-1]
    return None


def _context(top: Node) -> str:
    words = top.text.split()
    if words[0] in ("interface", "router", "line", "class-map", "policy-map", "route-map", "crypto", "control-plane", "ip", "snmp-server", "ntp", "zone-pair"):
        return " ".join(words[:3]) if words[0] != "interface" else " ".join(words[:2])
    return " ".join(words[:3])


def _walk(top: Node):
    yield top, top
    for node in top.walk():
        yield top, node


def build_xref(cfg: dict[str, Any], tree: ConfigTree) -> dict[str, Any]:
    defined: dict[str, set[str]] = {kind: set() for kind in KINDS}
    for acl in cfg.get("acls", []):
        defined["acl"].add(str(acl["name"]))
    for route_map in cfg.get("route_maps", []):
        defined["route-map"].add(route_map["name"])
    for entry in cfg.get("prefix_lists", []):
        defined["prefix-list"].add(entry["name"])
    for entry in cfg.get("as_path_lists", []):
        defined["as-path"].add(str(entry["name"]))
    for entry in cfg.get("community_lists", []):
        defined["community-list"].add(str(entry["name"]))
    for entry in cfg.get("class_maps", []):
        defined["class-map"].add(entry["name"])
    for entry in cfg.get("policy_maps", []):
        defined["policy-map"].add(entry["name"])

    name_to_kinds: dict[str, list[str]] = defaultdict(list)
    for kind, names in defined.items():
        for name in names:
            name_to_kinds[name].append(kind)

    usage: dict[tuple[str, str], list[str]] = defaultdict(list)
    for top in tree.root.children:
        context = _context(top)
        for _, node in _walk(top):
            tokens = node.text.split()
            if not tokens:
                continue
            definition = _definition(node.text) if node is top else None
            for position, token in enumerate(tokens):
                kinds = name_to_kinds.get(token)
                if not kinds:
                    continue
                for kind in kinds:
                    if definition == (kind, token):
                        continue
                    if token.isdigit():
                        before = tokens[position - 1].lower() if position else ""
                        if before not in _NUMBER_KEYWORDS:
                            continue
                    where = context if node is top else f"{context} › {node.text[:60]}"
                    if where not in usage[(kind, token)]:
                        usage[(kind, token)].append(where)

    refs: list[dict[str, str]] = []

    def add(kind: str, name: str, where: str, effect: str = "") -> None:
        name = (name or "").strip()
        if not name or name in _IGNORE_NAMES:
            return
        refs.append({"kind": kind, "name": name, "where": where, "effect": effect, "near": ""})

    for iface in cfg.get("interfaces", []):
        where = f"interface {iface['name']}"
        add("acl", iface.get("acl_in"), where + " · ip access-group in", "interface ACL")
        add("acl", iface.get("acl_out"), where + " · ip access-group out", "interface ACL")
        add("policy-map", iface.get("policy_in"), where + " · service-policy input", "QoS")
        add("policy-map", iface.get("policy_out"), where + " · service-policy output", "QoS")
        add("route-map", iface.get("pbr_route_map"), where + " · ip policy route-map", "PBR")

    for process in cfg.get("bgp", []):
        for neighbor in process.get("neighbors", []):
            if neighbor.get("is_peer_group"):
                where = f"bgp {process['asn']} peer-group {neighbor['neighbor']}"
            else:
                where = f"bgp {process['asn']} neighbor {neighbor['neighbor']}"
            add("route-map", neighbor.get("route_map_in"), where + " · route-map in", "BGP policy")
            add("route-map", neighbor.get("route_map_out"), where + " · route-map out", "BGP policy")
            add("prefix-list", neighbor.get("prefix_list_in"), where + " · prefix-list in", "BGP policy")
            add("prefix-list", neighbor.get("prefix_list_out"), where + " · prefix-list out", "BGP policy")
            add("as-path", neighbor.get("filter_list_in"), where + " · filter-list in", "BGP policy")
            add("as-path", neighbor.get("filter_list_out"), where + " · filter-list out", "BGP policy")
            for key, direction in (("distribute_list_in", "in"), ("distribute_list_out", "out")):
                value = neighbor.get(key) or ""
                if value.startswith("prefix "):
                    add("prefix-list", value.split()[1] if len(value.split()) > 1 else "", where + f" · distribute-list {direction}", "BGP policy")
                elif value:
                    add("acl", value.split()[0], where + f" · distribute-list {direction}", "BGP policy")
        for redistribute in process.get("redistribute", []):
            words = redistribute.split()
            if "route-map" in words and words.index("route-map") + 1 < len(words):
                add("route-map", words[words.index("route-map") + 1], f"bgp {process['asn']} · redistribute {words[0]}", "redistribution")
    for process in cfg.get("ospf", []):
        for redistribute in process.get("redistribute", []):
            words = redistribute.split()
            if "route-map" in words and words.index("route-map") + 1 < len(words):
                add("route-map", words[words.index("route-map") + 1], f"ospf {process['process']} · redistribute {words[0]}", "redistribution")
    for process in cfg.get("eigrp", []):
        for redistribute in process.get("redistribute", []):
            words = redistribute.split()
            if "route-map" in words and words.index("route-map") + 1 < len(words):
                add("route-map", words[words.index("route-map") + 1], f"eigrp {process['process']} · redistribute {words[0]}", "redistribution")

    nat_cfg = cfg.get("nat") or {}
    for rule in nat_cfg.get("dynamic", []):
        add("acl" if rule["match"] == "list" else "route-map", rule["acl"], f"ip nat {rule['direction']} {rule['kind']} · {rule['match']}", "NAT")
    for static in nat_cfg.get("static", []):
        for flag in static.get("flags", []):
            if flag.startswith("route-map "):
                add("route-map", flag.split()[1], "ip nat static · route-map", "NAT")
    for cmap in (cfg.get("crypto") or {}).get("crypto_maps", []):
        for entry in cmap["entries"]:
            add("acl", entry.get("acl"), f"crypto map {cmap['name']} {entry['seq']} · match address", "crypto ACL")

    for entry in cfg.get("route_maps", []):
        where = f"route-map {entry['name']} {entry['action']} {entry['seq']}"
        for match in entry.get("match", []):
            words = match.split()
            if match.startswith("ip address prefix-list") or match.startswith("ip next-hop prefix-list") or match.startswith("ip route-source prefix-list"):
                for name in words[3:]:
                    add("prefix-list", name, where + " · match", "route-map match")
            elif match.startswith("ip address") or match.startswith("ip next-hop") or match.startswith("ip route-source"):
                for name in words[2:]:
                    add("acl", name, where + " · match", "route-map match")
            elif match.startswith("as-path"):
                for name in words[1:]:
                    add("as-path", name, where + " · match", "route-map match")
            elif match.startswith("community"):
                for name in words[1:]:
                    if name not in ("exact-match",):
                        add("community-list", name, where + " · match", "route-map match")

    for entry in cfg.get("class_maps", []):
        for name in entry.get("acl_refs", []):
            add("acl", name, f"class-map {entry['name']}", "classification")
    for entry in cfg.get("policy_maps", []):
        for klass in entry.get("classes", []):
            add("class-map", klass.get("class"), f"policy-map {entry['name']}", "QoS")
    for line in cfg.get("lines", []):
        add("acl", (line.get("access_class") or "").split()[0] if line.get("access_class") else "", f"line {line['line']} · access-class", "management ACL")
    for community in cfg.get("snmp", {}).get("communities", []):
        add("acl", community.get("acl"), f"snmp-server community #{community['index']}", "management ACL")
    for group in cfg.get("snmp", {}).get("groups", []):
        words = (group.get("detail") or "").split()
        if "access" in words and words.index("access") + 1 < len(words):
            add("acl", words[words.index("access") + 1], f"snmp-server group {group['name']}", "management ACL")
    for pair in cfg.get("zbf", {}).get("zone_pairs", []):
        add("policy-map", pair.get("policy"), f"zone-pair {pair['name']}", "firewall")
    for text in cfg.get("ntp", {}).get("access_groups", []):
        words = text.split()
        if words:
            add("acl", words[-1], "ntp access-group", "management ACL")

    undefined = [ref for ref in refs if ref["name"] not in defined[ref["kind"]]]
    for ref in undefined:
        # IOS object names are case-sensitive; a case-only difference is the
        # classic cause of a "missing" ACL that is in fact defined.
        lowered = {name.lower(): name for name in defined[ref["kind"]]}
        ref["near"] = lowered.get(ref["name"].lower(), "")
    # dedupe
    seen = set()
    unique = []
    for ref in undefined:
        key = (ref["kind"], ref["name"], ref["where"])
        if key not in seen:
            seen.add(key)
            unique.append(ref)
    return {"defined": defined, "refs": refs, "undefined": unique, "usage": dict(usage)}


def used_by(xref: dict[str, Any], kind: str, name: str, limit: int = 4) -> list[str]:
    contexts = xref["usage"].get((kind, name), [])
    if len(contexts) <= limit:
        return list(contexts)
    return list(contexts[:limit]) + [f"+{len(contexts) - limit} more"]


def is_used(xref: dict[str, Any], kind: str, name: str) -> bool:
    return bool(xref["usage"].get((kind, name)))
