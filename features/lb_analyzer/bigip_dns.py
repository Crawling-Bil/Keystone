"""BIG-IP DNS services outside GTM: DNS Express zones, name servers and cache (forwarding) resolvers.

Read from the stanzas ``ltm dns zone``, ``ltm dns nameserver`` and the resolver (``net dns-resolver`` in a saved configuration, ``ltm dns cache resolver``
in older listings).  Written from the documented tmsh syntax; the DNS units used for testing carried only one resolver and no zone or name server, so
zones and name servers are not yet checked against a real configuration.

Documentation:
  ltm dns zone         https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_dns_zone.html
  ltm dns nameserver   https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_dns_nameserver.html
  ltm dns cache resolver  https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_dns_cache_resolver.html
"""

from __future__ import annotations

from typing import Any

from .bigip_extract import canon
from .tmsh_tree import TmshTree, TNode

RESOLVER_PREFIXES = (("net", "dns-resolver"), ("ltm", "dns", "cache", "resolver"))


def _named(tree: TmshTree, *prefix: str) -> list[TNode]:
    return [n for n in tree.all_with_prefix(*prefix) if len(n.tokens) == len(prefix) + 1]


def _zones(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": canon(n.tokens[-1]), "express": n.val("dns-express-enabled") or "yes", "server": canon(n.val("dns-express-server")), "notify": n.val("dns-express-notify-action") or "consume",
             "response_policy": n.val("response-policy") or "no", "tsig": n.val("server-tsig-key"), "clients": n.names("transfer-clients")} for n in _named(tree, "ltm", "dns", "zone")]


def _nameservers(tree: TmshTree) -> list[dict[str, Any]]:
    return [{"name": canon(n.tokens[-1]), "address": n.val("address") or "127.0.0.1", "port": n.val("port") or "53", "tsig": n.val("tsig-key")} for n in _named(tree, "ltm", "dns", "nameserver")]


def _resolvers(tree: TmshTree) -> list[dict[str, Any]]:
    out = []
    for prefix in RESOLVER_PREFIXES:
        for n in _named(tree, *prefix):
            zones = n.child("forward-zones")
            forward = {}
            for z in (zones.children if zones is not None else []):
                if z.tokens:
                    servers = [t for item in z.walk() if item.key == "nameservers" for t in item.names()]
                    forward[z.tokens[0]] = servers
            yes = lambda key: (n.val(key) or "yes") != "no"          # noqa: E731
            out.append({"name": canon(n.tokens[-1]), "forward": forward, "route_domain": n.val("route-domain"), "ipv4": yes("use-ipv4"), "ipv6": yes("use-ipv6"), "tcp": yes("use-tcp"), "udp": yes("use-udp"),
                        "default_zones": (n.val("answer-default-zones") or "no") == "yes", "max_queries": n.val("max-concurrent-queries") or "1024"})
    return out


def extract(tree: TmshTree) -> dict[str, Any] | None:
    """``None`` when the capture holds none of these objects."""
    zones, nameservers, resolvers = _zones(tree), _nameservers(tree), _resolvers(tree)
    if not (zones or nameservers or resolvers):
        return None
    return {"zones": zones, "nameservers": nameservers, "resolvers": resolvers}
