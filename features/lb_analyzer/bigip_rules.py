"""Findings for a BIG-IP configuration.

Rules live in one module per area (``bigip_rules_ltm``, ``_ssl``, ``_mgmt``, ``_ha``, ``_security``, ``_ucs``); this
module only runs them and applies the per-rule cap.

The rules read the dictionaries from :mod:`bigip_extract`, resolve names through
:class:`bigip_resolve.Resolver` and cite F5 documentation through :mod:`refs`.

``tmsh list`` and ``bigip.conf`` omit every value that equals the default, so a
rule that depends on a default says "default" and quotes the documented value
instead of treating a missing line as an unknown.  Rules that need a part of
the configuration that is not in the export (the management plane is in
``bigip_base.conf``) are skipped, and the coverage table says so.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..analyzer_core.findings import cap_per_rule, dedupe_findings, sort_findings
from . import bigip_rules_gtm, bigip_rules_ha, bigip_rules_ltm, bigip_rules_mgmt, bigip_rules_security, bigip_rules_sys, bigip_rules_ssl, bigip_rules_ucs
from .bigip_context import LCtx
from .bigip_resolve import Resolver

MAX_PER_RULE = 25
RULES = (
    bigip_rules_ltm.virtual_rules, bigip_rules_ltm.pool_rules, bigip_rules_ltm.monitor_rules, bigip_rules_ssl.ssl_rules, bigip_rules_ltm.http_rules, bigip_rules_ltm.irule_rules,
    bigip_rules_ltm.reference_rules, bigip_rules_ltm.unused_rules, bigip_rules_mgmt.management_rules, bigip_rules_ssl.certificate_rules, bigip_rules_ha.ha_rules,
    bigip_rules_mgmt.network_rules, bigip_rules_ha.runtime_rules, bigip_rules_security.security_rules, bigip_rules_ucs.ucs_rules, bigip_rules_gtm.gtm_rules, bigip_rules_gtm.dns_rules, bigip_rules_gtm.gtm_runtime_rules, bigip_rules_sys.sys_runtime_rules,
)


def evaluate(tree: Any, data: dict[str, Any], today: date | None = None, runtime: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ctx = LCtx(tree=tree, data=data, res=Resolver(data), today=today or date.today(), runtime=runtime or {})
    out: list[dict[str, Any]] = []
    for rule in RULES:
        out.extend(rule(ctx))
    return sort_findings(_overflow(dedupe_findings(out)))


def _overflow(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return cap_per_rule(items, MAX_PER_RULE)
