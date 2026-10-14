"""Shared context for the BIG-IP rule modules (``bigip_rules_*``): the object they receive and small helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_resolve import Resolver


@dataclass
class LCtx:
    tree: Any
    data: dict[str, Any]
    res: Resolver
    today: date
    runtime: dict[str, Any]

    @property
    def sysd(self) -> dict[str, Any]:
        return self.data["sys"]

    @property
    def has_base(self) -> bool:
        return bool(self.sysd["has_base"])


def vs_in_use(ctx: LCtx) -> bool:
    return bool(ctx.data["virtuals"])


def listing(names: Iterable[str], limit: int = 6) -> str:
    items = sorted(set(names))
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def aggregate(out: list[dict[str, Any]], rule_id: str, severity: str, category: str, title: str, names: list[str], detail: str, recommendation: str, reference: str) -> None:
    """One finding for a pattern that is normal on many virtual servers (shown once with the names, not 40 times)."""
    if not names:
        return
    out.append(finding(rule_id, severity, category, f"{title} ({len(names)})", obj=listing(names, 4), detail=f"{detail} Affected: {listing(names, 12)}.", recommendation=recommendation, reference=reference))
