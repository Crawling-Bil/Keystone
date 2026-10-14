"""Moved to ``features.firewall_analyzer.firewall_excel_exporter``.

Part of consolidating all firewall-vendor code (FortiGate, Mikrotik, Palo
Alto) under ``firewall_analyzer`` -- see
``features/switch_analyzer/firewall_service.py`` for the same move on the
parser side. This stub only exists so nothing importing the old path breaks;
it can be deleted once nothing references it (this codebase no longer does).
"""

from __future__ import annotations

from ...firewall_analyzer.firewall_excel_exporter import FirewallExcelExporter

__all__ = ["FirewallExcelExporter"]
