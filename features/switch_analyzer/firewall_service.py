"""Moved to ``features.firewall_analyzer.firewall_service``.

This file used to hold the Mikrotik/Palo Alto parsing-and-dashboard logic
directly; as part of consolidating all firewall-vendor code under
``firewall_analyzer`` (so Switch Analyzer only has to carry switch-specific
code, and every firewall vendor -- FortiGate, Mikrotik, Palo Alto -- lives in
one place), the real implementation now lives at
``features/firewall_analyzer/firewall_service.py``. This stub only exists so
nothing importing the old path breaks; it can be deleted once nothing
references it (this codebase no longer does -- see
``features/switch_analyzer/routes.py`` and ``features/firewall_analyzer/legacy.py``).
"""

from __future__ import annotations

from ..firewall_analyzer.firewall_service import analyze_firewall

__all__ = ["analyze_firewall"]
