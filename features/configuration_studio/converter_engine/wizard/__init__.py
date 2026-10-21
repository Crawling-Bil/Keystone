"""Guided, step-by-step conversion (Convert Firewall wizard).

``pan_validator`` reads generated PAN-OS "set" commands back and checks
that every reference resolves; ``firewall_wizard`` runs the translator
with the user's mapping, combines those checks with source-side mapping
checks, and gates each wizard step on the result.
"""
