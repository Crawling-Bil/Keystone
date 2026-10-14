"""Load Balancer Analyzer (F5 BIG-IP / TMOS).

Pipeline (``service.analyze``): detect -> read -> parse -> extract -> enrich -> rules -> sections -> overview.

Input
    ``routes``            Flask blueprint; accepts .ucs, bigip.conf / bigip_base.conf, ``tmsh list`` output or a terminal capture.
    ``bigip_ucs``         upload hook: turns a .ucs into configuration text plus the parsed archive.
    ``ucs_reader``        streams the archive by whitelist (no extraction to disk, no private keys).
    ``ucs_files``         small-file parsers: license, sys db, accounts, hosts.allow / deny, role map, packages.
    ``ucs_x509``          stdlib certificate reader.
    ``ucs_history``       /config/.diffVersions patches -> change history.
    ``bigip_runtime``     splits a terminal capture into configuration text and 'show' output.
Model
    ``tmsh_tree``         TMSH stanza parser (secrets hidden while parsing).
    ``bigip_extract``     LTM / net / sys / auth / cm -> dictionaries.
    ``bigip_security``    ASM, DoS, logging, AFM, APM, iApps, tunnels, global settings, inventory.
    ``bigip_enrich``      second pass: security modules, certificate details, UCS facts and history.
    ``bigip_resolve``     name resolution (profiles, pools, monitors) shared by rules and tabs.
Findings
    ``bigip_rules``       runs every rule module and applies the per-rule cap.
    ``bigip_rules_ltm`` / ``_ssl`` / ``_mgmt`` / ``_ha`` / ``_security`` / ``_ucs``;  ``bigip_context`` holds the shared context.
    ``refs``              F5 documentation links and documented defaults.
Presentation
    ``bigip_sections``    tab builder (LTM, network, system, hardening) + ``_security``, ``_ucs``, ``_live``.
    ``bigip_overview``    cards, device information, coverage table, notes.
"""
