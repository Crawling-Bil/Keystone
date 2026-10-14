"""F5 documentation cited by the Load Balancer Analyzer findings.

Every link below was opened on 2026-10-09 and the page title and the default
values quoted in the rule text were read from the page.  The one exception is
noted explicitly: my.f5.com knowledge-base articles render with JavaScript and
could not be read from this session, so none of them is cited.

``DEFAULTS`` records the documented default for every setting that a TMSH
listing omits when it equals the default (``tmsh list`` prints only the values
that differ), so a rule can say "default" instead of guessing.
"""

from __future__ import annotations

TMSH = "https://clouddocs.f5.com/cli/tmsh-reference/v16/modules/"

F5 = {
    # LTM objects (TMSH reference v16)
    "virtual": TMSH + "ltm/ltm_virtual.html",
    "virtual_address": TMSH + "ltm/ltm_virtual-address.html",
    "pool": TMSH + "ltm/ltm_pool.html",
    "node": TMSH + "ltm/ltm_node.html",
    "monitor_http": TMSH + "ltm/ltm_monitor_http.html",
    "client_ssl": TMSH + "ltm/ltm_profile_client-ssl.html",
    "server_ssl": TMSH + "ltm/ltm_profile_server-ssl.html",
    "http_profile": TMSH + "ltm/ltm_profile_http.html",
    "persist_cookie": TMSH + "ltm/ltm_persistence_cookie.html",
    "snat": TMSH + "ltm/ltm_snat.html",
    "snatpool": TMSH + "ltm/ltm_snatpool.html",
    "rule": TMSH + "ltm/ltm_rule.html",
    # system / network / cluster
    "httpd": TMSH + "sys/sys_httpd.html",
    "sshd": TMSH + "sys/sys_sshd.html",
    "snmp": TMSH + "sys/sys_snmp.html",
    "ntp": TMSH + "sys/sys_ntp.html",
    "syslog": TMSH + "sys/sys_syslog.html",
    "global_settings": TMSH + "sys/sys_global-settings.html",
    "ssl_cert": TMSH + "sys/sys_file_ssl-cert.html",
    "net_self": TMSH + "net/net_self.html",
    "net_self_allow": "https://clouddocs.f5.com/cli/tmsh-reference/v14/modules/net/net_self-allow.html",
    "net_trunk": TMSH + "net/net_trunk.html",
    "auth_ldap": TMSH + "auth/auth_ldap.html",
    "auth_user": TMSH + "auth/auth_user.html",
    "auth_source": TMSH + "auth/auth_source.html",
    "auth_tacacs": TMSH + "auth/auth_tacacs.html",
    "password_policy": TMSH + "auth/auth_password-policy.html",
    "device_group": TMSH + "cm/cm_device-group.html",
    "device": TMSH + "cm/cm_device.html",
    # concepts and guidance
    "monitors_concepts": "https://techdocs.f5.com/en-us/bigip-16-0-0/big-ip-local-traffic-manager-monitors-reference/monitors-concepts.html",
    "monitors_tasks": "https://techdocs.f5.com/en-us/bigip-16-0-0/big-ip-local-traffic-manager-monitors-reference/monitors-tasks.html",
    "monitoring_11_5": "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-concepts-11-5-1/15.html",
    "nodes_11_5": "https://techdocs.f5.com/kb/en-us/products/big-ip_ltm/manuals/product/ltm-concepts-11-5-1/5.html",
    "selfip_lockdown": "https://techdocs.f5.com/en-us/bigip-14-0-0/big-ip-access-policy-manager-secure-web-gateway-14-0-0/common-elements-for-self-ip-tasks.html",
    "dsc_failover": "https://techdocs.f5.com/en-us/bigip-14-1-0/big-ip-device-service-clustering-administration-14-1-0/managing-failover.html",
    "deploying_tls": "https://community.f5.com/kb/technicalarticles/deploying-tls-securely/278307",
    "nist_800_52": "https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    "pci_8_2_8": "https://www.pcisecuritystandards.org/faq/articles/Frequently_Asked_Question/what-is-the-purpose-of-pci-dss-requirement-8-2-8-which-requires-users-to-reauthenticate-after-15-minutes-of-idle-time",
}

# Documented defaults (TMSH reference v16, pages above).  A TMSH listing leaves these out when unchanged.
DEFAULTS = {
    "pool.load-balancing-mode": "round-robin",
    "pool.monitor": "none",
    "pool.min-active-members": 0,
    "pool.slow-ramp-time": 10,
    "pool.service-down-action": "none",
    "virtual.connection-limit": 0,
    "virtual.persist": "none",
    "virtual.source-address-translation": "none (no default is printed; the deprecated 'snat' option defaults to none)",
    "virtual.vlans": "all VLANs (vlans-disabled with an empty list)",
    "virtual.translate-address": "disabled in the TMSH reference",
    "monitor.interval": 5,
    "monitor.timeout": 16,
    "monitor.http.send": "GET /",
    "monitor.http.recv": "none",
    "client-ssl.ciphers": "DEFAULT",
    "client-ssl.secure-renegotiation": "require",
    "server-ssl.ciphers": "DEFAULT",
    "server-ssl.peer-cert-mode": "ignore",
    "server-ssl.secure-renegotiation": "require-strict",
    "http.insert-xforwarded-for": "disabled",
    "http.encrypt-cookies": "none",
    "http.server-agent-name": "BigIP",
    "persist-cookie.httponly": "enabled",
    "persist-cookie.secure": "enabled",
    "httpd.allow": "all",
    "sshd.allow": "all",
    "sshd.inactivity-timeout": 0,
    "snmp.communities": "public (read-only, any source)",
    "snmp.allowed-addresses": "127.0.0.0/8",
    "ntp.servers": "none",
    "syslog.remote-servers": "none",
    "global.console-inactivity-timeout": 0,
    "global.gui-setup": "enabled",
    "password-policy.policy-enforcement": "disabled",
    "password-policy.minimum-length": 6,
    "ldap.ssl": "disabled",
    "device-group.auto-sync": "disabled",
    "device-group.type": "sync-only",
    "trunk.lacp": "disabled",
    "self.allow-service": "none",
}


def f5(key: str) -> str:
    return F5[key]
