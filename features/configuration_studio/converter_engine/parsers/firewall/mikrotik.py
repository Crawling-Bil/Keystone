import re
from functools import partial
from pathlib import Path

from features.configuration_studio.converter_engine.models.firewall import (
    FirewallConfig,
    Interface,
    InterfaceListMember,
    StaticRoute,
    AddressListEntry,
    FirewallFilterRule,
    NatRule,
    IpsecProposal,
    IpsecProfile,
    IpsecPeer,
    IpsecPolicy,
    DhcpPool,
    DhcpServerBinding,
    DhcpServerNetwork,
    DhcpClientBinding,
    DnsStaticEntry,
    MssClamp,
    ManagementService,
    PolicyRouteRule,
    MangleRule,
    RawRule,
    QueueType,
    QueueSimple,
    QueueTree,
    PppProfile,
    PppSecret,
    IpsecIdentity,
    SnmpCommunity,
    LocalUser,
    SchedulerEntry,
    NetwatchEntry,
    OspfInstance,
    OspfNetwork,
    BgpPeer,
    LoggingRule,
    VpnServer,
)

# RouterOS sections that name a real feature with NO equivalent
# concept on a Palo Alto firewall at all (wireless AP, PPTP/L2TP
# dial-in server, a web/SOCKS proxy service, etc.) -- rather than
# guessing a forced mapping, every statement under one of these is
# preserved verbatim in config.review_commands together with a short,
# concrete explanation of why there's no direct translation and what
# the real PAN-OS alternative concept is, so the reviewer isn't left
# to guess from a bare unparsed line alone.
# Real credential material (a PSK, a RADIUS/VPN secret, ...) shows up
# verbatim in some RouterOS export lines this parser doesn't have a
# dedicated field for -- "/ip ipsec identity add ... secret=<real-psk>"
# is the one seen so far on a real customer export, but the risk is
# generic to any "key=value" statement this parser preserves verbatim
# in config.review_commands for a human to look at. Every such line is
# run through _redact_secret_values() before being kept, so a real
# secret from the source config never gets echoed back out in the
# generated output's REVIEW comments (translate() elsewhere already
# takes care never to invent/leak a real PSK on its own -- this closes
# the same gap for text carried through verbatim from the source).
_SECRET_VALUE_RE = re.compile(
    r'(?i)\b(secret|password|psk|pre-shared-key|pre_shared_key)=(\S+)'
)


def _redact_secret_values(text):
    return _SECRET_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)


_NO_EQUIVALENT_SECTIONS = {
    "/interface wireless security-profiles": (
        "Palo Alto firewalls are not WiFi access points -- there is no PAN-OS "
        "equivalent for wireless SSID/security-profile configuration. Wireless "
        "access at this site needs a separate AP or controller."
    ),
    "/interface pptp-client": (
        "PAN-OS does not implement PPTP in any role (deprecated/insecure, never "
        "supported). Redesign this WAN link as a site-to-site IPsec tunnel "
        "('set network tunnel ipsec ...') or, for remote-user access, GlobalProtect."
    ),
    "/interface pptp-server server": (
        "PAN-OS has no PPTP server role. Remote-access VPN on Palo Alto is "
        "GlobalProtect (SSL/IPsec) instead -- needs a GlobalProtect portal + "
        "gateway designed from scratch, not a line-by-line translation."
    ),
    "/interface l2tp-server server": (
        "PAN-OS has no L2TP/IPsec dial-in server role. Remote-access VPN on "
        "Palo Alto is GlobalProtect instead -- needs a GlobalProtect portal + "
        "gateway designed from scratch."
    ),
    "/interface eoip": (
        "PAN-OS has no EoIP (Ethernet-over-IP) tunnel type. Redesign as a real "
        "GRE tunnel ('set network tunnel gre ...') if this carries L2/bridged "
        "traffic, or as a routed IPsec tunnel if the traffic is IP-only."
    ),
    "/queue simple": (
        "PAN-OS QoS works differently: bandwidth is assigned per QoS class on a "
        "QoS Profile applied to a physical interface, then a QoS policy rule "
        "matches traffic (zone/address/etc, not this per-IP style) to a class. "
        "This queue's max-limit needs to become a QoS Profile + QoS policy rule "
        "pair designed manually."
    ),
    "/snmp community": (
        "PAN-OS SNMP (Device > Setup > Operations) isn't a community-string "
        "object with an inline allowed-address list the way RouterOS does it -- "
        "configure SNMP manager access there instead."
    ),
    "/system logging action": (
        "PAN-OS logging is not action/target based -- configure a Log "
        "Forwarding Profile ('set log-settings profiles ...') and attach it to "
        "the relevant security rules or system log types instead."
    ),
    "/system logging": (
        "PAN-OS logging is not action/target based -- configure a Log "
        "Forwarding Profile ('set log-settings profiles ...') instead."
    ),
    "/ip proxy": "PAN-OS does not run a web proxy service on the firewall itself.",
    "/ip proxy access": "PAN-OS does not run a web proxy service on the firewall itself.",
    "/ip socks": "PAN-OS does not run a SOCKS proxy service on the firewall itself.",
    "/ip socks access": "PAN-OS does not run a SOCKS proxy service on the firewall itself.",
    "/ip smb shares": "PAN-OS does not provide file-sharing (SMB) services on the firewall itself.",
    "/ip ssh": (
        "PAN-OS management SSH access/crypto settings live under Device > Setup "
        "> Management, not a RouterOS-style /ip ssh block -- review mgmt access "
        "settings manually."
    ),
    "/ip firewall layer7-protocol": (
        "A RouterOS layer7-protocol regex has no automatic PAN-OS equivalent -- "
        "building an equivalent Custom Application (App-ID) needs a real "
        "signature/context definition, not just the regex text, and must be "
        "created manually."
    ),
    "/ip neighbor discovery-settings": (
        "This is a coarse global LLDP/CDP discovery toggle -- PAN-OS LLDP is "
        "configured per-interface ('set network lldp ...'), not globally the "
        "same way. Review and enable it per interface manually if still needed."
    ),
    "/ip settings": (
        "General IP stack tunables like tcp-syncookies don't map to a single "
        "PAN-OS equivalent -- the closest PAN-OS concepts are Zone Protection "
        "Profiles (flood protection) already covered elsewhere in this output "
        "where applicable; review the rest manually."
    ),
    "/ip cloud": (
        "PAN-OS has no built-in generic Dynamic DNS client feature equivalent "
        "to RouterOS's IP Cloud/DDNS -- if dynamic DNS is still needed, it must "
        "be configured through a supported third-party DDNS provider under "
        "Device > Dynamic DNS, a separate setup."
    ),
    "/ppp profile": (
        "This defines IP/DNS assignment for RouterOS PPP-based dial-in users "
        "(PPTP/L2TP/PPPoE) -- there is no PAN-OS equivalent object. If "
        "remote-user VPN access is still needed, this becomes a GlobalProtect "
        "IP pool + gateway configuration designed from scratch."
    ),
    "/ppp secret": (
        "This is RouterOS's local VPN dial-in user database (PPTP/L2TP/PPPoE). "
        "PAN-OS remote-access VPN (GlobalProtect) uses its own Local User "
        "Database or an external auth profile (RADIUS/LDAP/SAML) instead -- "
        "these accounts need to be recreated there manually; note passwords "
        "appear in plaintext here, so rotate them as part of the migration."
    ),
    "/ip hotspot": (
        "PAN-OS has no built-in captive-portal hotspot feature equivalent to "
        "RouterOS's /ip hotspot. Captive portal on PAN-OS is configured via "
        "Authentication Portal under Device > User Identification > Captive "
        "Portal Settings, and is a fundamentally different architecture."
    ),
    "/ip hotspot profile": (
        "PAN-OS captive portal (Authentication Portal) has no hotspot-profile "
        "equivalent -- redesign from scratch if captive portal is needed."
    ),
    "/ip hotspot user": (
        "PAN-OS captive portal users live in the Local User Database "
        "(Device > Local User Database > Users) or an external auth source "
        "(RADIUS/LDAP/SAML), not a RouterOS-style hotspot user list."
    ),
    "/ip upnp": (
        "UPnP should NOT be enabled on a production firewall. PAN-OS does not "
        "support UPnP at all. If needed for specific devices, use static NAT "
        "rules instead."
    ),
    "/ip upnp interfaces": (
        "UPnP should NOT be enabled on a production firewall. PAN-OS does not "
        "support UPnP -- use static NAT rules instead."
    ),
    "/ip firewall connection tracking": (
        "PAN-OS connection tracking is always on and not user-configurable the "
        "way RouterOS exposes it. Session timeout settings live under "
        "Device > Setup > Session > Session Timeouts."
    ),
    "/ip firewall raw": (
        "RouterOS raw table rules have no direct PAN-OS equivalent. The closest "
        "concept is a DoS Protection Profile (Zone Protection Profile) or "
        "Decryption Profile rules, depending on what the raw rules accomplish."
    ),
    "/ip ipsec identity": (
        "PAN-OS IPsec identity/authentication is configured as part of the IKE "
        "Gateway object ('set network ike gateway ...') rather than a separate "
        "identity object. Review and recreate manually."
    ),
    "/interface gre": (
        "PAN-OS supports GRE tunnels ('set network tunnel gre ...') but the "
        "configuration structure is different -- each GRE tunnel needs a tunnel "
        "interface, IP address, and routing entry configured manually."
    ),
    "/tool bandwidth-server": (
        "PAN-OS has no built-in bandwidth test server. Disable this on RouterOS "
        "in production environments (security risk). No migration action needed."
    ),
    "/tool mac-server": (
        "MAC Telnet server is RouterOS-specific. PAN-OS management uses SSH/HTTPS "
        "only. No migration action needed -- disable on RouterOS for security."
    ),
    "/tool mac-server mac-winbox": (
        "MAC Winbox is RouterOS-specific. PAN-OS management uses SSH/HTTPS "
        "only. No migration action needed."
    ),
    "/tool mac-server ping": (
        "MAC Ping is RouterOS-specific. PAN-OS has no equivalent. "
        "No migration action needed."
    ),
    "/routing ospf instance": (
        "PAN-OS OSPF is configured under Network > Virtual Routers > "
        "<router> > OSPF tab. The architecture (area/interface assignment "
        "within a virtual router) differs from RouterOS's flat instance model "
        "-- redesign the OSPF topology manually."
    ),
    "/routing ospf area": (
        "PAN-OS OSPF areas are configured under Network > Virtual Routers > "
        "<router> > OSPF > Areas. Review and recreate manually."
    ),
    "/routing ospf interface-template": (
        "PAN-OS OSPF interface settings are configured per-interface under "
        "the OSPF area's interface list. No template concept exists."
    ),
    "/routing ospf network": (
        "PAN-OS OSPF network statements are replaced by interface assignments "
        "under each OSPF area. Review and recreate manually."
    ),
    "/routing bgp connection": (
        "PAN-OS BGP is configured under Network > Virtual Routers > "
        "<router> > BGP tab. The configuration model differs substantially "
        "from RouterOS -- redesign BGP peering manually."
    ),
    "/routing bgp template": (
        "PAN-OS BGP peer groups are configured under the BGP tab in virtual "
        "router settings. No direct template equivalent exists."
    ),
    "/system scheduler": (
        "PAN-OS has no built-in task scheduler equivalent. Scheduled "
        "operations (config backups, reboots) are handled via Panorama or "
        "external orchestration. No migration action needed."
    ),
    "/system script": (
        "PAN-OS has no scripting engine equivalent to RouterOS scripts. "
        "Automation is handled via XML API, REST API, or Panorama. "
        "Review what each script does and implement via API if still needed."
    ),
    "/user": (
        "PAN-OS administrative users are configured under Device > "
        "Administrators. The permission model (role-based with admin roles) "
        "differs from RouterOS's group-based model -- recreate users manually "
        "with appropriate admin roles. Rotate passwords during migration."
    ),
    "/system routerboard settings": (
        "RouterBoard hardware settings (boot device, boot protocol) are "
        "hardware-specific to MikroTik. No PAN-OS equivalent exists. "
        "No migration action needed."
    ),
    "/system routerboard mode-button": (
        "RouterBoard mode button is MikroTik hardware-specific. "
        "No PAN-OS equivalent. No migration action needed."
    ),
}

_NO_EQUIVALENT_SECTIONS.update({
    "/ip route rule": (
        "RouterOS '/ip route rule' is source/destination based policy routing into a "
        "named routing table. PAN-OS equivalent is Policy-Based Forwarding "
        "(Policies > Policy Based Forwarding) with a nexthop or a separate virtual "
        "router; it is NOT a line-by-line translation -- design it per flow."
    ),
    "/queue tree": (
        "RouterOS queue trees shape packets that were marked in /ip firewall mangle. "
        "PAN-OS QoS (Network > Network Profiles > QoS Profile + Policies > QoS) is "
        "class based (8 classes) and egress-interface based; the PCQ per-address "
        "fairness has no equivalent -- redesign the classes manually."
    ),
    "/queue type": (
        "RouterOS queue types (PCQ / pfifo / sfq ...) describe per-address fairness "
        "inside a queue. PAN-OS QoS has no per-address PCQ; use QoS Profile classes "
        "with guaranteed/maximum bandwidth instead."
    ),
    "/interface l2tp-client": (
        "RouterOS L2TP client (PPP over UDP/1701, usually with IPsec). PAN-OS cannot "
        "originate an L2TP client session; replace the link with a site-to-site IPsec "
        "tunnel ('set network tunnel ipsec ...') or GRE-over-IPsec."
    ),
    "/interface sstp-client": (
        "PAN-OS has no SSTP client. Replace with an IPsec site-to-site tunnel."
    ),
    "/interface ovpn-client": (
        "PAN-OS has no OpenVPN client. Replace with an IPsec site-to-site tunnel."
    ),
    "/interface pppoe-client": (
        "PAN-OS supports PPPoE on a layer3 ethernet interface "
        "('set network interface ethernet ethernet1/N layer3 pppoe ...'); the "
        "credentials must be re-entered, they are never copied."
    ),
    "/tool netwatch": (
        "Netwatch runs a script when a host goes up/down. PAN-OS equivalent for "
        "failover is Path Monitoring on the static route / PBF rule (and for alerting, "
        "a Log Forwarding profile or SNMP trap). The scripts themselves are not "
        "portable -- review what each one does."
    ),
    "/ip ipsec policy group": (
        "Policy template groups only matter for dynamic (road-warrior) IPsec peers "
        "(mode-config / generate-policy). PAN-OS equivalent is a GlobalProtect gateway "
        "or an IKE gateway with 'passive' mode plus a tunnel interface."
    ),
    "/ip ipsec mode-config": (
        "RouterOS IKEv2 mode-config hands an address pool to remote clients. PAN-OS "
        "equivalent is the GlobalProtect gateway IP pool (or IKEv2 config payload on "
        "a tunnel interface) -- redesign manually."
    ),
})

# Matches a "key=value" pair where value is either a double-quoted
# string (RouterOS escapes an embedded quote as \") or a single
# unquoted token. Used on every "add"/"set" line body, after any
# leading "[ ... ]" selector has been split off.
_KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=("(?:[^"\\]|\\.)*"|\S*)')


def _unquote(raw_value):
    if len(raw_value) >= 2 and raw_value[0] == '"' and raw_value[-1] == '"':
        return raw_value[1:-1].replace('\\"', '"')
    return raw_value


def _parse_kv(text):
    fields = {}
    for match in _KV_RE.finditer(text):
        fields[match.group(1)] = _unquote(match.group(2))
    return fields


def _split_selector(body):
    """
    RouterOS "set" lines target an existing object either by a bare
    index ("set 0 ...") or a bracketed find-expression
    ("set [ find default-name=ether1 ] ..." / "set [ find name=WAN ]
    ..."). Returns (selector_fields, remaining_body) either way, with
    selector_fields empty for a bare index (the caller falls back to
    matching by whatever field the remaining body itself sets, e.g.
    "name=").
    """

    match = re.match(r'^\[\s*(.*?)\s*\]\s*(.*)$', body)
    if match:
        return _parse_kv(match.group(1)), match.group(2)

    match = re.match(r'^(?:\d+|\*[0-9A-Fa-f]+)\s*(.*)$', body)
    if match:
        # remember the raw index so callers can recognise "*0" (the default
        # object in many menus) -- exposed through the special key below.
        index = body.split(None, 1)[0]
        return {"__index__": index}, match.group(1)

    return {}, body


_QUOTED_RE = re.compile(r'"(?:[^"\\]|\\.)*"')

# RouterOS prints a few attributes as bare words with no "=value"
# ("add blackhole dst-address=...", "add disabled=no ..." is NOT bare).
_ROUTE_TYPE_FLAGS = ("blackhole", "unreachable", "prohibit")

# Passwords/PSKs/communities are NEVER kept. These helpers only let the
# parser answer "is it set / is it weak / is it reused" and then forget it.
_COMMON_WEAK_SECRETS = {
    "password", "passw0rd", "p@ssw0rd", "admin", "administrator", "123456",
    "1234567", "12345678", "123456789", "1234567890", "qwerty", "letmein",
    "welcome", "cisco", "mikrotik", "test", "secret", "changeme", "default",
    "1234", "12345", "111111", "abc123", "pass", "vpn", "ipsec", "l2tp",
    "pptp", "public", "private", "root", "user", "guest",
}

_FILTER_KNOWN = {
    "chain", "action", "src-address", "dst-address", "src-address-list",
    "dst-address-list", "protocol", "src-port", "dst-port", "in-interface",
    "out-interface", "in-interface-list", "out-interface-list", "comment",
    "disabled", "log", "connection-state", "connection-nat-state",
    "connection-mark", "packet-mark", "routing-mark", "tcp-flags",
    "icmp-options", "src-address-type", "dst-address-type", "jump-target",
    "reject-with",
}
_NAT_KNOWN = {
    "chain", "action", "src-address", "dst-address", "src-address-list",
    "dst-address-list", "to-addresses", "to-ports", "protocol", "dst-port",
    "src-port", "in-interface", "out-interface", "in-interface-list",
    "out-interface-list", "connection-mark", "packet-mark", "routing-mark",
    "comment", "disabled",
}
_MANGLE_KNOWN = {
    "chain", "action", "new-connection-mark", "new-packet-mark",
    "new-routing-mark", "new-dscp", "passthrough", "src-address",
    "dst-address", "src-address-list", "dst-address-list", "protocol",
    "src-port", "dst-port", "in-interface", "out-interface",
    "in-interface-list", "out-interface-list", "connection-mark",
    "packet-mark", "routing-mark", "connection-state", "comment", "disabled",
    "new-mss",
}
_RAW_KNOWN = {
    "chain", "action", "address-list", "address-list-timeout", "protocol",
    "tls-host", "src-address", "dst-address", "src-address-list",
    "dst-address-list", "in-interface", "out-interface", "comment", "disabled",
}
_NEGATABLE_MATCH_KEYS = (
    "src-address", "dst-address", "src-address-list", "dst-address-list",
    "protocol", "src-port", "dst-port", "in-interface", "out-interface",
    "in-interface-list", "out-interface-list", "connection-state",
    "connection-nat-state", "connection-mark", "packet-mark", "routing-mark",
)

# "/interface <x>" sections that define a virtual/tunnel interface. They are
# modeled as Interface rows (so counts, IPs and remote endpoints are visible)
# but are NOT physical ports -- the translator reviews them instead of
# guessing an ethernetX/Y slot.
_TUNNEL_INTERFACE_SECTIONS = {
    "/interface l2tp-client": "l2tp-client",
    "/interface pptp-client": "pptp-client",
    "/interface sstp-client": "sstp-client",
    "/interface ovpn-client": "ovpn-client",
    "/interface pppoe-client": "pppoe-client",
    "/interface eoip": "eoip",
    "/interface gre": "gre",
    "/interface ipip": "ipip",
    "/interface wireguard": "wireguard",
    "/interface bonding": "bonding",
    "/interface vrrp": "vrrp",
}

_VPN_SERVER_SECTIONS = {
    "/interface l2tp-server server": "l2tp",
    "/interface pptp-server server": "pptp",
    "/interface sstp-server server": "sstp",
    "/interface ovpn-server server": "ovpn",
}

# Sections whose "set k=v" lines are flat tunables. Recorded as
# config.system_settings["<section> <key>"] so the analyzer can raise a
# finding (e.g. /ip ssh allow-none-crypto=yes) without a model class each.
_SETTINGS_SECTIONS = (
    "/ip ssh", "/ip settings", "/ip proxy", "/ip socks", "/ip upnp",
    "/ip cloud", "/tool bandwidth-server", "/tool mac-server",
    "/tool mac-server mac-winbox", "/tool mac-server ping",
    "/ip neighbor discovery-settings", "/interface bridge settings",
    "/ip accounting", "/ip accounting web-access", "/system package update",
    "/tool graphing", "/tool romon", "/ip dns", "/tool e-mail",
    "/ip firewall connection tracking", "/ip hotspot",
)

# Hardware/diagnostic menus that only ever carry vendor defaults in an /export
# ("/interface ethernet switch port set 3 default-vlan-id=0", LED mapping,
# RoMON, graphing). They change nothing a firewall migration or audit cares
# about and would otherwise flood the "not interpreted" list.
_QUIET_SECTIONS = {
    "/interface ethernet switch port", "/system leds", "/tool romon port",
    "/tool graphing queue", "/tool graphing interface", "/tool graphing resource",
}

_PPP_DEFAULT_INDEX_NAMES = {"*0": "default", "*FFFFFFFE": "default-encryption"}


def _bare_flags(text):
    """Bare (no '=') words of an add/set body, outside quoted values."""
    flat = _QUOTED_RE.sub('""', text)
    return [token for token in flat.split() if "=" not in token and not token.startswith("[")
            and token not in ("]", "find")]


def _is_weak_secret(value, name=""):
    secret = str(value or "")
    if not secret:
        return False
    low = secret.lower()
    if len(secret) < 8:
        return True
    if low in _COMMON_WEAK_SECRETS:
        return True
    owner = str(name or "").lower()
    if owner and (low == owner or (owner in low and len(low) <= len(owner) + 4)):
        return True
    if secret.isdigit() and len(secret) < 12:
        return True
    if len(set(secret)) <= 2:
        return True
    return False


def _extra_fields(fields, known):
    """Everything on a rule line the model has no dedicated field for."""
    extra = {}
    for key, value in fields.items():
        if key in known:
            continue
        if _SECRETISH_KEY_RE.search(key):
            continue
        extra[key] = value
    return extra


_SECRETISH_KEY_RE = re.compile(r"(?i)(secret|password|psk|pre-shared|private-key|key)$")


def _negated_keys(fields, keys):
    """RouterOS prints a negated match as 'key=!value'. The PAN-OS rule has
    no such per-field negation for most keys, so remember which were negated."""
    return {f"negated:{key}": fields[key] for key in keys if str(fields.get(key, "")).startswith("!")}


def _to_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("yes", "true")


def _to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


class MikrotikFirewallParser:
    """
    Parses a RouterOS "/export" configuration into the shared
    FirewallConfig model (models/firewall.py). RouterOS export syntax
    is fundamentally different from the IOS/VRP-style line-oriented
    configs the other parsers in this project handle: it's grouped
    into "/path" section headers, each followed by "add ..." (create)
    or "set ..." (modify an existing/default object) statements built
    from "key=value" pairs rather than positional CLI keywords -- so
    this parser is a section dispatcher + key/value reader rather than
    a per-keyword line matcher like parsers/switch/cisco.py.

    Anything under a recognized section that this parser doesn't yet
    turn into a model field, and anything under a section it doesn't
    recognize at all, is preserved verbatim in config.review_commands
    rather than silently dropped -- same convention the switch
    translators use for REVIEW-flagged output.
    """

    def parse_file(self, filename):
        config = FirewallConfig(
            source_vendor="Mikrotik",
            source_device_type="Firewall",
            source_file=str(filename),
        )

        path = Path(filename)
        with open(path, "r", encoding="utf-8", errors="ignore") as file:
            raw_lines = file.readlines()

        return self.parse_lines(raw_lines, config)

    def parse_text(self, text, source_name="<text>"):
        """Same as parse_file for an in-memory export (analyzer upload path)."""
        config = FirewallConfig(
            source_vendor="Mikrotik",
            source_device_type="Firewall",
            source_file=str(source_name),
        )
        return self.parse_lines(str(text).splitlines(keepends=True), config)

    def parse_lines(self, raw_lines, config):
        self._read_header(config, raw_lines)

        lines = self._join_continuations(raw_lines)

        # (object, owner-name, secret) triples gathered while reading. The
        # secret values only live here, are compared once in
        # _finalize_secrets() and are then dropped -- the model keeps
        # nothing but set / weak / reused flags.
        self._secret_pool = {"ppp-secret": [], "ipsec-psk": [], "l2tp-ipsec-secret": [], "snmp-community": []}
        self._default_objects = {}

        current_section = None
        # RouterOS export groups every add/set under the most recently
        # printed "/path" header until the next one -- unlike the
        # switch configs, there's no closing token, so the current
        # section stays in effect until a new "/..." line replaces it.
        interfaces_by_name = {}
        # name -> list of member interface names, filled in purely by
        # "/interface bridge port add" lines regardless of whether that
        # bridge's own "/interface bridge add" line has been seen yet
        # (a real /export always prints bridges before their ports,
        # but a hand-trimmed or reordered file may not -- see
        # _attach_bridge_ports, which reconciles this against
        # config.interfaces once the whole file has been read).
        bridge_port_membership = {}

        handlers = self._section_handlers()
        hooks = self._model_hooks()

        for line in lines:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("/"):
                current_section = stripped.lower()
                continue

            if current_section is None:
                # A statement before any "/section" header has ever
                # appeared -- not valid /export output. Keep it for
                # review rather than guessing a section for it.
                config.review_commands.append(stripped)
                continue

            if current_section in _QUIET_SECTIONS:
                config.modeled_sections.add(current_section)
                continue

            hook = hooks.get(current_section)
            if hook is not None:
                # Hooks fill the richer model rows (queues, PPP secrets,
                # SNMP, mangle ...). They never replace the review line
                # below: the converter keeps its explanation, the analyzer
                # uses config.modeled_sections to stop listing the section
                # as "not interpreted".
                try:
                    consumed = hook(config, stripped, interfaces_by_name)
                    if consumed is not False:
                        config.modeled_sections.add(current_section)
                        # Only the redacted text is kept: review_commands is
                        # redacted at the end of the parse, and a clear-text
                        # secret must not survive anywhere on the model.
                        config.modeled_lines.add(_redact_secret_values(f"{current_section} {stripped}"))
                except Exception as error:  # a single odd line must not abort the whole parse
                    config.review_commands.append(
                        f"{current_section} {stripped} -- could not be modeled ({type(error).__name__})"
                    )

            handler = handlers.get(current_section)
            if handler is None:
                config.review_commands.append(f"{current_section} {stripped}")
                continue

            handler(config, stripped, interfaces_by_name, bridge_port_membership)

        self._attach_bridge_ports(config, bridge_port_membership)
        self._finalize_secrets(config)

        config.review_commands = [_redact_secret_values(item) for item in config.review_commands]

        return config

    # ====================================================
    # EXPORT HEADER ("# sep/11/2026 11:30:07 by RouterOS 6.49.15" ...)
    # ====================================================

    @staticmethod
    def _read_header(config, raw_lines):
        for raw in raw_lines:
            text = raw.strip()
            if text.startswith("/"):
                break
            if not text.startswith("#"):
                continue
            body = text.lstrip("#").strip()
            match = re.match(r"^(.*?)\s+by RouterOS\s+(\S+)", body)
            if match:
                config.export_time = match.group(1).strip()
                config.routeros_version = match.group(2).strip()
                continue
            match = re.match(r"^(software id|model|serial number)\s*=\s*(.*)$", body, re.I)
            if match:
                key, value = match.group(1).lower(), match.group(2).strip()
                if key == "software id":
                    config.software_id = value
                elif key == "model":
                    config.model = value
                else:
                    config.serial_number = value

    # ====================================================
    # LINE JOINING
    # ====================================================

    @staticmethod
    def _join_continuations(raw_lines):
        """
        A RouterOS /export wraps long statements across lines with a
        trailing backslash; the continuation line's leading indentation
        is purely cosmetic (unlike the Cisco parser, where indentation
        marks a sub-command block) -- it's just how RouterOS wraps for
        terminal width. Re-join before any field parsing happens.

        The wrap point can fall ANYWHERE, including mid "key=value"
        (e.g. "comment=\\" then "    \"some text\"" on the next line) as
        often as it falls between two whole tokens (e.g. "disabled=no \\"
        then "    interface=bridge-LAN ..."). Reconstructing the
        original line correctly means never fabricating a separator of
        our own: keep whatever whitespace genuinely precedes the
        backslash (a real token boundary in the between-tokens case,
        nothing at all in the mid-key=value case) and strip only the
        next line's cosmetic leading indent before concatenating
        directly. An earlier version of this method rstripped that
        real trailing space away and then unconditionally reinserted
        exactly one space -- which happened to look right for the
        between-tokens case but injected a bogus space into every
        mid-"key=value" wrap, breaking _KV_RE (whose value pattern
        does not allow whitespace between "=" and the value) and
        silently emptying out fields like comment, name and advertise
        on real, wrapped /export files.
        """

        joined = []
        buffer = ""
        for raw in raw_lines:
            text = raw.rstrip("\r\n")
            if buffer:
                text = text.lstrip()
            if text.endswith("\\"):
                buffer += text[:-1]
                continue
            buffer += text
            joined.append(buffer.strip())
            buffer = ""
        if buffer.strip():
            joined.append(buffer.strip())
        return joined

    # ====================================================
    # SECTION HANDLERS
    # ====================================================

    def _section_handlers(self):
        handlers = {
            "/system identity": self._handle_identity,
            "/system clock": self._handle_system_clock,
            "/system ntp client": self._handle_ntp_client,
            "/interface ethernet": self._handle_physical_interface,
            "/interface bridge": self._handle_bridge,
            "/interface bridge port": self._handle_bridge_port,
            "/interface vlan": self._handle_vlan_interface,
            "/interface list": self._handle_interface_list,
            "/interface list member": self._handle_interface_list_member,
            "/ip address": self._handle_ip_address,
            "/ip route": self._handle_route,
            "/ip pool": self._handle_ip_pool,
            "/ip dhcp-server": self._handle_dhcp_server,
            "/ip dhcp-server network": self._handle_dhcp_server_network,
            "/ip dhcp-client": self._handle_dhcp_client,
            "/ip dns": self._handle_dns,
            "/ip dns static": self._handle_dns_static,
            "/ip service": self._handle_ip_service,
            "/ip firewall address-list": self._handle_address_list,
            "/ip firewall filter": self._handle_filter_rule,
            "/ip firewall mangle": self._handle_mangle,
            "/ip firewall nat": self._handle_nat_rule,
            "/ip ipsec proposal": self._handle_ipsec_proposal,
            "/ip ipsec profile": self._handle_ipsec_profile,
            "/ip ipsec peer": self._handle_ipsec_peer,
            "/ip ipsec policy": self._handle_ipsec_policy,
        }
        for section_label, explanation in _NO_EQUIVALENT_SECTIONS.items():
            handlers[section_label] = partial(
                self._handle_no_equivalent, section_label=section_label, explanation=explanation
            )
        return handlers

    def _handle_no_equivalent(
        self, config, statement, interfaces_by_name, bridge_port_membership, section_label, explanation
    ):
        config.review_commands.append(f"{section_label} {statement} -- {explanation}")

    def _handle_identity(self, config, statement, interfaces_by_name, bridge_port_membership):
        _selector, body = _split_selector(statement[len("set"):].strip()) if statement.startswith("set") else ({}, "")
        fields = _parse_kv(body)
        if fields.get("name"):
            config.hostname = fields["name"]

    def _handle_physical_interface(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Physical ports always exist on the device -- RouterOS never
        # "add"s one, only "set [ find default-name=... ] ..." to
        # rename/comment/disable it. A bare "add ..." here would be
        # unexpected /export output; keep it for review rather than
        # inventing an interface for it.
        if not statement.startswith("set"):
            config.review_commands.append(f"/interface ethernet {statement}")
            return

        selector, body = _split_selector(statement[len("set"):].strip())
        fields = _parse_kv(body)

        default_name = selector.get("default-name") or selector.get("name")
        final_name = fields.get("name") or default_name
        if not final_name:
            config.review_commands.append(f"/interface ethernet {statement}")
            return

        interface = interfaces_by_name.get(default_name) or interfaces_by_name.get(final_name)
        if interface is None:
            interface = Interface(name=final_name, interface_type="ethernet", default_name=default_name or "")
            config.interfaces.append(interface)
        else:
            interface.name = final_name
            if default_name and not interface.default_name:
                interface.default_name = default_name

        interfaces_by_name[final_name] = interface
        if default_name:
            interfaces_by_name[default_name] = interface

        if "comment" in fields:
            interface.comment = fields["comment"]
        if "disabled" in fields:
            interface.disabled = _to_bool(fields["disabled"])
        if "mtu" in fields:
            interface.mtu = _to_int(fields["mtu"])
        if fields.get("speed"):
            # A forced speed (auto-negotiation=no) must survive the move: a
            # PAN-OS port left on auto against a peer hard-set to 100M/full
            # comes up half-duplex or not at all.
            interface.speed = fields["speed"]
        if "l2mtu" in fields:
            interface.l2mtu = _to_int(fields["l2mtu"])

    def _handle_bridge(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface bridge {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        if not name:
            config.review_commands.append(f"/interface bridge {statement}")
            return

        interface = Interface(
            name=name,
            interface_type="bridge",
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
            mtu=_to_int(fields.get("mtu")),
        )
        config.interfaces.append(interface)
        interfaces_by_name[name] = interface

    def _handle_bridge_port(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface bridge port {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        bridge_name = fields.get("bridge")
        member = fields.get("interface")
        if not bridge_name or not member:
            config.review_commands.append(f"/interface bridge port {statement}")
            return

        if _to_bool(fields.get("disabled")):
            # RouterOS lets a bridge-port membership be disabled on its
            # own, independent of the bridge and of the underlying
            # interface -- the member interface is NOT actually part of
            # the bridge in the live config. Leaving it out here means
            # it falls through to being translated as its own
            # standalone routed interface (keeping any IP it carries)
            # instead of being silently folded into the bridge's zone.
            config.review_commands.append(
                f"/interface bridge port {statement} "
                f"(disabled bridge-port membership -- '{member}' was NOT added to "
                f"bridge '{bridge_name}', translated as a standalone interface instead)"
            )
            return

        # bridge_port_membership only ever holds plain name lists here
        # -- resolving them against real Interface objects (creating
        # the bridge's Interface if "/interface bridge add" was never
        # seen for it) happens once, in _attach_bridge_ports, after
        # the whole file has been read. That single reconciliation
        # point is what lets ports be listed before or after their
        # bridge without needing two different code paths here.
        bridge_port_membership.setdefault(bridge_name, []).append(member)

    def _handle_vlan_interface(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface vlan {statement}")
            return

        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        vlan_id = _to_int(fields.get("vlan-id"))
        if not name or vlan_id is None:
            config.review_commands.append(f"/interface vlan {statement}")
            return

        interface = Interface(
            name=name,
            interface_type="vlan",
            vlan_id=vlan_id,
            parent_interface=fields.get("interface", ""),
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
            mtu=_to_int(fields.get("mtu")),
        )
        config.interfaces.append(interface)
        interfaces_by_name[name] = interface

    def _handle_interface_list(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Just declares the list's name (add name=WAN); membership is
        # what matters and comes from "/interface list member" below,
        # so there's nothing to model from this section on its own.
        return

    def _handle_interface_list_member(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/interface list member {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        list_name = fields.get("list")
        interface = fields.get("interface")
        if not list_name or not interface:
            config.review_commands.append(f"/interface list member {statement}")
            return
        config.interface_list_members.append(
            InterfaceListMember(list_name=list_name, interface=interface)
        )

    def _handle_ip_address(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip address {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        address = fields.get("address")
        interface_name = fields.get("interface")
        if not address or not interface_name:
            config.review_commands.append(f"/ip address {statement}")
            return

        # A host address is exported without a prefix length
        # ("address=103.x.x.x network=103.x.x.x"); it is a /32. Left bare it
        # would be emitted as an invalid "ip 103.x.x.x" on the target.
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", address):
            address = f"{address}/32"

        interface = interfaces_by_name.get(interface_name)
        if interface is None:
            # Referenced before its own section defined it (or it's an
            # interface type this parser doesn't have a section
            # handler for, e.g. a bonding/VRRP interface) -- create a
            # stub so the IP isn't lost, typed "unknown" so the
            # translator knows to REVIEW rather than assume ethernet.
            interface = Interface(name=interface_name, interface_type="unknown")
            config.interfaces.append(interface)
            interfaces_by_name[interface_name] = interface

        if fields.get("comment"):
            interface.ip_address_comments[address] = fields["comment"]

        if _to_bool(fields.get("disabled")):
            # A disabled /ip address is NOT configured on the router. Keeping
            # it in ip_addresses made the old parser translate dead
            # addresses into live ones (and raised false duplicate-IP /
            # "multiple IPs" findings), so it is parked separately.
            interface.disabled_ip_addresses.append(address)
            return

        interface.ip_addresses.append(address)

    def _handle_route(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip route {statement}")
            return
        body = statement[len("add"):].strip()
        fields = _parse_kv(body)
        flags = _bare_flags(body)

        route_type = fields.get("type", "")
        if not route_type:
            route_type = next((flag for flag in flags if flag in _ROUTE_TYPE_FLAGS), "")

        # RouterOS 6 calls the policy table "routing-mark", RouterOS 7
        # "routing-table"; "main" is the ordinary table, anything else is a
        # PBR table that must NOT be merged into the default routing table.
        routing_mark = fields.get("routing-mark", "")
        if not routing_mark and fields.get("routing-table", "main") not in ("", "main"):
            routing_mark = fields["routing-table"]

        config.static_routes.append(
            StaticRoute(
                dst_address=fields.get("dst-address", "0.0.0.0/0"),
                gateway=fields.get("gateway", ""),
                distance=_to_int(fields.get("distance")),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                routing_mark=routing_mark,
                check_gateway=fields.get("check-gateway", ""),
                pref_src=fields.get("pref-src", ""),
                scope=_to_int(fields.get("scope")),
                target_scope=_to_int(fields.get("target-scope")),
                route_type=route_type,
            )
        )

    # ====================================================
    # SYSTEM SETTINGS (clock, NTP)
    # ====================================================

    def _handle_system_clock(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/system clock {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        if fields.get("time-zone-name"):
            config.timezone = fields["time-zone-name"]

    def _handle_ntp_client(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/system ntp client {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        for key in ("primary-ntp", "secondary-ntp"):
            if fields.get(key):
                config.ntp_servers.append(fields[key])

    # ====================================================
    # DHCP (server role + client role)
    # ====================================================

    def _handle_ip_pool(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip pool {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        if not name:
            config.review_commands.append(f"/ip pool {statement}")
            return
        config.dhcp_pools.append(DhcpPool(name=name, ranges=fields.get("ranges", "")))

    def _handle_dhcp_server(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-server {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.dhcp_servers.append(
            DhcpServerBinding(
                name=fields.get("name", f"dhcp-server{len(config.dhcp_servers) + 1}"),
                interface=fields.get("interface", ""),
                address_pool=fields.get("address-pool", ""),
                lease_time=fields.get("lease-time", ""),
                disabled=_to_bool(fields.get("disabled")),
                authoritative=fields.get("authoritative", ""),
            )
        )

    def _handle_dhcp_server_network(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-server network {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.dhcp_server_networks.append(
            DhcpServerNetwork(
                address=fields.get("address", ""),
                gateway=fields.get("gateway", ""),
                dns_servers=fields.get("dns-server", ""),
            )
        )

    def _handle_dhcp_client(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dhcp-client {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        interface = fields.get("interface")
        if not interface:
            config.review_commands.append(f"/ip dhcp-client {statement}")
            return
        config.dhcp_client_bindings.append(
            DhcpClientBinding(
                interface=interface,
                default_route_distance=_to_int(fields.get("default-route-distance")),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # ====================================================
    # DNS (global resolver + static host overrides)
    # ====================================================

    def _handle_dns(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("set"):
            config.review_commands.append(f"/ip dns {statement}")
            return
        fields = _parse_kv(statement[len("set"):].strip())
        servers = fields.get("servers", "")
        if servers:
            config.dns_servers = [s.strip() for s in servers.split(",") if s.strip()]

    def _handle_dns_static(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip dns static {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        name = fields.get("name")
        address = fields.get("address")
        if not name or not address:
            config.review_commands.append(f"/ip dns static {statement}")
            return
        config.dns_static_entries.append(
            DnsStaticEntry(
                name=name,
                address=address,
                disabled=_to_bool(fields.get("disabled")),
                ttl=fields.get("ttl", ""),
            )
        )

    # ====================================================
    # MANAGEMENT SERVICES ("/ip service")
    # ====================================================

    def _handle_ip_service(self, config, statement, interfaces_by_name, bridge_port_membership):
        # Unlike every other "set" statement in this parser, RouterOS
        # names the target object here as a bare leading word
        # ("set telnet disabled=yes ...") rather than through a "[ find
        # ... ]" selector or a numeric index, so _split_selector alone
        # can't recover the service name -- pull it off manually.
        if not statement.startswith("set"):
            config.review_commands.append(f"/ip service {statement}")
            return
        body = statement[len("set"):].strip()
        match = re.match(r'^([A-Za-z0-9_.-]+)\s*(.*)$', body)
        if not match:
            config.review_commands.append(f"/ip service {statement}")
            return
        service_name, rest = match.group(1), match.group(2)
        fields = _parse_kv(rest)
        config.management_services.append(
            ManagementService(
                name=service_name,
                disabled=_to_bool(fields.get("disabled")),
                port=_to_int(fields.get("port")),
                address=fields.get("address", ""),
            )
        )

    # ====================================================
    # MANGLE (change-mss only -- everything else has no PAN-OS
    # equivalent and is reviewed with an explanation instead)
    # ====================================================

    def _handle_mangle(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall mangle {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        action = fields.get("action", "")
        if action == "change-mss":
            config.mss_clamps.append(
                MssClamp(
                    new_mss=_to_int(fields.get("new-mss")),
                    in_interface=fields.get("in-interface", ""),
                    out_interface=fields.get("out-interface", ""),
                )
            )
            return
        config.review_commands.append(
            f"/ip firewall mangle {statement} -- mangle action '{action}' (anything "
            "other than change-mss, e.g. policy routing/marking) has no direct PAN-OS "
            "equivalent; redesign as a Policy-Based Forwarding (PBF) rule instead."
        )

    def _handle_address_list(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall address-list {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        list_name = fields.get("list")
        address = fields.get("address")
        if not list_name or not address:
            config.review_commands.append(f"/ip firewall address-list {statement}")
            return
        config.address_lists.append(
            AddressListEntry(
                list_name=list_name,
                address=address,
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _handle_filter_rule(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall filter {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        extra = _extra_fields(fields, _FILTER_KNOWN)
        extra.update(_negated_keys(fields, _NEGATABLE_MATCH_KEYS))
        config.filter_rules.append(
            FirewallFilterRule(
                chain=fields.get("chain", "forward"),
                action=fields.get("action", "accept"),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                src_address_list=fields.get("src-address-list", ""),
                dst_address_list=fields.get("dst-address-list", ""),
                protocol=fields.get("protocol", ""),
                src_port=fields.get("src-port", ""),
                dst_port=fields.get("dst-port", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                in_interface_list=fields.get("in-interface-list", ""),
                out_interface_list=fields.get("out-interface-list", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                log=_to_bool(fields.get("log")),
                connection_state=fields.get("connection-state", ""),
                connection_nat_state=fields.get("connection-nat-state", ""),
                connection_mark=fields.get("connection-mark", ""),
                packet_mark=fields.get("packet-mark", ""),
                routing_mark=fields.get("routing-mark", ""),
                tcp_flags=fields.get("tcp-flags", ""),
                icmp_options=fields.get("icmp-options", ""),
                src_address_type=fields.get("src-address-type", ""),
                dst_address_type=fields.get("dst-address-type", ""),
                jump_target=fields.get("jump-target", ""),
                reject_with=fields.get("reject-with", ""),
                extra=extra,
            )
        )

    def _handle_nat_rule(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip firewall nat {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        extra = _extra_fields(fields, _NAT_KNOWN)
        extra.update(_negated_keys(fields, _NEGATABLE_MATCH_KEYS))
        config.nat_rules.append(
            NatRule(
                chain=fields.get("chain", "srcnat"),
                action=fields.get("action", "masquerade"),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                src_address_list=fields.get("src-address-list", ""),
                dst_address_list=fields.get("dst-address-list", ""),
                to_addresses=fields.get("to-addresses", ""),
                to_ports=fields.get("to-ports", ""),
                protocol=fields.get("protocol", ""),
                dst_port=fields.get("dst-port", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                in_interface_list=fields.get("in-interface-list", ""),
                out_interface_list=fields.get("out-interface-list", ""),
                src_port=fields.get("src-port", ""),
                connection_mark=fields.get("connection-mark", ""),
                packet_mark=fields.get("packet-mark", ""),
                routing_mark=fields.get("routing-mark", ""),
                extra=extra,
            )
        )

    def _default_ipsec_proposal(self, config):
        for proposal in config.ipsec_proposals:
            if proposal.is_default:
                return proposal
        is_v6 = str(config.routeros_version).startswith("6")
        proposal = IpsecProposal(
            name="default",
            auth_algorithms="sha1",
            enc_algorithms="3des" if is_v6 else "aes-256-cbc,aes-192-cbc,aes-128-cbc",
            lifetime="30m",
            pfs_group="modp1024",
            is_default=True,
        )
        config.ipsec_proposals.append(proposal)
        return proposal

    def _handle_ipsec_proposal(self, config, statement, interfaces_by_name, bridge_port_membership):
        if statement.startswith("set"):
            # "set [ find default=yes ] enc-algorithms=aes-128-cbc" edits the
            # built-in proposal named "default" (not listed by /export when
            # untouched) -- the old parser dropped these edits, so every
            # policy referring to proposal=default was translated with the
            # wrong ciphers.
            selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
            if selector.get("default") == "yes" or selector.get("name") == "default":
                proposal = self._default_ipsec_proposal(config)
            elif selector.get("name"):
                proposal = next((p for p in config.ipsec_proposals if p.name == selector["name"]), None)
            else:
                proposal = None
            if proposal is None:
                config.review_commands.append(f"/ip ipsec proposal {statement}")
                return
            if "auth-algorithms" in fields:
                proposal.auth_algorithms = fields["auth-algorithms"]
            if "enc-algorithms" in fields:
                proposal.enc_algorithms = fields["enc-algorithms"]
            if "lifetime" in fields:
                proposal.lifetime = fields["lifetime"]
            if "pfs-group" in fields:
                proposal.pfs_group = fields["pfs-group"]
            if "disabled" in fields:
                proposal.disabled = _to_bool(fields["disabled"])
            return
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec proposal {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_proposals.append(
            IpsecProposal(
                name=fields.get("name", f"proposal{len(config.ipsec_proposals) + 1}"),
                auth_algorithms=fields.get("auth-algorithms", "sha1"),
                enc_algorithms=fields.get("enc-algorithms", "aes-256-cbc"),
                lifetime=fields.get("lifetime", ""),
                pfs_group=fields.get("pfs-group", "modp1024"),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _default_ipsec_profile(self, config):
        for profile in config.ipsec_profiles:
            if profile.is_default:
                return profile
        profile = IpsecProfile(
            name="default",
            dh_group="modp1024",
            enc_algorithm="aes-128",
            hash_algorithm="sha1",
            lifetime="1d",
            nat_traversal=True,
            dpd_interval="2m",
            is_default=True,
        )
        config.ipsec_profiles.append(profile)
        return profile

    def _handle_ipsec_profile(self, config, statement, interfaces_by_name, bridge_port_membership):
        if statement.startswith("set"):
            selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
            if selector.get("default") == "yes" or selector.get("name") == "default":
                profile = self._default_ipsec_profile(config)
            elif selector.get("name"):
                profile = next((p for p in config.ipsec_profiles if p.name == selector["name"]), None)
            else:
                profile = None
            if profile is None:
                config.review_commands.append(f"/ip ipsec profile {statement}")
                return
            if "dh-group" in fields:
                profile.dh_group = fields["dh-group"]
            if "enc-algorithm" in fields:
                profile.enc_algorithm = fields["enc-algorithm"]
            if "hash-algorithm" in fields:
                profile.hash_algorithm = fields["hash-algorithm"]
            if "lifetime" in fields:
                profile.lifetime = fields["lifetime"]
            if "nat-traversal" in fields:
                profile.nat_traversal = _to_bool(fields["nat-traversal"])
            if "dpd-interval" in fields:
                profile.dpd_interval = fields["dpd-interval"]
            return
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec profile {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_profiles.append(
            IpsecProfile(
                name=fields.get("name", f"profile{len(config.ipsec_profiles) + 1}"),
                dh_group=fields.get("dh-group", "modp1024"),
                enc_algorithm=fields.get("enc-algorithm", "aes-256"),
                hash_algorithm=fields.get("hash-algorithm", "sha1"),
                lifetime=fields.get("lifetime", "1d"),
                nat_traversal=_to_bool(fields["nat-traversal"]) if "nat-traversal" in fields else None,
                dpd_interval=fields.get("dpd-interval", ""),
            )
        )

    def _handle_ipsec_peer(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec peer {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        # RouterOS 6 defaults exchange-mode to "main" (IKEv1); 7 to "ike2".
        # /export omits defaults, so a peer without the key inherits this.
        default_mode = "main" if str(config.routeros_version).startswith("6") else "ike2"
        config.ipsec_peers.append(
            IpsecPeer(
                name=fields.get("name", f"peer{len(config.ipsec_peers) + 1}"),
                address=fields.get("address", ""),
                exchange_mode=fields.get("exchange-mode", default_mode),
                profile_name=fields.get("profile", ""),
                disabled=_to_bool(fields.get("disabled")),
                local_address=fields.get("local-address", ""),
                passive=_to_bool(fields.get("passive")),
                send_initial_contact=(
                    _to_bool(fields["send-initial-contact"]) if "send-initial-contact" in fields else None
                ),
            )
        )

    def _handle_ipsec_policy(self, config, statement, interfaces_by_name, bridge_port_membership):
        if not statement.startswith("add"):
            config.review_commands.append(f"/ip ipsec policy {statement}")
            return
        fields = _parse_kv(statement[len("add"):].strip())
        config.ipsec_policies.append(
            IpsecPolicy(
                peer_name=fields.get("peer", ""),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                proposal_name=fields.get("proposal", ""),
                tunnel=_to_bool(fields.get("tunnel"), default=True),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                action=fields.get("action", ""),
                level=fields.get("level", ""),
                ipsec_protocols=fields.get("ipsec-protocols", ""),
                sa_src_address=fields.get("sa-src-address", ""),
                sa_dst_address=fields.get("sa-dst-address", ""),
                template=_to_bool(fields.get("template")),
            )
        )

    # ====================================================
    # MODEL HOOKS -- richer rows for sections that either had no
    # model at all (queues, PPP, SNMP, scheduler ...) or whose
    # review-only handling hid facts the analyzer needs. A hook never
    # emits review lines itself: the legacy handler/review path in
    # parse_lines() still runs afterwards, unchanged.
    # ====================================================

    def _model_hooks(self):
        hooks = {
            "/ip route rule": self._hook_route_rule,
            "/ip firewall mangle": self._hook_mangle,
            "/ip firewall raw": self._hook_raw,
            "/queue type": self._hook_queue_type,
            "/queue simple": self._hook_queue_simple,
            "/queue tree": self._hook_queue_tree,
            "/ppp profile": self._hook_ppp_profile,
            "/ppp secret": self._hook_ppp_secret,
            "/ip ipsec identity": self._hook_ipsec_identity,
            "/snmp": self._hook_snmp,
            "/snmp community": self._hook_snmp_community,
            "/user": self._hook_user,
            "/system scheduler": self._hook_scheduler,
            "/tool netwatch": self._hook_netwatch,
            "/routing ospf instance": self._hook_ospf_instance,
            "/routing ospf network": self._hook_ospf_network,
            "/routing ospf interface-template": self._hook_ospf_template,
            "/routing bgp peer": self._hook_bgp_peer,
            "/routing bgp connection": self._hook_bgp_peer,
            "/system logging": self._hook_logging,
            "/system logging action": self._hook_logging_action,
        }
        for section, kind in _TUNNEL_INTERFACE_SECTIONS.items():
            hooks[section] = partial(self._hook_tunnel_interface, kind=kind)
        for section, kind in _VPN_SERVER_SECTIONS.items():
            hooks[section] = partial(self._hook_vpn_server, kind=kind)
        for section in _SETTINGS_SECTIONS:
            hooks[section] = partial(self._hook_settings, section=section)
        return hooks

    @staticmethod
    def _add_fields(statement):
        if not statement.startswith("add"):
            return None
        return _parse_kv(statement[len("add"):].strip())

    # -- policy routing / mangle / raw --------------------------------

    def _hook_route_rule(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.policy_routes.append(
            PolicyRouteRule(
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                interface=fields.get("interface", ""),
                table=fields.get("table", ""),
                action=fields.get("action", "lookup"),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _hook_mangle(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.mangle_rules.append(
            MangleRule(
                chain=fields.get("chain", ""),
                action=fields.get("action", ""),
                new_connection_mark=fields.get("new-connection-mark", ""),
                new_packet_mark=fields.get("new-packet-mark", ""),
                new_routing_mark=fields.get("new-routing-mark", ""),
                new_dscp=fields.get("new-dscp", ""),
                passthrough=_to_bool(fields["passthrough"]) if "passthrough" in fields else None,
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                src_address_list=fields.get("src-address-list", ""),
                dst_address_list=fields.get("dst-address-list", ""),
                protocol=fields.get("protocol", ""),
                src_port=fields.get("src-port", ""),
                dst_port=fields.get("dst-port", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                in_interface_list=fields.get("in-interface-list", ""),
                out_interface_list=fields.get("out-interface-list", ""),
                connection_mark=fields.get("connection-mark", ""),
                packet_mark=fields.get("packet-mark", ""),
                routing_mark=fields.get("routing-mark", ""),
                connection_state=fields.get("connection-state", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                extra=_extra_fields(fields, _MANGLE_KNOWN),
            )
        )

    def _hook_raw(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.raw_rules.append(
            RawRule(
                chain=fields.get("chain", ""),
                action=fields.get("action", ""),
                address_list=fields.get("address-list", ""),
                address_list_timeout=fields.get("address-list-timeout", ""),
                protocol=fields.get("protocol", ""),
                tls_host=fields.get("tls-host", ""),
                src_address=fields.get("src-address", ""),
                dst_address=fields.get("dst-address", ""),
                src_address_list=fields.get("src-address-list", ""),
                dst_address_list=fields.get("dst-address-list", ""),
                in_interface=fields.get("in-interface", ""),
                out_interface=fields.get("out-interface", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
                extra=_extra_fields(fields, _RAW_KNOWN),
            )
        )

    # -- queues -------------------------------------------------------

    def _hook_queue_type(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.queue_types.append(
            QueueType(
                name=fields.get("name", ""),
                kind=fields.get("kind", ""),
                pcq_classifier=fields.get("pcq-classifier", ""),
                pcq_rate=fields.get("pcq-rate", ""),
                pcq_limit=fields.get("pcq-limit", ""),
                pcq_total_limit=fields.get("pcq-total-limit", ""),
                pcq_burst_rate=fields.get("pcq-burst-rate", ""),
            )
        )

    def _hook_queue_simple(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.queue_simple.append(
            QueueSimple(
                name=fields.get("name", ""),
                target=fields.get("target", ""),
                max_limit=fields.get("max-limit", ""),
                limit_at=fields.get("limit-at", ""),
                burst_limit=fields.get("burst-limit", ""),
                priority=fields.get("priority", ""),
                queue=fields.get("queue", ""),
                parent=fields.get("parent", ""),
                packet_marks=fields.get("packet-marks", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _hook_queue_tree(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.queue_tree.append(
            QueueTree(
                name=fields.get("name", ""),
                parent=fields.get("parent", ""),
                packet_mark=fields.get("packet-mark", ""),
                queue=fields.get("queue", ""),
                max_limit=fields.get("max-limit", ""),
                limit_at=fields.get("limit-at", ""),
                burst_limit=fields.get("burst-limit", ""),
                priority=fields.get("priority", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # -- PPP ----------------------------------------------------------

    def _ppp_default_profile(self, config, name):
        for profile in config.ppp_profiles:
            if profile.name == name:
                return profile
        profile = PppProfile(name=name)
        config.ppp_profiles.append(profile)
        return profile

    def _hook_ppp_profile(self, config, statement, interfaces_by_name):
        if statement.startswith("set"):
            selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
            target = _PPP_DEFAULT_INDEX_NAMES.get(selector.get("__index__", "").upper())
            if target is None and selector.get("default") == "yes":
                target = "default"
            if target is None and selector.get("name"):
                target = selector["name"]
            if target is None:
                return False
            profile = self._ppp_default_profile(config, target)
        else:
            fields = self._add_fields(statement)
            if fields is None:
                return False
            profile = PppProfile(name=fields.get("name", ""))
            config.ppp_profiles.append(profile)
        for attr, key in (
            ("local_address", "local-address"),
            ("remote_address", "remote-address"),
            ("dns_server", "dns-server"),
            ("rate_limit", "rate-limit"),
            ("use_encryption", "use-encryption"),
            ("change_tcp_mss", "change-tcp-mss"),
            ("comment", "comment"),
        ):
            if key in fields:
                setattr(profile, attr, fields[key])

    def _hook_ppp_secret(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        secret = PppSecret(
            name=fields.get("name", ""),
            service=fields.get("service", "any"),
            profile=fields.get("profile", ""),
            local_address=fields.get("local-address", ""),
            remote_address=fields.get("remote-address", ""),
            caller_id=fields.get("caller-id", ""),
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
            password_set=bool(fields.get("password")),
        )
        config.ppp_secrets.append(secret)
        if fields.get("password"):
            self._secret_pool["ppp-secret"].append(
                (secret, secret.name, fields["password"], "password_weak", "password_reused")
            )

    # -- IPsec identity (PSK / certificate) ---------------------------

    def _hook_ipsec_identity(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        method = fields.get("auth-method", "pre-shared-key")
        identity = IpsecIdentity(
            peer=fields.get("peer", ""),
            auth_method=method,
            secret_set=bool(fields.get("secret")),
            certificate=fields.get("certificate", ""),
            mode_config=fields.get("mode-config", ""),
            policy_template_group=fields.get("policy-template-group", ""),
            generate_policy=fields.get("generate-policy", ""),
            my_id=fields.get("my-id", ""),
            remote_id=fields.get("remote-id", ""),
            comment=fields.get("comment", ""),
            disabled=_to_bool(fields.get("disabled")),
        )
        config.ipsec_identities.append(identity)
        if fields.get("secret"):
            self._secret_pool["ipsec-psk"].append(
                (identity, identity.peer, fields["secret"], "secret_weak", "secret_reused")
            )

    # -- SNMP ---------------------------------------------------------

    def _hook_snmp(self, config, statement, interfaces_by_name):
        if not statement.startswith("set"):
            return False
        _selector, body = _split_selector(statement[len("set"):].strip())
        fields = _parse_kv(body)
        snmp = config.snmp
        if "enabled" in fields:
            snmp.enabled = _to_bool(fields["enabled"])
        for attr, key in (
            ("contact", "contact"),
            ("location", "location"),
            ("trap_community", "trap-community"),
            ("trap_target", "trap-target"),
            ("trap_version", "trap-version"),
            ("trap_interfaces", "trap-interfaces"),
        ):
            if key in fields:
                setattr(snmp, attr, fields[key])

    def _hook_snmp_community(self, config, statement, interfaces_by_name):
        if statement.startswith("set"):
            selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
            if selector.get("default") == "yes":
                name = "public"          # the built-in community
            elif selector.get("name"):
                name = selector["name"]
            else:
                return False
            community = next((c for c in config.snmp_communities if c.name == name), None)
            if community is None:
                community = SnmpCommunity(name=name)
                config.snmp_communities.append(community)
        else:
            fields = self._add_fields(statement)
            if fields is None:
                return False
            community = SnmpCommunity(name=fields.get("name", ""))
            config.snmp_communities.append(community)
        if "name" in fields:
            community.name = fields["name"]
        if "addresses" in fields:
            community.addresses = fields["addresses"]
        if "security" in fields:
            community.security = fields["security"]
        if "read-access" in fields:
            community.read_access = _to_bool(fields["read-access"])
        if "write-access" in fields:
            community.write_access = _to_bool(fields["write-access"])
        if fields.get("authentication-password"):
            community.authentication_password_set = True
        if fields.get("encryption-password"):
            community.encryption_password_set = True
        if "disabled" in fields:
            community.disabled = _to_bool(fields["disabled"])

    # -- local users / scheduler / netwatch ---------------------------

    def _hook_user(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.local_users.append(
            LocalUser(
                name=fields.get("name", ""),
                group=fields.get("group", ""),
                address=fields.get("address", ""),
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _hook_scheduler(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.scheduler_entries.append(
            SchedulerEntry(
                name=fields.get("name", ""),
                on_event=_redact_secret_values(fields.get("on-event", ""))[:300],
                interval=fields.get("interval", ""),
                start_time=fields.get("start-time", ""),
                disabled=_to_bool(fields.get("disabled")),
                comment=fields.get("comment", ""),
            )
        )

    def _hook_netwatch(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.netwatch_entries.append(
            NetwatchEntry(
                host=fields.get("host", ""),
                interval=fields.get("interval", ""),
                down_script=_redact_secret_values(fields.get("down-script", ""))[:300],
                up_script=_redact_secret_values(fields.get("up-script", ""))[:300],
                comment=fields.get("comment", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    # -- dynamic routing ----------------------------------------------

    def _hook_ospf_instance(self, config, statement, interfaces_by_name):
        if statement.startswith("set"):
            selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
            name = "default" if selector.get("default") == "yes" else selector.get("name")
            if not name:
                return False
            instance = next((i for i in config.ospf_instances if i.name == name), None)
            if instance is None:
                instance = OspfInstance(name=name)
                config.ospf_instances.append(instance)
        else:
            fields = self._add_fields(statement)
            if fields is None:
                return False
            instance = OspfInstance(name=fields.get("name", "default"))
            config.ospf_instances.append(instance)
        if "router-id" in fields:
            instance.router_id = fields["router-id"]
        redistributed = [k.replace("redistribute-", "") for k, v in fields.items()
                         if k.startswith("redistribute") and v not in ("no", "")]
        if redistributed:
            instance.redistribute = ",".join(redistributed)
        if "disabled" in fields:
            instance.disabled = _to_bool(fields["disabled"])

    def _hook_ospf_network(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.ospf_networks.append(
            OspfNetwork(
                network=fields.get("network", ""),
                area=fields.get("area", ""),
                disabled=_to_bool(fields.get("disabled")),
                comment=fields.get("comment", ""),
            )
        )

    def _hook_ospf_template(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.ospf_networks.append(
            OspfNetwork(
                network=fields.get("networks") or fields.get("interfaces", ""),
                area=fields.get("area", ""),
                disabled=_to_bool(fields.get("disabled")),
                comment=fields.get("comment", ""),
            )
        )

    def _hook_bgp_peer(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        config.bgp_peers.append(
            BgpPeer(
                name=fields.get("name", ""),
                remote_address=fields.get("remote-address") or fields.get("remote.address", ""),
                remote_as=fields.get("remote-as") or fields.get("remote.as", ""),
                local_as=fields.get("local.as") or fields.get("as", ""),
                instance=fields.get("instance", ""),
                update_source=fields.get("update-source") or fields.get("local.address", ""),
                md5_key_set=bool(fields.get("tcp-md5-key")),
                disabled=_to_bool(fields.get("disabled")),
                comment=fields.get("comment", ""),
            )
        )

    # -- logging ------------------------------------------------------

    def _hook_logging(self, config, statement, interfaces_by_name):
        if statement.startswith("add"):
            fields = _parse_kv(statement[len("add"):].strip())
        elif statement.startswith("set"):
            _selector, body = _split_selector(statement[len("set"):].strip())
            fields = _parse_kv(body)
        else:
            return False
        config.logging_rules.append(
            LoggingRule(
                topics=fields.get("topics", ""),
                action=fields.get("action", ""),
                prefix=fields.get("prefix", ""),
                disabled=_to_bool(fields.get("disabled")),
            )
        )

    def _hook_logging_action(self, config, statement, interfaces_by_name):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        if fields.get("target") == "remote" and fields.get("remote"):
            key = "/system logging action remote-targets"
            existing = config.system_settings.get(key, "")
            config.system_settings[key] = f"{existing},{fields['remote']}".strip(",")
            return True
        return False

    # -- tunnels / VPN servers / flat settings -------------------------

    def _hook_tunnel_interface(self, config, statement, interfaces_by_name, kind):
        fields = self._add_fields(statement)
        if fields is None:
            return False
        name = fields.get("name")
        if not name:
            return False
        interface = interfaces_by_name.get(name)
        if interface is None:
            interface = Interface(name=name, interface_type=kind)
            config.interfaces.append(interface)
            interfaces_by_name[name] = interface
        else:
            interface.interface_type = kind
        interface.comment = fields.get("comment", interface.comment)
        interface.disabled = _to_bool(fields.get("disabled"))
        interface.mtu = _to_int(fields.get("mtu")) if "mtu" in fields else interface.mtu
        interface.remote_address = fields.get("connect-to") or fields.get("remote-address", "")
        interface.local_address = fields.get("local-address", "")
        tunnel_id = fields.get("tunnel-id") or fields.get("vrid")
        interface.tunnel_id = _to_int(tunnel_id)
        interface.user = fields.get("user", "")
        if kind == "bonding":
            interface.parent_interface = fields.get("slaves", "")
        elif kind == "vrrp":
            interface.parent_interface = fields.get("interface", "")
        if fields.get("password"):
            counter = f"{kind}-password"
            config.clear_text_secrets[counter] = config.clear_text_secrets.get(counter, 0) + 1

    def _hook_vpn_server(self, config, statement, interfaces_by_name, kind):
        if not statement.startswith("set"):
            return False
        _selector, body = _split_selector(statement[len("set"):].strip())
        fields = _parse_kv(body)
        server = next((s for s in config.vpn_servers if s.kind == kind), None)
        if server is None:
            server = VpnServer(kind=kind)
            config.vpn_servers.append(server)
        if "enabled" in fields:
            server.enabled = _to_bool(fields["enabled"])
        server.authentication = fields.get("authentication", server.authentication)
        server.default_profile = fields.get("default-profile", server.default_profile)
        server.use_ipsec = fields.get("use-ipsec", server.use_ipsec)
        server.keepalive_timeout = fields.get("keepalive-timeout", server.keepalive_timeout)
        if fields.get("ipsec-secret"):
            server.ipsec_secret_set = True
            self._secret_pool["l2tp-ipsec-secret"].append(
                (server, kind, fields["ipsec-secret"], "ipsec_secret_weak", None)
            )

    def _hook_settings(self, config, statement, interfaces_by_name, section):
        if not statement.startswith("set"):
            return False
        _selector, body = _split_selector(statement[len("set"):].strip())
        stored = False
        for key, value in _parse_kv(body).items():
            if _SECRETISH_KEY_RE.search(key):
                continue
            config.system_settings[f"{section} {key}"] = value[:200]
            stored = True
        return stored

    # ====================================================
    # SECRET POST-PASS
    # ====================================================

    def _finalize_secrets(self, config):
        """
        Flags weak / reused credentials, records how many are stored in
        clear text and then discards the values. Nothing derived here
        lets anybody recover a password: only booleans and counts are
        written to the model.
        """

        pool = getattr(self, "_secret_pool", {})
        for kind, entries in pool.items():
            if not entries:
                continue
            seen = {}
            for _obj, _owner, value, _weak_attr, _reused_attr in entries:
                seen[value] = seen.get(value, 0) + 1
            for obj, owner, value, weak_attr, reused_attr in entries:
                setattr(obj, weak_attr, _is_weak_secret(value, owner))
                if reused_attr:
                    setattr(obj, reused_attr, seen[value] > 1)
            config.clear_text_secrets[kind] = len(entries)

        legacy_snmp = [c for c in config.snmp_communities if c.security in ("", "none")]
        if legacy_snmp:
            config.clear_text_secrets["snmp-community"] = len(legacy_snmp)

        self._secret_pool = {}

    # ====================================================
    # POST-PASSES
    # ====================================================

    @staticmethod
    def _attach_bridge_ports(config, bridge_port_membership):
        """
        Reconciles "/interface bridge port" membership (collected as
        plain name lists, see _handle_bridge_port) against the actual
        bridge Interface objects, once the whole file has been read.
        Doing this as a single post-pass -- rather than looking the
        bridge up while reading each bridge-port line -- means port
        lines can appear before or after their bridge's own "add" line
        without needing two different code paths.
        """

        for bridge_name, members in bridge_port_membership.items():
            bridge = config.find_interface(bridge_name)
            if bridge is None:
                bridge = Interface(name=bridge_name, interface_type="bridge")
                config.interfaces.append(bridge)
            for port in members:
                if port not in bridge.bridge_ports:
                    bridge.bridge_ports.append(port)
