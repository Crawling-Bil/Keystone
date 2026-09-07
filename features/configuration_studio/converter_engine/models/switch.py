from dataclasses import dataclass, field
from typing import Optional

from features.configuration_studio.converter_engine.models.network import BaseConfig


@dataclass
class VLAN:
    vlan_id: int
    name: str = ""

    tagged_ports: list[str] = field(
        default_factory=list
    )

    untagged_ports: list[str] = field(
        default_factory=list
    )


@dataclass
class Interface:
    name: str
    description: str = ""

    interface_type: str = ""

    shutdown: bool = False

    # access / trunk / routed
    mode: str = ""

    access_vlan: Optional[int] = None
    native_vlan: Optional[int] = None

    allowed_vlans: list[str] = field(
        default_factory=list
    )

    ip_address: str = ""
    subnet_mask: str = ""

    channel_group: Optional[int] = None
    lacp_mode: str = ""

    # HSRP (Cisco "hsrp <group>" sub-block under an SVI/routed
    # interface) — Huawei's equivalent is VRRP. Only the fields this
    # project's real Nexus source actually showed are captured
    # (priority, hello timer, virtual IP, preempt) — see cisco.py's
    # parse_interface_command and huawei.py's translate_hsrp_to_vrrp.
    # This is a classic Cisco IOS feature too, not NX-OS-exclusive —
    # translation is gated on hsrp_group being set, not on platform
    # family.
    hsrp_group: Optional[int] = None
    hsrp_priority: Optional[int] = None
    hsrp_hello_interval: Optional[int] = None
    hsrp_hold_interval: Optional[int] = None
    hsrp_virtual_ip: str = ""

    # True only when the source explicitly configured "preempt" under
    # this hsrp group. Cisco HSRP defaults to preempt DISABLED, so a
    # False here is ambiguous on its own (could mean "explicitly not
    # wanted" or just "never touched") -- but since Huawei VRRP
    # defaults to preempt ENABLED, that ambiguity is exactly what
    # matters: True means the source really did want preemption (a
    # confirmed 1:1 match with VRRP's default, nothing to flag); False
    # means VRRP's default is a behavioral CHANGE from HSRP's real
    # default state, worth a review note.
    hsrp_preempt: bool = False

    # VRRP (Huawei "vrrp vrid <id> virtual-ip <vip>" under an SVI/routed
    # interface) — the Huawei equivalent of hsrp_* above. Only the form
    # confirmed on a real S5755 M-LAG pair (TTC-SWCODI-MN/BU-DMZ) is
    # captured — a bare "vrrp vrid <id> virtual-ip <vip>" with no
    # priority/preempt/track sub-commands in either real source file.
    # service.py's analyzer surfaces whichever of hsrp_virtual_ip /
    # vrrp_virtual_ip is set under one vendor-neutral "HSRP/VRRP IP"
    # column rather than requiring two separate columns.
    vrrp_vrid: Optional[int] = None
    vrrp_virtual_ip: str = ""

    # PoE (Huawei "poe enable" / "undo poe enable", interface-view).
    # Only ever seen in this project's real captures as CONFIG intent —
    # no real capture has a live per-port PoE table (Huawei's own
    # "display poe information" / "display poe-power" only ever print a
    # slot/PSE-level power budget, never a per-port state), so this is
    # the only place a Huawei PoE-capable port's enabled state comes
    # from. See service.py's PoE config-only fallback (mirrors the
    # vPC/M-LAG and stack config-only fallback pattern).
    poe_enabled: bool = False

    # vPC (Cisco NX-OS "vpc peer-link" / "vpc <id>" interface
    # sub-commands, only meaningful alongside a global "vpc domain"
    # block — see SwitchConfig.vpc_domain_id below). Huawei's
    # equivalent is M-LAG. NX-OS-exclusive by construction: neither
    # command exists outside a vPC-capable NX-OS platform.
    is_vpc_peer_link: bool = False
    vpc_id: Optional[int] = None

    # Huawei M-LAG interface sub-commands, the vPC-above's Huawei
    # equivalent — "peer-link <n>" (Eth-Trunk carrying the M-LAG peer
    # session) and "dfs-group <n> m-lag <id>" (an Eth-Trunk bound to the
    # DFS group as an M-LAG member port). Confirmed real VRP syntax on a
    # real S5755 M-LAG pair (TTC-SWCODI-MN/BU-DMZ). Only meaningful
    # alongside SwitchConfig.mlag_dfs_group_id.
    is_mlag_peer_link: bool = False
    mlag_id: Optional[int] = None

    spanning_tree_portfast: bool = False
    bpduguard: bool = False

    # Root Guard / Loop Guard (Cisco "spanning-tree guard root" /
    # "spanning-tree guard loop"). Huawei's equivalents ("stp
    # root-protection" / "stp loop-protection") are mutually exclusive
    # on the same port — see huawei.py's translate_interface.
    spanning_tree_root_guard: bool = False
    spanning_tree_loop_guard: bool = False

    # BPDU Filter (Cisco "spanning-tree bpdufilter enable"). Unlike
    # bpduguard above — whose Huawei equivalent ("stp bpdu-protection")
    # is a GLOBAL command — Huawei's BPDU Filter equivalent ("stp
    # bpdu-filter enable") is genuinely per-interface.
    bpdufilter: bool = False

    # Voice VLAN (Cisco "switchport voice vlan <id>"). Only the
    # numeric-ID form is captured — see cisco.py's parse_interface_command.
    voice_vlan_id: Optional[int] = None

    # LLDP per-interface transmit/receive (Cisco "no lldp transmit" /
    # "no lldp receive"). Huawei has no independent per-direction
    # toggle — huawei.py maps these onto "lldp admin-status
    # {tx|rx|txrx}" / "lldp disable".
    lldp_transmit_disabled: bool = False
    lldp_receive_disabled: bool = False

    helper_addresses: list[str] = field(
        default_factory=list
    )

    ospf_process: Optional[int] = None
    ospf_area: str = ""
    ospf_network_type: str = ""

    netstream_inbound: bool = False
    netstream_outbound: bool = False

    port_security_enabled: bool = False
    port_security_max: Optional[int] = None
    port_security_violation: str = ""
    port_security_sticky: bool = False
    port_security_sticky_macs: list[str] = field(
        default_factory=list
    )

    # Storm control (Cisco "storm-control {broadcast|multicast|unicast}
    # level <pct>" + "storm-control action {shutdown|trap}"). Percent
    # values are stored as strings since Cisco allows a decimal
    # (e.g. "80.5"); action is normalized to Cisco's own keyword
    # ("shutdown" / "trap") and mapped to VRP syntax at translation time.
    storm_control_broadcast_level: Optional[str] = None
    storm_control_multicast_level: Optional[str] = None
    storm_control_unicast_level: Optional[str] = None
    storm_control_action: str = ""

    # DHCP snooping trust + IP Source Guard (Cisco "ip dhcp snooping
    # trust" / "ip verify source"). Huawei's default trust state
    # (untrusted) matches Cisco's, so this is a direct 1:1 flag with
    # no inversion needed — see huawei.py's translate_interface.
    dhcp_snooping_trusted: bool = False
    ip_source_guard_enabled: bool = False

    # DHCP snooping flood rate limit (Cisco "ip dhcp snooping limit
    # rate <pps>", interface-view). Huawei's equivalent, "dhcp
    # snooping check dhcp-rate enable" + "dhcp snooping check
    # dhcp-rate <pps>", also supports system/VLAN scope, but only the
    # interface-view form is captured here — a direct 1:1 match for
    # Cisco's own interface-only command. V600R025C00 IP Addresses
    # and Services guide, DHCP Snooping Configuration, Section 10.6.2,
    # p.528 — default: disabled; once enabled, default max 5000 pps
    # (Keystone always emits an explicit value, so that default never
    # applies to translated output).
    dhcp_snooping_rate_limit_pps: Optional[int] = None

    vrf_forwarding: str = ""

    # PBR (Cisco "ip policy route-map <name>", interface-view) --
    # Huawei's equivalent is applying the MQC traffic-policy chain
    # that the same-named route-map translates to via "traffic-policy
    # <name> inbound" -- see huawei.py's translate_pbr /
    # translate_interface. TAM memory-keystone.md Sections 1kk/1ll.
    ip_policy_route_map: str = ""

    # Plain interface ACL application (Cisco "ip access-group <acl>
    # {in|out}") -- distinct from PBR above (no route-map/track
    # involved, just a straight permit-list packet filter). CloudEngine
    # VRP has no 1:1 "apply this ACL to this interface" command either
    # -- same MQC mechanism as PBR (traffic classifier/behavior/policy
    # -> "traffic-policy <name> {inbound|outbound}"), just with a
    # plain "permit" behavior instead of a redirect-nexthop one. See
    # huawei.py's translate_acl_application / translate_interface.
    # TAM memory-keystone.md Section 1aa (closes Section 1a finding 6).
    access_group_in: str = ""
    access_group_out: str = ""

    # PBR application, Huawei-native form ("traffic-policy <name>
    # {inbound|outbound}", interface-view) -- the Huawei-side
    # counterpart of ip_policy_route_map above, confirmed real and
    # LIVE DEPLOYED on a real S5755 (GTOPAS-MKS-SWCODI-S5755-FIX.txt:
    # "interface Vlanif109" / " traffic-policy LINTAS inbound"). See
    # models/switch.py's TrafficPolicy. TAM memory-keystone.md
    # Section 1ac.
    traffic_policy_inbound: str = ""
    traffic_policy_outbound: str = ""

    commands: list[str] = field(
        default_factory=list
    )


@dataclass
class IpSlaEntry:
    """
    Cisco "ip sla <id>" body (nested "icmp-echo <dest-ip>" /
    "frequency <n>" / "timeout <n>"). Only meaningful when a matching
    "track <id> ip sla <sla-id> reachability" line also exists AND is
    itself referenced by a live route-map clause -- Cisco's track/
    ip-sla pair collapses into a single Huawei "nqa test-instance"
    object at translation time (huawei.py's translate_nqa; TAM
    memory-keystone.md Section 1kk). A bare "ip sla <id>" with no
    icmp-echo body, or one nothing live references, is dangling/dead
    config and is not translated -- see translate_nqa's completeness
    check.
    """
    sla_id: int
    test_type: str = ""       # "icmp-echo" -- the only real type seen
    destination: str = ""     # icmp-echo target IP
    frequency: Optional[int] = None
    timeout: Optional[int] = None


@dataclass
class TrackObject:
    """
    Cisco "track <id> ip sla <sla-id> reachability" OR Huawei's own
    "track <id> nqa admin <test-name>" -- a thin naming wrapper only.
    On Cisco hardware this folds directly into whichever "nqa
    test-instance" replaces the referenced ip_sla entry at
    translation time (see huawei.py's translate_nqa); on real Huawei
    hardware it's a standalone numbered object in its own right,
    confirmed real VRP syntax (this project's own NQA + Track
    template, draft_huawei_master.txt / ADM-SWCODI-S5755.txt).
    Exactly one of sla_id/nqa_name is set depending on which vendor's
    config this came from. Single-line in every real example seen in
    this project (no "delay up/down" sub-block captured).
    """
    track_id: int
    sla_id: Optional[int] = None
    nqa_name: Optional[str] = None


@dataclass
class NqaTestInstance:
    """
    Huawei "nqa test-instance admin <name>" -- the Huawei-native
    equivalent of Cisco's IpSlaEntry above. Confirmed real and LIVE
    DEPLOYED backing a Policy-Based Routing redirect
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt):

        nqa test-instance admin gtopas_mks_lintas
         test-type icmp
         destination-address ipv4 172.20.20.26
         timeout 1
         frequency 9
         start now

    "probe-count <n>" appears in this project's own draft template
    (ADM-SWCODI-S5755.txt) but was absent from the real deployed
    capture above, so it's parsed when present but never assumed.
    TAM memory-keystone.md Section 1ac.
    """
    test_name: str
    test_type: str = ""
    destination: str = ""
    frequency: Optional[int] = None
    probe_count: Optional[int] = None
    timeout: Optional[int] = None
    start_now: bool = False


@dataclass
class TrafficClassifier:
    """
    Huawei "traffic classifier <name> type or|and" + one or more
    "if-match acl <n>" lines -- the match half of Huawei's MQC PBR
    chain (the Huawei-native equivalent of a Cisco route-map clause's
    "match ip address <acl>"). Confirmed real and LIVE DEPLOYED
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt): "traffic classifier LINTAS
    type or" / "if-match acl 3001". TAM memory-keystone.md Section
    1ac.
    """
    name: str
    match_type: str = "or"
    acl_numbers: list[str] = field(default_factory=list)


@dataclass
class TrafficBehavior:
    """
    Huawei "traffic behavior <name>" + a "redirect nexthop <ip>
    track nqa admin <name>" (or "... track <id>" against a
    standalone numbered track object) action line -- the action half
    of Huawei's MQC PBR chain, the Huawei-native equivalent of a
    Cisco route-map clause's "set ip next-hop verify-availability
    ... track <id>". Confirmed real and LIVE DEPLOYED
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt): "traffic behavior LINTAS" /
    "redirect nexthop 172.29.88.2 track nqa admin
    gtopas_mks_lintas". TAM memory-keystone.md Section 1ac.
    """
    name: str
    redirect_next_hop: str = ""
    track_id: Optional[int] = None
    track_nqa_name: Optional[str] = None


@dataclass
class TrafficPolicyBinding:
    """One "classifier <c> behavior <b> precedence <n>" line inside a
    "traffic policy <name>" block."""
    classifier: str
    behavior: str
    precedence: Optional[int] = None


@dataclass
class TrafficPolicy:
    """
    Huawei "traffic policy <name>" + one or more "classifier <c>
    behavior <b> precedence <n>" bindings -- ties a TrafficClassifier
    to a TrafficBehavior. Applied to an interface via "traffic-policy
    <name> {inbound|outbound}" (see Interface.traffic_policy_inbound/
    outbound below) -- the Huawei-native equivalent of Cisco's "ip
    policy route-map <name>". Confirmed real and LIVE DEPLOYED
    (GTOPAS-MKS-SWCODI-S5755-FIX.txt): "traffic policy LINTAS" /
    "classifier LINTAS behavior LINTAS precedence 5", applied on
    Vlanif109/Vlanif494 inbound. TAM memory-keystone.md Section 1ac.
    """
    name: str
    bindings: list["TrafficPolicyBinding"] = field(default_factory=list)


@dataclass
class EemPbrBinding:
    """
    Cisco "event manager applet <name>" block whose actions toggle
    PBR on/off via "ip policy route-map <name>" / "no ip policy
    route-map <name>" CLI commands -- a REAL, currently-active
    pattern on TAM 2026's Catalyst 3650 stacks (GTOPAS-PKU/MND/SMG/
    MKS-SWCO-C3650.txt real backups). In every one of those real
    captures the route-map is NEVER statically bound under any
    interface's own config (Interface.ip_policy_route_map stays
    blank) -- it's applied dynamically instead, triggered by an SNMP
    OID link-state watch on an upstream router. This is exactly the
    kind of "hidden custom routing behavior" a plain interface dump
    or "show ip route" can't reveal, so it's captured here for
    analyzer visibility even though (per TAM memory-keystone.md
    Section 1ll Part 1's confirmed, doc-verified finding) it is
    deliberately NOT replicated by the Cisco->Huawei translator --
    VRP's own default redirect-nexthop fallback already covers what
    the EEM applet was manually engineering. TAM memory-keystone.md
    Section 1ac.
    """
    applet_name: str
    route_map_name: str
    action: str = ""  # "enable" ("ip policy route-map ...") or "disable" ("no ip policy route-map ...")
    target_interfaces: list[str] = field(default_factory=list)
    trigger_description: str = ""


@dataclass
class RouteMapClause:
    """
    One "route-map <name> {permit|deny} <sequence>" clause. Only the
    fields this project's real PBR next-hop-tracking pattern actually
    uses are captured (match-by-ACL, next-hop-verify-availability
    with a track reference) -- see cisco.py's route-map parsing and
    huawei.py's translate_pbr. TAM memory-keystone.md Sections
    1kk/1ll.
    """
    sequence: int
    action: str = "permit"
    match_acl: str = ""
    set_next_hop: str = ""
    set_next_hop_track_id: Optional[int] = None


@dataclass
class RouteMap:
    name: str
    clauses: list["RouteMapClause"] = field(
        default_factory=list
    )


@dataclass
class StaticRoute:
    destination: str
    mask: str
    next_hop: str

    distance: Optional[int] = None
    description: str = ""

    # Optional trailing "track <id>" clause tying this route to a
    # TrackObject (withdrawn from the routing table when the tracked
    # SLA/NQA test fails). Confirmed real VRP syntax (this project's
    # own draft_huawei_master.txt NQA+Track template: "ip route-static
    # 0.0.0.0 0.0.0.0 10.x.x.x track 1"), though not yet seen deployed
    # live on any real TAM capture -- parsed whenever present, the
    # same way `distance`/"preference" already is, never silently
    # dropped. TAM memory-keystone.md Section 1ac.
    track_id: Optional[int] = None


@dataclass
class DhcpPool:
    name: str
    network: str = ""
    mask: str = ""
    gateway: list[str] = field(
        default_factory=list
    )
    dns_servers: list[str] = field(
        default_factory=list
    )
    domain_name: str = ""
    lease: str = ""
    options: list[str] = field(
        default_factory=list
    )


@dataclass
class StackMemberConfig:
    """One statically-declared Huawei iStack/CSS member, from 'stack
    member <n> renumber <n>' / 'stack member <n> priority <n>'. See
    SwitchConfig.stack_members_config."""
    member_id: int
    priority: Optional[int] = None


@dataclass
class SwitchConfig(BaseConfig):

    default_gateway: str = ""

    # Cisco platform family, auto-detected from source-exclusive syntax
    # markers (CiscoSwitchParser.detect_platform_family) — "nxos" or
    # "ios". Deliberately NOT a manual/user-supplied field: unlike
    # target_model (which can't be inferred from the source at all),
    # NX-OS proves its own identity through syntax Catalyst IOS/IOS-XE
    # never uses (boot nxos, vrf context, vpc, a literal "mgmt0"
    # interface), so requiring a manual selector here would be pure
    # friction — confirmed decision, memory-tam-2026-huawei-switch.md
    # cross-project note / memory-keystone.md Section 1k. Empty string
    # means detection found no NX-OS-exclusive marker (treat as
    # classic IOS — the same REVIEW-CISCO passthrough behavior as
    # before this field existed, never silently wrong).
    platform_family: str = ""

    # vPC domain (Cisco NX-OS "vpc domain <id>" global block) — Huawei
    # equivalent is M-LAG's "dfs-group <id>". Only the sub-command
    # this project's real source config showed a clean field-mapping
    # for is captured structurally (peer-keepalive's source/dest/vrf,
    # -> Huawei's "dual-active detection source ip ... peer ...");
    # every other sub-command seen (peer-gateway, auto-recovery, ip
    # arp synchronize) is preserved verbatim in vpc_domain_commands for
    # REVIEW rather than guessed — confirmed against the real M-LAG
    # Configuration Guide (V600R025C00 High Availability) that none of
    # those Cisco vPC refinements have a directly equivalent M-LAG
    # command (M-LAG's own "error-down auto-recovery" mechanism is a
    # different, unrelated feature from vPC's "auto-recovery" reload-
    # safety timer, for example — a same-name coincidence, not a real
    # command mapping). "peer-switch" and "delay restore <n>" now DO
    # have confirmed, real-hardware-verified M-LAG mappings (memory-
    # keystone.md Sections 1cc/1ee/1ff) and are captured structurally
    # below instead of falling into the generic REVIEW bucket.
    vpc_domain_id: Optional[int] = None
    vpc_peer_keepalive_source_ip: str = ""
    vpc_peer_keepalive_dest_ip: str = ""
    vpc_peer_keepalive_vrf: str = ""

    # Optional "interval <ms> timeout <sec>" suffix on the Cisco
    # "peer-keepalive destination ... source ... vrf ..." line —
    # maps directly to M-LAG's "dual-active detection ... timeout
    # <seconds>" (memory-keystone.md Section 1cc finding A). Empty
    # when the source line didn't carry an explicit timeout; never
    # guessed.
    vpc_peer_keepalive_timeout: str = ""

    # Cisco vPC "peer-switch" (bare, under "vpc domain <id>") — maps
    # to Huawei M-LAG's root-bridge-mode STP block (stp enable / stp
    # instance 0 root primary / stp bridge-address <shared-MAC> / stp
    # bpdu-protection) plus a required stp region-configuration block,
    # both real-hardware-confirmed on TAM's M-LAG pair (memory-
    # keystone.md Sections 1ee finding F, 1ff finding K). Both halves
    # need the OTHER M-LAG peer device's own real data (system MAC /
    # region-name) to fill in a real value rather than a REVIEW
    # placeholder — Keystone's pipeline currently translates one
    # device at a time with no paired-peer input, so these are
    # optional fields a caller can supply when that data is available;
    # left blank, the translator emits a REVIEW-flagged placeholder
    # with the doc-cited computation steps instead of guessing.
    vpc_peer_switch: bool = False
    mlag_peer_bridge_mac: str = ""
    mlag_stp_region_name: str = ""
    mlag_stp_revision_level: Optional[int] = None

    # Cisco vPC "delay restore <seconds>" (under "vpc domain <id>") —
    # maps directly to Huawei M-LAG's "m-lag up-delay <seconds>"
    # (memory-keystone.md Section 1cc finding B — a real correction to
    # this project's own earlier claim that no equivalent existed).
    vpc_delay_restore_seconds: Optional[int] = None

    vpc_domain_commands: list[str] = field(
        default_factory=list
    )

    # Huawei iStack/CSS static stack-formation commands ("stack" / "stack
    # member <n> renumber <n>" / "stack member <n> priority <p>"). A
    # draft config that has never been deployed has no "display stack"
    # runtime table at all (no live stack to show), so this is the only
    # place stack membership shows up for it — confirmed on a real S5755
    # draft with two "stack member N renumber N" blocks and no live
    # stack section anywhere in the file. Modeled as one entry per
    # declared member rather than a bare count so the config-only
    # fallback can still show a Member ID / Priority table like the live
    # "display stack" one does.
    stack_members_config: list[StackMemberConfig] = field(
        default_factory=list
    )

    # Huawei M-LAG global block ("dfs-group <id>") — the Huawei
    # equivalent of vpc_domain_id/vpc_peer_keepalive_* above. Confirmed
    # real VRP syntax on a real S5755 M-LAG pair:
    #
    #   dfs-group 1
    #    priority 100
    #    dual-active detection source ip 1.1.1.5 peer 1.1.1.6 timeout 5
    #
    # "dual-active detection" is M-LAG's peer-keepalive equivalent —
    # "source ip" is this switch's own address, "peer" is the other
    # M-LAG switch's address (a real, distinct sub-command, not to be
    # confused with vPC's "peer-keepalive destination/source" pair,
    # even though both surface as "peer-keepalive IP" / "peer IP" on
    # the analyzer's vPC/M-LAG tab).
    mlag_dfs_group_id: Optional[int] = None
    mlag_priority: Optional[int] = None
    mlag_dual_active_source_ip: str = ""
    mlag_dual_active_peer_ip: str = ""

    vlans: list[VLAN] = field(
        default_factory=list
    )

    interfaces: list[Interface] = field(
        default_factory=list
    )

    routes: list[StaticRoute] = field(
        default_factory=list
    )

    dhcp_pools: list[DhcpPool] = field(
        default_factory=list
    )

    snmp_commands: list[str] = field(
        default_factory=list
    )

    aaa_commands: list[str] = field(
        default_factory=list
    )

    tacacs_commands: list[str] = field(
        default_factory=list
    )

    radius_commands: list[str] = field(
        default_factory=list
    )

    ospf_commands: list[str] = field(
        default_factory=list
    )

    eigrp_commands: list[str] = field(
        default_factory=list
    )

    acl_commands: list[str] = field(
        default_factory=list
    )

    # PBR next-hop tracking (Cisco "track <id> ip sla <sla-id>
    # reachability" + "ip sla <sla-id>" + "route-map ... set ip
    # next-hop verify-availability ... track <id>") -- Huawei
    # equivalent is "nqa test-instance" + the MQC redirect chain, see
    # huawei.py's translate_nqa / translate_pbr. TAM
    # memory-keystone.md Sections 1kk/1ll.
    ip_sla_entries: list[IpSlaEntry] = field(
        default_factory=list
    )

    track_objects: list[TrackObject] = field(
        default_factory=list
    )

    route_maps: list[RouteMap] = field(
        default_factory=list
    )

    # Huawei-native PBR/NQA -- the Huawei-side counterparts of
    # ip_sla_entries/route_maps above (Cisco has no equivalent of
    # these three; Huawei has no equivalent of RouteMap). See
    # NqaTestInstance/TrafficClassifier/TrafficBehavior/TrafficPolicy
    # in this module. TAM memory-keystone.md Section 1ac.
    nqa_test_instances: list[NqaTestInstance] = field(
        default_factory=list
    )

    traffic_classifiers: list[TrafficClassifier] = field(
        default_factory=list
    )

    traffic_behaviors: list[TrafficBehavior] = field(
        default_factory=list
    )

    traffic_policies: list[TrafficPolicy] = field(
        default_factory=list
    )

    # Cisco-only: EEM applets that dynamically toggle PBR on/off --
    # see EemPbrBinding above. Empty for every other vendor/parser.
    eem_pbr_bindings: list[EemPbrBinding] = field(
        default_factory=list
    )

    dhcp_commands: list[str] = field(
        default_factory=list
    )

    # DHCP snooping (Cisco "ip dhcp snooping" global enable +
    # "ip dhcp snooping vlan <list>"). dhcp_snooping_vlans holds each
    # raw list-spec string as parsed (e.g. "10,20,30-35") — expanded
    # into individual VLAN IDs at translation time.
    dhcp_snooping_enabled: bool = False
    dhcp_snooping_vlans: list[str] = field(
        default_factory=list
    )

    # LLDP (Cisco global "lldp run"). True only when the source config
    # explicitly enables LLDP. Huawei ships with LLDP globally enabled
    # by default (opposite of Cisco) — see huawei.py's translate() for
    # the inversion this requires.
    lldp_enabled: bool = False

    # CDP, GLOBAL DISABLE (Cisco "no cdp run"). Cisco CDP has NO
    # equivalent protocol on Huawei at all (not even a differently-
    # named one) — Huawei's only standards-based neighbor-discovery
    # protocol is LLDP. This field exists purely to distinguish two
    # very different real-world intents behind a source config that
    # never enabled LLDP: (a) "no cdp run" present -> the network
    # operator deliberately disabled ALL neighbor discovery (a genuine
    # hardening posture, matched by also disabling LLDP on Huawei), vs
    # (b) neither line present -> Cisco's real default state is CDP
    # ON / LLDP off, i.e. neighbor discovery WAS wanted, just via CDP
    # instead of LLDP — see huawei.py's translate() for how this
    # decides whether LLDP should be left enabled on the Huawei side
    # despite the source never explicitly turning it on.
    cdp_disabled: bool = False

    # DHCP Snooping Option 82 (Cisco global "ip dhcp snooping
    # information option"). Huawei's equivalent, "dhcp option82
    # {insert|rebuild} enable", is scoped the same way as "dhcp
    # snooping enable" itself (VLAN/interface/BD view) — rendered
    # alongside the existing per-VLAN dhcp_snooping_vlans loop at
    # translation time rather than needing its own scope list.
    # V600R025C00 IP Addresses and Services guide, DHCP Snooping
    # Configuration, Section 10.8, pp.538-543. Default: disabled.
    dhcp_snooping_option82_enabled: bool = False

    # BPDU Guard, GLOBAL form (Huawei "stp bpdu-protection",
    # system-view — V600R025C00 Ethernet Switching guide, STP RSTP
    # MSTP Configuration, p.75/564). This is distinct from
    # Interface.bpduguard, which tracks Cisco's genuinely per-
    # interface "spanning-tree bpduguard enable" — the two map to the
    # same Huawei command from opposite directions (see huawei.py's
    # translate() for the Cisco-source direction; HuaweiSwitchParser
    # sets this field directly when Huawei is the source, closing the
    # mirror-image parser gap flagged in memory-keystone.md Section 1f).
    bpdu_guard_enabled: bool = False

    ntp_commands: list[str] = field(
        default_factory=list
    )

    banner_commands: list[str] = field(
        default_factory=list
    )

    username_commands: list[str] = field(
        default_factory=list
    )

    spanning_tree_commands: list[str] = field(
        default_factory=list
    )

    ssh_commands: list[str] = field(
        default_factory=list
    )

    line_vty_commands: list[str] = field(
        default_factory=list
    )

    logging_commands: list[str] = field(
        default_factory=list
    )

    global_commands: list[str] = field(
        default_factory=list
    )