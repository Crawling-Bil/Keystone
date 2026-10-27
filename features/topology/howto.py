"""'How to read this diagram': the legend page for trainers and new engineers, shown in the tool, in the report and in the draw.io file.

One list of sections is the single source: ``sections(l3)`` returns ``(heading, [paragraphs])``; the L3 sections appear only when the build
has an L3 view.  Every statement here is what the pictures really do; keep it in step with ``l3page.py`` / ``styles.py``.
"""

from __future__ import annotations

REFERENCES = (
    ("RFC 2328 OSPF version 2, section 10.1: neighbor states (FULL = adjacency complete)", "https://www.rfc-editor.org/rfc/rfc2328#section-10.1"),
    ("RFC 4271 BGP-4, section 8: finite state machine (Established = session up)", "https://www.rfc-editor.org/rfc/rfc4271#section-8"),
    ("RFC 5880 Bidirectional Forwarding Detection (BFD up = path forwards in both directions)", "https://www.rfc-editor.org/rfc/rfc5880"),
    ("RFC 3021 Using 31-bit prefixes on IPv4 point-to-point links", "https://www.rfc-editor.org/rfc/rfc3021"),
    ("F5 BIG-IP System Essentials: archives (UCS) - System > Archives, save sys ucs", "https://techdocs.f5.com/en-us/bigip-16-1-0/big-ip-system-essentials/archives.html"),
    ("F5 tmsh reference: net self, net route-domain, net trunk", "https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/"),
    ("Cisco Catalyst SD-WAN command reference (show sdwan bfd sessions, control connections, OMP)", "https://www.cisco.com/c/en/us/td/docs/routers/sdwan/command/sdwan-cr-book.pdf"),
)


def sections(l3: bool = True) -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = [
        ("Three pictures of the same network", [
            "L2 shows the cables: which port of which device is connected to which port, how ports are bundled (port-channel, vPC) and how fast they are.",
            "L3 shows the routed relations: which devices exchange IP packets with each other, through which addresses, and which routing protocol or static route says so.",
            "L3 over L2 puts the two together: the cables stay where they are, each L3 link is drawn on top as an arc, and the cables that carry it are thick and coloured. "
            "It answers the question 'this routed link runs over which physical cable?'.",
        ]),
        ("One file, every view", [
            "With the option 'All views' (the default) topology.drawio holds one page per view, in this order: L3 over L2, L3 route view, IP view, physical view and, when the captures show a vPC pair, the vPC view. "
            "Open the page tabs at the bottom of diagrams.net to switch; nothing needs to be built again. The ZIP and the report hold the same pictures. "
            "A view that has nothing to show for these captures (no routed interface, no vPC pair) is left out. Choose a single view in the form to get a smaller file.",
        ]),
        ("L2 views: how to read a line", [
            "Black = both devices report the link (confirmed). Orange dashed = only one end reports it. Red = the two ends disagree. Teal dashed = neighbor inferred from ARP, MAC table or a port description. "
            "With 'style lines by speed', colour and thickness give the rated speed (1G thin to 100G thick).",
            "Labels at the ends are the port names; when the port is routed, its address is added (Gi0/0/1 10.0.0.1/30). A frame around two switches is a vPC pair; a thick line leaving the frame is a bundle spanning both.",
            "A grey device was seen by CDP or LLDP on a neighbor but nobody captured it.",
        ]),
        ("F5 BIG-IP in the picture", [
            "A BIG-IP is read from its UCS archive (a tar.gz made with System > Archives > Create, or 'save sys ucs <name>' in tmsh). It is drawn as a load balancer. "
            "Each self IP is a routed interface: the VLAN is its description and VLAN id, the VLAN's tagged or untagged interface (or trunk) is the port the L3 over L2 view follows. "
            "A trunk is a bundle (LACP or static). A route domain is a VRF; the default route domain is the global table. Static routes are grouped by route domain and gateway like on any router.",
            "A floating self IP (a traffic group other than traffic-group-local-only) belongs to both units of an HA pair, so it is handled like an HSRP or VRRP address: a next hop that is the floating address is resolved to the BIG-IP pair.",
            "The UCS holds configuration only. Add a tmsh capture of the same unit ('show net interface', 'show net arp') to give the ports their state and speed and to prove neighbors with ARP; without it the BIG-IP links are dashed (configured, nothing proves them). "
            "The BIG-IP's own LLDP neighbors are not read, so a cable to it appears when the neighbor device reports it (CDP or LLDP) or when it is inferred from ARP or MAC tables.",
        ]),
    ]
    if not l3:
        return out
    out += [
        ("L3 views: the shapes", [
            "A rounded square is a captured device. A grey cloud is something nobody captured: a provider network (MPLS, Internet, Metro-E, mobile) or a gateway; the provider name comes from your hints, port descriptions, "
            "SD-WAN colours or neighbor names, and the line to it says which signal was used. A yellow oval is a subnet shared by more than two devices (a VLAN with several interfaces). "
            "A grey square named SD-WAN with an address is a remote SD-WAN site seen only through BFD sessions.",
        ]),
        ("L3 views: the lines", [
            "Direct routed link: two devices have addresses in the same small subnet (/30, /31 ...). Shared subnet: several devices on one VLAN. Tunnel: a GRE / IPsec tunnel interface. "
            "SD-WAN overlay: BFD sessions between two sites, one line per site pair, thick purple, colour pairs in the label. Routing adjacency: a routing session or next hop between devices that share no subnet. "
            "Gateway / access link: the way out of a site towards a cloud.",
            "Colour = VRF. Dark grey is the global table; every other VRF has its own colour, listed under the diagram. Management interfaces are not drawn.",
            "Solid = something in the captures proves it works: interface up/up, OSPF FULL, BGP Established, BFD up. Dashed = configured but nothing proves it. Red = something shows it broken. "
            "The sentence of each link (click it) says which.",
            "The label shows the interface and address at each end; in the middle the subnet, the VRF and the routes that use the link, for example 'OSPF default + 12 prefixes'.",
        ]),
        ("How to follow a packet", [
            "1. Find the source device. 2. Read its routing table through the labels: the line labelled with the longest prefix that contains the destination is where the packet leaves (a default route is the shortest match). "
            "3. Cross that line to the next device, at the address written at its end. 4. Repeat until the destination subnet is a directly connected one. "
            "5. In L3 over L2, look at the thick cable under each arc to see where the packet physically travels.",
            "The 'Trace a path' box does these steps for you: choose a source device and a destination address and the lines of the path are highlighted.",
        ]),
        ("What a dashed or missing line usually means", [
            "A dashed line: add the capture that proves it (show ip ospf neighbor, show ip bgp summary, show sdwan bfd sessions, show ip interface brief). "
            "A cloud named 'Gateway' only: the provider could not be recognised; add a rule to the Provider hints box. "
            "A route whose next hop is listed as unresolved: capture the device that owns the address.",
        ]),
        ("What the picture does not say", [
            "It shows routing intent: interface state, routing tables and neighbors at the time of the capture. It is not measured traffic, it does not show load or latency, "
            "and policy routing, ACLs, NAT and SD-WAN data policy are not evaluated. VLAN membership of trunks is not read, so for a VLAN interface the cable shown is the shortest chain, not proof.",
        ]),
    ]
    return out


def html(l3: bool = True) -> str:
    from html import escape
    body = "".join(f"<h3>{escape(h)}</h3>" + "".join(f"<p>{escape(p)}</p>" for p in paras) for h, paras in sections(l3))
    refs = "".join(f"<li><a href='{escape(u)}' target='_blank' rel='noopener noreferrer'>{escape(t)}</a></li>" for t, u in REFERENCES) if l3 else ""
    return body + (f"<h3>References</h3><ul>{refs}</ul>" if refs else "")
