# sep/11/2026 11:30:07 by RouterOS 6.49.15
# software id = ABCD-1234
#
# model = RB1100x4
# serial number = SYNTHETIC0001
/interface bridge
add name=Loopback
add name=bridge-lan
/interface ethernet
set [ find default-name=ether1 ] comment="to ISP" speed=100Mbps
set [ find default-name=ether2 ] comment="to LAN"
set [ find default-name=ether3 ] comment="to Core"
/interface l2tp-client
add connect-to=198.51.100.16 disabled=no name="Tunnel HQ" password=Sy-nth3tic-Pw-1 user=branch1
/interface eoip
add local-address=203.0.113.6 name="HQ EoIP" remote-address=203.0.113.161 tunnel-id=888
/interface pptp-server server
set enabled=yes
/interface l2tp-server server
set authentication=pap,mschap2 default-profile=prof-l2tp enabled=yes ipsec-secret=short use-ipsec=yes
/interface bridge port
add bridge=bridge-lan interface=ether2
/ip settings
set tcp-syncookies=yes
/ip address
add address=10.0.4.2/24 comment=CoreSwitch interface=ether3 network=10.0.4.0
add address=172.27.3.41/29 comment="IP NMS" disabled=yes interface=ether2 network=172.27.3.40
add address=203.0.113.103 interface=Loopback network=203.0.113.103
add address=10.9.9.1/24 interface=bridge-lan network=10.9.9.0
/ip route
add distance=1 gateway=203.0.113.1
add distance=1 gateway=10.0.4.9 routing-mark=LJN
add disabled=yes distance=1 gateway=10.0.6.1 routing-mark=route_dead
add distance=1 gateway=10.0.6.2 routing-mark=orphan
add blackhole dst-address=192.0.2.0/24
add check-gateway=ping distance=2 dst-address=198.18.0.0/15 gateway=10.0.4.8,10.0.4.7
add distance=1 dst-address=198.19.0.0/16 gateway=ether3
/ip route rule
add dst-address=0.0.0.0/0 src-address=10.9.9.0/24 table=LJN
add disabled=yes src-address=10.8.0.0/24 table=route_dead
/ip firewall mangle
add action=change-mss chain=forward new-mss=1360 out-interface=ether1 passthrough=yes protocol=tcp tcp-flags=syn
add action=mark-routing chain=prerouting new-routing-mark=LJN passthrough=no src-address=10.9.9.0/24
add action=mark-routing chain=prerouting new-routing-mark=route_dead passthrough=no src-address=10.8.0.0/24
add action=mark-packet chain=forward dst-address-list=!local new-packet-mark=pkt_up passthrough=no src-address=10.9.9.0/24
/ip firewall raw
add action=add-dst-to-address-list address-list=banking address-list-timeout=1h chain=prerouting protocol=tcp tls-host=*example-bank*
/ip firewall address-list
add address=10.0.0.0/8 list=local
add address=192.168.0.0/16 list=local
/ip firewall filter
add action=accept chain=input comment="established" connection-state=established,related
add action=drop chain=input comment="invalid" connection-state=invalid
add action=accept chain=input comment="mgmt" dst-port=22,8291 protocol=tcp src-address-list=local
add action=drop chain=forward comment="no flags" protocol=tcp tcp-flags=fin,syn
add action=drop chain=forward comment="not local" src-address-list=!local out-interface=ether1
add action=accept chain=forward comment=lan-out in-interface=ether2 out-interface=ether1
/ip firewall nat
add action=masquerade chain=srcnat comment=wan out-interface=ether1
add action=dst-nat chain=dstnat comment=web dst-address=!10.0.0.0/8 dst-port=443 protocol=tcp to-addresses=10.9.9.10 to-ports=443
/queue type
add kind=pcq name=pcq_dw pcq-classifier=dst-address pcq-rate=10M
add kind=pcq name=pcq_up pcq-classifier=src-address pcq-rate=10M
/queue tree
add max-limit=30M name=q_up packet-mark=pkt_up parent=global queue=pcq_up
add max-limit=30M name=q_dead packet-mark=pkt_never parent=global queue=pcq_missing
add disabled=yes max-limit=30M name=q_off packet-mark=pkt_up parent=global queue=pcq_dw
/queue simple
add max-limit=10M/10M name=guest target=10.9.9.0/24
/ppp profile
set *0 dns-server=10.0.4.53
add name=prof-l2tp use-encryption=no
/ppp secret
add name=alice password=abc123 profile=prof-l2tp service=l2tp
add name=bob password=Reused-Synth3tic-Value-9 profile=prof-l2tp service=l2tp
add name=carol password=Reused-Synth3tic-Value-9 profile=prof-l2tp service=l2tp
add disabled=yes name=dave password=Unique-Synth3tic-Value-3 service=pptp
/ip ipsec proposal
set [ find default=yes ] enc-algorithms=3des pfs-group=none
add disabled=yes name=off pfs-group=none
add auth-algorithms=sha256 enc-algorithms=aes-256-cbc lifetime=1h name=prop1 pfs-group=modp2048
/ip ipsec profile
add dh-group=modp2048 enc-algorithm=aes-256 hash-algorithm=sha256 name=prof1 nat-traversal=no
/ip ipsec peer
add address=198.51.100.50/32 exchange-mode=main local-address=203.0.113.6 name=peer-main profile=prof1
add disabled=yes exchange-mode=ike2 name=peer-off passive=yes profile=prof1
/ip ipsec identity
add peer=peer-main secret=weak1
/ip ipsec policy
add dst-address=10.50.0.0/24 peer=peer-main proposal=prop1 src-address=10.9.9.0/24 tunnel=yes
add dst-address=0.0.0.0/0 src-address=0.0.0.0/0 template=yes
/snmp
set contact=ops enabled=yes trap-community=Synth-Trap-Name
/snmp community
set [ find default=yes ] addresses=0.0.0.0/0 name=public
add addresses=0.0.0.0/0 name=Synth-Ro-Name write-access=yes
/ip service
set telnet address=10.0.0.0/8
set ftp disabled=yes
set ssh port=2200
/ip ssh
set allow-none-crypto=yes
/ip neighbor discovery-settings
set discover-interface-list=all
/system package update
set channel=testing
/ip dns
set allow-remote-requests=yes servers=10.0.4.53,10.0.4.54
/system identity
set name=SYNTH-RTR-1
/system scheduler
add interval=1d name=reboot on-event="/system reboot" start-time=03:00:00
/tool netwatch
add down-script=":log info down" host=10.0.4.1 interval=10s up-script=":log info up"
/routing ospf network
add area=backbone network=10.0.4.0/24
/system logging
set 0 action=disk topics=info,!pptp
/interface ethernet switch port
set 0 default-vlan-id=0
