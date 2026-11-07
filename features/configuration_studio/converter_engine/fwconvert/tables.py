"""Lookup tables shared by the readers and writers: predefined FortiGate services, PAN-OS App-ID defaults, and the IKE / ESP algorithm names of both vendors.

Sources:
* FortiGate predefined services: ``config firewall service custom`` of a factory configuration (FortiOS 7.x), https://docs.fortinet.com/product/fortigate/
* PAN-OS applications and their default ports: App-ID default ports (Safely Enable Applications on Default Ports), https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/app-id/application-default.html
* IKE / IPsec algorithm names: FortiOS CLI reference ``vpn ipsec phase1-interface`` / ``phase2-interface`` https://docs.fortinet.com/product/fortigate/ ;
  PAN-OS IKE and IPsec crypto profiles https://docs.paloaltonetworks.com/pan-os/11-0/pan-os-admin/vpns/set-up-site-to-site-vpn/set-up-ipsec/set-up-an-ipsec-tunnel
"""

from __future__ import annotations

# name -> [(protocol, destination ports)]; "" = every port
FORTI_SERVICES: dict[str, list[tuple[str, str]]] = {
    "HTTP": [("tcp", "80")], "HTTPS": [("tcp", "443")], "DNS": [("tcp", "53"), ("udp", "53")], "SSH": [("tcp", "22")], "TELNET": [("tcp", "23")],
    "FTP": [("tcp", "21")], "TFTP": [("udp", "69")], "SMTP": [("tcp", "25")], "SMTPS": [("tcp", "465")], "POP3": [("tcp", "110")], "POP3S": [("tcp", "995")],
    "IMAP": [("tcp", "143")], "IMAPS": [("tcp", "993")], "NTP": [("tcp", "123"), ("udp", "123")], "SNMP": [("tcp", "161-162"), ("udp", "161-162")],
    "SYSLOG": [("udp", "514")], "LDAP": [("tcp", "389")], "LDAP_UDP": [("udp", "389")], "LDAPS": [("tcp", "636")], "RDP": [("tcp", "3389")],
    "MYSQL": [("tcp", "3306")], "MS-SQL": [("tcp", "1433"), ("tcp", "1434")], "SMB": [("tcp", "445")], "SAMBA": [("tcp", "139")], "NFS": [("tcp", "111,2049"), ("udp", "111,2049")],
    "DHCP": [("udp", "67-68")], "BGP": [("tcp", "179")], "RADIUS": [("udp", "1812-1813")], "KERBEROS": [("tcp", "88"), ("udp", "88")], "NTP-TCP": [("tcp", "123")],
    "IKE": [("udp", "500,4500")], "ALL_TCP": [("tcp", "1-65535")], "ALL_UDP": [("udp", "1-65535")], "WINS": [("tcp", "1512"), ("udp", "1512")],
    "VNC": [("tcp", "5900")], "PING": [("icmp", "8")], "ALL_ICMP": [("icmp", "")], "TRACEROUTE": [("udp", "33434-33535")], "GRE": [("ip", "47")],
    "ESP": [("ip", "50")], "AH": [("ip", "51")], "OSPF": [("ip", "89")], "IMAP-ALL": [("tcp", "143,993")],
}
ANY_SERVICE = "ALL"

# PAN-OS application -> default ports, only for applications whose App-ID default is a plain port list (used to turn "application X, service application-default" into services)
APP_PORTS: dict[str, list[tuple[str, str]]] = {
    "web-browsing": [("tcp", "80")], "ssl": [("tcp", "443")], "dns": [("tcp", "53"), ("udp", "53")], "ssh": [("tcp", "22")], "telnet": [("tcp", "23")],
    "ftp": [("tcp", "21")], "smtp": [("tcp", "25")], "pop3": [("tcp", "110")], "imap": [("tcp", "143")], "ntp": [("udp", "123")], "snmp": [("udp", "161")],
    "snmp-trap": [("udp", "162")], "syslog": [("udp", "514"), ("tcp", "514")], "ldap": [("tcp", "389")], "ms-rdp": [("tcp", "3389")], "mysql": [("tcp", "3306")],
    "ms-ds-smb": [("tcp", "445")], "dhcp": [("udp", "67-68")], "bgp": [("tcp", "179")], "tftp": [("udp", "69")], "radius": [("udp", "1812-1813")],
    "ping": [("icmp", "8")], "icmp": [("icmp", "")], "ike": [("udp", "500,4500")], "ipsec-esp-udp": [("udp", "4500")], "kerberos": [("tcp", "88"), ("udp", "88")],
}

# FortiOS proposal token -> (PAN-OS encryption, PAN-OS hash); a token the target cannot express is mapped to None
FORTI_ENC = {"des": "des", "3des": "3des", "aes128": "aes-128-cbc", "aes192": "aes-192-cbc", "aes256": "aes-256-cbc", "aes128gcm": "aes-128-gcm", "aes256gcm": "aes-256-gcm"}
FORTI_HASH = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
PAN_ENC_TO_FORTI = {v: k for k, v in FORTI_ENC.items()}
PAN_ENC_TO_FORTI["aes-128-ccm"] = ""
FORTI_DH = {"1": "group1", "2": "group2", "5": "group5", "14": "group14", "15": "group15", "16": "group16", "19": "group19", "20": "group20", "21": "group21"}
PAN_DH_TO_FORTI = {v: k for k, v in FORTI_DH.items()}
