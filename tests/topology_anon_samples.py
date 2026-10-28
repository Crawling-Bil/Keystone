"""An invented estate with names, addresses, serials and descriptions that identify it, for the anonymized export tests.

Every value is made up: the city and company words are placeholders, addresses are RFC 1918 / RFC 5737, MACs use the VMware and Cisco-like
prefixes with invented tails.
"""

from __future__ import annotations

from topology_samples import iosxe_capture, nxos_capture

SECRET_WORDS = ("sby", "kantor", "akunting", "lantai", "telkomxyz", "gudang", "mawar")
SERIALS = ("FDO2311ABCD", "FOC2322WXYZ", "FDO2399QQQQ")
MACS = ("0050.5611.2233", "00aa.bb11.2233", "5254.00ab.cdef")


def estate() -> dict[str, str]:
    core = nxos_capture(
        "SBY-KANTOR-CORE-1", SERIALS[0], "10.77.0.11",
        cdp=[("SBY-KANTOR-LAN-SW-2.kantor.mawar.example(FOC2322WXYZ)", "10.77.0.21", "C9300L-48P-4X", "Ethernet1/1", "GigabitEthernet1/0/48"),
             ("SBY-GUDANG-CORE-2.kantor.mawar.example(FDO2399QQQQ)", "10.77.0.12", "N9K-C93180YC-FX3", "Ethernet1/47", "Ethernet1/47")],
        lldp=[("SBY-KANTOR-FW-1", "Eth1/40", "port5")],
        config_extra="interface Ethernet1/1\n  description KE SBY-KANTOR-LAN-SW-2 Gi1/0/48\ninterface Ethernet1/40\n  description Firewall Kantor Mawar port5\n"
                     "interface Ethernet1/20\n  no switchport\n  description Link ISP TelkomXYZ\n  ip address 203.0.113.9/30\n")
    access = iosxe_capture(
        "SBY-KANTOR-LAN-SW-2", SERIALS[1], "10.77.0.21",
        cdp=[("SBY-KANTOR-CORE-1.kantor.mawar.example(FDO2311ABCD)", "10.77.0.11", "N9K-C93180YC-FX3", "GigabitEthernet1/0/48", "Ethernet1/1")],
        config_extra="interface GigabitEthernet1/0/48\n description UPLINK KE SBY-KANTOR-CORE-1 Eth1/1\n!\n"
                     "interface GigabitEthernet1/0/10\n description Printer Akunting Lantai 3\n!\n",
        extra="SBY-KANTOR-LAN-SW-2#show mac address-table\n          Mac Address Table\n-------------------------------------------\n\n"
              "Vlan    Mac Address       Type        Ports\n----    -----------       --------    -----\n"
              f"  10    {MACS[0]}    DYNAMIC     Gi1/0/10\n  10    {MACS[1]}    DYNAMIC     Gi1/0/11\n  20    {MACS[2]}    DYNAMIC     Gi1/0/12\n"
              "Total Mac Addresses for this criterion: 3\n"
              "SBY-KANTOR-LAN-SW-2#show ip arp\nProtocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
              f"Internet  10.77.10.50             5   {MACS[0]}  ARPA   Vlan10\nInternet  10.77.10.51             7   {MACS[1]}  ARPA   Vlan10\n")
    return {"SBY-KANTOR-CORE-1.txt": core, "SBY-KANTOR-LAN-SW-2.txt": access}
