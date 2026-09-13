from dataclasses import dataclass
from pathlib import Path


@dataclass
class DetectionResult:
    vendor: str
    device_type: str
    confidence: int = 0


class DeviceDetector:

    def detect_file(self, filename):

        path = Path(filename)

        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as f:
            content = f.read()

        return self.detect_text(content)


    def detect_text(self, content):

        text = content.lower()

        candidates = []

        # ==========================================
        # CISCO SWITCH
        # ==========================================

        score = 0

        markers = [
            "switchport mode access",
            "switchport mode trunk",
            "switchport access vlan",
            "switchport trunk allowed vlan",
            "spanning-tree portfast",
            "interface gigabitethernet",
            "interface tengigabitethernet",
            "vlan internal allocation policy",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        if "hostname " in text:
            score += 2

        if "router ospf" in text:
            score += 2

        candidates.append(
            DetectionResult(
                vendor="Cisco",
                device_type="Switch",
                confidence=score
            )
        )

        # ==========================================
        # ARUBA SWITCH
        # ArubaOS-Switch / ProCurve
        # ==========================================

        score = 0

        markers = [
            "aruba",
            "procurve",
            "untagged ",
            "tagged ",
            "manager password",
            "operator password",
            "ip authorized-managers",
            "trunk ",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="Aruba",
                device_type="Switch",
                confidence=score
            )
        )

        # ==========================================
        # HUAWEI SWITCH
        # ==========================================

        score = 0

        markers = [
            "sysname ",
            "port link-type access",
            "port link-type trunk",
            "port default vlan",
            "port trunk allow-pass vlan",
            "interface vlanif",
            "display current-configuration",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="Huawei",
                device_type="Switch",
                confidence=score
            )
        )

        # ==========================================
        # MIKROTIK ROUTEROS
        # /export style configuration
        # ==========================================

        score = 0

        markers = [
            "/interface bridge",
            "/interface bridge port",
            "/interface vlan",
            "/ip firewall filter",
            "/ip firewall nat",
            "/ip firewall address-list",
            "/ip ipsec",
            "/system identity",
            "add chain=",
            "add action=",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        if "routeros" in text:
            score += 2

        candidates.append(
            DetectionResult(
                vendor="Mikrotik",
                device_type="Firewall",
                confidence=score
            )
        )

        # ==========================================
        # FORTIGATE FIREWALL
        # ==========================================

        score = 0

        markers = [
            "config system interface",
            "config firewall policy",
            "config firewall address",
            "config firewall addrgrp",
            "config firewall service custom",
            "config router static",
            "set srcintf",
            "set dstintf",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="FortiGate",
                device_type="Firewall",
                confidence=score
            )
        )

        # ==========================================
        # PALO ALTO FIREWALL
        # set-format configuration
        # ==========================================

        score = 0

        markers = [
            "set deviceconfig system hostname",
            "set rulebase security rules",
            "set rulebase nat rules",
            "set address ",
            "set address-group ",
            "set network interface ethernet",
            "set zone ",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        # A real PAN-OS "running-config" XML export (Device > Setup >
        # Operations > Export named configuration snapshot) instead of
        # the "set"-format CLI above -- structurally unrelated text, so
        # it needs its own marker set entirely. <devices>/<vsys>/
        # <rulebase> are PAN-OS-specific container tags no other
        # vendor's XML export in this tool uses, so a couple of them
        # together is already a confident match.
        xml_markers = [
            "<devices>",
            "<vsys>",
            "<rulebase>",
            "<deviceconfig>",
            "localhost.localdomain",
        ]
        xml_score = sum(10 for marker in xml_markers if marker in text)
        if xml_score and (text.lstrip().startswith("<?xml") or text.lstrip().startswith("<config")):
            score += xml_score + 10

        candidates.append(
            DetectionResult(
                vendor="Palo Alto",
                device_type="Firewall",
                confidence=score
            )
        )

        # ==========================================
        # CISCO FTD / ASA STYLE
        # ==========================================

        score = 0

        markers = [
            "access-group ",
            "access-list ",
            "object network ",
            "object-group network ",
            "nat (",
            "nameif ",
            "security-level ",
            "firepower",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="Cisco FTD",
                device_type="Firewall",
                confidence=score
            )
        )

        # ==========================================
        # CISCO WLC
        # AireOS / common exported CLI
        # ==========================================

        score = 0

        markers = [
            "config wlan create",
            "config wlan enable",
            "config wlan interface",
            "config interface create",
            "config interface address",
            "config radius auth add",
            "show wlan summary",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="Cisco",
                device_type="WLC",
                confidence=score
            )
        )

        # ==========================================
        # ARUBA WLC
        # ==========================================

        score = 0

        markers = [
            "wlan ssid-profile",
            "aaa profile",
            "virtual-ap",
            "ap-group",
            "dot1x authentication-profile",
        ]

        for marker in markers:
            if marker in text:
                score += 10

        candidates.append(
            DetectionResult(
                vendor="Aruba",
                device_type="WLC",
                confidence=score
            )
        )

        # ==========================================
        # GET BEST RESULT
        # ==========================================

        result = max(
            candidates,
            key=lambda item: item.confidence
        )

        if result.confidence == 0:

            return DetectionResult(
                vendor="Unknown",
                device_type="Unknown",
                confidence=0
            )

        return result