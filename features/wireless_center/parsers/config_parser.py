import re
from pathlib import Path


class HuaweiConfigParser:
    def __init__(self, content):
        self.content = content.replace("\r\n", "\n")
        self.lines = self.content.splitlines()

    @classmethod
    def from_file(cls, path):
        content = Path(path).read_text(
            encoding="utf-8",
            errors="ignore"
        )
        return cls(content)

    def parse(self):
        return {
            "wlc": self.parse_wlc(),
            "interfaces": self.parse_interfaces(),
            "local_users": self.parse_local_users(),
            "security_profiles": self.parse_named_profiles(
                "security-profile name"
            ),
            "ssid_profiles": self.parse_named_profiles(
                "ssid-profile name"
            ),
            "vap_profiles": self.parse_named_profiles(
                "vap-profile name"
            ),
            "traffic_profiles": self.parse_named_profiles(
                "traffic-profile name"
            ),
            "ap_system_profiles": self.parse_named_profiles(
                "ap-system-profile name"
            ),
            "radio_2g_profiles": self.parse_named_profiles(
                "radio-2g-profile name"
            ),
            "radio_5g_profiles": self.parse_named_profiles(
                "radio-5g-profile name"
            ),
            "regulatory_domain_profiles": self.parse_named_profiles(
                "regulatory-domain-profile name"
            ),
            "wired_port_profiles": self.parse_named_profiles(
                "wired-port-profile name"
            ),
            "aps": self.parse_aps(),
            "ap_groups": self.parse_ap_groups(),
        }

    def parse_wlc(self):
        data = {
            "hostname": "",
            "software_version": "",
            "model": "",
            "esn": "",
            "management_ip": "",
            "capwap_source": "",
            "uptime": "",
        }

        patterns = {
            "hostname": r"^\s*sysname\s+(.+)$",
            "software_version": r"Software Version\s+(\S+)",
            "esn": r"ESN of device:\s*(\S+)",
            "capwap_source": r"^\s*capwap source interface\s+(.+)$",
        }

        for line in self.lines:
            for key, pattern in patterns.items():
                match = re.search(pattern, line, re.I)
                if match and not data[key]:
                    data[key] = match.group(1).strip()

            match = re.search(
                r"VRP .*?\((AirEngine[^\s]+)\s+([^)]+)\)",
                line
            )
            if match:
                data["model"] = match.group(1)
                if not data["software_version"]:
                    data["software_version"] = match.group(2)

            match = re.search(
                r"Huawei\s+(AirEngine[^\s]+).*?uptime is\s+(.+)",
                line
            )
            if match:
                data["model"] = match.group(1)
                data["uptime"] = match.group(2)

        interfaces = self.parse_interfaces()

        capwap = data["capwap_source"].lower()

        for interface in interfaces:
            if interface["name"].lower() == capwap:
                data["management_ip"] = interface["ip"]
                break

        if not data["management_ip"]:
            for interface in interfaces:
                if interface["name"].lower().startswith("vlanif"):
                    if interface["ip"]:
                        data["management_ip"] = interface["ip"]
                        break

        return data

    def parse_interfaces(self):
        interfaces = []
        current = None

        for line in self.lines:
            match = re.match(
                r"^interface\s+(\S+)",
                line
            )

            if match:
                if current:
                    interfaces.append(current)

                current = {
                    "name": match.group(1),
                    "ip": "",
                    "mask": "",
                    "config": []
                }

                continue

            if current:
                if line.startswith("#"):
                    interfaces.append(current)
                    current = None
                    continue

                stripped = line.strip()

                if stripped:
                    current["config"].append(stripped)

                ip_match = re.match(
                    r"ip address\s+(\d+\.\d+\.\d+\.\d+)\s+"
                    r"(\d+\.\d+\.\d+\.\d+)",
                    stripped
                )

                if ip_match:
                    current["ip"] = ip_match.group(1)
                    current["mask"] = ip_match.group(2)

        if current:
            interfaces.append(current)

        return interfaces

    def parse_local_users(self):
        users = {}

        for line in self.lines:
            match = re.match(
                r"\s*local-user\s+(\S+)\s+(.+)",
                line
            )

            if not match:
                continue

            username = match.group(1)
            command = match.group(2)

            if username not in users:
                users[username] = {
                    "username": username,
                    "privilege": "",
                    "service_type": "",
                    "state": "",
                    "config": []
                }

            users[username]["config"].append(command)

            privilege = re.search(
                r"privilege level\s+(\d+)",
                command
            )

            if privilege:
                users[username]["privilege"] = privilege.group(1)

            service = re.search(
                r"service-type\s+(.+)",
                command
            )

            if service:
                users[username]["service_type"] = service.group(1)

            if "state block" in command:
                users[username]["state"] = "Blocked"
            elif "state active" in command:
                users[username]["state"] = "Active"

        return list(users.values())

    def parse_named_profiles(self, prefix):
        profiles = {}

        pattern = re.compile(
            r"^\s*" + re.escape(prefix) + r"\s+(.+)$"
        )

        current = None
        current_indent = 0

        for line in self.lines:
            match = pattern.match(line)

            if match:
                current = match.group(1).strip()
                current_indent = len(line) - len(line.lstrip(" \t"))

                profiles[current] = {
                    "name": current,
                    "config": []
                }

                continue

            if current:
                stripped = line.strip()
                indent = len(line) - len(line.lstrip(" \t"))

                if stripped and indent > current_indent:
                    profiles[current]["config"].append(
                        stripped
                    )

                elif stripped.startswith("#"):
                    current = None

                elif stripped and indent <= current_indent:
                    current = None

        return list(profiles.values())

    def parse_aps(self):
        aps = []

        pattern = re.compile(
            r"^\s*ap-id\s+(\d+)"
            r"(?:\s+type-id\s+(\d+))?"
            r"(?:\s+ap-mac\s+(\S+))?"
            r"(?:\s+ap-sn\s+(\S+))?"
        )

        current = None

        for line in self.lines:
            match = pattern.match(line)

            if match:
                if current:
                    aps.append(current)

                current = {
                    "ap_id": match.group(1),
                    "type_id": match.group(2) or "",
                    "mac": match.group(3) or "",
                    "serial": match.group(4) or "",
                    "name": "",
                    "group": "",
                    "ip": "",
                    "status": "",
                    "version": "",
                    "config": []
                }

                continue

            if current:
                stripped = line.strip()

                if line.startswith("#"):
                    aps.append(current)
                    current = None
                    continue

                # Do not skip "ap-group".
                # It is part of the current AP configuration
                # and must be parsed into current["group"].
                if stripped.startswith("ap-id "):
                    aps.append(current)
                    current = None
                    continue

                if stripped.startswith("ap-name "):
                    current["name"] = stripped[
                        len("ap-name "):
                    ].strip()

                elif stripped.startswith("ap-group "):
                    current["group"] = stripped[
                        len("ap-group "):
                    ].strip()

                if stripped:
                    current["config"].append(stripped)

        if current:
            aps.append(current)

        self.enrich_ap_runtime(aps)

        aps = self.deduplicate_aps(aps)

        return aps

    def deduplicate_aps(self, aps):
        unique = []
        indexes = {}
        duplicate_count = 0

        for ap in aps:
            serial = self.normalize_ap_identity(
                ap.get("serial", "")
            )

            mac = self.normalize_ap_identity(
                ap.get("mac", "")
            )

            ap_id = str(
                ap.get("ap_id", "")
            ).strip()

            if serial:
                identity = (
                    "serial",
                    serial
                )

            elif mac:
                identity = (
                    "mac",
                    mac
                )

            elif ap_id:
                identity = (
                    "ap_id",
                    ap_id
                )

            else:
                unique.append(ap)
                continue

            if identity not in indexes:
                ap["_duplicate_count"] = 1
                ap["_duplicate_identity"] = identity[0]

                indexes[identity] = len(unique)
                unique.append(ap)
                continue

            duplicate_count += 1

            existing = unique[
                indexes[identity]
            ]

            existing["_duplicate_count"] = (
                existing.get(
                    "_duplicate_count",
                    1
                ) + 1
            )

            existing[
                "_duplicate_identity"
            ] = identity[0]

            self.merge_duplicate_ap(
                existing,
                ap
            )

        self.ap_duplicate_count = (
            duplicate_count
        )

        self.ap_raw_count = len(aps)
        self.ap_unique_count = len(unique)

        return unique

    @staticmethod
    def normalize_ap_identity(value):
        return re.sub(
            r"[^a-zA-Z0-9]",
            "",
            str(value or "")
        ).lower()

    @staticmethod
    def merge_duplicate_ap(existing, duplicate):
        preferred_fields = [
            "name",
            "group",
            "type_id",
            "mac",
            "serial",
            "ip",
            "status",
            "version"
        ]

        for field in preferred_fields:
            current_value = str(
                existing.get(
                    field,
                    ""
                ) or ""
            ).strip()

            duplicate_value = str(
                duplicate.get(
                    field,
                    ""
                ) or ""
            ).strip()

            if (
                not current_value
                and duplicate_value
            ):
                existing[field] = (
                    duplicate.get(field)
                )

        existing_config = (
            existing.setdefault(
                "config",
                []
            )
        )

        for command in duplicate.get(
            "config",
            []
        ):
            if command not in existing_config:
                existing_config.append(command)

    def enrich_ap_runtime(self, aps):
        """Enrich AP runtime data only from `display ap all`."""
        by_id = {
            str(ap.get("ap_id", "")).strip(): ap
            for ap in aps
            if str(ap.get("ap_id", "")).strip()
        }
        by_mac = {
            self.normalize_ap_identity(ap.get("mac", "")): ap
            for ap in aps
            if self.normalize_ap_identity(ap.get("mac", ""))
        }

        in_section = False
        in_table = False

        state_map = {
            "nor": "Normal",
            "normal": "Normal",
            "idle": "Idle",
            "fault": "Fault",
            "standby": "Standby",
            "stdby": "Standby",
            "cfg": "Config",
            "cfgfa": "Config-Failed",
            "cfgfai": "Config-Failed",
            "download": "Download",
        }

        row_pattern = re.compile(
            r"^\s*(\d+)\s+"
            r"([0-9A-Fa-f:-]{12,17})\s+"
            r"(\S+)\s+"
            r"(\S+)\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3}|-)\s+"
            r"(\S+)\s+"
            r"(\S+)(?:\s+.*)?$"
        )

        for line in self.lines:
            stripped = line.strip()
            lower = stripped.lower()

            if "display ap all" in lower:
                in_section = True
                in_table = False
                continue

            if not in_section:
                continue

            if (
                stripped.startswith("<")
                and ">" in stripped
                and "display ap all" not in lower
            ):
                in_section = False
                in_table = False
                continue

            if (
                lower.startswith("id")
                and "mac" in lower
                and "name" in lower
                and "group" in lower
                and "state" in lower
            ):
                in_table = True
                continue

            if not in_table:
                continue

            match = row_pattern.match(stripped)
            if not match:
                continue

            ap_id, mac, ap_name, ap_group, ip, ap_type, raw_state = match.groups()

            ap = by_id.get(ap_id)
            if ap is None:
                ap = by_mac.get(self.normalize_ap_identity(mac))
            if ap is None:
                continue

            ap["name"] = ap_name
            ap["group"] = ap_group
            ap["ip"] = "" if ip == "-" else ip
            ap["status"] = state_map.get(raw_state.lower(), raw_state)
            ap["model"] = ap_type
            ap["runtime_type"] = ap_type
            ap["runtime_source"] = "display ap all"

    def parse_ap_groups(self):
        groups = []
        current = None
        current_radio = None

        for line in self.lines:
            match = re.match(
                r"^\s*ap-group name\s+(.+)$",
                line
            )

            if match:
                if current:
                    groups.append(current)

                current = {
                    "name": match.group(1).strip(),
                    "ap_system_profile": "",
                    "location_profile": "",
                    "radios": {},
                    "config": []
                }

                current_radio = None
                continue

            if not current:
                continue

            stripped = line.strip()

            if line.startswith("#"):
                groups.append(current)
                current = None
                current_radio = None
                continue

            if re.match(
                r"^(ap-id|ap-group name)\s+",
                stripped
            ):
                if stripped.startswith("ap-id "):
                    groups.append(current)
                    current = None
                    current_radio = None
                continue

            match = re.match(
                r"radio\s+(\d+)$",
                stripped
            )

            if match:
                current_radio = match.group(1)

                current["radios"].setdefault(
                    current_radio,
                    {
                        "radio": current_radio,
                        "vap_mappings": [],
                        "config": []
                    }
                )

                continue

            if stripped.startswith(
                "ap-system-profile "
            ):
                current["ap_system_profile"] = (
                    stripped.split(
                        " ",
                        1
                    )[1]
                )

            elif stripped.startswith(
                "location-profile "
            ):
                current["location_profile"] = (
                    stripped.split(
                        " ",
                        1
                    )[1]
                )

            elif current_radio is not None:
                current["radios"][
                    current_radio
                ]["config"].append(stripped)

                vap_match = re.match(
                    r"vap-profile\s+(\S+)"
                    r"\s+wlan\s+(\d+)"
                    r"(?:\s+service-vlan\s+"
                    r"vlan-id\s+(\d+))?",
                    stripped
                )

                if vap_match:
                    current["radios"][
                        current_radio
                    ]["vap_mappings"].append(
                        {
                            "vap_profile":
                                vap_match.group(1),
                            "wlan_id":
                                vap_match.group(2),
                            "service_vlan_override":
                                vap_match.group(3) or ""
                        }
                    )

            if stripped:
                current["config"].append(stripped)

        if current:
            groups.append(current)

        return groups
