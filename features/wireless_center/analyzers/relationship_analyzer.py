import re


class RelationshipAnalyzer:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def profile_map(profiles):
        return {
            profile["name"]: profile
            for profile in profiles
        }

    @staticmethod
    def find_value(config, prefix):
        for line in config:
            if line.startswith(prefix):
                return line[len(prefix):].strip()

        return ""

    @staticmethod
    def mask_sensitive(command):
        """Keep configuration useful without exposing credential material."""
        clean = str(command or "").strip()
        sensitive = re.search(
            r"\b(password|secret|cipher|shared-key|key-string|community|"
            r"private-key|pre-shared-key|pass-phrase)\b",
            clean,
            re.I,
        )
        if not sensitive:
            return clean
        return clean[:sensitive.start()].rstrip() + " <masked>"

    @classmethod
    def security_summary(cls, config):
        command = cls.find_value(config, "security ")
        safe = cls.mask_sensitive(command).replace("<masked>", "").strip()
        return safe or command

    def build_wlan_relationships(self):
        vap_profiles = self.profile_map(
            self.data["vap_profiles"]
        )

        ssid_profiles = self.profile_map(
            self.data["ssid_profiles"]
        )

        security_profiles = self.profile_map(
            self.data["security_profiles"]
        )

        traffic_profiles = self.profile_map(
            self.data["traffic_profiles"]
        )

        relationships = []

        for vap_name, vap in vap_profiles.items():
            config = vap["config"]

            ssid_profile = self.find_value(
                config,
                "ssid-profile "
            )

            security_profile = self.find_value(
                config,
                "security-profile "
            )

            traffic_profile = self.find_value(
                config,
                "traffic-profile "
            )

            auth_profile = self.find_value(
                config,
                "authentication-profile "
            )

            forward_mode = self.find_value(
                config,
                "forward-mode "
            )

            service_vlan = ""

            for line in config:
                match = re.search(
                    r"service-vlan\s+vlan-id\s+(\d+)",
                    line
                )

                if match:
                    service_vlan = match.group(1)

            ssid = ""

            if ssid_profile in ssid_profiles:
                ssid = self.find_value(
                    ssid_profiles[
                        ssid_profile
                    ]["config"],
                    "ssid "
                )

            security = ""

            if security_profile in security_profiles:
                security = self.security_summary(
                    security_profiles[
                        security_profile
                    ]["config"],
                )

            relationships.append(
                {
                    "vap_profile": vap_name,
                    "ssid_profile": ssid_profile,
                    "ssid": ssid,
                    "security_profile":
                        security_profile,
                    "security": security,
                    "traffic_profile":
                        traffic_profile,
                    "authentication_profile":
                        auth_profile,
                    "forward_mode": forward_mode,
                    "service_vlan": service_vlan,
                    "vap_config": config,
                }
            )

        return relationships

    def build_vap_inventory(self):
        """Return one operationally enriched row per VAP/WLAN profile.

        Huawei uses the VAP as the service-binding layer. This view keeps the
        profile's own configuration separate while resolving where it is
        delivered through AP groups, radios and WLAN IDs.
        """
        relationships = {
            item["vap_profile"]: item
            for item in self.build_wlan_relationships()
        }
        mappings_by_vap = {}
        for mapping in self.build_group_mapping():
            mappings_by_vap.setdefault(mapping["vap_profile"], []).append(mapping)

        rows = []
        for profile in self.data.get("vap_profiles", []):
            name = profile.get("name", "")
            relationship = relationships.get(name, {})
            mappings = mappings_by_vap.get(name, [])

            groups = []
            radios = []
            wlan_ids = []
            effective_vlans = []
            ap_count_by_group = {}
            for mapping in mappings:
                group = str(mapping.get("ap_group", "")).strip()
                if group and group not in groups:
                    groups.append(group)
                if group:
                    ap_count_by_group[group] = max(
                        ap_count_by_group.get(group, 0),
                        int(mapping.get("ap_count", 0) or 0),
                    )
                for radio in str(mapping.get("radio", "")).split(","):
                    radio = radio.strip()
                    if radio and radio not in radios:
                        radios.append(radio)
                wlan_id = str(mapping.get("wlan_id", "")).strip()
                if wlan_id and wlan_id not in wlan_ids:
                    wlan_ids.append(wlan_id)
                vlan = str(mapping.get("vlan", "")).strip()
                if vlan and vlan not in effective_vlans:
                    effective_vlans.append(vlan)

            if not groups:
                usage_scope = "Unassigned"
            elif len(groups) == 1:
                usage_scope = "Site-specific"
            else:
                usage_scope = "Shared across sites"

            full_config = [
                self.mask_sensitive(command)
                for command in profile.get("config", [])
                if str(command or "").strip()
            ]
            rows.append({
                "vap_profile": name,
                "usage_scope": usage_scope,
                "deployment_status": "Deployed" if groups else "Not mapped",
                "ssid": relationship.get("ssid", ""),
                "ssid_profile": relationship.get("ssid_profile", ""),
                "security": relationship.get("security", ""),
                "security_profile": relationship.get("security_profile", ""),
                "authentication_profile": relationship.get("authentication_profile", ""),
                "traffic_profile": relationship.get("traffic_profile", ""),
                "forward_mode": relationship.get("forward_mode", ""),
                "service_vlan": relationship.get("service_vlan", ""),
                "effective_vlans": ", ".join(effective_vlans),
                "ap_groups": ", ".join(groups),
                "ap_group_count": len(groups),
                "ap_count": sum(ap_count_by_group.values()),
                "radios": ", ".join(sorted(radios, key=lambda value: (len(value), value))),
                "wlan_ids": ", ".join(sorted(wlan_ids, key=lambda value: (len(value), value))),
                "mapping_count": len(mappings),
                "full_config": full_config,
            })

        return rows

    def build_ssid_catalog(self):
        """Group WLAN relationships by actual broadcast SSID.

        A single SSID is commonly reused across many site- or
        AP-group-specific VAP profiles (e.g. "SUV", "SUV_EKY",
        "SUV_Batam" all broadcasting the same "SUV" SSID). The raw
        per-VAP-profile list is useful for AP Group / Tags detail, but
        for an "SSID catalog" view it should collapse to one row per
        distinct SSID name, since that is what a person actually counts
        as "how many SSIDs are configured on this WLC".
        """
        catalog = {}
        order = []

        for item in self.build_wlan_relationships():
            ssid = str(item.get("ssid", "")).strip()
            if not ssid:
                # VAP/WLAN profile with no SSID bound — not a real
                # broadcast SSID, so it doesn't belong in the catalog.
                continue

            entry = catalog.get(ssid)
            if entry is None:
                entry = {
                    "ssid": ssid,
                    "security": item.get("security", ""),
                    "security_profiles": [],
                    "authentication_profiles": [],
                    "traffic_profiles": [],
                    "forward_modes": [],
                    "vlans": [],
                    "vap_profiles": [],
                }
                catalog[ssid] = entry
                order.append(ssid)

            for key, field in (
                ("security_profile", "security_profiles"),
                ("authentication_profile", "authentication_profiles"),
                ("traffic_profile", "traffic_profiles"),
                ("forward_mode", "forward_modes"),
                ("service_vlan", "vlans"),
                ("vap_profile", "vap_profiles"),
            ):
                value = str(item.get(key, "")).strip()
                if value and value not in entry[field]:
                    entry[field].append(value)

        results = []
        for ssid in order:
            entry = catalog[ssid]
            results.append({
                "ssid": entry["ssid"],
                "security": entry["security"],
                "security_profile": ", ".join(entry["security_profiles"]),
                "authentication_profile": ", ".join(entry["authentication_profiles"]),
                "traffic_profile": ", ".join(entry["traffic_profiles"]),
                "forward_mode": ", ".join(entry["forward_modes"]),
                "vlan": ", ".join(entry["vlans"]),
                "vap_profile_count": len(entry["vap_profiles"]),
                "vap_profiles": ", ".join(entry["vap_profiles"]),
            })

        return results

    def build_group_mapping(self):
        wlan_map = {
            item["vap_profile"]: item
            for item
            in self.build_wlan_relationships()
        }

        ap_members = {}

        for ap in self.data["aps"]:
            group = ap["group"]

            ap_members.setdefault(
                group,
                []
            ).append(ap)

        results = []

        for group in self.data["ap_groups"]:
            for radio_id, radio in (
                group["radios"].items()
            ):
                for mapping in (
                    radio["vap_mappings"]
                ):
                    wlan = wlan_map.get(
                        mapping["vap_profile"],
                        {}
                    )

                    vlan = (
                        mapping[
                            "service_vlan_override"
                        ]
                        or wlan.get(
                            "service_vlan",
                            ""
                        )
                    )

                    results.append(
                        {
                            "ap_group":
                                group["name"],
                            "ap_count":
                                len(
                                    ap_members.get(
                                        group["name"],
                                        []
                                    )
                                ),
                            "radio":
                                radio_id,
                            "wlan_id":
                                mapping["wlan_id"],
                            "vap_profile":
                                mapping[
                                    "vap_profile"
                                ],
                            "ssid":
                                wlan.get(
                                    "ssid",
                                    ""
                                ),
                            "security":
                                wlan.get(
                                    "security",
                                    ""
                                ),
                            "security_profile":
                                wlan.get(
                                    "security_profile",
                                    ""
                                ),
                            "vlan":
                                vlan,
                            "forward_mode":
                                wlan.get(
                                    "forward_mode",
                                    ""
                                ),
                        }
                    )

        return self._merge_radio_duplicates(results)

    @staticmethod
    def _merge_radio_duplicates(rows):
        """Collapse rows that differ only by radio index.

        A VAP/SSID mapping is very commonly applied identically across
        every radio band (0 = 2.4GHz, 1 = 5GHz, 2 = 6GHz, etc.) on the
        same AP group. That's one logical deployment, not three, so
        list it once with the radios it's active on instead of one row
        per radio.
        """
        merged = {}
        order = []

        for row in rows:
            key = (
                row["ap_group"], row["wlan_id"], row["vap_profile"],
                row["ssid"], row["security"], row["security_profile"],
                row["vlan"], row["forward_mode"],
            )
            entry = merged.get(key)
            if entry is None:
                entry = dict(row)
                entry["radios"] = []
                merged[key] = entry
                order.append(key)
            radio = str(row["radio"])
            if radio not in entry["radios"]:
                entry["radios"].append(radio)

        results = []
        for key in order:
            entry = merged[key]
            radios = sorted(entry.pop("radios"), key=lambda r: (len(r), r))
            entry["radio"] = ", ".join(radios)
            results.append(entry)

        return results

    def build_ap_profile_details(self):
        groups = {
            group["name"]: group
            for group in self.data["ap_groups"]
        }

        mappings = self.build_group_mapping()

        mapping_by_group = {}

        for item in mappings:
            mapping_by_group.setdefault(
                item["ap_group"],
                []
            ).append(item)

        result = []

        for ap in self.data["aps"]:
            group = groups.get(
                ap["group"],
                {}
            )

            result.append(
                {
                    **ap,
                    "ap_system_profile":
                        group.get(
                            "ap_system_profile",
                            ""
                        ),
                    "location_profile":
                        group.get(
                            "location_profile",
                            ""
                        ),
                    "wlan_mappings":
                        mapping_by_group.get(
                            ap["group"],
                            []
                        ),
                    "group_config":
                        group.get(
                            "config",
                            []
                        ),
                }
            )

        return result
