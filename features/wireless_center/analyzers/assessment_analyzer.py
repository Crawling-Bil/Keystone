class AssessmentAnalyzer:

    # Huawei VRP AP operational states (`display ap all`).
    HUAWEI_HEALTHY_STATUSES = {
        "",
        "normal",
        "online",
        "up",
        "standby",
    }
    HUAWEI_CRITICAL_STATUSES = {
        "fault",
        "offline",
        "down",
    }
    HUAWEI_WARNING_STATUSES = {
        "idle",
        "disconnected",
        "discovery",
        "joining",
        "join",
        "config",
        "configuring",
    }

    # Cisco IOS-XE (Catalyst 9800) AP join states
    # (`show wireless stats ap join summary`).
    CISCO_HEALTHY_STATUSES = {
        "",
        "joined",
    }
    CISCO_CRITICAL_STATUSES = {
        "not joined",
    }
    CISCO_WARNING_STATUSES = {
        "not present",
    }

    def __init__(self, data, inventory_stats=None):
        self.data = data or {}
        self.inventory_stats = inventory_stats or {}
        vendor = str(self.data.get("vendor", "Huawei")).strip().lower()
        if vendor == "cisco":
            self.HEALTHY_STATUSES = self.CISCO_HEALTHY_STATUSES
            self.CRITICAL_STATUSES = self.CISCO_CRITICAL_STATUSES
            self.WARNING_STATUSES = self.CISCO_WARNING_STATUSES
        else:
            self.HEALTHY_STATUSES = self.HUAWEI_HEALTHY_STATUSES
            self.CRITICAL_STATUSES = self.HUAWEI_CRITICAL_STATUSES
            self.WARNING_STATUSES = self.HUAWEI_WARNING_STATUSES

    def analyze(self):
        aps = self.data.get("aps", [])
        findings = []

        self._check_missing_group(aps, findings)
        self._check_missing_name(aps, findings)
        self._check_status(aps, findings)

        order = {
            "CRITICAL": 0,
            "WARNING": 1,
            "INFO": 2,
        }

        findings.sort(
            key=lambda item: order.get(
                item.get("severity", "INFO"),
                99
            )
        )

        critical = sum(
            1 for item in findings
            if item.get("severity") == "CRITICAL"
        )

        warning = sum(
            1 for item in findings
            if item.get("severity") == "WARNING"
        )

        if critical:
            health = "ATTENTION"
        elif warning:
            health = "WARNING"
        else:
            health = "HEALTHY"

        return {
            "summary": {
                "total_aps": len(aps),
                "inventory_total":
                    self.inventory_stats.get(
                        "total_inventory",
                        0
                    ),
                "matched":
                    self.inventory_stats.get(
                        "matched",
                        0
                    ),
                "unmatched":
                    self.inventory_stats.get(
                        "unmatched",
                        0
                    ),
                "warning": warning,
                "critical": critical,
                "health": health,
            },
            "findings": findings,
        }

    def _base(self, ap):
        return {
            "ap_id": ap.get("ap_id", ""),
            "ap_name": ap.get("name", ""),
            "ap_group": ap.get("group", ""),
            "mac": ap.get("mac", ""),
            "serial": ap.get("serial", ""),
            "status": ap.get("status", ""),
        }

    def _check_missing_group(self, aps, findings):
        for ap in aps:
            if str(
                ap.get("group", "")
            ).strip():
                continue

            finding = self._base(ap)

            finding.update({
                "severity": "WARNING",
                "category": "AP Configuration",
                "title":
                    "AP has no AP Group",
                "reason": (
                    "The AP is in the WLC configuration but "
                    "has no AP Group assignment."
                ),
                "possible_causes": [
                    "The AP has not been fully configured.",
                    "The AP uses the default configuration.",
                    "The AP Group assignment was removed.",
                    "The AP is a stale configuration entry.",
                ],
                "recommendation": [
                    "Verify the role and location of the AP.",
                    "Make sure the AP Group matches the site.",
                    "Review the WLANs/VAPs this AP is supposed to serve.",
                ],
            })

            findings.append(finding)

    def _check_missing_name(self, aps, findings):
        for ap in aps:
            if str(
                ap.get("name", "")
            ).strip():
                continue

            finding = self._base(ap)

            finding.update({
                "severity": "WARNING",
                "category": "AP Configuration",
                "title":
                    "AP has no AP Name",
                "reason": (
                    "The AP is registered in the WLC configuration but "
                    "its hostname or AP Name is missing."
                ),
                "possible_causes": [
                    "The AP has not been given a hostname.",
                    "The AP configuration is incomplete.",
                    "The AP is an old configuration entry.",
                ],
                "recommendation": [
                    "Identify the AP by its MAC address and serial number.",
                    "Use a consistent naming convention.",
                    "Add an AP Name if the AP is still in use.",
                ],
            })

            findings.append(finding)

    def _check_status(self, aps, findings):
        for ap in aps:
            status = str(
                ap.get("status", "")
            ).strip()

            status_normalized = (
                status.lower()
            )

            if (
                not status
                or status_normalized
                in self.HEALTHY_STATUSES
            ):
                continue

            finding = self._base(ap)

            if (
                status_normalized
                in self.CRITICAL_STATUSES
            ):

                finding.update(
                    self._critical_status_finding(
                        status
                    )
                )

            elif (
                status_normalized
                in self.WARNING_STATUSES
            ):

                finding.update(
                    self._warning_status_finding(
                        status
                    )
                )

            else:

                finding.update(
                    self._unknown_status_finding(
                        status
                    )
                )

            findings.append(finding)

    def _critical_status_finding(
        self,
        status
    ):
        return {
            "severity": "CRITICAL",
            "category": "AP Operational",
            "title":
                f"AP has status '{status}'",
            "reason": (
                f"The AP was found with operational status "
                f"'{status}'. This status means the AP "
                "is not in a normal operational state "
                "and needs to be checked."
            ),
            "possible_causes": [
                "The AP lost its connection to the WLC.",
                "The AP lost its network connection.",
                "A switchport or management VLAN problem.",
                "A PoE or power problem.",
                "A CAPWAP problem between the AP and the WLC.",
                "The AP has a hardware or software failure.",
            ],
            "recommendation": [
                "Verify the AP status directly on the WLC.",
                "Check that the AP management IP is reachable.",
                "Check the switchport the AP is connected to.",
                "Verify the AP management VLAN.",
                "Verify PoE and the power state of the AP.",
                "Review the WLC log for this AP.",
            ],
        }

    def _warning_status_finding(
        self,
        status
    ):
        return {
            "severity": "WARNING",
            "category": "AP Operational",
            "title":
                f"AP has transitional status '{status}'",
            "reason": (
                f"The AP was found with status '{status}'. "
                "This status can appear while the AP is "
                "going through discovery, join or "
                "configuration synchronisation with the WLC."
            ),
            "possible_causes": [
                "The AP is joining the WLC.",
                "The AP is synchronising its configuration.",
                "The AP connection to the WLC is unstable.",
                "The CAPWAP process has not finished.",
            ],
            "recommendation": [
                "Watch whether the status returns to normal.",
                "Verify the connectivity between the AP and the WLC.",
                "Review the CAPWAP process if the status persists.",
                "Review the WLC log for this AP.",
            ],
        }

    def _unknown_status_finding(
        self,
        status
    ):
        return {
            "severity": "WARNING",
            "category": "AP Operational",
            "title":
                f"AP has an unrecognised status '{status}'",
            "reason": (
                f"The analyzer found operational status "
                f"'{status}', but it has no classification "
                "rule in the analyzer. "
                "It is not treated as critical automatically."
            ),
            "possible_causes": [
                "A status specific to some Huawei WLC versions.",
                "A new status that has not been added to the analyzer.",
                "A different format of the AP inventory output.",
            ],
            "recommendation": [
                "Verify what the status means on the WLC.",
                "Review the operational state of the AP.",
                "Add the status to the classification rules if needed.",
            ],
        }
