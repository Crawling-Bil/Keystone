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
                    "AP tidak memiliki AP Group",
                "reason": (
                    "AP ditemukan pada konfigurasi WLC tetapi "
                    "tidak memiliki assignment AP Group."
                ),
                "possible_causes": [
                    "AP belum selesai dikonfigurasi.",
                    "AP menggunakan konfigurasi default.",
                    "Assignment AP Group terhapus.",
                    "AP merupakan stale configuration.",
                ],
                "recommendation": [
                    "Verifikasi fungsi dan lokasi AP.",
                    "Pastikan AP Group sesuai dengan site.",
                    "Review WLAN/VAP yang seharusnya dilayani AP.",
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
                    "AP tidak memiliki AP Name",
                "reason": (
                    "AP terdaftar pada konfigurasi WLC tetapi "
                    "hostname atau AP Name tidak ditemukan."
                ),
                "possible_causes": [
                    "AP belum diberi hostname.",
                    "Konfigurasi AP tidak lengkap.",
                    "AP merupakan konfigurasi lama.",
                ],
                "recommendation": [
                    "Identifikasi AP berdasarkan MAC dan Serial Number.",
                    "Gunakan naming convention yang konsisten.",
                    "Tambahkan AP Name jika AP masih aktif.",
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
                f"AP memiliki status '{status}'",
            "reason": (
                f"AP terdeteksi dengan operational status "
                f"'{status}'. Status ini menunjukkan AP "
                "tidak berada dalam kondisi operational normal "
                "dan membutuhkan pengecekan."
            ),
            "possible_causes": [
                "AP kehilangan koneksi ke WLC.",
                "AP kehilangan koneksi jaringan.",
                "Masalah switchport atau VLAN management.",
                "Masalah PoE atau power.",
                "Masalah CAPWAP antara AP dan WLC.",
                "AP mengalami hardware atau software failure.",
            ],
            "recommendation": [
                "Verifikasi status AP langsung pada WLC.",
                "Cek reachability IP management AP.",
                "Cek switchport tempat AP terhubung.",
                "Verifikasi VLAN management AP.",
                "Verifikasi PoE dan kondisi power AP.",
                "Review log WLC untuk AP tersebut.",
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
                f"AP memiliki status transisi '{status}'",
            "reason": (
                f"AP terdeteksi dengan status '{status}'. "
                "Status ini dapat muncul ketika AP sedang "
                "melakukan proses discovery, join, atau "
                "sinkronisasi konfigurasi dengan WLC."
            ),
            "possible_causes": [
                "AP sedang melakukan proses join.",
                "AP sedang melakukan sinkronisasi konfigurasi.",
                "Koneksi AP ke WLC tidak stabil.",
                "Proses CAPWAP belum selesai.",
            ],
            "recommendation": [
                "Monitor apakah status kembali normal.",
                "Verifikasi konektivitas AP ke WLC.",
                "Review proses CAPWAP jika status menetap.",
                "Review log WLC terkait AP tersebut.",
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
                f"AP memiliki status yang belum dikenali '{status}'",
            "reason": (
                f"Analyzer menemukan operational status "
                f"'{status}', tetapi status tersebut belum "
                "memiliki classification rule pada analyzer. "
                "Status ini tidak otomatis dianggap sebagai "
                "kondisi critical."
            ),
            "possible_causes": [
                "Status khusus pada versi Huawei WLC tertentu.",
                "Status baru yang belum dimasukkan ke analyzer.",
                "Perbedaan format output AP inventory.",
            ],
            "recommendation": [
                "Verifikasi arti status pada WLC.",
                "Review kondisi operational AP.",
                "Tambahkan status ke classification rule jika diperlukan.",
            ],
        }
