from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzers.assessment_analyzer import AssessmentAnalyzer
from .analyzers.relationship_analyzer import RelationshipAnalyzer
from .exporters.excel_exporter import ExcelExporter
from .importers.ap_inventory_importer import APInventoryImporter
from .parsers.cisco9800_parser import Cisco9800ConfigParser
from .parsers.config_parser import HuaweiConfigParser
from .inventory_master import compare_inventory, read_inventory
from .summaries import build_ap_device_summary


def detect_vendor(content: str) -> str:
    lowered = content.lower()
    if (
        "cisco ios xe software" in lowered
        or "c9800" in lowered
        or "show tech-support wireless" in lowered
        or "wireless management interface" in lowered
        or "wireless tag policy" in lowered
        or "wireless profile policy" in lowered
    ):
        return "Cisco"
    return "Huawei"


def _normalize_data(data: dict[str, Any]) -> dict[str, Any]:
    data.setdefault("wlc", {})
    data.setdefault("interfaces", [])
    data.setdefault("local_users", [])
    data.setdefault("aps", [])
    data.setdefault("ap_groups", [])
    for key in (
        "security_profiles", "ssid_profiles", "vap_profiles", "traffic_profiles",
        "ap_system_profiles", "radio_2g_profiles", "radio_5g_profiles",
        "regulatory_domain_profiles", "wired_port_profiles",
    ):
        data.setdefault(key, [])

    for ap in data["aps"]:
        defaults = {
            "ap_id": "", "name": "", "group": "", "type_id": "", "model": "",
            "mac": "", "serial": "", "ip": "", "status": "", "version": "",
            "inventory_match": "", "match_method": "",
        }
        for key, value in defaults.items():
            ap.setdefault(key, value)
        if not ap.get("model"):
            ap["model"] = ap.get("type_id", "")

    for user in data["local_users"]:
        user.setdefault("username", "")
        user.setdefault("privilege", "")
        user.setdefault("service_type", "")
        user.setdefault("state", "")
        config = user.get("config")
        if config is None:
            raw = user.get("configuration", "")
            config = [part.strip() for part in str(raw).split(" | ") if part.strip()]
            user["config"] = config
        elif isinstance(config, str):
            user["config"] = [config]
    return data


def _status_counts(data: dict[str, Any]) -> dict[str, int]:
    vendor = str(data.get("vendor", "Huawei")).lower()
    counts = {"normal": 0, "idle": 0, "standby": 0, "fault": 0, "other": 0}
    for ap in data.get("aps", []):
        status = str(ap.get("status", "")).strip().lower()
        if vendor == "cisco":
            if status == "joined": counts["normal"] += 1
            elif status == "not joined": counts["idle"] += 1
            elif status == "not present": counts["standby"] += 1
            elif status == "fault": counts["fault"] += 1
            else: counts["other"] += 1
        else:
            if status in {"normal", "nor"}: counts["normal"] += 1
            elif status == "idle": counts["idle"] += 1
            elif status == "standby": counts["standby"] += 1
            elif status == "fault": counts["fault"] += 1
            else: counts["other"] += 1
    return counts


def analyze(content: str, vendor: str = "Auto Detect", inventory_path: Path | None = None, deployment_mode: str = "existing") -> dict[str, Any]:
    resolved_vendor = detect_vendor(content) if vendor.lower().startswith("auto") else vendor.title()
    parser = Cisco9800ConfigParser(content) if resolved_vendor.lower() == "cisco" else HuaweiConfigParser(content)
    data = _normalize_data(parser.parse())
    data["vendor"] = resolved_vendor

    inventory_stats: dict[str, Any] = {}
    inventory_validation: dict[str, Any] = {}
    deployment_validation: dict[str, Any] = {}
    if inventory_path:
        inventory_validation = read_inventory(inventory_path, resolved_vendor)
        if inventory_validation["summary"].get("missing_identity_columns"):
            missing = ", ".join(inventory_validation["summary"]["missing_identity_columns"])
            raise ValueError(f"AP Inventory tidak memiliki identity column wajib: {missing}")

        # Enrich parsed APs before comparison. Huawei AC6508 operational CSV
        # carries the runtime IP, model, software and state that do not exist
        # in `display current-configuration`; comparing first creates false
        # model mismatches and hides the actual operational state.
        #
        # This importer is Huawei-only (its docstring says so, and it reads
        # Huawei AP Info CSV column names). It used to run unconditionally
        # for any vendor, including Cisco -- Cisco's parser already carries a
        # reliable native status ("Joined"/"Not Joined") straight from
        # `show wireless stats ap join summary`, and the unconditional
        # `ap["status"] = inventory["status"]` overwrite in merge() clobbered
        # it with whatever unrelated "Status"-ish column happened to exist in
        # the uploaded AP Master file (e.g. a deployment-workflow value like
        # "Installed"), silently corrupting the dashboard and triggering a
        # false "unknown status" assessment warning for a perfectly healthy,
        # joined AP. Only run this Huawei-specific enrichment for Huawei.
        if resolved_vendor.lower() == "huawei":
            try:
                importer = APInventoryImporter(inventory_path)
                importer.load()
                inventory_stats = importer.merge(data.get("aps", []))
                for ap in data.get("aps", []):
                    ap["match_method"] = ap.get("inventory_match_method", ap.get("match_method", ""))
                    match_value = ap.get("inventory_match", "")
                    if isinstance(match_value, bool):
                        ap["inventory_match"] = "Matched" if match_value else "Unmatched"
            except Exception:
                inventory_stats = {}

        deployment_validation = compare_inventory(
            inventory_validation["records"],
            data.get("aps", []),
            resolved_vendor,
        )

        if not inventory_stats:
            inventory_stats = {
                "matched": deployment_validation.get("summary", {}).get("matched", 0),
                "unmatched": deployment_validation.get("summary", {}).get("missing", 0),
            }

    relationship = RelationshipAnalyzer(data)
    wlan = relationship.build_wlan_relationships()
    ssid_catalog = relationship.build_ssid_catalog()
    vap_inventory = relationship.build_vap_inventory()
    groups = relationship.build_group_mapping()
    profiles = relationship.build_ap_profile_details()
    assessment = AssessmentAnalyzer(data, inventory_stats).analyze()
    status_counts = _status_counts(data)
    ap_device_summary = build_ap_device_summary(data.get("aps", []))
    unique_ssids = sorted({str(item.get("ssid", "")).strip() for item in wlan if str(item.get("ssid", "")).strip()})

    return {
        "data": data,
        "inventory_stats": inventory_stats,
        "inventory_validation": inventory_validation,
        "deployment_validation": deployment_validation,
        "deployment_mode": deployment_mode,
        "wlan_relationships": wlan,
        "ssid_catalog": ssid_catalog,
        "vap_inventory": vap_inventory,
        "group_mapping": groups,
        "profile_details": profiles,
        "assessment": assessment,
        "status_counts": status_counts,
        "ap_device_summary": ap_device_summary,
        "cards": {
            "total_aps": len(data.get("aps", [])),
            "unique_ssids": len(unique_ssids),
            "ap_groups": len(data.get("ap_groups", [])),
            "vap_profiles": len(data.get("vap_profiles", [])),
            "local_users": len(data.get("local_users", [])),
        },
    }


def export_excel(data: dict[str, Any], path: Path) -> None:
    data = _normalize_data(data)
    analyzer = RelationshipAnalyzer(data)
    ExcelExporter(data, analyzer).export(path)
