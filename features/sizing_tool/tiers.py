"""Which licence tier or subscription the replacement needs, from what the captured device uses today.

A refresh is not a like-for-like part number: the licence follows the feature set.  Each hint below names the feature the capture shows in use (the **evidence**), the licence the
replacement needs, and how sure the tool is: ``stated`` means the vendor's own page says so (the link is on the hint); ``confirm`` means the vendor gates the feature per platform or
release and the architect must check it for the model chosen.  The tool keeps no price list and no product catalogue: a licence name is what the vendor prints.

Sources (read for this module):

* Cisco Catalyst 9000 licensing (Network Essentials / Network Advantage base licences, DNA Essentials / DNA Advantage terms, StackWise Virtual at Advantage level):
  https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html
  Feature-by-licence for a given platform: Cisco Feature Navigator, https://cfnng.cisco.com/
* Aruba Central Licensing Guide (Foundation and Advanced subscriptions for switches and access points):
  https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf
* Palo Alto Networks, Activate Subscription Licenses (Advanced WildFire, Advanced URL Filtering, Advanced DNS Security, Advanced Threat Prevention, support, Decryption Mirroring):
  https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/activate-subscription-licenses
* Fortinet, FortiGate security bundles (the FortiGuard services of each bundle):
  https://www.fortinet.com/support/support-services/fortiguard-security-subscriptions/fortigate-security-bundles
* F5, Good / Better / Best licensing overview (BIG-IP LTM, DNS, AFM, ASM / Advanced WAF, APM and the bundles), and K7752 for licensing a unit:
  https://www.f5.com/pdf/licensing/good-better-best-licensing-overview.pdf , https://my.f5.com/manage/s/article/K7752
* Huawei, WLAN licence control items (AP resources are licensed by count, the licence file is bound to the ESN):
  https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items
"""

from __future__ import annotations

import re
from datetime import date, datetime
from typing import Any

from .common import iso_date

URL = {
    "cisco": "https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst_9000/cat9000-config-available-licenses.html",
    "cisco_cfn": "https://cfnng.cisco.com/",
    "aruba": "https://arubanetworking.hpe.com/techdocs/central/pdfs/2.5.7/licensing-guide.pdf",
    "pan": "https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/subscriptions/activate-subscription-licenses",
    "forti": "https://www.fortinet.com/support/support-services/fortiguard-security-subscriptions/fortigate-security-bundles",
    "f5_gbb": "https://www.f5.com/pdf/licensing/good-better-best-licensing-overview.pdf",
    "f5_k7752": "https://my.f5.com/manage/s/article/K7752",
    "huawei": "https://support.huawei.com/enterprise/en/doc/EDOC1000082825/42125e24/licenses-control-items",
}


def _feature(asset: dict[str, Any], *names: str) -> int:
    """The count of the first feature of the asset whose name contains one of ``names`` (0 when absent)."""
    for item in asset.get("features", []):
        if any(name.lower() in item.get("name", "").lower() for name in names):
            return int(item.get("count") or 1)
    return 0


def _hint(feature: str, evidence: str, needs: str, certainty: str, url: str, why: str = "") -> dict[str, str]:
    return {"feature": feature, "evidence": evidence, "needs": needs, "certainty": certainty, "url": url, "why": why}


def _cisco_switch(asset: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    if not str(asset.get("model", "")).upper().startswith("C9"):
        return out
    for lic in asset.get("licences", []):
        if re.search(r"network (?:advantage|essentials)|dna (?:advantage|essentials)", lic.get("name", ""), re.I) and "not" not in str(lic.get("state", "")).lower():
            out.append(_hint("Licence in use", f"{lic['name']} ({lic.get('state') or 'state not printed'})", f"At least {lic['name']} on the replacement",
                             "stated", URL["cisco"], "A base licence (Network Essentials / Advantage) is perpetual; DNA Essentials / Advantage is a term subscription ordered with the device."))
    if "stackwise virtual" in asset.get("ha", "").lower():
        out.append(_hint("StackWise Virtual", asset["ha"], "Network Advantage (Cisco Switching Licensing: Advantage)", "stated", URL["cisco"],
                         "The licensing page lists StackWise Virtual Link among the Advantage-level capabilities."))
    routed = [name for name in ("OSPF", "BGP", "EIGRP", "VRF", "MPLS", "VXLAN", "EVPN") if _feature(asset, name)]
    if routed:
        out.append(_hint("Routing / overlay features", ", ".join(routed), "Network Essentials or Advantage, by feature and platform", "confirm", URL["cisco_cfn"],
                         "The licensing page sends the reader to Cisco Feature Navigator for the licence of each feature; look the feature up for the replacement model before ordering."))
    return out


def _aruba(asset: dict[str, Any]) -> list[dict[str, str]]:
    if asset["device_type"] == "switch":
        return [_hint("Aruba Central management", "Aruba switch in the capture set", "Central subscription per switch: Foundation, or Advanced", "stated", URL["aruba"],
                      "Foundation covers group configuration, monitoring, stack management and User-Based Tunneling. Advanced adds the NetConductor Fabric Wizard, Cloud Authentication and the Streaming API: choose Advanced only if one of them is wanted.")]
    if asset["device_type"] in ("access_point", "wlc"):
        return [_hint("Aruba Central management", "Aruba access points in the capture set", "Central subscription per AP: Foundation, or Advanced", "stated", URL["aruba"],
                      "Advanced adds Access / Spectrum / Monitor radio modes, Air Slice, Unified Communications, MultiZone, Live Upgrades and the Streaming API; the rest of the radio features are Foundation.")]
    return []


def _palo_alto(asset: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    counts = asset.get("inspection") or {}
    if counts.get("threat"):
        out.append(_hint("Security profiles on rules", f"{counts['threat']} rule(s) with antivirus / anti-spyware / vulnerability / WildFire profiles or a profile group",
                         "Threat Prevention (or Advanced Threat Prevention), and Advanced WildFire where a WildFire profile is used", "confirm", URL["pan"],
                         "A profile group hides its members: open the group to see whether it holds URL filtering, WildFire or DNS profiles, each of which is a subscription."))
    if counts.get("application"):
        out.append(_hint("URL / application rules", f"{counts['application']} rule(s) match an application or carry a URL filtering profile",
                         "Advanced URL Filtering where a URL filtering profile is used; App-ID itself needs no subscription", "confirm", URL["pan"],
                         "Advanced URL Filtering and Advanced DNS Security are cloud services: the replacement needs the subscription activated on its own serial."))
    if counts.get("decrypt"):
        out.append(_hint("Decryption", f"{counts['decrypt']} decryption rule(s)", "Support licence; Decryption Mirroring needs its own free licence if it is used", "stated", URL["pan"],
                         "Decryption is a platform feature; its cost is throughput (see 'Size on' in the replacement plan), not a subscription."))
    if _feature(asset, "GlobalProtect"):
        out.append(_hint("GlobalProtect", f"{_feature(asset, 'GlobalProtect')} GlobalProtect object(s)", "GlobalProtect subscription if the gateway uses features beyond basic remote access (for example host-information checks)", "confirm",
                         URL["pan"], "Confirm the list of features that need the subscription for the PAN-OS version of the replacement."))
    return out


def _fortinet(asset: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    counts = asset.get("inspection") or {}
    if counts.get("threat"):
        out.append(_hint("IPS / antivirus profiles on policies", f"{counts['threat']} polic(ies) with IPS or antivirus", "A FortiGuard bundle that includes IPS and anti-malware (NGFW Service Bundle or Enterprise AI Service Bundle)",
                         "stated", URL["forti"], "Both bundles on the vendor page list IPS and anti-malware with URL and DNS filtering; DLP and inline malware prevention are listed only in the Enterprise AI Service Bundle."))
    if counts.get("application"):
        out.append(_hint("Application control / web filter on policies", f"{counts['application']} polic(ies)", "FortiGuard web / DNS filtering (in both bundles); confirm the Application Control entitlement", "confirm", URL["forti"],
                         "The bundle page does not list Application Control: check it on the quote for the model."))
    vdoms = asset.get("capacity", {}).get("VDOMs / vsys", 0)
    if vdoms and vdoms > 10:
        out.append(_hint("Virtual domains", f"{int(vdoms)} VDOMs", "A VDOM licence above the default number of the model", "confirm", URL["forti"], "Fortinet ships a default number of VDOMs per model; check the datasheet of the replacement for the number it includes."))
    return out


def _f5(asset: dict[str, Any]) -> list[dict[str, str]]:
    modules = [item["name"].split(" (")[0] for item in asset.get("features", []) if item.get("group") == "Provisioned modules"]
    out = []
    if modules:
        out.append(_hint("Provisioned modules", ", ".join(modules), "Each module provisioned today licensed on the replacement (LTM, or the matching DNS / AFM / ASM = Advanced WAF / APM module or bundle)", "stated", URL["f5_gbb"],
                         "The Good / Better / Best overview lists the local traffic, DNS, AFM, ASM and APM modules and the bundles; a module that is provisioned but unused is a saving."))
    if "cluster" in asset.get("ha", "").lower() or asset.get("pair_with") or asset.get("pair_missing"):
        out.append(_hint("Device group", asset.get("ha", ""), "A licence on every unit of the pair, generated from each unit's registration key", "stated", URL["f5_k7752"], "A BIG-IP is licensed per unit (K7752)."))
    return out


def _huawei(asset: dict[str, Any]) -> list[dict[str, str]]:
    out = [_hint("Licence file", asset.get("serial") or "ESN not in the capture", "A new licence file issued for the ESN of the replacement", "stated", URL["huawei"], "A Huawei licence is bound to the ESN of the device that carries it.")]
    cap = asset.get("capacity", {})
    aps = cap.get("Access points") or cap.get("Access points (configured)") or cap.get("Access points joined")
    if asset["device_type"] == "wlc" and aps:
        out.append(_hint("AP resources", f"{int(aps)} access points managed", f"AP licence for at least {int(aps)} (plus growth)", "stated", URL["huawei"], "Huawei licenses the number of APs a controller manages."))
    return out


_BY_VENDOR = {"Aruba": _aruba, "Palo Alto": _palo_alto, "Fortinet": _fortinet, "F5": _f5, "Huawei": _huawei}


def hints(asset: dict[str, Any]) -> list[dict[str, str]]:
    """The tier hints of one asset."""
    try:
        if asset.get("vendor") == "Cisco" and asset.get("device_type") == "switch":
            return _cisco_switch(asset)
        handler = _BY_VENDOR.get(asset.get("vendor", ""))
        return handler(asset) if handler else []
    except Exception:
        return []


def licence_tiers(assets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One row per hint and per group of devices that share it (so 40 access switches on Network Advantage are one row with 40 devices)."""
    rows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for asset in assets:
        for hint in hints(asset):
            key = (asset.get("vendor", ""), hint["feature"], hint["needs"], hint["certainty"])
            row = rows.setdefault(key, {"vendor": asset.get("vendor", ""), **hint, "devices": [], "evidence_samples": []})
            row["devices"].append(asset.get("hostname") or asset.get("source", ""))
            if hint["evidence"] not in row["evidence_samples"] and len(row["evidence_samples"]) < 3:
                row["evidence_samples"].append(hint["evidence"])
    out = sorted(rows.values(), key=lambda r: (r["vendor"], r["feature"]))
    for row in out:
        row["count"] = len(row["devices"])
        row["devices"] = row["devices"][:40]
    return out


def coterm(assets: list[dict[str, Any]], today: date | None = None, window_days: int = 120) -> list[dict[str, Any]]:
    """Licences with an end date, grouped into renewal windows: dates that are within ``window_days`` of the previous one belong to one window, and the latest date of the window is
    the co-term date to ask the vendor for (one renewal quote and one end date instead of one per device).  Expired licences form their own first window."""
    today = today or date.today()
    items = []
    for asset in assets:
        for lic in asset.get("licences", []):
            day = iso_date(lic.get("expires", ""))
            if day:
                items.append((datetime.strptime(day, "%Y-%m-%d").date(), asset.get("vendor", ""), asset.get("hostname") or asset.get("source", ""), lic.get("name", "")))
    items.sort()
    groups: list[list[tuple[date, str, str, str]]] = []
    for item in items:
        if groups and (item[0] - groups[-1][-1][0]).days <= window_days and (item[0] < today) == (groups[-1][-1][0] < today):
            groups[-1].append(item)
        else:
            groups.append([item])
    out = []
    for group in groups:
        out.append({"from": group[0][0].isoformat(), "to": group[-1][0].isoformat(), "coterm": group[-1][0].isoformat(), "expired": group[-1][0] < today, "licences": len(group),
                    "devices": len({g[2] for g in group}), "vendors": sorted({g[1] for g in group}), "samples": sorted({f"{g[2]}: {g[3]}" for g in group})[:6],
                    "days_between": (group[-1][0] - group[0][0]).days})
    return out
