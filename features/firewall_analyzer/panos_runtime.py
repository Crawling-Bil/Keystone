"""Facts from ``show system info`` that no PAN-OS configuration format carries: model, serial, software and content versions,
licence-dependent features, advanced-routing flag.  The capture has to include the command; a bare config export has none of it.

The findings only fire when the *configuration* depends on what the unit reports (a threat profile on a unit with no threat
content), so a plain staging box with no policy yet does not get noise.

Reference: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-upgrade/software-and-content-updates/install-content-and-software-updates
"""

from __future__ import annotations

import re
from typing import Any

from ..analyzer_core.findings import finding
from ..analyzer_core.result import kv_section
from .refs import PALO

LABELS = (
    ("model", "Model"), ("family", "Platform family"), ("serial", "Serial"), ("sw-version", "PAN-OS version"), ("uptime", "Uptime"), ("ip-address", "Management IP"), ("default-gateway", "Management gateway"),
    ("mac-address", "Management MAC"), ("app-version", "Applications content"), ("threat-version", "Threat content"), ("av-version", "Antivirus content"), ("wildfire-version", "WildFire content"),
    ("wildfire-rt", "WildFire real-time"), ("url-db", "URL database"), ("url-filtering-version", "URL filtering database"), ("global-protect-datafile-version", "GlobalProtect data file"),
    ("device-dictionary-version", "Device dictionary"), ("multi-vsys", "Multi virtual system"), ("advanced-routing", "Advanced routing"), ("operational-mode", "Operational mode"),
    ("device-certificate-status", "Device certificate"), ("zero-touch-provisioning", "Zero-touch provisioning"), ("cloud-mode", "Cloud mode"), ("vpn-disable-mode", "VPN disable mode"),
)
ZERO = {"", "0", "0.0", "0000.00.00.000", "none", "unknown"}


def advanced_routing(info: dict[str, str]) -> bool | None:
    value = (info.get("advanced-routing") or "").strip().lower()
    return True if value == "on" else False if value == "off" else None


def _missing(info: dict[str, str], key: str) -> bool:
    return key in info and info[key].strip().lower() in ZERO


def version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", text.split("-")[0])[:3])


def section(info: dict[str, str]) -> list[dict[str, Any]]:
    if not info:
        return []
    pairs = []
    for key, label in LABELS:
        if info.get(key, "") != "":
            tone = "warn" if key in ("threat-version", "av-version", "url-filtering-version") and _missing(info, key) else ("warn" if key == "device-certificate-status" and info[key].lower() == "none" else "")
            pairs.append((label, info[key], tone) if tone else (label, info[key]))
    return [kv_section("runtime_identity", "Device identity (show system info)", pairs, group="System",
                       hint="Only a capture that includes 'show system info' carries these values; a configuration export does not. Content versions of 0 mean the content was never installed on this unit.")]


def evaluate(d: dict[str, Any], info: dict[str, str]) -> list[dict[str, Any]]:
    if not info:
        return []
    out: list[dict[str, Any]] = []
    profiles = d.get("security_profiles", [])
    grouped = [r for r in d.get("security_rules", []) if r.get("profile_setting") and not r.get("disabled")]
    threat = [p for p in profiles if str(p.get("type", "")).lower() in ("virus", "antivirus", "spyware", "anti-spyware", "vulnerability", "wildfire-analysis", "wildfire")]
    if (_missing(info, "threat-version") or _missing(info, "av-version")) and (threat or grouped):
        absent = [name for key, name in (("threat-version", "Threat"), ("av-version", "Antivirus")) if _missing(info, key)]
        reported = ", ".join(f"{k} {info.get(k, 'n/a')}" for k in ("threat-version", "av-version", "wildfire-version"))
        out.append(finding("PAN-RT-001", "medium" if grouped else "low", "Content updates", f"{' and '.join(absent)} content is not installed but the policy uses threat profiles", obj="show system info",
                           detail=f"The unit reports {reported}, so Vulnerability, Anti-Spyware and Antivirus profiles have no signatures to match. "
                                  f"The configuration has {len(threat)} threat profile(s) and {len(grouped)} enabled rule(s) with a profile group; traffic matching them is allowed without that inspection. Applications content: {info.get('app-version', 'n/a')}.",
                           recommendation="Install a licence (Threat Prevention / Advanced Threat Prevention), then Device > Dynamic Updates > Check Now and download/install Antivirus and Applications and Threats; schedule automatic updates.", reference=PALO["content_updates"]))
    url_profiles = [p for p in profiles if "url" in str(p.get("type", "")).lower()]
    if url_profiles and _missing(info, "url-filtering-version"):
        out.append(finding("PAN-RT-002", "medium" if grouped else "low", "Content updates", "URL filtering profile exists but no URL filtering database is installed", obj="show system info",
                           detail=f"url-filtering-version is {info.get('url-filtering-version', '0')} with url-db '{info.get('url-db', 'n/a')}'. URL category rules in {len(url_profiles)} URL filtering profile(s) cannot classify sites without the PAN-DB/BrightCloud database, so category blocks do not take effect (custom URL categories still work).",
                           recommendation="Activate the URL Filtering licence and download PAN-DB (Device > Licenses, then Objects > Security Profiles > URL Filtering shows the database state).", reference=PALO["content_updates"]))
    if (info.get("device-certificate-status") or "").strip().lower() == "none":
        out.append(finding("PAN-RT-003", "info", "Device", "No device certificate is installed", obj="show system info",
                           detail="device-certificate-status is None. Cloud-delivered services (Strata Logging Service, Advanced WildFire cloud, IoT Security, DLP and others) authenticate the firewall with this certificate.",
                           recommendation="Install it from the Customer Support Portal one-time password (Device > Setup > Management > Device Certificate) if any cloud service is planned.", reference=PALO["device_cert"]))
    return out
