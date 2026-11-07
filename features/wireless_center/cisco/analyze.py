"""Cisco 9800 analysis: findings, cards and the payload the Cisco workspace
renders. Rules follow how a 9800 delivers service: a WLAN reaches an AP only
through Policy Tag (WLAN + Policy Profile) and the AP's tags."""
from __future__ import annotations

from collections import Counter
from typing import Any

from ..inventory_master import compare_inventory, read_inventory
from ..summaries import build_ap_device_summary
from . import parser9800

DEFAULT_TAGS = {"policy_tag": "default-policy-tag", "site_tag": "default-site-tag", "rf_tag": "default-rf-tag"}
UP_STATES = {"Registered", "Joined"}


def _finding(severity, category, title, detail, items=None):
    return {"severity": severity, "category": category, "title": title, "detail": detail, "items": list(items or [])[:200],
            "count": len(items) if items is not None else 1}


def findings(m: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    aps, wlans = m["aps"], m["wlans"]
    runtime = m["source_kind"] != "running-config"
    wlan_by_profile = {w["profile"]: w for w in wlans}
    policy_by_name = {p["name"]: p for p in m["policy_profiles"]}
    tags_used = Counter(a["policy_tag"] for a in aps if a.get("policy_tag"))
    label = lambda a: a.get("name") or a["mac"]

    if runtime:
        down = [a for a in aps if a["state"] not in UP_STATES]
        if down:
            out.append(_finding("Critical", "AP", f"{len(down)} AP not registered",
                                "Configured on this controller (static tags) or joined before, but not registered now. On an N+1 pair they may be joined to the other controller.",
                                [f"{label(a)} ({a['state']}{', ' + a['disconnect_reason'] if a.get('disconnect_reason') else ''})" for a in down]))
    bad = [a for a in aps if (a.get("misconfigured") or "").lower() == "yes"]
    if bad:
        out.append(_finding("Critical", "Tags", f"{len(bad)} AP with misconfigured tags",
                            "The controller flags the tag set of these APs as invalid.", [label(a) for a in bad]))
    for key, name in (("policy_tag", "Policy Tag"), ("site_tag", "Site Tag")):
        on_default = [a for a in aps if a.get(key) == DEFAULT_TAGS[key] and a["state"] in UP_STATES | {"Configured"}]
        if on_default:
            what = "broadcasts no WLAN unless the default tag was edited" if key == "policy_tag" else "uses the default AP Join and Flex profiles"
            out.append(_finding("Warning", "Tags", f"{len(on_default)} AP on {DEFAULT_TAGS[key]}",
                                f"An AP on the default {name} {what}.", [label(a) for a in on_default]))

    for tag in m["policy_tags"]:
        missing_w = [mp["wlan"] for mp in tag["mappings"] if mp["wlan"] not in wlan_by_profile]
        missing_p = [mp["policy"] for mp in tag["mappings"] if mp["policy"] not in policy_by_name]
        if missing_w or missing_p:
            out.append(_finding("Critical", "Policy Tag", f"Policy Tag {tag['name']} points to objects that do not exist",
                                "Missing WLAN or Policy Profile: the mapping is not delivered.",
                                [f"WLAN {w}" for w in missing_w] + [f"Policy {p}" for p in missing_p]))
        for mp in tag["mappings"]:
            w, p = wlan_by_profile.get(mp["wlan"]), policy_by_name.get(mp["policy"])
            if w and p and w["status"] == "UP" and p["status"] != "Enabled":
                out.append(_finding("Warning", "Policy Profile", f"WLAN {w['ssid']} uses disabled Policy Profile {p['name']}",
                                    f"In Policy Tag {tag['name']} the WLAN is UP but its Policy Profile is shut down, so it is not broadcast.",
                                    [tag["name"]]))
    unused_tags = [t["name"] for t in m["policy_tags"] if runtime and aps and not tags_used.get(t["name"]) and t["name"] != DEFAULT_TAGS["policy_tag"]]
    if unused_tags:
        out.append(_finding("Info", "Policy Tag", f"{len(unused_tags)} Policy Tag not used by any AP", "Candidates for clean-up.", unused_tags))

    mapped = {mp["wlan"] for t in m["policy_tags"] for mp in t["mappings"]}
    orphan = [w for w in wlans if w["profile"] not in mapped]
    if orphan:
        out.append(_finding("Warning", "WLAN", f"{len(orphan)} WLAN in no Policy Tag",
                            "A WLAN reaches APs only through a Policy Tag; these are never broadcast.", [f"{w['id']} {w['ssid']}" for w in orphan]))
    for w in wlans:
        if w["status"] == "UP" and w["security"] == "Open" and not w["mac_filtering"] and not w["web_auth"]:
            out.append(_finding("Critical", "WLAN", f"Open WLAN {w['ssid']} without MAC filtering or web auth",
                                "Anyone in range can associate.", [f"WLAN {w['id']}"]))
        if not w["broadcast"]:
            out.append(_finding("Info", "WLAN", f"WLAN {w['ssid']} hides its SSID", "Hidden SSIDs do not add security and slow down client roaming.", [f"WLAN {w['id']}"]))
    used_policies = {mp["policy"] for t in m["policy_tags"] for mp in t["mappings"]}
    no_vlan = [p["name"] for p in m["policy_profiles"] if p["name"] in used_policies and not p["vlan"] and p["switching"] == "Central"]
    if no_vlan:
        out.append(_finding("Warning", "Policy Profile", f"{len(no_vlan)} Policy Profile in use without a VLAN",
                            "Centrally switched clients land in VLAN 1 (the default).", no_vlan))

    versions = Counter(a["version"] for a in aps if a.get("version"))
    if len(versions) > 1:
        out.append(_finding("Warning", "Software", f"APs run {len(versions)} software versions",
                            "Mixed AP images usually mean a predownload or upgrade did not finish.",
                            [f"{v}: {n} AP" for v, n in versions.most_common()]))
    no_backup = [a for a in aps if a.get("secondary_wlc") in {"Not Configured", ""} and a.get("primary_wlc")]
    if no_backup and (m["wlc"].get("ha_mode") or "").lower() != "sso":
        out.append(_finding("Warning", "Redundancy", f"{len(no_backup)} AP without a secondary controller and no SSO pair",
                            "If this controller fails these APs have no configured place to join.", [label(a) for a in no_backup]))
    for r in m["wlc"].get("radios", []):
        if r["total"] and r["down"]:
            sev = "Warning" if r["down"] / r["total"] >= 0.2 else "Info"
            out.append(_finding(sev, "Radio", f"{r['down']} of {r['total']} {r['band']} radios down",
                                "Check `show ap dot11 ... summary`: radios can be disabled by RF profile, DFS or admin state.", []))
    plain = [u["username"] for u in m["local_users"] if u["plaintext"]]
    if plain:
        out.append(_finding("Warning", "Management", f"{len(plain)} local user with a type 0 password",
                            "Type 0 is stored in clear text; use `secret 9`.", plain))
    if not m["wlc"].get("ha_mode"):
        out.append(_finding("Info", "Redundancy", "HA state not in the capture", "Add `show redundancy` (part of show tech-support wireless).", []))
    order = {"Critical": 0, "Warning": 1, "Info": 2}
    return sorted(out, key=lambda f: (order.get(f["severity"], 3), f["category"], f["title"]))


def analyze(content: str, inventory_path=None, deployment_mode: str = "existing") -> dict[str, Any]:
    m = parser9800.parse(content)
    if not (m["wlans"] or m["aps"] or m["policy_tags"]):
        raise ValueError("This does not look like a Cisco 9800 capture: no WLAN, AP or tag found. "
                         "Upload show tech-support wireless or show running-config from the 9800.")
    if m["source_kind"] == "running-config":
        for ap in m["aps"]:
            if ap["state"] == "Not joined":
                ap["state"] = "Configured"
    # shape shared with deployment validation and the AP model summary
    for ap in m["aps"]:
        ap["status"] = ap["state"]
        ap["group"] = ap.get("policy_tag", "")
    deployment = {}
    validation = {}
    if inventory_path:
        validation = read_inventory(inventory_path, "Cisco")
        if validation["summary"].get("missing_identity_columns"):
            raise ValueError("AP Master is missing identity columns: " + ", ".join(validation["summary"]["missing_identity_columns"]))
        deployment = compare_inventory(validation["records"], m["aps"], "Cisco")
    states = Counter(a["state"] for a in m["aps"])
    result_findings = findings(m)
    sev = Counter(f["severity"] for f in result_findings)
    return {
        "vendor": "Cisco",
        "cisco": m,
        "data": {"vendor": "Cisco", "wlc": m["wlc"], "aps": m["aps"]},
        "findings": result_findings,
        "severity": dict(sev),
        "status_counts": dict(states),
        "ap_device_summary": build_ap_device_summary(m["aps"]),
        "deployment_validation": deployment,
        "inventory_validation": validation,
        "deployment_mode": deployment_mode,
        "cards": {
            "total_aps": len(m["aps"]),
            "registered": sum(states[s] for s in UP_STATES),
            "wlans": len(m["wlans"]),
            "wlans_up": sum(w["status"] == "UP" for w in m["wlans"]),
            "policy_tags": len(m["policy_tags"]),
            "policy_profiles": len(m["policy_profiles"]),
            "site_tags": len(m["site_tags"]),
        },
        "assessment": {"summary": {"total_aps": len(m["aps"])}},
    }
