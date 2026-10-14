"""Findings for the security modules (Advanced WAF, DoS, logging) and for global switches that are visible in the configuration.

Everything here reads ``data["extra"]`` (see ``bigip_security``); a capture without it simply yields nothing.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_context import LCtx
from .refs import F5


def security_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    extra = ctx.data.get("extra")
    if not extra:
        return []
    out: list[dict[str, Any]] = []
    for p in extra["asm_policies"]:
        if p["attached_to"] and not p["active"]:
            out.append(finding("LB-ASM-002", "medium", "Advanced WAF", "An LTM policy enables an ASM policy that is not active", obj=f"asm policy {p['name']}",
                               detail=f"{p['name']} is attached to {', '.join(p['attached_to'])} but has no 'active' flag, so it does not protect that traffic.",
                               recommendation="Apply the policy (Security > Application Security > Policies) or detach it from the virtual server.", reference=F5["asm_local_policy"]))
        elif not p["attached_to"]:
            why = (f"Its LTM policy ({', '.join(p['orphan_ltm'])}) exists but no virtual server uses it - usually a virtual server that was deleted without deleting the ASM policy." if p["orphan_ltm"]
                   else f"No enabled LTM policy action refers to {p['name']}.")
            out.append(finding("LB-ASM-001", "low" if p["active"] else "info", "Advanced WAF", "ASM policy is not attached to any virtual server", obj=f"asm policy {p['name']}",
                               detail=why + " It inspects no traffic. Old test policies accumulate and slow audits and ASM sync.", recommendation="Attach it through an LTM policy ('asm enable policy ...') or delete it.", reference=F5["asm_local_policy"]))
    if "asm" in extra["provisioned"] and extra["asm_policies"]:
        exposed = [r["virtual"] for r in extra["virtual_security"] if r["enabled"] and r["public"] and r["http"] and not r["asm"]]
        if exposed:
            out.append(finding("LB-ASM-004", "info", "Advanced WAF", f"{len(exposed)} public HTTP virtual server(s) have no ASM policy", obj=", ".join(exposed[:12]) + (" …" if len(exposed) > 12 else ""),
                               detail="ASM is provisioned and other virtual servers use it, but these public HTTP/HTTPS services are not covered by any enabled ASM policy action.",
                               recommendation="Confirm each is intentionally unprotected (for example a redirect-only listener) or attach a policy.", reference=F5["asm_local_policy"]))
    for d in extra["dos"]:
        if not d["used_by"]:
            out.append(finding("LB-DOS-001", "info", "DoS", "DoS profile is not attached to any virtual server", obj=f"security dos profile {d['name']}", detail="The profile exists but no virtual server lists it, so no DoS detection or mitigation runs for it.",
                               recommendation="Attach it to the virtual servers it was built for or delete it.", reference=F5["dos_apps"]))
    for item in extra["log_profiles"]:
        if not item["used_by"]:
            out.append(finding("LB-LOG-001", "info", "Logging", "Security logging profile is not attached to any virtual server", obj=f"security log profile {item['name']}", detail="Violations are only logged where the profile is attached.",
                               recommendation="Attach it to the protected virtual servers or remove it.", reference=F5["log_profile"]))
    for daemon, settings in extra["daemon_log"].items():
        loud = {k: v for k, v in settings.items() if k.endswith("log-level") and v.lower() == "debug"}
        if loud:
            ref = F5["daemon_log_tmm"] if daemon == "tmm" else F5["daemon_log_mcpd"]
            out.append(finding("LB-SYS-012", "low", "Logging", f"{daemon} logs at debug level", obj=f"sys daemon-log-settings {daemon}", detail=f"{', '.join(loud)} is set to debug. Debug logging on a production unit fills /var/log and costs CPU.",
                               recommendation="Return it to the default level once the troubleshooting is finished.", reference=ref))
    update = extra["software_update"]
    if update.get("auto-phonehome", "").lower() == "enabled":
        out.append(finding("LB-SYS-013", "info", "System", "Automatic phone-home to F5 is enabled", obj="sys software update", detail=f"auto-phonehome is enabled (auto-check {update.get('auto-check', 'n/a')}, frequency {update.get('frequency', 'n/a')}). "
                                                                                                   "The unit reports to F5 on a schedule; many security baselines require this to be a deliberate choice, and it needs outbound Internet access from the management network.",
                           recommendation="Keep it if the report is wanted and the egress is approved; otherwise disable it: tmsh modify sys software update auto-phonehome disabled.", reference=F5["software_update"]))
    return out
