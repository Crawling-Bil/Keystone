"""FortiGate findings.

Every rule works from the dictionaries produced by :mod:`forti_extract` and
cites Fortinet documentation through :mod:`refs`.  Rules only fire on what is
actually in the export: FortiOS ``show`` omits values that equal the default,
so a rule that depends on a default (HA monitor, DoS policy, ...) says so in its
text instead of claiming something is "disabled".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Callable, Iterable

from ..analyzer_core.findings import dedupe_findings, finding, sort_findings
from .forti_resolve import BUILTIN_OBJECT, RISKY_PORTS, Resolver
from .forti_tree import FortiTree
from .refs import FORTI

WEAK_DH_HIGH = {"1", "2"}                    # 768 / 1024 bit MODP
WEAK_DH_MEDIUM = {"5"}                       # 1536 bit MODP
MAX_PER_RULE = 25

GUESSABLE = "guessable"


@dataclass
class FCtx:
    tree: FortiTree
    data: dict[str, Any]
    res: Resolver
    today: date


def evaluate(tree: FortiTree, data: dict[str, Any], today: date | None = None) -> list[dict[str, Any]]:
    ctx = FCtx(tree=tree, data=data, res=Resolver(data), today=today or date.today())
    out: list[dict[str, Any]] = []
    for rule in RULES:
        out.extend(rule(ctx))
    return sort_findings(dedupe_findings(out))


def _cap(items: list[dict[str, Any]], rule_id: str, category: str, noun: str, reference: str = "") -> list[dict[str, Any]]:
    """Keep the list readable: show the first MAX_PER_RULE and summarise the rest."""
    if len(items) <= MAX_PER_RULE:
        return items
    kept = items[:MAX_PER_RULE]
    kept.append(finding(rule_id, "info", category, f"{len(items) - MAX_PER_RULE} more {noun} match this rule", detail=f"Only the first {MAX_PER_RULE} are listed. Sort the Policies tab by the same column to see the rest.", reference=reference))
    return kept


def _privileged(ctx: FCtx, profile: str) -> bool:
    if profile == "super_admin":
        return True
    for prof in ctx.data["accprofiles"]:
        if prof["name"] == profile:
            writes = [v for k, v in prof["perms"].items() if k not in ("scope", "admintimeout-override", "admintimeout", "system-diagnostics", "system-execute-ssh", "system-execute-telnet") and v == "read-write"]
            return len(writes) >= 6
    return False


def _intf_label(item: dict[str, Any]) -> str:
    return item["name"] + (f" ({item['ip']})" if item.get("ip") else "")


# ------------------------------------------------------------- administration
def admin_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    d, g = ctx.data, ctx.data["global"]
    ref = FORTI["harden_admin"]
    out: list[dict[str, Any]] = []

    for admin in d["admins"]:
        privileged = _privileged(ctx, admin["profile"])
        if admin["any_source"]:
            out.append(finding(
                "FGT-ADM-001", "high" if privileged else "medium", "Administration", "Administrator can log in from any address", obj=f"admin {admin['name']}",
                detail=f"Account '{admin['name']}' (profile {admin['profile'] or 'n/a'}) has no trusted host, or one that matches everything, so every interface that allows management accepts its login from anywhere.",
                recommendation="Set trusthost1..n to the management subnets (or a jump host /32), for example: config system admin / edit <name> / set trusthost1 10.0.0.0 255.255.255.0.", reference=ref))
        if admin["two_factor"] in ("disable", "") and not admin["remote_auth"]:
            out.append(finding(
                "FGT-ADM-002", "medium" if privileged else "low", "Administration", "Administrator without two-factor authentication", obj=f"admin {admin['name']}",
                detail=f"Account '{admin['name']}' authenticates with a local password only (two-factor is disabled).",
                recommendation="Enable FortiToken, email or SMS two-factor (set two-factor fortitoken) or move the account to a RADIUS/TACACS+/SAML backend that enforces MFA.", reference=ref))
        if admin["name"].lower() == "admin":
            out.append(finding(
                "FGT-ADM-003", "low", "Administration", "Default administrator account name is in use", obj="admin admin",
                detail="The built-in account name 'admin' is the first name attackers try. It cannot be deleted on every release, but it can be replaced by named accounts.",
                recommendation="Create named super-admin accounts, then restrict or rename the default one, and keep it for break-glass use with a long random password.", reference=ref))
        if admin["password"] == "clear":
            out.append(finding("FGT-ADM-009", "medium", "Administration", "Administrator password is stored readable", obj=f"admin {admin['name']}",
                               detail="The export holds this password unencrypted instead of as an ENC value.", recommendation="Re-export from a device with private-data-encryption enabled and rotate the password.", reference=FORTI["harden_70"]))

    if g.get("admin-telnet") == "enable":
        out.append(finding("FGT-ADM-004", "high", "Administration", "Telnet administration is enabled globally", obj="system global admin-telnet",
                           detail="admin-telnet lets the CLI be reached over clear-text Telnet on any interface that allows telnet access.",
                           recommendation="set admin-telnet disable and use SSH with trusted hosts.", reference=FORTI["harden_70"]))
    if g.get("admin-ssh-v1") == "enable":
        out.append(finding("FGT-ADM-005", "high", "Administration", "SSH protocol version 1 is enabled", obj="system global admin-ssh-v1",
                           detail="SSHv1 has known cryptographic weaknesses.", recommendation="set admin-ssh-v1 disable.", reference=FORTI["harden_70"]))
    versions = [v.lower() for v in g.get("admin-https-ssl-versions", "").split()]
    weak_versions = [v for v in versions if v in ("tlsv1-0", "tlsv1-1", "sslv3")]
    if weak_versions:
        out.append(finding("FGT-ADM-006", "medium", "Administration", "Legacy TLS versions allowed for the management GUI", obj="system global admin-https-ssl-versions",
                           detail="The GUI/REST listener accepts " + ", ".join(weak_versions) + ".", recommendation="set admin-https-ssl-versions tlsv1-2 tlsv1-3.", reference=FORTI["harden_70"]))
    if g.get("strong-crypto") == "disable":
        out.append(finding("FGT-ADM-007", "medium", "Administration", "strong-crypto is disabled", obj="system global strong-crypto",
                           detail="Without strong-crypto the device still negotiates weak ciphers and TLS/SSH algorithms.", recommendation="set strong-crypto enable (test legacy clients first).", reference=FORTI["harden_70"]))
    timeout = _int(g.get("admintimeout"))
    if timeout is not None and timeout > 15:
        out.append(finding("FGT-ADM-008", "medium" if timeout > 60 else "low", "Administration", f"Idle administration session lasts {timeout} minutes", obj="system global admintimeout",
                           detail="A forgotten browser or SSH session stays authenticated for this long. The default is 5 minutes.", recommendation="Use 5-15 minutes (set admintimeout 10).", reference=ref))
    lockout = _int(g.get("admin-lockout-threshold"))
    if lockout is not None and lockout > 5:
        out.append(finding("FGT-ADM-010", "low", "Administration", f"Administrator lockout threshold is {lockout} failed logins", obj="system global admin-lockout-threshold",
                           detail="A high threshold gives a password-guessing attack more attempts. The default is 3.", recommendation="Use 3-5 attempts with a lockout duration of at least 5 minutes.", reference=ref))
    if g.get("private-data-encryption") != "enable":
        out.append(finding("FGT-ADM-011", "low", "Administration", "Configuration backups are not protected with a private data key", obj="system global private-data-encryption",
                           detail="Without private-data-encryption the ENC values in a backup are encrypted with a key shared by all FortiGates of the same release, so a leaked backup exposes its passwords and pre-shared keys.",
                           recommendation="set private-data-encryption enable and store the passphrase in the password vault.", reference=FORTI["harden_70"]))
    cert = g.get("admin-server-cert", "")
    if cert.lower().startswith(("fortinet_factory", "fortinet_local")):
        out.append(finding("FGT-CRT-001", "medium", "Certificates", "Management GUI uses the factory certificate", obj="system global admin-server-cert",
                           detail=f"'{cert}' is a self-signed certificate that is identical on many devices, so browsers cannot tell this FortiGate from another.",
                           recommendation="Install a certificate from your enterprise or public CA and select it with set admin-server-cert.", reference=FORTI["harden_70"]))

    policy = d["password_policy"]
    if not policy or policy.get("status", "disable") != "enable":
        out.append(finding("FGT-ADM-012", "medium", "Administration", "No administrator password policy is enforced", obj="system password-policy",
                           detail="Without a password policy, local administrators may set short or simple passwords.",
                           recommendation="config system password-policy / set status enable / set minimum-length 12 / set min-upper-case-letter 1 / set min-number 1 / set expire-status enable.", reference=FORTI["password_policy"]))
    else:
        length = _int(policy.get("minimum-length"))
        if length is not None and length < 12:
            out.append(finding("FGT-ADM-012", "low", "Administration", f"Administrator password minimum length is {length}", obj="system password-policy minimum-length",
                               detail="Common baselines ask for at least 12 characters for administrative accounts.", recommendation="set minimum-length 12 or longer.", reference=FORTI["password_policy"]))

    auto = d["autoinstall"]
    if auto.get("auto-install-config") == "enable" or auto.get("auto-install-image") == "enable":
        out.append(finding("FGT-ADM-013", "low", "Administration", "USB auto-install of configuration or firmware is enabled", obj="system auto-install",
                           detail="A person with physical access can load a configuration or image from a USB stick at boot.", recommendation="set auto-install-config disable and set auto-install-image disable.", reference=FORTI["harden_overview"]))
    return out


# ----------------------------------------------------------------- interfaces
def interface_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    has_local_in = any(p["status"] == "enable" for p in ctx.data["local_in"])
    for item in ctx.data["interfaces"]:
        access = {a.lower() for a in item["allowaccess"]}
        wan = ctx.res.is_wan(item["name"])
        label = _intf_label(item)
        note = " Local-in policies exist, so confirm they actually restrict this." if has_local_in else " No local-in policy was found that could limit it."
        if "telnet" in access:
            out.append(finding("FGT-IFC-001", "high", "Interfaces", "Telnet management is allowed on an interface", obj=f"interface {item['name']}",
                               detail=f"{label} accepts Telnet, which sends credentials in clear text.", recommendation="Remove telnet: set allowaccess ping https ssh.", reference=FORTI["harden_70"]))
        if "http" in access:
            out.append(finding("FGT-IFC-002", "high" if wan else "medium", "Interfaces", "Clear-text HTTP management is allowed on an interface", obj=f"interface {item['name']}",
                               detail=f"{label} accepts the GUI over HTTP" + (" and faces the internet." if wan else "."), recommendation="Remove http from allowaccess and keep https only.", reference=FORTI["harden_70"]))
        if wan:
            exposed = sorted(access & {"https", "ssh", "snmp", "fgfm"})
            for proto in exposed:
                if proto in ("https", "ssh"):
                    out.append(finding("FGT-IFC-003", "high", "Interfaces", f"{proto.upper()} management is reachable from the internet-facing interface", obj=f"interface {item['name']}",
                                       detail=f"{label} is internet-facing (public address or WAN role) and allows {proto.upper()} administration. Trusted hosts reduce the risk but the login page and SSH daemon stay exposed to scanning." + note,
                                       recommendation="Remove it from the WAN allowaccess and manage from an inside or out-of-band interface, or restrict it with a local-in policy to specific source addresses.", reference=FORTI["best_policies"]))
                elif proto == "snmp":
                    out.append(finding("FGT-IFC-004", "high", "Interfaces", "SNMP is reachable from the internet-facing interface", obj=f"interface {item['name']}",
                                       detail=f"{label} answers SNMP from the internet." + note, recommendation="Remove snmp from the WAN allowaccess.", reference=FORTI["snmp"]))
                elif proto == "fgfm":
                    out.append(finding("FGT-IFC-005", "low", "Interfaces", "FortiManager management tunnel (FGFM) is allowed on the internet-facing interface", obj=f"interface {item['name']}",
                                       detail=f"{label} allows fgfm. This is normal for a FortiGate managed over the internet but should be limited to the FortiManager address." + note,
                                       recommendation="Restrict TCP 541 with a local-in policy to the FortiManager IP.", reference=FORTI["local_in"]))
    return _cap(out, "FGT-IFC-001", "Interfaces", "interface findings")


# ------------------------------------------------------------------- policies
def _is_inbound(ctx: FCtx, policy: dict[str, Any]) -> bool:
    return any(ctx.res.is_wan(name) for name in policy["srcintf"])


def _is_outbound(ctx: FCtx, policy: dict[str, Any]) -> bool:
    return any(ctx.res.is_wan(name) for name in policy["dstintf"]) and not _is_inbound(ctx, policy)


def _policy_obj(policy: dict[str, Any]) -> str:
    return f"policy {policy['id']}" + (f" '{policy['name']}'" if policy["name"] else "")


def policy_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    ngfw = {v["name"]: v["ngfw"] for v in d["vdoms"]}
    for policy in d["policies"]:
        if policy["status"] != "enable" or policy["action"] != "accept":
            continue
        vdom = policy["vdom"]
        src_all = res.expand_addr(vdom, policy["srcaddr"]).wildcard and not policy["srcaddr_negate"]
        dst_all = res.expand_addr(vdom, policy["dstaddr"]).wildcard and not policy["dstaddr_negate"]
        svc_all = res.any_service(vdom, policy["service"]) and not policy["service_negate"]
        identity = bool(policy["users"] or policy["groups"])
        inbound, outbound = _is_inbound(ctx, policy), _is_outbound(ctx, policy)
        obj = _policy_obj(policy)

        if src_all and dst_all and svc_all and not identity:
            out.append(finding("FGT-POL-001", "high", "Policy", "Accept policy allows any source to any destination on any service", obj=obj,
                               detail=f"{obj} ({','.join(policy['srcintf'])} → {','.join(policy['dstintf'])}) matches all addresses and all services, so it permits everything that reaches it. Rules below it never match for these interfaces.",
                               recommendation="Replace it with rules that name the source and destination networks and the services needed, and put a final explicit deny with logging at the end.", reference=FORTI["best_policies"]))
        elif inbound and svc_all and not identity:
            out.append(finding("FGT-POL-002", "high", "Policy", "Internet-facing policy allows every service", obj=obj,
                               detail=f"{obj} accepts traffic arriving on an internet-facing interface ({','.join(policy['srcintf'])}) with service ALL toward {','.join(policy['dstaddr'])}. Any open port on the destination is reachable.",
                               recommendation="Limit the service list to the ports that must be published.", reference=FORTI["best_policies"]))
        elif inbound:
            risky = res.risky_services(vdom, policy["service"])
            if risky and res.expand_addr(vdom, policy["srcaddr"]).wildcard and not identity:
                out.append(finding("FGT-POL-003", "high", "Policy", "Internet-facing policy publishes a management or legacy protocol to any source", obj=obj,
                                   detail=f"{obj} lets any internet source reach {', '.join(risky)} on {','.join(policy['dstaddr'])}.",
                                   recommendation="Do not publish these protocols directly. Use a VPN, or limit the source addresses to named partner ranges.", reference=FORTI["best_policies"]))

        if policy["logtraffic"] == "disable":
            out.append(finding("FGT-POL-004", "medium", "Policy", "Accept policy does not log traffic", obj=obj,
                               detail=f"{obj} has logtraffic disable, so allowed sessions leave no trace for investigations or compliance.",
                               recommendation="set logtraffic all (or utm where only security events are needed) and send logs off the device.", reference=FORTI["log_settings"]))
        if ngfw.get(vdom, "profile-based") != "policy-based" and not policy["profiles"] and not policy["learning"] and (inbound or outbound):
            out.append(finding("FGT-POL-005", "medium" if inbound else "low", "Policy", "Internet-facing accept policy has no security profile", obj=obj,
                               detail=f"{obj} ({','.join(policy['srcintf'])} → {','.join(policy['dstintf'])}) applies no antivirus, IPS, web filter, DNS filter or application control profile, so traffic is only filtered by address and port.",
                               recommendation="Attach at least an IPS sensor and antivirus, and a web filter / DNS filter for outbound browsing, with an SSL inspection profile where the licence allows.", reference=FORTI["best_policies"]))
        if policy["learning"]:
            out.append(finding("FGT-POL-006", "medium", "Policy", "Policy is in learning mode", obj=obj,
                               detail="Learning mode accepts and records traffic to build a baseline; it is meant to be temporary.", recommendation="Review the learned traffic and switch the policy to enforcing mode.", reference=FORTI["policies"]))
    out.extend(_shadowed(ctx))
    out.extend(_disabled_policies(ctx))
    out.extend(_unreferenced(ctx))
    if d["interfaces"] and any(ctx.res.is_wan(i["name"]) for i in d["interfaces"]) and not d["dos"]:
        out.append(finding("FGT-POL-010", "low", "Policy", "No DoS policy is configured", obj="firewall DoS-policy",
                           detail="No firewall DoS-policy exists, so anomaly checks (SYN flood, port scan, UDP flood) are not applied to traffic entering the internet-facing interfaces.",
                           recommendation="Create a DoS policy on each WAN interface with the anomaly thresholds from the Fortinet best-practice guide.", reference=FORTI["dos_policy"]))
    return _cap(out, "FGT-POL-004", "Policy", "policy findings")


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _disabled_policies(ctx: FCtx) -> list[dict[str, Any]]:
    disabled = [p for p in ctx.data["policies"] if p["status"] == "disable"]
    if not disabled:
        return []
    names = ", ".join(f"{p['id']}" + (f" ({p['name']})" if p["name"] else "") for p in disabled[:30])
    return [finding("FGT-POL-007", "info", "Policy", f"{len(disabled)} disabled policy(ies)", obj=names,
                    detail="Disabled rules add review effort and are easy to re-enable by mistake. Rules that are no longer needed can be removed after a retention period.",
                    recommendation="Confirm each with its owner, then delete the ones that are obsolete.", reference=FORTI["best_policies"])]


def _shadowed(ctx: FCtx) -> list[dict[str, Any]]:
    """Policies that can never match because an earlier policy already covers everything they match."""
    out: list[dict[str, Any]] = []
    res = ctx.res
    by_vdom: dict[str, list[dict[str, Any]]] = {}
    for policy in ctx.data["policies"]:
        by_vdom.setdefault(policy["vdom"], []).append(policy)
    for vdom, policies in by_vdom.items():
        if len(policies) > 3000:
            continue
        live = [p for p in policies if p["status"] == "enable"]
        cache: dict[str, tuple[Any, ...]] = {}

        def facts(p: dict[str, Any]) -> tuple[Any, ...]:
            if p["id"] not in cache:
                cache[p["id"]] = (res.expand_intf(vdom, p["srcintf"]), res.expand_intf(vdom, p["dstintf"]), res.expand_addr(vdom, p["srcaddr"]), res.expand_addr(vdom, p["dstaddr"]))
            return cache[p["id"]]

        for index, later in enumerate(live):
            if later["srcaddr_negate"] or later["dstaddr_negate"] or later["service_negate"] or later["internet_service"] or later["vpntunnel"]:
                continue
            l_si, l_di, l_sa, l_da = facts(later)
            for earlier in live[:index]:
                if (earlier["srcaddr_negate"] or earlier["dstaddr_negate"] or earlier["service_negate"] or earlier["internet_service"] or earlier["users"] or earlier["groups"]
                        or earlier["fsso"] or earlier["schedule"] != "always" or earlier["vpntunnel"]):
                    continue
                e_si, e_di, e_sa, e_da = facts(earlier)
                if not (e_si.covers(l_si) and e_di.covers(l_di)):
                    continue
                if not res.service_covers(vdom, earlier["service"], later["service"]):
                    continue
                if not (e_sa.covers(l_sa) and e_da.covers(l_da)):
                    continue
                same = earlier["action"] == later["action"]
                out.append(finding(
                    "FGT-POL-008", "low" if same else "medium", "Policy", "Policy is shadowed by an earlier policy" if not same else "Policy is redundant: an earlier policy already does the same",
                    obj=_policy_obj(later),
                    detail=f"{_policy_obj(later)} can never be hit: policy {earlier['id']}" + (f" '{earlier['name']}'" if earlier["name"] else "")
                           + f" above it matches the same traffic first ({earlier['action']})." + ("" if same else f" This policy wants to {later['action']} that traffic, so its intent is not enforced."),
                    recommendation="Reorder the policies, narrow the earlier one, or delete the unreachable one. Confirm with 'diagnose firewall iprope lookup' or the GUI policy lookup before changing production.",
                    reference=FORTI["best_policies"]))
                break
    return out


def referenced_names(tree: FortiTree) -> set[str]:
    names: set[str] = set()
    for node in tree.root.walk():
        for key, values in node.settings.items():
            if key in ("name", "comment", "comments", "alias", "description", "uuid"):
                continue
            names.update(values)
    return names


def _unreferenced(ctx: FCtx) -> list[dict[str, Any]]:
    used = referenced_names(ctx.tree)
    d = ctx.data
    kinds = (
        ("address", d["addresses"], "addresses"), ("address group", d["addrgrps"], "address groups"), ("custom service", d["services"], "custom services"),
        ("service group", d["svcgroups"], "service groups"), ("virtual IP", d["vips"], "virtual IPs"), ("IP pool", d["ippools"], "IP pools"),
    )
    out: list[dict[str, Any]] = []
    for label, items, plural in kinds:
        unused = [i["name"] for i in items if i["name"] not in used and not BUILTIN_OBJECT.match(i["name"])]
        if unused:
            out.append(finding("FGT-OBJ-001", "info", "Objects", f"{len(unused)} unreferenced {plural if len(unused) != 1 else label}", obj=", ".join(unused[:30]) + (" …" if len(unused) > 30 else ""),
                               detail=f"These {plural} are defined but nothing refers to them (no policy, group, VIP or setting). Orphans make audits harder and are often left over from retired services.",
                               recommendation="Confirm they are not needed (a policy in another VDOM or a FortiManager template may use them), then delete.", reference=FORTI["policy_objects"]))
    return out


# ----------------------------------------------------------------------- NAT
def nat_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    policies = [p for p in d["policies"] if p["status"] == "enable" and p["action"] == "accept"]
    groups = {(g["vdom"], g["name"]): g["members"] for g in d["vipgrps"]}
    for vip in d["vips"]:
        names = {vip["name"]} | {name for (vd, name), members in groups.items() if vd == vip["vdom"] and vip["name"] in members}
        users = [p for p in policies if p["vdom"] == vip["vdom"] and names & set(p["dstaddr"])]
        exposed = [p for p in users if _is_inbound(ctx, p) or vip["extintf"] == "any" or res.is_wan(vip["extintf"])]
        obj = f"vip {vip['name']}"
        if not vip["portforward"] and vip["type"] == "static-nat":
            full = [p for p in exposed if res.any_service(p["vdom"], p["service"])]
            if full:
                out.append(finding("FGT-NAT-001", "high", "NAT", "Virtual IP maps every port and a policy allows every service", obj=obj,
                                   detail=f"{vip['extip']} → {vip['mappedip']} is a one-to-one NAT without port forwarding, and policy {', '.join(p['id'] for p in full)} allows service ALL to it. All ports of the internal host are reachable from the internet.",
                                   recommendation="Enable portforward on the VIP and publish only the required ports, or reduce the policy to the exact services.", reference=FORTI["dnat"]))
            else:
                out.append(finding("FGT-NAT-002", "low", "NAT", "Virtual IP maps every port of the internal host", obj=obj,
                                   detail=f"{vip['extip']} → {vip['mappedip']} is a one-to-one NAT. Only the policy service list limits exposure.", recommendation="Prefer port-forwarding VIPs so that a later policy change cannot expose more than intended.", reference=FORTI["dnat"]))
        if vip["portforward"] and not vip["src_filter"]:
            for port in _ports(vip["mappedport"]) | _ports(vip["extport"]):
                label = RISKY_PORTS.get(str(port))
                if label:
                    high = port not in (22, 389)
                    out.append(finding("FGT-NAT-003", "high" if high else "medium", "NAT", f"Virtual IP publishes {label} without a source filter", obj=obj,
                                       detail=f"{vip['extip']}:{vip['extport']} → {vip['mappedip']}:{vip['mappedport']} exposes {label} to every address that can reach {vip['extintf']}.",
                                       recommendation="Remove the VIP and reach the service through VPN, or set src-filter to the partner addresses.", reference=FORTI["dnat"]))
                    break
        if vip["extintf"] == "any" and exposed:
            out.append(finding("FGT-NAT-004", "low", "NAT", "Virtual IP is bound to all interfaces", obj=obj, detail=f"extintf is 'any', so {vip['extip']} is translated on every interface, not only the internet-facing one.",
                               recommendation="Set extintf to the specific WAN interface.", reference=FORTI["dnat"]))
    return out


def _ports(value: str) -> set[int]:
    if not value:
        return set()
    found = set()
    for part in re.findall(r"\d+(?:-\d+)?", value):
        low, _, high = part.partition("-")
        low_i, high_i = int(low), int(high or low)
        if high_i - low_i <= 10:
            found.update(range(low_i, high_i + 1))
    return found


# ------------------------------------------------------------------------ VPN
def _split_proposal(proposal: str) -> tuple[str, str]:
    enc, _, auth = proposal.lower().partition("-")
    return enc, auth


def vpn_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    d = ctx.data
    out: list[dict[str, Any]] = []
    ref = FORTI["vpn"]
    p2_by_p1: dict[str, list[dict[str, Any]]] = {}
    for p2 in d["ipsec_p2"]:
        p2_by_p1.setdefault(p2["phase1"], []).append(p2)
    for p1 in d["ipsec_p1"]:
        obj = f"ipsec {p1['name']}"
        if p1["ike"] == "1" and p1["mode"] == "aggressive" and p1["auth"] == "psk":
            out.append(finding("FGT-VPN-001", "high", "VPN", "IKEv1 aggressive mode with a pre-shared key", obj=obj,
                               detail="Aggressive mode sends the identity and a hash of the pre-shared key in the clear during the first exchange, so a captured handshake can be attacked offline.",
                               recommendation="Move the tunnel to IKEv2 (set ike-version 2) or at least main mode with certificates; if it is for dial-up clients use IKEv2 with certificates or EAP.", reference=ref))
        elif p1["ike"] == "1":
            out.append(finding("FGT-VPN-007", "low", "VPN", "Tunnel uses IKEv1", obj=obj, detail="IKEv1 lacks the DoS protection, MOBIKE and modern authentication of IKEv2.", recommendation="Use set ike-version 2 when the peer supports it.", reference=ref))
        for proposal in p1["proposal"]:
            enc, auth = _split_proposal(proposal)
            findings_for = _weak_algorithm(enc, auth)
            if findings_for:
                severity, why = findings_for
                out.append(finding("FGT-VPN-002", severity, "VPN", f"Phase 1 proposal {proposal} uses a weak algorithm", obj=obj, detail=f"{why} (phase 1 'proposal {' '.join(p1['proposal'])}').",
                                   recommendation="Use aes256-sha256 / aes256gcm-prfsha384 style proposals.", reference=ref))
        out.extend(_dh_findings(p1["dhgrp"], obj, "Phase 1", ref))
        if p1["dpd"] == "disable":
            out.append(finding("FGT-VPN-005", "medium", "VPN", "Dead peer detection is disabled", obj=obj, detail="Without DPD the tunnel keeps the dead SA until its lifetime expires and traffic is black-holed after a peer or path failure.",
                               recommendation="set dpd on-idle (or on-demand) with dpd-retrycount 3 and dpd-retryinterval 10.", reference=ref))
        if p1["auth"] == "psk" and p1["type"] == "dynamic":
            out.append(finding("FGT-VPN-008", "medium", "VPN", "Dynamic (dial-up) tunnel authenticates with a shared key", obj=obj,
                               detail="One pre-shared key is shared by every remote peer, so one compromised site or client can impersonate all of them.", recommendation="Use certificate authentication (authmethod signature) or per-user EAP/XAuth.", reference=ref))
        if not p2_by_p1.get(p1["name"]):
            out.append(finding("FGT-VPN-009", "low", "VPN", "Phase 1 has no phase 2 selector", obj=obj, detail="No phase2-interface entry refers to this tunnel, so it will not carry traffic.", recommendation="Add the phase 2 or remove the unused phase 1.", reference=ref))
    for p2 in d["ipsec_p2"]:
        obj = f"ipsec phase2 {p2['name']}"
        if p2["pfs"] == "disable":
            out.append(finding("FGT-VPN-004", "medium", "VPN", "Perfect forward secrecy is disabled on phase 2", obj=obj, detail=f"Tunnel {p2['phase1']} derives all child keys from the phase 1 key, so a compromise of that key exposes recorded traffic.",
                               recommendation="set pfs enable with a DH group of 14 or higher (set dhgrp 14 or 20 or 21).", reference=ref))
        for proposal in p2["proposal"]:
            enc, auth = _split_proposal(proposal)
            weak = _weak_algorithm(enc, auth)
            if weak:
                out.append(finding("FGT-VPN-003", weak[0], "VPN", f"Phase 2 proposal {proposal} uses a weak algorithm", obj=obj, detail=f"{weak[1]} (phase 2 'proposal {' '.join(p2['proposal'])}').",
                                   recommendation="Use aes256-sha256 or aes256gcm.", reference=ref))
        if p2["pfs"] != "disable":
            out.extend(_dh_findings(p2["dhgrp"], obj, "Phase 2", ref))
    return _cap(out, "FGT-VPN-002", "VPN", "VPN findings")


def _weak_algorithm(enc: str, auth: str) -> tuple[str, str] | None:
    if enc == "des":
        return "high", "DES has a 56-bit key and can be brute-forced"
    if enc == "null":
        return "high", "NULL encryption provides no confidentiality"
    if enc == "3des":
        return "medium", "3DES has a 64-bit block size (Sweet32) and is deprecated"
    if auth in ("md5", "prfmd5"):
        return "medium", "MD5 is no longer collision resistant"
    if auth in ("sha1", "prfsha1") and enc not in ("aes128gcm", "aes256gcm"):
        return "low", "SHA-1 is deprecated for new designs"
    return None


def _dh_findings(groups: list[str], obj: str, stage: str, ref: str) -> list[dict[str, Any]]:
    out = []
    weak = [g for g in groups if g in WEAK_DH_HIGH]
    mid = [g for g in groups if g in WEAK_DH_MEDIUM]
    if weak:
        out.append(finding("FGT-VPN-006", "high", "VPN", f"{stage} allows Diffie-Hellman group {'/'.join(weak)}", obj=obj,
                           detail="Groups 1 and 2 are 768/1024-bit MODP groups that are within reach of precomputation attacks.", recommendation="Use group 14 (2048-bit) or an elliptic-curve group such as 19, 20 or 21.", reference=ref))
    elif mid:
        out.append(finding("FGT-VPN-006", "medium", "VPN", f"{stage} allows Diffie-Hellman group {'/'.join(mid)}", obj=obj,
                           detail="Group 5 is a 1536-bit MODP group, below the 2048-bit minimum most standards now require.", recommendation="Use group 14 or higher, or an elliptic-curve group.", reference=ref))
    return out


def sslvpn_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    ssl = ctx.data["sslvpn"]
    if not ssl or not ssl["enabled"]:
        return []
    s = ssl["settings"]
    out: list[dict[str, Any]] = []
    ref = FORTI["ssl_vpn"]
    minimum = s.get("ssl-min-proto-ver", "")
    if minimum in ("tls1-0", "tls1-1", "sslv3"):
        out.append(finding("FGT-SSL-001", "medium", "SSL VPN", f"SSL VPN accepts {minimum.replace('tls1-', 'TLS 1.')}", obj="vpn ssl settings ssl-min-proto-ver",
                           detail="Legacy TLS versions are deprecated by RFC 8996 and are vulnerable to downgrade attacks.", recommendation="set ssl-min-proto-ver tls1-2 (or tls1-3 when all clients support it).", reference=ref))
    if s.get("algorithm") == "low":
        out.append(finding("FGT-SSL-002", "medium", "SSL VPN", "SSL VPN allows low-strength ciphers", obj="vpn ssl settings algorithm", detail="algorithm low permits ciphers of 64/128-bit strength.", recommendation="set algorithm high.", reference=ref))
    if s.get("servercert", "").lower().startswith("fortinet_factory"):
        out.append(finding("FGT-SSL-003", "medium", "SSL VPN", "SSL VPN presents the factory certificate", obj="vpn ssl settings servercert",
                           detail="Users are trained to click through certificate warnings, and the certificate is not unique to this device.", recommendation="Install a CA-signed certificate and select it with set servercert.", reference=ref))
    sources = s.get("source-address", "")
    if s.get("source-interface") and (not sources or sources.lower() == "all") and not s.get("source-address6"):
        out.append(finding("FGT-SSL-004", "low", "SSL VPN", "SSL VPN login page is reachable from any source address", obj="vpn ssl settings source-address",
                           detail="Brute-force and exploit scans reach the portal from the whole internet.", recommendation="Restrict source-address to expected countries (geography address objects) or partner ranges.", reference=ref))
    if not ssl["rules"] and not s.get("authentication-rule"):
        out.append(finding("FGT-SSL-005", "low", "SSL VPN", "SSL VPN has no authentication rule", obj="vpn ssl settings authentication-rule", detail="Without an authentication rule users are mapped through firewall policies only.", recommendation="Add an authentication-rule per user group and portal.", reference=ref))
    return out


# -------------------------------------------------------------------- HA / ops
def ha_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    ha = ctx.data["ha"]
    if not ha or ha["mode"] == "standalone":
        return []
    out: list[dict[str, Any]] = []
    ref = FORTI["ha"]
    if len(ha["heartbeat"]) < 2:
        out.append(finding("FGT-HA-001", "medium", "High availability", "Only one heartbeat interface is configured", obj="system ha hbdev",
                           detail="If the single heartbeat link fails both units believe the peer is down and may both become primary (split brain).", recommendation="Configure at least two heartbeat interfaces on separate links (set hbdev ha1 100 ha2 50).", reference=ref))
    if not ha["monitor"]:
        out.append(finding("FGT-HA-002", "medium", "High availability", "No monitored interfaces are configured", obj="system ha monitor",
                           detail="A failed uplink or LAN port does not trigger a failover because no interface is monitored.", recommendation="set monitor to the WAN and LAN interfaces that must be up on the primary.", reference=ref))
    if not ha["password"]:
        out.append(finding("FGT-HA-003", "medium", "High availability", "HA cluster has no password", obj="system ha password", detail="Another FortiGate with the same group name and ID on the heartbeat network could join the cluster.", recommendation="set password <strong secret>.", reference=ref))
    if ha["session_pickup"] != "enable":
        out.append(finding("FGT-HA-004", "low", "High availability", "Session pickup is disabled", obj="system ha session-pickup", detail="Established sessions are dropped at failover and users must reconnect.", recommendation="set session-pickup enable where the traffic profile allows.", reference=ref))
    if ha["encryption"] != "enable" or ha["authentication"] != "enable":
        out.append(finding("FGT-HA-005", "low", "High availability", "HA heartbeat traffic is not encrypted/authenticated", obj="system ha encryption",
                           detail="Heartbeat and sync packets are sent in clear text. This matters when the heartbeat link crosses a switch that others can reach.", recommendation="Use a dedicated back-to-back cable, or set encryption enable and authentication enable.", reference=ref))
    return out


def logging_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    log = ctx.data["logging"]
    out: list[dict[str, Any]] = []
    remote = [s for s in log["syslog"] if s["status"] == "enable" and s["server"]] + [f for f in log["fortianalyzer"] if f["status"] == "enable" and f["server"]]
    cloud = log["fortiguard"].get("status") == "enable"
    ref = FORTI["log_settings"]
    if not remote and not cloud:
        local = "memory only" if log["memory"].get("status", "enable") == "enable" and log["disk"].get("status") != "enable" else "the local disk"
        out.append(finding("FGT-LOG-001", "medium", "Logging", "No remote log destination is enabled", obj="log syslogd / fortianalyzer / fortiguard",
                           detail=f"Logs stay on the device ({local}). They are lost on reboot or hardware failure and can be altered by an attacker with admin access.",
                           recommendation="Send logs to a syslog server or FortiAnalyzer: config log syslogd setting / set status enable / set server <ip> / set mode reliable.", reference=ref))
    for target in log["syslog"]:
        if target["status"] == "enable" and target["server"] and target["mode"] == "udp":
            out.append(finding("FGT-LOG-002", "low", "Logging", "Syslog uses UDP", obj=f"log {target['target']} → {target['server']}", detail="UDP syslog is unreliable and unencrypted, so events can be lost silently or read on the path.",
                               recommendation="set mode reliable (TCP) and enc-algorithm high-medium where the collector supports TLS.", reference=ref))
    if log["eventfilter"].get("event") == "disable":
        out.append(finding("FGT-LOG-003", "medium", "Logging", "System event logging is disabled", obj="log eventfilter event", detail="Administrator logins, configuration changes and system events are not logged.", recommendation="set event enable.", reference=ref))
    ntp = ctx.data["ntp"]
    if ntp and ntp["sync"] == "disable":
        out.append(finding("FGT-LOG-004", "medium", "Logging", "NTP time synchronisation is disabled", obj="system ntp ntpsync", detail="Log timestamps, certificate validation and token-based two-factor depend on correct time.",
                           recommendation="set ntpsync enable and use two internal or public NTP servers.", reference=FORTI["system_time"]))
    elif ntp and ntp["type"] == "custom" and len(ntp["servers"]) == 1:
        out.append(finding("FGT-LOG-005", "low", "Logging", "Only one NTP server is configured", obj="system ntp ntpserver", detail="One source cannot be cross-checked.", recommendation="Add a second server.", reference=FORTI["system_time"]))
    return out


def snmp_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    snmp = ctx.data["snmp"]
    out: list[dict[str, Any]] = []
    ref = FORTI["snmp"]
    for community in snmp["communities"]:
        if community["status"] != "enable":
            continue
        open_hosts = not community["hosts"] or any(h in ("0.0.0.0/0", "0.0.0.0") for h in community["hosts"])
        obj = f"snmp community {community['id']}"
        if community["name_kind"] == GUESSABLE:
            out.append(finding("FGT-SNMP-001", "high" if open_hosts else "medium", "SNMP", "SNMP community name is a well-known default", obj=obj,
                               detail="The community string is one of the names every scanner tries first" + (" and no host restriction is configured." if open_hosts else "."), recommendation="Use SNMPv3 (auth-priv) or a long random community restricted to the monitoring hosts.", reference=ref))
        elif open_hosts:
            out.append(finding("FGT-SNMP-002", "medium", "SNMP", "SNMP community accepts queries from any host", obj=obj, detail="The community has no host entry or allows 0.0.0.0/0.", recommendation="Add the monitoring server addresses under config hosts.", reference=ref))
        if community["query_v1"] == "enable" or community["query_v2c"] == "enable":
            out.append(finding("FGT-SNMP-003", "low", "SNMP", "SNMPv1/v2c queries are enabled", obj=obj, detail="v1/v2c send the community string in clear text.", recommendation="Move monitoring to SNMPv3 with authentication and privacy.", reference=ref))
    for user in snmp["users"]:
        if user["status"] != "enable":
            continue
        obj = f"snmp user {user['name']}"
        if user["level"] == "no-auth-no-priv":
            out.append(finding("FGT-SNMP-004", "high", "SNMP", "SNMPv3 user has no authentication", obj=obj, detail="security-level no-auth-no-priv accepts any request that names the user.", recommendation="set security-level auth-priv.", reference=ref))
        elif user["level"] == "auth-no-priv":
            out.append(finding("FGT-SNMP-004", "medium", "SNMP", "SNMPv3 user has no encryption", obj=obj, detail="security-level auth-no-priv sends data unencrypted.", recommendation="set security-level auth-priv with AES.", reference=ref))
        weak = [name for name, value in (("auth md5", user["auth"] == "md5"), ("priv des", user["priv"] == "des")) if value and user["level"] != "no-auth-no-priv"]
        if weak:
            out.append(finding("FGT-SNMP-005", "medium", "SNMP", "SNMPv3 user uses weak algorithms", obj=obj, detail="Configured: " + ", ".join(weak) + ".", recommendation="Use auth-proto sha256 (or sha) and priv-proto aes256 (or aes).", reference=ref))
    return out


def auth_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ldap in ctx.data["auth"]["ldap"]:
        if ldap["secure"] == "disable":
            out.append(finding("FGT-AUTH-001", "high" if ldap["type"] != "anonymous" else "medium", "Authentication", "LDAP server is contacted without encryption", obj=f"ldap {ldap['name']} → {ldap['server']}",
                               detail="With secure disable the bind (user name and password) and the user lookups cross the network in clear text on TCP 389.", recommendation="set secure ldaps (port 636) or starttls, and install the CA with set ca-cert.", reference=FORTI["harden_70"]))
        elif ldap["identity_check"] == "disable":
            out.append(finding("FGT-AUTH-002", "low", "Authentication", "LDAP server identity is not verified", obj=f"ldap {ldap['name']}", detail="server-identity-check is disabled, so a rogue server could answer.", recommendation="set server-identity-check enable.", reference=FORTI["harden_70"]))
    return out


def _routing_rules_bgp(ctx: FCtx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ref = FORTI["bgp"]
    for bgp in ctx.data["bgp"]:
        groups = {g["name"]: g for g in bgp["groups"]}
        for n in bgp["neighbors"]:
            group = groups.get(n["group"], {})

            def eff(key: str) -> str:
                return n[key] or group.get(key, "")
            obj = f"bgp neighbor {n['ip']} (AS {n['remote_as'] or group.get('remote_as', '?')})"
            if n["shutdown"]:
                continue
            ebgp = n["ebgp"] if n["remote_as"] else True
            if not (n["password"] or group.get("password")):
                out.append(finding("FGT-BGP-001", "medium" if ebgp else "low", "Routing", "BGP session has no authentication", obj=obj, detail="No MD5 password is configured, so a spoofed TCP reset or injected update can disturb the session.",
                                   recommendation="set password <secret> on both sides (and use ttl-security / GTSM for eBGP).", reference=ref))
            if ebgp and not (eff("route_map_in") or eff("prefix_list_in") or eff("filter_list_in")):
                out.append(finding("FGT-BGP-002", "high", "Routing", "eBGP neighbor has no inbound filter", obj=obj, detail="Everything the peer announces is accepted, including a default route, private ranges or your own prefixes (hijack / leak).",
                                   recommendation="Apply route-map-in or prefix-list-in that accepts only the prefixes expected from this peer.", reference=ref))
            if ebgp and not (eff("route_map_out") or eff("prefix_list_out") or eff("filter_list_out")):
                out.append(finding("FGT-BGP-003", "medium", "Routing", "eBGP neighbor has no outbound filter", obj=obj, detail="Every route in the table (including learned ones) is advertised to the peer, which can turn this site into a transit path.",
                                   recommendation="Apply route-map-out or prefix-list-out that announces only your own prefixes.", reference=ref))
            if ebgp and not eff("max_prefix"):
                out.append(finding("FGT-BGP-004", "low", "Routing", "eBGP neighbor has no maximum-prefix limit", obj=obj, detail="A leak from the peer can fill the routing table.", recommendation="set maximum-prefix <n> with a threshold and restart interval.", reference=ref))
    return out


def routing_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    out = _routing_rules_bgp(ctx)
    for ospf in ctx.data["ospf"]:
        for iface in ospf["interfaces"]:
            if iface["auth"] == "none" and iface["status"] == "enable":
                wan = ctx.res.is_wan(iface["interface"])
                out.append(finding("FGT-OSPF-001", "high" if wan else "medium", "Routing", "OSPF interface has no authentication", obj=f"ospf interface {iface['interface']}",
                                   detail="Any device on this segment can form an adjacency and inject routes." + (" The interface is internet-facing." if wan else ""),
                                   recommendation="set authentication md5 (or message-digest) with a key, or authentication-key on older releases.", reference=FORTI["ospf"]))
    disabled = [r for r in ctx.data["routes"] if r["status"] == "disable"]
    if disabled:
        out.append(finding("FGT-RT-001", "info", "Routing", f"{len(disabled)} disabled static route(s)", obj=", ".join(f"{r['seq']} ({r['dst']})" for r in disabled[:20]),
                           detail="Disabled routes are easy to forget and can change reachability if re-enabled.", recommendation="Delete the ones that are no longer needed.", reference=FORTI["policy_objects"]))
    return out


def sdwan_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    sd = ctx.data["sdwan"]
    if not sd or sd.get("status") == "disable" or not sd["members"]:
        return []
    out: list[dict[str, Any]] = []
    ref = FORTI["sdwan_health"]
    names = {h["name"] for h in sd["health_checks"]}
    if len(sd["members"]) >= 2 and not sd["health_checks"]:
        out.append(finding("FGT-SDW-001", "medium", "SD-WAN", "SD-WAN has several members but no health check", obj="system sdwan health-check",
                           detail="Without a performance SLA the FortiGate cannot detect a degraded or dead link and keeps steering traffic to it.", recommendation="Add a health-check with two probe servers per member.", reference=ref))
    for check in sd["health_checks"]:
        if not check["slas"]:
            out.append(finding("FGT-SDW-002", "low", "SD-WAN", "Health check has no SLA thresholds", obj=f"sdwan health-check {check['name']}",
                               detail="The probe only decides up or down. Latency, jitter and packet loss thresholds are what allow quality-based steering.", recommendation="Add a config sla block with latency-threshold, jitter-threshold and packetloss-threshold.", reference=ref))
    for rule in sd["rules"]:
        missing = [h for h in rule["health_check"] if h not in names]
        if missing:
            out.append(finding("FGT-SDW-003", "medium", "SD-WAN", "SD-WAN rule refers to an undefined health check", obj=f"sdwan service {rule['id']} {rule['name']}".strip(),
                               detail="Referenced but not defined: " + ", ".join(missing), recommendation="Create the health check or correct the name.", reference=ref))
    return out


def system_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    header = ctx.data["header"]
    built = header.get("built", "")
    out: list[dict[str, Any]] = []
    if len(built) == 6 and built.isdigit():
        try:
            built_on = date(2000 + int(built[:2]), int(built[2:4]), int(built[4:6]))
        except ValueError:
            return out
        months = (ctx.today.year - built_on.year) * 12 + ctx.today.month - built_on.month
        label = f"FortiOS {header.get('version', '?')} build {header.get('build', '?')} ({built_on:%b %Y})"
        if months >= 30:
            out.append(finding("FGT-SYS-001", "medium", "System", f"Firmware is {months} months old", obj=label,
                               detail=f"{label} was built {months} months before this analysis. Fortinet publishes security advisories (PSIRT) for FortiOS regularly, and many exploited FortiGate vulnerabilities were in releases of this age.",
                               recommendation="Compare the version with the PSIRT advisories and the Fortinet recommended-release list for this model, then plan an upgrade.", reference=FORTI["harden_70"]))
        elif months >= 18:
            out.append(finding("FGT-SYS-001", "low", "System", f"Firmware is {months} months old", obj=label, detail=f"{label}. Check whether a newer maintenance build of the same branch is available.",
                               recommendation="Review the PSIRT advisories for this branch.", reference=FORTI["harden_70"]))
    return out


def secret_rules(ctx: FCtx) -> Iterable[dict[str, Any]]:
    clear = []
    for node in ctx.tree.root.walk():
        for key, kind in node.secrets.items():
            if kind == "clear":
                parent = node
                while parent is not None and parent.kind != "config":
                    parent = parent.parent
                clear.append(f"{parent.name if parent else '?'} → {node.name or key}: {key}")
    if not clear:
        return []
    return [finding("FGT-SEC-001", "medium", "System", f"{len(clear)} credential(s) are stored in readable form", obj="; ".join(clear[:10]) + (" …" if len(clear) > 10 else ""),
                    detail="The export holds these values without the ENC marker. Anyone who can read the backup can use them. (Their values are not shown in this report.)", recommendation="Rotate them and enable private-data-encryption; check how the configuration was exported.", reference=FORTI["harden_70"])]


RULES: list[Callable[[FCtx], Iterable[dict[str, Any]]]] = [
    admin_rules, interface_rules, policy_rules, nat_rules, vpn_rules, sslvpn_rules, ha_rules, logging_rules, snmp_rules, auth_rules, routing_rules, sdwan_rules, system_rules, secret_rules,
]
