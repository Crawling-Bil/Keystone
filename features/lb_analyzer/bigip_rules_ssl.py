"""Findings for SSL profiles (protocols, ciphers, certificates they use) and for certificate objects."""

from __future__ import annotations

import re
from typing import Any, Iterable

from ..analyzer_core.findings import finding
from .bigip_extract import canon, short
from .bigip_resolve import Resolver
from .refs import F5
from .bigip_context import LCtx, vs_in_use

PROTOCOLS = ("SSLv3", "TLS1.0", "TLS1.1", "TLS1.2", "TLS1.3")
_OPTION_TO_PROTOCOL = {"no-sslv3": "SSLv3", "no-tlsv1": "TLS1.0", "no-tlsv1.1": "TLS1.1", "no-tlsv1.2": "TLS1.2", "no-tlsv1.3": "TLS1.3"}
_CIPHER_EXCLUSION = {"sslv3": "SSLv3", "tlsv1": "TLS1.0", "tlsv1_1": "TLS1.1", "tlsv1_2": "TLS1.2", "tlsv1_3": "TLS1.3"}
_WEAK_HIGH = {"rc4": "RC4", "export": "EXPORT-grade", "exp": "EXPORT-grade", "null": "NULL", "anull": "anonymous (aNULL)", "enull": "NULL encryption", "des": "single DES", "des-cbc-sha": "single DES", "rc2": "RC2", "idea": "IDEA", "seed": "SEED"}
_WEAK_MEDIUM = {"3des": "3DES", "des-cbc3-sha": "3DES", "md5": "MD5 MAC", "low": "LOW strength", "medium": "MEDIUM strength (includes RC4)", "all": "ALL (includes weak suites)"}
MINIMUM_RSA_BITS = 2048


def _options(res: Resolver, name: str) -> tuple[list[str] | None, str]:
    chain, root = res.chain(res.profiles, name)
    for index, profile in enumerate(chain):
        found = [key for key in ("options", "tm-options") if key in profile["lists"]]
        if found:
            return sorted({word.lower() for key in found for word in profile["lists"][key]}), "explicit" if index == 0 else "inherited:" + profile["short"]
    return None, "builtin:" + short(root) if root else ""


def ssl_state(res: Resolver, name: str) -> dict[str, Any]:
    """What the export lets us say about the TLS policy of a client-ssl or server-ssl profile."""
    options, osrc = _options(res, name)
    ciphers, csrc = res.profile_attr(name, "ciphers")
    group, gsrc = res.profile_attr(name, "cipher-group")
    cipher_excluded: set[str] = set()
    tokens: list[str] = []
    if ciphers:
        tokens = [t for t in re.split(r"[:\s,]+", ciphers.strip().strip('"')) if t]
        for token in tokens:
            if token[0] in "!-":
                label = _CIPHER_EXCLUSION.get(token[1:].lower())
                if label:
                    cipher_excluded.add(label)
    option_excluded = {_OPTION_TO_PROTOCOL[o] for o in (options or []) if o in _OPTION_TO_PROTOCOL}
    enabled = [p for p in PROTOCOLS if p not in cipher_excluded and p not in option_excluded]
    return {"options": options, "options_source": osrc, "ciphers": ciphers, "cipher_source": csrc, "cipher_group": group, "tokens": tokens, "known": options is not None, "enabled": enabled,
            "cipher_excluded": sorted(cipher_excluded), "option_excluded": sorted(option_excluded)}


def weak_ciphers(tokens: list[str]) -> tuple[list[str], list[str]]:
    high: set[str] = set()
    medium: set[str] = set()
    for token in tokens:
        if token[0] in "!-":
            continue
        for part in re.split(r"[+@]", token.lstrip("+")):
            key = part.lower()
            if key in _WEAK_HIGH:
                high.add(_WEAK_HIGH[key])
            elif key in _WEAK_MEDIUM:
                medium.add(_WEAK_MEDIUM[key])
    return sorted(high), sorted(medium)


def profile_certs(profile: dict[str, Any]) -> list[dict[str, str]]:
    node = profile["node"]
    out = []
    chain = node.child("cert-key-chain")
    for entry in (chain.children if chain else []):
        out.append({"entry": entry.key, "cert": entry.val("cert"), "key": entry.val("key"), "chain": entry.val("chain", "none")})
    if not out and node.has("cert"):
        out.append({"entry": "", "cert": node.val("cert"), "key": node.val("key"), "chain": node.val("chain", "none")})
    return out


def ssl_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    d, res = ctx.data, ctx.res
    out: list[dict[str, Any]] = []
    for p in d["profiles"]:
        if p["kind"] not in ("client-ssl", "server-ssl"):
            continue
        if not (res.is_used("profile", p["name"]) or not vs_in_use(ctx)):
            continue
        side = "client-ssl" if p["kind"] == "client-ssl" else "server-ssl"
        ref = F5["client_ssl"] if side == "client-ssl" else F5["server_ssl"]
        state = ssl_state(res, p["name"])
        if state["known"]:
            if "SSLv3" in state["enabled"]:
                out.append(finding("LB-SSL-001", "high", "SSL/TLS", "SSLv3 is enabled", obj=f"{side} {p['short']}",
                                   detail=f"{p['short']} lists options {state['options'] or 'none'} and its cipher string does not exclude SSLv3, so the obsolete SSLv3 protocol is negotiable.",
                                   recommendation="Add no-sslv3 (and no-tlsv1, no-tlsv1.1) to the profile options: 'modify ltm profile " + side + " " + p["short"] + " options { dont-insert-empty-fragments no-sslv3 no-tlsv1 no-tlsv1.1 }'.", reference=ref))
            old = [x for x in ("TLS1.0", "TLS1.1") if x in state["enabled"]]
            if old:
                out.append(finding("LB-SSL-002", "medium", "SSL/TLS", f"{' and '.join(old)} {'is' if len(old) == 1 else 'are'} enabled", obj=f"{side} {p['short']}",
                                   detail=f"{p['short']} still allows {', '.join(old)}. NIST SP 800-52 Rev. 2 makes TLS 1.2 the baseline for servers (and asks for TLS 1.3 support), so the older versions only serve legacy clients and should be retired.",
                                   recommendation="Disable the old versions with no-tlsv1 and no-tlsv1.1 after confirming no client depends on them (check the client-ssl handshake statistics first).", reference=F5["nist_800_52"]))
        else:
            out.append(finding("LB-SSL-004", "info", "SSL/TLS", "Enabled TLS versions are not stated in the export", obj=f"{side} {p['short']}",
                               detail=f"{p['short']} does not list options or tm-options, so it inherits them from {state['options_source'].replace('builtin:', 'built-in ').replace('inherited:', '')}. A TMSH listing omits default values, so the analyzer cannot confirm that TLS 1.0 and 1.1 are disabled.",
                               recommendation="Capture 'tmsh list ltm profile " + side + " " + p["short"] + " all-properties' (or the 'show running-config all-properties' variant) so the effective options are visible.", reference=ref))
        high, medium = weak_ciphers(state["tokens"])
        if high:
            out.append(finding("LB-SSL-003", "high", "SSL/TLS", "Weak cipher suites are allowed", obj=f"{side} {p['short']}",
                               detail=f"The cipher string of {p['short']} ({state['ciphers']}) includes {', '.join(high)}.", recommendation="Replace it with a modern string such as one that lists ECDHE and AES-GCM suites first and excludes RC4, DES, EXPORT and NULL, or use a cipher group.", reference=F5["deploying_tls"]))
        elif medium:
            out.append(finding("LB-SSL-003", "medium", "SSL/TLS", "Legacy cipher suites are allowed", obj=f"{side} {p['short']}",
                               detail=f"The cipher string of {p['short']} ({state['ciphers']}) includes {', '.join(medium)}.", recommendation="Prefer ECDHE with AES-GCM and drop 3DES, MD5 and the broad ALL/MEDIUM/LOW keywords.", reference=F5["deploying_tls"]))
        if side == "client-ssl":
            certs = profile_certs(p)
            if not certs:
                chain, root = res.chain(res.profiles, p["name"])
                inherited = [c for parent in chain[1:] for c in profile_certs(parent)]
                if not inherited:
                    out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Client-SSL profile has no certificate of its own", obj=p["short"],
                                       detail=f"{p['short']} lists no cert-key-chain and none of its parent profiles ({short(root) or 'built-in'}) does either, so it presents the certificate of the built-in profile - on a stock BIG-IP the self-signed default.crt. Confirm with 'tmsh list ltm profile client-ssl {p['short']} all-properties'.",
                                       recommendation="Import a certificate issued by your CA and reference it in cert-key-chain.", reference=F5["client_ssl"]))
            for c in certs:
                if c["cert"].endswith("default.crt"):
                    out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Client-SSL profile presents the self-signed default certificate", obj=p["short"],
                                       detail=f"{p['short']} uses {short(canon(c['cert']))}, the self-signed certificate that ships with the BIG-IP; clients cannot validate it and it is shared by every unit.",
                                       recommendation="Import a certificate issued by your CA (with its chain) and reference it in cert-key-chain.", reference=F5["client_ssl"]))
                elif c["chain"] in ("none", "") and c["cert"]:
                    out.append(finding("LB-SSL-010", "low", "SSL/TLS", "Certificate has no intermediate chain configured", obj=p["short"],
                                       detail=f"{p['short']} presents {short(canon(c['cert']))} with chain none; clients that do not already hold the intermediate CA cannot build the path.", recommendation="Add the issuing CA bundle as the chain in cert-key-chain.", reference=F5["client_ssl"]))
            sec_value, _ = res.profile_attr(p["name"], "secure-renegotiation")
            if sec_value and sec_value.lower() == "request":
                out.append(finding("LB-SSL-006", "medium", "SSL/TLS", "Secure renegotiation is only requested", obj=p["short"], detail=f"{p['short']} sets secure-renegotiation request; unpatched clients are accepted (documented default: require).",
                                   recommendation="Set secure-renegotiation require.", reference=F5["client_ssl"]))
        else:
            peer, src = res.profile_attr(p["name"], "peer-cert-mode")
            if (peer or "ignore").lower() == "ignore":
                out.append(finding("LB-SSL-007", "low", "SSL/TLS", "Back-end server certificates are not validated", obj=p["short"],
                                   detail=f"{p['short']} has peer-cert-mode ignore ({'explicit' if src == 'explicit' else 'documented default'}), so the BIG-IP re-encrypts to any server without checking its certificate.",
                                   recommendation="Set peer-cert-mode require with a ca-file (and server-name for SNI) when the back-end segment is not fully trusted.", reference=F5["server_ssl"]))
    for v in d["virtuals"]:
        for prof in v["profiles"]:
            base = prof["name"].rsplit("/", 1)[-1]
            if prof["name"] not in res.profiles and base in ("clientssl", "clientssl-secure", "clientssl-insecure-compatible") and v["enabled"]:
                out.append(finding("LB-SSL-005", "medium", "SSL/TLS", "Virtual server uses a stock client-SSL profile and its default certificate", obj=f"{v['short']} -> {short(prof['name'])}",
                                   detail=f"{v['short']} attaches the built-in {short(prof['name'])} profile directly. A stock BIG-IP gives that profile the self-signed default.crt, and its TLS options and ciphers are the factory defaults, which nobody on your team has reviewed.",
                                   recommendation="Create a custom client-ssl profile (parent clientssl-secure or your own policy) with your certificate chain and attach it to the virtual server.", reference=F5["client_ssl"]))
            if prof["name"].endswith(("clientssl-insecure-compatible", "serverssl-insecure-compatible")):
                out.append(finding("LB-SSL-009", "medium", "SSL/TLS", "Built-in insecure-compatible SSL profile is attached", obj=f"{v['short']} -> {short(prof['name'])}",
                                   detail=f"{v['short']} uses {short(prof['name'])}, the built-in profile that favours compatibility with old clients over strong protocols and ciphers.", recommendation="Create a custom profile from clientssl-secure/serverssl-secure (or your own policy) and attach it instead.", reference=F5["client_ssl"]))
    return out


# ===================================================================== certificates
def certificate_rules(ctx: LCtx) -> Iterable[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for c in ctx.data["certs"]:
        if c["system"]:
            continue
        if c["expires"]:
            days = (c["expires"] - ctx.today).days
            if days < 0:
                out.append(finding("LB-CRT-001", "high", "Certificates", "Certificate has expired", obj=c["short"], detail=f"{c['short']} expired on {c['expires']} ({-days} days ago).", recommendation="Renew it and update the profiles that use it.", reference=F5["ssl_cert"]))
            elif days <= 30:
                out.append(finding("LB-CRT-002", "medium", "Certificates", "Certificate expires within 30 days", obj=c["short"], detail=f"{c['short']} expires on {c['expires']} (in {days} days).", recommendation="Renew it before it lapses.", reference=F5["ssl_cert"]))
            elif days <= 90:
                out.append(finding("LB-CRT-002", "low", "Certificates", "Certificate expires within 90 days", obj=c["short"], detail=f"{c['short']} expires on {c['expires']} (in {days} days).", recommendation="Schedule the renewal.", reference=F5["ssl_cert"]))
        if c["key_size"] and c["key_type"].lower().startswith("rsa") and c["key_size"] < MINIMUM_RSA_BITS:
            out.append(finding("LB-CRT-003", "medium", "Certificates", "Certificate uses an RSA key shorter than 2048 bits", obj=c["short"], detail=f"{c['short']} has a {c['key_size']}-bit RSA key.", recommendation="Re-issue with at least a 2048-bit RSA key or an ECDSA P-256 key.", reference=F5["nist_800_52"]))
        if c["self_signed"] and not c.get("ca"):                 # a self-signed root CA in a trust bundle is normal; a self-signed leaf is not
            out.append(finding("LB-CRT-004", "low", "Certificates", "Certificate is self-signed", obj=c["short"], detail=f"{c['short']} has the same subject and issuer; clients must trust it manually.", recommendation="Use a certificate from your enterprise or a public CA on client-facing profiles.", reference=F5["ssl_cert"]))
        signature = (c.get("signature") or "").lower()
        if signature and any(w in signature for w in ("md5", "sha1")) and not c.get("ca"):
            out.append(finding("LB-CRT-005", "medium", "Certificates", "Certificate is signed with a weak hash (SHA-1 or MD5)", obj=c["short"], detail=f"{c['short']} uses {c['signature']}; browsers and TLS clients reject SHA-1 server certificates.",
                               recommendation="Re-issue it with SHA-256 or stronger.", reference=F5["ssl_cert"]))
        if c["expires"] and (c["expires"] - ctx.today).days <= 90 and not c.get("ca") and "used_by" in c and not c["used_by"]:
            out.append(finding("LB-CRT-006", "info", "Certificates", "Certificate that is expiring or expired is not used by any SSL profile", obj=c["short"],
                               detail=f"{c['short']} (expires {c['expires']}) is not referenced by a client-ssl or server-ssl profile in this configuration.",
                               recommendation="Delete it if it is a leftover, or check whether a virtual server outside this export uses it.", reference=F5["ssl_cert"]))
    return out
