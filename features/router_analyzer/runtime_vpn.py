"""Parsers for crypto / GETVPN and Cisco SD-WAN (cEdge) show output."""

from __future__ import annotations

import re
from typing import Any

from .config_tree import parse_config
from .netutil import is_ipv4


# --------------------------------------------------------------------------
# GETVPN (GDOI)
# --------------------------------------------------------------------------


def parse_gdoi(lines: list[str]) -> dict[str, Any]:
    """``show crypto gdoi`` on a group member."""
    info: dict[str, Any] = {"key_servers": [], "acl": [], "tek_sas": []}
    section = ""
    for line in lines:
        text = line.strip()
        if not text:
            continue
        m = re.match(r"^(Group Name|Group Identity|Rekeys received|IPSec SA Direction|Active Group Server|GM Reregisters in|Rekey Received\(hh:mm:ss\)|Rekey Acks sent|Registration status|Registered with|Re-registers in|Rekey Rcvd\(hh:mm:ss\)|Rekey ACKs sent|Last rekey from|Succeeded registration|Last rekey seq num|Rekey Transport Type|Lifetime \(secs\)|Encrypt Algorithm|Key Size|Sig Hash Algorithm|Sig Key Length \(bits\))\s*:\s*(.*)$", text)
        if m:
            key = m.group(1)
            value = m.group(2).strip()
            if key == "Rekeys received" and "rekeys_received" in info:
                continue
            info[{
                "Group Name": "group", "Group Identity": "identity", "Rekeys received": "rekeys_received", "IPSec SA Direction": "sa_direction",
                "Active Group Server": "active_ks", "GM Reregisters in": "reregister_in", "Rekey Received(hh:mm:ss)": "last_rekey_age", "Rekey Acks sent": "rekey_acks",
                "Registration status": "registration", "Registered with": "registered_with", "Re-registers in": "reregister_in", "Rekey Rcvd(hh:mm:ss)": "last_rekey_age",
                "Rekey ACKs sent": "rekey_acks", "Last rekey from": "last_rekey_from", "Succeeded registration": "registrations_ok", "Last rekey seq num": "rekey_seq",
                "Rekey Transport Type": "rekey_transport", "Lifetime (secs)": "kek_lifetime", "Encrypt Algorithm": "kek_encryption", "Key Size": "kek_key_size",
                "Sig Hash Algorithm": "kek_sig_hash", "Sig Key Length (bits)": "kek_sig_len",
            }[key]] = value
            if key == "Group Name":
                section = "group"
            continue
        if text.startswith("Group Server list"):
            m2 = re.search(r":\s*(\S+)", text)
            if m2:
                info["key_servers"].append(m2.group(1))
            section = "ks"
            continue
        if section == "ks" and is_ipv4(text):
            info["key_servers"].append(text)
            continue
        if text.startswith("ACL Downloaded From KS"):
            section = "acl"
            m3 = re.search(r"KS (\S+?):", text)
            if m3:
                info["acl_source"] = m3.group(1)
            continue
        if text.startswith("KEK POLICY"):
            section = "kek"
            continue
        if text.startswith("TEK POLICY"):
            section = "tek"
            continue
        if section == "acl":
            m4 = re.match(r"^access-list\s+(permit|deny)\s+(.*)$", text)
            if m4:
                info["acl"].append({"action": m4.group(1), "match": m4.group(2)})
                continue
        if section == "tek":
            m5 = re.match(r"^spi:\s*(\S+)", text)
            if m5:
                info["tek_sas"].append({"spi": m5.group(1)})
            m6 = re.match(r"^transform:\s*(.+)$", text)
            if m6 and info["tek_sas"]:
                info["tek_sas"][-1]["transform"] = m6.group(1).strip()
            m7 = re.search(r"remaining key lifetime \(sec\):\s*\((\d+)\)", text)
            if m7 and info["tek_sas"]:
                info["tek_sas"][-1]["remaining"] = int(m7.group(1))
            m8 = re.match(r"^(\S+):$", text)
            if m8:
                info.setdefault("tek_interfaces", []).append(m8.group(1))
    # IOS XE 16.x / 17.x prints "Registration status : Registered" and "Registered with : <ks>" instead of the older "Active Group Server"
    if not info.get("active_ks") and str(info.get("registration", "")).strip().lower() == "registered" and info.get("registered_with"):
        info["active_ks"] = info["registered_with"]
    return info


def parse_gdoi_gm(lines: list[str]) -> dict[str, Any]:
    info: dict[str, Any] = {}
    for line in lines:
        text = line.strip()
        m = re.match(r"^Group Member Information For Group (\S+):", text)
        if m:
            info["group"] = m.group(1)
        m = re.match(r"^(IPSec SA Direction|ACL Received From KS|Last rekey seq num)\s*:\s*(.*)$", text)
        if m:
            info[m.group(1)] = m.group(2).strip()
        m = re.match(r"^Remaining time\s*:\s*(.*)$", text)
        if m:
            info["reregister_remaining"] = m.group(1).strip()
        if text.startswith(":NOT RUNNING") or "NOT RUNNING" in text:
            info["retry_timer"] = "not running"
    return info


# --------------------------------------------------------------------------
# IPsec sessions / SAs
# --------------------------------------------------------------------------


def parse_crypto_session(lines: list[str]) -> list[dict[str, Any]]:
    """``show crypto session [detail]``."""
    sessions: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    flow: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        m = re.match(r"^Interface:\s*(.+)$", text)
        if m:
            cur = {"interfaces": m.group(1).split(), "status": "", "uptime": "", "peer": "", "ike_sas": [], "flows": []}
            sessions.append(cur)
            flow = None
            continue
        if cur is None:
            continue
        m = re.match(r"^Session status:\s*(\S+)", text)
        if m:
            cur["status"] = m.group(1)
            continue
        m = re.match(r"^Uptime:\s*(\S+)", text)
        if m:
            cur["uptime"] = m.group(1)
            continue
        m = re.match(r"^Peer:\s*(\S*)\s+port\s+(\d+)", text)
        if m:
            cur["peer"] = m.group(1)
            cur["peer_port"] = m.group(2)
            continue
        m = re.match(r"^Phase1_id:\s*(\S+)", text)
        if m:
            cur["phase1_id"] = m.group(1)
            continue
        m = re.match(r"^IKE SA:\s*local (\S+)/(\d+) remote (\S+)/(\d+) (\S+)", text)
        if m:
            cur["ike_sas"].append({"local": m.group(1), "remote": m.group(3), "state": m.group(5)})
            continue
        m = re.match(r"^IPSEC FLOW:\s*(permit|deny)\s*(.*)$", text)
        if m:
            flow = {"action": m.group(1), "match": m.group(2).strip(), "active_sas": 0, "decrypted": None, "decrypt_drops": None, "encrypted": None, "encrypt_drops": None}
            cur["flows"].append(flow)
            continue
        if flow is not None:
            m = re.match(r"^Active SAs:\s*(\d+)", text)
            if m:
                flow["active_sas"] = int(m.group(1))
                continue
            m = re.match(r"^Inbound:\s*#pkts dec'ed (-?\d+) drop (\d+)", text)
            if m:
                flow["decrypted"], flow["decrypt_drops"] = int(m.group(1)), int(m.group(2))
                continue
            m = re.match(r"^Outbound:\s*#pkts enc'ed (-?\d+) drop (\d+)", text)
            if m:
                flow["encrypted"], flow["encrypt_drops"] = int(m.group(1)), int(m.group(2))
    return sessions


def parse_ipsec_sa(lines: list[str]) -> list[dict[str, Any]]:
    """``show crypto ipsec sa`` -- one row per protected flow."""
    rows: list[dict[str, Any]] = []
    interface = map_tag = local_addr = ""
    cur: dict[str, Any] | None = None
    for line in lines:
        text = line.strip()
        m = re.match(r"^interface:\s*(\S+)", text)
        if m:
            interface = m.group(1)
            cur = None
            continue
        m = re.match(r"^Crypto map tag:\s*([^,]+), local addr (\S+)", text)
        if m:
            map_tag, local_addr = m.group(1), m.group(2)
            continue
        m = re.match(r"^local\s+ident \(addr/mask/prot/port\):\s*\((.+)\)$", text)
        if m:
            cur = {"interface": interface, "crypto_map": map_tag, "local_addr": local_addr, "local_ident": m.group(1), "remote_ident": "", "peer": "", "encaps": 0, "decaps": 0,
                   "send_errors": 0, "recv_errors": 0, "transform": "", "remaining": None, "status": ""}
            rows.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"^remote\s+ident \(addr/mask/prot/port\):\s*\((.+)\)$", text)
        if m:
            cur["remote_ident"] = m.group(1)
            continue
        m = re.match(r"^current_peer\s*(\S*)\s+port\s+(\d+)", text)
        if m:
            cur["peer"] = m.group(1) or f"(any):{m.group(2)}"
            continue
        m = re.match(r"^#pkts encaps:\s*(-?\d+)", text)
        if m:
            cur["encaps"] = int(m.group(1))
            continue
        m = re.match(r"^#pkts decaps:\s*(-?\d+)", text)
        if m:
            cur["decaps"] = int(m.group(1))
            continue
        m = re.match(r"^#send errors (\d+), #recv errors (\d+)", text)
        if m:
            cur["send_errors"], cur["recv_errors"] = int(m.group(1)), int(m.group(2))
            continue
        m = re.match(r"^transform:\s*(.+?)\s*,?$", text)
        if m and not cur["transform"]:
            cur["transform"] = m.group(1)
            continue
        m = re.search(r"remaining key lifetime \(sec\):\s*\((\d+)\)", text)
        if m and cur["remaining"] is None:
            cur["remaining"] = int(m.group(1))
            continue
        m = re.match(r"^Status:\s*(\S+)", text)
        if m and not cur["status"]:
            cur["status"] = m.group(1)
    return rows


def parse_isakmp_sa(lines: list[str]) -> list[dict[str, str]]:
    """``show crypto isakmp sa`` (IKEv1) and ``show crypto ikev2 sa`` summary rows."""
    rows = []
    for line in lines:
        m = re.match(r"^(\S+)\s+(\S+)\s+(QM_IDLE|MM_NO_STATE|MM_KEY_EXCH|MM_SA_SETUP|AG_INIT_EXCH|\S+_\S+)\s+(\d+)\s+(\S+)\s*$", line)
        if m and is_ipv4(m.group(1)) and is_ipv4(m.group(2)):
            rows.append({"dst": m.group(1), "src": m.group(2), "state": m.group(3), "conn_id": m.group(4), "status": m.group(5)})
    return rows


# --------------------------------------------------------------------------
# Cisco SD-WAN (IOS-XE in controller mode)
# --------------------------------------------------------------------------


def parse_sdwan_system_status(lines: list[str]) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in lines:
        m = re.match(r"^([A-Za-z][A-Za-z0-9 \-/()]{1,40}?):\s{1,}(\S.*)$", line)
        if m and not line.startswith(" "):
            info[m.group(1).strip()] = m.group(2).strip()
    return info


# UPTIME is d:hh:mm:ss (``1y 41:21:54:04`` after a year). The column is 11 characters wide, so a two-digit day count (``21:00:00:17``) fills it and the
# CONTROLLER GROUP ID that follows is printed against it without a space: ``21:00:00:170`` is uptime 21:00:00:17 and group 0.
_UPTIME = re.compile(r"(\d+:\d{2}:\d{2}:\d{2})(\d*)")
_PEER_TYPES = ("vsmart", "vmanage", "vbond", "vedge")


def parse_sdwan_control_connections(lines: list[str]) -> list[dict[str, str]]:
    """``show sdwan control connections``.

    Nine fixed columns come first.  ORGANIZATION may be blank (a vBond that is still
    in ``connect``) and UPTIME is blank while a connection is not up, so the variable
    tail is read from the right: group id (which may be glued to the uptime), optional uptime, state, proxy, color,
    and whatever is left is the organization.
    """
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) < 13 or parts[0] not in _PEER_TYPES or not is_ipv4(parts[2]):
            continue
        tail = parts[9:]
        group = tail.pop() if tail and tail[-1].isdigit() else ""
        uptime = ""
        glued = _UPTIME.fullmatch(tail[-1]) if tail else None
        if glued:
            tail.pop()
            uptime, group = glued.group(1), group or glued.group(2)
            if tail and re.fullmatch(r"\d+y", tail[-1]):           # a connection up for more than a year prints "1y 41:21:54:040": the years come as a word of their own
                uptime = f"{tail.pop()} {uptime}"
        if len(tail) < 3:
            continue
        rows.append({
            "type": parts[0], "protocol": parts[1], "system_ip": parts[2], "site_id": parts[3], "domain_id": parts[4], "private_ip": parts[5], "private_port": parts[6],
            "public_ip": parts[7], "public_port": parts[8], "organization": " ".join(tail[:-3]), "local_color": tail[-3], "proxy": tail[-2], "state": tail[-1],
            "uptime": uptime, "group_id": group,
        })
    return rows


# How the error codes of ``show sdwan control connection-history`` are grouped.  The code names and
# their meaning come from the legend the device prints; the grouping is Keystone's.  DCONFAIL, DISTLOC,
# DISCVBD and the certificate codes are described in Cisco's "Troubleshoot SD-WAN Control Connections".
CONTROL_ERROR_CLASS: dict[str, str] = {
    "NOERR": "normal", "DISCVBD": "normal",
    "DCONFAIL": "unreachable", "DHSTMO": "unreachable", "NOACTVB": "unreachable",
    "ORPTMO": "timeout", "VB_TMO": "timeout", "VM_TMO": "timeout", "VP_TMO": "timeout", "VS_TMO": "timeout",
    "DISTLOC": "local", "OPERDOWN": "local", "SYSIPCHNG": "local", "SYSPRCH": "local", "RMGSPR": "local", "RXTRDWN": "peer",
    "BDSGVERFL": "certificate", "CRTREJSER": "certificate", "BIDNTVRFD": "certificate", "CTORGNMMIS": "certificate", "VSCRTREV": "certificate", "VECRTREV": "certificate",
    "CRTVERFL": "certificate", "CRTVERCRLFL": "certificate", "CERTEXPRD": "certificate", "HAFAIL": "certificate", "ACSRREJ": "certificate", "NOSLPRCRT": "certificate", "HWCERTREV": "certificate",
    "DUPSER": "identity", "DUPSYSIPDEL": "identity", "NOZTPEN": "identity", "SERNTPRES": "identity", "NOVMCFG": "identity",
}


def control_error_class(code: str) -> str:
    return CONTROL_ERROR_CLASS.get(code, "other")


_LEGEND_ENTRY = re.compile(r"([A-Z][A-Z0-9_]{2,})\s*-\s+(.+?)(?=\s{2,}[A-Z][A-Z0-9_]{2,}\s*-\s|\s*$)")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def parse_sdwan_control_history(lines: list[str]) -> dict[str, Any]:
    """``show sdwan control connection-history``: the device prints its own error legend, then one row per event."""
    legend: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 14 and parts[0] in _PEER_TYPES and parts[13].isdigit() and is_ipv4(parts[2]):
            rest = parts[14:]
            downtime = rest.pop() if rest and _ISO_TIME.match(rest[-1]) else ""
            rows.append({
                "type": parts[0], "protocol": parts[1], "system_ip": parts[2], "site_id": parts[3], "domain_id": parts[4], "private_ip": parts[5], "public_ip": parts[7],
                "public_port": parts[8], "local_color": parts[9], "state": parts[10], "local_error": parts[11], "remote_error": parts[12], "repeat": int(parts[13]),
                "organization": " ".join(rest), "downtime": downtime,
            })
        elif not rows:
            for code, text in _LEGEND_ENTRY.findall(line):
                legend.setdefault(code, text.strip())
    if not rows and not legend:
        return {}
    return {"legend": legend, "rows": rows}


def parse_sdwan_bfd_sessions(lines: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 9 and is_ipv4(parts[0]) and parts[2] in ("up", "down", "init"):
            rows.append({
                "system_ip": parts[0], "site_id": parts[1], "state": parts[2], "source_color": parts[3], "remote_color": parts[4], "source_ip": parts[5],
                "dst_public_ip": parts[6], "dst_public_port": parts[7], "encap": parts[8], "multiplier": parts[9] if len(parts) > 9 else "",
                "interval": parts[10] if len(parts) > 10 else "", "uptime": parts[11] if len(parts) > 11 else "", "transitions": parts[12] if len(parts) > 12 else "",
            })
    return rows


def parse_sdwan_config(lines: list[str]) -> dict[str, Any]:
    """``show sdwan running-config`` -> system, tunnel interfaces, OMP, BFD, security, policy."""
    tree = parse_config(lines)
    info: dict[str, Any] = {"system": {}, "tunnel_interfaces": [], "omp": {}, "bfd": [], "security": [], "policy": [], "appqoe": [], "sslproxy": []}
    system = tree.top_first("system")
    if system:
        for child in system.children:
            parts = child.text.split(None, 1)
            if parts[0] == "no" and len(parts) > 1:
                info["system"][parts[1].strip()] = "disabled"
            else:
                info["system"][parts[0]] = " ".join(parts[1].split()) if len(parts) > 1 else "enabled"
    sdwan = tree.top_first("sdwan")
    if sdwan:
        for interface in sdwan.find("interface"):
            tunnel = interface.first("tunnel-interface")
            if not tunnel:
                continue
            allow = [child.text.replace("allow-service ", "") for child in tunnel.children if child.text.startswith("allow-service")]
            info["tunnel_interfaces"].append({
                "interface": interface.text.split()[1],
                "color": tunnel.get("color").split()[0] if tunnel.get("color") else "",
                "encapsulation": tunnel.get("encapsulation"),
                "restrict": "restrict" in tunnel.get("color").split(),
                "hello_interval": tunnel.get("hello-interval"),
                "hello_tolerance": tunnel.get("hello-tolerance"),
                "nat_refresh": tunnel.get("nat-refresh-interval"),
                "port_hop": tunnel.has("port-hop") and not tunnel.has("no port-hop"),
                "carrier": tunnel.get("carrier"),
                "vmanage_preference": tunnel.get("vmanage-connection-preference"),
                "allow_services": allow,
                "allow_all": any(a.strip() == "all" for a in allow) and not tunnel.has("no allow-service all"),
                "last_resort": tunnel.has("last-resort-circuit") and not tunnel.has("no last-resort-circuit"),
                "border": tunnel.has("border") and not tunnel.has("no border"),
            })
        omp = sdwan.first("omp")
        if omp:
            info["omp"] = {
                "shutdown": not omp.has("no shutdown") and omp.has("shutdown"),
                "ecmp_limit": omp.get("ecmp-limit"),
                "send_path_limit": omp.get("send-path-limit"),
                "graceful_restart": omp.has("graceful-restart") and not omp.has("no graceful-restart"),
                "holdtime": (omp.first("timers").get("holdtime") if omp.first("timers") else ""),
                "advertise": [f"{fam.text}: " + ", ".join(c.text for c in fam.children) for fam in omp.find("address-family")],
            }
    for node in tree.root.children:
        if node.text.startswith("bfd "):
            info["bfd"].append(node.text)
        elif node.text == "security":
            info["security"] = [" ".join(child.text.split()) for child in node.walk()]
        elif node.text == "policy":
            info["policy"] = [" ".join(child.text.split()) for child in node.children]
        elif node.text == "appqoe":
            info["appqoe"] = [" ".join(child.text.split()) for child in node.walk()]
        elif node.text == "sslproxy":
            info["sslproxy"] = [" ".join(child.text.split()) for child in node.children]
    return info
