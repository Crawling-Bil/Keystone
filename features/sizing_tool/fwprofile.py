"""Which throughput number a replacement firewall must be sized on.

A firewall datasheet prints several throughput figures and the headline one is measured with nothing switched on.  What a box can carry depends on what it does to the traffic:

1. **firewall** (stateful, NAT, no content inspection) -- the headline figure;
2. **application control** (App-ID, application list, URL filter) -- the vendor's "App-ID" / "NGFW" column;
3. **threat prevention** (IPS, antivirus, anti-spyware, sandbox) -- "Threat Prevention" (Palo Alto), "Threat Protection" (FortiGate), "AVC + IPS" (Cisco Secure Firewall);
4. **decryption** (SSL / TLS inspection of HTTPS) -- "SSL inspection" / "decryption" throughput, the lowest of all: inspecting the encrypted session costs the most.

The configuration says which of these are switched on: the security profiles attached to the rules, and the decryption rules / SSL inspection profiles.  The figure to size on is the
**highest level in use**, because one rule with deep inspection puts that load on the box for the traffic it matches.  A peak measured from monitoring is compared against the
datasheet column of that level, never against the headline number.

Datasheet columns and where to read them:

* Palo Alto Networks, PA-3400 Series datasheet (a datasheet of the current series lists "Firewall throughput", "Threat Prevention throughput", "IPsec VPN throughput", "Max sessions"):
  https://paloaltonetworks.com/resources/datasheets/pa-3400-series
* Fortinet, Product Matrix ("Firewall Throughput", "IPS Throughput", "NGFW Throughput", "Threat Protection Throughput", "SSL Inspection Throughput"):
  https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/Fortinet_Product_Matrix.pdf
* Cisco Secure Firewall 3100 Series datasheet (throughput FW + AVC, FW + AVC + IPS):
  https://www.cisco.com/c/en/us/products/collateral/security/firewalls/secure-firewall-3100-series-ds.html
* FortiGate SSL & SSH inspection (certificate inspection does not decrypt, deep inspection does):
  https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/929997/ssl-ssh-inspection
"""

from __future__ import annotations

import re
from typing import Any

LEVELS = ("firewall", "application", "threat", "decrypt")

# level -> the peak label to measure / type, the datasheet column per vendor
LABEL = {
    "firewall": "Peak throughput (Mbit/s)",
    "application": "Peak application-control throughput (Mbit/s)",
    "threat": "Peak threat-prevention throughput (Mbit/s)",
    "decrypt": "Peak SSL-inspected throughput (Mbit/s)",
}
TITLE = {
    "firewall": "Firewall throughput", "application": "Application-control throughput", "threat": "Threat-prevention throughput", "decrypt": "SSL-inspected (decrypted) throughput",
}
DATASHEET = {
    "Palo Alto": {"firewall": "Firewall throughput", "application": "Firewall throughput (App-ID)", "threat": "Threat Prevention throughput", "decrypt": "Threat Prevention throughput with decryption (see the datasheet footnote; ask the vendor for the decrypted figure)"},
    "Fortinet": {"firewall": "Firewall Throughput", "application": "NGFW Throughput", "threat": "Threat Protection Throughput", "decrypt": "SSL Inspection Throughput (IPS, avg. HTTPS)"},
    "Cisco": {"firewall": "Throughput: FW", "application": "Throughput: FW + AVC", "threat": "Throughput: FW + AVC + IPS", "decrypt": "TLS inspection throughput (see the datasheet)"},
}


def _count(pattern: str, text: str, flags: int = re.I | re.M) -> int:
    return len(re.findall(pattern, text, flags))


def _forti(text: str) -> dict[str, int]:
    """FortiGate: policies in ``config firewall policy`` that carry an IPS / antivirus / web / application profile, and those that use a deep-inspection SSL profile."""
    deep: set[str] = set()
    for match in re.finditer(r"^\s*edit\s+\"?([^\"\n]+?)\"?\s*\n((?:(?!^\s*next\b).*\n)*)", _section(text, r"config firewall ssl-ssh-profile"), re.I | re.M):
        if re.search(r"set\s+(?:https|ssl\s+inspect-all|ftps|imaps|pop3s|smtps)\s+.*deep-inspection|set\s+(?:https|ssl)\s+deep-inspection|set\s+inspect-all\s+deep-inspection", match.group(2), re.I) \
                or match.group(1).lower() == "deep-inspection":
            deep.add(match.group(1).lower())
    out = {"policies": 0, "threat": 0, "application": 0, "decrypt": 0}
    for match in re.finditer(r"^\s*edit\s+\d+\s*\n((?:(?!^\s*next\b).*\n)*)", _section(text, r"config firewall policy"), re.I | re.M):
        body = match.group(1)
        out["policies"] += 1
        if re.search(r"set\s+(?:ips-sensor|av-profile|virus-profile|dnsfilter-profile|file-filter-profile|emailfilter-profile|dlp-sensor|sandbox)\b|set\s+utm-status\s+enable", body, re.I) \
                and re.search(r"set\s+(?:ips-sensor|av-profile|virus-profile|file-filter-profile|dlp-sensor)\b", body, re.I):
            out["threat"] += 1
        elif re.search(r"set\s+(?:application-list|webfilter-profile|app-category)\b", body, re.I):
            out["application"] += 1
        ssl = re.search(r"set\s+ssl-ssh-profile\s+\"?([^\"\n]+?)\"?\s*$", body, re.I | re.M)
        if ssl and ssl.group(1).lower() in deep:
            out["decrypt"] += 1
    return out


def _section(text: str, header: str) -> str:
    """The lines from ``header`` to its closing ``end`` (the first ``end`` at the same indent as the header)."""
    match = re.search(r"^(\s*)" + header + r"\b.*\n", text, re.I | re.M)
    if not match:
        return ""
    rest = text[match.end():]
    stop = re.search(r"^" + re.escape(match.group(1)) + r"end\b", rest, re.I | re.M)
    return rest[: stop.start()] if stop else rest


def _pan(text: str) -> dict[str, int]:
    """PAN-OS (set, XML and curly formats): rules with threat profiles or a profile group, rules with an application / URL profile, and the decrypt rules of the decryption rulebase."""
    out = {"policies": 0, "threat": 0, "application": 0, "decrypt": 0}
    set_rules = set(re.findall(r"^\s*set\s+(?:device-group\s+\S+\s+|vsys\s+\S+\s+)*rulebase\s+security\s+rules\s+(\S+)", text, re.I | re.M))
    xml = "<rulebase>" in text or "<security>" in text
    if set_rules:
        out["policies"] = len(set_rules)
        threat = set(re.findall(r"rulebase\s+security\s+rules\s+(\S+)\s+profile-setting\s+(?:group|profiles\s+(?:virus|spyware|vulnerability|wildfire-analysis|file-blocking|data-filtering)\b)", text, re.I))
        url = set(re.findall(r"rulebase\s+security\s+rules\s+(\S+)\s+profile-setting\s+profiles\s+url-filtering\b", text, re.I)) - threat
        apps = set(re.findall(r"rulebase\s+security\s+rules\s+(\S+)\s+application\s+(?!any\b)\S+", text, re.I)) - threat
        out["threat"], out["application"] = len(threat), len(url | apps)
        out["decrypt"] = len(set(re.findall(r"rulebase\s+decryption\s+rules\s+(\S+)\s+action\s+decrypt\b", text, re.I)))
    elif xml:
        for rule in re.findall(r"<entry name=\"[^\"]+\">(?:(?!</entry>).)*?<from>.*?</entry>", _between(text, "<security>", "</security>"), re.I | re.S):
            out["policies"] += 1
            if re.search(r"<profile-setting>.*?(?:<group>|<virus>|<spyware>|<vulnerability>|<wildfire-analysis>)", rule, re.I | re.S):
                out["threat"] += 1
            elif re.search(r"<url-filtering>", rule, re.I) or re.search(r"<application>(?:(?!</application>).)*<member>(?!any<)", rule, re.I | re.S):
                out["application"] += 1
        out["decrypt"] = _count(r"<action>decrypt</action>", _between(text, "<decryption>", "</decryption>"), re.I)
    else:
        block = _braced(text, r"decryption\s*\{")
        out["decrypt"] = _count(r"\baction\s+decrypt\s*;", block)
        sec = _braced(text, r"\bsecurity\s*\{")
        out["policies"] = _count(r"\bfrom\s+", sec)
        out["threat"] = _count(r"profile-setting\s*\{[^{}]*(?:group|virus|spyware|vulnerability|wildfire-analysis)", sec, re.I | re.S)
    return out


def _between(text: str, start: str, end: str) -> str:
    a = text.find(start)
    if a < 0:
        return ""
    b = text.find(end, a)
    return text[a:b if b > 0 else len(text)]


def _braced(text: str, header: str) -> str:
    match = re.search(header, text)
    if not match:
        return ""
    depth, i = 1, match.end()
    while i < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        i += 1
    return text[match.end():i]


def read_inspection(text: str, vendor: str) -> dict[str, int]:
    """Counts of the rules that put each level of load on the box: ``{"policies", "application", "threat", "decrypt"}``; {} when the vendor is not read here."""
    if not text:
        return {}
    try:
        return _forti(text) if vendor == "Fortinet" else _pan(text) if vendor == "Palo Alto" else {}
    except Exception:                      # an addition to the reader: a pattern that does not fit leaves the figure undecided, never fails the capture
        return {}


def level_of(counts: dict[str, int]) -> str:
    """The highest level of load any rule of the firewall puts on it."""
    for level in ("decrypt", "threat", "application"):
        if (counts or {}).get(level):
            return level
    return "firewall"


_WORDS = {"decrypt": ("ssl", "tls", "decrypt"), "threat": ("threat", "ips", "antivirus"), "application": ("application", "app-id", "appid", "ngfw", "avc")}


def peak_for(peaks: dict[str, Any], level: str) -> str:
    """The label of the peak the architect has for a level, whatever the spelling of an imported column (``Threat prevention throughput`` is the same figure as ``Peak threat-prevention throughput``)."""
    if level == "firewall":
        return "Peak throughput (Mbit/s)" if "Peak throughput (Mbit/s)" in peaks else ""
    for label in peaks:
        low = label.lower()
        if "throughput" in low and any(word in low for word in _WORDS[level]) and not (level == "threat" and any(w in low for w in _WORDS["decrypt"])):
            return label
    return ""


def recommend(asset: dict[str, Any], today: dict[str, float] | None = None) -> dict[str, Any]:
    """What to size this firewall on: the level, the peak label to measure, the datasheet column, and why.  ``today`` is the peaks the architect has (label -> Mbit/s)."""
    counts = asset.get("inspection") or {}
    level = level_of(counts)
    if not counts:
        return {"level": "", "label": LABEL["threat"], "title": "Not known from this capture", "datasheet": "", "why": ["The capture does not say which security profiles the rules carry."
                " Size on the figure measured with the profiles that will be on after the refresh, from the vendor's threat-prevention column when in doubt."], "have_peak": False}
    parts = []
    if counts.get("decrypt"):
        parts.append(f"{counts['decrypt']} rule(s) decrypt SSL / TLS")
    if counts.get("threat"):
        parts.append(f"{counts['threat']} rule(s) carry IPS / antivirus / anti-spyware / sandbox profiles")
    if counts.get("application"):
        parts.append(f"{counts['application']} rule(s) match on application or URL category")
    if not parts:
        parts.append("no rule carries a security profile or decrypts: the headline firewall figure applies")
    why = ["; ".join(parts) + f" -> size on {TITLE[level].lower()}."]
    peaks = (asset.get("peaks") or {})
    found = peak_for(peaks, level)
    have = [name for lvl in LEVELS if (name := peak_for(peaks, lvl))]
    out = {"level": level, "label": found or LABEL[level], "title": TITLE[level], "datasheet": DATASHEET.get(asset.get("vendor", ""), {}).get(level, ""), "why": why, "counts": dict(counts),
           "have_peak": bool(found)}
    if "Peak throughput (Mbit/s)" in peaks and level != "firewall" and not found:
        why.append("The peak figure typed or imported is the plain 'Peak throughput': compare it with the datasheet column named above only if it was measured with the profiles on;"
                   " otherwise add the figure for this level.")
    elif not have and level != "firewall":
        why.append(f"No peak figure for this level yet: add '{LABEL[level]}' (Peak figures tab).")
    return out
