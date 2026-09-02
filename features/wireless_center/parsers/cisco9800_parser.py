import re
from pathlib import Path

class Cisco9800ConfigParser:
    def __init__(self, content):
        self.content=content.replace("\r\n","\n"); self.lines=self.content.splitlines()
    @classmethod
    def from_file(cls,path):
        return cls(Path(path).read_text(encoding="utf-8",errors="ignore"))
    def parse(self):
        wlans=self._wlans()
        policies=self._policy_tags()
        aps=self._aps()
        return {
          "vendor":"Cisco","platform":"Catalyst 9800","wlc":self._wlc(),
          "interfaces":self._interfaces(),"local_users":self._users(),
          "security_profiles":[],
          "ssid_profiles":[{"name":w["profile"],"config":[f'ssid {w["ssid"]}']} for w in wlans],
          "vap_profiles":[{"name":w["profile"],"config":[f'ssid-profile {w["profile"]}',f'security-profile {w["security"]}']+w["config"]} for w in wlans],
          "traffic_profiles":[],"ap_system_profiles":self._named_blocks("wireless profile ap "),
          "radio_2g_profiles":self._named_blocks("ap dot11 24ghz rf-profile "),
          "radio_5g_profiles":self._named_blocks("ap dot11 5ghz rf-profile "),
          "regulatory_domain_profiles":[],"wired_port_profiles":[],
          "aps":aps,"ap_groups":self._groups(policies,aps,wlans),
        }
    def _wlc(self):
        def one(p): 
            m=re.search(p,self.content,re.M|re.I); return m.group(1).strip() if m else ""
        return {"hostname":one(r"^hostname\s+(\S+)"),"software_version":one(r"Cisco IOS XE Software, Version\s+([^\s,]+)"),
          "model":one(r"^license udi pid\s+(\S+)"),"serial":one(r"^license udi pid\s+\S+\s+sn\s+(\S+)"),
          "management_ip":one(r"^interface Vlan\d+\n(?: .*\n)*? ip address\s+(\S+)"),"config":[]}
    def _interfaces(self):
        out=[]; cur=None
        for l in self.lines:
            m=re.match(r"^interface\s+(.+)",l)
            if m:
                if cur: out.append(cur)
                cur={"name":m.group(1),"ip":"","mask":"","config":[]}; continue
            if cur:
                if l.startswith(" "):
                    s=l.strip(); cur["config"].append(s)
                    m=re.match(r"ip address\s+(\S+)\s+(\S+)",s)
                    if m: cur["ip"],cur["mask"]=m.groups()
                elif l and not l.startswith("!"):
                    out.append(cur); cur=None
        if cur: out.append(cur)
        return out
    def _users(self):
        """Return one logical local-user record per Cisco username."""
        users = {}

        for line in self.lines:
            m = re.match(r"^\s*username\s+(\S+)\s+(.+?)\s*$", line, re.I)
            if not m:
                continue

            username = m.group(1).strip()
            fragment = m.group(2).strip()
            key = username.lower()

            user = users.setdefault(key, {
                "username": username,
                "privilege": "",
                "service_type": "local",
                "state": "Active",
                "configuration": "",
            })

            pm = re.search(r"\bprivilege\s+(\d+)\b", fragment, re.I)
            if pm:
                user["privilege"] = pm.group(1)

            # Mask credentials while preserving the rest of the configuration.
            safe = re.sub(
                r"\b(secret|password)\s+(?:\d+\s+)?\S+",
                lambda m: m.group(1) + " <removed>",
                fragment,
                flags=re.I,
            )

            fragments = [
                x.strip()
                for x in user["configuration"].split(" | ")
                if x.strip()
            ]
            if safe and safe not in fragments:
                fragments.append(safe)
            user["configuration"] = " | ".join(fragments)

        return list(users.values())

    def _named_blocks(self,prefix):
        d=[]; cur=None
        for l in self.lines:
            if l.startswith(prefix):
                if cur:d.append(cur)
                cur={"name":l[len(prefix):].strip().strip('"'),"config":[]}
            elif cur:
                if l.startswith(" "): cur["config"].append(l.strip())
                elif l and not l.startswith("!"):
                    d.append(cur);cur=None
        if cur:d.append(cur)
        return d
    def _wlans(self):
        out=[]; cur=None
        for l in self.lines:
            m=re.match(r'^wlan\s+(".*?"|\S+)\s+(\d+)\s+(".*?"|\S+)',l)
            if m:
                if cur: out.append(cur)
                profile=m.group(1).strip('"'); ssid=m.group(3).strip('"')
                cur={"profile":profile,"id":m.group(2),"ssid":ssid,"config":[],"security":"Open"}
            elif cur:
                if l.startswith(" "):
                    s=l.strip();cur["config"].append(s)
                    if "security wpa psk" in s:cur["security"]="WPA-PSK"
                    elif "security dot1x" in s:cur["security"]="802.1X"
                    elif "mac-filtering" in s:cur["security"]="MAC Filtering"
                elif l and not l.startswith("!"): out.append(cur);cur=None
        if cur:out.append(cur)
        return out
    def _policy_tags(self):
        tags={};cur=None
        for l in self.lines:
            m=re.match(r"^wireless tag policy\s+(.+)",l)
            if m: cur=m.group(1).strip().strip('"');tags.setdefault(cur,[])
            elif cur and l.startswith(" "):
                m=re.match(r'\s*wlan\s+(".*?"|\S+)\s+policy\s+(.+)',l)
                if m:tags[cur].append((m.group(1).strip('"'),m.group(2).strip().strip('"')))
            elif cur and l and not l.startswith("!"):cur=None
        return tags
    def _aps(self):
        """Return one Cisco AP record per normalized MAC, merging config and runtime."""
        aps = {}

        def norm_mac(value):
            raw = re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()
            if len(raw) != 12:
                return ""
            return ".".join(raw[i:i+4] for i in range(0, 12, 4))

        def get_ap(mac):
            key = norm_mac(mac)
            if not key:
                return None
            if key not in aps:
                aps[key] = {
                    "ap_id": "", "name": "", "mac": key, "serial": "",
                    "group": "", "type_id": "", "model": "", "ip": "",
                    "status": "Not Present", "native_status": "Not Present",
                    "operational_state": "NOT_PRESENT", "vendor": "Cisco",
                    "is_configured": False, "is_present_on_controller": False,
                    "site": "", "site_tag": "", "policy_tag": "", "rf_tag": "",
                    "last_failure_phase": "", "last_disconnect_reason": "",
                    "version": "",
                }
            return aps[key]

        # Static AP tag configuration. This never proves the AP is operational.
        current = None
        for line in self.lines:
            s = line.strip()
            m = re.match(r"^ap\s+([0-9a-fA-F.:-]{12,17})\s*$", s)
            if m:
                current = get_ap(m.group(1))
                if current:
                    current["is_configured"] = True
                continue

            if current is None:
                continue
            if s and not line.startswith((" ", "\t")):
                current = None
                continue
            if not s:
                continue

            m = re.match(r"^policy-tag\s+(.+)$", s)
            if m:
                current["policy_tag"] = m.group(1).strip().strip('"')
                current["group"] = current["policy_tag"]
                continue
            m = re.match(r"^site-tag\s+(.+)$", s)
            if m:
                current["site_tag"] = m.group(1).strip().strip('"')
                current["site"] = current["site_tag"]
                continue
            m = re.match(r"^rf-tag\s+(.+)$", s)
            if m:
                current["rf_tag"] = m.group(1).strip().strip('"')

        # `show ap summary` gives us AP Model (and a secondary source for
        # name/IP) which the join-summary table does not include at all.
        in_section = False
        in_table = False
        summary_row = re.compile(
            r"^(\S+)\s+(\d+)\s+(\S+)\s+"
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
            r"([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
            r"(.+?)\s+([A-Z]{2})\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)\s*$"
        )
        for line in self.lines:
            s = line.strip()
            low = s.lower()

            if "show ap summary" in low:
                in_section = True
                in_table = False
                continue
            if not in_section:
                continue
            if s.startswith("------------------ show ") and "show ap summary" not in low:
                in_section = False
                in_table = False
                continue
            if s.startswith("#show ") and "ap summary" not in low:
                in_section = False
                in_table = False
                continue
            if low.startswith("ap name") and "ap model" in low:
                in_table = True
                continue
            if not in_table or not s or s.startswith("-") or low.startswith("number of aps:"):
                continue

            m = summary_row.match(s)
            if not m:
                continue
            name, _slots, model, eth_mac, radio_mac, _location, _country, ip, state = m.groups()
            ap = get_ap(eth_mac) or get_ap(radio_mac)
            if ap is None:
                continue
            ap["model"] = model
            ap["type_id"] = model
            if not ap.get("name"):
                ap["name"] = name
            if not ap.get("ip"):
                ap["ip"] = ip
            # Join-summary status stays authoritative; only fill status
            # from here if the join-summary table wasn't present at all.
            if not ap.get("is_present_on_controller") and state:
                ap["native_status"] = ap.get("native_status") or state

        # Runtime join summary is authoritative for presence/status.
        in_section = False
        in_table = False
        for line in self.lines:
            s = line.strip()
            low = s.lower()

            if "show wireless stats ap join summary" in low:
                in_section = True
                in_table = False
                continue
            if not in_section:
                continue
            if s.startswith("------------------ show ") and "show wireless stats ap join summary" not in low:
                in_section = False
                in_table = False
                continue
            if s.startswith("#show ") and "wireless stats ap join summary" not in low:
                in_section = False
                in_table = False
                continue
            if low.startswith("base mac") and "ethernet mac" in low and "status" in low:
                in_table = True
                continue
            if not in_table or not s or s.startswith("-") or low.startswith("number of aps:"):
                continue

            m = re.match(
                r"^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
                r"(Joined|Not Joined)\s+(\S+)\s*(.*)$", s, re.I
            )
            if not m:
                continue

            base_mac, eth_mac, name, ip, native, phase, reason = m.groups()
            ap = get_ap(eth_mac) or get_ap(base_mac)
            if ap is None:
                continue
            native = "Joined" if native.lower() == "joined" else "Not Joined"
            ap.update({
                "name": name,
                "ip": ip,
                "status": native,
                "native_status": native,
                "operational_state": "ACTIVE" if native == "Joined" else "INACTIVE",
                "is_present_on_controller": True,
                "last_failure_phase": phase,
                "last_disconnect_reason": reason.strip(),
            })

        return list(aps.values())


    def _groups(self,policies,aps,wlans):
        # wlan_id used to be fabricated from the enumeration index within
        # each policy tag's wlan/policy mapping list (str(i+1)) instead of
        # the real WLAN ID Cisco assigns (`wlan <profile> <id> <ssid>`,
        # captured by _wlans() as w["id"]). That silently replaced the real
        # ID an engineer would cross-reference against `show wlan id N`
        # (e.g. 25, 3) with a meaningless per-tag counter (1, 2), and it was
        # also inconsistent with the Huawei parser, which does capture the
        # real wlan id. Look the real id up by profile name instead; leave
        # it blank (not a fabricated number) if a mapping references a wlan
        # profile that isn't defined anywhere -- that is itself a config
        # inconsistency worth surfacing as blank rather than hiding it.
        wlan_ids={w["profile"]:w["id"] for w in wlans}
        groups=[]
        for tag,maps in policies.items():
            members=[a for a in aps if a.get("group")==tag]
            vap=[{"wlan_id":wlan_ids.get(w,""),"vap_profile":w,"service_vlan_override":"","policy_profile":p} for w,p in maps]
            groups.append({"name":tag,"ap_system_profile":"","location_profile":"","radios":{"all":{"vap_mappings":vap}},"config":[f"wlan {w} policy {p}" for w,p in maps],"ap_count":len(members)})
        return groups
