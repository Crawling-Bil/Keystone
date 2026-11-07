# Five-minute demonstration

A script for showing Keystone to a colleague or a customer. It uses only the invented captures that ship with the Topology Builder, so nothing from a real network is on screen. The numbers below are what the application shows for these sets; if a number differs on your screen, trust the screen and tell us.

Before you start: Keystone is running (`http://127.0.0.1:8002`), the browser window is wide enough for the preview, and **Topology history** is empty or you do not mind seeing older runs. Total time: about five minutes.

## 0:00 - Why (30 seconds)

> "A change window starts with a question: what is connected to what, and what breaks if I touch this box? Normally that is a Visio drawing nobody trusts. Keystone builds the picture from the captures you already have, on your own computer, and tells you how much of it is proven and how much is a guess."

Open **Analyze > Topology Builder**. Say that nothing leaves the machine: Keystone listens on `127.0.0.1` only and sends no configuration to any outside service.

## 0:30 - Build the baseline (60 seconds)

1. Under *Device captures* press **Data center today**. Six capture files appear: two NX-OS cores in a vPC pair and four IOS XE access switches dual-homed to both.
2. Press **Build topology**. Watch the progress bar (stage, percentage, seconds).
3. Read the result aloud: **7 devices, 12 links, 2 findings**. Seven devices because the firewall `DC1-FW1` was never captured; the switches' LLDP tables mention it, so it is drawn as *seen only by neighbours*.
4. Open the physical view and the vPC view. Say: "Every line has the port at both ends. A black line is confirmed: both devices report it. An orange dashed line is reported by one end only."
5. Read the two findings. **TOPO-004** (info): a device advertised by neighbours but not captured, `DC1-FW1`. **TOPO-013** (info): four access captures lack `show lldp neighbors detail`, so those links rest on CDP only. Say: "The tool tells you what it could not see."

Reference for the claim "LLDP is how neighbours describe themselves": IEEE 802.1AB, https://standards.ieee.org/ieee/802.1AB/6047/

## 1:30 - Pin it as the baseline (30 seconds)

Open **Topology history** (button beside the name). The run is listed with devices, links, findings and the date it will be cleaned up. Press **Pin**. Say: "Pinned means: this is the approved state. It is kept until I delete it, and every later build is compared with it."

## 2:00 - A change window happened (75 seconds)

1. Close the history. Press **After a change window** (seven captures) and **Build topology**.
2. A banner appears above the result: **7 differences from the baseline, 3 to read**. Press **Show changes**.
3. Walk the three things that need attention:
   - `DC1-ACC2` management address changed from `10.20.0.22` to `10.20.0.122`: "the address SSH, SNMP and the neighbour tables use". Somebody has to update the inventory and the monitoring.
   - The link `DC1-ACC3 Gi1/0/48 - DC1-CORE2 Eth1/3` is gone. Either the cable moved, or the port is down.
   - A new finding, **TOPO-035** (medium): `DC1-ACC3` now reaches the core through `DC1-CORE1` only. "One uplink means one failure takes the switch down." That is the consequence of the removed link, found without anyone asking.
4. Mention the new switch `DC1-ACC5` with two uplinks, one to each core: "the new switch is wired the way the standard says".

Reference for dual-homing to a vPC pair: Cisco Nexus vPC recommendations, https://community.cisco.com/t5/networking-knowledge-base/nexus-vpc-recommendations/ta-p/3130797

## 3:15 - Cutover runbook (45 seconds)

Open the **Cutover runbook** tab, choose the *after* run, change type **replace**, device `DC1-CORE1`, press the build button. Read the summary: one device, one with an expected outage, 31 steps. The device row says "Outage for DC1-ACC3. No remaining path to DC1-CORE2, DC1-FW1." Say: "The runbook knows that ACC3 only has one path left, so it puts a warning exactly where a person would have been surprised."

Show that the runbook downloads as a printable page and as CSV.

## 4:00 - Firewall and load balancer, and the converter (45 seconds)

1. Back on **Create topology** press **Firewall and F5**. Build. The two NX-OS cores now share the picture with a FortiGate (a two-port aggregate, one port to each core) and an F5 BIG-IP (a two-port LACP trunk, one port to each core). Open the **F5 map** page: two virtual servers and their pools.
2. Say: "Same engine for Cisco, Huawei, Aruba, FortiGate, Palo Alto and F5. The firewall and the BIG-IP do not speak LLDP in these captures, so the findings say so (TOPO-008) and the links stay *reported by one end only* (TOPO-001) until the neighbour is captured too."
3. Open **Convert > Firewall**, load a FortiGate configuration, pick Palo Alto as the target. Show the **Conversion report**: converted, approximated, needs review, not converted. Say: "A migration is not 'done' when the file is generated; it is done when every line of this report has an owner."

References: PAN-OS NAT policy overview, https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/nat/nat-policy-rules/nat-policy-overview; FortiGate central SNAT, https://docs.fortinet.com/document/fortigate/7.4.2/administration-guide/421028/central-snat; F5 trunks (`tmsh net trunk`), https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/net/net_trunk.html

## 4:45 - Close (15 seconds)

> "Captures in, picture and findings out, a baseline to compare with, a runbook for the window, and nothing leaves this laptop. Passwords, pre-shared keys and SNMP community names are never shown or exported."

Press **Download pack** in the history to show the single ZIP (draw.io file, Excel, report, tables, SHA-256) that goes into the change record.

## If something goes wrong

| Symptom | What to say and do |
| --- | --- |
| The banner does not appear after the second build | No run is pinned. Open **Topology history**, pin the first run, build the second set again. |
| The numbers differ from this script | The demo files were edited. Trust the screen; the Compare tab lists every difference. |
| The preview is empty | Reload the page once; the build is stored, open it again from **Topology history > Open again**. |
| A question about real captures | Real captures are used the same way; the *Also make an anonymized copy* option makes a pack that is safe to share. |
