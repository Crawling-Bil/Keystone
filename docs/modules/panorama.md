# Panorama

Keystone reads a **Panorama** configuration export (the XML of `Device > Setup > Operations > Export named configuration snapshot`, or `show config running` on Panorama) in four places. The Panorama is detected from the XML itself (a `devices/entry` that holds `device-group`, `template` and `template-stack`), so there is no extra switch: upload it where you would upload a firewall configuration.

| Where | What happens |
|---|---|
| Firewall Analyzer (`Palo Alto` or `Auto`) | A Panorama-specific analysis: device groups, managed firewalls, templates and stacks, rule base in evaluation order, objects, administrators. |
| Convert > Firewall, PAN-OS to FortiGate | One device group (or one firewall of it) is resolved and converted. |
| Convert > Firewall, Panorama to Palo Alto ("flatten") | The same resolved view written as the XML of one ordinary PAN-OS firewall. |
| Topology Builder | One firewall node per template stack that has managed firewalls. |

## How a firewall's configuration is resolved

**Device groups (policy and objects).** Objects are looked up from the device group upwards, so a device group's own `Web-Servers` hides the one of its parent and of `shared`. Rules are not overridden but ordered: `shared` pre-rules, each ancestor's pre-rules down to the device group, the firewall's local rules, then the post-rules back up to `shared`, then the default rules (the innermost `default-security-rules` wins). A rule with a `<target>` is pushed only to the listed firewalls (or tags, or all but the listed ones with `negate`).

**Template stacks (network and device).** The first template of a stack has the highest priority; settings made on the stack itself win over all of its templates. A named object (an interface, a zone, a virtual router, a profile) of the higher template replaces the object of the same name as a unit; containers are merged, leaves and member lists are replaced. `$variables` are filled from the template, then the stack, then the per-firewall value.

References: [Device Group Policies](https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/panorama-overview/centralized-firewall-configuration-and-update-management/device-groups/device-group-policies), [Manage the Rule Hierarchy](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-the-rule-hierarchy), [Configure a Template Stack](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack), [Override a template setting with stack variables](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/override-a-template-setting/override-template-setting-using-template-stack-variables), [Push a rule to a subset of firewalls](https://docs.paloaltonetworks.com/panorama/11-1/panorama-admin/manage-firewalls/manage-device-groups/push-a-policy-rule-to-a-subset-of-firewalls).

## Findings

| Id | Topic |
|---|---|
| PANO-POL-001 to 005 | Allow rule with any/any/any/any; application `any` with or without security profiles; allow rule without profiles; no log at session end ([Security policy best practices](https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-best-practices/deploy-security-policy-best-practices)) |
| PANO-POL-006 to 008 | Disabled rules per rule base, redundant rule, shadowed rule (a bounded check: 4,000,000 candidate pairs per device group) |
| PANO-OBJ-001 | Rule uses an object its device group cannot see (the predefined `panw-*` external dynamic lists are always resolvable: [Built-in EDLs](https://docs.paloaltonetworks.com/network-security/security-policy/administration/objects/external-dynamic-lists/built-in-edls)) |
| PANO-OBJ-002 to 007 | Unused objects, duplicate objects, empty or unresolvable address groups, the same name with different values at two levels, the same value redefined |
| PANO-HIER-001 to 008 | Targets naming serials that are not managed, missing hierarchy in the export, empty device groups, firewall in no device group or no stack, templates in no stack, stack naming a missing template, stack without firewalls |
| PANO-MGT-001 to 005 | Administrators without a password profile, many superusers, no password complexity, complexity off, short minimum length ([Admin roles and access domains](https://docs.paloaltonetworks.com/best-practices/10-1/best-practices-for-managing-firewalls-with-panorama/configuration-change-management/admin-roles-and-access-domains)) |
| PANO-TPL-001 to 004 | Stack pushes Telnet/HTTP, no NTP, no permitted-IP restriction, an interface management profile that allows risky services ([Template and stack best practice](https://docs.paloaltonetworks.com/best-practices/10-1/best-practices-for-managing-firewalls-with-panorama/configuration-management/template-and-template-stack-management)) |

The **Device group** filter on the Policy and Objects tabs narrows the result to one device group.

## Convert

Enter the scope in the *VDOM / device group* field of the Firewall page. The page lists the device groups and firewalls of the uploaded file in that field:

- `Group` converts every rule of the device group. Rules that are pushed to specific firewalls only are kept and listed in the report.
- `Group:SERIAL` keeps only the rules pushed to that firewall and its virtual system.
- Empty works only when the export has one device group.

PAN-OS to FortiGate then runs on the resolved view, so everything in [Convert firewall](configuration-studio.md) applies, including the Conversion report. Panorama to Palo Alto writes `<group>_PAN-OS_flattened.xml`. Pre-shared keys, password hashes, SNMP communities and private keys are never copied.

While testing on real exports one converter bug was fixed: a static route whose destination or next hop is an address object used to abort the whole conversion; it is now resolved through the object, or reported as not converted.

## Firewall Analyzer: one run for the Panorama and its firewalls

Upload the Panorama export and the exports of the firewalls it manages **in the same run** (up to 60 files on this page; the other analyzers keep 16). Each firewall is then analyzed the way it really runs: the template stack that manages it, the device group's policy, and the firewall's own export laid over both (`features/firewall_analyzer/panorama_fusion.py`, `panorama_effective.build_standalone`).

- **Matching.** The firewall's export has no serial number, so it is matched to a stack by names and pushed template names (see above). A rule pushed with a target list is kept when it applies to any serial of the matched stack, so an HA pair is exact; rules pushed only to other firewalls of the stack are counted as "left out". With several device groups on one stack the most common one among its serials is used and the others are named.
- **What you see.** A *Panorama* tab on each matched firewall (Panorama export, template stack, device group, match confidence and score, rules applied) and finding PANO-LINK-001 with the [template stack](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-templates-and-template-stacks/configure-a-template-stack) reference. The Panorama's own report gets a table of which firewalls went with it and which could not be matched. The "policy is on Panorama" warning is removed from a firewall that now has its policy.
- **A firewall that cannot be matched** (its export holds only management settings, so no name points to a stack) is analyzed from its own export alone and a warning says why. Nothing is guessed: a tie between stacks is reported as a tie.
- Rule order is the documented one: shared and parent pre-rules first, the firewall's own rules, then post-rules back up, with the innermost default rules last ([Manage the Rule Hierarchy](https://docs.paloaltonetworks.com/panorama/administration/manage-firewalls/manage-device-groups/manage-the-rule-hierarchy)).
- Without a Panorama in the upload nothing changes: each file is analyzed alone as before.

## Topology

Every template stack with managed firewalls becomes one firewall node named after the stack (model "PAN-OS firewall (Panorama stack, N managed units)"), with the interfaces, zones and routing of the merged template. A Panorama has no CDP or LLDP of its own, so links come from the usual neighbour captures of the other devices. A firewall export has no neighbour table either: the switch it plugs into names it in its LLDP/CDP output or its port description (`Te1/0/1 ... <firewall> - ethernet1/2`), so upload the **switch captures** with the firewalls and the cable is drawn from the switch side (the page then lists it as reported by one end only, which is true: PAN-OS exports carry no LLDP table). HA links between the firewalls come from the HA settings. The Topology Builder page accepts `.xml` (PAN-OS and Panorama exports) next to the usual captures.

## Managed firewalls (Panorama together with the firewalls' own exports)

A firewall's own export holds only what is local to it (management, HA, local interfaces and VLAN interfaces). The interfaces, zones, routing and IPsec a template stack pushes are in the Panorama, and the addresses of those interfaces are usually **names of Shared address objects** (a layer 3 interface may take an address object: [Configure Layer 3 Interfaces](https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-networking-admin/configure-interfaces/layer-3-interfaces/configure-layer-3-interfaces)). Keystone therefore:

- resolves those names from the Shared location when it builds a template stack (interface addresses, static route destinations and next hops, IKE peer and local addresses); an object that is not in Shared is listed in the notes, never guessed;
- in the Topology Builder, matches each uploaded firewall to a template stack (`features/firewall_analyzer/panorama_link.py`) and reads it as the stack plus its own export (the firewall's entries win, an empty local `<zone/>` does not wipe the pushed zones, a local address list replaces the pushed one). The stack's own node is dropped for every stack that has a real unit on the picture. TOPO-044 lists what was matched and what could not be;
- in the Firewall Analyzer, reads the `panorama/local-panorama/panorama-server` spelling that PAN-OS 10.x and 11.x write, and raises PAN-NET-001 when interface addresses are object names that the file does not define.

The firewall's export has no serial number, so the match is by names: each interface, VLAN interface, zone, virtual router, IKE gateway or tunnel name that the firewall and a stack share counts `1 / (stacks that have it)`, and a pushed template name counts five times that; the firewall is linked only when one stack scores at least 1.5 times the second. With several Panorama exports the one the firewall lists as its `panorama-server` is used when its address is known. A firewall with no such evidence is drawn from its own export, as before.

## Secrets

Panorama exports contain password hashes, pre-shared keys, SNMP communities and API keys. The parser removes every leaf whose name matches a credential pattern (`password`, `phash`, `psk`, `private-key`, `api-key`, `snmp-community-string`, `wmi-password`, `shared-secret` and similar; settings whose value is only yes/no/enable/disable are kept). The Convert page shows only this masked tree as the source, never the upload. For any firewall file converted on that page (PAN-OS XML, set or curly view, FortiOS) the source pane now hides credential values too (`fwconvert/mask.py`), including SNMPv3 `authpwd` / `privpwd`; the conversion itself reads the real text. The analyzer, its Excel export, the topology JSON and the converter output were scanned for the credentials of an invented canary export (`tests/fixtures/panorama/synthetic_panorama.xml`): none is present.

## Limits

- The device-group hierarchy is read from `readonly/dg-meta-data` or a `parent-dg` element. An export without it is treated as flat under `shared` and PANO-HIER-002 says so. Export the full named configuration snapshot to get exact inheritance.
- `disable-override` is not applied; objects hidden by a lower level are reported instead.
- No hit counts: Panorama does not carry them in the export, so "unused" means "not referenced in the export".
- Per-firewall variable values come from the stack's `variable` entries; values set only on the firewall are not in the Panorama export.
- Local rules and local objects of a firewall are not in the Panorama export; when the firewall's own export is uploaded too, its local rulebase is placed between the pre-rules and the post-rules.
- A firewall whose export holds nothing but management settings cannot be matched to a stack without its serial number; it is analyzed alone and flagged.

Export format: [Save and export Panorama and firewall configurations](https://docs.paloaltonetworks.com/panorama/administration/administer-panorama/manage-panorama-and-firewall-configuration-backups/save-and-export-panorama-and-firewall-configurations).

Tests: `tests/test_panorama.py` (46 checks on the invented export).
