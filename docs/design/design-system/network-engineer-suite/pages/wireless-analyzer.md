# Wireless Analyzer — Page Rules

## Intake structure

- Show a three-step flow: WLC configuration, AP runtime inventory, then vendor + Analyze.
- WLC configuration is **Required**. AP inventory is **Recommended**, not hidden behind an “Optional” suffix.
- Steps 1 and 2 use equal-width, equal-height cards on desktop and stack at 720px.
- Give both cards the same header grid, drop-zone height, selected-file action, and helper region.
- Keep command guidance in progressive disclosure so the default view remains scannable.
- Huawei AC6508 copy must specifically call out AP Info CSV enrichment.

## Visual hierarchy

- Outer intake uses the main panel surface. File cards use the raised panel surface; the header and action bar use the inset surface.
- Cyan marks step numbers, required state, focus, and the primary CTA.
- A selected file includes filename text and a “Remove selected file” action; green is supplementary.
- Keep “Local processing” visible but secondary.

## Responsive and accessibility

- At 720px: stack cards, vendor field, and CTA into one column; keep summary metrics in two columns.
- Maintain 44px minimum controls and visible focus.
- Native file inputs remain keyboard-operable through their labels.
- Prevent page-level horizontal overflow; tables may scroll within `.table-wrap`.
- Loading analysis disables the CTA and exposes a textual progress state.

## Data output

- Preserve operational density in summary metrics, tabs, and tables.
- Chart colors read from semantic theme tokens.
- Status colors must be paired with labels and counts.
- Export As-Built remains primary only after a successful analysis; Export Analysis stays secondary.

## AP model and software summary

- Place the summary at the beginning of the Analyze Environment Overview tab.
- Show total AP models, unique known versions, mixed-version models, and unknown-version AP counts.
- Group exact software versions below each AP model and pair every count with textual operational status.
- Clicking a model or version filters the detailed AP Inventory; the summary is not a chart-only surface.
- On mobile, preserve a two-column metric grid and stack version rows without page overflow.

## Config Delta workspace

- Keep Config Delta inside Wireless Analyzer as a separate top-level workspace, not an analysis result tab.
- Use equal Source and Target upload cards. Source is always the desired reference state.
- Results must distinguish Identical, Missing on Target, Value Mismatch, Extra on Target, and Manual Review.
- Target-only configuration is report-only; never generate automatic removal commands.
- Mask secrets and exclude controller identity, management addressing, HA, AP assignment, licensing, and certificates from automatic commands.
- Generated implementation and rollback candidates remain review artifacts; do not push directly to devices.
- Keep detailed results in horizontally scrollable tables and command output in copyable monospace panels.
- Keep MAC authentication in a dedicated dependency view ordered from AAA/RADIUS through AP delivery.
- Show aligned and drift counts per dependency stage; include text labels so status never relies on color alone.
- Preserve Huawei `aaa` and `wlan` parent contexts plus nested radio indentation in generated CLI candidates.
- Treat local AAA users and all credential-bearing commands as manual-only, masked review data.
- Compare Huawei `sta-whitelist-profile` and `wids-whitelist-profile` blocks independently, including every Source-only MAC entry.
- Resolve `sta-access-mode whitelist` from VAP to STA whitelist profile and show the dependency in MAC Authentication results.
- Generate Source-only whitelist entries inside `wlan` and the correct profile context; keep Target-only entries report-only.

## VAP profile inventory

- Keep the SSID catalog unchanged and place one-row-per-profile VAP detail in its own analysis tab.
- Resolve VAP configuration through SSID, security, authentication, traffic, VLAN, AP Group/site, radio, and WLAN ID relationships.
- Distinguish Site-specific, Shared across sites, and Unassigned profiles with text labels, counts, and searchable fields.
- Present full VAP commands in progressive disclosure so the default table remains scannable.
- Keep the wide technical table inside an explicit horizontal-scroll wrapper and preserve keyboard-searchable text.

## AP Role Diff workspace

- Keep AP Role Diff as a separate top-level Wireless Analyzer workspace because it compares live operational state, not running configuration.
- Use equal TTC and HO upload cards; accept AP Info CSV/XLSX or complete `display ap all` TXT/LOG captures.
- Match AP identity by MAC, then serial, then AP name. Never use AP ID across WLCs as a stable identity.
- Treat Normal as active and Standby as peer standby; call out dual-active, no-active, missing-peer, and non-ready backup states with text labels.
- Keep Expected Allocation optional and provide a downloadable template. When supplied, clearly distinguish actual role from intended role.
- Compare peer group, IP, model, version, MAC, serial, and name, but do not confuse expected status differences with attribute drift.
- Keep detailed role output in horizontally scrollable tables and provide a multi-sheet Excel export.
- Keep a plain-language Status Guide visible in the AP Role Diff workspace. Explain Normal, Standby, Idle, and Fault with meaning and next action.
- Clarify that Standby is healthy when the peer WLC reports Normal; do not style Standby as an error.
- Include the same status and TTC/HO pairing guidance in accessible badge descriptions and the Excel export.
- Recognize both `AP Group` and Huawei `Group name` headers without requiring users to rename columns.
- Place AP Group mapping in its own result tab with a compact group summary followed by AP-level drill-down.
- Use TTC Group as the Mapping Group reference and fall back to HO Group only when the AP is absent from TTC.
- Distinguish Matched, Group Mismatch, Peer Group Missing, and Unassigned using text labels in addition to semantic color.
- Keep group filtering keyboard-operable, expose filtered counts with `aria-live`, and preserve tables inside horizontal scroll wrappers.
