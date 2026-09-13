(() => {
  const form = document.getElementById("switch-form");
  if (!form) return;

  const configFile = document.getElementById("switch-config-file");
  const button = document.getElementById("switch-analyze-button");
  const empty = document.getElementById("switch-empty");
  const resultPanel = document.getElementById("switch-result");
  const firewallResultPanel = document.getElementById("switch-firewall-result");
  const exportButton = document.getElementById("switch-export-button");
  const firewallExportButton = document.getElementById("firewall-export-button");
  let lastResult = null;
  const esc = value => window.NES.escape(value ?? "");
  const display = value => Array.isArray(value) ? value.join("\n") : (value ?? "");
  const formatKey = key => String(key).replaceAll("_", " ").replace(/\b\w/g, value => value.toUpperCase());

  function setFile(input, labelId, clearId, fallback) {
    document.getElementById(labelId).textContent = input.files[0]?.name || fallback;
    document.getElementById(clearId)?.classList.toggle("hidden", !input.files.length);
  }
  configFile.addEventListener("change", () => setFile(configFile, "switch-file-label", "clear-switch-file", "Cisco, Huawei, or Aruba running-config"));
  document.getElementById("clear-switch-file").addEventListener("click", () => {
    configFile.value = "";
    setFile(configFile, "switch-file-label", "clear-switch-file", "Cisco, Huawei, or Aruba running-config");
  });

  function switchTab(tabName) {
    document.querySelectorAll("#switch-tabs button").forEach(item => item.classList.toggle("active", item.dataset.tab === tabName));
    document.querySelectorAll("#switch-result .tab-content").forEach(item => item.classList.toggle("active", item.id === `switch-tab-${tabName}`));
  }
  document.getElementById("switch-tabs").addEventListener("click", event => {
    const tabButton = event.target.closest("button[data-tab]");
    if (tabButton) switchTab(tabButton.dataset.tab);
  });

  // Single Device / Compare Devices are two fully separate top-level
  // views (not a form stacked above a collapsible section) so each one
  // has room to show its complete result set without the other's forms
  // and tables crowding the page.
  function switchMode(mode) {
    document.querySelectorAll("#switch-mode-tabs button").forEach(item => item.classList.toggle("active", item.dataset.mode === mode));
    document.getElementById("switch-mode-single").classList.toggle("active", mode === "single");
    document.getElementById("switch-mode-compare").classList.toggle("active", mode === "compare");
    document.getElementById("switch-mode-sizing")?.classList.toggle("active", mode === "sizing");
    document.getElementById("switch-mode-collect")?.classList.toggle("active", mode === "collect");
  }
  document.getElementById("switch-mode-tabs").addEventListener("click", event => {
    const modeButton = event.target.closest("button[data-mode]");
    if (modeButton) switchMode(modeButton.dataset.mode);
  });

  // Firewall-shaped results (Mikrotik/Palo Alto, see renderFirewallResult
  // below) render into their own tab-shell/panel entirely separate from
  // the switch dashboard's #switch-tabs -- same tab-switching pattern,
  // just scoped to #switch-firewall-result instead of #switch-result.
  function firewallTab(tabName) {
    document.querySelectorAll("#firewall-tabs button").forEach(item => item.classList.toggle("active", item.dataset.tab === tabName));
    document.querySelectorAll("#switch-firewall-result .tab-content").forEach(item => item.classList.toggle("active", item.id === `firewall-tab-${tabName}`));
  }
  document.getElementById("firewall-tabs")?.addEventListener("click", event => {
    const tabButton = event.target.closest("button[data-tab]");
    if (tabButton) firewallTab(tabButton.dataset.tab);
  });

  document.addEventListener("input", event => {
    const searchId = event.target.dataset?.tableSearch;
    if (!searchId) return;
    const query = event.target.value.toLowerCase();
    document.getElementById(searchId)?.querySelectorAll("tbody tr").forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
    });
  });

  function filterTable(tableId, statusQuery) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const target = statusQuery.toLowerCase();
    table.querySelectorAll("tbody tr").forEach(row => {
      row.style.display = row.dataset.rowStatus === target ? "" : "none";
    });
    const searchInput = document.querySelector(`[data-table-search="${tableId}"]`);
    if (searchInput) searchInput.value = statusQuery;
  }

  function renderTable(id, columns, rows) {
    const table = document.getElementById(id);
    const head = `<thead><tr>${columns.map(column => `<th>${esc(column.label)}</th>`).join("")}</tr></thead>`;
    const statusColumn = columns.find(column => column.status);
    const body = rows.length ? rows.map(row => {
      const rowStatus = statusColumn ? String(display(statusColumn.value ? statusColumn.value(row) : row[statusColumn.key])).toLowerCase() : "";
      const statusAttr = statusColumn ? ` data-row-status="${esc(rowStatus)}"` : "";
      return `<tr${statusAttr}>${columns.map(column => {
        let value = column.value ? column.value(row) : row[column.key]; value = display(value);
        if (column.status) return `<td><span class="cell-status">${esc(value)}</span></td>`;
        return `<td>${esc(value)}</td>`;
      }).join("")}</tr>`;
    }).join("") : `<tr><td colspan="${columns.length}">No data found.</td></tr>`;
    table.innerHTML = head + `<tbody>${body}</tbody>`;
  }

  function renderKVList(id, obj) {
    document.getElementById(id).innerHTML = Object.entries(obj || {})
      .map(([key, value]) => `<div class="kv-row"><span>${esc(formatKey(key))}</span><strong>${esc(display(value) || "—")}</strong></div>`)
      .join("") || `<div class="kv-row"><span>No data</span><strong>—</strong></div>`;
  }

  // Column definitions shared between the single-device dashboard
  // (renderResult) and the Compare Devices "Full Device Data" tables
  // (renderCompareDeviceTables) so both views render each category
  // identically instead of drifting apart.
  const INTERFACE_COLUMNS = [
    { label: "Name", key: "name" },
    { label: "Status", key: "status", status: true },
    { label: "Protocol", key: "protocol" },
    { label: "Mode", key: "mode" },
    { label: "VLAN", key: "vlan" },
    { label: "Allowed VLANs", key: "allowed_vlans" },
    { label: "IP Address", key: "ip_address" },
    { label: "HSRP/VRRP IP", key: "hsrp_vrrp_ip" },
    { label: "Port Security", key: "port_security" },
    { label: "Description", key: "description" },
  ];
  const PORTCHANNEL_COLUMNS = [
    { label: "Name", key: "name" },
    { label: "Protocol", key: "protocol" },
    { label: "Status", key: "status" },
    { label: "Description", key: "description" },
    { label: "Mode", key: "mode" },
    { label: "VLAN", key: "vlan" },
    { label: "Allowed VLANs", key: "allowed_vlans" },
    { label: "IP Address", key: "ip_address" },
    { label: "Member Ports", key: "members" },
  ];
  const TRANSCEIVER_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Status", key: "status", status: true },
    { label: "Present", key: "present", value: row => row.present ? "Yes" : "No" },
    { label: "Type", key: "type" },
    { label: "Vendor Part Number", key: "vendor_part_number" },
    { label: "Serial Number", key: "serial_number" },
  ];
  const VPCMLAG_MEMBER_COLUMNS = [
    { label: "ID", key: "id" },
    { label: "Port", key: "port" },
    { label: "Status", key: "status", status: true },
    { label: "Consistency", key: "consistency" },
    { label: "VLANs", key: "vlans" },
  ];
  const POE_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Admin Status", key: "admin_status" },
    { label: "Oper Status", key: "oper_status", status: true },
    { label: "Power (W)", key: "power_watts" },
    { label: "Device", key: "device" },
    { label: "Class", key: "class" },
    { label: "Max (W)", key: "max_watts" },
    { label: "Source", key: "source" },
  ];
  const NEIGHBOR_COLUMNS = [
    { label: "Protocol", key: "protocol" },
    { label: "Neighbor", key: "neighbor_id" },
    { label: "Local Interface", key: "local_interface" },
    { label: "Remote Interface", key: "remote_interface" },
    { label: "Platform", key: "platform" },
  ];

  // PBR / SLA-Track / NQA — one shared set of columns for both Single
  // Device's Routing tab and Compare Devices' side-by-side panel (see
  // features/switch_analyzer/service.py's _build_pbr_summary for the
  // unified, vendor-neutral shape these read from).
  const PBR_SLA_COLUMNS = [
    { label: "Test", key: "id" },
    { label: "Kind", key: "kind" },
    { label: "Type", key: "test_type" },
    { label: "Destination", key: "destination" },
    { label: "Frequency (s)", key: "frequency" },
    { label: "Timeout (s)", key: "timeout" },
    { label: "Probe Count", key: "probe_count" },
  ];
  const PBR_TRACK_COLUMNS = [
    { label: "Track ID", key: "track_id" },
    { label: "Tracks", key: "tracks" },
  ];
  const PBR_POLICY_COLUMNS = [
    { label: "Mechanism", key: "vendor_mechanism" },
    { label: "Policy Name", key: "policy_name" },
    { label: "Sequence / Precedence", key: "sequence" },
    { label: "Action", key: "action" },
    { label: "Match", key: "match" },
    { label: "Set Next Hop", key: "set_next_hop" },
    { label: "Tracked By", key: "tracked_by" },
  ];
  const PBR_BINDING_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Policy Name", key: "policy_name" },
    { label: "Direction", key: "direction" },
    { label: "Mechanism", key: "mechanism" },
  ];
  const PBR_EEM_COLUMNS = [
    { label: "Applet Name", key: "applet_name" },
    { label: "Route-Map", key: "route_map_name" },
    { label: "Action", key: "action" },
    { label: "Target Interfaces", key: "target_interfaces", value: row => (row.target_interfaces || []).join(", ") },
    { label: "Trigger", key: "trigger_description" },
  ];

  // Renders one device's PBR/SLA-Track/NQA summary into the given
  // table element IDs. Shared by Single Device's Routing tab and
  // Compare Devices' side-by-side panel (called once per device
  // there) so the column definitions above stay in one place.
  function renderPbrTables(ids, pbr) {
    pbr = pbr || {};
    renderTable(ids.sla, PBR_SLA_COLUMNS, pbr.sla_tests || []);
    renderTable(ids.track, PBR_TRACK_COLUMNS, pbr.track_objects || []);
    renderTable(ids.policy, PBR_POLICY_COLUMNS, pbr.pbr_policies || []);
    renderTable(ids.binding, PBR_BINDING_COLUMNS, pbr.pbr_bindings || []);
    renderTable(ids.eem, PBR_EEM_COLUMNS, pbr.eem_dynamic_pbr || []);
  }

  function renderDashboardChart(result) {
    const container = document.getElementById("switch-dashboard-chart");
    if (!container) return;
    const cards = result.cards || {};

    const bars = [
      { label: "Interfaces Up", value: cards.interfaces_up || 0, color: "#3aa76d", tab: "interfaces", filter: "up" },
      { label: "Interfaces Down", value: cards.interfaces_down || 0, color: "#e2a33b", tab: "interfaces", filter: "down" },
      { label: "Total VLANs", value: cards.total_vlans || 0, color: "#4a90d9", tab: "vlans", filter: "" },
      { label: "Total Routes", value: cards.total_routes || 0, color: "#8e6fd6", tab: "routing", filter: "" },
      { label: "DNS Servers", value: cards.dns_servers || 0, color: "#5bb8b0", tab: "dns", filter: "" },
    ];

    const width = 900, height = 300;
    const paddingLeft = 46, paddingBottom = 46, paddingTop = 18, paddingRight = 16;
    const plotWidth = width - paddingLeft - paddingRight;
    const plotHeight = height - paddingTop - paddingBottom;
    const maxValue = Math.max(1, ...bars.map(b => b.value));
    const niceMax = Math.ceil(maxValue / 5) * 5 || 5;
    const barGap = 24;
    const barWidth = (plotWidth - barGap * (bars.length - 1)) / bars.length;

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(fraction => {
      const y = paddingTop + plotHeight * (1 - fraction);
      const value = Math.round(niceMax * fraction);
      return `<line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" stroke="#1c2934" stroke-width="1"></line>` +
        `<text x="${paddingLeft - 10}" y="${y + 4}" text-anchor="end" font-size="11" fill="#8a93a6">${value}</text>`;
    }).join("");

    const barsMarkup = bars.map((bar, index) => {
      const x = paddingLeft + index * (barWidth + barGap);
      const barHeight = Math.max(2, (bar.value / niceMax) * plotHeight);
      const y = paddingTop + plotHeight - barHeight;
      const labelX = x + barWidth / 2;
      return `
        <g class="dash-bar" data-index="${index}" style="cursor:pointer">
          <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6" fill="${bar.color}"></rect>
          <text x="${labelX}" y="${y - 8}" text-anchor="middle" font-size="15" font-weight="700" fill="#e8edf2">${bar.value}</text>
          <text x="${labelX}" y="${height - paddingBottom + 20}" text-anchor="middle" font-size="11" fill="#8a93a6">${esc(bar.label)}</text>
        </g>`;
    }).join("");

    container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width:100%;height:100%;display:block;">${gridLines}${barsMarkup}</svg>`;

    container.querySelectorAll(".dash-bar").forEach(group => {
      group.addEventListener("click", () => {
        const bar = bars[Number(group.dataset.index)];
        if (!bar) return;
        switchTab(bar.tab);
        if (bar.tab === "interfaces" && bar.filter) filterTable("switch-interface-table", bar.filter);
      });
    });
  }

  function renderResult(result) {
    document.getElementById("switch-source-name").textContent = result.hostname || "Switch Analysis";
    document.getElementById("switch-platform").textContent = `${result.vendor || "Unknown"} · ${result.device_type || "Switch"}`;

    renderDashboardChart(result);

    const stack = result.inventory?.stack || {};
    renderKVList("switch-information", {
      hostname: result.hostname,
      vendor: result.vendor,
      os_version: result.os_version?.os_version || "—",
      model: result.os_version?.model || "—",
      default_gateway: result.routing_protocols?.default_gateway || "—",
      stack_mode: stack.mode || "Unknown",
      stack_member_count: stack.member_count ?? "—",
      total_interfaces: result.cards?.total_interfaces ?? 0,
      total_vlans: result.cards?.total_vlans ?? 0,
      total_routes: result.cards?.total_routes ?? 0,
    });

    renderTable("switch-serial-table", [
      { label: "Slot", key: "slot" },
      { label: "Description", key: "description" },
      { label: "PID", key: "pid" },
      { label: "Serial Number", key: "serial" },
    ], result.inventory?.modules || []);

    renderKVList("switch-dns-summary", {
      dns_servers: (result.dns?.servers || []).join(", ") || "—",
      domain_name: result.dns?.domain || "—",
    });

    document.getElementById("switch-interface-count-label").textContent = `${(result.interfaces || []).length} interfaces`;
    renderTable("switch-interface-table", INTERFACE_COLUMNS, result.interfaces || []);

    renderTable("switch-route-table", [
      { label: "Destination", key: "destination" },
      { label: "Mask", key: "mask" },
      { label: "Next Hop", key: "next_hop" },
      { label: "Admin Distance", key: "distance" },
      { label: "Track ID", key: "track_id" },
    ], result.routes || []);

    renderTable("switch-routing-table-table", [
      { label: "Protocol", key: "protocol" },
      { label: "Destination", key: "destination" },
      { label: "Next Hop", key: "next_hop" },
      { label: "Interface", key: "interface" },
    ], result.routing_table || []);

    renderTable("switch-arp-table", [
      { label: "IP Address", key: "ip_address" },
      { label: "MAC Address", key: "mac_address" },
      { label: "Age", key: "age" },
      { label: "Interface", key: "interface" },
    ], result.arp_table || []);

    renderKVList("switch-routing-protocols", {
      default_gateway: result.routing_protocols?.default_gateway || "—",
      ospf: (result.routing_protocols?.ospf || []).join("\n") || "Not configured",
      eigrp: (result.routing_protocols?.eigrp || []).join("\n") || "Not configured",
    });

    const pbr = result.pbr || {};
    document.getElementById("switch-pbr-empty").classList.toggle("hidden", pbr.has_custom_routing);
    document.getElementById("switch-pbr-eem-note").classList.toggle("hidden", !(pbr.eem_dynamic_pbr || []).length);
    renderPbrTables({
      sla: "switch-pbr-sla-table",
      track: "switch-pbr-track-table",
      policy: "switch-pbr-policy-table",
      binding: "switch-pbr-binding-table",
      eem: "switch-pbr-eem-table",
    }, pbr);

    renderTable("switch-vlan-table", [
      { label: "VLAN ID", key: "vlan_id" },
      { label: "Name", key: "name" },
    ], result.vlans || []);

    const neighbors = result.neighbors || [];
    document.getElementById("switch-neighbors-empty").classList.toggle("hidden", neighbors.length > 0);
    renderTable("switch-neighbor-table", NEIGHBOR_COLUMNS, neighbors);

    const portChannels = result.port_channels || [];
    document.getElementById("switch-portchannel-empty").classList.toggle("hidden", portChannels.length > 0);
    renderTable("switch-portchannel-table", PORTCHANNEL_COLUMNS, portChannels);

    const transceivers = result.transceivers || [];
    document.getElementById("switch-transceiver-empty").classList.toggle("hidden", transceivers.length > 0);
    renderTable("switch-transceiver-table", TRANSCEIVER_COLUMNS, transceivers);

    const vpcMlag = result.vpc_mlag || { summary: {}, members: [], source: "none" };
    document.getElementById("switch-vpcmlag-empty").classList.toggle("hidden", vpcMlag.members.length > 0 || Object.keys(vpcMlag.summary || {}).length > 0);
    // "config" means there's no live show-command status at all — the
    // device (or draft) has vPC configured but was never active — see
    // service._apply_vpc_mlag_config_fallback. Flag that plainly instead
    // of letting a "configured (not active)" status row speak for itself.
    document.getElementById("switch-vpcmlag-note").classList.toggle("hidden", vpcMlag.source !== "config");
    renderKVList("switch-vpcmlag-summary", vpcMlag.summary || {});
    renderTable("switch-vpcmlag-table", VPCMLAG_MEMBER_COLUMNS, vpcMlag.members || []);

    const poe = result.poe || [];
    document.getElementById("switch-poe-empty").classList.toggle("hidden", poe.length > 0);
    // "cdp-detail" means there was no live PoE table at all ('show
    // power inline' etc. was never run) — these rows are each
    // connected device's own reported power draw from 'show cdp
    // neighbors detail' instead, so only currently-powered neighbors
    // show up (a port with no device attached has no row here, unlike
    // the live table which lists every PoE-capable port either way).
    const poeFromCdp = poe.length > 0 && poe.every(item => item.source === "cdp-detail");
    document.getElementById("switch-poe-note").classList.toggle("hidden", !poeFromCdp);
    // "config (poe enable)" means no live PoE table exists at all (see
    // service._apply_poe_config_fallback) — every real Huawei PoE
    // access-switch draft in this project has never had anything
    // plugged in yet, so these rows are just which ports are
    // configured for PoE, not a live power reading.
    const poeFromConfig = poe.length > 0 && poe.every(item => item.source === "config (poe enable)");
    document.getElementById("switch-poe-config-note")?.classList.toggle("hidden", !poeFromConfig);
    renderTable("switch-poe-table", POE_COLUMNS, poe);

    renderKVList("switch-dns-detail", {
      dns_servers: (result.dns?.servers || []).join(", ") || "Not configured",
      domain_name: result.dns?.domain || "Not configured",
    });

    const snmp = result.snmp || {};
    renderKVList("switch-snmp-summary", {
      snmp_configured: snmp.enabled ? "Yes" : "No",
      communities: (snmp.summary?.communities || []).join(", ") || "—",
      locations: (snmp.summary?.locations || []).join(", ") || "—",
      contacts: (snmp.summary?.contacts || []).join(", ") || "—",
      trap_hosts: (snmp.summary?.hosts || []).join(", ") || "—",
    });
    renderTable("switch-snmp-table", [
      { label: "Raw Command", key: "command" },
    ], (snmp.raw_commands || []).map(command => ({ command })));

    const dhcp = result.dhcp || {};
    const snooping = dhcp.snooping || {};
    renderKVList("switch-dhcp-summary", {
      dhcp_snooping: snooping.enabled ? "Enabled" : "Disabled",
      snooping_vlans: (snooping.vlans || []).join(", ") || "—",
      option_82: snooping.option82_enabled ? "Enabled" : "Disabled",
      trusted_interfaces: (snooping.trusted_interfaces || []).join(", ") || "—",
      server_pools: dhcp.pools?.length ?? 0,
      relay_interfaces: dhcp.helper_addresses?.length ?? 0,
    });
    renderTable("switch-dhcp-pool-table", [
      { label: "Pool Name", key: "name" },
      { label: "Network", key: "network" },
      { label: "Mask", key: "mask" },
      { label: "Gateway", key: "gateway" },
      { label: "DNS Servers", key: "dns_servers" },
      { label: "Domain", key: "domain_name" },
      { label: "Lease", key: "lease" },
      { label: "Options", key: "options", value: row => (row.options || []).join("; ") },
    ], dhcp.pools || []);
    renderTable("switch-dhcp-helper-table", [
      { label: "Interface", key: "interface" },
      { label: "Relay / Helper Servers", key: "servers", value: row => (row.servers || []).join(", ") },
    ], dhcp.helper_addresses || []);
    const rateLimited = snooping.rate_limited_interfaces || [];
    const trustedRows = (snooping.trusted_interfaces || []).map(name => ({ interface: name, trusted: true, limit_pps: rateLimited.find(item => item.interface === name)?.limit_pps ?? "" }));
    const untrustedRateLimited = rateLimited.filter(item => !(snooping.trusted_interfaces || []).includes(item.interface)).map(item => ({ interface: item.interface, trusted: false, limit_pps: item.limit_pps }));
    renderTable("switch-dhcp-snooping-table", [
      { label: "Interface", key: "interface" },
      { label: "Trust State", key: "trusted", value: row => row.trusted ? "Trusted" : "Untrusted" },
      { label: "Rate Limit (pps)", key: "limit_pps" },
    ], [...trustedRows, ...untrustedRateLimited]);
  }

  // ---- Firewall dashboard (Mikrotik / Palo Alto) -- entirely separate
  // render path from renderResult() above, since a firewall result's
  // shape (zones/security_rules/nat_rules/ipsec_tunnels/findings, see
  // features/switch_analyzer/firewall_service.py) has no overlap with a
  // switch result's (interfaces/VLANs/port-channels/PoE/...). Reuses
  // the same renderTable/renderKVList/esc/display helpers above so both
  // dashboards look and behave identically even though their data is
  // unrelated. ----

  const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };

  const FIREWALL_TAB_ORDER = {
    "palo alto": [
      "interfaces", "port_mapping", "cdp_lldp", "routing", "pbf", "ipsec",
      "security", "nat", "address", "vlans", "dhcp", "zones", "zone_protection",
      "security_profiles", "management_profiles", "qos", "administrators",
    ],
    mikrotik: [
      "interfaces", "vlans", "port_mapping", "security", "nat", "qos",
      "zones", "routing", "address", "ipsec", "dhcp",
    ],
  };

  function layoutFirewallTabs(vendor) {
    const order = FIREWALL_TAB_ORDER[String(vendor || "").toLowerCase()] || FIREWALL_TAB_ORDER.mikrotik;
    const nav = document.getElementById("firewall-tabs");
    const allButtons = [...nav.querySelectorAll("button[data-tab]")];
    allButtons.forEach(btn => btn.classList.add("hidden"));
    order.forEach(tabName => {
      const btn = allButtons.find(item => item.dataset.tab === tabName);
      const pane = document.getElementById(`firewall-tab-${tabName}`);
      if (!btn || !pane) return;
      btn.classList.remove("hidden");
      nav.appendChild(btn);
    });
    // Land on the first tab in this vendor's order every time a new
    // result is rendered, rather than leaving whatever tab a previous
    // (possibly other-vendor) result had focused active but now hidden.
    const firstVisible = order.find(tabName => document.getElementById(`firewall-tab-${tabName}`));
    if (firstVisible) firewallTab(firstVisible);
  }

  function renderFirewallResult(result) {
    document.getElementById("firewall-source-name").textContent = result.hostname || "Firewall Analysis";
    document.getElementById("firewall-platform").textContent = `${result.vendor || "Unknown"} · ${result.device_type || "Firewall"}`;

    // Mikrotik (RouterOS) and Palo Alto (PAN-OS) dashboards share this
    // one set of table ids, but the underlying data is genuinely
    // different in kind, not just in value -- RouterOS has no zone/
    // link-state/management-profile/security-profile concept at all,
    // and its VLAN/chain vocabulary has no Palo Alto equivalent either.
    // Rather than showing the other vendor's columns permanently blank,
    // several tables below pick a distinct column set per vendor.
    const isMikrotik = String(result.vendor || "").toLowerCase() === "mikrotik";

    const cards = result.cards || {};
    const deviceInfo = result.device_info || {};
    const managementServices = result.management_services || [];
    const disabledServices = managementServices.filter(item => item.disabled).map(item => item.field);
    renderKVList("firewall-information", {
      hostname: result.hostname,
      vendor: result.vendor,
      ...(deviceInfo.mgmt_ip ? { management_ip: `${deviceInfo.mgmt_ip}${deviceInfo.mgmt_netmask ? " / " + deviceInfo.mgmt_netmask : ""}` } : {}),
      ...(deviceInfo.mgmt_gateway ? { management_gateway: deviceInfo.mgmt_gateway } : {}),
      ...(deviceInfo.domain ? { domain: deviceInfo.domain } : {}),
      ...(deviceInfo.timezone ? { timezone: deviceInfo.timezone } : {}),
      ...((result.dns_servers || []).length ? { dns_servers: result.dns_servers.join(", ") } : {}),
      ...((result.ntp_servers || []).length ? { ntp_servers: result.ntp_servers.join(", ") } : {}),
      total_interfaces: cards.total_interfaces ?? 0,
      total_zones: cards.total_zones ?? 0,
      total_security_rules: cards.total_security_rules ?? 0,
      total_nat_rules: cards.total_nat_rules ?? 0,
      total_ipsec_tunnels: cards.total_ipsec_tunnels ?? 0,
      total_findings: cards.total_findings ?? 0,
      high_severity_findings: cards.high_severity_findings ?? 0,
      panorama_enabled: result.panorama_enabled ? "Yes" : "No",
      ...(managementServices.length ? { admin_services_disabled: disabledServices.length ? disabledServices.join(", ") : "None" } : {}),
    });

    const findings = result.findings || [];
    document.getElementById("firewall-findings-empty").classList.toggle("hidden", findings.length > 0);
    renderTable("firewall-findings-table", [
      { label: "Severity", key: "severity", status: true, value: row => SEVERITY_LABEL[row.severity] || row.severity },
      { label: "Category", key: "category" },
      { label: "Finding", key: "title" },
      { label: "Detail", key: "detail" },
    ], findings);

    renderTable("firewall-interface-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Zone / Bridge", key: "zone" },
      { label: "IP Address", key: "ip_address" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Zone", key: "zone" },
      { label: "IP Address", key: "ip_address" },
      { label: "VLAN Tag", key: "tag" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.interfaces || []);

    renderTable("firewall-port-mapping-table", isMikrotik ? [
      { label: "Current Name", key: "name" },
      { label: "Default/Factory Name", key: "default_name" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Default/Factory Name", key: "default_name" },
      { label: "Zone", key: "zone" },
      { label: "Mode", key: "mode" },
      { label: "Link State", key: "link_state" },
      { label: "Management Profile", key: "management_profile" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.port_mapping || []);

    renderTable("firewall-cdp-lldp-table", [
      { label: "Interface", key: "interface" },
      { label: "LLDP Enabled", key: "lldp_enabled", value: row => row.lldp_enabled ? "Yes" : "No" },
    ], result.cdp_lldp || []);

    renderTable("firewall-vlan-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "VLAN ID", key: "vlan_id" },
      { label: "Parent Interface", key: "parent_interface" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "VLAN Interface", key: "vlan_interface" },
      { label: "Tag", key: "tag" },
      { label: "Member Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
    ], result.vlans || []);

    renderTable("firewall-security-profile-table", [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Rule Count", key: "rule_count" },
    ], result.security_profiles || []);

    const qos = result.qos;
    if (Array.isArray(qos)) {
      // Mikrotik: raw "/queue simple"/"/queue tree" lines (see
      // firewall_service.py's _mikrotik_qos_from_unhandled -- RouterOS
      // QoS has no dedicated model, this is its best-effort surfacing).
      document.getElementById("firewall-qos-summary").innerHTML = "";
      renderTable("firewall-qos-table", [
        { label: "Section", key: "section" },
        { label: "Command", key: "line" },
      ], qos || []);
    } else {
      renderKVList("firewall-qos-summary", {
        qos_profiles: (qos?.profiles || []).join(", ") || "None configured",
      });
      renderTable("firewall-qos-table", [
        { label: "Interface", key: "interface" },
        { label: "QoS Profile", key: "profile" },
      ], qos?.interface_bindings || []);
    }

    renderTable("firewall-zone-table", isMikrotik ? [
      { label: "Zone", key: "name" },
      { label: "Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
    ] : [
      { label: "Zone", key: "name" },
      { label: "Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
      { label: "Zone Protection Profile", key: "zone_protection_profile" },
    ], result.zones || []);

    renderTable("firewall-management-profile-table", [
      { label: "Name", key: "name" },
      { label: "Permitted Services", key: "permitted_services", value: row => (row.permitted_services || []).join(", ") || "None" },
    ], result.management_profiles || []);

    renderTable("firewall-zone-protection-table", [
      { label: "Name", key: "name" },
      { label: "Protection Types", key: "protection_types", value: row => (row.protection_types || []).join(", ") || "None" },
    ], result.zone_protection_profiles || []);

    renderTable("firewall-pbf-table", [
      { label: "Name", key: "name" },
      { label: "From Zone", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Application", key: "application", value: row => (row.application || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Egress Interface", key: "egress_interface" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Monitor Profile", key: "monitor_profile" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.pbf_rules || []);

    renderTable("firewall-administrator-table", [
      { label: "Username", key: "username" },
      { label: "Role", key: "role" },
    ], result.administrators || []);

    renderTable("firewall-security-table", isMikrotik ? [
      { label: "Chain", key: "chain" },
      { label: "Name", key: "name" },
      { label: "In Interface / List", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "Out Interface / List", key: "to_zone", value: row => (row.to_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Protocol / Port", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Action", key: "action" },
      { label: "Log", key: "log", value: row => row.log ? "Yes" : "No" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "From Zone", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "To Zone", key: "to_zone", value: row => (row.to_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Security Profile", key: "profile_setting", value: row => Object.entries(row.profile_setting || {}).map(([type, names]) => `${type}:${names.join("/")}`).join(", ") },
      { label: "Action", key: "action" },
      { label: "Log", key: "log", value: row => row.log ? "Yes" : "No" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.security_rules || []);

    renderTable("firewall-nat-table", isMikrotik ? [
      { label: "Chain", key: "chain" },
      { label: "Name", key: "name" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service / Port", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Translated Address", key: "translated_address" },
      { label: "Translated Port", key: "translated_port" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Translated Address", key: "translated_address" },
      { label: "Translated Port", key: "translated_port" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.nat_rules || []);

    // Per-virtual-router routing detail -- static vs dynamic, and which
    // dynamic protocol (BGP/OSPF/RIP -- PAN-OS has no EIGRP support at
    // all, that's Cisco-proprietary) with its router-id/AS/area, so
    // "is this VR static, dynamic, or a mix" is answered directly
    // instead of just listing which protocols are technically enabled.
    const routingEntries = result.routing_protocols || [];
    if (routingEntries.length) {
      const summary = {};
      routingEntries.forEach(vr => {
        const parts = [vr.routing_type || "None configured"];
        if (vr.bgp) {
          const bgpDetail = [
            vr.bgp_as_number ? `AS ${vr.bgp_as_number}` : "",
            vr.bgp_router_id ? `Router ID ${vr.bgp_router_id}` : "",
          ].filter(Boolean).join(", ");
          parts.push(`BGP${bgpDetail ? ` (${bgpDetail})` : ""}`);
        }
        if (vr.ospf) {
          const ospfDetail = [
            vr.ospf_router_id ? `Router ID ${vr.ospf_router_id}` : "",
            (vr.ospf_area_ids || []).length ? `Area ${vr.ospf_area_ids.join("/")}` : "",
          ].filter(Boolean).join(", ");
          parts.push(`OSPF${ospfDetail ? ` (${ospfDetail})` : ""}`);
        }
        if (vr.rip) parts.push("RIP");
        const routeCount = vr.static_route_count || 0;
        if (routeCount) parts.push(`${routeCount} static route${routeCount === 1 ? "" : "s"}`);
        summary[vr.virtual_router] = parts.join(" — ");
      });
      renderKVList("firewall-routing-summary", summary);
    } else {
      document.getElementById("firewall-routing-summary").innerHTML = "";
    }

    const routingTypeByVr = {};
    (result.routing_protocols || []).forEach(vr => { routingTypeByVr[vr.virtual_router] = vr.routing_type; });

    renderTable("firewall-route-table", isMikrotik ? [
      { label: "Destination", key: "destination" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Metric", key: "metric" },
    ] : [
      { label: "Destination", key: "destination" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Metric", key: "metric" },
      { label: "Virtual Router", key: "virtual_router" },
      { label: "VR Routing Type", key: "routing_type", value: row => routingTypeByVr[row.virtual_router] || "" },
    ], result.static_routes || []);

    renderTable("firewall-address-table", [
      { label: "Name", key: "name" },
      { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
    ], result.address_objects || []);

    // Palo Alto-only concept (named service/App-ID objects) -- RouterOS
    // rules match raw ports/addresses directly, so this section is
    // hidden entirely for Mikrotik rather than showing two tables that
    // can never have data.
    document.getElementById("firewall-service-object-section").hidden = isMikrotik;
    if (!isMikrotik) {
      renderTable("firewall-service-object-table", [
        { label: "Service / Service Group", key: "name" },
        { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
      ], result.service_objects || []);

      renderTable("firewall-application-group-table", [
        { label: "Application Group", key: "name" },
        { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
      ], result.application_groups || []);
    }

    renderTable("firewall-ipsec-table", [
      { label: "Name", key: "name" },
      { label: "Peer Address", key: "peer_address" },
      { label: "DH Group", key: "dh_group" },
      { label: "IKE Encryption", key: "ike_encryption" },
      { label: "IKE Hash", key: "ike_hash" },
      { label: "ESP Encryption", key: "esp_encryption" },
      { label: "ESP Authentication", key: "esp_authentication" },
      { label: "Proxy ID Local", key: "proxy_id_local" },
      { label: "Proxy ID Remote", key: "proxy_id_remote" },
    ], result.ipsec_tunnels || []);

    const dhcp = result.dhcp || {};
    renderKVList("firewall-dhcp-summary", {
      dns_servers: (result.dns_servers || []).join(", ") || "—",
      ntp_servers: (result.ntp_servers || []).join(", ") || "—",
    });
    renderTable("firewall-dhcp-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "Interface", key: "interface" },
      { label: "Address Pool", key: "address_pool" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Interface", key: "interface" },
      { label: "Address Pool", key: "address_pool" },
      { label: "Gateway", key: "gateway" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], dhcp.servers || []);

    layoutFirewallTabs(result.vendor);
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(form);
    window.NES.setLoading(button, true, "Analyzing...");
    try {
      const response = await fetch("/switch-analyzer/api/analyze", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Analysis failed.");
      empty.classList.add("hidden");
      lastResult = payload.result;
      if (payload.result.device_type === "Firewall") {
        resultPanel.classList.add("hidden");
        firewallResultPanel.classList.remove("hidden");
        renderFirewallResult(payload.result);
        window.NES.toast("Firewall analysis completed.");
      } else {
        firewallResultPanel.classList.add("hidden");
        resultPanel.classList.remove("hidden");
        renderResult(payload.result);
        window.NES.toast("Switch analysis completed.");
      }
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(button, false);
    }
  });

  exportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastResult) return;
    window.NES.setLoading(exportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results: [lastResult] }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(exportButton, false);
    }
  });

  firewallExportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastResult) return;
    window.NES.setLoading(firewallExportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results: [lastResult] }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(firewallExportButton, false);
    }
  });

  // --- Compare Two Devices (old Cisco/Aruba vs. new Huawei draft) ---
  const compareForm = document.getElementById("switch-compare-form");
  const compareButton = document.getElementById("switch-compare-button");
  const compareEmpty = document.getElementById("switch-compare-empty");
  const compareResultPanel = document.getElementById("switch-compare-result");
  const compareExportButton = document.getElementById("switch-compare-export-button");
  let lastCompare = null; // { result_a, result_b, comparison }

  function renderDiffTable(id, diff) {
    const rows = [
      ...(diff?.only_a || []).map(value => ({ value, a: "Only Device A", b: "" })),
      ...(diff?.only_b || []).map(value => ({ value, a: "", b: "Only Device B" })),
      ...(diff?.both || []).map(value => ({ value, a: "Both", b: "Both" })),
    ];
    renderTable(id, [
      { label: "Value", key: "value" },
      { label: "Device A", key: "a" },
      { label: "Device B", key: "b" },
    ], rows);
  }

  // The diff tables above only cover VLANs/routes/DNS servers — this
  // fills in every OTHER parsed table (interfaces, port-channels,
  // transceivers, vPC/M-LAG, PoE, neighbors) for both devices side by
  // side, so the full detail is visible on the page without needing
  // the Excel export just to see it.
  function renderCompareDeviceTables(resultA, resultB) {
    renderTable("switch-compare-interfaces-a", INTERFACE_COLUMNS, resultA.interfaces || []);
    renderTable("switch-compare-interfaces-b", INTERFACE_COLUMNS, resultB.interfaces || []);

    renderTable("switch-compare-portchannels-a", PORTCHANNEL_COLUMNS, resultA.port_channels || []);
    renderTable("switch-compare-portchannels-b", PORTCHANNEL_COLUMNS, resultB.port_channels || []);

    renderTable("switch-compare-transceivers-a", TRANSCEIVER_COLUMNS, resultA.transceivers || []);
    renderTable("switch-compare-transceivers-b", TRANSCEIVER_COLUMNS, resultB.transceivers || []);

    renderTable("switch-compare-vpcmlag-a", VPCMLAG_MEMBER_COLUMNS, resultA.vpc_mlag?.members || []);
    renderTable("switch-compare-vpcmlag-b", VPCMLAG_MEMBER_COLUMNS, resultB.vpc_mlag?.members || []);
    const vpcNote = document.getElementById("switch-compare-vpcmlag-note");
    const sourceA = resultA.vpc_mlag?.source, sourceB = resultB.vpc_mlag?.source;
    if (sourceA === "config" || sourceB === "config") {
      const who = sourceA === "config" && sourceB === "config" ? "Both devices"
        : sourceA === "config" ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      vpcNote.textContent = `${who} show vPC/M-LAG configuration only, no live status — no "show vpc brief" was ever run (expected for a draft that isn't deployed/active yet). Members are shown as "configured (not active)".`;
      vpcNote.classList.remove("hidden");
    } else {
      vpcNote.classList.add("hidden");
    }

    renderTable("switch-compare-poe-a", POE_COLUMNS, resultA.poe || []);
    renderTable("switch-compare-poe-b", POE_COLUMNS, resultB.poe || []);
    const poeNote = document.getElementById("switch-compare-poe-note");
    const poeFromCdpA = (resultA.poe || []).length > 0 && resultA.poe.every(item => item.source === "cdp-detail");
    const poeFromCdpB = (resultB.poe || []).length > 0 && resultB.poe.every(item => item.source === "cdp-detail");
    const poeFromConfigA = (resultA.poe || []).length > 0 && resultA.poe.every(item => item.source === "config (poe enable)");
    const poeFromConfigB = (resultB.poe || []).length > 0 && resultB.poe.every(item => item.source === "config (poe enable)");
    if (poeFromCdpA || poeFromCdpB) {
      const who = poeFromCdpA && poeFromCdpB ? "Both devices"
        : poeFromCdpA ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      poeNote.textContent = `${who} never ran a live PoE show command — power draw shown is each connected device's own reported figure from "show cdp neighbors detail" instead.`;
      poeNote.classList.remove("hidden");
    } else if (poeFromConfigA || poeFromConfigB) {
      const who = poeFromConfigA && poeFromConfigB ? "Both devices"
        : poeFromConfigA ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      poeNote.textContent = `${who} never ran a live PoE show command — rows shown are just which ports are configured with "poe enable", not a live power reading (expected for a draft with nothing plugged in yet).`;
      poeNote.classList.remove("hidden");
    } else {
      poeNote.classList.add("hidden");
    }

    renderTable("switch-compare-neighbors-a", NEIGHBOR_COLUMNS, resultA.neighbors || []);
    renderTable("switch-compare-neighbors-b", NEIGHBOR_COLUMNS, resultB.neighbors || []);
  }

  function renderCompareResult(payload) {
    const { result_a, result_b, comparison } = payload;
    document.getElementById("switch-compare-title").textContent =
      `${result_a.hostname || "Device A"} vs. ${result_b.hostname || "Device B"}`;

    const deviceA = comparison.device_a || {};
    const deviceB = comparison.device_b || {};
    const fieldLabels = [
      ["hostname", "Hostname"], ["vendor", "Vendor"], ["model", "Model"],
      ["os_version", "OS Version"], ["stack_mode", "Stack Mode"],
      ["stack_member_count", "Stack Member Count"],
      ["total_interfaces", "Total Interfaces"], ["interfaces_up", "Interfaces Up"],
      ["interfaces_down", "Interfaces Down"], ["total_vlans", "Total VLANs"],
      ["total_routes", "Total Routes"], ["neighbor_count", "Neighbor Count"],
      ["port_channel_count", "Port-Channel Count"], ["transceiver_count", "Transceiver Count"],
      ["poe_port_count", "PoE Port Count"],
      ["has_custom_routing", "Has PBR / SLA-Track / NQA?"],
    ];
    const formatCompareValue = (key, value) => (key === "has_custom_routing" ? (value ? "Yes" : "No") : value);
    renderTable("switch-compare-devices-table", [
      { label: "Field", key: "field" },
      { label: "Device A", key: "a" },
      { label: "Device B", key: "b" },
    ], fieldLabels.map(([key, label]) => ({
      field: label,
      a: formatCompareValue(key, deviceA[key]),
      b: formatCompareValue(key, deviceB[key]),
    })));

    renderDiffTable("switch-compare-vlans-table", comparison.vlans);
    renderDiffTable("switch-compare-routes-table", comparison.routes);
    renderDiffTable("switch-compare-dns-table", comparison.dns_servers);

    const pbrA = comparison.pbr?.a || {};
    const pbrB = comparison.pbr?.b || {};
    document.getElementById("switch-compare-pbr-eem-note").classList.toggle(
      "hidden",
      !((pbrA.eem_dynamic_pbr || []).length || (pbrB.eem_dynamic_pbr || []).length),
    );
    renderPbrTables({
      sla: "switch-compare-pbr-sla-a", track: "switch-compare-pbr-track-a",
      policy: "switch-compare-pbr-policy-a", binding: "switch-compare-pbr-binding-a",
      eem: "switch-compare-pbr-eem-a",
    }, pbrA);
    renderPbrTables({
      sla: "switch-compare-pbr-sla-b", track: "switch-compare-pbr-track-b",
      policy: "switch-compare-pbr-policy-b", binding: "switch-compare-pbr-binding-b",
      eem: "switch-compare-pbr-eem-b",
    }, pbrB);

    renderCompareDeviceTables(result_a, result_b);

    compareEmpty.classList.add("hidden");
    compareResultPanel.classList.remove("hidden");
  }

  compareForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(compareForm);
    window.NES.setLoading(compareButton, true, "Comparing...");
    try {
      const response = await fetch("/switch-analyzer/api/compare", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Comparison failed.");
      lastCompare = payload;
      renderCompareResult(payload);
      window.NES.toast("Device comparison completed.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareButton, false);
    }
  });

  compareExportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastCompare) return;
    window.NES.setLoading(compareExportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/compare/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(lastCompare),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Comparison Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareExportButton, false);
    }
  });

  // --- Sizing Assessment (batch: analyze N files, roll up into one
  // port/PoE/VLAN/redundancy summary) ---
  const sizingFilesInput = document.getElementById("switch-sizing-files");
  const sizingFilesFallback = "Cisco, Huawei, or Aruba running-configs — one file per device";
  sizingFilesInput?.addEventListener("change", () => {
    const count = sizingFilesInput.files.length;
    document.getElementById("switch-sizing-files-label").textContent =
      count ? `${count} file${count === 1 ? "" : "s"} selected` : sizingFilesFallback;
    document.getElementById("clear-switch-sizing-files")?.classList.toggle("hidden", !count);
  });
  document.getElementById("clear-switch-sizing-files")?.addEventListener("click", () => {
    sizingFilesInput.value = "";
    sizingFilesInput.dispatchEvent(new Event("change"));
  });

  const sizingForm = document.getElementById("switch-sizing-form");
  const sizingButton = document.getElementById("switch-sizing-button");
  const sizingEmpty = document.getElementById("switch-sizing-empty");
  const sizingResultPanel = document.getElementById("switch-sizing-result");
  const sizingExportButton = document.getElementById("switch-sizing-export-button");
  let lastSizingResults = null; // the analyzed results array, reused for export

  function renderSizingResult(summary, results) {
    const { devices, totals } = summary;
    document.getElementById("switch-sizing-subtitle").textContent =
      `${totals.device_count} device${totals.device_count === 1 ? "" : "s"}`;

    renderKVList("switch-sizing-totals", {
      physical_ports: `${totals.physical_port_count} total (${totals.physical_ports_up} up / ${totals.physical_ports_down} down)`,
      trunk_ports: totals.trunk_port_count,
      port_channels_eth_trunks: totals.port_channel_count,
      poe: `${totals.poe_port_count} port(s), ${totals.poe_total_watts} W total`,
      transceivers: totals.transceiver_count,
      unique_vlans_across_batch: totals.unique_vlan_count,
      static_routes: totals.static_route_count,
      devices_with_ospf: totals.ospf_device_count,
      devices_with_vpc_mlag: totals.vpc_mlag_device_count,
      hsrp_vrrp_svis: totals.hsrp_vrrp_svi_count,
      stacked_devices: totals.stacked_device_count,
    });

    // Group devices by Vendor + Model (product/PID) so a replacement quote
    // can be broken down by exactly what to reorder, not just how many
    // devices are in the batch overall.
    const deviceTypeCounts = new Map();
    for (const device of devices) {
      const vendor = device.vendor || "Unknown";
      const model = device.model || "Unknown";
      const key = vendor + "|" + model;
      const existing = deviceTypeCounts.get(key);
      if (existing) existing.total += 1;
      else deviceTypeCounts.set(key, { vendor, model, total: 1 });
    }
    const deviceTypeRows = Array.from(deviceTypeCounts.values())
      .sort((a, b) => b.total - a.total || a.vendor.localeCompare(b.vendor) || a.model.localeCompare(b.model));
    renderTable("switch-sizing-devicetypes-table", [
      { label: "Vendor", key: "vendor" },
      { label: "Model", key: "model" },
      { label: "Total", key: "total" },
    ], deviceTypeRows);

    const portTypeRows = Object.entries(totals.port_type_totals || {}).map(([type, count]) => ({ type, count }));
    renderTable("switch-sizing-porttypes-table", [
      { label: "Port Type", key: "type" },
      { label: "Count", key: "count" },
    ], portTypeRows);

    // Broken down by Type + Vendor Part Number, not just Type — two
    // transceivers reported under the same media class ("1000BaseSX
    // SFP") can still be different orderable parts (a genuine Cisco
    // GLC-SX-MMD vs. a third-party/compatible optic with its own vendor
    // code), so the part number is what a reviewer actually needs to
    // know precisely what to buy.
    renderTable("switch-sizing-transceivertypes-table", [
      { label: "Transceiver Type", key: "type" },
      { label: "Vendor Part Number", key: "vendor_part_number" },
      { label: "Count", key: "count" },
    ], totals.transceiver_part_totals || []);

    renderTable("switch-sizing-devices-table", [
      { label: "Hostname", key: "hostname" },
      { label: "Vendor", key: "vendor" },
      { label: "Model", key: "model" },
      { label: "Serial Number", key: "serial_number" },
      { label: "OS Version", key: "os_version" },
      { label: "Physical Ports", key: "physical_port_count" },
      { label: "Ports Up", key: "physical_ports_up" },
      { label: "Ports Down", key: "physical_ports_down" },
      { label: "Trunk Ports", key: "trunk_port_count" },
      { label: "Port-Channels", key: "port_channel_count" },
      { label: "PoE Ports", key: "poe_port_count" },
      { label: "PoE (W)", key: "poe_total_watts" },
      { label: "Transceivers", key: "transceiver_count" },
      { label: "VLANs", key: "vlan_count" },
      { label: "Routes", key: "static_route_count" },
      { label: "OSPF", key: "ospf_configured", value: row => row.ospf_configured ? "Yes" : "No" },
      { label: "vPC/M-LAG", key: "vpc_mlag_configured", value: row => row.vpc_mlag_configured ? `Yes (${row.vpc_mlag_source})` : "No" },
      { label: "HSRP/VRRP SVIs", key: "hsrp_vrrp_svi_count" },
      { label: "Stack", key: "stack_mode", value: row => row.stack_member_count > 1 ? `${row.stack_mode} (${row.stack_member_count})` : row.stack_mode },
    ], devices);

    sizingEmpty.classList.add("hidden");
    sizingResultPanel.classList.remove("hidden");
  }

  sizingForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const files = Array.from(sizingFilesInput.files || []);
    if (!files.length) {
      window.NES.toast("Select at least one switch config file.", "error");
      return;
    }
    const vendor = document.getElementById("switch-sizing-vendor").value;

    window.NES.setLoading(sizingButton, true, `Analyzing 0/${files.length}...`);
    try {
      // Reuses the same per-file /api/analyze endpoint the Single
      // Device form already calls — sequential rather than parallel so
      // the button can show real progress on a large batch and so one
      // bad file's error message clearly names which file it was.
      const results = [];
      for (let index = 0; index < files.length; index += 1) {
        const formData = new FormData();
        formData.append("config_file", files[index]);
        formData.append("vendor", vendor);
        window.NES.setLoading(sizingButton, true, `Analyzing ${index + 1}/${files.length}...`);
        const response = await fetch("/switch-analyzer/api/analyze", { method: "POST", body: formData });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(`${files[index].name}: ${payload.error || "Analysis failed."}`);
        results.push(payload.result);
      }

      const sizingResponse = await fetch("/switch-analyzer/api/sizing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results }),
      });
      const sizingPayload = await sizingResponse.json();
      if (!sizingResponse.ok || !sizingPayload.ok) throw new Error(sizingPayload.error || "Sizing summary failed.");

      lastSizingResults = results;
      renderSizingResult(sizingPayload.summary, results);
      window.NES.toast(`Sizing assessment built for ${results.length} device(s).`);
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(sizingButton, false);
    }
  });

  sizingExportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastSizingResults) return;
    window.NES.setLoading(sizingExportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results: lastSizingResults }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(sizingExportButton, false);
    }
  });
})();
