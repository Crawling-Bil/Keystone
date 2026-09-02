(() => {
  const form = document.getElementById("switch-form");
  if (!form) return;

  const configFile = document.getElementById("switch-config-file");
  const button = document.getElementById("switch-analyze-button");
  const empty = document.getElementById("switch-empty");
  const resultPanel = document.getElementById("switch-result");
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

    renderKVList("switch-information", {
      hostname: result.hostname,
      vendor: result.vendor,
      os_version: result.os_version?.os_version || "—",
      model: result.os_version?.model || "—",
      default_gateway: result.routing_protocols?.default_gateway || "—",
      total_interfaces: result.cards?.total_interfaces ?? 0,
      total_vlans: result.cards?.total_vlans ?? 0,
      total_routes: result.cards?.total_routes ?? 0,
    });

    renderKVList("switch-dns-summary", {
      dns_servers: (result.dns?.servers || []).join(", ") || "—",
      domain_name: result.dns?.domain || "—",
    });

    document.getElementById("switch-interface-count-label").textContent = `${(result.interfaces || []).length} interfaces`;
    renderTable("switch-interface-table", [
      { label: "Name", key: "name" },
      { label: "Status", key: "status", status: true },
      { label: "Protocol", key: "protocol" },
      { label: "Mode", key: "mode" },
      { label: "VLAN", key: "vlan" },
      { label: "IP Address", key: "ip_address" },
      { label: "Port Security", key: "port_security" },
      { label: "Description", key: "description" },
    ], result.interfaces || []);

    renderTable("switch-route-table", [
      { label: "Destination", key: "destination" },
      { label: "Mask", key: "mask" },
      { label: "Next Hop", key: "next_hop" },
      { label: "Admin Distance", key: "distance" },
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

    renderTable("switch-vlan-table", [
      { label: "VLAN ID", key: "vlan_id" },
      { label: "Name", key: "name" },
    ], result.vlans || []);

    const neighbors = result.neighbors || [];
    document.getElementById("switch-neighbors-empty").classList.toggle("hidden", neighbors.length > 0);
    renderTable("switch-neighbor-table", [
      { label: "Protocol", key: "protocol" },
      { label: "Neighbor", key: "neighbor_id" },
      { label: "Local Interface", key: "local_interface" },
      { label: "Remote Interface", key: "remote_interface" },
      { label: "Platform", key: "platform" },
    ], neighbors);

    const portChannels = result.port_channels || [];
    document.getElementById("switch-portchannel-empty").classList.toggle("hidden", portChannels.length > 0);
    renderTable("switch-portchannel-table", [
      { label: "Name", key: "name" },
      { label: "Protocol", key: "protocol" },
      { label: "Status", key: "status" },
      { label: "Member Ports", key: "members" },
    ], portChannels);

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
      resultPanel.classList.remove("hidden");
      renderResult(payload.result);
      window.NES.toast("Switch analysis completed.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(button, false);
    }
  });
})();
