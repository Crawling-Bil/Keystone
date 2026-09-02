(() => {
  const form = document.getElementById("wireless-form");
  if (!form) return;
  const configFile = document.getElementById("wireless-config-file");
  const inventoryFile = document.getElementById("inventory-file");
  const button = document.getElementById("analyze-button");
  const empty = document.getElementById("wireless-empty");
  const resultPanel = document.getElementById("wireless-result");
  const esc = value => window.NES.escape(value ?? "");
  const display = value => Array.isArray(value) ? value.join("\n") : (value ?? "");
  const formatKey = key => String(key).replaceAll("_", " ").replace(/\b\w/g, value => value.toUpperCase());

  function setFile(input, labelId, clearId, fallback) {
    document.getElementById(labelId).textContent = input.files[0]?.name || fallback;
    document.getElementById(clearId)?.classList.toggle("hidden", !input.files.length);
    input.closest(".drop-zone")?.classList.toggle("has-file", Boolean(input.files.length));
  }
  configFile.addEventListener("change", () => setFile(configFile, "wireless-file-label", "clear-wireless-file", "TXT, CFG, or terminal capture"));
  inventoryFile.addEventListener("change", () => setFile(inventoryFile, "inventory-file-label", "clear-inventory-file", "Huawei AP Info, AP Master, CSV or XLSX"));
  document.getElementById("clear-wireless-file").addEventListener("click", () => { configFile.value = ""; setFile(configFile,"wireless-file-label","clear-wireless-file","TXT, CFG, or terminal capture"); });
  document.getElementById("clear-inventory-file").addEventListener("click", () => { inventoryFile.value = ""; setFile(inventoryFile,"inventory-file-label","clear-inventory-file","Huawei AP Info, AP Master, CSV or XLSX"); });

  document.querySelectorAll(".wireless-mode-card").forEach(card => card.addEventListener("click", () => {
    const hasWork = Boolean(configFile.files.length || inventoryFile.files.length || resultPanel && !resultPanel.classList.contains("hidden"));
    if (card.dataset.url) {
      if (hasWork && !window.confirm("Switch workspace? Current Existing Deployment input or result will remain on this page but unsaved browser selections may be lost.")) return;
      window.location.href = card.dataset.url;
      return;
    }
    if (card.classList.contains("active")) return;
    if (hasWork && !window.confirm("Switch Wireless Center mode? Unsaved file selections and current view may be cleared.")) return;
    document.querySelectorAll(".wireless-mode-card").forEach(item => item.classList.toggle("active", item === card));
    document.getElementById("deployment-mode").value = card.dataset.mode;
    document.getElementById("master-builder")?.classList.add("hidden");
    document.getElementById("inventory-validator")?.classList.add("hidden");
  }));

  const masterVendor = document.getElementById("master-vendor");
  const validationVendor = document.getElementById("validation-vendor");
  function updateMasterPreview() {
    const parts = [document.getElementById("master-site").value.trim(), document.getElementById("master-floor").value.trim(), document.getElementById("master-prefix").value.trim() || "AP", "001"].filter(Boolean);
    document.getElementById("naming-preview").value = parts.join("-");
    const cisco = masterVendor.value === "Cisco";
    document.getElementById("vendor-fields-note").textContent = cisco ? "Cisco template includes Site Tag, Policy Tag, and RF Tag." : "Huawei template includes AP Group and Regulatory Domain.";
    validationVendor.value = masterVendor.value;
  }
  [masterVendor, ...["master-site","master-floor","master-prefix"].map(id => document.getElementById(id))].forEach(el => el.addEventListener("input", updateMasterPreview));
  masterVendor.addEventListener("change", updateMasterPreview);
  updateMasterPreview();
  document.getElementById("download-master").addEventListener("click", () => {
    const params = new URLSearchParams({
      quantity: document.getElementById("master-quantity").value || "0",
      site: document.getElementById("master-site").value,
      floor: document.getElementById("master-floor").value,
      prefix: document.getElementById("master-prefix").value || "AP",
    });
    window.location.href = `/wireless/template/${masterVendor.value}?${params}`;
  });

  const validationForm = document.getElementById("inventory-validation-form");
  const validationFile = document.getElementById("validation-file");
  validationFile.addEventListener("change", () => { document.getElementById("validation-file-label").textContent = validationFile.files[0]?.name || "CSV or XLSX"; });
  document.getElementById("clear-validation-file").addEventListener("click", () => { validationFile.value=""; document.getElementById("validation-file-label").textContent="CSV or XLSX"; document.getElementById("inventory-validation-result").classList.add("hidden"); });
  validationForm.addEventListener("submit", async event => {
    event.preventDefault();
    const validateButton = document.getElementById("validate-inventory-button");
    window.NES.setLoading(validateButton, true, "Validating...");
    try {
      const response = await fetch("/wireless/api/validate-inventory", {method:"POST", body:new FormData(validationForm)});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Validation failed.");
      const r = payload.result, s = r.summary, box = document.getElementById("inventory-validation-result");
      box.innerHTML = `<header><strong>${esc(r.vendor)} AP Master</strong><span class="cell-status">${s.valid ? "VALID" : "REVIEW REQUIRED"}</span></header>
        <div class="validation-metrics"><div><span>Records</span><strong>${s.total_records}</strong></div><div><span>Critical</span><strong>${s.critical}</strong></div><div><span>Warning</span><strong>${s.warning}</strong></div></div>
        ${(s.missing_identity_columns || []).length ? `<p class="muted-copy">Missing mandatory identity columns: ${esc(s.missing_identity_columns.join(", "))}</p>` : ""}
        ${(s.missing_vendor_columns || []).length ? `<p class="muted-copy">Recommended vendor columns not found: ${esc(s.missing_vendor_columns.join(", "))}</p>` : ""}
        <div class="validation-issues">${(r.issues || []).slice(0,50).map(i => `<div><strong>Row ${i.row} · ${esc(i.severity)}</strong> — ${esc(i.field)}: ${esc(i.message)}</div>`).join("") || "No row-level issues detected."}</div>`;
      box.classList.remove("hidden");
      window.NES.toast("AP master validation completed.");
    } catch (error) { window.NES.toast(error.message, "error"); }
    finally { window.NES.setLoading(validateButton, false); }
  });

  function renderTable(id, columns, rows) {
    const table = document.getElementById(id);
    const head = `<thead><tr>${columns.map(column => `<th>${esc(column.label)}</th>`).join("")}</tr></thead>`;
    const statusColumn = columns.find(column => column.status);
    const body = rows.length ? rows.map(row => {
      const rowStatus = statusColumn ? String(display(statusColumn.value ? statusColumn.value(row) : row[statusColumn.key])).toLowerCase() : "";
      const statusAttr = statusColumn ? ` data-row-status="${esc(rowStatus)}"` : "";
      return `<tr${statusAttr}>${columns.map(column => {
      let value = column.value ? column.value(row) : row[column.key]; value = display(value);
      if (column.validation) return `<td><span class="validation-state ${String(value).toLowerCase().replaceAll(" ","-")}">${esc(value)}</span></td>`;
      if (column.status) return `<td><span class="cell-status">${esc(value)}</span></td>`;
      if (column.config) {
        const lines = Array.isArray(row[column.key]) ? row[column.key] : String(value || "").split("\n").filter(Boolean);
        return `<td><details class="vap-config-preview"><summary>${esc(lines.length)} command${lines.length === 1 ? "" : "s"}</summary><code>${lines.length ? lines.map(esc).join("\n") : "No profile commands"}</code></details></td>`;
      }
      return `<td>${esc(value)}</td>`;
    }).join("")}</tr>`;
    }).join("") : `<tr><td colspan="${columns.length}">No data found.</td></tr>`;
    table.innerHTML = head + `<tbody>${body}</tbody>`;
  }

  function renderDeployment(validation) {
    const noData = !validation || !validation.summary;
    document.getElementById("deployment-empty").classList.toggle("hidden", !noData);
    document.getElementById("deployment-content").classList.toggle("hidden", noData);
    const asBuilt = document.getElementById("wireless-as-built");
    asBuilt.classList.toggle("hidden", noData);
    if (noData) return;
    const s = validation.summary;
    const metrics = [["Planned",s.planned],["Matched",s.matched],["Validated",s.validated],["Mismatch",s.mismatch],["Missing",s.missing],["Unexpected",s.unexpected]];
    document.getElementById("deployment-summary").innerHTML = metrics.map(([label,value]) => `<article><span>${label}</span><strong>${value || 0}</strong></article>`).join("");
    renderTable("deployment-table", [
      {label:"AP ID",key:"ap_id"},{label:"Planned AP",key:"ap_name"},{label:"Actual AP",key:"actual_ap_name"},
      {label:"Planned Serial",key:"serial_number"},{label:"Actual Serial",key:"actual_serial"},{label:"Planned MAC",key:"mac_address"},
      {label:"Actual MAC",key:"actual_mac"},{label:"Planned IP",key:"management_ip"},{label:"Actual IP",key:"actual_ip"},
      {label:"Actual Group/Tag",key:"actual_group"},{label:"Actual Status",key:"actual_status",status:true},{label:"Match By",key:"match_method"},
      {label:"Validation",key:"validation_status",validation:true},{label:"Mismatch Fields",key:"mismatch_fields"}
    ], validation.rows || []);
    renderTable("unexpected-table", [
      {label:"AP ID",key:"ap_id"},{label:"AP Name",key:"name"},{label:"Serial",key:"serial"},{label:"MAC",key:"mac"},
      {label:"IP",key:"ip"},{label:"Group/Tag",key:"group"},{label:"Status",key:"status",status:true}
    ], validation.unexpected_aps || []);
    document.getElementById("deployment-count-label").textContent = `${(validation.rows || []).length} planned AP records`;
  }

  function switchTab(tabName) {
    document.querySelectorAll("#wireless-tabs button").forEach(item => {
      const active = item.dataset.tab === tabName;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
      item.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll(".tab-content").forEach(item => item.classList.toggle("active", item.id === `tab-${tabName}`));
  }

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

  function renderDashboardChart(result) {
    const container = document.getElementById("wireless-dashboard-chart");
    if (!container) return;
    const status = result.status_counts || {};
    const vendor = (result.data?.vendor || "Unknown").toLowerCase();
    const cisco = vendor === "cisco";
    const rootStyles = getComputedStyle(document.documentElement);
    const themeColor = (token, fallback) => rootStyles.getPropertyValue(token).trim() || fallback;
    const chartGreen = themeColor("--green", "#73ca9c");
    const chartAmber = themeColor("--amber", "#efbc5c");
    const chartRed = themeColor("--red", "#ff7f85");
    const chartCyan = themeColor("--blue", "#24b4cd");
    const chartText = themeColor("--text", "#f1f7f9");
    const chartMuted = themeColor("--muted", "#a8bbc3");
    const chartBorder = themeColor("--border", "#2b4b59");

    // Cisco's join-summary table only ever reports Joined / Not Joined /
    // Not Present — there is no "Fault" state, so that bar would always
    // read zero and isn't meaningful here. "Not Joined" (idle) is the
    // actionable status for Cisco; "Not Present" just means the AP has
    // never shown up in the join table at all (often just unprovisioned
    // inventory), so it's a WARNING-level detail better left to the AP
    // Inventory tab than the headline dashboard.
    const bars = cisco ? [
      { label: "AP Joined", value: status.normal || 0, color: chartGreen, tab: "aps", filter: "Joined" },
      { label: "AP Not Joined", value: status.idle || 0, color: chartAmber, tab: "aps", filter: "Not Joined" },
      { label: "Total SSID", value: result.cards?.unique_ssids || 0, color: chartCyan, tab: "wlan", filter: "" },
      { label: "Total AP Group", value: result.cards?.ap_groups || 0, color: "#8aa4ff", tab: "groups", filter: "" },
    ] : [
      { label: "AP Normal", value: status.normal || 0, color: chartGreen, tab: "aps", filter: "Normal" },
      { label: "AP Standby", value: status.standby || 0, color: chartAmber, tab: "aps", filter: "Standby" },
      { label: "AP Fault", value: status.fault || 0, color: chartRed, tab: "aps", filter: "Fault" },
      { label: "Total SSID", value: result.cards?.unique_ssids || 0, color: chartCyan, tab: "wlan", filter: "" },
      { label: "Total AP Group", value: result.cards?.ap_groups || 0, color: "#8aa4ff", tab: "groups", filter: "" },
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
      return `<line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" stroke="${chartBorder}" stroke-width="1"></line>` +
        `<text x="${paddingLeft - 10}" y="${y + 4}" text-anchor="end" font-size="11" fill="${chartMuted}">${value}</text>`;
    }).join("");

    const barsMarkup = bars.map((bar, index) => {
      const x = paddingLeft + index * (barWidth + barGap);
      const barHeight = Math.max(2, (bar.value / niceMax) * plotHeight);
      const y = paddingTop + plotHeight - barHeight;
      const labelX = x + barWidth / 2;
      return `
        <g class="dash-bar" data-index="${index}" style="cursor:pointer">
          <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6" fill="${bar.color}"></rect>
          <text x="${labelX}" y="${y - 8}" text-anchor="middle" font-size="15" font-weight="700" fill="${chartText}">${bar.value}</text>
          <text x="${labelX}" y="${height - paddingBottom + 20}" text-anchor="middle" font-size="11" fill="${chartMuted}">${esc(bar.label)}</text>
        </g>`;
    }).join("");

    container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width:100%;height:100%;display:block;">${gridLines}${barsMarkup}</svg>`;

    container.querySelectorAll(".dash-bar").forEach(group => {
      group.addEventListener("click", () => {
        const bar = bars[Number(group.dataset.index)];
        if (!bar) return;
        switchTab(bar.tab);
        if (bar.tab === "aps" && bar.filter) filterTable("ap-table", bar.filter);
      });
    });
  }

  function renderAPDeviceSummary(summary) {
    const container = document.getElementById("ap-device-summary");
    if (!container) return;
    const data = summary || {summary:{},rows:[]};
    const metrics = [
      ["AP Models", data.summary?.models || 0],
      ["Software Versions", data.summary?.versions || 0],
      ["Mixed Models", data.summary?.mixed_models || 0],
      ["Unknown Version", data.summary?.unknown_versions || 0],
    ];
    const metricMarkup = `<div class="ap-summary-metrics">${metrics.map(([label,value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("")}</div>`;
    if (!(data.rows || []).length) {
      container.innerHTML = metricMarkup + `<div class="empty-state compact">No AP device data found. Upload AP runtime inventory to populate model and software details.</div>`;
      return;
    }
    const groups = data.rows.map(model => {
      const stateClass = String(model.consistency || "").toLowerCase().replaceAll(" ", "-");
      const versions = (model.versions || []).map(version => `<button type="button" class="ap-version-row" data-ap-model="${esc(model.model)}" data-ap-version="${esc(version.version)}"><span class="ap-version-name">${esc(version.version)}</span><strong>${esc(version.count)} AP</strong><small>${esc(version.status_text || "Status unavailable")}</small></button>`).join("");
      return `<section class="ap-model-group"><header><button type="button" data-ap-model="${esc(model.model)}"><span><strong>${esc(model.model)}</strong><small>${esc(model.version_count)} detected version · ${esc(model.total)} AP</small></span></button><span class="consistency-badge ${esc(stateClass)}">${esc(model.consistency)}</span></header><div>${versions}</div></section>`;
    }).join("");
    container.innerHTML = metricMarkup + `<div class="ap-model-list">${groups}</div>`;
  }

  function renderResult(result) {
    const data = result.data, assessment = result.assessment, status = result.status_counts;
    const vendor = data.vendor || "Unknown", cisco = vendor.toLowerCase() === "cisco";
    const deployment = result.deployment_validation || {};
    const cards = [
      ["Total AP", result.cards.total_aps], ["SSID", result.cards.unique_ssids], ["AP Groups", result.cards.ap_groups],
      [cisco ? "Joined" : "Normal", status.normal], ["Validated", deployment.summary?.validated || 0], ["Critical", assessment.summary.critical]
    ];
    document.getElementById("wireless-summary").innerHTML = cards.map(([label,value]) => `<article><span>${esc(label)}</span><strong>${esc(value)}</strong></article>`).join("");
    renderAPDeviceSummary(result.ap_device_summary);
    renderDashboardChart(result);
    document.getElementById("wireless-source-name").textContent = result.source_name;
    document.getElementById("wireless-platform").textContent = `${vendor} · ${data.wlc?.model || "Wireless Controller"} · ${String(result.deployment_mode || "assessment").replaceAll("_"," ")}`;
    document.getElementById("wireless-export").href = result.export_url;
    document.getElementById("wireless-as-built").href = result.as_built_url || "#";
    document.getElementById("wlc-information").innerHTML = Object.entries(data.wlc || {}).map(([key,value]) => `<div class="kv-row"><span>${esc(formatKey(key))}</span><strong>${esc(display(value))}</strong></div>`).join("");
    const statusLabels = cisco ? {normal:"Joined",idle:"Not Joined",standby:"Not Present",fault:"Fault",other:"Other"} : {normal:"Normal",idle:"Idle",standby:"Standby",fault:"Fault",other:"Other"};
    document.getElementById("status-breakdown").innerHTML = Object.entries(statusLabels).map(([key,label]) => `<div class="status-box"><span>${label}</span><strong>${status[key] || 0}</strong></div>`).join("");
    const health = String(assessment.summary.health || "HEALTHY");
    document.getElementById("assessment-summary").innerHTML = `<div class="assessment-banner ${health.toLowerCase()}"><div><strong>${esc(health)}</strong><span>${assessment.summary.warning || 0} warning · ${assessment.summary.critical || 0} critical</span></div><div><strong>${deployment.summary?.matched || assessment.summary.matched || 0} matched</strong><span>${deployment.summary?.missing || assessment.summary.unmatched || 0} missing/unmatched AP</span></div></div>`;
    renderDeployment(deployment);
    renderTable("ap-table", [
      {label:"AP ID",key:"ap_id"},{label:"AP Name",key:"name"},{label:"AP Group",key:"group"},{label:"Type ID",key:"type_id"},
      {label:"AP Model",key:"model"},{label:"MAC Address",key:"mac"},{label:"Serial Number",key:"serial"},{label:"IP Address",key:"ip"},
      {label:"Status",key:"status",status:true},{label:"OS Version",key:"version"},{label:"Inventory Match",key:"inventory_match"},{label:"Match Method",key:"match_method"}
    ], data.aps || []);
    document.getElementById("ap-count-label").textContent = `${(data.aps || []).length} AP records`;
    renderTable("wlan-table", [
      {label:"SSID",key:"ssid"},{label:"Security",key:"security"},
      {label:"Security Profile",key:"security_profile"},{label:"Authentication",key:"authentication_profile"},{label:"Traffic Profile",key:"traffic_profile"},
      {label:"VLAN",key:"vlan"},{label:"Forward Mode",key:"forward_mode"},
      {label:"Deployed VAP Profiles",key:"vap_profile_count"},{label:"VAP Profile Names",key:"vap_profiles"}
    ], result.ssid_catalog || []);
    const vapRows = result.vap_inventory || [];
    const vapMetrics = [
      ["Total VAP", vapRows.length],
      ["Site-specific", vapRows.filter(row => row.usage_scope === "Site-specific").length],
      ["Shared", vapRows.filter(row => row.usage_scope === "Shared across sites").length],
      ["Not mapped", vapRows.filter(row => row.deployment_status === "Not mapped").length],
    ];
    document.getElementById("vap-summary").innerHTML = vapMetrics.map(([label,value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join("");
    document.getElementById("vap-count-label").textContent = `${vapRows.length} VAP profiles`;
    renderTable("vap-table", [
      {label:"VAP Profile",key:"vap_profile"},{label:"Usage",key:"usage_scope",status:true},{label:"Mapping",key:"deployment_status"},
      {label:"SSID",key:"ssid"},{label:"SSID Profile",key:"ssid_profile"},{label:"Service VLAN",key:"service_vlan"},{label:"Effective VLAN",key:"effective_vlans"},
      {label:"Security",key:"security"},{label:"Security Profile",key:"security_profile"},{label:"Authentication Profile",key:"authentication_profile"},
      {label:"Traffic Profile",key:"traffic_profile"},{label:"Forward Mode",key:"forward_mode"},{label:"AP Group / Site",key:"ap_groups"},
      {label:"Site Count",key:"ap_group_count"},{label:"AP Count",key:"ap_count"},{label:"Radio",key:"radios"},{label:"WLAN ID",key:"wlan_ids"},
      {label:"Full VAP Config",key:"full_config",config:true}
    ], vapRows);
    renderTable("group-table", [
      {label:"AP Group / Tag",key:"ap_group"},{label:"AP Count",key:"ap_count"},{label:"Radio",key:"radio"},{label:"WLAN ID",key:"wlan_id"},
      {label:"SSID",key:"ssid"},{label:"VAP Profile",key:"vap_profile"},{label:"Security",key:"security"},{label:"Security Profile",key:"security_profile"},
      {label:"VLAN",key:"vlan"},{label:"Forward Mode",key:"forward_mode"}
    ], result.group_mapping || []);
    renderTable("profile-table", [
      {label:"AP ID",key:"ap_id"},{label:"AP Name",key:"name"},{label:"AP Group",key:"group"},{label:"AP System Profile",key:"ap_system_profile"},
      {label:"Location Profile",key:"location_profile"},{label:"WLAN Count",value:row => (row.wlan_mappings || []).length},
      {label:"SSID / VAP Mapping",value:row => (row.wlan_mappings || []).map(item => `Radio ${item.radio}: ${item.ssid} (${item.vap_profile})`).join(" | ")}
    ], result.profile_details || []);
    renderTable("user-table", [
      {label:"Username",key:"username"},{label:"Privilege",key:"privilege"},{label:"Service Type",key:"service_type"},
      {label:"State",key:"state",status:true},{label:"Configuration",value:row => row.config || row.configuration || ""}
    ], data.local_users || []);
    const findings = assessment.findings || [];
    document.getElementById("finding-list").innerHTML = findings.length ? findings.map(item => `<article class="finding-card"><span class="finding-severity ${esc(item.severity)}">${esc(item.severity)}</span><div><h4>${esc(item.title || item.category || "Finding")}</h4><div class="finding-meta">${esc([item.ap_id,item.ap_name,item.status].filter(Boolean).join(" · "))}</div><p>${esc(item.reason || item.description || "")}</p><p><strong>Recommendation:</strong> ${esc(item.recommendation || "Review the AP configuration and operational status.")}</p></div></article>`).join("") : `<div class="empty-state compact">No findings. Wireless assessment is healthy.</div>`;
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    window.NES.setLoading(button, true, "Analyzing...");
    try {
      const response = await fetch("/wireless/api/analyze", {method:"POST",body:new FormData(form)});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Analysis failed.");
      empty.classList.add("hidden"); resultPanel.classList.remove("hidden"); renderResult(payload.result); window.NES.toast("Wireless analysis completed.");
    } catch (error) { window.NES.toast(error.message,"error"); }
    finally { window.NES.setLoading(button,false); }
  });

  document.getElementById("wireless-tabs").addEventListener("click", event => {
    const tabButton = event.target.closest("button[data-tab]"); if (!tabButton) return;
    switchTab(tabButton.dataset.tab);
  });
  document.getElementById("wireless-tabs").addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = [...document.querySelectorAll("#wireless-tabs button[data-tab]")];
    const current = Math.max(0, tabs.indexOf(document.activeElement));
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    event.preventDefault();
    switchTab(tabs[next].dataset.tab);
    tabs[next].focus();
  });
  document.getElementById("ap-device-summary")?.addEventListener("click", event => {
    const trigger = event.target.closest("[data-ap-model]");
    if (!trigger) return;
    const model = String(trigger.dataset.apModel || "").toLowerCase();
    const version = String(trigger.dataset.apVersion || "").toLowerCase();
    switchTab("aps");
    const input = document.querySelector('[data-table-search="ap-table"]');
    if (input) input.value = trigger.dataset.apVersion ? `${trigger.dataset.apModel} · ${trigger.dataset.apVersion}` : trigger.dataset.apModel;
    document.querySelectorAll("#ap-table tbody tr").forEach(row => {
      const text = row.textContent.toLowerCase();
      row.style.display = text.includes(model) && (!version || text.includes(version)) ? "" : "none";
    });
  });
  document.addEventListener("input", event => {
    const input = event.target.closest("[data-table-search]"); if (!input) return;
    const table = document.getElementById(input.dataset.tableSearch), query = input.value.toLowerCase();
    let visible = 0, total = 0;
    table?.querySelectorAll("tbody tr").forEach(row => {
      total += 1;
      const matched = row.textContent.toLowerCase().includes(query);
      row.style.display = matched ? "" : "none";
      if (matched) visible += 1;
    });
    if (input.dataset.tableSearch === "vap-table") {
      document.getElementById("vap-count-label").textContent = visible
        ? `${visible} of ${total} VAP profiles`
        : "No matching VAP profiles — try profile, site, SSID, VLAN, or authentication.";
    }
  });
})();
