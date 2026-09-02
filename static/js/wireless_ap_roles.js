(() => {
  const form = document.getElementById("ap-role-form");
  if (!form) return;
  const esc = value => window.NES.escape(value ?? "");
  const aFile = document.getElementById("ap-role-a-file");
  const bFile = document.getElementById("ap-role-b-file");
  const allocationFile = document.getElementById("ap-role-allocation-file");
  const compareButton = document.getElementById("compare-ap-role-button");
  const resultPanel = document.getElementById("ap-role-result");
  const emptyPanel = document.getElementById("ap-role-empty");
  const overviewGroupFilter = document.getElementById("ap-role-overview-group-filter");
  const groupFilter = document.getElementById("ap-role-group-filter");
  const groupStatusFilter = document.getElementById("ap-role-group-status-filter");
  let currentRows = [];
  let currentGroupSummary = [];

  function setFile(input, labelId, clearId, fallback) {
    document.getElementById(labelId).textContent = input.files[0]?.name || fallback;
    document.getElementById(clearId).classList.toggle("hidden", !input.files.length);
    input.closest(".drop-zone")?.classList.toggle("has-file", Boolean(input.files.length));
  }

  const fileBindings = [
    [aFile, "ap-role-a-label", "clear-ap-role-a", "AP Info CSV/XLSX or display ap all TXT"],
    [bFile, "ap-role-b-label", "clear-ap-role-b", "AP Info CSV/XLSX or display ap all TXT"],
    [allocationFile, "ap-role-allocation-label", "clear-ap-role-allocation", "CSV or XLSX"],
  ];
  fileBindings.forEach(([input, label, clear, fallback]) => {
    input.addEventListener("change", () => setFile(input, label, clear, fallback));
    document.getElementById(clear).addEventListener("click", () => {
      input.value = "";
      setFile(input, label, clear, fallback);
    });
  });

  function switchTab(name) {
    document.querySelectorAll("#ap-role-tabs [data-ap-role-tab]").forEach(button => {
      const active = button.dataset.apRoleTab === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll(".ap-role-tab-content").forEach(panel => {
      panel.classList.toggle("active", panel.id === `ap-role-tab-${name}`);
    });
  }

  const tabs = document.getElementById("ap-role-tabs");
  tabs.addEventListener("click", event => {
    const button = event.target.closest("[data-ap-role-tab]");
    if (button) switchTab(button.dataset.apRoleTab);
  });
  tabs.addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const buttons = [...tabs.querySelectorAll("[data-ap-role-tab]")];
    const current = Math.max(0, buttons.indexOf(document.activeElement));
    const next = event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + buttons.length) % buttons.length;
    event.preventDefault();
    switchTab(buttons[next].dataset.apRoleTab);
    buttons[next].focus();
  });

  function slug(value) {
    return String(value || "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  }

  const stateHelp = {
    Normal: "AP terhubung ke WLC dan bekerja normal.",
    Standby: "AP dikenali oleh WLC cadangan dan siap mengambil alih.",
    Idle: "AP dikenal WLC tetapi belum terhubung atau belum pernah berkomunikasi.",
    Fault: "AP gagal terhubung atau melakukan registrasi ke WLC.",
    Missing: "AP tidak ditemukan pada inventory WLC ini.",
  };

  const groupStatusHelp = {
    Matched: "AP berada pada AP Group yang sama di Controller A dan Controller B.",
    "Group Mismatch": "AP berada pada AP Group yang berbeda antara Controller A dan Controller B.",
    "Peer Group Missing": "AP Group hanya tersedia pada salah satu WLC atau AP tidak ditemukan pada peer WLC.",
    Unassigned: "AP tidak memiliki AP Group pada kedua WLC.",
  };

  function badge(value, type = "status") {
    const label = value || "—";
    const help = type === "state" ? stateHelp[label] : type === "group-status" ? groupStatusHelp[label] : "";
    const description = help ? ` title="${esc(help)}" aria-label="${esc(`${label}: ${help}`)}"` : "";
    return `<span class="role-badge ${esc(type)} ${esc(slug(label))}"${description}>${esc(label)}</span>`;
  }

  const columns = [
    ["AP Name", row => esc(row.ap_name)],
    ["MAC", row => esc(row.mac), "mono"],
    ["Controller A State", row => badge(row.a_status, "state")],
    ["Controller B State", row => badge(row.b_status, "state")],
    ["Detected Role", row => badge(row.role, "role")],
    ["Expected", row => esc(row.expected_active || "—")],
    ["Allocation", row => badge(row.allocation_status, "allocation")],
    ["Severity", row => badge(row.severity, "severity")],
    ["Mapping Group", row => esc(row.mapping_group || "Unassigned")],
    ["Group Mapping", row => badge(row.group_status, "group-status")],
    ["Controller A / B Group", row => `${esc(row.a_group || "—")}<br><small>${esc(row.b_group || "—")}</small>`],
    ["Controller A / B Model", row => `${esc(row.a_model || "—")}<br><small>${esc(row.b_model || "—")}</small>`],
    ["Controller A / B Version", row => `${esc(row.a_version || "—")}<br><small>${esc(row.b_version || "—")}</small>`],
    ["Attribute Difference", row => (row.attribute_mismatches || []).map(esc).join(", ") || "—"],
    ["Matched By", row => esc(row.match_method)],
  ];

  const groupColumns = [
    ["AP Name", row => esc(row.ap_name)],
    ["MAC", row => esc(row.mac), "mono"],
    ["Mapping Group", row => esc(row.mapping_group || "Unassigned")],
    ["Controller A Group", row => esc(row.a_group || "—")],
    ["Controller B Group", row => esc(row.b_group || "—")],
    ["Group Mapping", row => badge(row.group_status, "group-status")],
    ["Active Controller", row => badge(row.active_wlc, "role")],
    ["Controller A State", row => badge(row.a_status, "state")],
    ["Controller B State", row => badge(row.b_status, "state")],
    ["Detected Role", row => badge(row.role, "role")],
    ["Severity", row => badge(row.severity, "severity")],
  ];

  function renderRoleTable(id, rows, tableColumns = columns, emptyMessage = "No AP records in this category.") {
    const table = document.getElementById(id);
    const body = rows.length ? rows.map(row => `<tr data-severity="${esc(slug(row.severity))}">${tableColumns.map(([label, value, className]) => `<td${className ? ` class="${className}"` : ""}>${value(row)}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${tableColumns.length}">${esc(emptyMessage)}</td></tr>`;
    table.innerHTML = `<thead><tr>${tableColumns.map(([label]) => `<th>${esc(label)}</th>`).join("")}</tr></thead><tbody>${body}</tbody>`;
  }

  function groupOptions() {
    return currentGroupSummary.map(item => item.group).filter(Boolean);
  }

  function populateGroupFilters() {
    const options = groupOptions().map(group => `<option value="${esc(group)}">${esc(group)}</option>`).join("");
    overviewGroupFilter.innerHTML = `<option value="">All AP Groups</option>${options}`;
    groupFilter.innerHTML = `<option value="">All AP Groups</option>${options}`;
  }

  function rowMatches(row, query, group, status = "") {
    const groupMatch = !group || row.mapping_group === group;
    const statusMatch = !status || row.group_status === status;
    const textMatch = !query || [
      row.ap_name, row.mac, row.mapping_group, row.a_group, row.b_group,
      row.a_status, row.b_status, row.role, row.active_wlc, row.model,
    ].join(" ").toLowerCase().includes(query.toLowerCase());
    return groupMatch && statusMatch && textMatch;
  }

  function renderOverviewRows() {
    const query = document.getElementById("ap-role-search").value.trim();
    const rows = currentRows.filter(row => rowMatches(row, query, overviewGroupFilter.value));
    renderRoleTable("ap-role-all-table", rows);
    document.getElementById("ap-role-count-label").textContent = `${rows.length} of ${currentRows.length} AP identities`;
  }

  function renderGroupRows() {
    const query = document.getElementById("ap-role-group-search").value.trim();
    const rows = currentRows.filter(row => rowMatches(row, query, groupFilter.value, groupStatusFilter.value));
    renderRoleTable("ap-role-group-ap-table", rows, groupColumns, "No AP records match these group filters.");
    document.getElementById("ap-role-group-ap-count").textContent = `${rows.length} of ${currentRows.length} AP`;
  }

  function renderGroupSummary() {
    const query = document.getElementById("ap-role-group-summary-search").value.trim().toLowerCase();
    const rows = currentGroupSummary.filter(item => !query || item.group.toLowerCase().includes(query));
    const table = document.getElementById("ap-role-group-summary-table");
    const body = rows.length ? rows.map(item => `<tr>
      <td><strong>${esc(item.group)}</strong></td><td>${esc(item.total_aps)}</td><td>${esc(item.active_a)}</td><td>${esc(item.active_b)}</td>
      <td>${esc(item.healthy_pairs)}</td><td>${esc(item.role_issues)}</td><td>${esc(item.group_mismatch)}</td><td>${esc(item.peer_group_missing)}</td>
      <td><button type="button" class="table-action" data-view-ap-group="${esc(item.group)}" aria-label="View APs in ${esc(item.group)}">View APs</button></td>
    </tr>`).join("") : '<tr><td colspan="9">No AP Group matches this search.</td></tr>';
    table.innerHTML = `<thead><tr><th>AP Group</th><th>Total AP</th><th>Active Controller A</th><th>Active Controller B</th><th>Healthy Pairs</th><th>Role Issues</th><th>Group Mismatch</th><th>Peer Missing</th><th>Action</th></tr></thead><tbody>${body}</tbody>`;
    document.getElementById("ap-role-group-summary-count").textContent = `${rows.length} of ${currentGroupSummary.length} groups`;
  }

  function renderInputIssues(issues) {
    const table = document.getElementById("ap-role-input-table");
    const body = issues.length ? issues.map(issue => `<tr><td>${esc(issue.source)}</td><td>${badge(issue.severity, "severity")}</td><td>${esc(issue.message)}</td></tr>`).join("") : `<tr><td colspan="3">No input quality issues detected.</td></tr>`;
    table.innerHTML = `<thead><tr><th>Source</th><th>Severity</th><th>Message</th></tr></thead><tbody>${body}</tbody>`;
  }

  function renderResult(result) {
    const summary = result.summary || {};
    const metrics = [
      ["Total AP", summary.total_aps], ["AP Groups", summary.ap_groups],
      ["Active Controller A", summary.active_a], ["Active Controller B", summary.active_b],
      ["Healthy Pairs", summary.healthy_pairs], ["Role Issues", summary.role_issues],
      ["Group Mismatch", summary.group_mismatch], ["Critical", summary.critical],
    ];
    document.getElementById("ap-role-summary").innerHTML = metrics.map(([label, value]) => `<article><span>${esc(label)}</span><strong>${esc(value || 0)}</strong></article>`).join("");
    document.getElementById("ap-role-comparison-name").textContent = `${result.a_name} ↔ ${result.b_name}`;
    document.getElementById("ap-role-source-summary").textContent = `${result.sources.a_records} Controller A records · ${result.sources.b_records} Controller B records · ${result.sources.allocation_records} expected allocations`;
    document.getElementById("ap-role-export").href = result.export_url;
    const policyLabels = {identity_priority: "Identity matching", active_state: "Active state", standby_state: "Standby state", capture_guidance: "Capture window"};
    document.getElementById("ap-role-policy").innerHTML = Object.entries(result.policy || {}).map(([key, value]) => `<div class="kv-row"><span>${esc(policyLabels[key] || key)}</span><strong>${esc(value)}</strong></div>`).join("");
    const distribution = [
      ["Active Controller A", summary.active_a], ["Active Controller B", summary.active_b],
      ["Dual Active", summary.dual_active], ["No Active", summary.no_active],
      ["Missing Peer", summary.missing_peer], ["Input Issues", (result.input_issues || []).length],
    ];
    document.getElementById("ap-role-distribution").innerHTML = distribution.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value || 0)}</strong></div>`).join("");

    currentRows = result.rows || [];
    currentGroupSummary = result.group_summary || [];
    populateGroupFilters();
    overviewGroupFilter.value = "";
    groupFilter.value = "";
    groupStatusFilter.value = "";
    document.getElementById("ap-role-search").value = "";
    document.getElementById("ap-role-group-search").value = "";
    document.getElementById("ap-role-group-summary-search").value = "";
    renderOverviewRows();
    renderRoleTable("ap-role-a-table", currentRows.filter(row => row.active_wlc === "A"));
    renderRoleTable("ap-role-b-table", currentRows.filter(row => row.active_wlc === "B"));
    renderRoleTable("ap-role-issues-table", currentRows.filter(row => !["Active A", "Active B"].includes(row.role) || row.missing_peer));
    renderRoleTable("ap-role-allocation-table", currentRows.filter(row => row.allocation_status === "Role Mismatch"));
    renderRoleTable("ap-role-attributes-table", currentRows.filter(row => row.attribute_mismatch));
    renderGroupSummary();
    renderGroupRows();
    const groupMetrics = [
      ["AP Groups", summary.ap_groups], ["Matched", summary.group_matched],
      ["Mismatch", summary.group_mismatch], ["Peer Missing", summary.peer_group_missing],
    ];
    document.getElementById("ap-role-group-metrics").innerHTML = groupMetrics.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value ?? 0)}</strong></div>`).join("");
    renderInputIssues(result.input_issues || []);
    switchTab("overview");
  }

  document.getElementById("ap-role-search").addEventListener("input", renderOverviewRows);
  overviewGroupFilter.addEventListener("change", renderOverviewRows);
  document.getElementById("ap-role-group-summary-search").addEventListener("input", renderGroupSummary);
  document.getElementById("ap-role-group-search").addEventListener("input", renderGroupRows);
  groupFilter.addEventListener("change", renderGroupRows);
  groupStatusFilter.addEventListener("change", renderGroupRows);
  document.getElementById("ap-role-group-summary-table").addEventListener("click", event => {
    const button = event.target.closest("[data-view-ap-group]");
    if (!button) return;
    groupFilter.value = button.dataset.viewApGroup;
    groupStatusFilter.value = "";
    document.getElementById("ap-role-group-search").value = "";
    renderGroupRows();
    document.querySelector(".ap-group-detail-panel")?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
  });

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!aFile.files.length || !bFile.files.length) {
      window.NES.toast("Select both Controller A and Controller B AP State files.", "error");
      return;
    }
    window.NES.setLoading(compareButton, true, "Comparing AP roles...");
    try {
      const response = await fetch("/wireless/api/compare-ap-roles", {method: "POST", body: new FormData(form)});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "AP role comparison failed.");
      emptyPanel.classList.add("hidden");
      resultPanel.classList.remove("hidden");
      renderResult(payload.result);
      window.NES.toast("Controller A and Controller B AP role comparison completed.");
      resultPanel.scrollIntoView({behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start"});
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareButton, false);
    }
  });
})();
