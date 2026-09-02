(() => {
  const form = document.getElementById("delta-form");
  if (!form) return;
  const esc = value => window.NES.escape(value ?? "");
  const sourceFile = document.getElementById("delta-source-file");
  const targetFile = document.getElementById("delta-target-file");
  const compareButton = document.getElementById("compare-button");
  const resultPanel = document.getElementById("delta-result");
  const emptyPanel = document.getElementById("delta-empty");

  function setWorkspace(name, updateUrl = true) {
    if (!["analysis", "roles", "delta"].includes(name)) name = "analysis";
    document.getElementById("wireless-analysis-workspace").classList.toggle("hidden", name !== "analysis");
    document.getElementById("wireless-role-workspace").classList.toggle("hidden", name !== "roles");
    document.getElementById("wireless-delta-workspace").classList.toggle("hidden", name !== "delta");
    document.querySelectorAll("[data-wireless-workspace]").forEach(button => {
      const active = button.dataset.wirelessWorkspace === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });
    if (updateUrl) {
      const url = new URL(window.location.href);
      if (name === "delta") url.searchParams.set("mode", "compare");
      else if (name === "roles") url.searchParams.set("mode", "roles");
      else url.searchParams.delete("mode");
      window.history.replaceState({}, "", url);
    }
  }
  window.NESWireless = {setWorkspace};

  document.querySelectorAll("[data-wireless-workspace]").forEach(button => {
    button.addEventListener("click", () => setWorkspace(button.dataset.wirelessWorkspace));
  });
  const requestedMode = new URLSearchParams(window.location.search).get("mode");
  setWorkspace(requestedMode === "compare" || requestedMode === "delta" ? "delta" : requestedMode === "roles" ? "roles" : "analysis", false);

  function setFile(input, labelId, clearId) {
    document.getElementById(labelId).textContent = input.files[0]?.name || "TXT, CFG, or terminal capture";
    document.getElementById(clearId).classList.toggle("hidden", !input.files.length);
    input.closest(".drop-zone")?.classList.toggle("has-file", Boolean(input.files.length));
  }
  sourceFile.addEventListener("change", () => setFile(sourceFile, "delta-source-label", "clear-delta-source"));
  targetFile.addEventListener("change", () => setFile(targetFile, "delta-target-label", "clear-delta-target"));
  document.getElementById("clear-delta-source").addEventListener("click", () => {
    sourceFile.value = ""; setFile(sourceFile, "delta-source-label", "clear-delta-source");
  });
  document.getElementById("clear-delta-target").addEventListener("click", () => {
    targetFile.value = ""; setFile(targetFile, "delta-target-label", "clear-delta-target");
  });

  function switchTab(name) {
    document.querySelectorAll("#delta-tabs [data-delta-tab]").forEach(button => {
      const active = button.dataset.deltaTab === name;
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
    });
    document.querySelectorAll(".delta-tab-content").forEach(panel => {
      panel.classList.toggle("active", panel.id === `delta-tab-${name}`);
    });
  }
  document.getElementById("delta-tabs").addEventListener("click", event => {
    const button = event.target.closest("[data-delta-tab]");
    if (button) switchTab(button.dataset.deltaTab);
  });
  document.getElementById("delta-tabs").addEventListener("keydown", event => {
    if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
    const tabs = [...document.querySelectorAll("#delta-tabs [data-delta-tab]")];
    const current = Math.max(0, tabs.indexOf(document.activeElement));
    const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
    event.preventDefault();
    switchTab(tabs[next].dataset.deltaTab);
    tabs[next].focus();
  });

  function commandPreview(commands) {
    const values = commands || [];
    if (!values.length) return "—";
    return `<details class="delta-command-preview"><summary>${values.length} line${values.length === 1 ? "" : "s"}</summary><code>${values.map(esc).join("\n")}</code></details>`;
  }

  function statusBadge(status) {
    const slug = String(status || "").toLowerCase().replaceAll(" ", "-");
    return `<span class="delta-status ${esc(slug)}">${esc(status)}</span>`;
  }

  function renderTable(id, rows) {
    const table = document.getElementById(id);
    const headers = ["Category", "Object", "Name", "Result", "Impact", "Source Delta", "Target-only Detail"];
    const body = rows.length ? rows.map(row => `<tr><td>${esc(row.category)}</td><td>${esc(row.object_type)}</td><td class="delta-object-name">${esc(row.name)}</td><td>${statusBadge(row.status)}</td><td><span class="impact-label ${esc(String(row.impact).toLowerCase())}">${esc(row.impact)}</span></td><td>${commandPreview(row.missing_commands)}</td><td>${commandPreview(row.extra_commands)}</td></tr>`).join("") : `<tr><td colspan="7">No records in this category.</td></tr>`;
    table.innerHTML = `<thead><tr>${headers.map(header => `<th>${header}</th>`).join("")}</tr></thead><tbody>${body}</tbody>`;
  }

  function renderMacAuth(result) {
    const summary = result.mac_auth || {};
    const metrics = [
      ["Chain Objects", summary.total_objects],
      ["Aligned", summary.identical],
      ["Drift", summary.drift],
      ["Manual", summary.manual_review],
    ];
    document.getElementById("delta-mac-auth-metrics").innerHTML = metrics.map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value || 0)}</strong></div>`).join("");
    document.getElementById("delta-mac-auth-stages").innerHTML = (summary.stages || []).map((stage, index) => `<article><span class="delta-stage-index">${index + 1}</span><div><strong>${esc(stage.stage)}</strong><small>${esc(stage.total || 0)} objects · ${esc(stage.identical || 0)} aligned · ${esc((stage.missing || 0) + (stage.changed || 0) + (stage.extra || 0))} drift</small></div></article>`).join("");

    const rows = (result.rows || []).filter(row => row.mac_auth_dependency);
    const headers = ["Stage", "Object", "Name", "Result", "Impact", "Source Delta", "Target-only Detail"];
    const body = rows.length ? rows.map(row => `<tr><td><span class="delta-stage-label">${esc(row.dependency_stage)}</span></td><td>${esc(row.object_type)}</td><td class="delta-object-name">${esc(row.name)}</td><td>${statusBadge(row.status)}</td><td><span class="impact-label ${esc(String(row.impact).toLowerCase())}">${esc(row.impact)}</span></td><td>${commandPreview(row.missing_commands)}</td><td>${commandPreview(row.extra_commands)}</td></tr>`).join("") : `<tr><td colspan="7">No MAC authentication dependency was detected.</td></tr>`;
    document.getElementById("delta-mac-auth-table").innerHTML = `<thead><tr>${headers.map(header => `<th>${header}</th>`).join("")}</tr></thead><tbody>${body}</tbody>`;
  }

  function renderResult(result) {
    const s = result.summary || {};
    const metrics = [
      ["Total Objects", s.total_objects], ["Identical", s.identical],
      ["Missing", s.missing], ["Value Mismatch", s.changed],
      ["Target-only", s.extra], ["Manual Review", s.manual_review],
    ];
    document.getElementById("delta-summary").innerHTML = metrics.map(([label,value]) => `<article><span>${esc(label)}</span><strong>${esc(value || 0)}</strong></article>`).join("");
    document.getElementById("delta-comparison-name").textContent = `${result.source_name} → ${result.target_name}`;
    document.getElementById("delta-platform").textContent = `${result.vendor} · Source-to-Target · ${s.generated_objects || 0} generated · ${s.structured_objects || 0} structured + ${s.fallback_objects || 0} fallback objects`;
    document.getElementById("delta-download").href = result.delta_url;
    document.getElementById("delta-rollback-download").href = result.rollback_url;
    document.getElementById("delta-export").href = result.export_url;

    const safetyLabels = {
      direction: "Direction",
      target_only_policy: "Target-only policy",
      secrets: "Sensitive values",
      coverage: "Configuration coverage",
      mac_auth: "MAC-auth coverage",
      device_specific: "Device-specific config",
    };
    document.getElementById("delta-safety").innerHTML = Object.entries(result.safety || {}).map(([key,value]) => `<div class="kv-row"><span>${esc(safetyLabels[key] || key)}</span><strong>${esc(value)}</strong></div>`).join("");

    const differences = (result.rows || []).filter(row => row.status !== "Identical");
    const categories = {};
    differences.forEach(row => { categories[row.category] = (categories[row.category] || 0) + 1; });
    document.getElementById("delta-category-summary").innerHTML = Object.entries(categories).sort((a,b) => b[1] - a[1]).map(([category,count]) => `<div><span>${esc(category)}</span><strong>${count}</strong></div>`).join("") || `<div><span>No configuration drift detected</span><strong>0</strong></div>`;

    renderTable("delta-all-table", differences);
    renderTable("delta-missing-table", differences.filter(row => row.status === "Missing on Target"));
    renderTable("delta-changed-table", differences.filter(row => row.status === "Value Mismatch"));
    renderTable("delta-extra-table", differences.filter(row => row.status === "Extra on Target"));
    renderMacAuth(result);
    renderTable("delta-manual-table", differences.filter(row => row.manual_review));
    document.getElementById("delta-implementation-code").textContent = result.implementation_config || "";
    document.getElementById("delta-rollback-code").textContent = result.rollback_config || "";
    switchTab("overview");
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (!sourceFile.files.length || !targetFile.files.length) {
      window.NES.toast("Select both Source and Target WLC configuration files.", "error");
      return;
    }
    window.NES.setLoading(compareButton, true, "Comparing...");
    try {
      const response = await fetch("/wireless/api/compare", {method: "POST", body: new FormData(form)});
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Comparison failed.");
      emptyPanel.classList.add("hidden");
      resultPanel.classList.remove("hidden");
      renderResult(payload.result);
      window.NES.toast("Source-to-Target config delta generated.");
      const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      resultPanel.scrollIntoView({behavior: reducedMotion ? "auto" : "smooth", block: "start"});
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareButton, false);
    }
  });
})();
