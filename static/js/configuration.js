(() => {
  const form = document.getElementById("converter-form");
  if (!form) return;

  // A whole terminal session is reduced to its show running-config block before conversion; say so next to the line count.
  function sourceLineLabel(data) {
    if (data.capture) {
      return `${data.capture.config_lines} lines (${data.capture.command} cut from a ${data.capture.total_lines}-line session)`;
    }
    return `${data.source_lines} lines`;
  }

  const targetVendorSelect = document.getElementById("target-vendor");
  const targetModelField = document.getElementById("target-model-field");
  const targetModelSelect = document.getElementById("target-model");

  // Target-model options depend on the currently selected target
  // vendor (Huawei, Cisco, Aruba and Palo Alto each have their own confirmed model
  // list -- see PALOALTO_TARGET_MODELS / HUAWEI_TARGET_MODELS
  // server-side); the server embeds both lists once at page load so
  // switching vendors doesn't need a round trip.
  let targetModelsByVendor = {};
  try {
    const targetModelsDataEl = document.getElementById("target-models-by-vendor");
    targetModelsByVendor = targetModelsDataEl ? JSON.parse(targetModelsDataEl.textContent) : {};
  } catch (error) {
    targetModelsByVendor = {};
  }

  function updateTargetModelVisibility() {
    if (!targetVendorSelect || !targetModelField || !targetModelSelect) return;
    const vendorKey = (targetVendorSelect.value || "").toLowerCase();
    const models = targetModelsByVendor[vendorKey] || [];
    targetModelField.classList.toggle("hidden", models.length === 0);
    const previousValue = targetModelSelect.value;
    const optionsHtml = models
      .map(m => `<option value="${window.NES.escape(m.model)}"${m.model === previousValue ? " selected" : ""}>${window.NES.escape(m.label)}</option>`)
      .join("");
    targetModelSelect.innerHTML = `<option value="">Auto / not sure (skip port check)</option>${optionsHtml}`;
  }
  targetVendorSelect?.addEventListener("change", updateTargetModelVisibility);
  updateTargetModelVisibility();

  // Interface/zone mapping preview & edit (Mikrotik -> Palo Alto SD-WAN
  // migration) is only meaningful once a translator actually supports it
  // (Palo Alto today) -- see build_interface_mapping_preview() server-side.
  const previewMappingButton = document.getElementById("preview-mapping-button");
  function updatePreviewMappingVisibility() {
    if (!targetVendorSelect || !previewMappingButton) return;
    const isPaloAlto = (targetVendorSelect.value || "").toLowerCase() === "palo alto";
    previewMappingButton.classList.toggle("hidden", !isPaloAlto);
  }
  targetVendorSelect?.addEventListener("change", updatePreviewMappingVisibility);
  updatePreviewMappingVisibility();

  const fileInput = document.getElementById("config-file");
  const fileLabel = document.getElementById("config-file-label");
  const fileSelection = document.getElementById("config-file-selection");
  const selectedConfigName = document.getElementById("selected-config-name");
  const clearConfigFile = document.getElementById("clear-config-file");
  const button = document.getElementById("convert-button");
  const empty = document.getElementById("converter-empty");
  const resultPanel = document.getElementById("converter-result");
  const batchResultPanel = document.getElementById("batch-result");
  const mappingResultPanel = document.getElementById("mapping-result");

  function updateSingleFileSelection() {
    const file = fileInput.files[0];
    fileLabel.textContent = file?.name || "TXT, CFG, CONF, LOG or XML";
    selectedConfigName.textContent = file?.name || "—";
    fileSelection.classList.toggle("hidden", !file);
  }

  fileInput.addEventListener("change", updateSingleFileSelection);
  clearConfigFile.addEventListener("click", () => {
    fileInput.value = "";
    updateSingleFileSelection();
    window.NES.toast("Selected configuration file cancelled.");
  });

  const batchFiles = document.getElementById("batch-files");
  const batchFolder = document.getElementById("batch-folder");
  const batchButton = document.getElementById("batch-convert-button");
  const batchSelection = document.getElementById("batch-selection");
  const batchSelectionCount = document.getElementById("batch-selection-count");
  const clearBatchFiles = document.getElementById("clear-batch-files");
  let batchConvertedItems = [];

  function selectedBatchFiles() {
    const files = [...batchFiles.files, ...batchFolder.files];
    const seen = new Set();
    return files.filter(file => {
      const key = `${file.webkitRelativePath || file.name}|${file.size}|${file.lastModified}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function updateBatchSelection() {
    const directCount = batchFiles.files.length;
    const folderCount = batchFolder.files.length;
    const total = selectedBatchFiles().length;
    document.getElementById("batch-file-label").textContent = directCount
      ? `${directCount} file${directCount > 1 ? "s" : ""} or archive selected`
      : "Configs or ZIP archive";
    document.getElementById("batch-folder-label").textContent = folderCount
      ? `${folderCount} file${folderCount > 1 ? "s" : ""} from folder`
      : "Folder and subfolders";
    batchSelectionCount.textContent = `${total} item${total === 1 ? "" : "s"} selected`;
    batchSelection.classList.toggle("hidden", total === 0);
  }

  batchFiles.addEventListener("change", updateBatchSelection);
  batchFolder.addEventListener("change", updateBatchSelection);
  clearBatchFiles.addEventListener("click", () => {
    batchFiles.value = "";
    batchFolder.value = "";
    updateBatchSelection();
  });

  async function showBatchPreview(item) {
    if (!item?.preview_url) return;
    const preview = document.getElementById("batch-preview");
    preview.classList.remove("hidden");
    document.getElementById("batch-preview-title").textContent = `Loading ${item.source_name}...`;
    try {
      const response = await fetch(item.preview_url);
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Preview could not be loaded.");
      const data = payload.result;
      document.getElementById("batch-detected-platform").textContent = `${data.source_vendor} ${data.source_device_type}`;
      document.getElementById("batch-detected-hostname").textContent = data.hostname;
      document.getElementById("batch-review-count").textContent = data.review_count;
      document.getElementById("batch-output-lines").textContent = data.output_lines;
      document.getElementById("batch-source-line-count").textContent = sourceLineLabel(data);
      document.getElementById("batch-conversion-path").textContent = `${data.source_vendor} → ${data.target_vendor}`;
      document.getElementById("batch-preview-title").textContent = data.source_name;
      document.getElementById("batch-target-label").textContent = `${data.target_vendor} output`;
      document.getElementById("batch-source-editor").textContent = data.source_text;
      document.getElementById("batch-output-editor").textContent = data.output_text;
      const download = document.getElementById("download-batch-config");
      download.href = data.download_url;
      download.setAttribute("download", data.output_name);
      preview.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      preview.classList.add("hidden");
      window.NES.toast(error.message, "error");
    }
  }

  batchButton.addEventListener("click", async () => {
    const files = selectedBatchFiles();
    if (!files.length) {
      window.NES.toast("Select configuration files, a folder, or a ZIP archive.", "error");
      return;
    }

    const formData = new FormData();
    files.forEach(file => {
      const uploadName = file.webkitRelativePath || file.name;
      formData.append("config_files", file, uploadName);
    });
    ["domain", "source_vendor", "source_device_type", "target_vendor", "target_device_type", "target_model", "profile_key"].forEach(name => {
      const field = form.querySelector(`[name="${name}"]`);
      formData.append(name, field?.value || "");
    });
    if (form.querySelector('[name="hide_secrets"]')?.checked) formData.append("hide_secrets", "1");

    window.NES.setLoading(batchButton, true, "Converting batch...");
    try {
      const response = await fetch("/configuration/api/batch", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Batch conversion failed.");
      const data = payload.result;
      batchConvertedItems = data.converted || [];
      document.getElementById("batch-summary").textContent = `${data.converted_count} converted · ${data.failed_count} failed`;
      document.getElementById("download-batch").href = data.download_url;

      const convertedRows = batchConvertedItems.map((item, index) => ({
        ...item,
        rowType: "converted",
        rowIndex: index,
        detail: item.profile
          ? `${item.output_lines} lines · ${item.review_count} review markers · ${item.profile} profile`
          : `${item.output_lines} lines · ${item.review_count} review markers`,
      }));
      const failedRows = (data.failed || []).map(item => ({
        ...item,
        rowType: "failed",
        hostname: "—",
        source_vendor: "—",
        source_device_type: "—",
        detail: item.error,
      }));
      const rows = [...convertedRows, ...failedRows];

      document.getElementById("batch-table").innerHTML = `<thead><tr><th>Source File</th><th>Hostname</th><th>Platform</th><th>Status</th><th>Detail</th><th>Result</th></tr></thead><tbody>${rows.map(item => `<tr><td>${window.NES.escape(item.source_name)}</td><td>${window.NES.escape(item.hostname || "—")}</td><td>${window.NES.escape(item.rowType === "converted" ? `${item.source_vendor} ${item.source_device_type}` : "—")}</td><td><span class="cell-status">${window.NES.escape(item.status)}</span></td><td>${window.NES.escape(item.detail || "")}</td><td>${item.rowType === "converted" ? `<button type="button" class="table-action-button batch-view-button" data-result-index="${item.rowIndex}">View Result</button>` : "—"}</td></tr>`).join("")}</tbody>`;

      empty.classList.add("hidden");
      resultPanel.classList.add("hidden");
      batchResultPanel.classList.remove("hidden");
      document.getElementById("batch-preview").classList.toggle("hidden", !batchConvertedItems.length);
      if (batchConvertedItems.length) await showBatchPreview(batchConvertedItems[0]);
      window.NES.toast("Batch conversion completed.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(batchButton, false);
    }
  });

  document.getElementById("batch-table").addEventListener("click", event => {
    const viewButton = event.target.closest(".batch-view-button");
    if (!viewButton) return;
    showBatchPreview(batchConvertedItems[Number(viewButton.dataset.resultIndex)]);
  });

  // ---- Interface map tab (switch converts): every source port -> the port it becomes on the target model. ----
  const interfaceMapPanel = document.getElementById("interface-map-panel");
  const preflightPanel = document.getElementById("preflight-panel");
  const roundtripPanel = document.getElementById("roundtrip-panel");
  const fwReportPanel = document.getElementById("fwreport-panel");
  const configView = document.getElementById("config-view");
  const resultTabs = document.querySelectorAll(".cv-result-tab");
  const showUnusedToggle = document.getElementById("interface-map-show-unused");
  let currentInterfaceMap = null;

  function setResultTab(name) {
    resultTabs.forEach(tab => {
      const active = tab.dataset.resultTab === name;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
    interfaceMapPanel?.classList.toggle("hidden", name !== "interface-map");
    preflightPanel?.classList.toggle("hidden", name !== "preflight");
    roundtripPanel?.classList.toggle("hidden", name !== "roundtrip");
    fwReportPanel?.classList.toggle("hidden", name !== "fwreport");
    configView?.classList.toggle("hidden", name === "interface-map" || name === "preflight" || name === "roundtrip" || name === "fwreport");
  }
  resultTabs.forEach(tab => tab.addEventListener("click", () => setResultTab(tab.dataset.resultTab)));

  const IM_STATUS = {
    ok: ["Mapped", "tone-ok"],
    review: ["Review", "tone-warn"],
    missing: ["No equivalent", "tone-bad"],
    stanza: ["Not a port", "tone-mute"],
  };

  function renderInterfaceMapTable() {
    const table = document.getElementById("interface-map-table");
    if (!table || !currentInterfaceMap) return;
    const esc = window.NES.escape;
    const allRows = currentInterfaceMap.rows || [];
    const anyUsed = allRows.some(row => row.in_use);
    const rows = showUnusedToggle?.checked || !anyUsed ? allRows : allRows.filter(row => row.in_use);
    if (!rows.length) {
      table.innerHTML = '<tbody><tr><td>No physical ports were found in this configuration.</td></tr></tbody>';
      return;
    }
    table.innerHTML = `<thead><tr><th>Source port</th><th>Role</th><th>Speed</th><th>Member</th><th>In use</th><th>&rarr; Target port</th><th>Status</th><th>Note</th></tr></thead><tbody>${rows.map(row => {
      const [label, tone] = IM_STATUS[row.status] || [row.status, ""];
      return `<tr class="im-row im-${esc(row.status)}"><td><code>${esc(row.source)}</code></td><td>${esc(row.role || "—")}</td><td>${esc(row.speed || "—")}</td><td>${esc(row.member)}</td><td>${row.in_use ? "yes" : "no"}</td><td><code>${esc(row.target || "—")}</code></td><td><span class="cell-status ${tone}">${esc(label)}</span></td><td>${esc(row.note || "")}</td></tr>`;
    }).join("")}</tbody>`;
  }

  const FIT_VERDICT = {
    "fits": ["Target fits", "tone-ok"],
    "partial": ["Target only partly fits", "tone-warn"],
    "does-not-fit": ["Target does not fit", "tone-bad"],
  };

  // Target-fit banner: do the ports the source really uses exist on the chosen target model?
  function renderTargetFit(fit) {
    const box = document.getElementById("interface-map-fit");
    if (!box) return;
    if (!fit || !fit.verdict || fit.verdict === "unknown" || !fit.used) {
      box.classList.add("hidden");
      box.innerHTML = "";
      return;
    }
    const esc = window.NES.escape;
    const [label, tone] = FIT_VERDICT[fit.verdict] || [fit.verdict, ""];
    const needs = Object.entries(fit.needs || {}).map(([k, n]) => `${esc(n)} x ${esc(k)}`).join(", ");
    let html = `<p class="im-fit-head"><span class="cell-status ${tone}">${esc(label)}</span> ${esc(fit.mapped)} of ${esc(fit.used)} configured ports have a counterpart on the target${needs ? ` (needs ${needs})` : ""}.</p>`;
    if ((fit.missing_ports || []).length) {
      html += `<ul class="im-fit-list">${fit.missing_ports.map(p => `<li><code>${esc(p.source)}</code> ${esc(p.note || "")}</li>`).join("")}</ul>`;
      if (fit.missing > fit.missing_ports.length) html += `<p class="im-fit-more">${esc(fit.missing - fit.missing_ports.length)} more not listed.</p>`;
    }
    if ((fit.alternatives || []).length) {
      html += `<p class="im-fit-alt">Models in the catalog where every used port has a counterpart: ${fit.alternatives.map(a => `<strong>${esc(a.model)}</strong> (${esc(a.label)})`).join("; ")}.</p>`;
    }
    box.innerHTML = html;
    box.classList.remove("hidden");
  }

  const PREFLIGHT_READY = {
    ready: ["Ready to paste", "tone-ok"],
    decisions: ["Decisions needed before it goes live", "tone-warn"],
    blocked: ["Target model does not fit", "tone-bad"],
  };
  const PREFLIGHT_GROUP = { decision: ["Needs a decision", "tone-warn"], dropped: ["Not converted", "tone-bad"] };

  // Pre-flight tab (switch converts): converted / needs a decision / dropped, REVIEW counts by code, structural checks, target fit.
  function renderPreflight(pre) {
    if (!preflightPanel) return;
    const tab = [...resultTabs].find(t => t.dataset.resultTab === "preflight");
    if (!pre) {
      tab?.classList.add("hidden");
      return;
    }
    tab?.classList.remove("hidden");
    const esc = window.NES.escape;
    const attention = (pre.review_lines || 0) + (pre.checks || []).length;
    const count = document.getElementById("preflight-tab-count");
    if (count) count.textContent = attention ? String(attention) : "";
    const [label, tone] = PREFLIGHT_READY[pre.readiness] || [pre.readiness, ""];
    document.getElementById("preflight-lead").textContent = label;
    const chip = (text, n, t) => `<span class="cell-status ${t}">${esc(text)} ${esc(n)}</span>`;
    document.getElementById("preflight-summary").innerHTML = [
      `<span class="cell-status ${tone}">${esc(label)}</span>`,
      chip("Converted lines", pre.converted_lines || 0, "tone-ok"),
      chip("Need a decision", pre.decision || 0, "tone-warn"),
      chip("Not converted", pre.dropped || 0, "tone-bad"),
      chip("Structural checks", (pre.checks || []).length, (pre.checks || []).length ? "tone-warn" : "tone-ok"),
    ].join("");
    const fitBox = document.getElementById("preflight-fit");
    const fit = pre.fit;
    if (fit && fit.verdict) {
      const [fitLabel, fitTone] = FIT_VERDICT[fit.verdict] || [fit.verdict, ""];
      fitBox.innerHTML = `<p class="im-fit-head"><span class="cell-status ${fitTone}">${esc(fitLabel)}</span> ${esc(fit.mapped)} of ${esc(fit.used)} configured ports have a counterpart on the target.</p>`;
      fitBox.classList.remove("hidden");
    } else {
      fitBox.innerHTML = "";
      fitBox.classList.add("hidden");
    }
    const checks = pre.checks || [];
    document.getElementById("preflight-checks").innerHTML = checks.length
      ? `<ul class="im-fit-list">${checks.map(c => `<li><code>${esc(c.code)}</code> ${esc(c.subject)} ${esc(c.message)}</li>`).join("")}</ul>`
      : "";
    const table = document.getElementById("preflight-table");
    const rows = pre.by_code || [];
    table.innerHTML = rows.length
      ? `<thead><tr><th>Review code</th><th>Count</th><th>Meaning</th></tr></thead><tbody>${rows.map(row => {
          const [groupLabel, groupTone] = PREFLIGHT_GROUP[row.group] || [row.group, ""];
          return `<tr><td><code>${esc(row.code)}</code></td><td>${esc(row.count)}</td><td><span class="cell-status ${groupTone}">${esc(groupLabel)}</span></td></tr>`;
        }).join("")}</tbody>`
      : '<tbody><tr><td>No review markers in the converted configuration.</td></tr></tbody>';
  }

  const ROUNDTRIP_VERDICT = {
    equivalent: ["Reads back the same", "tone-ok"],
    flagged: ["Differences, all marked REVIEW", "tone-warn"],
    differences: ["Silent differences: check before use", "tone-bad"],
    unreadable: ["Could not be read back", "tone-bad"],
    empty: ["Nothing to compare", "tone-mute"],
  };
  const ROUNDTRIP_STATUS = { missing: ["Missing on target", "tone-bad"], changed: ["Changed", "tone-warn"] };

  // Round-trip tab (switch converts): the converted text read back by the target parser and compared with the source.
  function renderRoundtrip(rt) {
    if (!roundtripPanel) return;
    const tab = [...resultTabs].find(t => t.dataset.resultTab === "roundtrip");
    if (!rt || !rt.verdict) {
      tab?.classList.add("hidden");
      return;
    }
    tab?.classList.remove("hidden");
    const esc = window.NES.escape;
    const count = document.getElementById("roundtrip-tab-count");
    if (count) count.textContent = rt.silent ? String(rt.silent) : "";
    const [label, tone] = ROUNDTRIP_VERDICT[rt.verdict] || [rt.verdict, ""];
    document.getElementById("roundtrip-lead").textContent = label;
    const chip = (text, n, t) => `<span class="cell-status ${t}">${esc(text)} ${esc(n)}</span>`;
    document.getElementById("roundtrip-summary").innerHTML = [
      `<span class="cell-status ${tone}">${esc(label)}</span>`,
      chip("Checked", rt.checked || 0, "tone-mute"),
      chip("Same", rt.same || 0, "tone-ok"),
      chip("Silent differences", rt.silent || 0, rt.silent ? "tone-bad" : "tone-ok"),
      chip("Marked REVIEW", rt.flagged || 0, rt.flagged ? "tone-warn" : "tone-ok"),
    ].join("");
    document.getElementById("roundtrip-note").textContent = rt.reason
      ? rt.reason
      : "A silent difference is something the source configures that the converted text does not, with no REVIEW line to tell the engineer. Lines the target adds on its own are not counted.";
    const areas = document.getElementById("roundtrip-areas");
    areas.innerHTML = (rt.areas || []).length
      ? `<thead><tr><th>Area</th><th>Same</th><th>Changed</th><th>Missing</th><th>Silent</th></tr></thead><tbody>${rt.areas.map(a => `<tr><td>${esc(a.area)}</td><td>${esc(a.same)}</td><td>${esc(a.changed)}</td><td>${esc(a.missing)}</td><td>${a.silent ? `<span class="cell-status tone-bad">${esc(a.silent)}</span>` : "0"}</td></tr>`).join("")}</tbody>`
      : "";
    const table = document.getElementById("roundtrip-table");
    const rows = rt.rows || [];
    table.innerHTML = rows.length
      ? `<thead><tr><th>Area</th><th>Item</th><th>Status</th><th>Source</th><th>Target</th><th>REVIEW line</th><th>Note</th></tr></thead><tbody>${rows.map(row => {
          const [statusLabel, statusTone] = ROUNDTRIP_STATUS[row.status] || [row.status, ""];
          return `<tr class="im-row"><td>${esc(row.area)}</td><td><code>${esc(row.item)}</code></td><td><span class="cell-status ${statusTone}">${esc(statusLabel)}</span></td><td>${esc(row.source)}</td><td>${esc(row.target)}</td><td>${row.flagged ? '<span class="cell-status tone-ok">yes</span>' : '<span class="cell-status tone-bad">none</span>'}</td><td>${esc(row.note || "")}</td></tr>`;
        }).join("")}</tbody>`
      : '<tbody><tr><td>No difference found between the source and the converted text.</td></tr></tbody>';
  }

  function renderInterfaceMap(map) {
    if (!interfaceMapPanel) return;
    currentInterfaceMap = map || null;
    setResultTab("config");
    const tabCount = document.getElementById("interface-map-tab-count");
    if (!map) {
      resultTabs.forEach(tab => { if (tab.dataset.resultTab === "interface-map") tab.classList.add("hidden"); });
      return;
    }
    resultTabs.forEach(tab => tab.classList.remove("hidden"));
    const esc = window.NES.escape;
    const used = map.configured_counts || {};
    const attention = (used.review || 0) + (used.missing || 0);
    if (tabCount) tabCount.textContent = attention ? String(attention) : "";
    const source = map.source_model ? `${map.source_model}${(map.source_modules || []).length ? " + " + map.source_modules.join(", ") : ""}` : "source model not recognised (ports read from the names)";
    const target = map.target_model || "no Target Model chosen (naming rule only)";
    document.getElementById("interface-map-lead").textContent = `${source} → ${target}`;
    renderTargetFit(map.fit);
    document.getElementById("interface-map-warnings").innerHTML = (map.warnings || []).map(w => `<p class="im-warning">${esc(w)}</p>`).join("");
    const chip = (label, count, tone) => `<span class="cell-status ${tone}">${esc(label)} ${esc(count)}</span>`;
    document.getElementById("interface-map-summary").innerHTML = [
      chip("Configured ports mapped", used.ok || 0, "tone-ok"),
      chip("Need review", used.review || 0, "tone-warn"),
      chip("No equivalent on target", used.missing || 0, "tone-bad"),
      chip("Config stanzas that are not ports", used.stanza || 0, "tone-mute"),
      `<span class="im-total">${esc((map.rows || []).length)} ports in the source model</span>`,
    ].join("");
    renderInterfaceMapTable();
  }
  showUnusedToggle?.addEventListener("change", renderInterfaceMapTable);

  // ---- FortiGate <-> PAN-OS conversion report (firewall page): what did not carry over, by layer, with the documentation link. ----
  const FW_STATUS_TONE = { "Not converted": "tone-bad", "Needs review": "tone-warn", "Approximated": "tone-mute", "Converted": "tone-ok" };
  const FW_LAYER_LABEL = { interfaces: "Interfaces and zones", objects: "Objects", policies: "Security policy", nat: "NAT", routes: "Routing", vpn: "Site-to-site VPN" };
  let currentFwReport = null;

  function renderFwReportTable() {
    const table = document.getElementById("fwreport-table");
    if (!table || !currentFwReport) return;
    const esc = window.NES.escape;
    const filter = document.getElementById("fwreport-filter")?.value || "";
    const rows = (currentFwReport.rows || []).filter(row => filter === "all" ? true : filter ? row.status === filter : row.status !== "Converted");
    table.innerHTML = rows.length
      ? `<thead><tr><th>Status</th><th>Layer</th><th>What</th><th>Why, and what to do</th><th>Read</th></tr></thead><tbody>${rows.map(row => `<tr class="im-row ${row.status === "Not converted" ? "im-missing" : row.status === "Needs review" ? "im-review" : ""}"><td><span class="cell-status ${FW_STATUS_TONE[row.status] || ""}">${esc(row.status)}</span></td><td>${esc(FW_LAYER_LABEL[row.layer] || row.layer)}</td><td><code>${esc(row.kind)} ${esc(row.name)}</code></td><td>${esc(row.message)}</td><td>${/^https:\/\//.test(row.documentation || "") ? `<a href="${esc(row.documentation)}" target="_blank" rel="noopener noreferrer">Documentation</a>` : "—"}</td></tr>`).join("")}</tbody>`
      : '<tbody><tr><td>Nothing in this view.</td></tr></tbody>';
  }

  function renderFwReport(report, downloadUrl) {
    const tabs = document.getElementById("fw-tabs");
    if (!tabs || !fwReportPanel) return;
    if (!report) {
      tabs.classList.add("hidden");
      currentFwReport = null;
      return;
    }
    currentFwReport = report;
    tabs.classList.remove("hidden");
    setResultTab("config");
    const esc = window.NES.escape;
    const counts = report.counts || {};
    const attention = (counts.review || 0) + (counts.not_converted || 0);
    const count = document.getElementById("fwreport-tab-count");
    if (count) count.textContent = attention ? String(attention) : "";
    const chip = (text, n, tone) => `<span class="cell-status ${tone}">${esc(text)} ${esc(n)}</span>`;
    document.getElementById("fwreport-summary").innerHTML = [
      chip("Not converted", counts.not_converted || 0, counts.not_converted ? "tone-bad" : "tone-ok"),
      chip("Needs review", counts.review || 0, counts.review ? "tone-warn" : "tone-ok"),
      chip("Approximated", counts.approximated || 0, "tone-mute"),
      chip("Converted", counts.converted || 0, "tone-ok"),
    ].join("");
    const layers = Object.entries(report.summary || {});
    document.getElementById("fwreport-layers").innerHTML = layers.length
      ? `<thead><tr><th>Layer</th><th>Read</th><th>Written</th><th>Approximated</th><th>Needs review</th><th>Not converted</th></tr></thead><tbody>${layers.map(([layer, row]) => `<tr><td>${esc(FW_LAYER_LABEL[layer] || layer)}</td><td>${esc(row.read)}</td><td>${esc(row.written)}</td><td>${esc(row.approximated)}</td><td>${row.review ? `<span class="cell-status tone-warn">${esc(row.review)}</span>` : "0"}</td><td>${row.not_converted ? `<span class="cell-status tone-bad">${esc(row.not_converted)}</span>` : "0"}</td></tr>`).join("")}</tbody>`
      : "";
    const link = document.getElementById("fwreport-download");
    if (link) {
      link.href = downloadUrl || "#";
      link.classList.toggle("hidden", !downloadUrl);
    }
    renderFwReportTable();
  }
  document.getElementById("fwreport-filter")?.addEventListener("change", renderFwReportTable);

  // The FortiGate <-> PAN-OS options (layers, VDOM) show when the chosen pair is converted by that converter.
  const fwOptions = document.getElementById("fw-options");
  const sourceVendorSelect = document.getElementById("source-vendor");
  let panoramaFound = false;   // the chosen file is a Panorama export: the page asks for a device group instead of a VDOM
  function updateFwOptions() {
    if (!fwOptions || !targetVendorSelect) return;
    const source = (sourceVendorSelect?.value || "").toLowerCase();
    const target = (targetVendorSelect.value || "").toLowerCase();
    const pair = (source === "fortigate" && target === "palo alto") || (source === "palo alto" && target === "fortigate") || (source.startsWith("auto") && (target === "fortigate" || target === "palo alto"));
    fwOptions.classList.toggle("hidden", !(pair || panoramaFound));
    if (previewMappingButton && source === "fortigate") previewMappingButton.classList.add("hidden");
  }
  sourceVendorSelect?.addEventListener("change", () => { updatePreviewMappingVisibility(); updateFwOptions(); });
  targetVendorSelect?.addEventListener("change", updateFwOptions);
  updateFwOptions();

  // A Panorama export has no firewall of its own. When the chosen file is one, the VDOM field becomes a device-group picker
  // (name, or name:serial to keep only the rules pushed to one firewall) fed by /configuration/api/panorama-scopes.
  async function detectPanorama() {
    const input = document.getElementById("fw-vdom");
    const list = document.getElementById("fw-vdom-list");
    const label = document.getElementById("fw-vdom-label");
    const note = document.getElementById("fw-panorama-note");
    if (!input || !list || !label) return;
    panoramaFound = false;
    list.innerHTML = "";
    label.innerHTML = "FortiGate VDOM <small>(empty = the first one)</small>";
    input.placeholder = "root";
    note?.classList.add("hidden");
    const file = fileInput.files[0];
    if (file) {
      try {
        const head = await file.slice(0, 2048).text();
        if (/^\s*(<\?xml|<config)/.test(head)) {
          const form = new FormData();
          form.append("config_file", file);
          const data = await (await fetch("/configuration/api/panorama-scopes", { method: "POST", body: form })).json();
          if (data.ok && data.panorama) {
            panoramaFound = true;
            label.innerHTML = "Panorama device group <small>(name, or name:serial for one firewall)</small>";
            input.placeholder = data.groups.length ? data.groups[0].group : "";
            data.groups.forEach((g) => {
              const option = document.createElement("option");
              option.value = g.group;
              option.label = `${g.rules} rules, ${g.firewalls.length} firewall(s)`;
              list.appendChild(option);
              g.firewalls.forEach((f) => {
                const sub = document.createElement("option");
                sub.value = `${g.group}:${f.serial}`;
                sub.label = f.stack ? `one firewall, stack ${f.stack}` : "one firewall";
                list.appendChild(sub);
              });
            });
            if (note) {
              note.textContent = `Panorama export: ${data.groups.length} device group(s). Pick one; the converter flattens it (shared and parent objects, pre/post rules in order, the template stack's interfaces, zones and routing) and converts that.`;
              note.classList.remove("hidden");
            }
          }
        }
      } catch (_) { /* not a Panorama file, or the check could not run: the page behaves as before */ }
    }
    updateFwOptions();
  }
  fileInput.addEventListener("change", detectPanorama);
  clearConfigFile.addEventListener("click", detectPanorama);

  function renderSecretsNote(secrets) {
    const note = document.getElementById("secrets-note");
    if (!note) return;
    const lines = secrets && secrets.lines ? secrets.lines : 0;
    note.classList.toggle("hidden", !lines);
    if (!lines) return;
    const count = `${lines} line${lines === 1 ? "" : "s"}`;
    document.getElementById("secrets-note-text").textContent = secrets.hidden
      ? `${count} carried a password hash, SNMP community or shared key in the source; the values are hidden (<hidden>) in this output and in the download.`
      : `${count} carry a password hash, SNMP community or shared key copied from the source. Treat the output and the download like a credential file, or tick "Hide passwords and keys in the output" and convert again before you share it.`;
  }

  function renderConvertResult(data) {
    document.getElementById("detected-platform").textContent = `${data.source_vendor} ${data.source_device_type}`;
    document.getElementById("detected-hostname").textContent = data.hostname;
    document.getElementById("review-count").textContent = data.review_count;
    document.getElementById("output-lines").textContent = data.output_lines;
    document.getElementById("source-line-count").textContent = sourceLineLabel(data);
    const pathParts = [`${data.source_vendor} → ${data.target_vendor}`];
    if (data.target_model) pathParts.push(data.target_model);
    if (data.profile) pathParts.push(`${data.profile} profile`);
    document.getElementById("conversion-path").textContent = pathParts.join(" · ");
    document.getElementById("source-editor").textContent = data.source_text;
    document.getElementById("output-editor").textContent = data.output_text;
    const download = document.getElementById("download-config");
    download.href = data.download_url;
    download.setAttribute("download", data.download_name);
    renderSecretsNote(data.secrets);
    empty.classList.add("hidden");
    batchResultPanel.classList.add("hidden");
    mappingResultPanel?.classList.add("hidden");
    renderInterfaceMap(data.interface_map);
    renderPreflight(data.preflight);
    renderRoundtrip(data.roundtrip);
    renderFwReport(data.fwconvert, data.report_download_url);
    resultPanel.classList.remove("hidden");
    window.NES.toast(`Converted ${data.hostname} successfully.`);
  }

  function baseConvertFormData() {
    return new FormData(form);
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = baseConvertFormData();
    window.NES.setLoading(button, true, "Converting...");
    try {
      const response = await fetch("/configuration/api/convert", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Conversion failed.");
      renderConvertResult(payload.result);
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(button, false);
    }
  });

  // ---- Interface/zone mapping preview & edit (Mikrotik -> Palo Alto
  // SD-WAN migration). Only meaningfully reachable when the target
  // vendor is Palo Alto (see updatePreviewMappingVisibility above),
  // but the handlers below stay defensive (?. / supported checks)
  // since the backend is the actual source of truth on support. ----

  const mappingHostnameLine = document.getElementById("mapping-hostname-line");
  const mappingInterfacesBody = document.querySelector("#mapping-interfaces-table tbody");
  const mappingIpsecBody = document.querySelector("#mapping-ipsec-table tbody");
  const mappingIpsecPanel = document.getElementById("mapping-ipsec-panel");
  const mappingSdwanEnabled = document.getElementById("mapping-sdwan-enabled");
  const mappingSdwanZone = document.getElementById("mapping-sdwan-zone");
  const mappingPanoramaEnabled = document.getElementById("mapping-panorama-enabled");
  const mappingTemplateName = document.getElementById("mapping-template-name");
  const mappingDgName = document.getElementById("mapping-dg-name");
  const generateMappedButton = document.getElementById("generate-mapped-button");

  function sdwanLinkOptions(selected) {
    const options = [
      ["", "Not SD-WAN"],
      ["mpls", "MPLS"],
      ["ethernet", "Ethernet (DIA)"],
      ["lte", "LTE"],
    ];
    return options
      .map(([value, label]) => `<option value="${value}"${value === (selected || "") ? " selected" : ""}>${label}</option>`)
      .join("");
  }

  function renderMappingPreview(result) {
    mappingHostnameLine.textContent =
      `Detected hostname: ${result.hostname || "—"}. Review the auto-detected mapping below, adjust anything, then generate the config.`;

    const interfaces = result.interfaces || [];
    mappingInterfacesBody.innerHTML = interfaces
      .map(row => {
        const canBeSdwanMember = !row.is_bridge && row.interface_type !== "vlan";
        const reviewBadge = row.needs_review ? ` <span class="mapping-needs-review">needs review</span>` : "";
        const zoneValue = window.NES.escape(row.suggested_zone || "");
        const panValue = window.NES.escape(row.suggested_pan_interface || "");
        return (
          `<tr data-name="${window.NES.escape(row.name)}">` +
          `<td>${window.NES.escape(row.name)}${reviewBadge}</td>` +
          `<td>${window.NES.escape(row.interface_type || "")}${row.is_bridge ? " (bridge)" : ""}</td>` +
          `<td>${canBeSdwanMember ? `<input type="text" class="map-pan-interface" value="${panValue}" placeholder="ethernet1/1">` : "—"}</td>` +
          `<td><input type="text" class="map-zone" value="${zoneValue}"></td>` +
          `<td>${canBeSdwanMember ? `<select class="map-sdwan-link">${sdwanLinkOptions("")}</select>` : "—"}</td>` +
          `</tr>`
        );
      })
      .join("");

    const tunnels = result.ipsec_tunnels || [];
    mappingIpsecPanel.classList.toggle("hidden", tunnels.length === 0);
    mappingIpsecBody.innerHTML = tunnels
      .map(
        row =>
          `<tr data-tunnel="${window.NES.escape(row.tunnel_name)}">` +
          `<td>${window.NES.escape(row.tunnel_name)}</td>` +
          `<td>${window.NES.escape(row.peer_name || "—")}</td>` +
          `<td><input type="text" class="map-tunnel-zone" value="${window.NES.escape(row.suggested_zone || "")}" placeholder="IPSEC-Tunnel"></td>` +
          `<td><input type="number" class="map-tunnel-unit" min="1" max="9999" value="${row.suggested_unit || ""}"></td>` +
          `</tr>`
      )
      .join("");

    mappingSdwanZone.value = result.suggested_sdwan_zone || "SDWAN";
    mappingTemplateName.value = result.suggested_template_name || "";
    mappingDgName.value = result.suggested_device_group_name || "";
  }

  previewMappingButton?.addEventListener("click", async () => {
    const hasFile = fileInput.files.length > 0;
    const hasText = document.getElementById("config-text").value.trim().length > 0;
    if (!hasFile && !hasText) {
      window.NES.toast("Upload a configuration file or paste one first.", "error");
      return;
    }

    const formData = baseConvertFormData();
    window.NES.setLoading(previewMappingButton, true, "Analyzing...");
    try {
      const response = await fetch("/configuration/api/preview-mapping", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Could not analyze this configuration.");
      const result = payload.result;
      if (!result.supported) {
        window.NES.toast("Interface/zone mapping isn't available for this source/target combination yet.", "error");
        return;
      }
      renderMappingPreview(result);
      empty.classList.add("hidden");
      resultPanel.classList.add("hidden");
      batchResultPanel.classList.add("hidden");
      mappingResultPanel?.classList.remove("hidden");
      mappingResultPanel?.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(previewMappingButton, false);
    }
  });

  generateMappedButton?.addEventListener("click", async () => {
    const interfaceMapping = {};
    mappingInterfacesBody.querySelectorAll("tr[data-name]").forEach(row => {
      const name = row.dataset.name;
      const panInterfaceInput = row.querySelector(".map-pan-interface");
      const zoneInput = row.querySelector(".map-zone");
      const sdwanSelect = row.querySelector(".map-sdwan-link");
      const entry = {};
      if (panInterfaceInput && panInterfaceInput.value.trim()) entry.pan_interface = panInterfaceInput.value.trim();
      if (zoneInput && zoneInput.value.trim()) entry.zone = zoneInput.value.trim();
      if (sdwanSelect && sdwanSelect.value) entry.sdwan_link_type = sdwanSelect.value;
      if (Object.keys(entry).length) interfaceMapping[name] = entry;
    });

    const ipsecMapping = {};
    mappingIpsecBody.querySelectorAll("tr[data-tunnel]").forEach(row => {
      const tunnelName = row.dataset.tunnel;
      const zoneInput = row.querySelector(".map-tunnel-zone");
      const unitInput = row.querySelector(".map-tunnel-unit");
      const entry = {};
      if (zoneInput && zoneInput.value.trim()) entry.zone = zoneInput.value.trim();
      if (unitInput && unitInput.value) entry.tunnel_unit = Number(unitInput.value);
      if (Object.keys(entry).length) ipsecMapping[tunnelName] = entry;
    });

    const mapping = {
      interfaces: interfaceMapping,
      ipsec_tunnels: ipsecMapping,
      sdwan: {
        enabled: !!mappingSdwanEnabled?.checked,
        zone: mappingSdwanZone?.value.trim() || "SDWAN",
      },
      panorama: {
        enabled: !!mappingPanoramaEnabled?.checked,
        template_name: mappingTemplateName?.value.trim() || "",
        device_group_name: mappingDgName?.value.trim() || "",
      },
    };

    const formData = baseConvertFormData();
    formData.set("interface_mapping", JSON.stringify(mapping));
    window.NES.setLoading(generateMappedButton, true, "Generating...");
    try {
      const response = await fetch("/configuration/api/convert", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Conversion failed.");
      renderConvertResult(payload.result);
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(generateMappedButton, false);
    }
  });
})();


// Settings panel folds away once a conversion is on screen, so the result
// gets the full width. A slim bar above the result tells which source is
// loaded and brings the panel back.
(function () {
  const form = document.getElementById("converter-form");
  const bar = document.getElementById("cv-source-bar");
  if (!form || !bar) return;
  const $ = id => document.getElementById(id);
  const hide = $("cv-settings-hide");

  function summary() {
    const file = $("config-file")?.files?.[0];
    const text = ($("config-text")?.value || "").trim();
    const source = file ? file.name : text ? `Pasted config (${text.split("\n").length} lines)` : "No source yet";
    const from = $("source-vendor")?.value || "Auto Detect";
    const to = $("target-vendor")?.value || "";
    const model = $("target-model")?.selectedOptions?.[0]?.value ? ` · ${$("target-model").selectedOptions[0].textContent.trim()}` : "";
    return `${source} · ${from} → ${to}${model}`;
  }

  function collapse() {
    $("cv-source-summary").textContent = summary();
    form.classList.add("settings-collapsed");
    bar.classList.remove("hidden");
    $("cv-settings-open").textContent = "Change source & settings";
    hide?.classList.remove("hidden");
  }

  function expand() {
    form.classList.remove("settings-collapsed");
    $("cv-settings-open").textContent = "Hide settings";
  }

  function reset() {
    form.classList.remove("settings-collapsed");
    bar.classList.add("hidden");
  }

  window.NES = window.NES || {};
  window.NES.convertSettings = { collapse, expand, reset };

  $("cv-settings-open")?.addEventListener("click", () => {
    if (form.classList.contains("settings-collapsed")) expand(); else collapse();
  });
  hide?.addEventListener("click", collapse);

  // Fold after a result shows up (wizard, conversion, mapping preview).
  ["wizard-result", "converter-result", "mapping-result", "batch-result"].forEach(id => {
    const el = $(id);
    if (!el) return;
    new MutationObserver(() => {
      if (!el.classList.contains("hidden") && el.offsetParent !== null) collapse();
    }).observe(el, { attributes: true, attributeFilter: ["class"] });
  });
  $("wizard-restart")?.addEventListener("click", reset);
})();
