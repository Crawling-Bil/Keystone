(() => {
  const form = document.getElementById("converter-form");
  if (!form) return;

  const targetVendorSelect = document.getElementById("target-vendor");
  const targetModelField = document.getElementById("target-model-field");
  const targetModelSelect = document.getElementById("target-model");

  // Target-model options depend on the currently selected target
  // vendor (Huawei and Palo Alto each have their own confirmed model
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
    targetModelSelect.innerHTML = `<option value="">Auto / not sure (skip port-count check)</option>${optionsHtml}`;
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
    fileLabel.textContent = file?.name || "TXT, CFG, CONF or LOG";
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
      document.getElementById("batch-source-line-count").textContent = `${data.source_lines} lines`;
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
    ["source_vendor", "source_device_type", "target_vendor", "target_device_type", "target_model", "profile_key"].forEach(name => {
      const field = form.querySelector(`[name="${name}"]`);
      formData.append(name, field?.value || "");
    });

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

  function renderConvertResult(data) {
    document.getElementById("detected-platform").textContent = `${data.source_vendor} ${data.source_device_type}`;
    document.getElementById("detected-hostname").textContent = data.hostname;
    document.getElementById("review-count").textContent = data.review_count;
    document.getElementById("output-lines").textContent = data.output_lines;
    document.getElementById("source-line-count").textContent = `${data.source_lines} lines`;
    const pathParts = [`${data.source_vendor} → ${data.target_vendor}`];
    if (data.target_model) pathParts.push(data.target_model);
    if (data.profile) pathParts.push(`${data.profile} profile`);
    document.getElementById("conversion-path").textContent = pathParts.join(" · ");
    document.getElementById("source-editor").textContent = data.source_text;
    document.getElementById("output-editor").textContent = data.output_text;
    const download = document.getElementById("download-config");
    download.href = data.download_url;
    download.setAttribute("download", data.download_name);
    empty.classList.add("hidden");
    batchResultPanel.classList.add("hidden");
    mappingResultPanel.classList.add("hidden");
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
      mappingResultPanel.classList.remove("hidden");
      mappingResultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
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
