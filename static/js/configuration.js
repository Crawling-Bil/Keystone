(() => {
  const form = document.getElementById("converter-form");
  if (!form) return;

  const targetVendorSelect = document.getElementById("target-vendor");
  const targetModelField = document.getElementById("target-model-field");
  function updateTargetModelVisibility() {
    if (!targetVendorSelect || !targetModelField) return;
    const isHuawei = (targetVendorSelect.value || "").toLowerCase() === "huawei";
    targetModelField.classList.toggle("hidden", !isHuawei);
  }
  targetVendorSelect?.addEventListener("change", updateTargetModelVisibility);
  updateTargetModelVisibility();

  const fileInput = document.getElementById("config-file");
  const fileLabel = document.getElementById("config-file-label");
  const fileSelection = document.getElementById("config-file-selection");
  const selectedConfigName = document.getElementById("selected-config-name");
  const clearConfigFile = document.getElementById("clear-config-file");
  const button = document.getElementById("convert-button");
  const empty = document.getElementById("converter-empty");
  const resultPanel = document.getElementById("converter-result");
  const batchResultPanel = document.getElementById("batch-result");

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

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(form);
    window.NES.setLoading(button, true, "Converting...");
    try {
      const response = await fetch("/configuration/api/convert", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Conversion failed.");
      const data = payload.result;
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
      resultPanel.classList.remove("hidden");
      window.NES.toast(`Converted ${data.hostname} successfully.`);
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(button, false);
    }
  });
})();
