document.addEventListener("DOMContentLoaded", () => {

    // ========================================================
    // API HELPER
    // ========================================================

    async function apiRequest(url, options = {}) {

        const response = await fetch(url, options);

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error("Invalid response from server.");
        }

        if (!response.ok) {
            throw new Error(data.error || "Request failed.");
        }

        return data;

    }


    // ========================================================
    // ESCAPE HTML
    // ========================================================

    function escapeHtml(value) {

        if (value === null || value === undefined) {
            return "-";
        }

        return String(value)
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#039;");

    }


    // ========================================================
    // CONFIG PUSH
    //
    // Own top-level page for pushing an operator-prepared draft
    // config to devices already in DEVICES_FILE (i.e. showed up in a
    // Discovery scan at some point) -- independent of ZTP and of the
    // Upgrade Jobs pipeline. The created job reuses Lifecycle
    // Manager's own Jobs queue/log UI (job list rendering there is
    // already generic over job.type), so this page only handles
    // device selection, draft assignment, and job creation.
    // ========================================================

    let allDevices = [];
    let allDrafts = [];
    const selectedIPs = new Set();

    const checklistContainer = document.getElementById("config-push-device-checklist");
    const devicesStatus = document.getElementById("config-push-devices-status");
    const selectedCountEl = document.getElementById("config-push-selected-count");
    const draftListContainer = document.getElementById("config-push-device-list");
    const createJobButton = document.getElementById("config-push-create-job-button");
    const refreshDevicesButton = document.getElementById("config-push-refresh-devices");

    function draftsMatchingHostname(hostname) {

        const target = String(hostname || "").toLowerCase();

        return allDrafts.filter(
            draft => String(draft.hostname || "").toLowerCase() === target
        );

    }

    function renderChecklist() {

        if (allDevices.length === 0) {

            checklistContainer.innerHTML = `
                <div class="empty-state">
                    No devices discovered yet. Run a scan on the Discovery page first.
                </div>
            `;

            return;

        }

        checklistContainer.innerHTML = allDevices.map(device => `
            <label class="config-push-checklist-row">
                <input
                    type="checkbox"
                    class="config-push-select-checkbox"
                    value="${escapeHtml(device.ip)}"
                    ${selectedIPs.has(device.ip) ? "checked" : ""}
                >
                <span class="config-push-checklist-row-main">
                    <strong>${escapeHtml(device.hostname || device.ip)}</strong>
                    <span>${escapeHtml(device.ip)} · ${escapeHtml(device.vendor)} ${escapeHtml(device.platform)}</span>
                </span>
            </label>
        `).join("");

    }

    function renderDraftAssignments() {

        const selectedDevices = allDevices.filter(
            device => selectedIPs.has(device.ip)
        );

        selectedCountEl.textContent =
            `${selectedDevices.length} device${selectedDevices.length === 1 ? "" : "s"} selected`;

        createJobButton.disabled = selectedDevices.length === 0;

        if (selectedDevices.length === 0) {

            draftListContainer.innerHTML = `
                <div class="empty-state">
                    Select at least one device above.
                </div>
            `;

            return;

        }

        // Preserve anything the operator already typed/picked for a
        // device that's still selected across a re-render (e.g. after
        // checking one more box).
        const previousValues = {};
        draftListContainer.querySelectorAll(".config-push-draft-text").forEach(textarea => {
            previousValues[textarea.dataset.ip] = textarea.value;
        });

        draftListContainer.innerHTML = selectedDevices.map(device => {

            const matchingDrafts = draftsMatchingHostname(device.hostname);
            const otherDrafts = allDrafts.filter(draft => !matchingDrafts.includes(draft));

            // Exactly one draft already named after this device is the
            // one unambiguous case worth pre-filling automatically --
            // 0 or 2+ matches are left on "paste manually" rather than
            // guessing which one the operator meant.
            const autoSelected = matchingDrafts.length === 1 ? matchingDrafts[0] : null;

            const optionsHtml = [
                `<option value="">Paste manually below…</option>`,
                ...matchingDrafts.map(draft => `
                    <option value="${escapeHtml(draft.id)}" ${autoSelected === draft ? "selected" : ""}>
                        ★ ${escapeHtml(draft.hostname)} — ${draft.line_count} line(s) (${escapeHtml(draft.source)})
                    </option>
                `),
                ...otherDrafts.map(draft => `
                    <option value="${escapeHtml(draft.id)}">
                        ${escapeHtml(draft.hostname)} — ${draft.line_count} line(s) (${escapeHtml(draft.source)})
                    </option>
                `),
            ].join("");

            const preserved = previousValues[device.ip];
            const initialValue = preserved !== undefined
                ? preserved
                : (autoSelected ? autoSelected.content : "");

            return `
                <div class="config-push-device" data-ip="${escapeHtml(device.ip)}">
                    <div class="config-push-device-header">
                        <strong>${escapeHtml(device.hostname || device.ip)}</strong>
                        <span>${escapeHtml(device.ip)} · ${escapeHtml(device.vendor)} ${escapeHtml(device.platform)}</span>
                    </div>
                    <select class="config-push-draft-picker" data-ip="${escapeHtml(device.ip)}">
                        ${optionsHtml}
                    </select>
                    <textarea
                        class="config-push-draft-text"
                        data-ip="${escapeHtml(device.ip)}"
                        rows="8"
                        placeholder="Paste the draft config for this device, or pick a saved draft above."
                    >${escapeHtml(initialValue)}</textarea>
                </div>
            `;

        }).join("");

    }

    checklistContainer.addEventListener("change", event => {

        if (!event.target.classList.contains("config-push-select-checkbox")) {
            return;
        }

        const ip = event.target.value;

        if (event.target.checked) {
            selectedIPs.add(ip);
        } else {
            selectedIPs.delete(ip);
        }

        renderDraftAssignments();

    });

    draftListContainer.addEventListener("change", event => {

        const picker = event.target.closest(".config-push-draft-picker");
        if (!picker) {
            return;
        }

        const draft = allDrafts.find(item => item.id === picker.value);

        const textarea = picker.closest(".config-push-device")?.querySelector(".config-push-draft-text");
        if (textarea) {
            textarea.value = draft ? draft.content : "";
        }

    });

    async function loadDevicesAndDrafts() {

        devicesStatus.textContent = "Loading devices…";

        try {

            const [deviceData, draftData] = await Promise.all([
                apiRequest("/lifecycle/api/devices"),
                apiRequest("/lifecycle/api/config-drafts"),
            ]);

            allDevices = deviceData.devices || [];
            allDrafts = draftData.drafts || [];

            // Drop any selection that no longer corresponds to a known device
            // (e.g. it was cleared from Discovery since the last load).
            const knownIPs = new Set(allDevices.map(device => device.ip));
            Array.from(selectedIPs).forEach(ip => {
                if (!knownIPs.has(ip)) {
                    selectedIPs.delete(ip);
                }
            });

            devicesStatus.textContent =
                allDevices.length === 0
                    ? "No devices discovered yet."
                    : `${allDevices.length} device${allDevices.length === 1 ? "" : "s"} available.`;

            renderChecklist();
            renderDraftAssignments();

        } catch (error) {

            devicesStatus.textContent = "Failed to load devices.";
            window.NES.toast(error.message, "error");

        }

    }

    refreshDevicesButton?.addEventListener("click", loadDevicesAndDrafts);

    createJobButton.addEventListener("click", async () => {

        const configs = {};
        const missing = [];

        draftListContainer.querySelectorAll(".config-push-draft-text").forEach(textarea => {
            const value = textarea.value.trim();
            if (value) {
                configs[textarea.dataset.ip] = value;
            } else {
                missing.push(textarea.dataset.ip);
            }
        });

        if (Object.keys(configs).length === 0) {
            window.NES.toast("Select at least one device and provide a draft config.", "error");
            return;
        }

        if (missing.length) {
            window.NES.toast(`Provide a draft config for every selected device (missing: ${missing.join(", ")}).`, "error");
            return;
        }

        createJobButton.disabled = true;
        createJobButton.textContent = "Creating...";

        try {

            await apiRequest(
                "/lifecycle/api/jobs",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        type: "config_push",
                        devices: Array.from(selectedIPs),
                        configs,
                    }),
                }
            );

            window.NES.toast("Config push job created — run Pre-Check on the Upgrade Jobs page when ready.");

            selectedIPs.clear();
            renderChecklist();
            renderDraftAssignments();

        } catch (error) {

            window.NES.toast(error.message, "error");

        } finally {

            createJobButton.disabled = selectedIPs.size === 0;
            createJobButton.textContent = "Create Config Push Job";

        }

    });


    // ========================================================
    // INITIAL LOAD
    // ========================================================


    async function syncDemoBadge() {

        try {

            const settings = await apiRequest("/lifecycle/api/settings");
            const badge = document.getElementById("config-push-demo-badge");

            if (badge) {
                badge.classList.toggle("hidden", settings.demo_mode === false);
            }

        } catch (error) {
            // Non-critical -- leave the badge as shipped in the template.
        }

    }

    syncDemoBadge();
    loadDevicesAndDrafts();

});
