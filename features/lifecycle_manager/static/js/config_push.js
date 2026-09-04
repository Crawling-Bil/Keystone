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

            window.NES.toast("Config push job created — run its Pre-Check below when ready.");

            selectedIPs.clear();
            renderChecklist();
            renderDraftAssignments();
            refreshConfigPushJobs();

        } catch (error) {

            window.NES.toast(error.message, "error");

        } finally {

            createJobButton.disabled = selectedIPs.size === 0;
            createJobButton.textContent = "Create Config Push Job";

        }

    });


    // ========================================================
    // CONFIG PUSH JOBS
    //
    // Self-contained job list for this page: create (above), Pre-Check,
    // and Start all happen right here -- a config_push job never needs a
    // detour through the Upgrade Jobs page. Backend is unchanged and
    // already generic across job types (POST .../precheck, .../start,
    // DELETE .../<id>); this only adds the UI for it. Markup/classes are
    // deliberately copied from app.js's own job-card rendering (job-card,
    // job-device-row, precheck-result, live-command-panel,
    // execution-log-panel, status-badge/job-status-*) so a config_push
    // job looks identical here to how it looks on Upgrade Jobs / Live
    // Logs -- all three read the exact same job record.
    // ========================================================

    let configPushJobs = [];
    let configPushPollTimer = null;

    const jobListContainer = document.getElementById("config-push-job-list");
    const jobsStatusEl = document.getElementById("config-push-jobs-status");

    function getJobStatusClass(status) {

        if (status === "ready") {
            return "job-status-ready";
        }

        if (status === "completed") {
            return "job-status-completed";
        }

        if (status === "precheck_failed" || status === "failed") {
            return "job-status-failed";
        }

        if (status === "prechecking" || status === "running") {
            return "job-status-running";
        }

        return "status-offline";

    }

    function calculateJobProgress(job) {

        const devices = job.devices || [];

        if (devices.length === 0) {
            return 0;
        }

        const total = devices.reduce((sum, device) => sum + Number(device.progress || 0), 0);

        return Math.round(total / devices.length);

    }

    function formatLogTime(timestamp) {

        if (!timestamp) {
            return "--:--:--";
        }

        const date = new Date(timestamp);

        if (Number.isNaN(date.getTime())) {
            return String(timestamp);
        }

        return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

    }

    function renderExecutionLogPanel(job) {

        const logs = job.logs || [];

        if (!logs.length) {
            return "";
        }

        return `
            <div class="execution-log-panel">
                <div class="execution-log-title">Execution Log</div>
                <div class="execution-log-list" data-job-id="${escapeHtml(job.id)}">
                    ${logs.map(log => `
                        <div class="execution-log-line ${escapeHtml(log.level || "info")}">
                            <span>${escapeHtml(formatLogTime(log.timestamp))}</span>
                            <strong>${escapeHtml(log.message || "")}</strong>
                        </div>
                    `).join("")}
                </div>
            </div>
        `;

    }

    function renderLiveCommandPanel(device) {

        const results = device.live_command_results || [];
        const isActive = device.status === "running";

        if (!results.length && !isActive) {
            return "";
        }

        const rows = results.length
            ? results.map(result => {
                const ok = result.status === "success";
                return `
                    <div class="live-command-row ${ok ? "success" : "failed"}">
                        <span class="live-command-icon">${ok ? "\u2713" : "\u2715"}</span>
                        <div>
                            <span class="live-command-line-text">${escapeHtml(result.line || "")}</span>
                            ${
                                !ok && result.output
                                    ? `<div class="live-command-output">${escapeHtml(result.output)}</div>`
                                    : ""
                            }
                        </div>
                    </div>
                `;
            }).join("")
            : `<div class="live-command-empty">Waiting for the first command...</div>`;

        return `
            <div class="live-command-panel">
                <div class="live-command-title">
                    ${isActive ? `<span class="live-command-live-dot"></span>` : ""}
                    Live Commands${results.length ? ` (${results.length})` : ""}
                </div>
                <div class="live-command-list">${rows}</div>
            </div>
        `;

    }

    function renderPrecheckPanel(device) {

        const precheck = device.precheck;

        if (!precheck || !precheck.checks) {
            return "";
        }

        return `
            <div class="precheck-result">
                <div class="precheck-title">Pre-Check Results - ${escapeHtml(device.hostname)}</div>
                <div class="precheck-grid">
                    ${precheck.checks.map(check => `
                        <div class="precheck-item ${escapeHtml(check.status)}">
                            <strong>${check.status === "passed" ? "\u2713" : "\u00d7"} ${escapeHtml(check.name)}</strong>
                            <span>${escapeHtml(check.message)}</span>
                        </div>
                    `).join("")}
                </div>
            </div>
        `;

    }

    function renderConfigPushJobs() {

        if (!jobListContainer) {
            return;
        }

        if (configPushJobs.length === 0) {

            jobListContainer.innerHTML = `
                <div class="empty-state">No config push jobs yet. Create one above.</div>
            `;

            return;

        }

        // Preserve execution-log scroll position across re-renders, same
        // rule as Upgrade Jobs: stay pinned to the bottom unless the
        // operator scrolled up to read something earlier.
        const logScrollState = new Map();
        jobListContainer.querySelectorAll(".execution-log-list[data-job-id]").forEach(panel => {
            const distanceFromBottom = panel.scrollHeight - panel.scrollTop - panel.clientHeight;
            logScrollState.set(panel.dataset.jobId, {
                followTail: distanceFromBottom <= 40,
                scrollTop: panel.scrollTop,
            });
        });

        jobListContainer.innerHTML = configPushJobs.map(job => {

            const progress = calculateJobProgress(job);
            const canPrecheck = ["pending", "precheck_failed"].includes(job.status);
            const canStart = job.status === "ready";
            const devices = job.devices || [];

            return `
                <div class="job-card" data-job-id="${escapeHtml(job.id)}" data-job-type="config_push">

                    <div class="job-card-header">

                        <div>
                            <strong>${escapeHtml(job.name)}</strong>
                            <span>${escapeHtml(job.created_at)}</span>
                        </div>

                        <div class="job-actions">

                            <span class="status-badge ${getJobStatusClass(job.status)}">${escapeHtml(job.status)}</span>

                            ${
                                canPrecheck
                                    ? `<button type="button" class="button button-primary button-small cp-job-precheck-button" data-job-id="${escapeHtml(job.id)}">Run Pre-Check</button>`
                                    : ""
                            }

                            ${
                                canStart
                                    ? `<button type="button" class="button button-primary button-small cp-job-start-button" data-job-id="${escapeHtml(job.id)}">Start Config Push</button>`
                                    : ""
                            }

                            <a class="button button-secondary button-small" href="/lifecycle/live-logs?job=${encodeURIComponent(job.id)}">Watch Live</a>

                            <button type="button" class="button button-danger button-small cp-job-delete-button" data-job-id="${escapeHtml(job.id)}">Delete</button>

                        </div>

                    </div>

                    <div class="job-progress-wrapper">
                        <div class="job-progress-info">
                            <span>Overall Progress</span>
                            <span>${progress}%</span>
                        </div>
                        <div class="job-progress">
                            <div class="job-progress-bar" style="width: ${progress}%"></div>
                        </div>
                    </div>

                    ${devices.map(device => `
                        <div class="job-device-row" data-ip="${escapeHtml(device.ip)}">

                            <div>
                                <strong>${escapeHtml(device.hostname)}</strong>
                                <div>${escapeHtml(device.ip)}</div>
                            </div>

                            <div>${escapeHtml(device.model)}</div>
                            <div>${escapeHtml(device.current_version)}</div>
                            <div class="target-version">${escapeHtml(device.target_version)}</div>

                            <div class="job-stage execution-stage">
                                ${device.status === "running" ? `<span class="execution-running-dot"></span>` : ""}
                                ${device.status === "completed" ? `<span class="completed-check">\u2713</span>` : ""}
                                <span>${escapeHtml(device.stage)}</span>
                            </div>

                        </div>

                        ${renderLiveCommandPanel(device)}
                        ${renderPrecheckPanel(device)}
                    `).join("")}

                    ${renderExecutionLogPanel(job)}

                </div>
            `;

        }).join("");

        jobListContainer.querySelectorAll(".execution-log-list[data-job-id]").forEach(panel => {
            const previous = logScrollState.get(panel.dataset.jobId);
            if (!previous || previous.followTail) {
                panel.scrollTop = panel.scrollHeight;
            } else {
                panel.scrollTop = previous.scrollTop;
            }
        });

    }

    async function refreshConfigPushJobs() {

        try {

            const data = await apiRequest("/lifecycle/api/jobs");
            configPushJobs = (data.jobs || []).filter(job => job.type === "config_push");

            if (jobsStatusEl) {
                jobsStatusEl.textContent = configPushJobs.length
                    ? `${configPushJobs.length} config push job${configPushJobs.length === 1 ? "" : "s"}.`
                    : "Jobs you create above show up here — Pre-Check, then start, without leaving this page.";
            }

            renderConfigPushJobs();

            const stillActive = configPushJobs.some(job => job.status === "running" || job.status === "prechecking");
            if (!stillActive && configPushPollTimer) {
                clearInterval(configPushPollTimer);
                configPushPollTimer = null;
            }

        } catch (error) {

            if (jobsStatusEl) {
                jobsStatusEl.textContent = "Failed to load config push jobs.";
            }
            console.error(error);

        }

    }

    function startConfigPushJobPolling() {

        if (configPushPollTimer) {
            return;
        }

        configPushPollTimer = setInterval(refreshConfigPushJobs, 1500);

    }

    jobListContainer?.addEventListener("click", async event => {

        const precheckButton = event.target.closest(".cp-job-precheck-button");

        if (precheckButton) {

            const jobId = precheckButton.dataset.jobId;

            precheckButton.disabled = true;
            precheckButton.textContent = "Checking...";

            let password = "";

            try {

                const settings = await apiRequest("/lifecycle/api/settings");

                if (settings.demo_mode === false) {

                    const sshUsername = settings?.ssh?.username || "";
                    password = prompt(
                        sshUsername
                            ? `Enter SSH password for '${sshUsername}' (this Pre-Check) — check Settings if this username is wrong:`
                            : "Enter SSH password for this Pre-Check — no SSH username is set in Settings yet, so login will fail. Set it in Settings first."
                    );

                    if (password === null) {
                        precheckButton.disabled = false;
                        precheckButton.textContent = "Run Pre-Check";
                        return;
                    }

                    if (!password) {
                        window.NES.toast("SSH password is required.", "error");
                        precheckButton.disabled = false;
                        precheckButton.textContent = "Run Pre-Check";
                        return;
                    }

                }

                await apiRequest(`/lifecycle/api/jobs/${jobId}/precheck`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password }),
                });

                await refreshConfigPushJobs();

                window.NES.toast("Pre-Check completed.");

            } catch (error) {

                window.NES.toast(error.message, "error");
                await refreshConfigPushJobs();

            }

            return;

        }

        const startButton = event.target.closest(".cp-job-start-button");

        if (startButton) {

            const jobId = startButton.dataset.jobId;

            const confirmed = confirm("Push the draft config to every device in this job?");
            if (!confirmed) {
                return;
            }

            startButton.disabled = true;
            startButton.textContent = "Starting...";

            try {

                const settings = await apiRequest("/lifecycle/api/settings");
                let password = "";

                if (settings.demo_mode === false) {

                    const sshUsername = settings?.ssh?.username || "";
                    password = prompt(
                        sshUsername
                            ? `REAL CONFIG PUSH: Enter SSH password for '${sshUsername}'. The draft config will be applied and saved. Check Settings if this username is wrong.`
                            : "REAL CONFIG PUSH: Enter SSH password. No SSH username is set in Settings yet, so login will fail — set it in Settings first."
                    );

                    if (password === null) {
                        startButton.disabled = false;
                        startButton.textContent = "Start Config Push";
                        return;
                    }

                    if (!password) {
                        throw new Error("SSH password is required for real config push mode.");
                    }

                    const finalConfirmation = confirm("Confirm REAL config push to these devices?");
                    if (!finalConfirmation) {
                        startButton.disabled = false;
                        startButton.textContent = "Start Config Push";
                        return;
                    }

                }

                await apiRequest(`/lifecycle/api/jobs/${jobId}/start`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password }),
                });

                await refreshConfigPushJobs();
                startConfigPushJobPolling();

                window.NES.toast("Config push started.");

            } catch (error) {

                window.NES.toast(error.message, "error");
                await refreshConfigPushJobs();

            }

            return;

        }

        const deleteButton = event.target.closest(".cp-job-delete-button");

        if (deleteButton) {

            const confirmed = confirm("Delete this config push job?");
            if (!confirmed) {
                return;
            }

            try {

                await apiRequest(`/lifecycle/api/jobs/${deleteButton.dataset.jobId}`, { method: "DELETE" });
                await refreshConfigPushJobs();

                window.NES.toast("Config push job deleted.");

            } catch (error) {

                window.NES.toast(error.message, "error");

            }

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
    refreshConfigPushJobs().then(() => {
        if (configPushJobs.some(job => job.status === "running" || job.status === "prechecking")) {
            startConfigPushJobPolling();
        }
    });

});
