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
    // CONFIG BACKUP
    //
    // Own top-level page for capturing a read-only snapshot
    // (CONFIG_CAPTURE_COMMANDS -- a fixed ~40-command list, see
    // config_capture_engine.py) from devices already in DEVICES_FILE
    // -- independent of ZTP, firmware upgrades, and Config Push. Two
    // steps, both self-contained on this page: pick devices and click
    // Capture Config to create the job (created straight into
    // "ready" -- capture is read-only, so there is no Pre-Check
    // stage), then Start Capture in the job list below to actually
    // run it and download the resulting backup bundle.
    // ========================================================

    let allDevices = [];
    const selectedIPs = new Set();

    const checklistContainer = document.getElementById("config-backup-device-checklist");
    const devicesStatus = document.getElementById("config-backup-devices-status");
    const selectedCountEl = document.getElementById("config-backup-selected-count");
    const createJobButton = document.getElementById("config-backup-create-job-button");
    const refreshDevicesButton = document.getElementById("config-backup-refresh-devices");
    const checkReachabilityButton = document.getElementById("config-backup-check-reachability");
    const reachabilityStatusEl = document.getElementById("config-backup-reachability-status");

    function formatRelativeTime(timestamp) {

        if (!timestamp) {
            return "";
        }

        const then = new Date(timestamp).getTime();
        if (Number.isNaN(then)) {
            return "";
        }

        const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
        if (seconds < 5) {
            return "just now";
        }
        if (seconds < 60) {
            return `${seconds}s ago`;
        }
        const minutes = Math.round(seconds / 60);
        if (minutes < 60) {
            return `${minutes}m ago`;
        }
        const hours = Math.round(minutes / 60);
        if (hours < 24) {
            return `${hours}h ago`;
        }
        return `${Math.round(hours / 24)}d ago`;

    }

    function renderReachabilityBadge(device) {

        // Discovery's own "online" status is a snapshot from whenever
        // that IP range was last scanned, with no timestamp recorded --
        // there is no way to tell how stale it is from the device list
        // alone. This badge is deliberately separate: it only reflects
        // an explicit Check Reachability click, and always shows how
        // long ago that was, so "reachable" here never gets mistaken
        // for a live/continuous status.
        if (!device.reachability_checked_at) {
            return "";
        }

        const badgeClass = device.reachable ? "job-status-completed" : "job-status-failed";
        const label = device.reachable ? "Reachable" : "Unreachable";
        const relative = formatRelativeTime(device.reachability_checked_at);

        return `
            <span class="status-badge ${badgeClass}" title="Checked ${escapeHtml(relative)}">
                ${label} · ${escapeHtml(relative)}
            </span>
        `;

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
                ${renderReachabilityBadge(device)}
            </label>
        `).join("");

    }

    function syncSelectedCount() {

        const count = selectedIPs.size;
        selectedCountEl.textContent = `${count} device${count === 1 ? "" : "s"} selected`;
        createJobButton.disabled = count === 0;

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

        syncSelectedCount();

    });

    async function loadDevices() {

        devicesStatus.textContent = "Loading devices…";

        try {

            const deviceData = await apiRequest("/lifecycle/api/devices");
            allDevices = deviceData.devices || [];

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
            syncSelectedCount();

        } catch (error) {

            devicesStatus.textContent = "Failed to load devices.";
            window.NES.toast(error.message, "error");

        }

    }

    refreshDevicesButton?.addEventListener("click", loadDevices);

    checkReachabilityButton?.addEventListener("click", async () => {

        if (allDevices.length === 0) {
            window.NES.toast("No devices to check yet.", "error");
            return;
        }

        checkReachabilityButton.disabled = true;
        checkReachabilityButton.textContent = "Checking...";
        if (reachabilityStatusEl) {
            reachabilityStatusEl.textContent = `Checking ${allDevices.length} device(s)...`;
        }

        try {

            const data = await apiRequest("/lifecycle/api/devices/check-reachability", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ips: allDevices.map(device => device.ip) }),
            });

            const byIp = new Map((data.devices || []).map(device => [device.ip, device]));
            allDevices = allDevices.map(device => byIp.get(device.ip) || device);
            renderChecklist();

            const reachableCount = Object.values(data.results || {}).filter(Boolean).length;
            const totalChecked = Object.keys(data.results || {}).length;
            if (reachabilityStatusEl) {
                reachabilityStatusEl.textContent =
                    `${reachableCount}/${totalChecked} reachable just now`;
            }

            window.NES.toast(`Checked ${totalChecked} device(s) — ${reachableCount} reachable.`);

        } catch (error) {

            window.NES.toast(error.message, "error");
            if (reachabilityStatusEl) {
                reachabilityStatusEl.textContent = "";
            }

        } finally {

            checkReachabilityButton.disabled = false;
            checkReachabilityButton.textContent = "Check Reachability";

        }

    });

    createJobButton.addEventListener("click", async () => {

        if (selectedIPs.size === 0) {
            window.NES.toast("Select at least one device.", "error");
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
                        type: "config_capture",
                        devices: Array.from(selectedIPs),
                    }),
                }
            );

            window.NES.toast("Config capture job created — click Start Capture below when ready.");

            selectedIPs.clear();
            renderChecklist();
            syncSelectedCount();
            refreshConfigBackupJobs();

        } catch (error) {

            window.NES.toast(error.message, "error");

        } finally {

            createJobButton.disabled = selectedIPs.size === 0;
            createJobButton.textContent = "Capture Config";

        }

    });


    // ========================================================
    // CONFIG BACKUP JOBS
    // ========================================================

    let configBackupJobs = [];
    let configBackupPollTimer = null;

    const jobListContainer = document.getElementById("config-backup-job-list");
    const jobsStatusEl = document.getElementById("config-backup-jobs-status");

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
                        <span class="live-command-icon">${ok ? "✓" : "✕"}</span>
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

    function renderConfigBackupJobs() {

        if (!jobListContainer) {
            return;
        }

        if (configBackupJobs.length === 0) {

            jobListContainer.innerHTML = `
                <div class="empty-state">No config backup jobs yet. Create one above.</div>
            `;

            return;

        }

        const logScrollState = new Map();
        jobListContainer.querySelectorAll(".execution-log-list[data-job-id]").forEach(panel => {
            const distanceFromBottom = panel.scrollHeight - panel.scrollTop - panel.clientHeight;
            logScrollState.set(panel.dataset.jobId, {
                followTail: distanceFromBottom <= 40,
                scrollTop: panel.scrollTop,
            });
        });

        jobListContainer.innerHTML = configBackupJobs.map(job => {

            const progress = calculateJobProgress(job);
            const canStart = job.status === "ready";
            const devices = job.devices || [];

            return `
                <div class="job-card" data-job-id="${escapeHtml(job.id)}" data-job-type="config_capture">

                    <div class="job-card-header">

                        <div>
                            <strong>${escapeHtml(job.name)}</strong>
                            <span>${escapeHtml(job.created_at)}</span>
                        </div>

                        <div class="job-actions">

                            <span class="status-badge ${getJobStatusClass(job.status)}">${escapeHtml(job.status)}</span>

                            ${
                                canStart
                                    ? `<button type="button" class="button button-primary button-small cb-job-start-button" data-job-id="${escapeHtml(job.id)}">Start Capture</button>`
                                    : ""
                            }

                            <button type="button" class="button button-danger button-small cb-job-delete-button" data-job-id="${escapeHtml(job.id)}">Delete</button>

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

                    ${devices.map(device => {

                        const bundle = device.capture_bundle;

                        return `
                            <div class="job-device-row" data-ip="${escapeHtml(device.ip)}">

                                <div>
                                    <strong>${escapeHtml(device.hostname)}</strong>
                                    <div>${escapeHtml(device.ip)}</div>
                                </div>

                                <div>${escapeHtml(device.model)}</div>
                                <div>${escapeHtml(device.current_version)}</div>
                                <div></div>

                                <div class="job-stage execution-stage">
                                    ${device.status === "running" ? `<span class="execution-running-dot"></span>` : ""}
                                    ${device.status === "completed" ? `<span class="completed-check">✓</span>` : ""}
                                    <span>${escapeHtml(device.stage)}</span>
                                    ${
                                        bundle
                                            ? `<a class="button button-secondary button-small" href="/lifecycle/api/jobs/${encodeURIComponent(job.id)}/devices/${encodeURIComponent(device.ip)}/backup">Download Backup${bundle.failed_count ? ` (${bundle.failed_count} failed)` : ""}</a>`
                                            : ""
                                    }
                                </div>

                            </div>

                            ${renderLiveCommandPanel(device)}
                        `;

                    }).join("")}

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

    async function refreshConfigBackupJobs() {

        try {

            const data = await apiRequest("/lifecycle/api/jobs");
            configBackupJobs = (data.jobs || []).filter(job => job.type === "config_capture");

            if (jobsStatusEl) {
                jobsStatusEl.textContent = configBackupJobs.length
                    ? `${configBackupJobs.length} config backup job${configBackupJobs.length === 1 ? "" : "s"}.`
                    : "Jobs you create above show up here — capture, then download the bundle.";
            }

            renderConfigBackupJobs();

            const stillActive = configBackupJobs.some(job => job.status === "running");
            if (!stillActive && configBackupPollTimer) {
                clearInterval(configBackupPollTimer);
                configBackupPollTimer = null;
            }

        } catch (error) {

            if (jobsStatusEl) {
                jobsStatusEl.textContent = "Failed to load config backup jobs.";
            }
            console.error(error);

        }

    }

    function startConfigBackupJobPolling() {

        if (configBackupPollTimer) {
            return;
        }

        configBackupPollTimer = setInterval(refreshConfigBackupJobs, 1500);

    }

    jobListContainer?.addEventListener("click", async event => {

        const startButton = event.target.closest(".cb-job-start-button");

        if (startButton) {

            const jobId = startButton.dataset.jobId;

            const confirmed = confirm("Run the full capture command set against every device in this job?");
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
                            ? `Enter SSH password for '${sshUsername}' (this capture is read-only -- nothing on the device changes). Check Settings if this username is wrong.`
                            : "Enter SSH password for this capture. No SSH username is set in Settings yet, so login will fail — set it in Settings first."
                    );

                    if (password === null) {
                        startButton.disabled = false;
                        startButton.textContent = "Start Capture";
                        return;
                    }

                    if (!password) {
                        throw new Error("SSH password is required for a real config capture.");
                    }

                }

                await apiRequest(`/lifecycle/api/jobs/${jobId}/start`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password }),
                });

                await refreshConfigBackupJobs();
                startConfigBackupJobPolling();

                window.NES.toast("Config capture started.");

            } catch (error) {

                window.NES.toast(error.message, "error");
                await refreshConfigBackupJobs();

            }

            return;

        }

        const deleteButton = event.target.closest(".cb-job-delete-button");

        if (deleteButton) {

            const confirmed = confirm("Delete this config backup job?");
            if (!confirmed) {
                return;
            }

            try {

                await apiRequest(`/lifecycle/api/jobs/${deleteButton.dataset.jobId}`, { method: "DELETE" });
                await refreshConfigBackupJobs();

                window.NES.toast("Config backup job deleted.");

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
            const badge = document.getElementById("config-backup-demo-badge");

            if (badge) {
                badge.classList.toggle("hidden", settings.demo_mode === false);
            }

        } catch (error) {
            // Non-critical -- leave the badge as shipped in the template.
        }

    }

    syncDemoBadge();
    loadDevices();
    refreshConfigBackupJobs().then(() => {
        if (configBackupJobs.some(job => job.status === "running")) {
            startConfigBackupJobPolling();
        }
    });

});
