// Live Logs -- suite-wide page (see routes.py live_logs_page()).
//
// Merges two sources Keystone already produces, without touching
// either one's own backend:
//   - Lifecycle Manager jobs (upgrade + config_push), via the
//     existing GET /lifecycle/api/jobs poll and the existing generic
//     GET /lifecycle/api/jobs/<id>/stream SSE endpoint (stream_job()
//     in features/lifecycle_manager/routes.py -- unchanged).
//   - ZTP's activity feed, via its existing GET /ztp/api/activity
//     poll (features/ztp/routes.py ztp_activity() -- unchanged),
//     the exact same since_id-cursor pattern the ZTP tab itself uses
//     (features/ztp/static/js/app.js pollZtpActivity()).
//
// This used to be a tab embedded inside Lifecycle Manager's own
// index.html/app.js. It moved out here so it can show ALL of the
// suite's live activity in one place instead of just one module's --
// Configuration Studio, Wireless Analyzer and Switch Analyzer don't
// emit anything structured yet, so they're not represented; add them
// the same way (a source in SOURCES below) once they do.
(function () {
    "use strict";

    // ------------------------------------------------------------------
    // Shared helpers -- this page loads standalone (its own <script>,
    // not features/lifecycle_manager/static/js/app.js), so these are
    // self-contained copies rather than imports, matching how
    // config_push.js already duplicates apiRequest()/escapeHtml()
    // instead of sharing app.js's.
    // ------------------------------------------------------------------

    async function apiRequest(url, options = {}) {
        const response = await fetch(url, {
            headers: { "Content-Type": "application/json" },
            ...options,
        });
        let data = null;
        try {
            data = await response.json();
        } catch (error) {
            data = null;
        }
        if (!response.ok || !data || data.success === false) {
            const message = (data && (data.error || data.message)) || `Request failed (${response.status})`;
            throw new Error(message);
        }
        return data;
    }

    function escapeHtml(value) {
        return String(value ?? "").replace(/[&<>"']/g, char => ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#39;",
        }[char]));
    }

    function cssEscape(value) {
        if (window.CSS && typeof window.CSS.escape === "function") {
            return window.CSS.escape(value);
        }
        return String(value).replace(/["\\]/g, "\\$&");
    }

    function formatLogTime(timestamp) {
        if (!timestamp) {
            return "--:--:--";
        }
        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) {
            return "--:--:--";
        }
        return date.toLocaleTimeString([], { hour12: false });
    }

    function formatUnixTime(unixSeconds) {
        const date = new Date(unixSeconds * 1000);
        return date.toLocaleTimeString([], { hour12: false });
    }

    function getJobStatusClass(status) {
        if (status === "ready") return "job-status-ready";
        if (status === "completed") return "job-status-completed";
        if (status === "precheck_failed" || status === "failed") return "job-status-failed";
        if (status === "running") return "job-status-running";
        if (status === "prechecking") return "job-status-running";
        return "job-status-ready";
    }

    // Live Logs only WATCHES jobs -- Run Pre-Check / Start live on the
    // Upgrade Jobs page's job cards (features/lifecycle_manager/static
    // /js/app.js's .run-precheck-button / .start-upgrade-button). A job
    // sitting at one of these statuses has an empty device/log panel
    // not because anything is broken, but because nobody has taken
    // that next step yet -- say so plainly instead of leaving the rail
    // and console looking like a job that's simply slow to report in.
    function getNotStartedHint(status) {
        if (status === "pending") {
            return {
                rail: "Needs Pre-Check",
                console: "This job hasn't started yet. Go to <strong>Upgrade Jobs</strong> and click <strong>Run Pre-Check</strong> on this job's card to begin.",
            };
        }
        if (status === "precheck_failed") {
            return {
                rail: "Pre-Check failed",
                console: "Pre-Check failed for this job. Go to <strong>Upgrade Jobs</strong>, check what failed, and click <strong>Run Pre-Check</strong> again.",
            };
        }
        if (status === "ready") {
            return {
                rail: "Ready -- not started",
                console: "Pre-Check passed, but this job hasn't been started yet. Go to <strong>Upgrade Jobs</strong> and click <strong>Start Upgrade</strong> / <strong>Start Config Push</strong> on this job's card to begin.",
            };
        }
        return null;
    }

    // Same markup/behavior as features/lifecycle_manager/static/js
    // /app.js's renderLiveCommandPanel() -- config_push jobs' live
    // per-command results, one panel per device.
    function renderLiveCommandPanel(device) {
        const results = device.live_command_results || [];
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
                <div class="live-command-list" data-ip="${escapeHtml(device.ip || "")}">
                    ${rows}
                </div>
            </div>
        `;
    }

    // Same markup/behavior as app.js's renderExecutionLogPanel() -- ""
    // when the job has no log lines yet.
    function renderExecutionLogPanel(job) {
        const logs = job.logs || [];
        if (!logs.length) {
            return "";
        }
        return `
            <div class="execution-log-panel">
                <div class="execution-log-title">
                    Execution Log
                </div>
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

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    const ZTP_SOURCE_ID = "__ztp__";
    const ZTP_MAX_ENTRIES = 400;

    let selectedSourceId = null; // a job id, or ZTP_SOURCE_ID
    let jobsCache = [];
    let jobsPollTimer = null;

    let liveLogsSource = null; // EventSource for the selected LM job
    let liveLogsStreamedJobId = null;

    let ztpEvents = []; // accumulated buffer, id-ordered, capped
    let ztpLastId = 0;
    let ztpPollTimer = null;

    // ------------------------------------------------------------------
    // Lifecycle Manager job stream (SSE) -- same contract as before:
    // one EventSource for whichever job is currently selected.
    // ------------------------------------------------------------------

    function closeLiveLogsStream() {
        if (liveLogsSource) {
            liveLogsSource.close();
            liveLogsSource = null;
            liveLogsStreamedJobId = null;
        }
    }

    function openLiveLogsStream(jobId) {
        if (liveLogsStreamedJobId === jobId || typeof EventSource === "undefined") {
            return;
        }
        closeLiveLogsStream();

        const source = new EventSource(`/lifecycle/api/jobs/${jobId}/stream`);

        source.addEventListener("log", event => {
            if (selectedSourceId !== jobId) {
                return;
            }
            let entry;
            try {
                entry = JSON.parse(event.data);
            } catch (error) {
                return;
            }
            const list = document.querySelector(
                `#live-logs-console .execution-log-list[data-job-id="${cssEscape(jobId)}"]`
            );
            if (!list) {
                // No log panel rendered yet for this job -- the next
                // poll tick builds the panel from scratch out of the
                // authoritative job.logs, which already includes this
                // entry, so there is nothing to patch in by hand here.
                return;
            }
            const row = document.createElement("div");
            row.className = `execution-log-line ${entry.level || "info"}`;
            row.innerHTML = `
                <span>${escapeHtml(formatLogTime(entry.timestamp))}</span>
                <strong>${escapeHtml(entry.message || "")}</strong>
            `;
            list.appendChild(row);
            list.scrollTop = list.scrollHeight;
        });

        source.addEventListener("command_result", event => {
            if (selectedSourceId !== jobId) {
                return;
            }
            let result;
            try {
                result = JSON.parse(event.data);
            } catch (error) {
                return;
            }
            const list = document.querySelector(
                `#live-logs-console .live-logs-device[data-ip="${cssEscape(result.ip || "")}"] .live-command-list`
            );
            if (!list) {
                return;
            }
            const empty = list.querySelector(".live-command-empty");
            if (empty) {
                empty.remove();
            }
            const ok = result.status === "success";
            const row = document.createElement("div");
            row.className = `live-command-row ${ok ? "success" : "failed"}`;
            row.innerHTML = `
                <span class="live-command-icon">${ok ? "\u2713" : "\u2715"}</span>
                <div>
                    <span class="live-command-line-text">${escapeHtml(result.line || "")}</span>
                    ${
                        !ok && result.output
                            ? `<div class="live-command-output">${escapeHtml(result.output)}</div>`
                            : ""
                    }
                </div>
            `;
            list.appendChild(row);
            list.scrollTop = list.scrollHeight;
        });

        source.addEventListener("done", () => {
            if (liveLogsStreamedJobId === jobId) {
                closeLiveLogsStream();
            }
        });

        source.addEventListener("error", () => {
            if (liveLogsStreamedJobId === jobId) {
                closeLiveLogsStream();
            }
        });

        liveLogsSource = source;
        liveLogsStreamedJobId = jobId;
    }

    // ------------------------------------------------------------------
    // Rail -- one pinned "ZTP Activity Feed" entry, then the Lifecycle
    // Manager jobs list (running/prechecking first, newest next).
    // ------------------------------------------------------------------

    function renderRail() {
        const rail = document.getElementById("live-logs-job-rail");
        if (!rail) {
            return;
        }

        const ztpSelected = selectedSourceId === ZTP_SOURCE_ID;
        const ztpItem = `
            <button
                type="button"
                class="live-logs-job-item ${ztpSelected ? "active" : ""}"
                data-source-id="${ZTP_SOURCE_ID}"
            >
                <span class="live-logs-job-type type-ztp">ZTP</span>
                <strong class="live-logs-job-name">ZTP Activity Feed</strong>
                <span class="live-logs-ztp-indicator">SFTP &middot; DHCP &middot; Syslog</span>
            </button>
        `;

        let jobsHtml;
        if (!jobsCache.length) {
            jobsHtml = `<div class="empty-state">No upgrade or config push jobs yet.</div>`;
        } else {
            const sorted = [...jobsCache].sort((a, b) => {
                const aRunning = a.status === "running" || a.status === "prechecking";
                const bRunning = b.status === "running" || b.status === "prechecking";
                if (aRunning !== bRunning) {
                    return aRunning ? -1 : 1;
                }
                return String(b.created_at || "").localeCompare(String(a.created_at || ""));
            });
            jobsHtml = sorted.map(job => {
                const isConfigPush = job.type === "config_push";
                const isSelected = job.id === selectedSourceId;
                const hint = getNotStartedHint(job.status);
                return `
                    <button
                        type="button"
                        class="live-logs-job-item ${isSelected ? "active" : ""}"
                        data-source-id="${escapeHtml(job.id)}"
                    >
                        <span class="live-logs-job-type ${isConfigPush ? "type-config-push" : "type-upgrade"}">
                            ${isConfigPush ? "Config Push" : "Upgrade"}
                        </span>
                        <strong class="live-logs-job-name">${escapeHtml(job.name)}</strong>
                        ${hint ? `<span class="live-logs-job-hint">${escapeHtml(hint.rail)}</span>` : ""}
                        <span class="status-badge ${getJobStatusClass(job.status)}">${escapeHtml(job.status)}</span>
                    </button>
                `;
            }).join("");
        }

        rail.innerHTML = `
            <div class="live-logs-rail-section-label">Live sources</div>
            ${ztpItem}
            <div class="live-logs-rail-section-label">Jobs</div>
            ${jobsHtml}
        `;

        rail.querySelectorAll(".live-logs-job-item").forEach(item => {
            item.addEventListener("click", () => {
                selectSource(item.dataset.sourceId);
            });
        });
    }

    function selectSource(sourceId) {
        if (selectedSourceId === sourceId) {
            return;
        }
        selectedSourceId = sourceId;
        renderRail();
        renderConsole();
    }

    // ------------------------------------------------------------------
    // Console -- branches on what's selected.
    // ------------------------------------------------------------------

    function renderConsole() {
        if (selectedSourceId === ZTP_SOURCE_ID) {
            closeLiveLogsStream();
            renderZtpConsole();
            return;
        }
        renderJobConsole();
    }

    function renderJobConsole() {
        const panel = document.getElementById("live-logs-console");
        if (!panel) {
            return;
        }

        const job = jobsCache.find(item => item.id === selectedSourceId);

        if (!job) {
            panel.innerHTML = `
                <div class="live-logs-console-empty">
                    Pick a source on the left to watch it live.
                </div>
            `;
            delete panel.dataset.currentJobId;
            return;
        }

        // Preserve scroll position across poll-driven re-renders of the
        // SAME job -- but not across switching to a DIFFERENT job, where
        // a stale scrollTop from the previous job's panel would land on
        // the new job's freshly built (and unrelated) panel instead.
        const isSameJob = panel.dataset.currentJobId === job.id;
        const scrollState = new Map();
        if (isSameJob) {
            panel.querySelectorAll("[data-scroll-key]").forEach(el => {
                scrollState.set(el.dataset.scrollKey, {
                    followTail: el.scrollHeight - el.scrollTop - el.clientHeight <= 40,
                    scrollTop: el.scrollTop,
                });
            });
        }

        const isConfigPush = job.type === "config_push";
        const devices = job.devices || [];

        const deviceSections = isConfigPush
            ? devices.map(device => {
                const commandPanel = renderLiveCommandPanel(device);
                if (!commandPanel) {
                    return "";
                }
                return `
                    <div class="live-logs-device" data-ip="${escapeHtml(device.ip || "")}">
                        <div class="live-logs-device-head">
                            <strong>${escapeHtml(device.hostname || device.ip || "device")}</strong>
                            <span>${escapeHtml(device.ip || "")}</span>
                        </div>
                        ${commandPanel}
                    </div>
                `;
            }).join("")
            : "";

        const logPanel = renderExecutionLogPanel(job);
        const notStartedHint = getNotStartedHint(job.status);
        const notice = notStartedHint
            ? `<div class="live-logs-not-started-notice">${notStartedHint.console}</div>`
            : "";

        panel.innerHTML = `
            <div class="live-logs-console-head">
                <div>
                    <strong>${escapeHtml(job.name)}</strong>
                    <span class="live-logs-job-type ${isConfigPush ? "type-config-push" : "type-upgrade"}">
                        ${isConfigPush ? "Config Push" : "Upgrade"}
                    </span>
                </div>
                <span class="status-badge ${getJobStatusClass(job.status)}">${escapeHtml(job.status)}</span>
            </div>
            <div class="live-logs-console-body">
                ${notice}
                ${deviceSections}
                ${logPanel}
                ${
                    !deviceSections && !logPanel && !notice
                        ? `<div class="live-logs-console-empty">Waiting for this job to start producing output&hellip;</div>`
                        : ""
                }
            </div>
        `;
        panel.dataset.currentJobId = job.id;

        panel.querySelectorAll(".live-command-list, .execution-log-list").forEach(el => {
            const deviceAncestor = el.closest("[data-ip]");
            const key = deviceAncestor ? `device:${deviceAncestor.dataset.ip}` : "log";
            el.dataset.scrollKey = key;
            const previous = scrollState.get(key);
            if (!previous || previous.followTail) {
                el.scrollTop = el.scrollHeight;
            } else {
                el.scrollTop = previous.scrollTop;
            }
        });

        if (job.status === "running" || job.status === "prechecking") {
            openLiveLogsStream(job.id);
        } else {
            closeLiveLogsStream();
        }
    }

    // Same entry markup/classes as the ZTP tab itself
    // (features/ztp/static/js/app.js renderZtpActivityEntry() /
    // features/lifecycle_manager/static/css/style.css
    // .ztp-activity-entry*) so this looks identical there and here.
    function renderZtpEntry(event) {
        const el = document.createElement("div");
        el.className = `ztp-activity-entry ztp-activity-entry-level-${escapeHtml(event.level)}`;
        el.innerHTML = `
            <span class="ztp-activity-entry-time">${formatUnixTime(event.ts)}</span>
            <span class="ztp-activity-entry-source ztp-activity-entry-source-${escapeHtml(event.source)}">${escapeHtml(event.source)}</span>
            ${event.esn ? `<span class="ztp-activity-entry-esn">${escapeHtml(event.esn)}</span>` : ""}
            <span class="ztp-activity-entry-message">${escapeHtml(event.message)}</span>
        `;
        return el;
    }

    function renderZtpConsole() {
        const panel = document.getElementById("live-logs-console");
        if (!panel) {
            return;
        }

        panel.innerHTML = `
            <div class="live-logs-console-head">
                <div>
                    <strong>ZTP Activity Feed</strong>
                    <span class="live-logs-job-type type-ztp">ZTP</span>
                </div>
                <button type="button" id="live-logs-ztp-clear" class="button button-secondary">Clear</button>
            </div>
            <div class="live-logs-console-body">
                <div id="live-logs-ztp-log" class="ztp-activity-log">
                    ${
                        ztpEvents.length
                            ? ""
                            : `<div class="empty-state">Nothing yet -- start a ZTP support server and power on a switch to see activity here.</div>`
                    }
                </div>
            </div>
        `;
        delete panel.dataset.currentJobId;

        const log = document.getElementById("live-logs-ztp-log");
        if (log) {
            ztpEvents.forEach(event => {
                log.appendChild(renderZtpEntry(event));
            });
            log.scrollTop = log.scrollHeight;
        }

        const clearButton = document.getElementById("live-logs-ztp-clear");
        if (clearButton) {
            clearButton.addEventListener("click", async () => {
                try {
                    await apiRequest("/ztp/api/activity/clear", { method: "POST" });
                    ztpEvents = [];
                    ztpLastId = 0;
                    if (selectedSourceId === ZTP_SOURCE_ID) {
                        renderZtpConsole();
                    }
                } catch (error) {
                    // Non-fatal -- the feed just keeps whatever it already has.
                }
            });
        }
    }

    // ------------------------------------------------------------------
    // Polling loops -- Lifecycle Manager jobs list (drives the rail +
    // the selected job's console) and the ZTP activity feed (always
    // accumulating in the background, same as the ZTP tab itself does
    // while its page is open, so switching to it shows recent history
    // immediately instead of waiting for the next tick).
    // ------------------------------------------------------------------

    async function refreshJobs() {
        try {
            const data = await apiRequest("/lifecycle/api/jobs");
            jobsCache = data.jobs || [];

            if (!selectedSourceId) {
                const activeJob = jobsCache.find(job => job.status === "running" || job.status === "prechecking");
                if (activeJob) {
                    selectedSourceId = activeJob.id;
                } else if (jobsCache.length) {
                    selectedSourceId = jobsCache[0].id;
                } else {
                    selectedSourceId = ZTP_SOURCE_ID;
                }
            }

            renderRail();
            if (selectedSourceId !== ZTP_SOURCE_ID) {
                renderJobConsole();
            }
        } catch (error) {
            console.error(error);
        }
    }

    async function pollZtpActivity() {
        try {
            const data = await apiRequest(`/ztp/api/activity?since_id=${ztpLastId}`);
            const events = data.events || [];
            if (!events.length) {
                return;
            }

            const wasOnZtp = selectedSourceId === ZTP_SOURCE_ID;
            const log = wasOnZtp ? document.getElementById("live-logs-ztp-log") : null;
            const wasScrolledToBottom = log
                ? log.scrollHeight - log.scrollTop - log.clientHeight < 40
                : true;
            const emptyState = log ? log.querySelector(".empty-state") : null;
            if (emptyState) {
                emptyState.remove();
            }

            events.forEach(event => {
                ztpEvents.push(event);
                ztpLastId = Math.max(ztpLastId, event.id);
                if (log) {
                    log.appendChild(renderZtpEntry(event));
                }
            });

            if (ztpEvents.length > ZTP_MAX_ENTRIES) {
                ztpEvents = ztpEvents.slice(-ZTP_MAX_ENTRIES);
            }
            while (log && log.children.length > ZTP_MAX_ENTRIES) {
                log.removeChild(log.firstChild);
            }

            if (log && wasScrolledToBottom) {
                log.scrollTop = log.scrollHeight;
            }
        } catch (error) {
            // Non-fatal -- just try again on the next tick.
        }
    }

    function start() {
        renderRail();
        renderConsole();
        refreshJobs();
        pollZtpActivity();
        jobsPollTimer = setInterval(refreshJobs, 2000);
        ztpPollTimer = setInterval(pollZtpActivity, 2000);
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start);
    } else {
        start();
    }
})();
