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
    // ZTP PROVISIONING
    // ========================================================


    const ztpDeviceTable = document.getElementById("ztp-device-table");
    const ztpDevicesStatus = document.getElementById("ztp-devices-status");
    const ztpRegisterForm = document.getElementById("ztp-register-form");
    const ztpGenerateForm = document.getElementById("ztp-generate-form");
    const ztpGenerateResult = document.getElementById("ztp-generate-result");

    const ztpSftpStatus = document.getElementById("ztp-sftp-status");
    const ztpSftpStartButton = document.getElementById("ztp-sftp-start-button");
    const ztpSftpStopButton = document.getElementById("ztp-sftp-stop-button");

    const ztpDhcpStatus = document.getElementById("ztp-dhcp-status");
    const ztpDhcpStartButton = document.getElementById("ztp-dhcp-start-button");
    const ztpDhcpStopButton = document.getElementById("ztp-dhcp-stop-button");
    const ztpDhcpConfirm = document.getElementById("ztp-dhcp-confirm");

    const ztpSyslogStatus = document.getElementById("ztp-syslog-status");
    const ztpSyslogStartButton = document.getElementById("ztp-syslog-start-button");
    const ztpSyslogStopButton = document.getElementById("ztp-syslog-stop-button");

    const ztpActivityLog = document.getElementById("ztp-activity-log");
    const ztpActivityStatus = document.getElementById("ztp-activity-status");
    const ztpActivityClearButton = document.getElementById("ztp-activity-clear-button");

    const ztpImportFileInput = document.getElementById("ztp-import-file");
    const ztpImportResult = document.getElementById("ztp-import-result");

    const ztpFirmwarePicker = document.getElementById("ztp-firmware-picker");
    const ztpSftpBindIpPicker = document.getElementById("ztp-sftp-bind-ip-picker");
    const ztpDhcpInterfacePicker = document.getElementById("ztp-dhcp-interface-picker");

    function getZtpStatusBadge(status) {

        const safeStatus = escapeHtml(status || "pending");

        let className = "status-pending";

        if (status === "provisioned") {
            className = "status-provisioned";
        }

        if (status === "failed") {
            className = "status-failed";
        }

        return `
            <span class="status-badge ${className}">
                ${safeStatus}
            </span>
        `;

    }

    function renderZtpDevices(devices) {

        if (!devices.length) {

            ztpDeviceTable.innerHTML = `
                <tr>
                    <td colspan="7" class="empty-state">No devices pre-registered yet.</td>
                </tr>
            `;

            return;

        }

        ztpDeviceTable.innerHTML = devices.map(device => `
            <tr>
                <td>${escapeHtml(device.esn)}</td>
                <td>${escapeHtml(device.hostname)}</td>
                <td>${escapeHtml(device.mac)}</td>
                <td>${escapeHtml(device.mgmt_ip)}</td>
                <td>${escapeHtml(device.site)}</td>
                <td>${getZtpStatusBadge(device.status)}</td>
                <td>
                    ${
                        device.status !== "provisioned"
                            ? `<button type="button" class="button button-secondary button-small ztp-mark-provisioned" data-esn="${escapeHtml(device.esn)}">Mark Provisioned</button>`
                            : ""
                    }
                    <button type="button" class="button button-danger button-small ztp-delete-device" data-esn="${escapeHtml(device.esn)}">Delete</button>
                </td>
            </tr>
        `).join("");

    }

    async function loadZtpDevices() {

        try {

            const data = await apiRequest("/ztp/api/devices");

            renderZtpDevices(data.devices);

            const pendingCount = data.devices.filter(d => d.status !== "provisioned").length;

            ztpDevicesStatus.textContent =
                `${data.devices.length} registered (${pendingCount} pending).`;

        } catch (error) {

            ztpDevicesStatus.textContent = "Failed to load devices.";

            window.NES.toast(error.message);

        }

    }

    ztpRegisterForm.addEventListener("submit", async event => {

        event.preventDefault();

        const registerButton = document.getElementById("ztp-register-button");

        const payload = {
            esn: document.getElementById("ztp-esn").value.trim(),
            mac: document.getElementById("ztp-mac").value.trim(),
            hostname: document.getElementById("ztp-hostname").value.trim(),
            site: document.getElementById("ztp-site").value.trim(),
            mgmt_ip: document.getElementById("ztp-mgmt-ip").value.trim(),
            mgmt_mask: document.getElementById("ztp-mgmt-mask").value.trim(),
            gateway: document.getElementById("ztp-gateway").value.trim(),
            vrp_username: document.getElementById("ztp-username").value.trim(),
            vrp_password: document.getElementById("ztp-password").value,
            firmware_filename: document.getElementById("ztp-firmware").value.trim(),
            vrp_version: document.getElementById("ztp-vrp-version").value.trim()
        };

        registerButton.disabled = true;
        registerButton.textContent = "Registering...";

        try {

            await apiRequest("/ztp/api/devices", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            window.NES.toast(`Registered ${payload.esn}.`);

            ztpRegisterForm.reset();

            document.getElementById("ztp-mgmt-mask").value = "255.255.255.0";
            document.getElementById("ztp-username").value = "ztp-admin";

            await loadZtpDevices();

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            registerButton.disabled = false;
            registerButton.textContent = "Register Device";

        }

    });

    ztpDeviceTable.addEventListener("click", async event => {

        const markButton = event.target.closest(".ztp-mark-provisioned");
        const deleteButton = event.target.closest(".ztp-delete-device");

        if (markButton) {

            try {

                await apiRequest(
                    `/ztp/api/devices/${encodeURIComponent(markButton.dataset.esn)}/status`,
                    {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ status: "provisioned" })
                    }
                );

                window.NES.toast("Marked as provisioned.");

                await loadZtpDevices();

            } catch (error) {

                window.NES.toast(error.message);

            }

            return;

        }

        if (deleteButton) {

            const confirmed = confirm(
                `Remove ${deleteButton.dataset.esn} from ZTP pre-registration?`
            );

            if (!confirmed) {
                return;
            }

            try {

                await apiRequest(
                    `/ztp/api/devices/${encodeURIComponent(deleteButton.dataset.esn)}`,
                    { method: "DELETE" }
                );

                window.NES.toast("Device removed.");

                await loadZtpDevices();

            } catch (error) {

                window.NES.toast(error.message);

            }

        }

    });

    ztpGenerateForm.addEventListener("submit", async event => {

        event.preventDefault();

        const generateButton = document.getElementById("ztp-generate-button");

        const payload = {
            fileserver_url: document.getElementById("ztp-fileserver-url").value.trim(),
            syslog_target: document.getElementById("ztp-syslog-target").value.trim()
        };

        generateButton.disabled = true;
        generateButton.textContent = "Generating...";

        ztpGenerateResult.classList.add("hidden");

        try {

            const data = await apiRequest("/ztp/api/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            ztpGenerateResult.innerHTML = `
                <strong>Generated ${escapeHtml(data.intermediate_file)} + ${data.config_files.length} config file(s)</strong>
                ${data.config_files.map(name => escapeHtml(name)).join(", ")}
                <br>Staged in: ${escapeHtml(data.staging_dir)}
            `;

            ztpGenerateResult.classList.remove("hidden");

            window.NES.toast("Deployment files generated.");

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            generateButton.disabled = false;
            generateButton.textContent = "Generate Files";

        }

    });

    async function refreshZtpSftpStatus() {

        try {

            const data = await apiRequest("/ztp/api/sftp/status");

            ztpSftpStatus.textContent = data.running ? "Running." : "Stopped.";
            ztpSftpStartButton.disabled = data.running;
            ztpSftpStopButton.disabled = !data.running;

        } catch (error) {

            ztpSftpStatus.textContent = "Status unavailable.";

        }

    }

    function fillZtpFileServerUrl(username, password, host, port) {

        const url = `sftp://${encodeURIComponent(username)}:${encodeURIComponent(password)}@${host}:${port}/`;

        document.getElementById("ztp-fileserver-url").value = url;
        document.getElementById("ztp-dhcp-option67").value = `${url}ztp_script.ini`;

    }

    ztpSftpStartButton.addEventListener("click", async () => {

        const username = document.getElementById("ztp-sftp-username").value.trim();
        const password = document.getElementById("ztp-sftp-password").value;
        const bindIp = document.getElementById("ztp-sftp-bind-ip").value.trim();

        const payload = {
            username,
            password,
            bind_ip: bindIp,
            port: document.getElementById("ztp-sftp-port").value.trim()
        };

        ztpSftpStartButton.disabled = true;

        try {

            const result = await apiRequest("/ztp/api/sftp/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            // "0.0.0.0" (all interfaces) isn't a real destination the
            // switch can connect to -- only auto-fill when the bind IP
            // is one specific, reachable address (typically because the
            // interface picker above was used).
            if (bindIp && bindIp !== "0.0.0.0") {

                fillZtpFileServerUrl(username, password, bindIp, result.port);
                window.NES.toast("ZTP SFTP server started -- File Server URL and Option 67 URL filled in below.");

            } else {

                window.NES.toast(
                    "ZTP SFTP server started on all interfaces (0.0.0.0) -- pick the specific " +
                    "staging-segment IP above to auto-fill File Server URL / Option 67."
                );

            }

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpSftpStatus();

        }

    });

    ztpSftpStopButton.addEventListener("click", async () => {

        ztpSftpStopButton.disabled = true;

        try {

            await apiRequest("/ztp/api/sftp/stop", { method: "POST" });

            window.NES.toast("ZTP SFTP server stopped.");

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpSftpStatus();

        }

    });

    async function refreshZtpDhcpStatus() {

        try {

            const data = await apiRequest("/ztp/api/dhcp/status");

            ztpDhcpStatus.textContent = data.running ? "Running." : "Stopped.";
            ztpDhcpStartButton.disabled = data.running || !ztpDhcpConfirm.checked;
            ztpDhcpStopButton.disabled = !data.running;

        } catch (error) {

            ztpDhcpStatus.textContent = "Status unavailable.";

        }

    }

    ztpDhcpConfirm.addEventListener("change", () => {

        ztpDhcpStartButton.disabled = !ztpDhcpConfirm.checked;

    });

    ztpDhcpStartButton.addEventListener("click", async () => {

        if (!ztpDhcpConfirm.checked) {

            window.NES.toast("Confirm this interface is on an isolated staging segment first.");

            return;

        }

        const payload = {
            interface: document.getElementById("ztp-dhcp-interface").value.trim(),
            range_start: document.getElementById("ztp-dhcp-range-start").value.trim(),
            range_end: document.getElementById("ztp-dhcp-range-end").value.trim(),
            subnet_mask: document.getElementById("ztp-dhcp-subnet-mask").value.trim(),
            lease_time: document.getElementById("ztp-dhcp-lease-time").value.trim() || "30m",
            gateway: document.getElementById("ztp-dhcp-gateway").value.trim(),
            dns_server: document.getElementById("ztp-dhcp-dns").value.trim(),
            option67_url: document.getElementById("ztp-dhcp-option67").value.trim(),
            confirm_isolated_segment: ztpDhcpConfirm.checked
        };

        ztpDhcpStartButton.disabled = true;

        try {

            await apiRequest("/ztp/api/dhcp/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            window.NES.toast("ZTP DHCP server started.");

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpDhcpStatus();

        }

    });

    ztpDhcpStopButton.addEventListener("click", async () => {

        ztpDhcpStopButton.disabled = true;

        try {

            await apiRequest("/ztp/api/dhcp/stop", { method: "POST" });

            window.NES.toast("ZTP DHCP server stopped.");

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpDhcpStatus();

        }

    });


    // --------------------------------------------------------
    // ZTP Syslog Receiver -- forwards the switch's own ZTP process
    // log lines (if SYSLOG_INFO on the generated .ini is wired up
    // and the format is right, see syslog_server.py's docstring)
    // into the Activity Log panel below in real time.
    // --------------------------------------------------------

    async function refreshZtpSyslogStatus() {

        try {

            const data = await apiRequest("/ztp/api/syslog/status");

            ztpSyslogStatus.textContent = data.running ? "Running." : "Stopped.";
            ztpSyslogStartButton.disabled = data.running;
            ztpSyslogStopButton.disabled = !data.running;

        } catch (error) {

            ztpSyslogStatus.textContent = "Status unavailable.";

        }

    }

    ztpSyslogStartButton.addEventListener("click", async () => {

        const payload = {
            bind_ip: document.getElementById("ztp-syslog-bind-ip").value.trim(),
            port: document.getElementById("ztp-syslog-port").value.trim()
        };

        ztpSyslogStartButton.disabled = true;

        try {

            const result = await apiRequest("/ztp/api/syslog/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            window.NES.toast(
                `ZTP syslog receiver started on port ${result.port} -- ` +
                `enter "${payload.bind_ip}:${result.port}" as the Live Log Target above.`
            );

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpSyslogStatus();

        }

    });

    ztpSyslogStopButton.addEventListener("click", async () => {

        ztpSyslogStopButton.disabled = true;

        try {

            await apiRequest("/ztp/api/syslog/stop", { method: "POST" });

            window.NES.toast("ZTP syslog receiver stopped.");

        } catch (error) {

            window.NES.toast(error.message);

        } finally {

            await refreshZtpSyslogStatus();

        }

    });


    // --------------------------------------------------------
    // ZTP Activity Log -- polls /ztp/api/activity for everything
    // Keystone has observed about an in-flight ZTP run (SFTP file
    // requests, syslog lines, server lifecycle events) so nobody has
    // to console into the switch and grep its log by hand to see how
    // far a run got.
    // --------------------------------------------------------

    let ztpActivityLastId = 0;
    const ZTP_ACTIVITY_MAX_ENTRIES = 400;

    function formatZtpActivityTime(unixSeconds) {
        const date = new Date(unixSeconds * 1000);
        return date.toLocaleTimeString([], { hour12: false });
    }

    function renderZtpActivityEntry(event) {

        const el = document.createElement("div");
        el.className = `ztp-activity-entry ztp-activity-entry-level-${escapeHtml(event.level)}`;

        el.innerHTML = `
            <span class="ztp-activity-entry-time">${formatZtpActivityTime(event.ts)}</span>
            <span class="ztp-activity-entry-source ztp-activity-entry-source-${escapeHtml(event.source)}">${escapeHtml(event.source)}</span>
            ${event.esn ? `<span class="ztp-activity-entry-esn">${escapeHtml(event.esn)}</span>` : ""}
            <span class="ztp-activity-entry-message">${escapeHtml(event.message)}</span>
        `;

        return el;

    }

    async function pollZtpActivity() {

        try {

            const data = await apiRequest(`/ztp/api/activity?since_id=${ztpActivityLastId}`);
            const events = data.events || [];

            if (!events.length) {
                return;
            }

            // First entries ever seen this page load -- clear the
            // "Nothing yet" placeholder before appending real ones.
            if (ztpActivityLastId === 0) {
                ztpActivityLog.innerHTML = "";
            }

            const wasScrolledToBottom =
                ztpActivityLog.scrollHeight - ztpActivityLog.scrollTop - ztpActivityLog.clientHeight < 40;

            events.forEach(event => {
                ztpActivityLog.appendChild(renderZtpActivityEntry(event));
                ztpActivityLastId = Math.max(ztpActivityLastId, event.id);
            });

            while (ztpActivityLog.children.length > ZTP_ACTIVITY_MAX_ENTRIES) {
                ztpActivityLog.removeChild(ztpActivityLog.firstChild);
            }

            if (wasScrolledToBottom) {
                ztpActivityLog.scrollTop = ztpActivityLog.scrollHeight;
            }

            const last = events[events.length - 1];
            ztpActivityStatus.textContent =
                `${events.length} new event(s) -- last update ${formatZtpActivityTime(last.ts)}.`;

        } catch (error) {

            // Non-fatal -- just try again on the next poll tick.

        }

    }

    ztpActivityClearButton.addEventListener("click", async () => {

        try {

            await apiRequest("/ztp/api/activity/clear", { method: "POST" });

            ztpActivityLastId = 0;
            ztpActivityLog.innerHTML = `
                <div class="empty-state">Nothing yet — start the SFTP/DHCP/Syslog servers and click Generate Files to begin a run.</div>
            `;
            ztpActivityStatus.textContent = "Cleared.";

        } catch (error) {

            window.NES.toast(error.message);

        }

    });

    // Poll every 2 seconds -- fast enough to feel live for a human
    // watching a ZTP run, without hammering the server.
    setInterval(pollZtpActivity, 2000);


    // --------------------------------------------------------
    // Interface pickers (SFTP bind IP + DHCP interface) -- these
    // fill in the existing plain-text inputs rather than replace
    // them, so a platform quirk in interface detection never blocks
    // manual entry: the dropdowns are a convenience layered on top,
    // not the only way to set these fields.
    // --------------------------------------------------------

    async function loadZtpInterfaces() {

        ztpSftpBindIpPicker.innerHTML = `<option value="0.0.0.0">0.0.0.0 (All Interfaces)</option>`;
        ztpDhcpInterfacePicker.innerHTML = `<option value="">— Pick a detected interface —</option>`;

        try {

            const data = await apiRequest("/ztp/api/interfaces");
            const interfaces = data.interfaces || [];

            interfaces.forEach(iface => {

                iface.ipv4_addresses.forEach(ip => {
                    const option = document.createElement("option");
                    option.value = ip;
                    option.textContent = `${ip} (${iface.name})`;
                    ztpSftpBindIpPicker.appendChild(option);
                });

                const dhcpOption = document.createElement("option");
                dhcpOption.value = iface.name;
                dhcpOption.textContent = `${iface.name} — ${iface.ipv4_addresses.join(", ")}`;
                ztpDhcpInterfacePicker.appendChild(dhcpOption);

            });

        } catch (error) {

            // Non-fatal -- both fields still accept manual entry.
            window.NES.toast("Could not list local network interfaces; enter them manually.");

        }

    }

    ztpSftpBindIpPicker.addEventListener("change", () => {
        if (ztpSftpBindIpPicker.value) {
            document.getElementById("ztp-sftp-bind-ip").value = ztpSftpBindIpPicker.value;
        }
    });

    ztpDhcpInterfacePicker.addEventListener("change", () => {
        if (ztpDhcpInterfacePicker.value) {
            document.getElementById("ztp-dhcp-interface").value = ztpDhcpInterfacePicker.value;
        }
    });


    // --------------------------------------------------------
    // Firmware picker -- lists Huawei firmware already uploaded to
    // the Firmware Repository, so a filename can be picked instead
    // of retyped (and mistyped) by hand.
    // --------------------------------------------------------

    async function loadZtpFirmwareOptions() {

        ztpFirmwarePicker.innerHTML = `<option value="">— Pick from Firmware Repository —</option>`;

        try {

            const data = await apiRequest("/lifecycle/api/firmware");
            const firmwares = (data.firmwares || []).filter(fw => fw.vendor === "Huawei");

            if (!firmwares.length) {
                const option = document.createElement("option");
                option.value = "";
                option.textContent = "No Huawei firmware uploaded yet";
                option.disabled = true;
                ztpFirmwarePicker.appendChild(option);
                return;
            }

            firmwares.forEach(fw => {
                const option = document.createElement("option");
                option.value = fw.filename;
                option.textContent = `${fw.model || "Unknown model"} — ${fw.version || "?"} (${fw.filename})`;
                ztpFirmwarePicker.appendChild(option);
            });

        } catch (error) {

            window.NES.toast("Could not load the firmware repository; enter a filename manually.");

        }

    }

    ztpFirmwarePicker.addEventListener("change", () => {
        document.getElementById("ztp-firmware").value = ztpFirmwarePicker.value;
    });


    // --------------------------------------------------------
    // Bulk pre-register from an uploaded Excel workbook.
    // --------------------------------------------------------

    ztpImportFileInput.addEventListener("change", async () => {

        const file = ztpImportFileInput.files[0];
        if (!file) {
            return;
        }

        const formData = new FormData();
        formData.append("file", file);

        ztpImportResult.hidden = false;
        ztpImportResult.innerHTML = "Importing...";

        try {

            const data = await apiRequest("/ztp/api/devices/import", {
                method: "POST",
                body: formData
            });

            const failedLines = (data.failed || [])
                .map(item => `Row ${item.row} (${escapeHtml(item.esn || "no ESN")}): ${escapeHtml(item.error)}`)
                .join("<br>");

            ztpImportResult.innerHTML = `
                <strong>${data.registered_count} device(s) registered${data.failed.length ? `, ${data.failed.length} failed` : ""}.</strong>
                ${failedLines ? `<div>${failedLines}</div>` : ""}
            `;

            window.NES.toast(`Imported ${data.registered_count} device(s) from Excel.`);

            await loadZtpDevices();

        } catch (error) {

            ztpImportResult.innerHTML = `<strong>Import failed.</strong> ${escapeHtml(error.message)}`;
            window.NES.toast(error.message);

        } finally {

            ztpImportFileInput.value = "";

        }

    });


    // ========================================================
    // TABS
    // ========================================================

    function initZtpTabs() {

        const buttons = Array.from(document.querySelectorAll(".ztp-tab-button"));
        const panels = Array.from(document.querySelectorAll(".ztp-tab-panel"));

        if (!buttons.length || !panels.length) {
            return;
        }

        function activate(target) {

            buttons.forEach((button) => {
                const isMatch = button.dataset.tabTarget === target;
                button.classList.toggle("active", isMatch);
                button.setAttribute("aria-selected", isMatch ? "true" : "false");
            });

            panels.forEach((panel) => {
                panel.classList.toggle("active", panel.dataset.tabPanel === target);
            });

        }

        buttons.forEach((button) => {
            button.addEventListener("click", () => activate(button.dataset.tabTarget));
        });

        const initiallyActive = buttons.find((button) => button.classList.contains("active"));
        activate(initiallyActive ? initiallyActive.dataset.tabTarget : buttons[0].dataset.tabTarget);

    }


    // ========================================================
    // INITIAL LOAD
    // ========================================================


    async function syncDemoBadge() {

        try {

            const settings = await apiRequest("/lifecycle/api/settings");
            const badge = document.getElementById("ztp-demo-badge");

            if (badge) {
                badge.classList.toggle("hidden", settings.demo_mode === false);
            }

        } catch (error) {
            // Non-critical -- leave the badge as shipped in the template.
        }

    }

    const ztpRefreshButton = document.getElementById("ztp-refresh-button");

    ztpRefreshButton?.addEventListener("click", async () => {

        ztpRefreshButton.disabled = true;
        ztpRefreshButton.textContent = "Refreshing...";

        await Promise.all([
            loadZtpDevices(),
            refreshZtpSftpStatus(),
            refreshZtpDhcpStatus(),
            refreshZtpSyslogStatus(),
            loadZtpInterfaces(),
            loadZtpFirmwareOptions(),
        ]);

        ztpRefreshButton.disabled = false;
        ztpRefreshButton.textContent = "Refresh";

        window.NES.toast("Data refreshed.");

    });


    // ========================================================
    // INITIAL LOAD
    // ========================================================

    initZtpTabs();
    syncDemoBadge();
    loadZtpDevices();
    refreshZtpSftpStatus();
    refreshZtpDhcpStatus();
    refreshZtpSyslogStatus();
    loadZtpInterfaces();
    loadZtpFirmwareOptions();
    pollZtpActivity();

});
