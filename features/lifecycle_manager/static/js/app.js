document.addEventListener("DOMContentLoaded", () => {

    // ========================================================
    // ELEMENTS
    // ========================================================

    const pages = document.querySelectorAll(".page");
    const navItems = document.querySelectorAll(".nav-item");

    const pageTitle = document.getElementById("page-title");
    const pageDescription = document.getElementById("page-description");

    const refreshButton = document.getElementById("refresh-button");

    const dashboardTable = document.getElementById(
        "dashboard-device-table"
    );

    const discoveryTable = document.getElementById(
        "discovery-device-table"
    );

    const firmwareTable = document.getElementById(
        "firmware-table"
    );

    const discoveryForm = document.getElementById(
        "discovery-form"
    );

    const firmwareForm = document.getElementById(
        "firmware-upload-form"
    );

    const settingsForm = document.getElementById(
        "settings-form"
    );

    const clearDevicesButton = document.getElementById(
        "clear-devices-button"
    );

    const informationModal = document.getElementById(
        "information-modal"
    );

    const informationModalTitle = document.getElementById(
        "information-modal-title"
    );

    const informationModalMessage = document.getElementById(
        "information-modal-message"
    );

    const informationModalClose = document.getElementById(
        "information-modal-close"
    );


    // ========================================================
    // PAGE CONFIG
    // ========================================================

    const pageConfig = {

        dashboard: {
            title: "Dashboard",
            description:
                "Overview of your switch staging environment."
        },

        discovery: {
            title: "Device Discovery",
            description:
                "Discover and inventory switches on the staging network."
        },

        firmware: {
            title: "Firmware Repository",
            description:
                "Manage firmware images available for switch upgrades."
        },

        jobs: {
            title: "Upgrade Jobs",
            description:
                "Monitor switch firmware deployment operations."
        },

        settings: {
            title: "Settings",
            description:
                "Configure the switch staging environment."
        }

    };


    // ========================================================
    // PAGE NAVIGATION
    // ========================================================

    function navigateToPage(pageName) {

        pages.forEach(page => {
            page.classList.remove("active");
        });

        navItems.forEach(item => {
            item.classList.remove("active");
        });

        const targetPage = document.getElementById(
            `page-${pageName}`
        );

        const targetNav = document.querySelector(
            `.nav-item[data-page="${pageName}"]`
        );

        if (targetPage) {
            targetPage.classList.add("active");
        }

        if (targetNav) {
            targetNav.classList.add("active");
        }

        const config = pageConfig[pageName];

        if (config) {

            pageTitle.textContent =
                config.title;

            pageDescription.textContent =
                config.description;

        }

        if (pageName === "dashboard") {
            loadDashboard();
            loadDevices();
        }

        if (pageName === "discovery") {
            loadDevices();
        }

        if (pageName === "firmware") {
            loadFirmware();
        }

        if (pageName === "settings") {
            loadSettings();
        }

        if (pageName === "jobs") {
            loadJobs();
        }

    }


    navItems.forEach(item => {

        item.addEventListener("click", () => {

            navigateToPage(
                item.dataset.page
            );

        });

    });


    document
        .querySelectorAll("[data-go-page]")
        .forEach(button => {

            button.addEventListener(
                "click",
                () => {

                    navigateToPage(
                        button.dataset.goPage
                    );

                }
            );

        });


    // ========================================================
    // API HELPER
    // ========================================================

    async function apiRequest(
        url,
        options = {}
    ) {

        const response = await fetch(
            url,
            options
        );

        let data;

        try {

            data = await response.json();

        } catch {

            throw new Error(
                "Invalid response from server."
            );

        }

        if (!response.ok) {

            throw new Error(
                data.error ||
                "Request failed."
            );

        }

        return data;

    }


    // ========================================================
    // TOAST
    // ========================================================

    let toastTimer;

    function showToast(
        message
    ) {

        const toast =
            document.getElementById(
                "toast"
            );

        const toastMessage =
            document.getElementById(
                "toast-message"
            );

        toastMessage.textContent =
            message;

        toast.classList.add(
            "show"
        );

        clearTimeout(
            toastTimer
        );

        toastTimer = setTimeout(
            () => {

                toast.classList.remove(
                    "show"
                );

            },
            3000
        );

    }


    // ========================================================
    // INFORMATION MODAL
    // ========================================================

    function showInformationModal(
        title,
        message
    ) {

        informationModalTitle.textContent =
            title;

        informationModalMessage.textContent =
            message;

        informationModal.classList.remove(
            "hidden"
        );

        informationModalClose.focus();

    }


    function closeInformationModal() {

        informationModal.classList.add(
            "hidden"
        );

    }


    informationModalClose.addEventListener(
        "click",
        closeInformationModal
    );


    informationModal.addEventListener(
        "click",
        event => {

            if (event.target === informationModal) {
                closeInformationModal();
            }

        }
    );


    // ========================================================
    // ESCAPE HTML
    // ========================================================

    function escapeHtml(value) {

        if (
            value === null ||
            value === undefined
        ) {
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
    // STATUS BADGE
    // ========================================================

    function getStatusBadge(
        status
    ) {

        const safeStatus =
            escapeHtml(
                status || "unknown"
            );

        let className =
            "status-offline";

        if (
            status === "online"
        ) {
            className =
                "status-online";
        }

        if (
            status === "failed"
        ) {
            className =
                "status-failed";
        }

        return `
            <span
                class="
                    status-badge
                    ${className}
                "
            >
                ${safeStatus}
            </span>
        `;

    }


    // ========================================================
    // DASHBOARD
    // ========================================================

    async function loadDashboard() {

        try {

            const data =
                await apiRequest(
                    "/lifecycle/api/dashboard"
                );

            document.getElementById(
                "stat-total-devices"
            ).textContent =
                data.total_devices ?? 0;

            document.getElementById(
                "stat-online-devices"
            ).textContent =
                data.online_devices ?? 0;

            document.getElementById(
                "stat-firmware-images"
            ).textContent =
                data.firmware_images ?? 0;

            document.getElementById(
                "stat-active-jobs"
            ).textContent =
                data.active_jobs ?? 0;

        } catch (error) {

            console.error(
                "Dashboard error:",
                error
            );

        }

    }


    // ========================================================
    // DEVICES
    // ========================================================

    async function loadDevices() {

        try {

            const data =
                await apiRequest(
                    "/lifecycle/api/devices"
                );

            const devices =
                data.devices || [];

            renderDashboardDevices(
                devices
            );

            renderDiscoveryDevices(
                devices
            );

        } catch (error) {

            console.error(
                "Device load error:",
                error
            );

        }

    }


    function renderDashboardDevices(
        devices
    ) {

        if (!devices.length) {

            dashboardTable.innerHTML = `
                <tr>
                    <td
                        colspan="7"
                        class="empty-state"
                    >
                        No devices discovered.
                    </td>
                </tr>
            `;

            return;

        }

        dashboardTable.innerHTML =
            devices.map(
                device => `
                    <tr>

                        <td>
                            ${escapeHtml(device.ip)}
                        </td>

                        <td>
                            ${escapeHtml(device.hostname)}
                        </td>

                        <td>
                            ${escapeHtml(device.vendor)}
                        </td>

                        <td>
                            ${escapeHtml(device.platform)}
                        </td>

                        <td>
                            ${escapeHtml(device.model)}
                        </td>

                        <td>
                            ${escapeHtml(device.version)}
                        </td>

                        <td>
                            ${getStatusBadge(device.status)}
                        </td>

                    </tr>
                `
            ).join("");

    }


    function renderDiscoveryDevices(
        devices
    ) {

        if (!devices.length) {

            discoveryTable.innerHTML = `
                <tr>
                    <td
                        colspan="8"
                        class="empty-state"
                    >
                        No discovery results.
                    </td>
                </tr>
            `;

            return;

        }

        discoveryTable.innerHTML =
            devices.map(
                device => `
                    <tr>

                        <td>
                            <input
                                type="checkbox"
                                class="device-checkbox"
                                value="${escapeHtml(device.ip)}"
                                ${
                                    device.status !== "online"
                                        ? "disabled"
                                        : ""
                                }
                            >
                        </td>

                        <td>
                            ${escapeHtml(device.ip)}
                        </td>

                        <td>
                            ${escapeHtml(device.hostname)}
                        </td>

                        <td>
                            ${escapeHtml(device.vendor)}
                        </td>

                        <td>
                            ${escapeHtml(device.platform)}
                        </td>

                        <td>
                            ${escapeHtml(device.model)}
                        </td>

                        <td>
                            ${escapeHtml(device.version)}
                        </td>

                        <td>
                            ${getStatusBadge(device.status)}
                        </td>

                    </tr>
                `
            ).join("");

    }


    // ========================================================
    // DEVICE DISCOVERY
    // ========================================================

    discoveryForm.addEventListener(
        "submit",
        async event => {

            event.preventDefault();

            const scanButton =
                document.getElementById(
                    "scan-button"
                );

            const statusText =
                document.getElementById(
                    "discovery-status"
                );

            const demoMode =
                document.getElementById(
                    "demo-mode"
                ).checked;

            const payload = {

                start_ip:
                    document.getElementById(
                        "start-ip"
                    ).value.trim(),

                end_ip:
                    document.getElementById(
                        "end-ip"
                    ).value.trim(),

                username:
                    document.getElementById(
                        "ssh-username"
                    ).value.trim(),

                password:
                    document.getElementById(
                        "ssh-password"
                    ).value,

                demo_mode:
                    demoMode

            };


            scanButton.disabled = true;

            scanButton.textContent =
                "Discovering...";

            statusText.textContent =
                demoMode
                    ? "Loading demo devices..."
                    : "Scanning network. Please wait...";


            try {

                const data =
                    await apiRequest(
                        "/lifecycle/api/discovery",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(
                                    payload
                                )
                        }
                    );


                const discoveredDevices =
                    data.devices || [];

                loadSettings();

                renderDiscoveryDevices(
                    discoveredDevices
                );

                renderDashboardDevices(
                    discoveredDevices
                );

                document.getElementById(
                    "selected-device-count"
                ).textContent =
                    "0 devices selected";

                document.getElementById(
                    "stage-upgrade-button"
                ).disabled = true;

                if (
                    !demoMode &&
                    data.no_devices
                ) {

                    statusText.textContent =
                        "No devices discovered.";

                    const failedLines = (data.failed_devices || [])
                        .map((item) => `${item.ip} — ${item.status}: ${item.error || "Unknown error"}`)
                        .join("\n");

                    showInformationModal(
                        "No Devices Discovered",
                        `No supported network device could be discovered between ${payload.start_ip} and ${payload.end_ip}.` +
                        (failedLines ? `\n\n${failedLines}` : " Check IP reachability, SSH access, credentials, and supported platform settings before trying again.")
                    );

                } else {

                    statusText.textContent =
                        `${
                            discoveredDevices.length
                        } device(s) discovered.`;

                    showToast(
                        "Device discovery completed."
                    );

                    if (
                        !demoMode &&
                        data.ztp_auto_provisioned &&
                        data.ztp_auto_provisioned.length
                    ) {

                        showToast(
                            `ZTP: ${data.ztp_auto_provisioned.length} pre-registered device(s) auto-marked provisioned (ESN match).`
                        );

                    }

                    if (
                        !demoMode &&
                        data.failed_devices &&
                        data.failed_devices.length
                    ) {

                        const failedLines = data.failed_devices
                            .map((item) => `${item.ip} — ${item.status}: ${item.error || "Unknown error"}`)
                            .join("\n");

                        showInformationModal(
                            `${discoveredDevices.length} Discovered, ${data.failed_devices.length} Failed`,
                            `Scanned ${payload.start_ip}–${payload.end_ip} (${data.attempted_count} address(es)). ` +
                            `${discoveredDevices.length} device(s) were successfully discovered. ` +
                            `The rest did not respond or failed authentication:\n\n${failedLines}`
                        );
                    }

                }

                await loadDashboard();


            } catch (error) {

                statusText.textContent =
                    `Discovery failed: ${error.message}`;

                showToast(
                    error.message
                );

            } finally {

                scanButton.disabled =
                    false;

                scanButton.textContent =
                    "Start Discovery";

            }

        }
    );


    // ========================================================
    // CLEAR DEVICES
    // ========================================================

    clearDevicesButton.addEventListener(
        "click",
        async () => {

            const confirmed =
                confirm(
                    "Clear all discovered devices?"
                );

            if (!confirmed) {
                return;
            }

            try {

                await apiRequest(
                    "/lifecycle/api/devices",
                    {
                        method: "DELETE"
                    }
                );

                renderDashboardDevices(
                    []
                );

                renderDiscoveryDevices(
                    []
                );

                document.getElementById(
                    "discovery-status"
                ).textContent =
                    "Device list cleared.";

                await loadDashboard();

                showToast(
                    "Device inventory cleared."
                );

            } catch (error) {

                showToast(
                    error.message
                );

            }

        }
    );


    // ========================================================
    // FIRMWARE REPOSITORY
    // ========================================================

    async function loadFirmware() {

        try {

            const data =
                await apiRequest(
                    "/lifecycle/api/firmware"
                );

            renderFirmware(
                data.firmwares || []
            );

        } catch (error) {

            console.error(
                "Firmware load error:",
                error
            );

        }

    }


    function formatFileSize(
        bytes
    ) {

        if (!bytes) {
            return "0 B";
        }

        const units = [
            "B",
            "KB",
            "MB",
            "GB"
        ];

        let size = bytes;
        let unitIndex = 0;

        while (
            size >= 1024 &&
            unitIndex <
                units.length - 1
        ) {

            size /= 1024;

            unitIndex++;

        }

        return `
            ${size.toFixed(
                unitIndex === 0
                    ? 0
                    : 2
            )}
            ${units[unitIndex]}
        `;

    }


    function renderFirmware(
        firmwares
    ) {

        if (!firmwares.length) {

            firmwareTable.innerHTML = `
                <tr>
                    <td
                        colspan="8"
                        class="empty-state"
                    >
                        No firmware images uploaded.
                    </td>
                </tr>
            `;

            return;

        }


        firmwareTable.innerHTML =
            firmwares.map(
                firmware => {

                    const uploaded =
                        firmware.uploaded_at
                            ? new Date(
                                firmware.uploaded_at
                            ).toLocaleString()
                            : "-";

                    return `
                        <tr>

                            <td>
                                ${escapeHtml(firmware.vendor)}
                            </td>

                            <td>
                                ${escapeHtml(firmware.platform)}
                            </td>

                            <td>
                                ${escapeHtml(firmware.model)}
                            </td>

                            <td>
                                ${escapeHtml(firmware.version)}
                            </td>

                            <td>
                                ${escapeHtml(firmware.filename)}
                                ${firmware.patch_filename ? `<br><small style="color:var(--muted)">+ patch: ${escapeHtml(firmware.patch_filename)}</small>` : ""}
                            </td>

                            <td>
                                ${formatFileSize(firmware.size)}
                                ${firmware.patch_filename ? `<br><small style="color:var(--muted)">+ ${formatFileSize(firmware.patch_size)}</small>` : ""}
                            </td>

                            <td>
                                ${escapeHtml(uploaded)}
                            </td>

                            <td>

                                <button
                                    class="
                                        button
                                        button-danger
                                        delete-firmware
                                    "
                                    data-id="${escapeHtml(firmware.id)}"
                                >
                                    Delete
                                </button>

                            </td>

                        </tr>
                    `;

                }

            ).join("");

    }


    // ========================================================
    // FIRMWARE UPLOAD
    // ========================================================

    firmwareForm.addEventListener(
        "submit",
        event => {

            event.preventDefault();

            const fileInput =
                document.getElementById(
                    "firmware-file"
                );

            if (
                !fileInput.files.length
            ) {

                showToast(
                    "Select a firmware file first."
                );

                return;

            }


            const formData =
                new FormData();

            formData.append(
                "vendor",
                document.getElementById(
                    "firmware-vendor"
                ).value
            );

            formData.append(
                "platform",
                document.getElementById(
                    "firmware-platform"
                ).value.trim()
            );

            formData.append(
                "model",
                document.getElementById(
                    "firmware-model"
                ).value.trim()
            );

            formData.append(
                "version",
                document.getElementById(
                    "firmware-version"
                ).value.trim()
            );

            formData.append(
                "file",
                fileInput.files[0]
            );

            const patchInput =
                document.getElementById(
                    "firmware-patch-file"
                );

            if (
                patchInput &&
                patchInput.files.length
            ) {

                formData.append(
                    "patch_file",
                    patchInput.files[0]
                );

            }


            uploadFirmware(
                formData
            );

        }
    );


    function uploadFirmware(
        formData
    ) {

        const xhr =
            new XMLHttpRequest();

        const progressContainer =
            document.getElementById(
                "upload-progress-container"
            );

        const progressBar =
            document.getElementById(
                "upload-progress-bar"
            );

        const progressText =
            document.getElementById(
                "upload-progress-text"
            );

        const uploadButton =
            document.getElementById(
                "upload-firmware-button"
            );


        progressContainer.classList.remove(
            "hidden"
        );

        progressBar.style.width =
            "0%";

        progressText.textContent =
            "0%";

        uploadButton.disabled =
            true;

        uploadButton.textContent =
            "Uploading...";


        xhr.upload.addEventListener(
            "progress",
            event => {

                if (
                    !event.lengthComputable
                ) {
                    return;
                }

                const percent =
                    Math.round(
                        (
                            event.loaded /
                            event.total
                        ) * 100
                    );

                progressBar.style.width =
                    `${percent}%`;

                progressText.textContent =
                    `${percent}%`;

            }
        );


        xhr.addEventListener(
            "load",
            async () => {

                uploadButton.disabled =
                    false;

                uploadButton.textContent =
                    "Upload Firmware";


                if (
                    xhr.status >= 200 &&
                    xhr.status < 300
                ) {

                    progressBar.style.width =
                        "100%";

                    progressText.textContent =
                        "100%";

                    firmwareForm.reset();

                    showToast(
                        "Firmware uploaded successfully."
                    );

                    await loadFirmware();

                    await loadDashboard();


                    setTimeout(
                        () => {

                            progressContainer
                                .classList
                                .add(
                                    "hidden"
                                );

                        },
                        1000
                    );

                } else {

                    let message =
                        "Firmware upload failed.";

                    try {

                        const data =
                            JSON.parse(
                                xhr.responseText
                            );

                        message =
                            data.error ||
                            message;

                    } catch {
                    }

                    showToast(
                        message
                    );

                }

            }
        );


        xhr.addEventListener(
            "error",
            () => {

                uploadButton.disabled =
                    false;

                uploadButton.textContent =
                    "Upload Firmware";

                showToast(
                    "Firmware upload failed."
                );

            }
        );


        xhr.open(
            "POST",
            "/lifecycle/api/firmware/upload"
        );

        xhr.send(
            formData
        );

    }


    // ========================================================
    // DELETE FIRMWARE
    // ========================================================

    firmwareTable.addEventListener(
        "click",
        async event => {

            const button =
                event.target.closest(
                    ".delete-firmware"
                );

            if (!button) {
                return;
            }

            const confirmed =
                confirm(
                    "Delete this firmware image?"
                );

            if (!confirmed) {
                return;
            }


            try {

                await apiRequest(
                    `/lifecycle/api/firmware/${button.dataset.id}`,
                    {
                        method: "DELETE"
                    }
                );

                showToast(
                    "Firmware deleted."
                );

                await loadFirmware();

                await loadDashboard();

            } catch (error) {

                showToast(
                    error.message
                );

            }

        }
    );


    // ========================================================
    // SETTINGS
    // ========================================================

    async function loadSettings() {

        try {

            const settings =
                await apiRequest(
                    "/lifecycle/api/settings"
                );


            document.getElementById(
                "settings-source-ip"
            ).value =
                settings
                    .firmware_server
                    ?.source_ip || "";


            document.getElementById(
                "settings-max-parallel"
            ).value =
                settings
                    .upgrade
                    ?.max_parallel || 10;


            document.getElementById(
                "settings-reconnect-timeout"
            ).value =
                settings
                    .upgrade
                    ?.reconnect_timeout || 600;


            document.getElementById(
                "settings-transfer-method"
            ).value =
                settings
                    .transfer
                    ?.method || "sftp";


            document.getElementById(
                "settings-tftp-server-ip"
            ).value =
                settings
                    .transfer
                    ?.tftp_server_ip || "";


            document.getElementById(
                "settings-tftp-port"
            ).value =
                settings
                    .transfer
                    ?.tftp_port || 69;


            document.getElementById(
                "settings-ftp-server-ip"
            ).value =
                settings
                    .transfer
                    ?.ftp_server_ip || "";


            document.getElementById(
                "settings-ftp-port"
            ).value =
                settings
                    .transfer
                    ?.ftp_port || 21;


            document.getElementById(
                "demo-mode"
            ).checked =
                settings.demo_mode !== false;


            const demoBadge =
                document.getElementById(
                    "demo-badge"
                );

            if (
                settings.demo_mode === false
            ) {

                demoBadge.classList.add(
                    "hidden"
                );

            } else {

                demoBadge.classList.remove(
                    "hidden"
                );

            }

        } catch (error) {

            console.error(
                "Settings error:",
                error
            );

        }

    }


    settingsForm.addEventListener(
        "submit",
        async event => {

            event.preventDefault();


            const payload = {

                firmware_server: {

                    source_ip:
                        document.getElementById(
                            "settings-source-ip"
                        ).value.trim(),

                    port: 8000,

                    bind_address:
                        "0.0.0.0"

                },

                upgrade: {

                    max_parallel:
                        Number(
                            document.getElementById(
                                "settings-max-parallel"
                            ).value
                        ),

                    reconnect_timeout:
                        Number(
                            document.getElementById(
                                "settings-reconnect-timeout"
                            ).value
                        ),

                    reconnect_interval:
                        10

                },

                transfer: {

                    method:
                        document.getElementById(
                            "settings-transfer-method"
                        ).value,

                    tftp_server_ip:
                        document.getElementById(
                            "settings-tftp-server-ip"
                        ).value.trim(),

                    tftp_port:
                        Number(
                            document.getElementById(
                                "settings-tftp-port"
                            ).value
                        ) || 69,

                    ftp_server_ip:
                        document.getElementById(
                            "settings-ftp-server-ip"
                        ).value.trim(),

                    ftp_port:
                        Number(
                            document.getElementById(
                                "settings-ftp-port"
                            ).value
                        ) || 21

                }

            };


            try {

                await apiRequest(
                    "/lifecycle/api/settings",
                    {

                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                payload
                            )

                    }
                );


                showToast(
                    "Settings saved."
                );


            } catch (error) {

                showToast(
                    error.message
                );

            }

        }
    );


    // ========================================================
    // REFRESH
    // ========================================================

    refreshButton.addEventListener(
        "click",
        async () => {

            refreshButton.disabled =
                true;

            refreshButton.textContent =
                "Refreshing...";


            await Promise.all([
                loadDashboard(),
                loadDevices(),
                loadFirmware()
            ]);


            refreshButton.disabled =
                false;

            refreshButton.textContent =
                "Refresh";

            showToast(
                "Data refreshed."
            );

        }
    );




    // DEVICE SELECTION

    function getSelectedDevices() {

        return Array.from(
            document.querySelectorAll(
                ".device-checkbox:checked"
            )
        ).map(
            checkbox => checkbox.value
        );

    }

    function updateDeviceSelection() {

        const selectedDevices =
            getSelectedDevices();

        const countElement =
            document.getElementById(
                "selected-device-count"
            );

        const stageButton =
            document.getElementById(
                "stage-upgrade-button"
            );

        if (countElement) {

            const count =
                selectedDevices.length;

            countElement.textContent =
                `${count} device${
                    count === 1 ? "" : "s"
                } selected`;

        }

        if (stageButton) {

            stageButton.disabled =
                selectedDevices.length === 0;

        }

    }

    discoveryTable.addEventListener(
        "change",
        event => {

            if (
                event.target.classList.contains(
                    "device-checkbox"
                )
            ) {

                updateDeviceSelection();

            }

        }
    );

    const stageUpgradeButton =
        document.getElementById(
            "stage-upgrade-button"
        );

    if (stageUpgradeButton) {

        stageUpgradeButton.addEventListener(
            "click",
            () => {

                const selectedDevices =
                    getSelectedDevices();

                if (
                    selectedDevices.length === 0
                ) {

                    showToast(
                        "Select at least one device."
                    );

                    return;

                }

                openUpgradeWizard(
                    selectedDevices
                );

            }
        );

    }


    // UPGRADE WIZARD ENGINE


    let wizardStep = 1;
    let wizardDevices = [];
    let wizardFirmwares = [];


    async function openUpgradeWizard(
        selectedIPs
    ) {

        try {

            const [
                deviceData,
                firmwareData
            ] = await Promise.all([
                apiRequest(
                    "/lifecycle/api/devices"
                ),
                apiRequest(
                    "/lifecycle/api/firmware"
                )
            ]);


            wizardDevices =
                (
                    deviceData.devices ||
                    []
                ).filter(
                    device =>
                        selectedIPs.includes(
                            device.ip
                        )
                );


            wizardFirmwares =
                firmwareData.firmwares ||
                [];


            if (
                wizardFirmwares.length === 0
            ) {

                showToast(
                    "Upload firmware before creating an upgrade job."
                );

                return;

            }


            renderWizardDevices();

            renderFirmwareAssignments();

            setWizardStep(
                1
            );


            document
                .getElementById(
                    "upgrade-wizard-modal"
                )
                .classList
                .remove(
                    "hidden"
                );


        } catch (error) {

            showToast(
                error.message
            );

        }

    }


    function closeUpgradeWizard() {

        document
            .getElementById(
                "upgrade-wizard-modal"
            )
            .classList
            .add(
                "hidden"
            );

    }


    function renderWizardDevices() {

        const table =
            document.getElementById(
                "wizard-device-table"
            );


        table.innerHTML =
            wizardDevices.map(
                device => `
                    <tr>

                        <td>
                            ${escapeHtml(device.ip)}
                        </td>

                        <td>
                            ${escapeHtml(device.hostname)}
                        </td>

                        <td>
                            ${escapeHtml(device.vendor)}
                        </td>

                        <td>
                            ${escapeHtml(device.platform)}
                        </td>

                        <td>
                            ${escapeHtml(device.model)}
                        </td>

                        <td>
                            ${escapeHtml(device.version)}
                        </td>

                    </tr>
                `
            ).join("");

    }


    function getCompatibleFirmwares(
        device
    ) {

        return wizardFirmwares.filter(
            firmware => {

                const vendorMatch =
                    String(
                        firmware.vendor ||
                        ""
                    ).toLowerCase()
                    ===
                    String(
                        device.vendor ||
                        ""
                    ).toLowerCase();


                const platformMatch =
                    !firmware.platform
                    ||
                    !device.platform
                    ||
                    String(
                        firmware.platform
                    ).toLowerCase()
                    ===
                    String(
                        device.platform
                    ).toLowerCase();


                const firmwareModel =
                    String(
                        firmware.model ||
                        ""
                    ).toLowerCase();


                const deviceModel =
                    String(
                        device.model ||
                        ""
                    ).toLowerCase();


                const modelMatch =
                    !firmwareModel
                    ||
                    firmwareModel ===
                        deviceModel
                    ||
                    deviceModel.startsWith(
                        firmwareModel
                    )
                    ||
                    firmwareModel.startsWith(
                        deviceModel
                    );


                return (
                    vendorMatch &&
                    platformMatch &&
                    modelMatch
                );

            }
        );

    }


    function renderFirmwareAssignments() {

        const container =
            document.getElementById(
                "wizard-firmware-assignments"
            );


        container.innerHTML =
            wizardDevices.map(
                device => {

                    const compatible =
                        getCompatibleFirmwares(
                            device
                        );


                    const options =
                        compatible.map(
                            firmware => `
                                <option
                                    value="${escapeHtml(firmware.id)}"
                                >
                                    ${escapeHtml(firmware.version)}
                                    -
                                    ${escapeHtml(firmware.filename)}
                                </option>
                            `
                        ).join("");


                    return `
                        <div
                            class="firmware-assignment"
                        >

                            <div
                                class="assignment-device"
                            >

                                <strong>
                                    ${escapeHtml(device.hostname)}
                                </strong>

                                <span>
                                    ${escapeHtml(device.ip)}
                                </span>

                            </div>


                            <div
                                class="assignment-info"
                            >

                                <strong>
                                    ${escapeHtml(device.vendor)}
                                </strong>

                                <span>
                                    ${escapeHtml(device.platform)}
                                </span>

                            </div>


                            <div
                                class="assignment-info"
                            >

                                <strong>
                                    ${escapeHtml(device.model)}
                                </strong>

                                <span>
                                    Current:
                                    ${escapeHtml(device.version)}
                                </span>

                            </div>


                            <div>

                                ${
                                    compatible.length
                                        ?
                                        `
                                            <div
                                                class="compatibility-ok"
                                            >
                                                Compatible firmware found
                                            </div>

                                            <select
                                                class="firmware-assignment-select"
                                                data-device-ip="${escapeHtml(device.ip)}"
                                            >
                                                ${options}
                                            </select>
                                        `
                                        :
                                        `
                                            <div
                                                class="compatibility-warning"
                                            >
                                                No compatible firmware found
                                            </div>
                                        `
                                }

                            </div>

                        </div>
                    `;

                }

            ).join("");

    }


    function validateFirmwareAssignments() {

        for (
            const device
            of wizardDevices
        ) {

            const selector =
                document.querySelector(
                    `.firmware-assignment-select[data-device-ip="${device.ip}"]`
                );


            if (
                !selector ||
                !selector.value
            ) {

                showToast(
                    `No compatible firmware selected for ${device.hostname}.`
                );

                return false;

            }

        }


        return true;

    }


    function getWizardAssignments() {

        const assignments = {};


        document
            .querySelectorAll(
                ".firmware-assignment-select"
            )
            .forEach(
                selector => {

                    assignments[
                        selector.dataset.deviceIp
                    ] =
                        selector.value;

                }
            );


        return assignments;

    }


    function renderWizardReview() {

        const assignments =
            getWizardAssignments();


        const firmwareMap =
            Object.fromEntries(
                wizardFirmwares.map(
                    firmware => [
                        firmware.id,
                        firmware
                    ]
                )
            );


        const container =
            document.getElementById(
                "wizard-review-content"
            );


        container.innerHTML =
            wizardDevices.map(
                device => {

                    const firmware =
                        firmwareMap[
                            assignments[
                                device.ip
                            ]
                        ] || {};


                    return `
                        <div
                            class="review-device"
                        >

                            <div>

                                <strong>
                                    ${escapeHtml(device.hostname)}
                                </strong>

                                <span>
                                    ${escapeHtml(device.ip)}
                                </span>

                            </div>


                            <div>

                                <strong>
                                    ${escapeHtml(device.model)}
                                </strong>

                                <span>
                                    ${escapeHtml(device.vendor)}
                                </span>

                            </div>


                            <div>

                                <strong>
                                    ${escapeHtml(device.version)}
                                </strong>

                                <span>
                                    Current Version
                                </span>

                            </div>


                            <div>

                                <strong>
                                    ${escapeHtml(firmware.version)}
                                </strong>

                                <span>
                                    ${escapeHtml(firmware.filename)}
                                </span>

                            </div>

                        </div>
                    `;

                }

            ).join("");

    }


    function setWizardStep(
        step
    ) {

        wizardStep =
            step;


        document
            .querySelectorAll(
                ".wizard-panel"
            )
            .forEach(
                panel =>
                    panel.classList.remove(
                        "active"
                    )
            );


        document
            .querySelectorAll(
                ".wizard-step"
            )
            .forEach(
                indicator =>
                    indicator.classList.remove(
                        "active"
                    )
            );


        document
            .getElementById(
                `wizard-step-${step}`
            )
            .classList
            .add(
                "active"
            );


        document
            .querySelector(
                `[data-step-indicator="${step}"]`
            )
            .classList
            .add(
                "active"
            );


        const backButton =
            document.getElementById(
                "wizard-back-button"
            );


        const nextButton =
            document.getElementById(
                "wizard-next-button"
            );


        const createButton =
            document.getElementById(
                "wizard-create-job-button"
            );


        backButton.classList.toggle(
            "hidden",
            step === 1
        );


        nextButton.classList.toggle(
            "hidden",
            step === 3
        );


        createButton.classList.toggle(
            "hidden",
            step !== 3
        );


        if (
            step === 3
        ) {

            renderWizardReview();

        }

    }


    document
        .getElementById(
            "wizard-next-button"
        )
        .addEventListener(
            "click",
            () => {

                if (
                    wizardStep === 2 &&
                    !validateFirmwareAssignments()
                ) {

                    return;

                }


                if (
                    wizardStep < 3
                ) {

                    setWizardStep(
                        wizardStep + 1
                    );

                }

            }
        );


    document
        .getElementById(
            "wizard-back-button"
        )
        .addEventListener(
            "click",
            () => {

                if (
                    wizardStep > 1
                ) {

                    setWizardStep(
                        wizardStep - 1
                    );

                }

            }
        );


    document
        .getElementById(
            "close-upgrade-wizard"
        )
        .addEventListener(
            "click",
            closeUpgradeWizard
        );


    document
        .getElementById(
            "wizard-cancel-button"
        )
        .addEventListener(
            "click",
            closeUpgradeWizard
        );


    document
        .getElementById(
            "wizard-create-job-button"
        )
        .addEventListener(
            "click",
            async () => {

                if (
                    !validateFirmwareAssignments()
                ) {

                    return;

                }


                const button =
                    document.getElementById(
                        "wizard-create-job-button"
                    );


                button.disabled =
                    true;


                button.textContent =
                    "Creating...";


                try {

                    const jobName =
                        document
                            .getElementById(
                                "upgrade-job-name"
                            )
                            .value
                            .trim();


                    await apiRequest(
                        "/lifecycle/api/jobs",
                        {

                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({

                                    name:
                                        jobName,

                                    devices:
                                        wizardDevices.map(
                                            device =>
                                                device.ip
                                        ),

                                    assignments:
                                        getWizardAssignments()

                                })

                        }
                    );


                    closeUpgradeWizard();


                    document
                        .querySelectorAll(
                            ".device-checkbox"
                        )
                        .forEach(
                            checkbox =>
                                checkbox.checked =
                                    false
                        );


                    updateDeviceSelection();


                    await loadDashboard();

                    await loadJobs();


                    navigateToPage(
                        "jobs"
                    );


                    showToast(
                        "Upgrade job created."
                    );


                } catch (error) {

                    showToast(
                        error.message
                    );

                } finally {

                    button.disabled =
                        false;


                    button.textContent =
                        "Create Upgrade Job";

                }

            }
        );


    function getJobStatusClass(
        status
    ) {

        if (
            status === "ready"
        ) {
            return "job-status-ready";
        }


        if (
            status === "completed"
        ) {
            return "job-status-completed";
        }


        if (
            status === "precheck_failed"
            ||
            status === "failed"
        ) {
            return "job-status-failed";
        }


        if (
            status === "prechecking"
            ||
            status === "running"
        ) {
            return "job-status-running";
        }


        return "status-offline";

    }


    function calculateJobProgress(
        job
    ) {

        const devices =
            job.devices ||
            [];


        if (
            devices.length === 0
        ) {
            return 0;
        }


        const total =
            devices.reduce(
                (
                    sum,
                    device
                ) =>
                    sum +
                    Number(
                        device.progress ||
                        0
                    ),
                0
            );


        return Math.round(
            total /
            devices.length
        );

    }


    function renderLiveCommandPanel(device) {
        // device.live_command_results is persisted by
        // execute_config_push_job's "command_result" branch the moment
        // EACH pushed line's outcome is known (see routes.py) -- this is
        // the authoritative, poll-driven baseline: correct on every
        // refresh even if the SSE connection below never opens or drops.
        // syncJobStreams() appends rows into the SAME .live-command-list
        // between poll ticks for a snappier feel; the next poll always
        // rebuilds this panel from scratch from the persisted results, so
        // anything appended live self-corrects the moment the next poll
        // lands rather than needing to be reconciled by hand.
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
                <div class="live-command-list">
                    ${rows}
                </div>
            </div>
        `;
    }


    function renderPrecheck(
        device
    ) {

        const precheck =
            device.precheck;


        if (
            !precheck ||
            !precheck.checks
        ) {
            return "";
        }


        return `
            <div
                class="precheck-result"
            >

                <div
                    class="precheck-title"
                >
                    Pre-Check Results
                    -
                    ${escapeHtml(device.hostname)}
                </div>


                <div
                    class="precheck-grid"
                >

                    ${
                        precheck.checks.map(
                            check => `

                                <div
                                    class="
                                        precheck-item
                                        ${escapeHtml(check.status)}
                                    "
                                >

                                    <strong>
                                        ${
                                            check.status === "passed"
                                                ? "✓"
                                                : "×"
                                        }

                                        ${escapeHtml(check.name)}
                                    </strong>


                                    <span>
                                        ${escapeHtml(check.message)}
                                    </span>

                                </div>

                            `
                        ).join("")
                    }

                </div>

                ${renderPrecheckRawOutputs(precheck.raw_outputs)}

            </div>
        `;

    }


    function renderPrecheckRawOutputs(rawOutputs) {

        if (
            !rawOutputs ||
            Object.keys(rawOutputs).length === 0
        ) {
            return "";
        }

        return `
            <div class="precheck-raw-section">
                <div class="precheck-raw-heading">
                    Huawei Raw Command Outputs
                </div>

                ${
                    Object.entries(rawOutputs).map(
                        ([key, item]) => `
                            <details class="precheck-raw-item">
                                <summary>
                                    <span>${escapeHtml(item.command || key)}</span>
                                    <span class="raw-output-status ${escapeHtml(item.status || "success")}">
                                        ${escapeHtml((item.status || "success").toUpperCase())}
                                    </span>
                                </summary>
                                <pre>${escapeHtml(item.output || "No output returned.")}</pre>
                            </details>
                        `
                    ).join("")
                }
            </div>
        `;

    }


    function formatLogTime(timestamp) {
        if (!timestamp) {
            return "--:--:--";
        }

        const date = new Date(timestamp);
        if (Number.isNaN(date.getTime())) {
            return String(timestamp);
        }

        return date.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        });
    }


    async function loadJobs() {

        const container =
            document.getElementById(
                "upgrade-job-list"
            );


        if (!container) {
            return;
        }


        // Preserve each execution log's scroll state across this re-render.
        // A panel counts as "following the tail" if it's within 40px of its
        // own bottom (or has never been scrolled at all, e.g. a brand new
        // job) — in that case we keep it pinned to the bottom after the
        // refresh so the newest lines are always visible without the user
        // having to scroll down manually. Anything scrolled further up than
        // that is left where it was, so reading earlier lines isn't
        // interrupted by the next poll.
        const logScrollState = new Map();
        container
            .querySelectorAll(".execution-log-list[data-job-id]")
            .forEach(panel => {
                const distanceFromBottom =
                    panel.scrollHeight - panel.scrollTop - panel.clientHeight;
                logScrollState.set(panel.dataset.jobId, {
                    followTail: distanceFromBottom <= 40,
                    scrollTop: panel.scrollTop,
                });
            });


        try {

            const data =
                await apiRequest(
                    "/lifecycle/api/jobs"
                );


            const jobs =
                data.jobs ||
                [];


            if (
                jobs.length === 0
            ) {

                container.innerHTML = `
                    <div
                        class="empty-state"
                    >
                        No upgrade jobs created.
                    </div>
                `;

                return;

            }


            container.innerHTML =
                jobs.map(
                    job => {

                        const progress =
                            calculateJobProgress(
                                job
                            );


                        const canPrecheck =
                            [
                                "pending",
                                "precheck_failed"
                            ].includes(
                                job.status
                            );


                        const canStartUpgrade =
                            job.status ===
                            "ready";


                        const isRunning =
                            job.status ===
                            "running";


                        return `

                            <div
                                class="job-card"
                                data-job-id="${escapeHtml(job.id)}"
                                data-job-type="${escapeHtml(job.type || "upgrade")}"
                            >

                                <div
                                    class="job-card-header"
                                >

                                    <div>

                                        <strong>
                                            ${escapeHtml(job.name)}
                                        </strong>

                                        <span>
                                            ${escapeHtml(job.created_at)}
                                        </span>

                                    </div>


                                    <div
                                        class="job-actions"
                                    >

                                        <span
                                            class="
                                                status-badge
                                                ${getJobStatusClass(job.status)}
                                            "
                                        >
                                            ${escapeHtml(job.status)}
                                        </span>


                                        ${
                                            canPrecheck
                                                ?
                                                `
                                                    <button
                                                        type="button"
                                                        class="
                                                            button
                                                            button-primary
                                                            button-small
                                                            run-precheck-button
                                                        "
                                                        data-job-id="${escapeHtml(job.id)}"
                                                        data-job-type="${escapeHtml(job.type || "upgrade")}"
                                                    >
                                                        Run Pre-Check
                                                    </button>
                                                `
                                                :
                                                ""
                                        }


                                        ${
                                            canStartUpgrade
                                                ?
                                                `
                                                    <button
                                                        type="button"
                                                        class="
                                                            button
                                                            button-primary
                                                            button-small
                                                            start-upgrade-button
                                                        "
                                                        data-job-id="${escapeHtml(job.id)}"
                                                        data-job-type="${escapeHtml(job.type || "upgrade")}"
                                                    >
                                                        ${job.type === "config_push" ? "Start Config Push" : "Start Upgrade"}
                                                    </button>
                                                `
                                                :
                                                ""
                                        }


                                        <button
                                            type="button"
                                            class="
                                                button
                                                button-danger
                                                button-small
                                                delete-job-button
                                            "
                                            data-job-id="${escapeHtml(job.id)}"
                                        >
                                            Delete
                                        </button>

                                    </div>

                                </div>


                                <div
                                    class="job-progress-wrapper"
                                >

                                    <div
                                        class="job-progress-info"
                                    >

                                        <span>
                                            Overall Progress
                                        </span>

                                        <span>
                                            ${progress}%
                                        </span>

                                    </div>


                                    <div
                                        class="job-progress"
                                    >

                                        <div
                                            class="job-progress-bar"
                                            style="width: ${progress}%"
                                        ></div>

                                    </div>

                                </div>


                                ${
                                    (
                                        job.devices ||
                                        []
                                    ).map(
                                        device => `

                                            <div
                                                class="job-device-row"
                                                data-ip="${escapeHtml(device.ip)}"
                                            >

                                                <div>

                                                    <strong>
                                                        ${escapeHtml(device.hostname)}
                                                    </strong>

                                                    <div>
                                                        ${escapeHtml(device.ip)}
                                                    </div>

                                                </div>


                                                <div>
                                                    ${escapeHtml(device.model)}
                                                </div>


                                                <div>
                                                    ${escapeHtml(device.current_version)}
                                                </div>


                                                <div
                                                    class="target-version"
                                                >
                                                    ${escapeHtml(device.target_version)}
                                                </div>


                                                <div
                                                    class="
                                                        job-stage
                                                        execution-stage
                                                    "
                                                >

                                                    ${
                                                        device.status === "running"
                                                            ?
                                                            `
                                                                <span
                                                                    class="execution-running-dot"
                                                                ></span>
                                                            `
                                                            :
                                                            ""
                                                    }


                                                    ${
                                                        device.status === "completed"
                                                            ?
                                                            `
                                                                <span
                                                                    class="completed-check"
                                                                >
                                                                    ✓
                                                                </span>
                                                            `
                                                            :
                                                            ""
                                                    }


                                                    <span>
                                                        ${escapeHtml(device.stage)}
                                                    </span>

                                                </div>

                                            </div>


                                            ${
                                                job.type === "config_push"
                                                    ? renderLiveCommandPanel(device)
                                                    : ""
                                            }

                                            ${renderPrecheck(device)}

                                        `
                                    ).join("")
                                }

                                ${
                                    (job.logs || []).length
                                        ?
                                        `
                                            <div class="execution-log-panel">
                                                <div class="execution-log-title">
                                                    Execution Log
                                                </div>
                                                <div class="execution-log-list" data-job-id="${escapeHtml(job.id)}">
                                                    ${(job.logs || []).map(log => `
                                                        <div class="execution-log-line ${escapeHtml(log.level || "info")}">
                                                            <span>${escapeHtml(formatLogTime(log.timestamp))}</span>
                                                            <strong>${escapeHtml(log.message || "")}</strong>
                                                        </div>
                                                    `).join("")}
                                                </div>
                                            </div>
                                        `
                                        :
                                        ""
                                }

                            </div>

                        `;

                    }

                ).join("");


            container
                .querySelectorAll(".execution-log-list[data-job-id]")
                .forEach(panel => {
                    const previous = logScrollState.get(panel.dataset.jobId);
                    if (!previous || previous.followTail) {
                        panel.scrollTop = panel.scrollHeight;
                    } else {
                        panel.scrollTop = previous.scrollTop;
                    }
                });


            syncJobStreams(jobs);


        } catch (error) {

            console.error(
                error
            );


            container.innerHTML = `
                <div
                    class="empty-state"
                >
                    Failed to load upgrade jobs.
                </div>
            `;

        }

    }


    document.addEventListener(
        "click",
        async event => {

            const startUpgradeButton =
                event.target.closest(
                    ".start-upgrade-button"
                );


            if (
                startUpgradeButton
            ) {

                const isConfigPush = startUpgradeButton.dataset.jobType === "config_push";
                const defaultLabel = isConfigPush ? "Start Config Push" : "Start Upgrade";

                const confirmed =
                    confirm(
                        isConfigPush
                            ? "Push the draft config to every device in this job?"
                            : "Start upgrade for all devices in this job?"
                    );


                if (
                    !confirmed
                ) {
                    return;
                }


                startUpgradeButton.disabled =
                    true;


                startUpgradeButton.textContent =
                    "Starting...";


                try {

                    const settings = await apiRequest("/lifecycle/api/settings");
                    let password = "";

                    if (settings.demo_mode === false) {
                        const upgradeUsername = settings?.ssh?.username || "";
                        password = prompt(
                            isConfigPush
                                ? (upgradeUsername
                                    ? `REAL CONFIG PUSH: Enter SSH password for '${upgradeUsername}'. The draft config will be applied and saved. Check Settings if this username is wrong.`
                                    : "REAL CONFIG PUSH: Enter SSH password. No SSH username is set in Settings yet, so login will fail — set it in Settings first.")
                                : (upgradeUsername
                                    ? `REAL HUAWEI UPGRADE: Enter SSH password for '${upgradeUsername}'. The device may reboot. Check Settings if this username is wrong.`
                                    : "REAL HUAWEI UPGRADE: Enter SSH password. No SSH username is set in Settings yet, so login will fail — set it in Settings first.")
                        );

                        if (password === null) {
                            startUpgradeButton.disabled = false;
                            startUpgradeButton.textContent = defaultLabel;
                            return;
                        }

                        if (!password) {
                            throw new Error(`SSH password is required for real ${isConfigPush ? "config push" : "upgrade"} mode.`);
                        }

                        const finalConfirmation = confirm(
                            isConfigPush
                                ? "Confirm REAL config push to these devices?"
                                : "Confirm REAL Huawei firmware upgrade and reboot?"
                        );

                        if (!finalConfirmation) {
                            startUpgradeButton.disabled = false;
                            startUpgradeButton.textContent = defaultLabel;
                            return;
                        }
                    }

                    await apiRequest(
                        `/lifecycle/api/jobs/${startUpgradeButton.dataset.jobId}/start`,
                        {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({ password })
                        }
                    );


                    await loadJobs();

                    await loadDashboard();


                    startJobPolling();


                    showToast(
                        isConfigPush ? "Config push started." : "Upgrade started."
                    );


                } catch (error) {

                    showToast(
                        error.message
                    );


                    await loadJobs();

                }


                return;

            }


            const precheckButton =
                event.target.closest(
                    ".run-precheck-button"
                );


            if (
                precheckButton
            ) {

                const jobId =
                    precheckButton.dataset.jobId;


                precheckButton.disabled =
                    true;


                precheckButton.textContent =
                    "Checking...";


                const demoMode =
                    document.getElementById(
                        "demo-mode"
                    ).checked;

                let password = "";

                if (!demoMode) {
                    let promptUsername = "";
                    try {
                        const currentSettings = await apiRequest("/lifecycle/api/settings");
                        promptUsername = currentSettings?.ssh?.username || "";
                    } catch (e) {
                        // fall through with an empty username hint
                    }

                    password = prompt(
                        promptUsername
                            ? `Enter SSH password for '${promptUsername}' (this Pre-Check) — check Settings if this username is wrong:`
                            : "Enter SSH password for this Pre-Check — no SSH username is set in Settings yet, so login will fail. Set it in Settings first."
                    );

                    if (password === null) {
                        precheckButton.disabled = false;
                        precheckButton.textContent = "Run Pre-Check";
                        return;
                    }

                    if (!password) {
                        showToast("SSH password is required.");
                        precheckButton.disabled = false;
                        precheckButton.textContent = "Run Pre-Check";
                        return;
                    }
                }

                try {

                    await apiRequest(
                        `/lifecycle/api/jobs/${jobId}/precheck`,
                        {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json"
                            },
                            body: JSON.stringify({
                                password: password
                            })
                        }
                    );


                    await loadJobs();

                    await loadDashboard();


                    showToast(
                        "Pre-Check completed."
                    );


                } catch (error) {

                    showToast(
                        error.message
                    );


                    await loadJobs();

                }


                return;

            }


            const deleteButton =
                event.target.closest(
                    ".delete-job-button"
                );


            if (
                deleteButton
            ) {

                const confirmed =
                    confirm(
                        "Delete this upgrade job?"
                    );


                if (
                    !confirmed
                ) {
                    return;
                }


                try {

                    await apiRequest(
                        `/lifecycle/api/jobs/${deleteButton.dataset.jobId}`,
                        {
                            method: "DELETE"
                        }
                    );


                    await loadJobs();

                    await loadDashboard();


                    showToast(
                        "Upgrade job deleted."
                    );


                } catch (error) {

                    showToast(
                        error.message
                    );

                }

            }

        }
    );




    // ========================================================
    // CONFIG PUSH -- LIVE COMMAND STREAM (SSE)
    //
    // The regular /lifecycle/api/jobs poll (loadJobs(), above) already
    // carries device.live_command_results, so the live-command panel is
    // correct on every poll regardless of this. What SSE adds is
    // updating it BETWEEN poll ticks -- the closer-to-real-time "kaya
    // live ssh gitu" view -- by opening one EventSource per running
    // config_push job (not per device: routes.py's stream_job() already
    // multiplexes every device in the job over the same connection) and
    // appending rows as command_result events arrive.
    //
    // Appending is deliberately not de-duplicated against the next
    // poll's full re-render: the panel is rebuilt from
    // device.live_command_results on every poll anyway, so anything
    // appended here just gets replaced by the authoritative version a
    // few seconds later. Simpler than reconciling two sources of truth,
    // and the failure mode if it ever mismatched would be a cosmetic
    // flash, not stale or wrong data reaching the operator.
    // ========================================================

    const activeJobStreams = new Map();

    function closeJobStream(jobId) {
        const source = activeJobStreams.get(jobId);
        if (source) {
            source.close();
            activeJobStreams.delete(jobId);
        }
    }

    function openJobStream(jobId) {
        if (activeJobStreams.has(jobId) || typeof EventSource === "undefined") {
            return;
        }

        const source = new EventSource(`/lifecycle/api/jobs/${jobId}/stream`);

        source.addEventListener("command_result", event => {
            let result;
            try {
                result = JSON.parse(event.data);
            } catch (error) {
                return;
            }

            const list = document.querySelector(
                `.job-card[data-job-id="${jobId}"] .job-device-row[data-ip="${cssEscape(result.ip || "")}"] .live-command-list`
            );
            if (!list) {
                // The panel hasn't been rendered by a poll yet (job just
                // started) -- the next poll tick will pick this result up
                // from the persisted jobs.json, so there's nothing to do
                // here but wait for it rather than trying to build the
                // panel from scratch out of a single event.
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
            closeJobStream(jobId);
        });

        source.addEventListener("error", () => {
            // A job that's gone (deleted, or the dev server restarted)
            // would otherwise have EventSource retry forever -- close it
            // and let the next poll's syncJobStreams() decide whether to
            // reopen (it won't, once the job is no longer "running").
            closeJobStream(jobId);
        });

        activeJobStreams.set(jobId, source);
    }

    function syncJobStreams(jobs) {
        const runningConfigPushIds = new Set(
            (jobs || [])
                .filter(job => job.type === "config_push" && job.status === "running")
                .map(job => job.id)
        );

        runningConfigPushIds.forEach(jobId => openJobStream(jobId));

        Array.from(activeJobStreams.keys()).forEach(jobId => {
            if (!runningConfigPushIds.has(jobId)) {
                closeJobStream(jobId);
            }
        });
    }

    function cssEscape(value) {
        if (window.CSS && typeof window.CSS.escape === "function") {
            return window.CSS.escape(value);
        }
        return String(value).replace(/["\\]/g, "\\$&");
    }


    let jobPollingTimer = null;


    function startJobPolling() {

        if (
            jobPollingTimer
        ) {
            return;
        }


        jobPollingTimer =
            setInterval(
                async () => {

                    try {

                        const data =
                            await apiRequest(
                                "/lifecycle/api/jobs"
                            );


                        const hasRunningJobs =
                            (
                                data.jobs ||
                                []
                            ).some(
                                job =>
                                    job.status ===
                                    "running"
                            );


                        await loadJobs();

                        await loadDashboard();


                        if (
                            !hasRunningJobs
                        ) {

                            clearInterval(
                                jobPollingTimer
                            );


                            jobPollingTimer =
                                null;

                        }


                    } catch (error) {

                        console.error(
                            error
                        );

                    }

                },
                1500
            );

    }


    // ========================================================
    // INITIAL LOAD
    // ========================================================

    loadDashboard();

    loadDevices();

    loadSettings();

});
