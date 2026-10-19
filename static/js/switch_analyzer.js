(() => {
  const form = document.getElementById("switch-form");
  if (!form) return;

  const configFile = document.getElementById("switch-config-file");
  const button = document.getElementById("switch-analyze-button");
  const empty = document.getElementById("switch-empty");
  const resultPanel = document.getElementById("switch-result");
  const firewallResultPanel = document.getElementById("switch-firewall-result");
  const exportButton = document.getElementById("switch-export-button");
  const firewallExportButton = document.getElementById("firewall-export-button");
  let lastResult = null;
  const esc = value => window.NES.escape(value ?? "");
  const display = value => Array.isArray(value) ? value.join("\n") : (value ?? "");
  const formatKey = key => String(key).replaceAll("_", " ").replace(/\b\w/g, value => value.toUpperCase());

  function setFile(input, labelId, clearId, fallback) {
    document.getElementById(labelId).textContent = input.files[0]?.name || fallback;
    document.getElementById(clearId)?.classList.toggle("hidden", !input.files.length);
  }
  const SWITCH_FILE_FALLBACK = "Cisco, Huawei, or Aruba capture — each file is one device";
  const SWITCH_FILE_FALLBACK_MORE = "Add more files — the devices already analyzed stay";

  // ---- The file list ---------------------------------------------------------------------------
  // The list is the source of truth. Picking or dropping files ADDS to it (a file is never listed twice),
  // a file leaves with its x, and "Analyze Switch" analyses only what is new (or what was analyzed with another
  // vendor choice), so devices that are already done are kept and nothing has to be chosen again.
  let queue = [];      // { id, name, size, file, text, status: "waiting" | "done" | "failed", vendor, result, error }
  let nextEntryId = 1;
  const fileKey = file => `${file.name}|${file.size}|${file.lastModified}`;
  const sizeText = bytes => (bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : bytes >= 1024 ? `${Math.round(bytes / 1024)} KB` : `${bytes} B`);
  const STATE_TEXT = { waiting: "waiting", done: "analyzed", failed: "failed" };

  function renderFileList() {
    const list = document.getElementById("switch-file-list");
    if (list) {
      list.innerHTML = queue.map(entry => `<li data-file-id="${entry.id}"><span class="sw-file-name" title="${esc(entry.name)}">${esc(entry.name)}</span>`
        + `<small>${esc(sizeText(entry.size))}</small><span class="sw-file-state ${entry.status}">${STATE_TEXT[entry.status]}</span>`
        + `<button type="button" class="sw-file-x" data-remove-file="${entry.id}" aria-label="Remove ${esc(entry.name)}" title="Remove this file and its analysis">×</button></li>`).join("");
      list.classList.toggle("hidden", !queue.length);
    }
    document.getElementById("switch-file-label").textContent = queue.length ? SWITCH_FILE_FALLBACK_MORE : SWITCH_FILE_FALLBACK;
    const clear = document.getElementById("clear-switch-file");
    clear?.classList.toggle("hidden", !queue.length);
    if (clear) clear.textContent = queue.length > 1 ? `Remove all ${queue.length} files` : "Remove file";
  }

  function addFiles(files) {
    const known = new Set(queue.filter(entry => entry.file).map(entry => fileKey(entry.file)));
    let added = 0;
    files.forEach(file => {
      if (known.has(fileKey(file))) return;
      known.add(fileKey(file));
      queue.push({ id: nextEntryId++, name: file.name, size: file.size, file, text: "", status: "waiting", vendor: "", result: null, error: "" });
      added += 1;
    });
    renderFileList();
    if (files.length && !added) window.NES.toast("These files are already in the list.");
  }

  configFile.addEventListener("change", () => { addFiles([...configFile.files]); configFile.value = ""; });
  const dropZone = configFile.closest(".drop-zone");
  if (dropZone) {
    ["dragenter", "dragover"].forEach(name => dropZone.addEventListener(name, event => { event.preventDefault(); dropZone.classList.add("dragover"); }));
    ["dragleave", "drop"].forEach(name => dropZone.addEventListener(name, event => { event.preventDefault(); dropZone.classList.remove("dragover"); }));
    dropZone.addEventListener("drop", event => addFiles([...(event.dataTransfer?.files || [])]));
  }
  document.getElementById("clear-switch-file").addEventListener("click", () => removeEntries(queue.map(entry => entry.id)));
  document.addEventListener("click", event => {
    const remove = event.target.closest("[data-remove-file]");
    if (remove) removeEntries([Number(remove.dataset.removeFile)]);
    const removeDevice = event.target.closest("[data-remove-device]");
    if (removeDevice) {
      const entry = devices[Number(removeDevice.dataset.removeDevice)];
      if (entry) removeEntries([entry.id]);
    }
  });

  function switchTab(tabName) {
    // a tab hidden because the capture has no data is opened on request (a dashboard bar, a "Open Findings" button)
    document.querySelector(`#switch-tabs button[data-tab="${tabName}"]`)?.classList.remove("hidden");
    document.querySelectorAll("#switch-tabs button").forEach(item => item.classList.toggle("active", item.dataset.tab === tabName));
    document.querySelectorAll("#switch-result .tab-content").forEach(item => item.classList.toggle("active", item.id === `switch-tab-${tabName}`));
  }
  document.getElementById("switch-tabs").addEventListener("click", event => {
    const tabButton = event.target.closest("button[data-tab]");
    if (tabButton) switchTab(tabButton.dataset.tab);
  });

  // Single Device / Compare Devices are two fully separate top-level
  // views (not a form stacked above a collapsible section) so each one
  // has room to show its complete result set without the other's forms
  // and tables crowding the page.
  function switchMode(mode) {
    document.querySelectorAll("#switch-mode-tabs button").forEach(item => item.classList.toggle("active", item.dataset.mode === mode));
    document.getElementById("switch-mode-single").classList.toggle("active", mode === "single");
    document.getElementById("switch-mode-compare").classList.toggle("active", mode === "compare");
    document.getElementById("switch-mode-sizing")?.classList.toggle("active", mode === "sizing");
    document.getElementById("switch-mode-collect")?.classList.toggle("active", mode === "collect");
  }
  document.getElementById("switch-mode-tabs").addEventListener("click", event => {
    const modeButton = event.target.closest("button[data-mode]");
    if (modeButton) switchMode(modeButton.dataset.mode);
  });

  // Firewall-shaped results (Mikrotik/Palo Alto, see renderFirewallResult
  // below) render into their own tab-shell/panel entirely separate from
  // the switch dashboard's #switch-tabs -- same tab-switching pattern,
  // just scoped to #switch-firewall-result instead of #switch-result.
  function firewallTab(tabName) {
    document.querySelectorAll("#firewall-tabs button").forEach(item => item.classList.toggle("active", item.dataset.tab === tabName));
    document.querySelectorAll("#switch-firewall-result .tab-content").forEach(item => item.classList.toggle("active", item.id === `firewall-tab-${tabName}`));
  }
  document.getElementById("firewall-tabs")?.addEventListener("click", event => {
    const tabButton = event.target.closest("button[data-tab]");
    if (tabButton) firewallTab(tabButton.dataset.tab);
  });

  // Tone of a status pill. "admin down" is amber (intentional shutdown) and
  // deliberately not the red of a port that is down by itself.
  const STATUS_TONE = { "same": "ok", "changed": "warn", "moved": "warn", "only on a": "warn", "only on b": "warn", "applied": "ok", "referenced": "ok", "not applied": "mute", "up": "ok", "down": "bad", "admin down": "warn", "unknown": "mute", "both": "ok", "only here": "warn", "incomplete": "warn", "unresolved": "mute", "system": "mute", "high": "bad", "medium": "warn", "low": "mute", "info": "mute", "healthy": "ok", "not bundled": "bad", "good": "ok", "green": "ok", "normal": "ok", "ok": "ok", "yellow": "warn", "warning": "warn", "red": "bad", "critical": "bad", "bad": "bad", "emergencies": "bad", "alerts": "bad", "errors": "bad", "warnings": "warn", "notifications": "mute", "informational": "mute", "debugging": "mute", "analyzed": "ok", "covered": "ok", "ignored": "mute", "not parsed": "warn", "error": "bad", "missing": "warn", "active": "ok", "act/unsup": "mute", "suspended": "warn", "suspend": "warn", "config only": "warn", "device only": "mute", "trunking": "ok", "not-trunking": "warn", "forwarding": "ok", "blocking": "warn", "learning": "warn", "listening": "warn", "broken (inconsistent)": "bad", "this switch": "ok", "root bridge": "ok", "off": "mute", "on": "ok", "faulty": "bad", "deny": "bad", "searching": "warn" };
  const toneOf = value => STATUS_TONE[String(value ?? "").toLowerCase()] || "";

  function rowMarkup(columns, row, statusColumn) {
    const rowStatus = statusColumn ? String(display(statusColumn.value ? statusColumn.value(row) : row[statusColumn.key])).toLowerCase() : "";
    const statusAttr = statusColumn ? ` data-row-status="${esc(rowStatus)}"` : "";
    return `<tr${statusAttr}>${columns.map(column => {
      let value = column.value ? column.value(row) : row[column.key]; value = display(value);
      if (column.status) {
        const tone = column.tones ? (column.tones[String(value ?? "").toLowerCase()] || "") : toneOf(value);
        const title = column.title ? column.title(row) : "";
        return `<td><span class="cell-status${tone ? ` tone-${tone}` : ""}"${title ? ` title="${esc(title)}"` : ""}>${esc(value)}</span></td>`;
      }
      // clip: long free text (descriptions) is cut with an ellipsis and keeps the full value in a tooltip.
      if (column.clip) return `<td class="clip" title="${esc(value)}">${esc(value)}</td>`;
      const hint = column.title && !isBlank(value) ? column.title(row) : "";
      return hint ? `<td title="${esc(hint)}">${esc(value)}</td>` : `<td>${esc(value)}</td>`;
    }).join("")}</tr>`;
  }

  function headMarkup(columns) {
    return `<thead><tr>${columns.map(column => `<th>${esc(column.label)}</th>`).join("")}</tr></thead>`;
  }

  function renderTable(id, columns, rows, options = {}) {
    const table = document.getElementById(id);
    if (options.hideEmpty) columns = dropEmptyColumns(columns, rows).columns;
    const statusColumn = columns.find(column => column.status);
    const body = rows.length ? rows.map(row => rowMarkup(columns, row, statusColumn)).join("") : `<tr><td colspan="${columns.length}">No data found.</td></tr>`;
    table.innerHTML = headMarkup(columns) + `<tbody>${body}</tbody>`;
  }

  // ---- Filterable tables (interfaces, ARP, MAC) ---------------------------
  // These can be large (a distribution switch easily learns thousands of
  // MACs), so the rows live in memory and only the first ROW_CAP matching
  // rows are put in the DOM. Searching runs over ALL rows, never just the
  // rendered ones, so a host beyond the cap is still found.
  const ROW_CAP = 500;
  const filterable = new Map(); // table id -> state

  const hexOnly = value => String(value ?? "").toLowerCase().replace(/[^0-9a-f]/g, "");

  // A search term that looks like (part of) a MAC address, in any vendor
  // notation, returns its bare hex digits so "0050.5600" finds "00-50-56-00".
  // IPv4 fragments ("10.1.1.1", "10.10.10.10") are made of 1-3 digit octets
  // and are never taken for MAC text.
  function macDigits(term) {
    if (!/^[0-9a-f.:-]+$/.test(term)) return "";
    const digits = hexOnly(term);
    if (digits.length < 4) return "";
    if (!/[.:-]/.test(term)) return digits.length >= 6 ? digits : "";
    const groups = term.split(/[.:-]/).filter(Boolean);
    if (groups.some(group => group.length > 6)) return "";
    if (term.includes(".") && !term.includes(":") && !term.includes("-")) {
      return groups.some(group => group.length === 4) ? digits : "";
    }
    return digits;
  }

  function filterableState(id, columns, rows, options) {
    const statusColumn = columns.find(column => column.status);
    const entries = rows.map(row => {
      const cells = columns.map(column => String(display(column.value ? column.value(row) : row[column.key]) ?? ""));
      return {
        row,
        text: cells.join("\n").toLowerCase(),
        hex: columns.map((column, index) => (column.mac ? hexOnly(cells[index]) : "")).filter(Boolean).join(" "),
        chip: options.chip ? String(options.chip(row) ?? "").toLowerCase() : "",
        chip2: options.chip2 ? String(options.chip2(row) ?? "").toLowerCase() : "",
      };
    });
    return {
      id, columns, statusColumn, entries,
      query: "", chip: "", chip2: "", cap: ROW_CAP,
      options,
      chipOrder: options.chipOrder || null,
      chipOrder2: options.chipOrder2 || null,
      noun: options.noun || "rows",
      emptyText: options.emptyText || "No data found.",
    };
  }

  function matchEntries(state) {
    const terms = state.query.toLowerCase().split(/\s+/).filter(Boolean).map(term => ({ term, mac: macDigits(term) }));
    return state.entries.filter(entry => (!state.chip || entry.chip === state.chip) && (!state.chip2 || entry.chip2 === state.chip2)
      && terms.every(item => entry.text.includes(item.term) || (item.mac && entry.hex.includes(item.mac))));
  }

  function paintFilterable(state) {
    const table = document.getElementById(state.id);
    if (!table) return;
    if (!table.tHead) table.insertAdjacentHTML("afterbegin", headMarkup(state.columns));
    const matched = matchEntries(state);
    const shown = matched.slice(0, state.cap);
    let body;
    if (!shown.length) {
      body = `<tr class="empty-row"><td colspan="${state.columns.length}">${state.entries.length ? "No row matches the filter." : esc(state.emptyText)}</td></tr>`;
    } else {
      body = shown.map(entry => rowMarkup(state.columns, entry.row, state.statusColumn)).join("");
      if (matched.length > shown.length) {
        body += `<tr class="more-row"><td colspan="${state.columns.length}">Showing ${shown.length} of ${matched.length} rows `
          + `<button type="button" data-show-more="${esc(state.id)}">Show ${ROW_CAP} more</button>`
          + `<button type="button" data-show-all="${esc(state.id)}">Show all ${matched.length}</button></td></tr>`;
      }
    }
    let tbody = table.tBodies[0];
    if (!tbody) tbody = table.appendChild(document.createElement("tbody"));
    tbody.innerHTML = body;
    const total = state.entries.length;
    const label = matched.length === total ? `${total} ${state.noun}` : `${matched.length} of ${total} ${state.noun}`;
    document.querySelectorAll("[data-table-count]").forEach(node => {
      if (node.dataset.tableCount.split(/\s+/).includes(state.id)) node.textContent = label;
    });
  }

  function renderFilterable(id, columns, rows, options = {}) {
    if (options.hideEmpty) {
      const split = dropEmptyColumns(columns, rows);
      columns = split.columns;
      noteHiddenColumns(id, split.hidden);
    }
    const state = filterableState(id, columns, rows, options);
    filterable.set(id, state);
    // A new result starts unfiltered: clear any search text left from the last one.
    document.querySelectorAll("[data-table-search]").forEach(input => {
      if (groupIds(input.dataset.tableSearch).includes(id)) input.value = "";
    });
    const table = document.getElementById(id);
    if (table) table.innerHTML = headMarkup(columns) + "<tbody></tbody>";
    paintFilterable(state);
    refreshChips();
    return state;
  }

  // Same rows, other columns: the search text, the selected chip and the row cap
  // survive. Search matches the visible columns only, so a hit is always visible.
  function reconfigureFilterable(id, columns) {
    const old = filterable.get(id);
    if (!old) return;
    const state = filterableState(id, columns, old.entries.map(entry => entry.row), old.options);
    state.query = old.query; state.chip = old.chip; state.chip2 = old.chip2; state.cap = old.cap;
    filterable.set(id, state);
    const table = document.getElementById(id);
    if (table) table.innerHTML = headMarkup(columns) + "<tbody></tbody>";
    paintFilterable(state);
    refreshChips();
  }

  const groupIds = value => String(value || "").split(/\s+/).filter(Boolean);

  // Chips are built from the data: one per distinct value, with counts. For a
  // Compare pane (two tables, one chip row) the counts read "A / B".
  function refreshChips() {
    paintChipRows("data-chips-for", "chip", "chipOrder");
    paintChipRows("data-chips2-for", "chip2", "chipOrder2");   // a second row of buttons on the same table (log severity)
  }

  function paintChipRows(attribute, field, orderField) {
    const dataKey = attribute.replace(/^data-/, "").replace(/-(\w)/g, (_m, letter) => letter.toUpperCase());
    document.querySelectorAll(`[${attribute}]`).forEach(container => {
      const states = groupIds(container.dataset[dataKey]).map(id => filterable.get(id)).filter(Boolean);
      if (!states.length) { container.innerHTML = ""; return; }
      const counts = states.map(state => {
        const map = new Map();
        state.entries.forEach(entry => { if (entry[field]) map.set(entry[field], (map.get(entry[field]) || 0) + 1); });
        return map;
      });
      const values = new Set();
      counts.forEach(map => map.forEach((_count, value) => values.add(value)));
      if (!values.size) { container.innerHTML = ""; return; }
      const order = states.find(state => state[orderField])?.[orderField] || [];
      const sorted = [...values].sort((a, b) => {
        const ia = order.indexOf(a), ib = order.indexOf(b);
        if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
        const total = value => counts.reduce((sum, map) => sum + (map.get(value) || 0), 0);
        return total(b) - total(a) || a.localeCompare(b);
      });
      const active = states[0][field];
      const countText = value => counts.map(map => map.get(value) || 0).join(" / ");
      const allText = states.map(state => state.entries.length).join(" / ");
      container.innerHTML = [
        `<button type="button" class="filter-chip${active ? "" : " active"}" data-chip="" title="Show everything">All <span class="chip-count">${allText}</span></button>`,
        ...sorted.map(value => {
          const tone = toneOf(value);
          const title = states.length > 1 ? `${value}: ${states.map((_s, index) => `${index ? "Device B" : "Device A"} ${counts[index].get(value) || 0}`).join(", ")}` : value;
          return `<button type="button" class="filter-chip${tone ? ` tone-${tone}` : ""}${active === value ? " active" : ""}" data-chip="${esc(value)}" title="${esc(title)}">`
            + `${tone ? '<i class="chip-dot"></i>' : ""}${esc(value)} <span class="chip-count">${countText(value)}</span></button>`;
        }),
      ].join("");
    });
  }

  document.addEventListener("click", event => {
    const scroll = event.target.closest("[data-scroll-to]");
    if (scroll) {
      document.getElementById(scroll.dataset.scrollTo)?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
      return;
    }
    const chip = event.target.closest(".filter-chip");
    if (chip) {
      const container = chip.closest("[data-chips-for],[data-chips2-for]");
      const second = Boolean(container?.dataset.chips2For);
      groupIds(second ? container.dataset.chips2For : container?.dataset.chipsFor).forEach(id => {
        const state = filterable.get(id);
        if (!state) return;
        state[second ? "chip2" : "chip"] = chip.dataset.chip || "";
        state.cap = ROW_CAP;
        paintFilterable(state);
      });
      refreshChips();
      return;
    }
    const more = event.target.closest("[data-show-more],[data-show-all]");
    if (more) {
      const state = filterable.get(more.dataset.showMore || more.dataset.showAll);
      if (!state) return;
      state.cap = more.dataset.showAll ? Infinity : state.cap + ROW_CAP;
      paintFilterable(state);
    }
  });

  document.addEventListener("input", event => {
    const searchIds = event.target.dataset?.tableSearch;
    if (!searchIds) return;
    const value = event.target.value;
    groupIds(searchIds).forEach(id => {
      const state = filterable.get(id);
      if (state) {
        state.query = value;
        state.cap = ROW_CAP;
        paintFilterable(state);
        return;
      }
      // Small static tables: plain substring filter over the rendered rows.
      const query = value.toLowerCase();
      document.getElementById(id)?.querySelectorAll("tbody tr").forEach(row => {
        row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
      });
    });
  });

  // Dashboard bars jump to the Interfaces tab with one state selected.
  function filterTable(tableId, statusQuery) {
    const state = filterable.get(tableId);
    if (!state) return;
    state.chip = String(statusQuery || "").toLowerCase();
    state.query = "";
    state.cap = ROW_CAP;
    document.querySelectorAll(`[data-table-search~="${tableId}"]`).forEach(input => { input.value = ""; });
    paintFilterable(state);
    refreshChips();
  }

  function renderKVList(id, obj) {
    document.getElementById(id).innerHTML = Object.entries(obj || {})
      .map(([key, value]) => `<div class="kv-row"><span>${esc(formatKey(key))}</span><strong>${esc(display(value) || "—")}</strong></div>`)
      .join("") || `<div class="kv-row"><span>No data</span><strong>—</strong></div>`;
  }

  // Column definitions shared between the single-device dashboard
  // (renderResult) and the Compare Devices "Full Device Data" tables
  // (renderCompareDeviceTables) so both views render each category
  // identically instead of drifting apart.
  // Status is one of up / down / admin down / unknown (see
  // features/switch_analyzer/live_state.py). The pill's tooltip carries the
  // evidence ("shutdown in config; Administratively down in show interfaces
  // status") so a reviewer can see WHY a port was classed the way it was.
  const interfaceStateTitle = row => [row.status_detail, row.status_source ? `source: ${row.status_source}` : ""].filter(Boolean).join(" — ");
  const INTERFACE_CHIP_ORDER = ["up", "down", "admin down", "unknown"];

  // Overview "Serial Numbers": every part with its PID and serial (parts.py).
  const SERIAL_COLUMNS = [
    { label: "Slot", key: "slot" },
    { label: "Kind", key: "kind" },
    { label: "Description", key: "description", clip: true },
    { label: "PID", key: "pid" },
    { label: "Serial Number", key: "serial" },
  ];
  const SERIAL_CHIP_ORDER = ["chassis", "stack member", "stack", "stack module", "stack cable", "module", "power supply", "fan", "transceiver", "part"];

  // Warnings about the capture file itself (a file that mixes two devices' prompts).
  function showCaptureNotes(notes) {
    const box = document.getElementById("switch-capture-notes");
    if (!box) return;
    box.classList.toggle("hidden", !notes.length);
    const detail = document.getElementById("switch-capture-notes-detail");
    if (detail) detail.textContent = notes.map(note => note.text).join(" ");
  }
  // Port-channel membership: the bundle a physical port belongs to (Po101, Eth-Trunk1, lag1) with its state in the bundle,
  // and, on the bundle's own row, the member ports. hideEmpty drops both columns for a capture without bundles.
  const bundleStateText = row => {
    const state = String(row.bundle_state || "");
    if (/^bundled/.test(state)) return "bundled";
    if (/not listed in show lacp neighbor/.test(state)) return "no LACP partner listed";
    if (/^configured as a member/.test(state)) return "configured";
    return state;
  };
  // Cisco's own short spelling so a four-member bundle fits the cell: Ethernet1/45 -> Eth1/45 (the tooltip keeps the full names)
  const shortPort = name => String(name || "").replace(/^TwentyFiveGigE/, "Twe").replace(/^HundredGigE/, "Hu").replace(/^FortyGigabitEthernet/, "Fo").replace(/^TenGigabitEthernet/, "Te")
    .replace(/^GigabitEthernet/, "Gi").replace(/^FastEthernet/, "Fa").replace(/^Ethernet/, "Eth");
  const bundleCell = row => (row.bundle ? `${row.bundle}${bundleStateText(row) ? ` · ${bundleStateText(row)}` : ""}` : "");
  const INTERFACE_COLUMNS = [
    { label: "Name", key: "name" },
    { label: "Port-channel", key: "bundle", value: bundleCell, title: row => (row.bundle ? `${row.name} is a member of ${row.bundle}${row.bundle_mode ? ` (${row.bundle_mode})` : ""}${row.bundle_state ? `: ${row.bundle_state}` : ""}` : "") },
    { label: "Members", key: "bundle_members", value: row => (row.bundle_members || []).map(item => shortPort(item.port)).join(", "), clip: true, title: row => (row.bundle_members || []).map(item => `${item.port}: ${item.state || "member"}`).join("\n") },
    { label: "Status", key: "status", status: true, title: interfaceStateTitle },
    { label: "Protocol", key: "protocol" },
    { label: "Mode", key: "mode" },
    { label: "VLAN", key: "vlan" },
    { label: "Allowed VLANs", key: "allowed_vlans" },
    { label: "IP Address", key: "ip_address" },
    { label: "HSRP/VRRP IP", key: "hsrp_vrrp_ip" },
    { label: "Port Security", key: "port_security" },
    { label: "Description", key: "description" },
  ];
  // Columns only a runtime table such as ArubaOS-CX `show interface` fills; hideEmpty drops them for a capture that has none.
  const INTERFACE_RUNTIME_COLUMNS = [
    { label: "Speed", key: "speed" },
    { label: "Duplex", key: "duplex" },
    { label: "Port Type", key: "port_type" },
    { label: "Link Since", key: "link_since" },
    { label: "Link Changes", key: "transitions", title: () => "Link up and down transitions since the switch booted (show interface)" },
    { label: "RX Errors", key: "rx_errors", title: row => `${row.rx_crc || 0} of them CRC/FCS, in ${row.rx_packets || 0} received packets` },
    { label: "TX Drops", key: "tx_dropped", title: row => `dropped while queuing, ${row.tx_packets || 0} packets sent` },
    { label: "In %", key: "util_in", title: () => "Receive utilisation when the capture was taken" },
    { label: "Out %", key: "util_out", title: () => "Transmit utilisation when the capture was taken" },
    { label: "MAC", key: "mac_address" },
    { label: "MTU", key: "mtu" },
  ];
  // Single Device also spells the evidence out; Compare keeps it in the tooltip
  // so its half-width panes stay readable.
  const INTERFACE_COLUMNS_DETAIL = [...INTERFACE_COLUMNS, ...INTERFACE_RUNTIME_COLUMNS, { label: "Status Detail", key: "status_detail" }];
  // Compare Devices puts two interface tables side by side, each in half the page.
  // It starts with the columns a migration check needs; "All columns" adds Protocol,
  // HSRP/VRRP IP and Port Security. Long text is clipped (full text in the tooltip).
  const INTERFACE_COLUMNS_COMPARE = ["name", "status", "mode", "vlan", "allowed_vlans", "ip_address", "description"]
    .map(key => INTERFACE_COLUMNS.find(column => column.key === key))
    .map(column => (column.key === "description" || column.key === "allowed_vlans" ? { ...column, clip: true } : column));
  const ARP_COLUMNS = [
    { label: "IP Address", key: "ip_address" },
    { label: "MAC Address", key: "mac_address", mac: true },
    { label: "Interface", key: "interface" },
    { label: "VLAN", key: "vlan" },
    { label: "Type", key: "type" },
    { label: "Age", key: "age" },
  ];
  // Protocol keeps the code the device printed (C, S*, O E2, Direct); the group makes "static" or "ospf" searchable.
  const ROUTING_GROUP_ORDER = ["Connected", "Local", "Static", "OSPF", "EIGRP", "BGP", "RIP", "IS-IS", "FHRP", "Other"];
  // VRF, preference / metric, age and route type are printed by NX-OS only; the columns disappear for captures without them.
  const ROUTING_TABLE_COLUMNS = [
    { label: "Protocol", key: "protocol", value: row => (row.group && row.group.toLowerCase() !== String(row.protocol ?? "").toLowerCase() ? `${row.protocol} (${row.group})` : row.protocol) },
    { label: "VRF", key: "vrf" },
    { label: "Destination", key: "destination" },
    { label: "Next Hop", key: "next_hop" },
    { label: "Interface", key: "interface" },
    { label: "Pref / Metric", key: "distance", value: row => (row.distance === undefined || row.distance === "" ? "" : `${row.distance} / ${row.metric ?? ""}`) },
    { label: "Age", key: "age" },
    { label: "Detail", key: "detail", clip: true },
  ];
  const MAC_COLUMNS = [
    { label: "VLAN", key: "vlan" },
    { label: "MAC Address", key: "mac_address", mac: true },
    { label: "Type", key: "type" },
    { label: "Interface", key: "interface" },
    { label: "Age", key: "age" },
  ];
  const PORTCHANNEL_COLUMNS = [
    { label: "Name", key: "name" },
    { label: "Protocol", key: "protocol" },
    { label: "Status", key: "status" },
    { label: "Description", key: "description" },
    { label: "Mode", key: "mode" },
    { label: "VLAN", key: "vlan" },
    { label: "Allowed VLANs", key: "allowed_vlans" },
    { label: "IP Address", key: "ip_address" },
    { label: "Member Ports", key: "members" },
    { label: "Member state", value: row => (row.member_states || []).map(item => (item.flag ? `${item.port} (${item.flag})` : item.meaning ? `${item.port} (${item.meaning})` : item.port)).join(", ") },
    { label: "LACP partner", key: "lacp_partner" },
  ];
  const TRANSCEIVER_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Status", key: "status", status: true },
    { label: "Present", key: "present", value: row => row.present ? "Yes" : "No" },
    { label: "Type", key: "type" },
    { label: "Vendor Part Number", key: "vendor_part_number" },
    { label: "Serial Number", key: "serial_number" },
  ];
  const VPCMLAG_MEMBER_COLUMNS = [
    { label: "ID", key: "id" },
    { label: "Port", key: "port" },
    { label: "Status", key: "status", status: true },
    { label: "Consistency", key: "consistency" },
    { label: "VLANs", key: "vlans" },
  ];
  const POE_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Admin Status", key: "admin_status" },
    { label: "Oper Status", key: "oper_status", status: true },
    { label: "Power (W)", key: "power_watts" },
    { label: "Device", key: "device" },
    { label: "Class", key: "class" },
    { label: "Max (W)", key: "max_watts" },
    { label: "Source", key: "source" },
  ];
  const VLAN_COLUMNS = [
    { label: "VLAN ID", key: "vlan_id" },
    { label: "Name", key: "name" },
    { label: "State", key: "status", status: true },
    { label: "Ports", key: "port_count" },
    { label: "Port list", key: "ports", clip: true },
    { label: "Type", key: "type" },
    { label: "MTU", key: "mtu" },
    { label: "Defined in", key: "source" },
  ];
  const TRUNK_COLUMNS = [
    { label: "Port", key: "port" },
    { label: "Mode", key: "mode" },
    { label: "Encapsulation", key: "encapsulation" },
    { label: "Status", key: "status", status: true },
    { label: "Port-channel", key: "port_channel" },
    { label: "Native VLAN", key: "native_vlan" },
    { label: "Allowed VLANs", key: "allowed", clip: true },
    { label: "Active VLANs", key: "active", clip: true },
    { label: "Forwarding VLANs", key: "forwarding", clip: true },
  ];
  const STP_INSTANCE_COLUMNS = [
    { label: "Instance", key: "id" },
    { label: "Protocol", key: "protocol" },
    { label: "Root", key: "root_role", value: row => (row.is_root ? "this switch" : "other bridge"), status: true },
    { label: "Root priority", key: "root_priority" },
    { label: "Root address", key: "root_address" },
    { label: "Root cost", key: "root_cost" },
    { label: "Root port", key: "root_port" },
    { label: "Bridge priority", key: "bridge_priority" },
    { label: "Ports", value: row => (row.ports || []).length },
    { label: "Blocking", key: "blocking" },
    { label: "Broken", key: "inconsistent" },
  ];
  const STP_PORT_COLUMNS = [
    { label: "Instance", key: "instance" },
    { label: "Interface", key: "interface" },
    { label: "Role", key: "role_name" },
    { label: "State", key: "state_name", status: true },
    { label: "Cost", key: "cost" },
    { label: "Prio.Nbr", value: row => `${row.priority}.${row.port_number}` },
    { label: "Type", key: "type" },
    { label: "Inconsistent", key: "inconsistent", clip: true },
  ];
  const MAC_VLAN_COLUMNS = [
    { label: "VLAN", key: "vlan" },
    { label: "Dynamic", key: "dynamic" },
    { label: "Static", key: "static" },
    { label: "Total", key: "total" },
  ];
  const LICENCE_STATUS_COLUMNS = [
    { label: "Licence", key: "name" },
    { label: "Tag", key: "tag", clip: true },
    { label: "Count", key: "count" },
    { label: "Status", key: "status", status: true },
    { label: "Type", key: "license_type" },
    { label: "Enforcement", key: "enforcement" },
    { label: "Export status", key: "export_status" },
  ];
  const LICENCE_TERM_COLUMNS = [
    { label: "Licence", key: "license" },
    { label: "Tag", key: "tag", clip: true },
    { label: "Type", key: "type" },
    { label: "Start", key: "start" },
    { label: "End", key: "end" },
  ];
  const LICENCE_RTU_COLUMNS = [
    { label: "Feature", key: "feature" },
    { label: "Version", key: "version" },
    { label: "Type", key: "license_type" },
    { label: "State", key: "state" },
    { label: "Evaluation left", key: "eval_left" },
    { label: "Evaluation total", key: "eval_total" },
    { label: "Period used", key: "period_used" },
    { label: "Priority", key: "priority" },
  ];
  const VLAN_CHIP_ORDER = ["config + device", "device only", "config only", "config"];
  const TRUNK_CHIP_ORDER = ["trunking", "trnk-bndl", "not-trunking"];
  const STP_STATE_ORDER = ["forwarding", "blocking", "broken (inconsistent)", "learning", "listening", "disabled"];
  const POE_CHIP_ORDER = ["on", "off", "faulty", "deny", "searching"];

  const NEIGHBOR_COLUMNS = [
    { label: "Protocol", key: "protocol" },
    { label: "Neighbor", key: "neighbor_id" },
    { label: "Local Interface", key: "local_interface" },
    { label: "Remote Interface", key: "remote_interface" },
    { label: "Platform", key: "platform" },
    { label: "Management IP", key: "management_address" },
    { label: "Software", key: "software" },
    { label: "Native VLAN", key: "native_vlan" },
  ];

  // PBR / SLA-Track / NQA — one shared set of columns for both Single
  // Device's Routing tab and Compare Devices' side-by-side panel (see
  // features/switch_analyzer/service.py's _build_pbr_summary for the
  // unified, vendor-neutral shape these read from).
  const PBR_SLA_COLUMNS = [
    { label: "Test", key: "id" },
    { label: "Kind", key: "kind" },
    { label: "Type", key: "test_type" },
    { label: "Destination", key: "destination" },
    { label: "Frequency (s)", key: "frequency" },
    { label: "Timeout (s)", key: "timeout" },
    { label: "Probe Count", key: "probe_count" },
  ];
  const PBR_TRACK_COLUMNS = [
    { label: "Track ID", key: "track_id" },
    { label: "Tracks", key: "tracks" },
  ];
  const PBR_POLICY_COLUMNS = [
    { label: "Mechanism", key: "vendor_mechanism" },
    { label: "Policy Name", key: "policy_name" },
    { label: "Sequence / Precedence", key: "sequence" },
    { label: "Action", key: "action" },
    { label: "Match", key: "match" },
    { label: "Set Next Hop", key: "set_next_hop" },
    { label: "Tracked By", key: "tracked_by" },
  ];
  const PBR_BINDING_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Policy Name", key: "policy_name" },
    { label: "Direction", key: "direction" },
    { label: "Mechanism", key: "mechanism" },
  ];
  const PBR_EEM_COLUMNS = [
    { label: "Applet Name", key: "applet_name" },
    { label: "Route-Map", key: "route_map_name" },
    { label: "Action", key: "action" },
    { label: "Target Interfaces", key: "target_interfaces", value: row => (row.target_interfaces || []).join(", ") },
    { label: "Trigger", key: "trigger_description" },
  ];

  // Renders one device's PBR/SLA-Track/NQA summary into the given
  // table element IDs. Shared by Single Device's Routing tab and
  // Compare Devices' side-by-side panel (called once per device
  // there) so the column definitions above stay in one place.
  function renderPbrTables(ids, pbr) {
    pbr = pbr || {};
    renderTable(ids.sla, PBR_SLA_COLUMNS, pbr.sla_tests || []);
    renderTable(ids.track, PBR_TRACK_COLUMNS, pbr.track_objects || []);
    renderTable(ids.policy, PBR_POLICY_COLUMNS, pbr.pbr_policies || []);
    renderTable(ids.binding, PBR_BINDING_COLUMNS, pbr.pbr_bindings || []);
    renderTable(ids.eem, PBR_EEM_COLUMNS, pbr.eem_dynamic_pbr || []);
  }

  // ---- Layer 3 (l3.py): gateways, default / static routes, OSPF, ACLs --------
  const L3_FINDING_TITLES = {
    ospf_no_interfaces: "OSPF is configured but not running",
    ospf_network_matches_nothing: "OSPF network statements match no interface",
    ospf_all_passive: "OSPF is passive on every interface",
    ip_routing_off: "IP routing is not enabled",
    no_l3_found: "No Layer-3 configuration in this capture",
    l3_address_changed: "Gateway address changed",
    l3_address_moved: "Address moved to another interface",
    l3_interface_missing_b: "Layer-3 interface missing on Device B",
    l3_interface_only_b: "Extra Layer-3 interface on Device B",
    dhcp_helper_differs: "DHCP relay servers differ",
    default_route_changed: "Default route changed",
    default_route_missing_b: "No default route on Device B",
    default_route_only_b: "Default route only on Device B",
    static_route_changed: "Static route next hop changed",
    static_route_missing_b: "Static route missing on Device B",
    static_route_only_b: "Extra static route on Device B",
    ospf_missing_b: "OSPF missing on Device B",
    ospf_not_running_b: "OSPF not running on Device B",
    ospf_area_differs: "OSPF area differs",
    ospf_interface_missing_b: "OSPF interface missing on Device B",
    ospf_inactive_a: "OSPF on Device A carries no routes",
    ospf_only_b: "OSPF only on Device B",
    acl_missing_b: "ACL missing on Device B",
    acl_only_b: "Extra ACL on Device B",
    acl_changed: "ACL differs",
    dhcp_snooping_missing_b: "DHCP snooping missing on Device B",
    dhcp_snooping_vlans_differ: "DHCP snooping VLANs differ",
    inter_vlan_routing_new: "Inter-VLAN routing is new on Device B",
  };

  // ---- Health tab (health.py): findings, LACP partners, spanning tree, environment, licence ----
  const HEALTH_SEVERITY = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const HEALTH_BANNER = { high: "attention", medium: "warning" };
  // What the LACP table, its explanation and the empty-state text say depends on the platform the numbers came from.
  const HEALTH_LACP_TEXT = {
    ios: "From <code>show lacp neighbor</code>. State <code>0x3d</code> = partner is bundled, collecting and distributing; an all-zero partner ID means no LACPDU ever arrived from the far end.",
    nxos: "From <code>show lacp neighbor</code>. State <code>0x3d</code> = partner is bundled, collecting and distributing; an all-zero partner ID means no LACPDU ever arrived from the far end.",
    huawei: "From <code>display eth-trunk</code> (LACP mode, shown as <em>Static</em>). The partner port state is eight bits, printed in this order: Activity, Timeout, Aggregation, Synchronization, Collecting, Distributing, Defaulted, Expired. A healthy partner reads <code>10111100</code>; a partner ID of <code>0000-0000-0000</code> means no LACPDU was received from the far end.",
    aruba: "Link-aggregation state is not read for ArubaOS-Switch yet.",
    aoscx: "From <code>show lacp interface</code>. State letters: A active, P passive, S short and L long timeout, F aggregable, I individual, N in sync, O out of sync, C collecting, D distributing, X expired, E defaulted. A healthy partner reads <code>ALFNCD</code> (or <code>ASFNCD</code> with the fast rate) and the member's forwarding state is <code>up</code>; <code>lacp-block</code> means the port is kept out of the bundle.",
  };
  const HEALTH_LICENCE_HINT = "From <code>show license all</code> and <code>show license usage</code>.";
  const HEALTH_LACP_COLUMNS = [
    { label: "Port", key: "port" },
    { label: "Group", key: "group" },
    { label: "Partner ID", key: "partner_id" },
    { label: "Partner port", key: "partner_port" },
    { label: "Partner state", value: row => row.healthy ? "Healthy" : "Not bundled", status: true, title: row => `${row.state}: ${row.state_bits || "no flags"}` },
    { label: "State", key: "state" },
    { label: "Flags", key: "flags" },
    { label: "Age", key: "age" },
  ];
  const HEALTH_ENV_COLUMNS = [
    { label: "Type", key: "type" },
    { label: "Name", key: "name" },
    { label: "Location", key: "location" },
    { label: "State", key: "state", status: true },
    { label: "Reading", key: "reading" },
  ];
  const HEALTH_STACK_COLUMNS = [
    { label: "Member", key: "member" },
    { label: "Role", key: "role" },
    { label: "MAC", key: "mac" },
    { label: "Priority", key: "priority" },
    { label: "Model", key: "model" },
  ];
  const HEALTH_NXOS_LICENCE_COLUMNS = [
    { label: "Feature", key: "license" },
    { label: "Installed", key: "tag" },
    { label: "Count", key: "count" },
    { label: "Status", key: "status" },
    { label: "Expiry", key: "expiry" },
    { label: "Comments", key: "comments" },
  ];
  const HEALTH_LICENCE_COLUMNS = [
    { label: "Licence", key: "license" },
    { label: "Entitlement", key: "tag" },
    { label: "Count", key: "count" },
    { label: "Status", key: "status" },
  ];

  // Labels for the keys the backend sends for the non-IOS platforms; anything else is title-cased from its key.
  const HEALTH_LABELS = {
    nx_os_release: "NX-OS release", vpc_role: "vPC role", vpc_peer: "vPC peer", vpc_keep_alive: "vPC keep-alive", vpc_peer_switch: "vPC peer-switch",
    bpdu_guard_default: "BPDU Guard default", bpdu_protection: "BPDU protection", bridge_id: "Bridge ID", cpu_utilisation: "CPU utilisation",
    rom_version: "ROM version", portfast_default: "PortFast default", loopguard_default: "Loop Guard default", root_bridge_for: "Root bridge for",
    last_reset_service: "Last reset service", primary_image: "Primary image", secondary_image: "Secondary image", default_boot_image: "Default boot image",
  };
  function renderHealthKV(id, obj) {
    const entries = Object.entries(obj || {});
    document.getElementById(id).innerHTML = entries.length
      ? entries.map(([key, value]) => `<div class="kv-row"><span>${esc(HEALTH_LABELS[key] || formatKey(key))}</span><strong>${esc(display(value) || "—")}</strong></div>`).join("")
      : `<div class="kv-row"><span>No data</span><strong>—</strong></div>`;
  }

  // Only links to the vendors' own documentation are drawn as links, whatever the backend sends.
  const HEALTH_DOC_HOSTS = /^https:\/\/(?:www\.cisco\.com|developer\.cisco\.com|support\.huawei\.com|info\.support\.huawei\.com|community\.networking\.hpe\.com|arubanetworking\.hpe\.com)\//;
  function healthDocLink(doc) {
    const url = doc && String(doc.url || "");
    if (!HEALTH_DOC_HOSTS.test(url)) return "";
    return ` <a class="health-doc" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(doc.title)}</a>`;
  }

  function renderLicenceDetail(detail, supported) {
    const status = (detail.status || []).map(item => [item.label, item.value]);
    const kv = {};
    status.forEach(([label, value]) => { kv[label.toLowerCase().replace(/[^a-z0-9]+/g, "_")] = value; });
    renderKVList("switch-health-licence-status", supported ? kv : {});
    const toggle = (boxId, tableId, columns, rows) => {
      byId(boxId).classList.toggle("hidden", !supported || !rows.length);
      if (rows.length) renderTable(tableId, columns, rows);
    };
    toggle("switch-health-entitlement-box", "switch-health-entitlement-table", LICENCE_STATUS_COLUMNS, detail.entitlements || []);
    toggle("switch-health-term-box", "switch-health-term-table", LICENCE_TERM_COLUMNS, detail.terms || []);
    toggle("switch-health-rtu-box", "switch-health-rtu-table", LICENCE_RTU_COLUMNS, detail.rtu || []);
    byId("switch-health-licence-hint").classList.toggle("hidden", !supported || (!!detail.captured && !detail.note));
  }

  // ---- Extra tables: sections an analysis module adds to an existing tab (Nexus CPU and memory, vPC statistics, LACP counters ...).
  // The result carries {tab, id, title, hint, columns: [{key, label, status?}], rows}; each is appended to its tab, before the element marked data-extra-before when the tab has one.
  function renderExtraTables(tables) {
    document.querySelectorAll(".sw-extra").forEach(node => node.remove());
    (tables || []).forEach((table, index) => {
      const host = document.getElementById(`switch-tab-${table.tab}`);
      if (!host || !(table.rows || []).length) return;
      const id = `switch-extra-${index}`;
      const box = document.createElement("div");
      box.className = "sw-extra";
      box.innerHTML = `<h3 class="subsection-title">${esc(table.title)}</h3>` + (table.hint ? `<p class="field-hint">${esc(table.hint)}</p>` : "") + `<div class="table-wrap"><table id="${id}"></table></div>`;
      const anchor = host.querySelector("[data-extra-before]");
      if (anchor) host.insertBefore(box, anchor); else host.appendChild(box);
      renderTable(id, table.columns.map(column => ({ label: column.label, key: column.key, status: !!column.status, tones: column.tones })), table.rows);
    });
  }

  function renderHealth(health) {
    health = health || {};
    const supported = health.supported !== false;
    const findings = health.findings || [];
    const counts = health.counts || {};
    const note = document.getElementById("switch-health-unsupported");
    note.textContent = health.note || "";
    note.classList.toggle("hidden", supported);
    document.getElementById("switch-health-tab-count").textContent = supported && findings.length ? String(findings.length) : "";
    document.getElementById("switch-health-summary").textContent = supported
      ? `${findings.length} finding${findings.length === 1 ? "" : "s"}: ${counts.high || 0} high, ${counts.medium || 0} medium, ${counts.low || 0} low, ${counts.info || 0} info. Scope: ${health.scope || "Cisco IOS / IOS XE"}. Every finding quotes lines that are in this capture.`
      : "";
    const box = document.getElementById("switch-health-findings");
    box.innerHTML = !supported ? "" : findings.length
      ? findings.map(item => `<div class="assessment-banner ${HEALTH_BANNER[item.severity] || "info"}" role="status"><div><strong><span class="health-sev sev-${esc(item.severity)}">${esc(HEALTH_SEVERITY[item.severity] || item.severity)}</span>${esc(item.title)}${item.where ? `<small>${esc(item.where)}</small>` : ""}</strong><span>${esc(item.text)}${healthDocLink(item.doc)}</span></div></div>`).join("")
      : `<div class="assessment-banner" role="status"><div><strong>No findings</strong><span>Every check this capture can answer passed.</span></div></div>`;

    const family = health.family || "ios";
    const hints = (health.capture || {}).hints || {};
    const lacp = health.lacp || [];
    const lacpEmpty = document.getElementById("switch-health-lacp-empty");
    lacpEmpty.textContent = hints.lacp || "Not in this capture. Add show lacp neighbor.";
    lacpEmpty.classList.toggle("hidden", !supported || lacp.length > 0);
    document.getElementById("switch-health-lacp-hint").innerHTML = HEALTH_LACP_TEXT[family] || HEALTH_LACP_TEXT.ios;
    // AOS-CX prints the partner state as letters and a forwarding state, and no age.
    const lacpColumns = family === "aoscx"
      ? HEALTH_LACP_COLUMNS.map(column => column.key === "flags" ? { ...column, label: "Forwarding" } : column.key === "state" ? { ...column, label: "Partner state letters" } : column)
      : HEALTH_LACP_COLUMNS;
    renderTable("switch-health-lacp-table", lacpColumns, lacp, { hideEmpty: family === "aoscx" });

    // The backend sends a ready-made, labelled list for the platforms that are not IOS; IOS keeps its own keys.
    const stp = health.stp || {};
    renderHealthKV("switch-health-stp", stp.display ? stp.display : Object.keys(stp).length ? {
      mode: stp.mode || "—",
      root_bridge_for: stp.root_for || "—",
      portfast_default: stp.portfast_default || "—",
      bpdu_guard_default: stp.bpduguard_default || "—",
      loopguard_default: stp.loopguard_default || "—",
    } : {});

    const env = health.environment || {};
    const envRows = Array.isArray(env.rows) ? env.rows : []
      .concat((env.sensors || []).map(item => ({ type: "Sensor", name: item.name, location: item.location, state: item.state, reading: item.reading })))
      .concat((env.fans || []).map(item => ({ type: "Fan", name: `Fan ${item.fan}`, location: `switch ${item.switch}`, state: item.state, reading: `${item.speed} rpm, ${item.airflow}` })))
      .concat((env.power_supplies || []).map(item => ({ type: "Power supply", name: `${item.slot} ${item.pid}`, location: "", state: item.status, reading: `${item.watts} W, system power ${item.system_power}` })));
    const envEmpty = document.getElementById("switch-health-env-empty");
    envEmpty.textContent = hints.env || "Not in this capture. Add show env all.";
    envEmpty.classList.toggle("hidden", !supported || envRows.length > 0);
    renderTable("switch-health-env-table", HEALTH_ENV_COLUMNS, envRows);

    const software = health.software || {};
    const licence = health.licence || {};
    byId("switch-health-software-title").textContent = family === "ios" || family === "nxos" ? "Software and licence" : "Software";
    renderHealthKV("switch-health-software", !supported ? {} : software.display ? software.display : {
      uptime: software.uptime || "—",
      last_reload: software.last_reload || "—",
      last_reload_reason: software.last_reload_reason || "—",
      smart_account: licence.smart_account || "—",
      virtual_account: licence.virtual_account || "—",
    });
    const stack = health.stack || {};
    const stackRows = supported ? (stack.display || {}) : {};
    byId("switch-health-stack-section").classList.toggle("hidden", !Object.keys(stackRows).length);
    renderHealthKV("switch-health-stack", stackRows);
    renderTable("switch-health-stack-table", HEALTH_STACK_COLUMNS, supported ? (stack.members || []) : [], { hideEmpty: true });
    byId("switch-health-stack-table").closest(".table-wrap").classList.toggle("hidden", !(supported && (stack.members || []).length));
    renderTable("switch-health-licence-table", family === "nxos" ? HEALTH_NXOS_LICENCE_COLUMNS : HEALTH_LICENCE_COLUMNS, licence.licenses || []);
    // Smart licensing detail exists on IOS XE only. NX-OS prints one feature table; Huawei and Aruba print nothing the tab reads.
    const licenceDetail = licence.detail || {};
    const licenceRows = (licence.licenses || []).length > 0;
    byId("switch-health-licence-section").classList.toggle("hidden", !supported || (family !== "ios" && !licenceDetail.captured));
    byId("switch-health-licence-table").closest(".table-wrap").classList.toggle("hidden", !supported || (family !== "ios" && !licenceRows));
    byId("switch-health-licence-hint").innerHTML = licenceDetail.note ? esc(licenceDetail.note) + "." : HEALTH_LICENCE_HINT;
    renderLicenceDetail(licenceDetail, supported);

    const missing = (health.capture || {}).missing || [];
    document.getElementById("switch-health-missing").innerHTML = !supported ? "" : missing.length
      ? missing.map(item => `<div class="kv-row"><span>${esc(item.command)}</span><strong>${esc(item.adds)}</strong></div>`).join("")
      : `<div class="kv-row"><span>Nothing missing</span><strong>every command this tab can use is in the capture</strong></div>`;
  }

  function renderL3Findings(id, findings, okText) {
    const box = document.getElementById(id);
    if (!box) return;
    const list = findings || [];
    const items = list.length
      ? list.map(item => `<div class="assessment-banner ${item.level === "warning" ? "warning" : "info"}" role="status"><div><strong>${esc(L3_FINDING_TITLES[item.code] || formatKey(item.code))}</strong><span>${esc(item.text)}</span></div></div>`)
      : (okText ? [`<div class="assessment-banner" role="status"><div><strong>${esc(okText)}</strong></div></div>`] : []);
    box.innerHTML = items.join("");
    box.classList.toggle("hidden", !items.length);
  }

  const l3AclText = row => [row.acl_in, row.acl_out].filter(Boolean)
    .concat((row.traffic_policies || []).map(item => `${item.policy} (${item.direction})`))
    .concat((row.traffic_filters || []).map(item => `${item.acl} (${item.direction})`)).join(", ");

  const L3_INTERFACE_COLUMNS = [
    { label: "Interface", key: "name" },
    { label: "Kind", key: "kind" },
    { label: "Address", key: "address" },
    { label: "Secondary", key: "secondary", value: row => (row.secondary || []).join(", ") },
    { label: "State", key: "status", status: true, title: row => row.status_detail || "" },
    { label: "HSRP/VRRP IP", key: "virtual_ip" },
    { label: "VRF", key: "vrf" },
    { label: "DHCP Relay", key: "helpers", value: row => (row.helpers || []).join(", ") },
    { label: "ACL / Policy", key: "acl_in", value: l3AclText },
    { label: "OSPF Area", key: "ospf_area" },
    { label: "Description", key: "description", clip: true },
  ];
  const L3_DEFAULT_COLUMNS = [
    { label: "Next Hop", key: "next_hop" },
    { label: "Configured By", key: "via" },
    { label: "VRF", key: "vrf" },
    { label: "Distance", key: "distance" },
    { label: "Description", key: "description", clip: true },
  ];
  const L3_OSPF_PROCESS_COLUMNS = [
    { label: "Process", key: "id" },
    { label: "VRF", key: "vrf" },
    { label: "Router ID", key: "router_id" },
    { label: "Areas", key: "areas", value: row => (row.areas || []).join(", ") },
    { label: "Interfaces", key: "interface_count" },
    { label: "Network Statements", key: "networks", value: row => (row.networks || []).map(item => `${item.cidr} area ${item.area}`).join("; ") },
    { label: "Passive", key: "passive_default", value: row => row.passive_default ? "all (except listed)" : (row.passive_interfaces || []).join(", ") },
    { label: "Redistribute", key: "redistribute", value: row => (row.redistribute || []).join("; ") },
  ];
  const L3_OSPF_INTERFACE_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Address", key: "ip" },
    { label: "Process", key: "process" },
    { label: "Area", key: "area" },
    { label: "Enabled By", key: "how" },
    { label: "Passive", key: "passive", value: row => row.passive ? "yes" : "no" },
    { label: "Network Type", key: "network_type" },
    { label: "Cost", key: "cost" },
  ];
  const L3_ACL_COLUMNS = [
    { label: "ACL", key: "name" },
    { label: "Family", key: "family" },
    { label: "Type", key: "kind" },
    { label: "Rules", key: "rules" },
    { label: "Applied", key: "applied_label", status: true },
    { label: "Applied To", key: "applied_to" },
    { label: "Also Referenced By", key: "referenced_text", clip: true },
    { label: "Note", key: "note" },
  ];
  const L3_ACL_BINDING_COLUMNS = [
    { label: "Applied To", key: "target" },
    { label: "ACL", key: "acl" },
    { label: "Direction", key: "direction" },
    { label: "Via", key: "via" },
    { label: "ACL Defined", key: "defined", value: row => row.defined ? "yes" : "no — not in this capture" },
  ];

  function renderL3(result) {
    const l3 = result.l3 || {};
    renderL3Findings("switch-l3-findings", l3.findings, "");
    renderTable("switch-l3-interface-table", L3_INTERFACE_COLUMNS, l3.interfaces || []);
    renderTable("switch-l3-default-table", L3_DEFAULT_COLUMNS, l3.default_routes || []);

    const table = l3.routing_table || {};
    const summary = document.getElementById("switch-routing-table-summary");
    if (summary) {
      const groups = Object.entries(table.by_protocol || {}).map(([name, count]) => `${name} ${count}`).join(" · ");
      summary.textContent = table.captured
        ? `${table.total} routes in the device's own table — ${groups || "none"}.${table.gateway_of_last_resort ? ` Gateway of last resort: ${table.gateway_of_last_resort}.` : ""}`
        : "The capture does not include the routing table (show ip route / display ip routing-table).";
    }

    const ospf = l3.ospf || {};
    renderKVList("switch-l3-ospf-summary", {
      status: result.cards?.ospf_status || "Not configured",
      processes: (ospf.processes || []).map(item => item.id || "(default)").join(", ") || "—",
      interfaces_running_ospf: (ospf.interfaces || []).length,
    });
    renderTable("switch-l3-ospf-process-table", L3_OSPF_PROCESS_COLUMNS, ospf.processes || []);
    renderTable("switch-l3-ospf-interface-table", L3_OSPF_INTERFACE_COLUMNS, ospf.interfaces || []);

    const acls = l3.acls || { definitions: [], bindings: [] };
    const appliedTo = {};
    (acls.bindings || []).forEach(item => { if (item.acl) (appliedTo[item.acl] = appliedTo[item.acl] || []).push(`${item.target} ${item.direction}`); });
    renderTable("switch-l3-acl-table", L3_ACL_COLUMNS, (acls.definitions || []).map(item => ({
      ...item,
      applied_label: item.applied ? "applied" : (item.referenced_by?.length ? "referenced" : "not applied"),
      applied_to: [...new Set(appliedTo[item.name] || [])].join(", "),
      referenced_text: (item.referenced_by || []).join("; "),
      note: item.system ? "system / auto-generated" : "",
    })));
    renderTable("switch-l3-acl-binding-table", L3_ACL_BINDING_COLUMNS, acls.bindings || []);
    const ruleRows = [];
    (acls.definitions || []).forEach(item => (item.rule_lines || []).forEach((line, index) => ruleRows.push({ acl: item.name, seq: index + 1, rule: line })));
    renderTable("switch-l3-acl-rule-table", [
      { label: "ACL", key: "acl" }, { label: "#", key: "seq" }, { label: "Rule", key: "rule" },
    ], ruleRows.slice(0, 2000));
    const extra = acls.reported_not_in_config || [];
    const hint = document.getElementById("switch-l3-acl-hint");
    if (hint) {
      const reported = acls.reported_count;
      hint.textContent = (acls.definitions || []).length
        ? `${acls.definitions.length} ACL${acls.definitions.length === 1 ? "" : "s"} in the configuration.`
        : (reported === 0 ? "The device reported no ACLs, and none are in the configuration." : "No ACL is defined in the configuration.");
      if (extra.length) hint.textContent += ` The device also reported ${extra.length} ACL${extra.length === 1 ? "" : "s"} that are not in the running-config (built-in or system lists such as ${extra.slice(0, 3).join(", ")}).`;
    }
  }

  const arpChip = row => row.type;
  const macChip = row => row.type;

  function describeStates(cards) {
    cards = cards || {};
    const parts = [`${cards.interfaces_up ?? 0} up`, `${cards.interfaces_down ?? 0} down`, `${cards.interfaces_admin_down ?? 0} admin down`];
    if (cards.interfaces_unknown) parts.push(`${cards.interfaces_unknown} unknown`);
    return parts.join(" · ");
  }

  // How the vendor was decided (features/switch_analyzer/fingerprint.py):
  // "device identity" = the device's own show version / inventory / system
  // output named the platform, which beats any keyword guess.
  function describeDetection(result) {
    const detection = result.detection || {};
    if (!detection.method) return "—";
    if (detection.method === "selected by user") return "selected by you";
    const evidence = (detection.evidence || []).slice(0, 2).join("; ");
    const confidence = detection.fingerprint ? ` (${detection.confidence} confidence)` : "";
    return `${detection.method}${confidence}${evidence ? ` — ${evidence}` : ""}`;
  }

  function detectionAdvice(result, label) {
    const detection = result.detection || {};
    const who = label ? `${label} (${result.hostname || "unnamed"}): ` : "";
    if (detection.warning) return { title: "Vendor selection contradicts the capture", detail: who + detection.warning };
    if (detection.method === "keyword scoring") {
      return {
        title: "Vendor not identified from the device itself",
        detail: `${who}nothing in this capture names the platform outright (no show version / inventory / system banner), so “${result.vendor || "Unknown"}” was inferred from command syntax and table layouts. If that is wrong, choose the vendor explicitly and analyze again.`,
      };
    }
    return null;
  }

  // The device printed "Total number of entries: 204" but the capture holds
  // fewer rows: lines were lost (terminal scrollback, a log chunk, a paused
  // --More--). Say so rather than presenting a partial table as complete.
  function showTableCheck(check, noteId, detailId, label) {
    const note = document.getElementById(noteId);
    if (!note) return;
    const short = check && check.reported != null && check.parsed < check.reported;
    note.classList.toggle("hidden", !short);
    if (!short) return;
    document.getElementById(detailId).textContent =
      `The device reported ${check.reported} ${label} entries ("${check.source}") but only ${check.parsed} rows are in this capture, ${check.reported - check.parsed} missing. `
      + "The terminal scrollback or log most likely cut the output. Re-run the command with the terminal length set to 0 (Cisco: terminal length 0 · Huawei: screen-length 0 temporary · Aruba: no page) and capture again.";
  }

  function showDetectionNote(results, noteId, titleId, detailId) {
    const list = Array.isArray(results) ? results : [results];
    const advice = list.map((item, index) => detectionAdvice(item, list.length > 1 ? (index ? "Device B" : "Device A") : "")).filter(Boolean);
    const note = document.getElementById(noteId);
    if (!note) return;
    note.classList.toggle("hidden", !advice.length);
    if (!advice.length) return;
    document.getElementById(titleId).textContent = advice[0].title;
    document.getElementById(detailId).textContent = advice.map(item => item.detail).join(" ");
  }

  function renderDashboardChart(result) {
    const container = document.getElementById("switch-dashboard-chart");
    if (!container) return;
    const cards = result.cards || {};

    // Up is green, down red, admin down amber (an intentional shutdown must not
    // look like a fault), unknown grey and only drawn when there is something
    // unknown to report.
    const bars = [
      { label: "Interfaces Up", value: cards.interfaces_up || 0, color: "#3aa76d", tab: "interfaces", filter: "up" },
      { label: "Interfaces Down", value: cards.interfaces_down || 0, color: "#e0586b", tab: "interfaces", filter: "down" },
      { label: "Interfaces Admin Down", value: cards.interfaces_admin_down || 0, color: "#e2a33b", tab: "interfaces", filter: "admin down" },
      ...((cards.interfaces_unknown || 0) > 0
        ? [{ label: "Interfaces Unknown", value: cards.interfaces_unknown, color: "#7f8a99", tab: "interfaces", filter: "unknown" }]
        : []),
      { label: "Total VLANs", value: cards.total_vlans || 0, color: "#4a90d9", tab: "vlans", filter: "" },
      { label: "ARP Entries", value: cards.arp_entries || 0, color: "#5d7fd6", tab: "arp", filter: "" },
      { label: "MAC Entries", value: cards.mac_entries || 0, color: "#6f6fd6", tab: "mac", filter: "" },
      { label: "Total Routes", value: cards.total_routes || 0, color: "#8e6fd6", tab: "routing", filter: "" },
      { label: "DNS Servers", value: cards.dns_servers || 0, color: "#5bb8b0", tab: "dns", filter: "" },
    ];

    const width = 900, height = 300;
    const paddingLeft = 46, paddingBottom = 52, paddingTop = 18, paddingRight = 16;
    const plotWidth = width - paddingLeft - paddingRight;
    const plotHeight = height - paddingTop - paddingBottom;
    const maxValue = Math.max(1, ...bars.map(b => b.value));
    const niceMax = Math.ceil(maxValue / 5) * 5 || 5;
    const barGap = 24;
    const barWidth = (plotWidth - barGap * (bars.length - 1)) / bars.length;

    const gridLines = [0, 0.25, 0.5, 0.75, 1].map(fraction => {
      const y = paddingTop + plotHeight * (1 - fraction);
      const value = Math.round(niceMax * fraction);
      return `<line x1="${paddingLeft}" y1="${y}" x2="${width - paddingRight}" y2="${y}" class="dash-grid" stroke-width="1"></line>` +
        `<text x="${paddingLeft - 10}" y="${y + 4}" class="dash-tick" text-anchor="end" font-size="11">${value}</text>`;
    }).join("");

    const barsMarkup = bars.map((bar, index) => {
      const x = paddingLeft + index * (barWidth + barGap);
      const barHeight = Math.max(2, (bar.value / niceMax) * plotHeight);
      const y = paddingTop + plotHeight - barHeight;
      const labelX = x + barWidth / 2;
      // Two-line label ("Interfaces" / "Admin Down") so nine bars still fit.
      const [firstWord, ...otherWords] = bar.label.split(" ");
      const labelLines = otherWords.length ? [firstWord, otherWords.join(" ")] : [firstWord];
      const labelMarkup = labelLines.map((line, lineIndex) =>
        `<text x="${labelX}" y="${height - paddingBottom + 20 + lineIndex * 14}" class="dash-tick" text-anchor="middle" font-size="11">${esc(line)}</text>`).join("");
      return `
        <g class="dash-bar" data-index="${index}" style="cursor:pointer">
          <title>${esc(bar.label)}: ${bar.value}</title>
          <rect x="${x}" y="${y}" width="${barWidth}" height="${barHeight}" rx="6" fill="${bar.color}"></rect>
          <text x="${labelX}" y="${y - 8}" class="dash-value" text-anchor="middle" font-size="15" font-weight="700">${bar.value}</text>
          ${labelMarkup}
        </g>`;
    }).join("");

    container.innerHTML = `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" style="width:100%;height:100%;display:block;">${gridLines}${barsMarkup}</svg>`;

    container.querySelectorAll(".dash-bar").forEach(group => {
      group.addEventListener("click", () => {
        const bar = bars[Number(group.dataset.index)];
        if (!bar) return;
        switchTab(bar.tab);
        if (bar.tab === "interfaces" && bar.filter) filterTable("switch-interface-table", bar.filter);
      });
    });
  }

  function renderResult(result) {
    document.getElementById("switch-source-name").textContent = result.hostname || "Switch Analysis";
    document.getElementById("switch-platform").textContent =
      [result.vendor || "Unknown", result.device_type || "Switch", result.os_version?.model, result.serials?.serial_number ? `SN ${result.serials.serial_number}` : ""].filter(Boolean).join(" · ");
    showDetectionNote(result, "switch-detection-note", "switch-detection-title", "switch-detection-detail");

    renderDashboardChart(result);

    const stack = result.inventory?.stack || {};
    renderKVList("switch-information", {
      hostname: result.hostname,
      vendor: result.vendor,
      vendor_identified_by: describeDetection(result),
      os_version: result.os_version?.os_version || "—",
      model: result.os_version?.model || "—",
      serial_number: result.serials?.display || "—",
      default_gateway: result.routing_protocols?.default_gateway || "—",
      default_route: result.cards?.default_route || "—",
      ospf: result.cards?.ospf_status || "—",
      access_lists: result.cards?.acl_count ?? 0,
      stack_mode: stack.mode || "Unknown",
      stack_member_count: stack.member_count ?? "—",
      total_interfaces: result.cards?.total_interfaces ?? 0,
      interface_states: describeStates(result.cards),
      arp_entries: result.cards?.arp_entries ?? 0,
      mac_entries: result.cards?.mac_entries ?? 0,
      total_vlans: result.cards?.total_vlans ?? 0,
      total_routes: result.cards?.total_routes ?? 0,
    });

    // Hardware parts and transceivers (result.parts); a result saved before that
    // list existed only has the inventory modules, shown without a Kind.
    renderFilterable("switch-serial-table", SERIAL_COLUMNS, result.parts || result.inventory?.modules || [], {
      chip: row => row.kind, chipOrder: SERIAL_CHIP_ORDER, noun: "parts",
      emptyText: "No serial numbers found in this capture.",
    });
    showCaptureNotes(result.capture_notes || []);

    renderKVList("switch-dns-summary", {
      dns_servers: (result.dns?.servers || []).join(", ") || "—",
      domain_name: result.dns?.domain || "—",
    });

    renderFilterable("switch-interface-table", INTERFACE_COLUMNS_DETAIL, result.interfaces || [], {
      chip: row => row.status, chipOrder: INTERFACE_CHIP_ORDER, noun: "interfaces",
      emptyText: "No interfaces found.", hideEmpty: true,
    });

    const arpRows = result.arp_table || [];
    document.getElementById("switch-arp-empty").classList.toggle("hidden", arpRows.length > 0);
    document.getElementById("switch-arp-tab-count").textContent = arpRows.length || "";
    showTableCheck(result.table_checks?.arp, "switch-arp-check", "switch-arp-check-detail", "ARP");
    showDeviceCount(result.table_checks?.arp, "switch-arp-device");
    renderFilterable("switch-arp-table", ARP_COLUMNS, arpRows, { chip: arpChip, noun: "ARP entries", emptyText: "No ARP entries found.", hideEmpty: true });

    const macRows = result.mac_table || [];
    document.getElementById("switch-mac-empty").classList.toggle("hidden", macRows.length > 0);
    document.getElementById("switch-mac-tab-count").textContent = macRows.length || "";
    showTableCheck(result.table_checks?.mac, "switch-mac-check", "switch-mac-check-detail", "MAC");
    showDeviceCount(result.table_checks?.mac, "switch-mac-device");
    const perVlan = result.table_checks?.mac?.device?.vlans || [];
    byId("switch-mac-vlan-box").classList.toggle("hidden", !perVlan.length);
    renderTable("switch-mac-vlan-table", MAC_VLAN_COLUMNS, perVlan);
    renderFilterable("switch-mac-table", MAC_COLUMNS, macRows, { chip: macChip, noun: "MAC entries", emptyText: "No MAC entries found.", hideEmpty: true });

    renderTable("switch-route-table", [
      { label: "Destination", key: "destination" },
      { label: "Mask", key: "mask" },
      { label: "Next Hop", key: "next_hop" },
      { label: "Admin Distance", key: "distance" },
      { label: "Track ID", key: "track_id" },
      { label: "VRF", key: "vrf" },
      { label: "Description", key: "description", clip: true },
    ], result.routes || []);

    // The device's own routing table can hold thousands of routes: searchable, with one chip per protocol.
    renderFilterable("switch-routing-table-table", ROUTING_TABLE_COLUMNS, result.routing_table || [], {
      chip: row => row.group || row.protocol, chipOrder: ROUTING_GROUP_ORDER, noun: "routes", hideEmpty: true,
      emptyText: "The capture has no routing table (show ip route / display ip routing-table).",
    });

    renderKVList("switch-routing-protocols", {
      default_gateway: result.routing_protocols?.default_gateway || "—",
      ospf: (result.routing_protocols?.ospf || []).join("\n") || "Not configured",
      eigrp: (result.routing_protocols?.eigrp || []).join("\n") || "Not configured",
    });

    renderL3(result);

    const pbr = result.pbr || {};
    document.getElementById("switch-pbr-empty").classList.toggle("hidden", pbr.has_custom_routing);
    document.getElementById("switch-pbr-eem-note").classList.toggle("hidden", !(pbr.eem_dynamic_pbr || []).length);
    renderPbrTables({
      sla: "switch-pbr-sla-table",
      track: "switch-pbr-track-table",
      policy: "switch-pbr-policy-table",
      binding: "switch-pbr-binding-table",
      eem: "switch-pbr-eem-table",
    }, pbr);

    renderVlans(result);
    renderTrunks(result);
    renderSpanningTree(result);

    const neighbors = result.neighbors || [];
    document.getElementById("switch-neighbors-empty").classList.toggle("hidden", neighbors.length > 0);
    renderTable("switch-neighbor-table", NEIGHBOR_COLUMNS, neighbors, { hideEmpty: true });

    const portChannels = result.port_channels || [];
    document.getElementById("switch-portchannel-empty").classList.toggle("hidden", portChannels.length > 0);
    renderTable("switch-portchannel-table", PORTCHANNEL_COLUMNS, portChannels, { hideEmpty: true });
    renderHealth(result.health);
    renderExtraTables(result.extra_tables);

    const transceivers = result.transceivers || [];
    document.getElementById("switch-transceiver-empty").classList.toggle("hidden", transceivers.length > 0);
    renderTable("switch-transceiver-table", TRANSCEIVER_COLUMNS, transceivers, { hideEmpty: true });

    const vpcMlag = result.vpc_mlag || { summary: {}, members: [], source: "none" };
    document.getElementById("switch-vpcmlag-empty").classList.toggle("hidden", vpcMlag.members.length > 0 || Object.keys(vpcMlag.summary || {}).length > 0);
    // "config" means there's no live show-command status at all — the
    // device (or draft) has vPC configured but was never active — see
    // service._apply_vpc_mlag_config_fallback. Flag that plainly instead
    // of letting a "configured (not active)" status row speak for itself.
    document.getElementById("switch-vpcmlag-note").classList.toggle("hidden", vpcMlag.source !== "config");
    renderKVList("switch-vpcmlag-summary", vpcMlag.summary || {});
    renderTable("switch-vpcmlag-table", VPCMLAG_MEMBER_COLUMNS, vpcMlag.members || []);

    const poe = result.poe || [];
    document.getElementById("switch-poe-empty").classList.toggle("hidden", poe.length > 0);
    // "cdp-detail" means there was no live PoE table at all ('show
    // power inline' etc. was never run) — these rows are each
    // connected device's own reported power draw from 'show cdp
    // neighbors detail' instead, so only currently-powered neighbors
    // show up (a port with no device attached has no row here, unlike
    // the live table which lists every PoE-capable port either way).
    const poeFromCdp = poe.length > 0 && poe.every(item => item.source === "cdp-detail");
    document.getElementById("switch-poe-note").classList.toggle("hidden", !poeFromCdp);
    // "config (poe enable)" means no live PoE table exists at all (see
    // service._apply_poe_config_fallback) — every real Huawei PoE
    // access-switch draft in this project has never had anything
    // plugged in yet, so these rows are just which ports are
    // configured for PoE, not a live power reading.
    const poeFromConfig = poe.length > 0 && poe.every(item => item.source === "config (poe enable)");
    document.getElementById("switch-poe-config-note")?.classList.toggle("hidden", !poeFromConfig);
    renderFilterable("switch-poe-table", POE_COLUMNS, poe, {
      chip: row => row.oper_status, chipOrder: POE_CHIP_ORDER, noun: "PoE ports", emptyText: "No PoE data found.", hideEmpty: true,
    });

    renderKVList("switch-dns-detail", {
      dns_servers: (result.dns?.servers || []).join(", ") || "Not configured",
      domain_name: result.dns?.domain || "Not configured",
    });

    const snmp = result.snmp || {};
    renderKVList("switch-snmp-summary", {
      snmp_configured: snmp.enabled ? "Yes" : "No",
      communities: (snmp.summary?.communities || []).join(", ") || "—",
      locations: (snmp.summary?.locations || []).join(", ") || "—",
      contacts: (snmp.summary?.contacts || []).join(", ") || "—",
      trap_hosts: (snmp.summary?.hosts || []).join(", ") || "—",
    });
    renderTable("switch-snmp-table", [
      { label: "Raw Command", key: "command" },
    ], (snmp.raw_commands || []).map(command => ({ command })));

    const dhcp = result.dhcp || {};
    const snooping = dhcp.snooping || {};
    renderKVList("switch-dhcp-summary", {
      dhcp_snooping: snooping.enabled ? "Enabled" : "Disabled",
      snooping_vlans: (snooping.vlans || []).join(", ") || "—",
      option_82: snooping.option82_enabled ? "Enabled" : "Disabled",
      trusted_interfaces: (snooping.trusted_interfaces || []).join(", ") || "—",
      server_pools: dhcp.pools?.length ?? 0,
      relay_interfaces: dhcp.helper_addresses?.length ?? 0,
    });
    renderTable("switch-dhcp-pool-table", [
      { label: "Pool Name", key: "name" },
      { label: "Network", key: "network" },
      { label: "Mask", key: "mask" },
      { label: "Gateway", key: "gateway" },
      { label: "DNS Servers", key: "dns_servers" },
      { label: "Domain", key: "domain_name" },
      { label: "Lease", key: "lease" },
      { label: "Options", key: "options", value: row => (row.options || []).join("; ") },
    ], dhcp.pools || []);
    renderTable("switch-dhcp-helper-table", [
      { label: "Interface", key: "interface" },
      { label: "Relay / Helper Servers", key: "servers", value: row => (row.servers || []).join(", ") },
    ], dhcp.helper_addresses || []);
    const rateLimited = snooping.rate_limited_interfaces || [];
    const trustedRows = (snooping.trusted_interfaces || []).map(name => ({ interface: name, trusted: true, limit_pps: rateLimited.find(item => item.interface === name)?.limit_pps ?? "" }));
    const untrustedRateLimited = rateLimited.filter(item => !(snooping.trusted_interfaces || []).includes(item.interface)).map(item => ({ interface: item.interface, trusted: false, limit_pps: item.limit_pps }));
    renderTable("switch-dhcp-snooping-table", [
      { label: "Interface", key: "interface" },
      { label: "Trust State", key: "trusted", value: row => row.trusted ? "Trusted" : "Untrusted" },
      { label: "Rate Limit (pps)", key: "limit_pps" },
    ], [...trustedRows, ...untrustedRateLimited]);
    renderDynamic(result);
  }

  // ---- Dynamic Single Device page -------------------------------------------------------------
  // The Router Analyzer builds its tabs from what a capture contains. This page keeps its fixed
  // panels, but result.tabs (features/switch_analyzer/tabs.py) says which of them have something
  // to show: the others are hidden and listed under "Not in this capture" with the command that
  // would fill them. "Show all tabs" brings them back.
  const byId = id => document.getElementById(id);
  let currentTabs = [];
  let showAllTabs = false;

  const tabButtons = () => [...document.querySelectorAll("#switch-tabs button[data-tab]")];

  function applyTabs(tabs) {
    currentTabs = tabs || [];
    const byKey = new Map(currentTabs.map(tab => [tab.key, tab]));
    tabButtons().forEach(tabButton => {
      const tab = byKey.get(tabButton.dataset.tab);
      const empty = !!tab && !tab.has;
      tabButton.classList.toggle("hidden", empty && !showAllTabs);
      tabButton.classList.toggle("is-empty", empty);
      let badge = tabButton.querySelector(".tab-count");
      if (!badge) {
        badge = document.createElement("span");
        badge.className = "tab-count";
        tabButton.append(badge);
      }
      // Health writes its own badge (number of findings, renderHealth); the others come from tabs.py.
      if (tabButton.dataset.tab !== "health") badge.textContent = tab && tab.count ? String(tab.count) : "";
    });
    renderMissingTabs();
    const active = tabButtons().find(item => item.classList.contains("active"));
    if (!active || active.classList.contains("hidden")) switchTab("overview");
  }

  // "Not in this capture. Add show ip arp." -> "Add <code>show ip arp</code>"
  function missingReasonHtml(tab) {
    const text = String(tab.why || "");
    const match = text.match(/^Not in this capture\.\s*Add\s+(.+?)\.?$/i);
    return match ? `Add <code>${esc(match[1])}</code>` : esc(text.replace(/\.$/, "") || "Nothing configured or captured");
  }

  function renderMissingTabs() {
    const box = byId("switch-tabs-missing");
    if (!box) return;
    const missing = currentTabs.filter(tab => !tab.has);
    box.classList.toggle("hidden", !missing.length);
    if (!missing.length) { box.innerHTML = ""; return; }
    const wasOpen = box.open;
    box.innerHTML = `<summary><strong>Not in this capture</strong> · ${missing.length} tab${missing.length === 1 ? "" : "s"} ${showAllTabs ? "shown empty" : "hidden"}</summary>`
      + `<ul>${missing.map(tab => `<li><strong>${esc(tab.label)}</strong><span>${missingReasonHtml(tab)}</span></li>`).join("")}</ul>`
      + `<button type="button" class="sw-link" data-toggle-all-tabs>${showAllTabs ? "Hide empty tabs" : "Show all tabs"}</button>`;
    box.open = wasOpen;
  }

  document.addEventListener("click", event => {
    if (event.target.closest("[data-toggle-all-tabs]")) {
      showAllTabs = !showAllTabs;
      applyTabs(currentTabs);
      return;
    }
    const go = event.target.closest("[data-goto-tab]");
    if (go) {
      const tabButton = tabButtons().find(item => item.dataset.tab === go.dataset.gotoTab);
      tabButton?.classList.remove("hidden");
      switchTab(go.dataset.gotoTab);
    }
  });

  // Routing tab: eight sections. A section with nothing in the capture folds to one line; the jump
  // bar shows how much each one holds and opens the section it points to.
  const ROUTING_SECTIONS = [
    ["interfaces", "Layer-3 interfaces"], ["default", "Default route"], ["static", "Static routes"], ["table", "Routing table"],
    ["ospf", "OSPF"], ["acl", "Access lists"], ["protocols", "Protocols"], ["pbr", "PBR / SLA / NQA"],
  ];

  function routingSectionCounts(result) {
    const l3 = result.l3 || {};
    const acls = l3.acls || {};
    const ospf = l3.ospf || {};
    const protocols = result.routing_protocols || {};
    const pbr = result.pbr || {};
    return {
      interfaces: (l3.interfaces || []).length,
      default: (l3.default_routes || []).length,
      static: (result.routes || []).length,
      table: (result.routing_table || []).length,
      ospf: (ospf.processes || []).length + (ospf.interfaces || []).length,
      acl: (acls.definitions || []).length + (acls.bindings || []).length,
      protocols: (protocols.ospf || []).length + (protocols.eigrp || []).length + (l3.other_protocols || []).length + (protocols.default_gateway ? 1 : 0),
      pbr: (pbr.sla_tests || []).length + (pbr.track_objects || []).length + (pbr.pbr_policies || []).length + (pbr.pbr_bindings || []).length + (pbr.eem_dynamic_pbr || []).length,
    };
  }

  function paintRoutingSections(result) {
    const counts = routingSectionCounts(result);
    const nav = byId("switch-routing-nav");
    if (nav) {
      nav.innerHTML = ROUTING_SECTIONS.map(([key, label]) => `<button type="button" class="sw-subnav-chip${counts[key] ? "" : " is-empty"}" data-section-jump="${key}" title="${counts[key] ? "Jump to this section" : "Nothing in this capture — click to open anyway"}">${esc(label)} <span class="chip-count">${counts[key] || "—"}</span></button>`).join("");
    }
    ROUTING_SECTIONS.forEach(([key]) => {
      const section = byId(`switch-sec-${key}`);
      if (!section) return;
      section.classList.toggle("is-empty", !counts[key]);
      section.classList.remove("open");
    });
  }

  document.addEventListener("click", event => {
    const jump = event.target.closest("[data-section-jump]");
    const heading = event.target.closest(".sw-section.is-empty > h3");
    const section = jump ? byId(`switch-sec-${jump.dataset.sectionJump}`) : heading?.parentElement;
    if (!section) return;
    section.classList.toggle("open", jump ? true : !section.classList.contains("open"));
    if (jump) section.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  });

  // Columns the capture has no data for are left out (a Port Security column that is empty on every
  // row is noise). The first column and status columns always stay.
  const isBlank = value => value === null || value === undefined || value === "" || value === "-" || value === "—" || (Array.isArray(value) && !value.length);

  function dropEmptyColumns(columns, rows) {
    if (!rows.length) return { columns, hidden: [] };
    const keep = [];
    const hidden = [];
    columns.forEach((column, index) => {
      const used = index === 0 || column.status || rows.some(row => !isBlank(column.value ? column.value(row) : row[column.key]));
      (used ? keep : hidden).push(column);
    });
    return { columns: keep, hidden };
  }

  function noteHiddenColumns(id, hidden) {
    document.querySelectorAll(`[data-columns-note="${id}"]`).forEach(node => {
      node.classList.toggle("hidden", !hidden.length);
      node.textContent = hidden.length ? `Not shown, because this capture has no data for them: ${hidden.map(column => column.label).join(", ")}.` : "";
    });
  }

  // ---- Findings tab ---------------------------------------------------------------------------
  const SEVERITIES = ["high", "medium", "low", "info"];
  const SEVERITY_NAMES = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const SEVERITY_TONE = { high: "bad", medium: "warn", low: "mute", info: "mute" };

  // The facts the capture holds about the objects a finding names: neighbour, bundle, vPC, log history (finding_context.py).
  function findingEvidence(evidence) {
    if (!(evidence || []).length) return "";
    return `<dl class="sw-evidence">${evidence.map(row => `<dt>${esc(row.label)}</dt><dd>${esc(row.value)}</dd>`).join("")}</dl>`;
  }

  function findingRelated(related) {
    if (!related || !(related.rows || []).length) return "";
    const head = related.columns.map(column => `<th>${esc(column.label)}</th>`).join("");
    const body = related.rows.map(row => `<tr>${related.columns.map(column => `<td>${esc(row[column.key] || "")}</td>`).join("")}</tr>`).join("");
    return `<div class="table-wrap sw-related"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>`
      + (related.more ? `<p class="field-hint">and ${esc(related.more)} more not shown.</p>` : "");
  }

  function findingSearchText(item) {
    const evidence = (item.evidence || []).map(row => `${row.label} ${row.value}`).join(" ");
    const related = ((item.related || {}).rows || []).map(row => Object.values(row).join(" ")).join(" ");
    return `${item.id} ${item.title} ${item.object} ${item.detail} ${item.category} ${item.meaning || ""} ${evidence} ${related}`.toLowerCase();
  }

  function findingCard(item) {
    return `<article class="sw-finding sev-${esc(item.severity)}">`
      + `<div class="sw-finding-head"><span class="cell-status tone-${SEVERITY_TONE[item.severity] || "mute"}">${esc(SEVERITY_NAMES[item.severity] || item.severity)}</span>`
      + `<code>${esc(item.id)}</code>${item.category ? `<span class="sw-chip">${esc(item.category)}</span>` : ""}</div>`
      + `<h4>${esc(item.title)}</h4>`
      + (item.object ? `<p class="sw-finding-object"><span>Object</span><code>${esc(item.object)}</code></p>` : "")
      + (item.detail ? `<p>${esc(item.detail)}</p>` : "")
      + (item.meaning ? `<p class="sw-finding-meaning"><strong>What it means</strong> ${esc(item.meaning)}</p>` : "")
      + findingEvidence(item.evidence)
      + findingRelated(item.related)
      + (item.recommendation ? `<p class="sw-finding-fix"><strong>Fix</strong> ${esc(item.recommendation)}</p>` : "")
      + (/^https?:\/\//i.test(item.reference || "") ? `<a class="sw-ref" href="${esc(item.reference)}" target="_blank" rel="noopener noreferrer">Documentation ↗</a>` : "")
      + `</article>`;
  }

  function renderFindings(result) {
    const box = byId("switch-findings-view");
    const all = result.findings || [];
    if (!all.length) {
      box.innerHTML = `<div class="empty-state compact">No findings — nothing in this capture tripped a rule. The Coverage tab shows what the rules could and could not check.</div>`;
      return;
    }
    const counts = Object.fromEntries(SEVERITIES.map(sev => [sev, all.filter(item => item.severity === sev).length]));
    const categories = [...new Set(all.map(item => item.category).filter(Boolean))].sort();
    box.innerHTML = `<div class="sw-findings-tools"><div class="filter-chips" id="switch-findings-chips" aria-label="Filter findings by severity"></div>`
      + `<select id="switch-findings-category" aria-label="Category"><option value="">All categories</option>${categories.map(cat => `<option value="${esc(cat)}">${esc(cat)}</option>`).join("")}</select>`
      + `<input type="search" id="switch-findings-search" placeholder="Search title, object, detail..." aria-label="Search findings"><span class="table-count" id="switch-findings-count"></span></div>`
      + `<div id="switch-findings-list" class="sw-finding-list"></div>`;
    const state = { sev: "all", cat: "", q: "" };
    const chips = byId("switch-findings-chips");
    const list = byId("switch-findings-list");
    const paint = () => {
      chips.innerHTML = `<button type="button" class="filter-chip${state.sev === "all" ? " active" : ""}" data-sev="all">All <span class="chip-count">${all.length}</span></button>`
        + SEVERITIES.filter(sev => counts[sev]).map(sev => `<button type="button" class="filter-chip tone-${SEVERITY_TONE[sev]}${state.sev === sev ? " active" : ""}" data-sev="${sev}"><i class="chip-dot"></i>${SEVERITY_NAMES[sev]} <span class="chip-count">${counts[sev]}</span></button>`).join("");
      const terms = state.q.toLowerCase().split(/\s+/).filter(Boolean);
      const shown = all.filter(item => (state.sev === "all" || item.severity === state.sev) && (!state.cat || item.category === state.cat)
        && terms.every(term => findingSearchText(item).includes(term)));
      byId("switch-findings-count").textContent = shown.length === all.length ? `${all.length} findings` : `${shown.length} of ${all.length} findings`;
      list.innerHTML = shown.length ? shown.map(findingCard).join("") : `<div class="empty-state compact">No finding matches the filter.</div>`;
    };
    chips.addEventListener("click", event => {
      const chip = event.target.closest("[data-sev]");
      if (chip) { state.sev = chip.dataset.sev; paint(); }
    });
    byId("switch-findings-category").addEventListener("change", event => { state.cat = event.target.value; paint(); });
    byId("switch-findings-search").addEventListener("input", event => { state.q = event.target.value; paint(); });
    paint();
  }

  function renderOverviewFindings(result) {
    const box = byId("switch-overview-findings");
    if (!box) return;
    const all = result.findings || [];
    const high = all.filter(item => item.severity === "high").length;
    const medium = all.filter(item => item.severity === "medium").length;
    box.classList.toggle("hidden", !all.length);
    box.classList.toggle("attention", high > 0);
    box.classList.toggle("warning", high === 0);
    if (!all.length) { box.innerHTML = ""; return; }
    const parts = [high ? `${high} high` : "", medium ? `${medium} medium` : "", `${all.length - high - medium} low or info`].filter(Boolean);
    box.innerHTML = `<div><strong>${all.length} finding${all.length === 1 ? "" : "s"} in this capture</strong><span>${esc(parts.join(" · "))}. ${esc(all[0].title)}${all.length > 1 ? " and more." : "."}</span></div>`
      + `<button type="button" class="secondary-button" data-goto-tab="findings">Open Findings</button>`;
  }

  // ---- Logs tab -------------------------------------------------------------------------------
  const LOG_FLAP_COLUMNS = [
    { label: "Interface", key: "interface" },
    { label: "Down", key: "down" },
    { label: "Up", key: "up" },
    { label: "Admin down", key: "admin_down" },
    { label: "First", key: "first" },
    { label: "Last", key: "last" },
    { label: "Seen as", key: "kind" },
  ];
  const LOG_EVENT_COLUMNS = [
    { label: "Time", key: "time" },
    { label: "Area", key: "label" },
    { label: "Message", key: "id" },
    { label: "Severity", key: "severity", status: true },
    { label: "Object", key: "object" },
    { label: "Text", key: "text", clip: true },
  ];
  const LOG_TOP_COLUMNS = [
    { label: "Message", key: "id" },
    { label: "Severity", key: "severity", status: true },
    { label: "Count", key: "count" },
    { label: "First", key: "first" },
    { label: "Last", key: "last" },
    { label: "Example", key: "example", clip: true },
  ];

  // chipLabels: names of the button rows, e.g. {area: "Area", severity: "Severity"}; a table with two rows labels both.
  function filterBlock(id, placeholder, label, withChips, severityChips) {
    const row = (attribute, name, title, extra) => `<div class="chip-row"><span class="chip-row-label">${esc(name)}</span><div class="filter-chips${extra}" ${attribute}="${id}" aria-label="${esc(title)}"></div></div>`;
    const chipRows = (withChips && severityChips)
      ? row("data-chips-for", "Area", `Filter ${label} by area`, "") + row("data-chips2-for", "Severity", `Filter ${label} by severity`, " sw-sev-chips")
      : withChips ? `<div class="filter-chips" data-chips-for="${id}" aria-label="Filter ${esc(label)}"></div>`
        : severityChips ? row("data-chips2-for", "Severity", `Filter ${label} by severity`, " sw-sev-chips") : "";
    return `<div class="table-tools"><input type="search" data-table-search="${id}" placeholder="${esc(placeholder)}" aria-label="${esc(label)}"><span class="table-count" data-table-count="${id}"></span></div>`
      + chipRows
      + `<div class="table-wrap"><table id="${id}"></table></div>`;
  }

  // Most severe first, like the "Messages by severity" line of the Logging card.
  const LOG_SEVERITY_ORDER = ["emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"];

  function logLevelText(entry) {
    return entry ? `${entry.level}${entry.logged !== undefined ? ` (${entry.logged} logged)` : ""}` : "—";
  }

  function renderLogs(result) {
    const box = byId("switch-logs-view");
    const logs = result.logs || {};
    if (!logs.captured) {
      const why = currentTabs.find(tab => tab.key === "logs")?.why || "No log command in this capture. Add show logging.";
      box.innerHTML = `<div class="empty-state compact">${missingReasonHtml({ why })}</div>`;
      return;
    }
    const severity = (logs.by_severity || []).map(item => `<span class="cell-status tone-${toneOf(item.level) || "mute"}" title="severity ${esc(item.number)}">${esc(item.level)} ${esc(item.count)}</span>`).join(" ");
    const settings = logs.settings || {};
    const hosts = (settings.hosts || []).map(host => (typeof host === "string" ? host : `${host.host}${host.port ? `:${host.port}` : ""}`));
    const duration = logs.duration || {};
    const level = (label, entry, warnLevel) => (entry ? [label, `${logLevelText(entry)}`, warnLevel && entry.level === warnLevel ? "warn" : ""] : null);
    // Same list as the Router Analyzer's Logs tab: what the buffer holds, the period it covers and how the device logs.
    const rows = [
      ["Messages in the buffer", Number(logs.message_count || 0).toLocaleString()],
      ["Window", logs.first && logs.last ? `${logs.first} → ${logs.last}` : "—"],
      ["Duration", duration.text ? `${duration.text}${duration.assumed ? ` (${duration.assumed})` : ""}` : "not available: the time stamps carry no date", duration.text && !duration.reliable ? "warn" : ""],
      ["Order in the file", logs.order || "order unknown"],
      settings.buffer_bytes ? ["Buffer size", `${Number(settings.buffer_bytes).toLocaleString()} bytes`, settings.buffer_bytes < 32000 ? "warn" : ""] : null,
      level("Console level", settings.console, "debugging"),
      level("Monitor level", settings.monitor),
      level("Buffer level", settings.buffer),
      level("Trap (syslog servers) level", settings.trap),
      Object.keys(settings).length ? ["Syslog servers", hosts.join(", ") || "none", hosts.length ? "" : "warn"] : null,
      logs.buffer_overwritten ? ["Buffer overwritten", `${logs.buffer_overwritten.toLocaleString()} older messages are gone (${Number(logs.buffer_visible || 0).toLocaleString()} still visible)`, "warn"] : null,
      settings.persistent !== undefined ? ["Persistent logging", settings.persistent ? "yes" : "no"] : null,
      ["Command", logs.source || "—"],
      ["Format", `${logs.style || ""}${logs.validated ? ` — ${logs.validated}` : ""}`],
    ].filter(Boolean);
    const kvRow = ([key, value, tone]) => `<div class="kv-row"><span>${esc(key)}</span><strong${tone ? ` class="sw-tone-${tone}"` : ""}>${esc(value ?? "—")}</strong></div>`;
    const jump = [["switch-log-sec-summary", "Logging"], ["switch-log-sec-flaps", "State changes seen in the log"], ["switch-log-sec-events", "Events by area"], ["switch-log-sec-top", "Most frequent messages"]];
    box.innerHTML = (logs.note ? `<div class="assessment-banner info" role="note"><div><strong>About this log</strong><span>${esc(logs.note)}</span></div></div>` : "")
      + `<nav class="sw-subnav" aria-label="Jump to a section of the log">${jump.map(([id, label]) => `<button type="button" class="sw-subnav-chip" data-scroll-to="${id}">${esc(label)}</button>`).join("")}</nav>`
      + `<section id="switch-log-sec-summary"><h3 class="subsection-title">Logging</h3>`
      + `<p class="field-hint">Duration is the last time stamp minus the first. A clock that was set while the log was running (NTP after a reload) makes it longer than the period the messages really cover.</p>`
      + `<article class="sw-card sw-log-summary">${rows.map(kvRow).join("")}<div class="kv-row"><span>Messages by severity</span><strong>${severity || "—"}</strong></div></article></section>`
      + `<section id="switch-log-sec-flaps"><h3 class="subsection-title">State changes seen in the log</h3>`
      + ((logs.flaps || []).length
        ? `<p class="field-hint">Ports that changed state in this log, most transitions first.${logs.flap_total > (logs.flaps || []).length ? ` Showing ${(logs.flaps || []).length} of ${logs.flap_total}.` : ""}</p>${filterBlock("switch-logs-flaps-table", "Search interface...", "interface flaps", false)}`
        : `<div class="empty-state compact">No interface changed state in this log.</div>`) + `</section>`
      + `<section id="switch-log-sec-events"><h3 class="subsection-title">Events by area</h3>`
      + ((logs.events || []).length
        ? `<p class="field-hint">Messages that matter, grouped by area (at most 150 are listed per area). Totals in the whole log: ${(logs.families || []).map(family => `${esc(family.label)} ${esc(family.count)}`).join(" · ")}.</p>${filterBlock("switch-logs-events-table", "Search message, object or text...", "log events", true, true)}`
        : `<div class="empty-state compact">No event outside interface flaps in this log.</div>`) + `</section>`
      + `<section id="switch-log-sec-top"><h3 class="subsection-title">Most frequent messages</h3>`
      + ((logs.top || []).length ? filterBlock("switch-logs-top-table", "Search message or example...", "frequent messages", false, true) : `<div class="empty-state compact">—</div>`) + `</section>`;
    if ((logs.flaps || []).length) renderFilterable("switch-logs-flaps-table", LOG_FLAP_COLUMNS, logs.flaps, { noun: "ports", emptyText: "No flaps." });
    if ((logs.events || []).length) {
      renderFilterable("switch-logs-events-table", LOG_EVENT_COLUMNS, logs.events, { chip: row => row.label, noun: "events", emptyText: "No events.", chipOrder: (logs.families || []).map(family => family.label), chip2: row => row.severity, chipOrder2: LOG_SEVERITY_ORDER });
    }
    if ((logs.top || []).length) renderFilterable("switch-logs-top-table", LOG_TOP_COLUMNS, logs.top, { noun: "message types", emptyText: "No messages.", chip2: row => row.severity, chipOrder2: LOG_SEVERITY_ORDER });
  }

  // ---- VLANs, trunks, spanning tree, device-reported counts -------------------------------------
  function showDeviceCount(check, noteId) {
    const note = byId(noteId);
    const text = check && check.device_note ? check.device_note : "";
    note.textContent = text;
    note.classList.toggle("hidden", !text);
  }

  function renderVlans(result) {
    const summary = result.vlan_summary || {};
    const device = summary.device || {};
    const note = byId("switch-vlan-summary");
    const parts = [];
    if (device.existing != null) {
      const extra = [device.vtp != null ? `${device.vtp} in VTP` : "", device.extended ? `${device.extended} extended` : ""].filter(Boolean).join(", ");
      parts.push(`The device counts ${device.existing} VLANs${extra ? ` (${extra})` : ""}`
        + (summary.listed != null ? `; this capture lists ${summary.listed}${summary.builtin ? `, ${summary.builtin} of them built in (VLAN 1 and 1002-1005, not listed below)` : ""}.` : "."));
    }
    if (summary.default_vlan_ports) {
      parts.push(`VLAN 1 (the default VLAN) holds ${summary.default_vlan_ports} access port${summary.default_vlan_ports === 1 ? "" : "s"}.`);
    }
    if (summary.captured && summary.complete === false) parts.push("The VLAN table is shorter than the device count: the capture lost lines. Run the command again with the terminal length set to 0.");
    note.textContent = parts.join(" ");
    note.classList.toggle("hidden", !parts.length);
    renderFilterable("switch-vlan-table", VLAN_COLUMNS, result.vlans || [], {
      chip: row => row.source, chipOrder: VLAN_CHIP_ORDER, noun: "VLANs", emptyText: "No VLANs found.", hideEmpty: true,
    });
  }

  function renderTrunks(result) {
    const rows = result.trunks?.rows || [];
    const open = rows.filter(row => row.allowed_all).length;
    byId("switch-trunk-summary").textContent = rows.length
      ? `${rows.length} trunk port${rows.length === 1 ? "" : "s"}${open ? `, ${open} allowing every VLAN (1-4094)` : ""}. Allowed is what the port permits, active is what also exists on this switch, forwarding is what spanning tree lets through.`
      : "No trunk ports in this capture (show interface trunk printed nothing).";
    renderFilterable("switch-trunk-table", TRUNK_COLUMNS, rows, {
      chip: row => row.status, chipOrder: TRUNK_CHIP_ORDER, noun: "trunks", emptyText: "No trunk ports.", hideEmpty: true,
    });
  }

  function renderSpanningTree(result) {
    const stp = result.spanning_tree || {};
    const instances = stp.instances || [];
    const note = byId("switch-stp-note");
    note.textContent = stp.note || "";
    note.classList.toggle("hidden", !stp.note);
    renderKVList("switch-stp-summary", instances.length ? {
      protocol: stp.protocol === "ieee" ? "PVST+ (ieee)" : (stp.protocol === "rstp" ? "Rapid PVST+ (rstp)" : (stp.protocol === "mstp" ? "MST (mstp)" : stp.protocol || "—")),
      instances: instances.length,
      root_bridges_seen: stp.root_bridges ?? "—",
      this_switch_is_root_for: (stp.root_for || []).join(", ") || "no instance",
      ports_blocking: stp.blocking ?? 0,
      ports_broken: (stp.broken || []).length,
    } : (stp.summary && Object.keys(stp.summary).length ? stp.summary : {}));
    renderFilterable("switch-stp-instance-table", STP_INSTANCE_COLUMNS, instances, {
      chip: row => (row.is_root ? "this switch is root" : "other root bridge"), noun: "instances", emptyText: "No spanning-tree instances.", hideEmpty: true,
    });
    renderFilterable("switch-stp-port-table", STP_PORT_COLUMNS, stp.ports || [], {
      chip: row => row.state_name, chipOrder: STP_STATE_ORDER, noun: "ports", emptyText: "No spanning-tree ports.", hideEmpty: true,
    });
  }

  // ---- Coverage tab ---------------------------------------------------------------------------
  const COVERAGE_STATUS_ORDER = ["analyzed", "covered", "not parsed", "error", "missing", "ignored"];

  function renderCoverage(result) {
    const box = byId("switch-coverage-view");
    const coverage = result.coverage || { rows: [], counts: {}, commands: 0 };
    const rows = coverage.rows || [];
    if (!rows.length) { box.innerHTML = `<div class="empty-state compact">No commands were recognised in this capture.</div>`; return; }
    const labelOf = key => currentTabs.find(tab => tab.key === key)?.label || "";
    box.innerHTML = `<p class="field-hint">What the analyzer did with every command in this capture. <strong>analyzed</strong> fills a tab, <strong>covered</strong> is already contained in another command, <strong>not parsed</strong> was read but its output is not used yet, <strong>missing</strong> is not in the file but would add detail, <strong>ignored</strong> is not relevant (session or clock output).</p>`
      + `<p class="field-hint">${coverage.commands || 0} commands found in the file. Use the buttons to show one status.</p>`
      + filterBlock("switch-coverage-table", "Search command or note...", "coverage", true);
    renderFilterable("switch-coverage-table", [
      { label: "Command", key: "command" },
      { label: "Status", key: "status", status: true },
      { label: "Lines", key: "lines" },
      { label: "Shown in", key: "tab", value: row => labelOf(row.tab) },
      { label: "Note", key: "note" },
    ], rows, { chip: row => row.status, chipOrder: COVERAGE_STATUS_ORDER, noun: "commands", emptyText: "No commands." });
  }

  function renderDynamic(result) {
    paintRoutingSections(result);
    renderOverviewFindings(result);
    renderFindings(result);
    renderLogs(result);
    renderCoverage(result);
    applyTabs(result.tabs || []);
  }

  // ---- Several devices at once ----------------------------------------------------------------
  // Each chosen file is analyzed on its own (one /api/analyze call per file) and kept here, so
  // switching between devices needs no new upload and no new analysis.
  let devices = [];      // the analyzed (or failed) entries of the queue, in list order
  let activeDevice = 0;
  const syncDevices = () => { devices = queue.filter(entry => entry.status !== "waiting"); };

  // Remove files from the list together with their analysis; the device on screen moves to its neighbour.
  function removeEntries(ids) {
    const shown = devices[activeDevice];
    queue = queue.filter(entry => !ids.includes(entry.id));
    syncDevices();
    renderFileList();
    if (!devices.length) {
      lastResult = null;
      resultPanel.classList.add("hidden");
      firewallResultPanel.classList.add("hidden");
      empty.classList.remove("hidden");
      renderDeviceBar();
      return;
    }
    const keep = shown ? devices.indexOf(shown) : -1;
    showDevice(keep >= 0 ? keep : Math.min(activeDevice, devices.length - 1));
  }

  function renderDeviceBar() {
    const bar = byId("switch-device-bar");
    if (!bar) return;
    bar.classList.toggle("hidden", devices.length < 2);   // one device needs no switcher; its file has an x in the list above
    bar.innerHTML = devices.map((device, index) => {
      const result = device.result;
      const title = result ? (result.hostname || device.name) : device.name;
      const sub = result
        ? [result.vendor, result.device_type === "Firewall" ? "firewall" : `${result.findings?.length ?? 0} finding${(result.findings?.length ?? 0) === 1 ? "" : "s"}`].filter(Boolean).join(" · ")
        : "analysis failed";
      return `<div class="sw-device-wrap"><button type="button" role="tab" class="sw-device${index === activeDevice ? " active" : ""}${result ? "" : " failed"}" data-device="${index}" aria-selected="${index === activeDevice}" title="${esc(device.name)}">`
        + `<strong>${esc(title)}</strong><span>${esc(sub)}</span></button>`
        + `<button type="button" class="sw-device-x" data-remove-device="${index}" aria-label="Remove ${esc(title)}" title="Remove this device">×</button></div>`;
    }).join("");
    const switchResults = devices.filter(device => device.result && device.result.device_type !== "Firewall");
    byId("switch-export-all-button")?.classList.toggle("hidden", switchResults.length < 2);
  }

  function showDevice(index) {
    activeDevice = index;
    const device = devices[index];
    renderDeviceBar();
    const errorBox = byId("switch-device-error");
    const body = byId("switch-result-body");
    if (!device.result) {
      lastResult = null;
      firewallResultPanel.classList.add("hidden");
      resultPanel.classList.remove("hidden");
      body.classList.add("hidden");
      errorBox.classList.remove("hidden");
      byId("switch-device-error-title").textContent = `${device.name} could not be analyzed`;
      byId("switch-device-error-detail").textContent = device.error || "Analysis failed.";
      return;
    }
    lastResult = device.result;
    errorBox.classList.add("hidden");
    body.classList.remove("hidden");
    if (device.result.device_type === "Firewall") {
      resultPanel.classList.add("hidden");
      firewallResultPanel.classList.remove("hidden");
      renderFirewallResult(device.result);
    } else {
      firewallResultPanel.classList.add("hidden");
      resultPanel.classList.remove("hidden");
      renderResult(device.result);
    }
  }

  byId("switch-device-bar")?.addEventListener("click", event => {
    const pick = event.target.closest("[data-device]");
    if (pick) showDevice(Number(pick.dataset.device));
  });

  async function analyzeOne(formData) {
    const response = await fetch("/switch-analyzer/api/analyze", { method: "POST", body: formData });
    let payload = null;
    try { payload = await response.json(); } catch (error) { payload = null; }
    if (!response.ok || !payload || !payload.ok) throw new Error(payload?.error || `Analysis failed (HTTP ${response.status}).`);
    return payload.result;
  }

  async function exportResults(list, trigger) {
    if (!list.length) return;
    window.NES.setLoading(trigger, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results: list }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(trigger, false);
    }
  }

  // ---- Collect Backup: copy the commands of a list ----------------------------------------------
  async function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch (error) { /* fall through to the textarea route */ }
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;top:0;left:0;opacity:0";
    document.body.append(area);
    area.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch (error) { copied = false; }
    area.remove();
    return copied;
  }

  document.addEventListener("click", async event => {
    const copyButton = event.target.closest("[data-copy-collect]");
    if (!copyButton) return;
    const original = copyButton.textContent;
    try {
      const response = await fetch(copyButton.dataset.copyCollect);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const lines = (await response.text()).split(/\r?\n/).filter(line => line.trim() && !/^\s*[!#]/.test(line));
      if (!(await copyToClipboard(lines.join("\n")))) throw new Error("clipboard blocked");
      copyButton.textContent = "Copied";
      window.NES.toast(`Copied ${lines.length} commands. Paste them into the device session.`);
    } catch (error) {
      window.NES.toast("Could not copy automatically — use Download .txt instead.", "error");
    } finally {
      window.setTimeout(() => { copyButton.textContent = original; }, 1600);
    }
  });

  // ---- Firewall dashboard (Mikrotik / Palo Alto) -- entirely separate
  // render path from renderResult() above, since a firewall result's
  // shape (zones/security_rules/nat_rules/ipsec_tunnels/findings, see
  // features/switch_analyzer/firewall_service.py) has no overlap with a
  // switch result's (interfaces/VLANs/port-channels/PoE/...). Reuses
  // the same renderTable/renderKVList/esc/display helpers above so both
  // dashboards look and behave identically even though their data is
  // unrelated. ----

  const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };

  const FIREWALL_TAB_ORDER = {
    "palo alto": [
      "interfaces", "port_mapping", "cdp_lldp", "routing", "pbf", "ipsec",
      "security", "nat", "address", "vlans", "dhcp", "zones", "zone_protection",
      "security_profiles", "management_profiles", "qos", "administrators",
    ],
    mikrotik: [
      "interfaces", "vlans", "port_mapping", "security", "nat", "qos",
      "zones", "routing", "address", "ipsec", "dhcp",
    ],
  };

  function layoutFirewallTabs(vendor) {
    const order = FIREWALL_TAB_ORDER[String(vendor || "").toLowerCase()] || FIREWALL_TAB_ORDER.mikrotik;
    const nav = document.getElementById("firewall-tabs");
    const allButtons = [...nav.querySelectorAll("button[data-tab]")];
    allButtons.forEach(btn => btn.classList.add("hidden"));
    order.forEach(tabName => {
      const btn = allButtons.find(item => item.dataset.tab === tabName);
      const pane = document.getElementById(`firewall-tab-${tabName}`);
      if (!btn || !pane) return;
      btn.classList.remove("hidden");
      nav.appendChild(btn);
    });
    // Land on the first tab in this vendor's order every time a new
    // result is rendered, rather than leaving whatever tab a previous
    // (possibly other-vendor) result had focused active but now hidden.
    const firstVisible = order.find(tabName => document.getElementById(`firewall-tab-${tabName}`));
    if (firstVisible) firewallTab(firstVisible);
  }

  function renderFirewallResult(result) {
    document.getElementById("firewall-source-name").textContent = result.hostname || "Firewall Analysis";
    document.getElementById("firewall-platform").textContent = `${result.vendor || "Unknown"} · ${result.device_type || "Firewall"}`;

    // Mikrotik (RouterOS) and Palo Alto (PAN-OS) dashboards share this
    // one set of table ids, but the underlying data is genuinely
    // different in kind, not just in value -- RouterOS has no zone/
    // link-state/management-profile/security-profile concept at all,
    // and its VLAN/chain vocabulary has no Palo Alto equivalent either.
    // Rather than showing the other vendor's columns permanently blank,
    // several tables below pick a distinct column set per vendor.
    const isMikrotik = String(result.vendor || "").toLowerCase() === "mikrotik";

    const cards = result.cards || {};
    const deviceInfo = result.device_info || {};
    const managementServices = result.management_services || [];
    const disabledServices = managementServices.filter(item => item.disabled).map(item => item.field);
    renderKVList("firewall-information", {
      hostname: result.hostname,
      vendor: result.vendor,
      ...(deviceInfo.mgmt_ip ? { management_ip: `${deviceInfo.mgmt_ip}${deviceInfo.mgmt_netmask ? " / " + deviceInfo.mgmt_netmask : ""}` } : {}),
      ...(deviceInfo.mgmt_gateway ? { management_gateway: deviceInfo.mgmt_gateway } : {}),
      ...(deviceInfo.domain ? { domain: deviceInfo.domain } : {}),
      ...(deviceInfo.timezone ? { timezone: deviceInfo.timezone } : {}),
      ...((result.dns_servers || []).length ? { dns_servers: result.dns_servers.join(", ") } : {}),
      ...((result.ntp_servers || []).length ? { ntp_servers: result.ntp_servers.join(", ") } : {}),
      total_interfaces: cards.total_interfaces ?? 0,
      total_zones: cards.total_zones ?? 0,
      total_security_rules: cards.total_security_rules ?? 0,
      total_nat_rules: cards.total_nat_rules ?? 0,
      total_ipsec_tunnels: cards.total_ipsec_tunnels ?? 0,
      total_findings: cards.total_findings ?? 0,
      high_severity_findings: cards.high_severity_findings ?? 0,
      panorama_enabled: result.panorama_enabled ? "Yes" : "No",
      ...(managementServices.length ? { admin_services_disabled: disabledServices.length ? disabledServices.join(", ") : "None" } : {}),
    });

    const findings = result.findings || [];
    document.getElementById("firewall-findings-empty").classList.toggle("hidden", findings.length > 0);
    renderTable("firewall-findings-table", [
      { label: "Severity", key: "severity", status: true, value: row => SEVERITY_LABEL[row.severity] || row.severity },
      { label: "Category", key: "category" },
      { label: "Finding", key: "title" },
      { label: "Detail", key: "detail" },
    ], findings);

    renderTable("firewall-interface-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Zone / Bridge", key: "zone" },
      { label: "IP Address", key: "ip_address" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Zone", key: "zone" },
      { label: "IP Address", key: "ip_address" },
      { label: "VLAN Tag", key: "tag" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.interfaces || []);

    renderTable("firewall-port-mapping-table", isMikrotik ? [
      { label: "Current Name", key: "name" },
      { label: "Default/Factory Name", key: "default_name" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Default/Factory Name", key: "default_name" },
      { label: "Zone", key: "zone" },
      { label: "Mode", key: "mode" },
      { label: "Link State", key: "link_state" },
      { label: "Management Profile", key: "management_profile" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.port_mapping || []);

    renderTable("firewall-cdp-lldp-table", [
      { label: "Interface", key: "interface" },
      { label: "LLDP Enabled", key: "lldp_enabled", value: row => row.lldp_enabled ? "Yes" : "No" },
    ], result.cdp_lldp || []);

    renderTable("firewall-vlan-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "VLAN ID", key: "vlan_id" },
      { label: "Parent Interface", key: "parent_interface" },
      { label: "Comment", key: "comment" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "VLAN Interface", key: "vlan_interface" },
      { label: "Tag", key: "tag" },
      { label: "Member Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
    ], result.vlans || []);

    renderTable("firewall-security-profile-table", [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Rule Count", key: "rule_count" },
    ], result.security_profiles || []);

    const qos = result.qos;
    if (Array.isArray(qos)) {
      // Mikrotik: raw "/queue simple"/"/queue tree" lines (see
      // firewall_service.py's _mikrotik_qos_from_unhandled -- RouterOS
      // QoS has no dedicated model, this is its best-effort surfacing).
      document.getElementById("firewall-qos-summary").innerHTML = "";
      renderTable("firewall-qos-table", [
        { label: "Section", key: "section" },
        { label: "Command", key: "line" },
      ], qos || []);
    } else {
      renderKVList("firewall-qos-summary", {
        qos_profiles: (qos?.profiles || []).join(", ") || "None configured",
      });
      renderTable("firewall-qos-table", [
        { label: "Interface", key: "interface" },
        { label: "QoS Profile", key: "profile" },
      ], qos?.interface_bindings || []);
    }

    renderTable("firewall-zone-table", isMikrotik ? [
      { label: "Zone", key: "name" },
      { label: "Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
    ] : [
      { label: "Zone", key: "name" },
      { label: "Interfaces", key: "interfaces", value: row => (row.interfaces || []).join(", ") },
      { label: "Zone Protection Profile", key: "zone_protection_profile" },
    ], result.zones || []);

    renderTable("firewall-management-profile-table", [
      { label: "Name", key: "name" },
      { label: "Permitted Services", key: "permitted_services", value: row => (row.permitted_services || []).join(", ") || "None" },
    ], result.management_profiles || []);

    renderTable("firewall-zone-protection-table", [
      { label: "Name", key: "name" },
      { label: "Protection Types", key: "protection_types", value: row => (row.protection_types || []).join(", ") || "None" },
    ], result.zone_protection_profiles || []);

    renderTable("firewall-pbf-table", [
      { label: "Name", key: "name" },
      { label: "From Zone", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Application", key: "application", value: row => (row.application || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Egress Interface", key: "egress_interface" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Monitor Profile", key: "monitor_profile" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.pbf_rules || []);

    renderTable("firewall-administrator-table", [
      { label: "Username", key: "username" },
      { label: "Role", key: "role" },
    ], result.administrators || []);

    renderTable("firewall-security-table", isMikrotik ? [
      { label: "Chain", key: "chain" },
      { label: "Name", key: "name" },
      { label: "In Interface / List", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "Out Interface / List", key: "to_zone", value: row => (row.to_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Protocol / Port", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Action", key: "action" },
      { label: "Log", key: "log", value: row => row.log ? "Yes" : "No" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "From Zone", key: "from_zone", value: row => (row.from_zone || []).join(", ") || "any" },
      { label: "To Zone", key: "to_zone", value: row => (row.to_zone || []).join(", ") || "any" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Security Profile", key: "profile_setting", value: row => Object.entries(row.profile_setting || {}).map(([type, names]) => `${type}:${names.join("/")}`).join(", ") },
      { label: "Action", key: "action" },
      { label: "Log", key: "log", value: row => row.log ? "Yes" : "No" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.security_rules || []);

    renderTable("firewall-nat-table", isMikrotik ? [
      { label: "Chain", key: "chain" },
      { label: "Name", key: "name" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service / Port", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Translated Address", key: "translated_address" },
      { label: "Translated Port", key: "translated_port" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Type", key: "type" },
      { label: "Source", key: "source", value: row => (row.source || []).join(", ") || "any" },
      { label: "Destination", key: "destination", value: row => (row.destination || []).join(", ") || "any" },
      { label: "Service", key: "service", value: row => (row.service || []).join(", ") || "any" },
      { label: "Translated Address", key: "translated_address" },
      { label: "Translated Port", key: "translated_port" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], result.nat_rules || []);

    // Per-virtual-router routing detail -- static vs dynamic, and which
    // dynamic protocol (BGP/OSPF/RIP -- PAN-OS has no EIGRP support at
    // all, that's Cisco-proprietary) with its router-id/AS/area, so
    // "is this VR static, dynamic, or a mix" is answered directly
    // instead of just listing which protocols are technically enabled.
    const routingEntries = result.routing_protocols || [];
    if (routingEntries.length) {
      const summary = {};
      routingEntries.forEach(vr => {
        const parts = [vr.routing_type || "None configured"];
        if (vr.bgp) {
          const bgpDetail = [
            vr.bgp_as_number ? `AS ${vr.bgp_as_number}` : "",
            vr.bgp_router_id ? `Router ID ${vr.bgp_router_id}` : "",
          ].filter(Boolean).join(", ");
          parts.push(`BGP${bgpDetail ? ` (${bgpDetail})` : ""}`);
        }
        if (vr.ospf) {
          const ospfDetail = [
            vr.ospf_router_id ? `Router ID ${vr.ospf_router_id}` : "",
            (vr.ospf_area_ids || []).length ? `Area ${vr.ospf_area_ids.join("/")}` : "",
          ].filter(Boolean).join(", ");
          parts.push(`OSPF${ospfDetail ? ` (${ospfDetail})` : ""}`);
        }
        if (vr.rip) parts.push("RIP");
        const routeCount = vr.static_route_count || 0;
        if (routeCount) parts.push(`${routeCount} static route${routeCount === 1 ? "" : "s"}`);
        summary[vr.virtual_router] = parts.join(" — ");
      });
      renderKVList("firewall-routing-summary", summary);
    } else {
      document.getElementById("firewall-routing-summary").innerHTML = "";
    }

    const routingTypeByVr = {};
    (result.routing_protocols || []).forEach(vr => { routingTypeByVr[vr.virtual_router] = vr.routing_type; });

    renderTable("firewall-route-table", isMikrotik ? [
      { label: "Destination", key: "destination" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Metric", key: "metric" },
    ] : [
      { label: "Destination", key: "destination" },
      { label: "Next Hop", key: "nexthop" },
      { label: "Metric", key: "metric" },
      { label: "Virtual Router", key: "virtual_router" },
      { label: "VR Routing Type", key: "routing_type", value: row => routingTypeByVr[row.virtual_router] || "" },
    ], result.static_routes || []);

    renderTable("firewall-address-table", [
      { label: "Name", key: "name" },
      { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
    ], result.address_objects || []);

    // Palo Alto-only concept (named service/App-ID objects) -- RouterOS
    // rules match raw ports/addresses directly, so this section is
    // hidden entirely for Mikrotik rather than showing two tables that
    // can never have data.
    document.getElementById("firewall-service-object-section").hidden = isMikrotik;
    if (!isMikrotik) {
      renderTable("firewall-service-object-table", [
        { label: "Service / Service Group", key: "name" },
        { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
      ], result.service_objects || []);

      renderTable("firewall-application-group-table", [
        { label: "Application Group", key: "name" },
        { label: "Members", key: "members", value: row => (row.members || []).join(", ") },
      ], result.application_groups || []);
    }

    renderTable("firewall-ipsec-table", [
      { label: "Name", key: "name" },
      { label: "Peer Address", key: "peer_address" },
      { label: "DH Group", key: "dh_group" },
      { label: "IKE Encryption", key: "ike_encryption" },
      { label: "IKE Hash", key: "ike_hash" },
      { label: "ESP Encryption", key: "esp_encryption" },
      { label: "ESP Authentication", key: "esp_authentication" },
      { label: "Proxy ID Local", key: "proxy_id_local" },
      { label: "Proxy ID Remote", key: "proxy_id_remote" },
    ], result.ipsec_tunnels || []);

    const dhcp = result.dhcp || {};
    renderKVList("firewall-dhcp-summary", {
      dns_servers: (result.dns_servers || []).join(", ") || "—",
      ntp_servers: (result.ntp_servers || []).join(", ") || "—",
    });
    renderTable("firewall-dhcp-table", isMikrotik ? [
      { label: "Name", key: "name" },
      { label: "Interface", key: "interface" },
      { label: "Address Pool", key: "address_pool" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ] : [
      { label: "Name", key: "name" },
      { label: "Interface", key: "interface" },
      { label: "Address Pool", key: "address_pool" },
      { label: "Gateway", key: "gateway" },
      { label: "Disabled", key: "disabled", value: row => row.disabled ? "Yes" : "No" },
    ], dhcp.servers || []);

    layoutFirewallTabs(result.vendor);
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const vendor = form.querySelector('[name="vendor"]')?.value || "Auto Detect";
    // Pasted text only counts when no file is in the list (the paste box is hidden unless a page script shows it).
    const pasted = (document.getElementById("switch-config-text")?.value || "").trim();
    if (!queue.length && pasted) {
      queue.push({ id: nextEntryId++, name: "pasted configuration", size: pasted.length, file: null, text: pasted, status: "waiting", vendor: "", result: null, error: "" });
      renderFileList();
    }
    if (!queue.length) { window.NES.toast("Add a switch capture first.", "error"); return; }
    // New files, files that failed before, and files analyzed with another vendor choice.
    const pending = queue.filter(entry => entry.status !== "done" || entry.vendor !== vendor);
    if (!pending.length) { window.NES.toast("Every file in the list is already analyzed. Add a file, remove one, or change the vendor to analyze again."); return; }
    const before = devices.length;
    window.NES.setLoading(button, true, "Analyzing...");
    try {
      for (const [index, entry] of pending.entries()) {
        if (pending.length > 1) button.innerHTML = `Analyzing ${index + 1} of ${pending.length}...`;
        const data = new FormData();
        data.append("vendor", vendor);
        if (entry.file) data.append("config_file", entry.file, entry.name); else data.append("config_text", entry.text);
        try {
          entry.result = await analyzeOne(data);
          entry.error = "";
          entry.status = "done";
        } catch (error) {
          entry.result = null;
          entry.error = error.message;
          entry.status = "failed";
        }
        entry.vendor = vendor;
        syncDevices();
        renderFileList();
        renderDeviceBar();
      }
      const good = pending.filter(entry => entry.status === "done");
      if (!good.length) throw new Error(pending[0]?.error || "Analysis failed.");
      empty.classList.add("hidden");
      // Show the first device that was just analyzed; devices from earlier runs stay in the bar.
      showDevice(Math.max(0, devices.indexOf(good[0])));
      const failed = pending.length - good.length;
      window.NES.toast(pending.length > 1 || failed ? `${good.length} of ${pending.length} devices analyzed${failed ? ` — ${failed} failed, see the device list` : ""}.`
        : (good[0].result.device_type === "Firewall" ? "Firewall analysis completed." : "Switch analysis completed."),
        failed ? "error" : "success");
    } catch (error) {
      window.NES.toast(error.message, "error");
      if (devices.length > before || devices.length) showDevice(Math.min(activeDevice, devices.length - 1));
    } finally {
      window.NES.setLoading(button, false);
    }
  });

  exportButton?.addEventListener("click", event => {
    event.preventDefault();
    if (lastResult) exportResults([lastResult], exportButton);
  });

  document.getElementById("switch-export-all-button")?.addEventListener("click", event => {
    event.preventDefault();
    exportResults(devices.filter(item => item.result && item.result.device_type !== "Firewall").map(item => item.result), event.currentTarget);
  });

  firewallExportButton?.addEventListener("click", event => {
    event.preventDefault();
    if (lastResult) exportResults([lastResult], firewallExportButton);
  });

  // --- Compare Two Devices (old Cisco/Aruba vs. new Huawei draft) ---
  const compareForm = document.getElementById("switch-compare-form");
  const compareButton = document.getElementById("switch-compare-button");
  const compareEmpty = document.getElementById("switch-compare-empty");
  const compareResultPanel = document.getElementById("switch-compare-result");
  const compareExportButton = document.getElementById("switch-compare-export-button");
  let lastCompare = null; // { result_a, result_b, comparison }

  const DIFF_CHIP_ORDER = ["both", "only a", "only b"];

  function renderDiffTable(id, diff, options = {}) {
    const rows = [
      ...(diff?.only_a || []).map(value => ({ value, a: "Only Device A", b: "", chip: "only a" })),
      ...(diff?.only_b || []).map(value => ({ value, a: "", b: "Only Device B", chip: "only b" })),
      ...(diff?.both || []).map(value => ({ value, a: "Both", b: "Both", chip: "both" })),
    ];
    const columns = [
      { label: "Value", key: "value" },
      { label: "Device A", key: "a" },
      { label: "Device B", key: "b" },
    ];
    if (options.filterable) {
      renderFilterable(id, columns, rows, { chip: row => row.chip, chipOrder: DIFF_CHIP_ORDER, noun: options.noun || "rows" });
    } else {
      renderTable(id, columns, rows);
    }
  }

  // The diff tables above only cover VLANs/routes/DNS servers — this
  // fills in every OTHER parsed table (interfaces, port-channels,
  // transceivers, vPC/M-LAG, PoE, neighbors) for both devices side by
  // side, so the full detail is visible on the page without needing
  // the Excel export just to see it.
  // Hosts survive a migration even though port names do not, so ARP / MAC
  // rows are matched on the host itself: MAC alone for the MAC table, IP + MAC
  // for ARP, MACs normalised to bare hex (same rule as compare.py).
  const macKey = value => { const digits = hexOnly(value); return digits.length === 12 ? digits : ""; };
  const arpKey = row => { const mac = macKey(row.mac_address); return mac && row.ip_address ? `${row.ip_address}|${mac}` : ""; };
  const macRowKey = row => macKey(row.mac_address);

  function withPresence(rows, otherRows, keyOf) {
    const other = new Set(otherRows.map(keyOf).filter(Boolean));
    return rows.map(row => {
      const key = keyOf(row);
      // "system" = the switch's own CPU / supervisor entries (live_state.is_system_mac):
      // present on every box by design, so never reported as a missing host.
      return { ...row, _match: row.system ? "system" : (!key ? "unresolved" : (other.has(key) ? "both" : "only here")) };
    });
  }

  const COMPARE_ARP_COLUMNS = [
    { label: "IP Address", key: "ip_address" },
    { label: "MAC Address", key: "mac_address", mac: true },
    { label: "Interface", key: "interface" },
    { label: "VLAN", key: "vlan" },
    { label: "Type", key: "type" },
    { label: "Match", key: "_match", status: true },
  ];
  const COMPARE_MAC_COLUMNS = [
    { label: "VLAN", key: "vlan" },
    { label: "MAC Address", key: "mac_address", mac: true },
    { label: "Type", key: "type" },
    { label: "Interface", key: "interface" },
    { label: "Match", key: "_match", status: true },
  ];
  const MATCH_CHIP_ORDER = ["only here", "both", "system", "unresolved"];

  // Compact / All columns for the Compare Devices interface tables.
  let compareInterfaceView = "compact";
  const compareInterfaceColumns = () => (compareInterfaceView === "all" ? INTERFACE_COLUMNS : INTERFACE_COLUMNS_COMPARE);
  function syncCompareColumnToggle() {
    document.querySelectorAll("[data-compare-columns]").forEach(button => {
      const on = button.dataset.compareColumns === compareInterfaceView;
      button.classList.toggle("active", on);
      button.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }
  document.addEventListener("click", event => {
    const button = event.target.closest("[data-compare-columns]");
    if (!button) return;
    compareInterfaceView = button.dataset.compareColumns === "all" ? "all" : "compact";
    syncCompareColumnToggle();
    ["switch-compare-interfaces-a", "switch-compare-interfaces-b"].forEach(id => reconfigureFilterable(id, compareInterfaceColumns()));
  });

  function renderCompareDeviceTables(resultA, resultB) {
    document.querySelectorAll('[data-compare-title="a"]').forEach(node => { node.textContent = `Device A · ${resultA.hostname || "unnamed"}`; });
    document.querySelectorAll('[data-compare-title="b"]').forEach(node => { node.textContent = `Device B · ${resultB.hostname || "unnamed"}`; });

    const interfaceOptions = { chip: row => row.status, chipOrder: INTERFACE_CHIP_ORDER, noun: "interfaces", emptyText: "No interfaces found." };
    renderFilterable("switch-compare-interfaces-a", compareInterfaceColumns(), resultA.interfaces || [], interfaceOptions);
    renderFilterable("switch-compare-interfaces-b", compareInterfaceColumns(), resultB.interfaces || [], interfaceOptions);
    syncCompareColumnToggle();

    const arpA = resultA.arp_table || [], arpB = resultB.arp_table || [];
    document.getElementById("switch-compare-arp-empty").classList.toggle("hidden", arpA.length > 0 || arpB.length > 0);
    const arpOptions = { chip: row => row._match, chipOrder: MATCH_CHIP_ORDER, noun: "ARP entries", emptyText: "No ARP entries found." };
    renderFilterable("switch-compare-arp-a", COMPARE_ARP_COLUMNS, withPresence(arpA, arpB, arpKey), arpOptions);
    renderFilterable("switch-compare-arp-b", COMPARE_ARP_COLUMNS, withPresence(arpB, arpA, arpKey), arpOptions);

    const macA = resultA.mac_table || [], macB = resultB.mac_table || [];
    document.getElementById("switch-compare-mac-empty").classList.toggle("hidden", macA.length > 0 || macB.length > 0);
    const macOptions = { chip: row => row._match, chipOrder: MATCH_CHIP_ORDER, noun: "MAC entries", emptyText: "No MAC entries found." };
    renderFilterable("switch-compare-mac-a", COMPARE_MAC_COLUMNS, withPresence(macA, macB, macRowKey), macOptions);
    renderFilterable("switch-compare-mac-b", COMPARE_MAC_COLUMNS, withPresence(macB, macA, macRowKey), macOptions);

    renderTable("switch-compare-portchannels-a", PORTCHANNEL_COLUMNS, resultA.port_channels || []);
    renderTable("switch-compare-portchannels-b", PORTCHANNEL_COLUMNS, resultB.port_channels || []);

    renderTable("switch-compare-transceivers-a", TRANSCEIVER_COLUMNS, resultA.transceivers || []);
    renderTable("switch-compare-transceivers-b", TRANSCEIVER_COLUMNS, resultB.transceivers || []);

    renderTable("switch-compare-vpcmlag-a", VPCMLAG_MEMBER_COLUMNS, resultA.vpc_mlag?.members || []);
    renderTable("switch-compare-vpcmlag-b", VPCMLAG_MEMBER_COLUMNS, resultB.vpc_mlag?.members || []);
    const vpcNote = document.getElementById("switch-compare-vpcmlag-note");
    const sourceA = resultA.vpc_mlag?.source, sourceB = resultB.vpc_mlag?.source;
    if (sourceA === "config" || sourceB === "config") {
      const who = sourceA === "config" && sourceB === "config" ? "Both devices"
        : sourceA === "config" ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      vpcNote.textContent = `${who} show vPC/M-LAG configuration only, no live status — no "show vpc brief" was ever run (expected for a draft that isn't deployed/active yet). Members are shown as "configured (not active)".`;
      vpcNote.classList.remove("hidden");
    } else {
      vpcNote.classList.add("hidden");
    }

    renderTable("switch-compare-poe-a", POE_COLUMNS, resultA.poe || []);
    renderTable("switch-compare-poe-b", POE_COLUMNS, resultB.poe || []);
    const poeNote = document.getElementById("switch-compare-poe-note");
    const poeFromCdpA = (resultA.poe || []).length > 0 && resultA.poe.every(item => item.source === "cdp-detail");
    const poeFromCdpB = (resultB.poe || []).length > 0 && resultB.poe.every(item => item.source === "cdp-detail");
    const poeFromConfigA = (resultA.poe || []).length > 0 && resultA.poe.every(item => item.source === "config (poe enable)");
    const poeFromConfigB = (resultB.poe || []).length > 0 && resultB.poe.every(item => item.source === "config (poe enable)");
    if (poeFromCdpA || poeFromCdpB) {
      const who = poeFromCdpA && poeFromCdpB ? "Both devices"
        : poeFromCdpA ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      poeNote.textContent = `${who} never ran a live PoE show command — power draw shown is each connected device's own reported figure from "show cdp neighbors detail" instead.`;
      poeNote.classList.remove("hidden");
    } else if (poeFromConfigA || poeFromConfigB) {
      const who = poeFromConfigA && poeFromConfigB ? "Both devices"
        : poeFromConfigA ? `${resultA.hostname || "Device A"}` : `${resultB.hostname || "Device B"}`;
      poeNote.textContent = `${who} never ran a live PoE show command — rows shown are just which ports are configured with "poe enable", not a live power reading (expected for a draft with nothing plugged in yet).`;
      poeNote.classList.remove("hidden");
    } else {
      poeNote.classList.add("hidden");
    }

    renderTable("switch-compare-neighbors-a", NEIGHBOR_COLUMNS, resultA.neighbors || []);
    renderTable("switch-compare-neighbors-b", NEIGHBOR_COLUMNS, resultB.neighbors || []);
  }

  const L3_RESULT_LABEL = { "same": "Same", "changed": "Changed", "moved": "Moved", "only a": "Only on A", "only b": "Only on B", "none": "None" };
  const l3Result = status => L3_RESULT_LABEL[status] || status;
  const L3_INTERFACE_CHIP_ORDER = ["same", "changed", "moved", "only a", "only b"];
  const STATIC_ROUTE_CHIP_ORDER = ["same", "changed", "only a", "only b"];

  function renderCompareL3(l3) {
    l3 = l3 || {};
    renderL3Findings("switch-compare-l3-findings", l3.findings, "No Layer-3 differences were detected between the two captures.");
    renderFilterable("switch-compare-l3-interfaces", [
      { label: "Interface", key: "label" },
      { label: "Result", key: "result", status: true },
      { label: "Device A", key: "a_address", value: row => row.a.address },
      { label: "Device B", key: "b_address", value: row => row.b.address },
      { label: "A name", key: "a_name", value: row => row.a.name },
      { label: "B name", key: "b_name", value: row => row.b.name },
      { label: "A FHRP/VRRP VIP", key: "a_vip", value: row => row.a.virtual_ip },
      { label: "B FHRP/VRRP VIP", key: "b_vip", value: row => row.b.virtual_ip },
      { label: "A DHCP relay", key: "a_helpers", value: row => (row.a.helpers || []).join(", ") },
      { label: "B DHCP relay", key: "b_helpers", value: row => (row.b.helpers || []).join(", ") },
      { label: "A ACL / policy", key: "a_acl", value: row => row.a.acl },
      { label: "B ACL / policy", key: "b_acl", value: row => row.b.acl },
    ], (l3.interfaces || []).map(row => ({ ...row, result: l3Result(row.status) })), {
      chip: row => row.status, chipOrder: L3_INTERFACE_CHIP_ORDER, noun: "interfaces",
    });

    const def = l3.default_route || {};
    renderTable("switch-compare-l3-default", [
      { label: "Result", key: "result", status: true },
      { label: "Device A next hop", key: "a_hop" },
      { label: "A configured by", key: "a_via" },
      { label: "Device B next hop", key: "b_hop" },
      { label: "B configured by", key: "b_via" },
    ], [{
      result: l3Result(def.status || "none"),
      a_hop: ((def.a || {}).next_hops || []).join(", "), a_via: (def.a || {}).via || "",
      b_hop: ((def.b || {}).next_hops || []).join(", "), b_via: (def.b || {}).via || "",
    }]);

    renderFilterable("switch-compare-l3-static", [
      { label: "VRF", key: "vrf" },
      { label: "Destination", key: "cidr" },
      { label: "Result", key: "result", status: true },
      { label: "A next hop", key: "a_next_hop" },
      { label: "A distance", key: "a_distance" },
      { label: "B next hop", key: "b_next_hop" },
      { label: "B distance", key: "b_distance" },
      { label: "Description", key: "description", value: row => row.a_description || row.b_description, clip: true },
    ], (l3.static_routes || []).map(row => ({ ...row, result: l3Result(row.status) })), {
      chip: row => row.status, chipOrder: STATIC_ROUTE_CHIP_ORDER, noun: "static routes",
    });

    const oa = l3.ospf?.a || {};
    const ob = l3.ospf?.b || {};
    const joined = value => (Array.isArray(value) ? value.join("; ") : (value ?? ""));
    renderTable("switch-compare-l3-ospf", [
      { label: "OSPF", key: "item" }, { label: "Device A", key: "a" }, { label: "Device B", key: "b" },
    ], [
      ["State", oa.state, ob.state], ["Process", oa.process, ob.process], ["Router ID", oa.router_id, ob.router_id],
      ["Areas", joined(oa.areas), joined(ob.areas)], ["Network statements", joined(oa.networks), joined(ob.networks)],
      ["Interfaces running OSPF", joined(oa.interfaces), joined(ob.interfaces)],
      ["Redistribute", joined(oa.redistribute), joined(ob.redistribute)],
    ].map(([item, a, b]) => ({ item, a: a || "—", b: b || "—" })));

    renderTable("switch-compare-l3-acls", [
      { label: "ACL", key: "name" },
      { label: "Result", key: "result", status: true },
      { label: "A rules", key: "a_rules" },
      { label: "A applied to", key: "a_applied" },
      { label: "B rules", key: "b_rules" },
      { label: "B applied to", key: "b_applied" },
      { label: "Note", key: "note" },
    ], (l3.acls || []).map(row => ({ ...row, result: l3Result(row.status), note: row.system ? "system / auto-generated" : "" })));

    const snoop = l3.dhcp_snooping || {};
    renderTable("switch-compare-l3-snooping", [
      { label: "DHCP snooping", key: "item" }, { label: "Device A", key: "a" }, { label: "Device B", key: "b" },
    ], [
      ["Enabled", snoop.a_enabled ? "Yes" : "No", snoop.b_enabled ? "Yes" : "No"],
      ["VLANs", snoop.a_vlans || "—", snoop.b_vlans || "—"],
      ["Trusted interfaces", (snoop.a_trusted || []).join(", ") || "—", (snoop.b_trusted || []).join(", ") || "—"],
    ].map(([item, a, b]) => ({ item, a, b })));
  }

  // HSRP pair check: one row per group of the two devices, problems first.
  const FHRP_VERDICT_TONES = { "healthy pair": "ok", "both active": "bad", "both standby": "bad", "disabled": "bad", "initial": "warn", "only on a": "warn", "only on b": "warn", "settings differ": "warn", "same priority": "warn", "not settled": "warn" };
  const FHRP_STATE_TONES = { "active": "ok", "standby": "ok", "listen": "warn", "speak": "warn", "learn": "warn", "initial": "bad", "init": "bad", "disabled": "bad" };
  const FHRP_CHIP_ORDER = ["healthy pair", "only on a", "only on b", "initial", "disabled", "both active", "both standby", "settings differ", "same priority", "not settled"];

  function renderCompareFhrp(fhrp, resultA, resultB) {
    const panel = document.getElementById("switch-compare-fhrp-panel");
    if (!panel) return;
    const rows = (fhrp && fhrp.rows) || [];
    panel.classList.toggle("hidden", !rows.length);
    if (!rows.length) return;
    const healthy = (fhrp.counts || {})["Healthy pair"] || 0;
    const nameA = resultA.hostname || "Device A";
    const nameB = resultB.hostname || "Device B";
    document.getElementById("switch-compare-fhrp-hint").textContent =
      `${rows.length} group${rows.length === 1 ? "" : "s"} matched by interface and group number (a routed port that has another name on each switch is matched by group number): `
      + `${healthy} healthy Active / Standby pair${healthy === 1 ? "" : "s"}, ${rows.length - healthy} to look at. `
      + `${nameA} is Active for ${fhrp.active_a || 0} group${fhrp.active_a === 1 ? "" : "s"}, ${nameB} for ${fhrp.active_b || 0}.`;
    const ordered = [...rows].sort((left, right) => (left.verdict === "Healthy pair") - (right.verdict === "Healthy pair"));
    renderFilterable("switch-compare-fhrp-table", [
      { label: "Verdict", key: "verdict", status: true, tones: FHRP_VERDICT_TONES },
      { label: "Interface", key: "interface" },
      { label: "Group", key: "group" },
      { label: "Virtual IP", key: "virtual_ip" },
      { label: "A IP Address", key: "a_ip" },
      { label: "B IP Address", key: "b_ip" },
      { label: "A state", key: "a_state", status: true, tones: FHRP_STATE_TONES },
      { label: "B state", key: "b_state", status: true, tones: FHRP_STATE_TONES },
      { label: "A priority", key: "a_priority" },
      { label: "B priority", key: "b_priority" },
      { label: "A preempt", key: "a_preempt" },
      { label: "B preempt", key: "b_preempt" },
      { label: "What differs", key: "reason" },
    ], ordered, { chip: row => row.verdict, chipOrder: FHRP_CHIP_ORDER, noun: "HSRP groups" });
  }

  // OSPF link-state database pair check: the LSA totals of the two routers per process, area and type, differences first.
  const OSPF_VERDICT_TONES = { "same": "ok", "differs": "bad", "check": "warn", "only on a": "warn", "only on b": "warn" };
  const OSPF_CHIP_ORDER = ["same", "differs", "check", "only on a", "only on b"];

  function renderCompareOspf(ospf, resultA, resultB) {
    const panel = document.getElementById("switch-compare-ospf-panel");
    if (!panel) return;
    const rows = (ospf && ospf.rows) || [];
    panel.classList.toggle("hidden", !rows.length);
    if (!rows.length) return;
    const counts = ospf.counts || {};
    const same = counts["Same"] || 0;
    const nameA = resultA.hostname || "Device A";
    const nameB = resultB.hostname || "Device B";
    const cut = (ospf.incomplete || []).map(side => (side === "A" ? nameA : nameB));
    let hint = `${rows.length} LSA group${rows.length === 1 ? "" : "s"} (process, area and LSA type) compared: ${same} with the same number of LSAs on both routers, ${rows.length - same} to look at. `
      + "Routers of one area hold the same link-state database, so a difference means a flooding problem or two captures taken at different moments.";
    if (cut.length) {
      hint += ` The terminal pager cut the database output of ${cut.join(" and ")}, so its counts are not compared: capture again after terminal length 0.`;
    }
    document.getElementById("switch-compare-ospf-hint").textContent = hint;
    const ordered = [...rows].sort((left, right) => (left.verdict === "Same") - (right.verdict === "Same"));
    const showVrf = rows.some(row => row.vrf && row.vrf !== "—" && row.vrf !== "default");
    const columns = [
      { label: "Verdict", key: "verdict", status: true, tones: OSPF_VERDICT_TONES },
      { label: "Process", key: "process" },
      { label: "VRF", key: "vrf" },
      { label: "Area", key: "area" },
      { label: "LSA type", key: "type" },
      { label: "A LSAs", key: "a_count" },
      { label: "B LSAs", key: "b_count" },
      { label: "A oldest (s)", key: "a_oldest" },
      { label: "B oldest (s)", key: "b_oldest" },
      { label: "What differs", key: "reason" },
    ].filter(column => showVrf || column.key !== "vrf");
    renderFilterable("switch-compare-ospf-table", columns, ordered, { chip: row => row.verdict, chipOrder: OSPF_CHIP_ORDER, noun: "LSA groups" });
  }

  // Spanning-tree pair check: protocol match, root-bridge visibility, and any VLAN where the
  // two devices disagree about (or both claim) the root.
  function renderCompareStp(stp, resultA, resultB) {
    const panel = document.getElementById("switch-compare-stp-panel");
    if (!panel) return;
    stp = stp || {};
    const hasData = stp.captured && ((stp.counts || {}).a_instances || (stp.counts || {}).b_instances);
    panel.classList.toggle("hidden", !hasData);
    if (!hasData) return;
    renderL3Findings("switch-compare-stp-findings", stp.findings,
      "No spanning-tree disagreements were found between the two captures.");
    const counts = stp.counts || {};
    const proto = stp.protocol || {};
    const nameA = resultA.hostname || "Device A", nameB = resultB.hostname || "Device B";
    document.getElementById("switch-compare-stp-hint").textContent =
      `Protocol: ${proto.a || "—"} on A, ${proto.b || "—"} on B${proto.same ? " (same)" : ""}. `
      + `${counts.a_instances || 0} VLAN/instance(s) on A (${counts.a_blocking || 0} blocking, ${counts.a_broken || 0} inconsistent), `
      + `${counts.b_instances || 0} on B (${counts.b_blocking || 0} blocking, ${counts.b_broken || 0} inconsistent). `
      + `${(stp.root_mismatch || []).length} VLAN(s) where ${nameA} and ${nameB} disagree about the root bridge.`;
    renderTable("switch-compare-stp-table", [
      { label: "VLAN", key: "vlan" },
      { label: "Device A root bridge", key: "a_root" },
      { label: "Device B root bridge", key: "b_root" },
    ], stp.root_mismatch || []);
  }

  // vPC / M-LAG pair check: domain, role split and consistency checks (one row per check), then
  // one row per vPC / Eth-Trunk ID with its up/consistency state on each side.
  const VPCMLAG_VERDICT_TONES = {
    "same": "ok", "healthy split": "ok", "up on both": "ok", "different priority": "ok",
    "differs": "bad", "both primary": "bad", "both secondary": "bad", "down": "bad", "inconsistent": "bad", "failed on both": "bad",
    "only on one side": "warn", "only on a": "warn", "only on b": "warn", "same priority": "warn", "check": "warn",
  };

  function renderCompareVpcMlag(vpc, resultA, resultB) {
    const panel = document.getElementById("switch-compare-vpcmlag-panel");
    if (!panel) return;
    vpc = vpc || {};
    const show = (vpc.rows || []).length || (vpc.member_rows || []).length;
    panel.classList.toggle("hidden", !show);
    if (!show) return;
    const nameA = resultA.hostname || "Device A", nameB = resultB.hostname || "Device B";
    const bad = (vpc.rows || []).filter(row => !["Same", "Healthy split", "Different priority"].includes(row.verdict)).length;
    document.getElementById("switch-compare-vpcmlag-hint").textContent = vpc.configured_a && vpc.configured_b
      ? `${nameA} and ${nameB} compared as a vPC / M-LAG pair: ${bad} of ${(vpc.rows || []).length} domain check(s) need a look.`
      : `vPC / M-LAG is not configured (or the feature is disabled) on ${!vpc.configured_a ? nameA : nameB} — the pair cannot be checked further.`;
    renderTable("switch-compare-vpcmlag-domain-table", [
      { label: "Check", key: "check" },
      { label: "Verdict", key: "verdict", status: true, tones: VPCMLAG_VERDICT_TONES },
      { label: "Device A", key: "a" },
      { label: "Device B", key: "b" },
      { label: "What differs", key: "reason" },
    ], vpc.rows || []);
    renderTable("switch-compare-vpcmlag-members-table", [
      { label: "ID", key: "id" },
      { label: "Port", key: "port" },
      { label: "Verdict", key: "verdict", status: true, tones: VPCMLAG_VERDICT_TONES },
      { label: "A status", key: "a_status" },
      { label: "B status", key: "b_status" },
      { label: "A consistency", key: "a_consistency" },
      { label: "B consistency", key: "b_consistency" },
      { label: "What differs", key: "reason" },
    ], [...(vpc.member_rows || [])].sort((left, right) => (left.verdict === "Up on both") - (right.verdict === "Up on both")));
  }

  function renderCompareResult(payload) {
    const { result_a, result_b, comparison } = payload;
    document.getElementById("switch-compare-title").textContent =
      `${result_a.hostname || "Device A"} vs. ${result_b.hostname || "Device B"}`;
    showDetectionNote([result_a, result_b], "switch-compare-detection-note", "switch-compare-detection-title", "switch-compare-detection-detail");

    const deviceA = comparison.device_a || {};
    const deviceB = comparison.device_b || {};
    const fieldLabels = [
      ["hostname", "Hostname"], ["vendor", "Vendor"], ["model", "Model"], ["serial_number", "Serial Number"],
      ["os_version", "OS Version"], ["stack_mode", "Stack Mode"],
      ["stack_member_count", "Stack Member Count"],
      ["total_interfaces", "Total Interfaces"], ["interfaces_up", "Interfaces Up"],
      ["interfaces_down", "Interfaces Down"], ["interfaces_admin_down", "Interfaces Admin Down"],
      ["interfaces_unknown", "Interfaces Unknown"], ["arp_entries", "ARP Entries"],
      ["mac_entries", "MAC Entries"], ["total_vlans", "Total VLANs"],
      ["total_routes", "Total Routes"], ["neighbor_count", "Neighbor Count"],
      ["port_channel_count", "Port-Channel Count"], ["transceiver_count", "Transceiver Count"],
      ["poe_port_count", "PoE Port Count"],
      ["vpc_mlag_configured", "vPC / M-LAG?"],
      ["has_custom_routing", "Has PBR / SLA-Track / NQA?"],
    ];
    const VPC_MLAG_SOURCE_LABEL = { live: "Yes (live)", config: "Yes (config only)" };
    const formatCompareValue = (key, value, device) => {
      if (key === "has_custom_routing") return value ? "Yes" : "No";
      if (key === "vpc_mlag_configured") {
        if (!value) return "No";
        const label = VPC_MLAG_SOURCE_LABEL[device?.vpc_mlag_source] || "Yes";
        const detail = device?.vpc_mlag_detail || "";
        return detail ? `${label} — ${detail}` : label;
      }
      return value;
    };
    renderTable("switch-compare-devices-table", [
      { label: "Field", key: "field" },
      { label: "Device A", key: "a" },
      { label: "Device B", key: "b" },
    ], fieldLabels.map(([key, label]) => ({
      field: label,
      a: formatCompareValue(key, deviceA[key], deviceA),
      b: formatCompareValue(key, deviceB[key], deviceB),
    })));

    renderDiffTable("switch-compare-vlans-table", comparison.vlans, { filterable: true, noun: "VLANs" });
    renderDiffTable("switch-compare-routes-table", comparison.routes, { filterable: true, noun: "routes" });
    renderCompareL3(comparison.l3);
    renderCompareFhrp(comparison.fhrp, result_a, result_b);
    renderCompareOspf(comparison.ospf_live, result_a, result_b);
    renderCompareStp(comparison.spanning_tree, result_a, result_b);
    renderCompareVpcMlag(comparison.vpc_mlag, result_a, result_b);
    renderDiffTable("switch-compare-dns-table", comparison.dns_servers);
    renderDiffTable("switch-compare-ntp-table", comparison.ntp_servers);
    renderDiffTable("switch-compare-syslog-table", comparison.syslog_servers);
    renderDiffTable("switch-compare-tacacs-table", comparison.tacacs_servers);
    renderDiffTable("switch-compare-radius-table", comparison.radius_servers);
    renderDiffTable("switch-compare-snmp-table", comparison.snmp_trap_hosts);
    renderDiffTable("switch-compare-neighbor-identity-table", comparison.neighbors);

    const pbrA = comparison.pbr?.a || {};
    const pbrB = comparison.pbr?.b || {};
    document.getElementById("switch-compare-pbr-eem-note").classList.toggle(
      "hidden",
      !((pbrA.eem_dynamic_pbr || []).length || (pbrB.eem_dynamic_pbr || []).length),
    );
    renderPbrTables({
      sla: "switch-compare-pbr-sla-a", track: "switch-compare-pbr-track-a",
      policy: "switch-compare-pbr-policy-a", binding: "switch-compare-pbr-binding-a",
      eem: "switch-compare-pbr-eem-a",
    }, pbrA);
    renderPbrTables({
      sla: "switch-compare-pbr-sla-b", track: "switch-compare-pbr-track-b",
      policy: "switch-compare-pbr-policy-b", binding: "switch-compare-pbr-binding-b",
      eem: "switch-compare-pbr-eem-b",
    }, pbrB);

    renderCompareDeviceTables(result_a, result_b);

    compareEmpty.classList.add("hidden");
    compareResultPanel.classList.remove("hidden");
  }

  compareForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const formData = new FormData(compareForm);
    window.NES.setLoading(compareButton, true, "Comparing...");
    try {
      const response = await fetch("/switch-analyzer/api/compare", { method: "POST", body: formData });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Comparison failed.");
      lastCompare = payload;
      renderCompareResult(payload);
      window.NES.toast("Device comparison completed.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareButton, false);
    }
  });

  compareExportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastCompare) return;
    window.NES.setLoading(compareExportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/compare/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(lastCompare),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Comparison Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(compareExportButton, false);
    }
  });

  // --- Sizing Assessment (batch: analyze N files, roll up into one
  // port/PoE/VLAN/redundancy summary) ---
  const sizingFilesInput = document.getElementById("switch-sizing-files");
  const sizingFilesFallback = "Cisco, Huawei, or Aruba running-configs — one file per device";
  sizingFilesInput?.addEventListener("change", () => {
    const count = sizingFilesInput.files.length;
    document.getElementById("switch-sizing-files-label").textContent =
      count ? `${count} file${count === 1 ? "" : "s"} selected` : sizingFilesFallback;
    document.getElementById("clear-switch-sizing-files")?.classList.toggle("hidden", !count);
  });
  document.getElementById("clear-switch-sizing-files")?.addEventListener("click", () => {
    sizingFilesInput.value = "";
    sizingFilesInput.dispatchEvent(new Event("change"));
  });

  const sizingForm = document.getElementById("switch-sizing-form");
  const sizingButton = document.getElementById("switch-sizing-button");
  const sizingEmpty = document.getElementById("switch-sizing-empty");
  const sizingResultPanel = document.getElementById("switch-sizing-result");
  const sizingExportButton = document.getElementById("switch-sizing-export-button");
  let lastSizingResults = null; // the analyzed results array, reused for export

  function renderSizingResult(summary, results) {
    const { devices, totals } = summary;
    document.getElementById("switch-sizing-subtitle").textContent =
      `${totals.device_count} device${totals.device_count === 1 ? "" : "s"}`;

    renderKVList("switch-sizing-totals", {
      physical_ports: `${totals.physical_port_count} total (${totals.physical_ports_up} up / ${totals.physical_ports_down} down / ${totals.physical_ports_admin_down ?? 0} admin down${totals.physical_ports_unknown ? ` / ${totals.physical_ports_unknown} unknown` : ""})`,
      trunk_ports: totals.trunk_port_count,
      port_channels_eth_trunks: totals.port_channel_count,
      poe: `${totals.poe_port_count} port(s), ${totals.poe_total_watts} W total`,
      transceivers: totals.transceiver_count,
      unique_vlans_across_batch: totals.unique_vlan_count,
      static_routes: totals.static_route_count,
      devices_with_ospf: totals.ospf_device_count,
      devices_with_vpc_mlag: totals.vpc_mlag_device_count,
      hsrp_vrrp_svis: totals.hsrp_vrrp_svi_count,
      stacked_devices: totals.stacked_device_count,
    });

    // Group devices by Vendor + Model (product/PID) so a replacement quote
    // can be broken down by exactly what to reorder, not just how many
    // devices are in the batch overall.
    const deviceTypeCounts = new Map();
    for (const device of devices) {
      const vendor = device.vendor || "Unknown";
      const model = device.model || "Unknown";
      const key = vendor + "|" + model;
      const existing = deviceTypeCounts.get(key);
      if (existing) existing.total += 1;
      else deviceTypeCounts.set(key, { vendor, model, total: 1 });
    }
    const deviceTypeRows = Array.from(deviceTypeCounts.values())
      .sort((a, b) => b.total - a.total || a.vendor.localeCompare(b.vendor) || a.model.localeCompare(b.model));
    renderTable("switch-sizing-devicetypes-table", [
      { label: "Vendor", key: "vendor" },
      { label: "Model", key: "model" },
      { label: "Total", key: "total" },
    ], deviceTypeRows);

    const portTypeRows = Object.entries(totals.port_type_totals || {}).map(([type, count]) => ({ type, count }));
    renderTable("switch-sizing-porttypes-table", [
      { label: "Port Type", key: "type" },
      { label: "Count", key: "count" },
    ], portTypeRows);

    // Broken down by Type + Vendor Part Number, not just Type — two
    // transceivers reported under the same media class ("1000BaseSX
    // SFP") can still be different orderable parts (a genuine Cisco
    // GLC-SX-MMD vs. a third-party/compatible optic with its own vendor
    // code), so the part number is what a reviewer actually needs to
    // know precisely what to buy.
    renderTable("switch-sizing-transceivertypes-table", [
      { label: "Transceiver Type", key: "type" },
      { label: "Vendor Part Number", key: "vendor_part_number" },
      { label: "Count", key: "count" },
    ], totals.transceiver_part_totals || []);

    renderTable("switch-sizing-devices-table", [
      { label: "Hostname", key: "hostname" },
      { label: "Vendor", key: "vendor" },
      { label: "Model", key: "model" },
      { label: "Serial Number", key: "serial_number" },
      { label: "OS Version", key: "os_version" },
      { label: "Physical Ports", key: "physical_port_count" },
      { label: "Ports Up", key: "physical_ports_up" },
      { label: "Ports Down", key: "physical_ports_down" },
      { label: "Ports Admin Down", key: "physical_ports_admin_down" },
      { label: "Ports Unknown", key: "physical_ports_unknown" },
      { label: "Trunk Ports", key: "trunk_port_count" },
      { label: "Port-Channels", key: "port_channel_count" },
      { label: "PoE Ports", key: "poe_port_count" },
      { label: "PoE (W)", key: "poe_total_watts" },
      { label: "Transceivers", key: "transceiver_count" },
      { label: "VLANs", key: "vlan_count" },
      { label: "Routes", key: "static_route_count" },
      { label: "OSPF", key: "ospf_configured", value: row => row.ospf_configured ? "Yes" : "No" },
      { label: "vPC/M-LAG", key: "vpc_mlag_configured", value: row => row.vpc_mlag_configured ? `Yes (${row.vpc_mlag_source})` : "No" },
      { label: "HSRP/VRRP SVIs", key: "hsrp_vrrp_svi_count" },
      { label: "Stack", key: "stack_mode", value: row => row.stack_member_count > 1 ? `${row.stack_mode} (${row.stack_member_count})` : row.stack_mode },
    ], devices);

    sizingEmpty.classList.add("hidden");
    sizingResultPanel.classList.remove("hidden");
  }

  sizingForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const files = Array.from(sizingFilesInput.files || []);
    if (!files.length) {
      window.NES.toast("Select at least one switch config file.", "error");
      return;
    }
    const vendor = document.getElementById("switch-sizing-vendor").value;

    window.NES.setLoading(sizingButton, true, `Analyzing 0/${files.length}...`);
    try {
      // Reuses the same per-file /api/analyze endpoint the Single
      // Device form already calls — sequential rather than parallel so
      // the button can show real progress on a large batch and so one
      // bad file's error message clearly names which file it was.
      const results = [];
      for (let index = 0; index < files.length; index += 1) {
        const formData = new FormData();
        formData.append("config_file", files[index]);
        formData.append("vendor", vendor);
        window.NES.setLoading(sizingButton, true, `Analyzing ${index + 1}/${files.length}...`);
        const response = await fetch("/switch-analyzer/api/analyze", { method: "POST", body: formData });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(`${files[index].name}: ${payload.error || "Analysis failed."}`);
        results.push(payload.result);
      }

      const sizingResponse = await fetch("/switch-analyzer/api/sizing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results }),
      });
      const sizingPayload = await sizingResponse.json();
      if (!sizingResponse.ok || !sizingPayload.ok) throw new Error(sizingPayload.error || "Sizing summary failed.");

      lastSizingResults = results;
      renderSizingResult(sizingPayload.summary, results);
      window.NES.toast(`Sizing assessment built for ${results.length} device(s).`);
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(sizingButton, false);
    }
  });

  sizingExportButton?.addEventListener("click", async event => {
    event.preventDefault();
    if (!lastSizingResults) return;
    window.NES.setLoading(sizingExportButton, true, "Exporting...");
    try {
      const response = await fetch("/switch-analyzer/api/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ results: lastSizingResults }),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) throw new Error(payload.error || "Export failed.");
      window.location.href = payload.download_url;
      window.NES.toast("Excel export ready — download starting.");
    } catch (error) {
      window.NES.toast(error.message, "error");
    } finally {
      window.NES.setLoading(sizingExportButton, false);
    }
  });
})();
