/*
 * Keystone analyzer kit
 * ---------------------
 * One renderer for every result-shaped analyzer (Router, Firewall, Load
 * Balancer).  A page declares itself with
 *
 *   <section class="an-page" data-analyzer="router" data-api="/router-analyzer" data-boot='{...}'>
 *
 * and this script wires the intake form, calls <api>/api/analyze, and renders
 * the "keystone.analysis/1" result (see features/analyzer_core/result.py):
 * overview cards, one tab per section group, a findings tab, a coverage tab
 * and a collect-list tab.
 *
 * It must survive Keystone's SPA router, which mounts pages lazily and may
 * insert a second analyzer page into the live document without replaying page
 * scripts; so initialisation is driven by a MutationObserver as well as by the
 * normal DOMContentLoaded scan, and everything is scoped to the page root
 * (no global ids).
 */
(() => {
  "use strict";

  if (window.KeystoneAnalyzerKit) {
    window.KeystoneAnalyzerKit.scan();
    return;
  }

  const ICONS = "/static/icons/nes-icons.svg";
  const SEVERITIES = ["high", "medium", "low", "info"];
  const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info" };
  const STATUS_LABEL = { analysed: "Analysed", covered: "Covered", ignored: "Ignored", "not parsed": "Not parsed", error: "Rejected", missing: "Missing" };
  const MAX_CHIPS = 6;

  // ---------------------------------------------------------------- helpers
  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [key, value] of Object.entries(attrs)) {
        if (value === null || value === undefined || value === false) continue;
        if (key === "class") node.className = value;
        else if (key === "text") node.textContent = value;
        else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
        else node.setAttribute(key, value === true ? "" : value);
      }
    }
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child.nodeType ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", "an-icon");
    const use = document.createElementNS(ns, "use");
    use.setAttribute("href", `${ICONS}#${name}`);
    svg.appendChild(use);
    return svg;
  }

  const toast = (message, type) => (window.NES && window.NES.toast ? window.NES.toast(message, type) : console.log(message));

  function plain(value) {
    if (value === null || value === undefined) return "";
    if (Array.isArray(value)) return value.map(plain).join(" ");
    return String(value);
  }

  function formatNumber(value) {
    return typeof value === "number" && Number.isFinite(value) ? (Number.isInteger(value) ? value.toLocaleString() : String(Math.round(value * 100) / 100)) : plain(value);
  }

  function statusTone(text) {
    const t = plain(text).toLowerCase();
    if (!t || t === "—") return "mute";
    if (/^(up(\/up)?|ok|good|yes|used|in use|established|full|registered|permit|strong|analysed|active)$/.test(t)) return "ok";
    if (/admin|shutdown|n\/a|none|disabled|ignored|covered/.test(t)) return "mute";
    if (/down|fail|error|weak|idle|deny|bad|reject|no reference|not registered|missing/.test(t)) return "bad";
    return "warn";
  }

  function severityTone(sev) {
    return { high: "bad", medium: "warn", low: "info", info: "mute" }[sev] || "mute";
  }

  // ------------------------------------------------------------- table view
  const haystackCache = new WeakMap();

  function haystack(row, columns) {
    let value = haystackCache.get(row);
    if (value === undefined) {
      value = columns.map(col => plain(row[col.key])).join(" \u0001 ").toLowerCase();
      haystackCache.set(row, value);
    }
    return value;
  }

  function compareValues(a, b) {
    const x = Array.isArray(a) ? a.join(" ") : a;
    const y = Array.isArray(b) ? b.join(" ") : b;
    const nx = typeof x === "number" ? x : (x !== "" && x !== null && x !== undefined && !isNaN(Number(String(x).replace(/[, %]/g, ""))) && /^[\d.,%\s-]+$/.test(String(x)) ? Number(String(x).replace(/[, %]/g, "")) : null);
    const ny = typeof y === "number" ? y : (y !== "" && y !== null && y !== undefined && !isNaN(Number(String(y).replace(/[, %]/g, ""))) && /^[\d.,%\s-]+$/.test(String(y)) ? Number(String(y).replace(/[, %]/g, "")) : null);
    if (nx !== null && ny !== null) return nx - ny;
    if (nx !== null) return -1;
    if (ny !== null) return 1;
    return String(x ?? "").localeCompare(String(y ?? ""), undefined, { numeric: true, sensitivity: "base" });
  }

  function renderCell(col, row) {
    const value = row[col.key];
    const tone = (row._tones && row._tones[col.key]) || "";
    const td = h("td", { class: `an-cell an-${col.kind}` });
    switch (col.kind) {
      case "num":
        td.textContent = formatNumber(value);
        break;
      case "id":                                  // port, VLAN tag, policy ID: digits, never grouped as 8,443
        td.textContent = plain(value);
        break;
      case "status": {
        const text = plain(value);
        if (text) td.append(h("span", { class: `an-pill tone-${tone || statusTone(text)}`, text }));
        break;
      }
      case "severity":
        td.append(h("span", { class: `an-pill tone-${severityTone(value)}`, text: SEVERITY_LABEL[value] || plain(value) }));
        break;
      case "list": {
        const items = Array.isArray(value) ? value : (value ? [value] : []);
        const shown = items.slice(0, MAX_CHIPS);
        const box = h("div", { class: "an-chips" });
        shown.forEach(item => box.append(h("span", { class: `an-chip${tone ? ` tone-${tone}` : ""}`, text: plain(item) })));
        if (items.length > MAX_CHIPS) box.append(h("span", { class: "an-chip more", title: items.slice(MAX_CHIPS).map(plain).join("\n"), text: `+${items.length - MAX_CHIPS}` }));
        td.append(box);
        break;
      }
      default: {
        const span = h("span", { text: plain(value) });
        if (tone) span.className = `an-tone-text tone-${tone}`;
        td.append(span);
      }
    }
    return td;
  }

  function buildTable(section, state) {
    const columns = section.columns;
    const rows = section.rows;
    const wrap = h("div", { class: "an-table-block", "data-section": section.id });
    const search = h("input", { type: "search", class: "an-search", placeholder: "Filter rows…", "aria-label": `Filter ${section.title}` });
    const count = h("span", { class: "an-count", "aria-live": "polite" });
    const head = h("thead");
    const body = h("tbody");
    const pager = h("div", { class: "an-pager" });
    // Filter buttons ("facets"): one row of buttons per facet column, built from the rows themselves,
    // e.g. every VRF in a routing table or every status in the Coverage tab. A facet with a single value
    // gets no buttons (nothing to filter). A click selects the value, a second click goes back to All.
    // (Declared before the block is assembled below: using facetBox earlier is a temporal-dead-zone error.)
    const facetDefs = (section.facets || []).filter(def => columns.some(col => col.key === def.key));
    const facetBox = facetDefs.length ? h("div", { class: "an-facets" }) : null;
    const table = h("table", { class: "an-table" }, head, body);
    const scroller = h("div", { class: "an-table-scroll" }, table);
    const tools = h("div", { class: "an-table-tools" }, section.searchable && rows.length > 8 ? search : null, count);
    // Node.append(null) writes the text "null": leave out the facet box when the table has no facets
    wrap.append(...[facetBox, tools, scroller, pager].filter(Boolean));

    const local = state.tables[section.id] || (state.tables[section.id] = { q: "", sortKey: null, sortDir: 1, page: 0 });
    local.facet = local.facet || {};

    const cellText = (row, key) => plain(row[key]);

    function facetValues(def) {
      const found = new Map();
      rows.forEach(row => {
        const value = cellText(row, def.key);
        if (!value) return;
        const entry = found.get(value) || { count: 0, tone: (row._tones && row._tones[def.key]) || "" };
        entry.count += 1;
        found.set(value, entry);
      });
      const order = def.order || [];
      return [...found.entries()].sort((a, b) => {
        const ia = order.indexOf(a[0]), ib = order.indexOf(b[0]);
        if (ia !== -1 || ib !== -1) return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
        return String(a[0]).localeCompare(String(b[0]), undefined, { numeric: true });
      });
    }

    function paintFacets() {
      if (!facetBox) return;
      facetBox.replaceChildren(...facetDefs.map(def => {
        const values = facetValues(def);
        if (values.length < 2) { delete local.facet[def.key]; return null; }
        const active = local.facet[def.key] || "";
        const pick = value => () => { local.facet[def.key] = value === active ? "" : value; local.page = 0; paint(); };
        return h("div", { class: "an-sev-chips an-facet", role: "group", "aria-label": `Filter by ${def.label || def.key}` },
          h("button", { type: "button", class: `an-chip link${active ? "" : " active"}`, "aria-pressed": active ? "false" : "true", onclick: pick(active), text: `All ${rows.length.toLocaleString()}` }),
          values.map(([value, info]) => h("button", { type: "button", class: `an-chip link${info.tone ? ` tone-${info.tone}` : ""}${active === value ? " active" : ""}`, "aria-pressed": active === value ? "true" : "false", onclick: pick(value),
            text: `${def.prefix || ""}${value} ${info.count.toLocaleString()}` })));
      }).filter(Boolean));
    }

    function filtered() {
      let list = rows;
      facetDefs.forEach(def => { const chosen = local.facet[def.key]; if (chosen) list = list.filter(row => cellText(row, def.key) === chosen); });
      const terms = local.q.toLowerCase().split(/\s+/).filter(Boolean);
      if (terms.length) list = list.filter(row => { const hay = haystack(row, columns); return terms.every(term => hay.includes(term)); });
      if (local.sortKey) {
        const key = local.sortKey;
        list = [...list].sort((a, b) => local.sortDir * compareValues(a[key], b[key]));
      }
      return list;
    }

    function paint() {
      paintFacets();
      const list = filtered();
      const size = section.page_size || 200;
      const pages = Math.max(1, Math.ceil(list.length / size));
      local.page = Math.min(local.page, pages - 1);
      const start = local.page * size;
      const slice = list.slice(start, start + size);

      head.replaceChildren(h("tr", null, columns.map(col => {
        const active = local.sortKey === col.key;
        const th = h("th", { scope: "col", class: `an-${col.kind}`, "aria-sort": active ? (local.sortDir === 1 ? "ascending" : "descending") : "none" },
          h("button", { type: "button", class: "an-sort", onclick: () => { if (local.sortKey === col.key) local.sortDir *= -1; else { local.sortKey = col.key; local.sortDir = 1; } paint(); } },
            col.label, active ? h("span", { class: "an-sort-mark", "aria-hidden": "true", text: local.sortDir === 1 ? "▲" : "▼" }) : null));
        return th;
      })));
      body.replaceChildren(...slice.map(row => h("tr", { class: row._tone ? `tone-row-${row._tone}` : "" }, columns.map(col => renderCell(col, row)))));
      if (!slice.length) {
        body.append(h("tr", null, h("td", { colspan: columns.length, class: "an-empty-cell", text: rows.length ? "No row matches the filter." : section.empty })));
      }
      const total = section.total > rows.length ? section.total : rows.length;
      let label = list.length === rows.length ? `${rows.length.toLocaleString()} row${rows.length === 1 ? "" : "s"}` : `${list.length.toLocaleString()} of ${rows.length.toLocaleString()} rows`;
      if (total > rows.length) label += ` (capture holds ${total.toLocaleString()}; first ${rows.length.toLocaleString()} shown)`;
      count.textContent = rows.length || local.q ? label : "";
      pager.replaceChildren();
      if (pages > 1) {
        const go = page => () => { local.page = page; paint(); };
        pager.append(
          h("button", { type: "button", class: "an-btn small", disabled: local.page === 0, onclick: go(0), "aria-label": "First page", text: "«" }),
          h("button", { type: "button", class: "an-btn small", disabled: local.page === 0, onclick: go(local.page - 1), "aria-label": "Previous page", text: "‹" }),
          h("span", { class: "an-pager-info", text: `${(start + 1).toLocaleString()}–${Math.min(start + size, list.length).toLocaleString()} of ${list.length.toLocaleString()}` }),
          h("button", { type: "button", class: "an-btn small", disabled: local.page >= pages - 1, onclick: go(local.page + 1), "aria-label": "Next page", text: "›" }),
          h("button", { type: "button", class: "an-btn small", disabled: local.page >= pages - 1, onclick: go(pages - 1), "aria-label": "Last page", text: "»" }));
      }
    }

    search.value = local.q;
    let timer = 0;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { local.q = search.value; local.page = 0; paint(); }, 120); });
    paint();
    return wrap;
  }

  function buildKv(section) {
    if (!section.pairs.length) return h("p", { class: "an-empty", text: section.empty });
    const list = h("dl", { class: "an-kv" });
    section.pairs.forEach(pair => {
      const value = pair.value;
      const dd = h("dd", { class: pair.tone ? `tone-${pair.tone}` : "" });
      if (Array.isArray(value)) {
        if (!value.length) dd.textContent = "—";
        else value.forEach(item => dd.append(h("span", { class: "an-chip", text: plain(item) })));
      } else dd.textContent = plain(value) || "—";
      list.append(h("dt", { text: pair.label }), dd);
    });
    return list;
  }

  function buildSection(section, state) {
    const header = h("header", { class: "an-section-head" }, h("h3", { text: section.title }), section.hint ? h("p", { text: section.hint }) : null);
    const body = section.kind === "table" ? buildTable(section, state) : buildKv(section);
    return h("section", { class: "an-section", id: null, "data-section-id": section.id }, header, body);
  }

  // --------------------------------------------------------------- analyzer
  class Analyzer {
    constructor(root) {
      this.root = root;
      this.key = root.dataset.analyzer;
      this.api = (root.dataset.api || "").replace(/\/$/, "");
      try { this.boot = JSON.parse(root.dataset.boot || "{}"); } catch (error) { this.boot = {}; }
      this.files = [];
      this.state = { results: [], index: 0, tab: "overview", errors: [], tables: [], findings: { sev: "all", cat: "", q: "" }, collect: null };
      this.q = role => root.querySelector(`[data-role="${role}"]`);
      this.bindIntake();
    }

    // ------------------------------------------------------------- intake
    bindIntake() {
      const q = this.q;
      this.input = q("file-input");
      this.drop = q("drop");
      this.fileList = q("file-list");
      this.paste = q("paste");
      this.analyzeButton = q("analyze");
      this.resultBox = q("result");
      this.emptyBox = q("empty");
      this.status = q("status");
      const form = q("form");
      this.form = form;
      const reopen = q("reopen");
      if (reopen) reopen.addEventListener("click", () => form.classList.remove("collapsed"));
      this.input.addEventListener("change", () => { this.addFiles([...this.input.files]); this.input.value = ""; });
      ["dragenter", "dragover"].forEach(name => this.drop.addEventListener(name, event => { event.preventDefault(); this.drop.classList.add("dragover"); }));
      ["dragleave", "drop"].forEach(name => this.drop.addEventListener(name, event => { event.preventDefault(); this.drop.classList.remove("dragover"); }));
      this.drop.addEventListener("drop", event => this.addFiles([...(event.dataTransfer?.files || [])]));
      form.addEventListener("submit", event => { event.preventDefault(); this.analyze(); });
      const togglePaste = q("toggle-paste");
      if (togglePaste) togglePaste.addEventListener("click", () => {
        const hidden = this.paste.closest("[data-role='paste-wrap']").classList.toggle("hidden");
        togglePaste.setAttribute("aria-expanded", String(!hidden));
        if (!hidden) this.paste.focus();
      });
      const collectShortcut = q("open-collect");
      if (collectShortcut) collectShortcut.addEventListener("click", () => {
        if (this.state.results.length) this.setTab("collect");
        else this.showCollectInEmpty();
      });
      this.renderFiles();
    }

    addFiles(files) {
      const known = new Set(this.files.map(file => `${file.name}:${file.size}`));
      files.forEach(file => { if (!known.has(`${file.name}:${file.size}`)) this.files.push(file); });
      this.renderFiles();
    }

    renderFiles() {
      this.fileList.replaceChildren(...this.files.map((file, index) => h("li", null,
        h("span", { class: "an-file-name", text: file.name }), h("small", { text: formatBytes(file.size) }),
        h("button", { type: "button", class: "an-icon-btn", "aria-label": `Remove ${file.name}`, onclick: () => { this.files.splice(index, 1); this.renderFiles(); }, text: "×" }))));
      this.fileList.classList.toggle("hidden", !this.files.length);
    }

    async analyze() {
      const text = this.paste.value.trim();
      if (!this.files.length && !text) { toast("Add a capture file or paste the command output first.", "error"); return; }
      const data = new FormData();
      this.files.forEach(file => data.append("config_files", file, file.name));
      if (text) data.append("config_text", this.paste.value);
      const platform = this.q("platform");
      data.append("platform", platform ? platform.value : "auto");
      this.analyzeButton.disabled = true;
      const original = this.analyzeButton.textContent;
      this.analyzeButton.textContent = "Analyzing…";
      this.status.textContent = `Analyzing ${this.files.length + (text ? 1 : 0)} capture(s)…`;
      try {
        const response = await fetch(`${this.api}/api/analyze`, { method: "POST", body: data });
        let payload = null;
        try { payload = await response.json(); } catch (error) { /* non-JSON error body */ }
        if (!response.ok || !payload || !payload.ok) {
          const message = (payload && payload.error) || `Analysis failed (HTTP ${response.status}).`;
          this.state.errors = payload && payload.errors ? payload.errors : [{ source: "", error: message }];
          toast(message, "error");
          if (!this.state.results.length) this.renderErrorsOnly();
          else this.render();
          return;
        }
        this.state = { results: payload.results, index: 0, tab: "overview", errors: payload.errors || [], tables: payload.results.map(() => ({})), findings: { sev: "all", cat: "", q: "" }, collect: this.state.collect };
        this.render();
        this.collapseIntake(payload.results.length);
        toast(`Analyzed ${payload.results.length} device${payload.results.length === 1 ? "" : "s"}.`);
      } catch (error) {
        toast("Could not reach the local service.", "error");
      } finally {
        this.analyzeButton.disabled = false;
        this.analyzeButton.textContent = original;
        this.status.textContent = "";
      }
    }

    collapseIntake(count) {
      const names = this.files.map(file => file.name);
      if (this.paste.value.trim()) names.push("pasted text");
      const summary = this.q("intake-summary");
      if (summary) summary.textContent = `${count} device${count === 1 ? "" : "s"} analyzed from ${names.length === 1 ? names[0] : `${names.length} captures`}`;
      this.form.classList.add("collapsed");
    }

    renderErrorsOnly() {
      this.emptyBox.classList.remove("hidden");
      this.resultBox.classList.add("hidden");
      let box = this.emptyBox.querySelector(".an-errors");
      if (box) box.remove();
      box = this.errorBanner();
      if (box) this.emptyBox.append(box);
    }

    errorBanner() {
      if (!this.state.errors.length) return null;
      return h("div", { class: "an-banner bad an-errors", role: "alert" }, h("strong", { text: "Some captures could not be analyzed" }),
        h("ul", null, this.state.errors.map(item => h("li", null, item.source ? h("code", { text: item.source }) : null, item.source ? " — " : "", item.error))));
    }

    // ------------------------------------------------------------- render
    get result() { return this.state.results[this.state.index]; }

    groups() {
      const seen = [];
      (this.result.sections || []).forEach(section => { if (section.group && !seen.includes(section.group)) seen.push(section.group); });
      return seen;
    }

    tabs() {
      const result = this.result;
      const tabs = [{ key: "overview", label: "Overview" }];
      this.groups().forEach(group => tabs.push({ key: `g:${group}`, label: group }));
      tabs.push({ key: "findings", label: "Findings", badge: result.findings.length, tone: result.findings.some(f => f.severity === "high") ? "bad" : (result.findings.length ? "warn" : "ok") });
      tabs.push({ key: "coverage", label: "Coverage", badge: (result.coverage || []).filter(c => c.status === "missing").length || null, tone: "warn" });
      tabs.push({ key: "collect", label: "Collect" });
      return tabs;
    }

    render() {
      const result = this.result;
      if (!result) return;
      this.emptyBox.classList.add("hidden");
      this.resultBox.classList.remove("hidden");
      const tabs = this.tabs();
      if (!tabs.some(tab => tab.key === this.state.tab)) this.state.tab = "overview";

      const pieces = [];
      if (this.state.results.length > 1) {
        pieces.push(h("div", { class: "an-devices", role: "tablist", "aria-label": "Devices" }, this.state.results.map((item, index) => {
          const high = item.findings.filter(f => f.severity === "high").length;
          return h("button", { type: "button", role: "tab", class: `an-device${index === this.state.index ? " active" : ""}`, "aria-selected": String(index === this.state.index), onclick: () => { this.state.index = index; this.render(); } },
            h("strong", { text: item.hostname || item.source_name }), h("small", { text: item.platform || item.vendor || "" }),
            high ? h("span", { class: "an-pill tone-bad", text: `${high} high` }) : h("span", { class: "an-pill tone-ok", text: "no high" }));
        })));
      }
      const exportButton = h("button", { type: "button", class: "an-btn primary", onclick: event => this.exportExcel(event.currentTarget) }, icon("upload"), this.state.results.length > 1 ? `Export ${this.state.results.length} devices to Excel` : "Export to Excel");
      pieces.push(h("div", { class: "an-toolbar" },
        h("div", { class: "an-toolbar-title" }, h("strong", { text: result.hostname || result.source_name }), h("span", { text: [result.platform, result.source_name].filter(Boolean).join(" · ") })), exportButton));
      const banner = this.errorBanner();
      if (banner) pieces.push(banner);
      (result.warnings || []).forEach(warning => pieces.push(h("div", { class: "an-banner warn", role: "note" }, h("span", { text: warning }))));

      const tablist = h("div", { class: "an-tabs", role: "tablist", "aria-label": "Analysis sections" }, tabs.map(tab => h("button", {
        type: "button", role: "tab", class: `an-tab${tab.key === this.state.tab ? " active" : ""}`, "aria-selected": String(tab.key === this.state.tab), "data-tab": tab.key,
        onclick: () => this.setTab(tab.key),
        onkeydown: event => this.tabKey(event, tabs),
      }, tab.label, tab.badge ? h("span", { class: `an-badge tone-${tab.tone || "mute"}`, text: tab.badge }) : null)));
      const panel = h("div", { class: "an-panel", role: "tabpanel", "data-role": "panel" });
      this.resultBox.replaceChildren(...pieces, h("div", { class: "an-shell" }, tablist, panel));
      this.panel = panel;
      this.renderTab();
    }

    tabKey(event, tabs) {
      if (!["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) return;
      event.preventDefault();
      const index = tabs.findIndex(tab => tab.key === this.state.tab);
      const next = event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : (index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
      this.setTab(tabs[next].key);
      this.resultBox.querySelector(`.an-tab[data-tab="${CSS.escape(tabs[next].key)}"]`)?.focus();
    }

    setTab(key, sectionId) {
      this.state.tab = key;
      this.resultBox.querySelectorAll(".an-tab").forEach(button => {
        const active = button.dataset.tab === key;
        button.classList.toggle("active", active);
        button.setAttribute("aria-selected", String(active));
      });
      this.renderTab(sectionId);
    }

    renderTab(sectionId) {
      const key = this.state.tab;
      if (key === "overview") this.panel.replaceChildren(this.overview());
      else if (key === "findings") this.panel.replaceChildren(this.findingsView());
      else if (key === "coverage") this.panel.replaceChildren(this.coverageView());
      else if (key === "collect") this.panel.replaceChildren(this.collectView());
      else {
        const group = key.slice(2);
        const sections = this.result.sections.filter(section => section.group === group);
        const state = { tables: this.state.tables[this.state.index] };
        this.panel.replaceChildren(h("div", { class: "an-sections" }, sections.length > 3 ? this.sectionNav(sections) : null, sections.map(section => buildSection(section, state))));
      }
      if (sectionId) this.focusSection(sectionId);
    }

    sectionNav(sections) {
      return h("nav", { class: "an-jump", "aria-label": "Jump to section" }, sections.map(section => h("button", { type: "button", class: "an-chip link", onclick: () => this.focusSection(section.id), text: section.title })));
    }

    focusSection(id) {
      const section = this.result.sections.find(item => item.id === id);
      if (!section) return;
      const key = section.group ? `g:${section.group}` : "overview";
      if (this.state.tab !== key) { this.setTab(key, id); return; }
      const node = this.panel.querySelector(`[data-section-id="${CSS.escape(id)}"]`);
      if (node) {
        node.scrollIntoView({ block: "start", behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth" });
        node.classList.add("flash");
        setTimeout(() => node.classList.remove("flash"), 1600);
      }
    }

    // ----------------------------------------------------------- overview
    overview() {
      const result = this.result;
      const cards = h("div", { class: "an-cards" }, result.cards.map(item => {
        const clickable = Boolean(item.section);
        const body = [h("span", { class: "an-card-label", text: item.label }), h("strong", { class: "an-card-value", text: formatNumber(item.value) }), item.hint ? h("small", { text: item.hint }) : null];
        return clickable
          ? h("button", { type: "button", class: `an-card tone-${item.tone || "mute"}`, onclick: () => this.goto(item.section) }, body)
          : h("div", { class: `an-card tone-${item.tone || "mute"}` }, body);
      }));
      const info = h("article", { class: "an-box" }, h("h3", { text: "Device information" }),
        result.info.length ? h("dl", { class: "an-kv" }, result.info.map(row => [h("dt", { text: row.label }), h("dd", { text: plain(row.value) })])) : h("p", { class: "an-empty", text: "No device details found in the capture." }));
      const top = result.findings.filter(f => f.severity !== "info").slice(0, 7);
      const findings = h("article", { class: "an-box" }, h("h3", { text: "Most important findings" }),
        top.length ? h("ul", { class: "an-top-findings" }, top.map(f => h("li", null, h("span", { class: `an-pill tone-${severityTone(f.severity)}`, text: SEVERITY_LABEL[f.severity] }),
          h("button", { type: "button", class: "an-link", onclick: () => this.openFinding(f), text: f.title })))) : h("p", { class: "an-empty", text: "No findings above informational level." }),
        result.findings.length ? h("button", { type: "button", class: "an-btn small", onclick: () => this.setTab("findings"), text: `View all ${result.findings.length} findings` }) : null);
      return h("div", { class: "an-overview" }, cards, h("div", { class: "an-two" }, info, findings));
    }

    goto(target) {
      if (["findings", "coverage", "collect", "overview"].includes(target)) this.setTab(target);
      else this.focusSection(target);
    }

    openFinding(finding) {
      this.state.findings = { sev: "all", cat: finding.category || "", q: finding.title.slice(0, 40) };
      this.setTab("findings");
    }

    // ----------------------------------------------------------- findings
    findingsView() {
      const all = this.result.findings;
      const f = this.state.findings;
      const counts = Object.fromEntries(SEVERITIES.map(sev => [sev, all.filter(item => item.severity === sev).length]));
      const categories = [...new Set(all.map(item => item.category).filter(Boolean))].sort();
      const list = h("div", { class: "an-finding-list" });
      const count = h("span", { class: "an-count" });
      const search = h("input", { type: "search", class: "an-search", placeholder: "Filter findings…", "aria-label": "Filter findings", value: f.q });
      const select = h("select", { class: "an-select", "aria-label": "Category" }, h("option", { value: "", text: "All categories" }), categories.map(cat => h("option", { value: cat, text: cat })));
      select.value = f.cat;
      const chips = h("div", { class: "an-sev-chips", role: "group", "aria-label": "Severity" });

      const paint = () => {
        chips.replaceChildren(h("button", { type: "button", class: `an-chip link${f.sev === "all" ? " active" : ""}`, onclick: () => { f.sev = "all"; paint(); }, text: `All ${all.length}` }),
          ...SEVERITIES.map(sev => h("button", { type: "button", class: `an-chip link tone-${severityTone(sev)}${f.sev === sev ? " active" : ""}`, onclick: () => { f.sev = sev; paint(); }, text: `${SEVERITY_LABEL[sev]} ${counts[sev]}` })));
        const terms = f.q.toLowerCase().split(/\s+/).filter(Boolean);
        const shown = all.filter(item => (f.sev === "all" || item.severity === f.sev) && (!f.cat || item.category === f.cat)
          && terms.every(term => `${item.id} ${item.title} ${item.object} ${item.detail} ${item.category}`.toLowerCase().includes(term)));
        count.textContent = `${shown.length} of ${all.length}`;
        list.replaceChildren(...(shown.length ? shown.map(item => this.findingCard(item)) : [h("p", { class: "an-empty", text: all.length ? "No finding matches the filter." : "No findings — nothing in this capture tripped a rule. The Coverage tab shows what the rules could and could not check." })]));
      };
      search.addEventListener("input", () => { f.q = search.value; paint(); });
      select.addEventListener("change", () => { f.cat = select.value; paint(); });
      paint();
      return h("div", { class: "an-findings" }, h("div", { class: "an-table-tools" }, chips, select, search, count), list);
    }

    findingCard(item) {
      return h("article", { class: `an-finding sev-${item.severity}` },
        h("div", { class: "an-finding-head" }, h("span", { class: `an-pill tone-${severityTone(item.severity)}`, text: SEVERITY_LABEL[item.severity] }), h("code", { class: "an-rule-id", text: item.id }), item.category ? h("span", { class: "an-chip", text: item.category }) : null),
        h("h4", { text: item.title }),
        item.object ? h("p", { class: "an-finding-object" }, h("span", { text: "Object" }), h("code", { text: item.object })) : null,
        item.detail ? h("p", { class: "an-finding-detail", text: item.detail }) : null,
        item.recommendation ? h("p", { class: "an-finding-fix" }, h("strong", { text: "Fix " }), item.recommendation) : null,
        item.reference ? h("a", { class: "an-ref", href: item.reference, target: "_blank", rel: "noopener noreferrer" }, "Documentation ↗") : null);
    }

    // ----------------------------------------------------------- coverage
    coverageView() {
      const rows = this.result.coverage || [];
      const section = {
        id: "coverage_table", kind: "table", title: "Commands in this capture", hint: "What was understood, what was ignored and why, and the commands that would add more detail. “Missing” rows are not in the file. Use the buttons to show one status.",
        columns: [{ key: "command", label: "Command", kind: "mono" }, { key: "status", label: "Status", kind: "status" }, { key: "lines", label: "Lines", kind: "num" }, { key: "note", label: "Note", kind: "wrap" }],
        rows: rows.map(row => ({ command: row.command, status: STATUS_LABEL[row.status] || row.status, lines: row.lines, note: row.note, _tones: { status: row.tone || "" } })),
        facets: [{ key: "status", label: "status", order: ["analysed", "covered", "not parsed", "error", "missing", "ignored"].map(key => STATUS_LABEL[key]) }],
        total: rows.length, empty: "No commands.", searchable: true, page_size: 200,
      };
      return h("div", { class: "an-sections" }, buildSection(section, { tables: this.state.tables[this.state.index] }));
    }

    // ------------------------------------------------------------ collect
    collectView() {
      const box = h("div", { class: "an-collect" });
      this.fillCollect(box);
      return box;
    }

    async loadCollect() {
      if (this.state.collect) return this.state.collect;
      try {
        const response = await fetch(`${this.api}/api/collect-scripts`);
        const payload = await response.json();
        this.state.collect = payload.scripts || [];
      } catch (error) {
        this.state.collect = [];
      }
      return this.state.collect;
    }

    async fillCollect(box) {
      box.replaceChildren(h("p", { class: "an-empty", text: "Loading collect lists…" }));
      const scripts = await this.loadCollect();
      const pieces = [h("div", { class: "an-section-head" }, h("h3", { text: "Collect lists" }),
        h("p", { text: `Paste a list into the device session, save the whole terminal buffer, and upload it here. Files named ${this.boot.collect_prefix || "collect-"}*.txt in static/collect-scripts appear here automatically.` }))];
      if (scripts.length) {
        pieces.push(h("div", { class: "an-collect-grid" }, scripts.map(script => h("article", { class: "an-box" },
          h("h4", { text: script.title }), h("p", { text: script.description || `${script.commands} commands` }),
          h("small", { text: `${script.commands} commands · ${formatBytes(script.size)}` }),
          h("div", { class: "an-actions" },
            h("a", { class: "an-btn small", href: script.url, download: script.file }, "Download .txt"),
            h("button", { type: "button", class: "an-btn small", onclick: () => this.copyScript(script) }, "Copy commands"))))));
      } else {
        pieces.push(h("div", { class: "an-banner info", role: "note" }, h("span", { text: this.boot.no_collect_message || "No collect list has been published for this analyzer yet. Use the command table below; a file named like the pattern above will show up here as soon as it is added." })));
      }
      const reference = this.boot.commands || [];
      if (reference.length) {
        pieces.push(buildSection({
          id: "command_reference", kind: "table", title: "Commands this analyzer reads", hint: "Each command unlocks the tables named on the right. Abbreviations are accepted (show int desc, sh ip bgp neighbors).",
          columns: [{ key: "command", label: "Command", kind: "mono" }, { key: "purpose", label: "What it adds", kind: "wrap" }],
          rows: reference, total: reference.length, empty: "", searchable: false, page_size: 200,
        }, { tables: {} }));
      }
      box.replaceChildren(...pieces);
    }

    async copyScript(script) {
      try {
        const response = await fetch(script.url);
        const text = (await response.text()).split(/\r?\n/).filter(line => line.trim() && !/^\s*[!#]/.test(line)).join("\n");
        await navigator.clipboard.writeText(text);
        toast(`Copied ${script.commands} commands.`);
      } catch (error) {
        toast("Could not copy automatically — use Download .txt instead.", "error");
      }
    }

    showCollectInEmpty() {
      const holder = this.q("collect-inline");
      if (!holder) return;
      holder.classList.toggle("hidden");
      if (!holder.classList.contains("hidden")) this.fillCollect(holder);
    }

    // ------------------------------------------------------------- export
    async exportExcel(button) {
      button.disabled = true;
      try {
        const response = await fetch(`${this.api}/api/export`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ results: this.state.results }) });
        const payload = await response.json();
        if (!response.ok || !payload.ok) throw new Error(payload.error || `HTTP ${response.status}`);
        const link = h("a", { href: payload.download_url, download: payload.download_name || "analysis.xlsx" });
        document.body.append(link);
        link.click();
        link.remove();
        toast("Excel export ready.");
      } catch (error) {
        toast(`Export failed: ${error.message}`, "error");
      } finally {
        button.disabled = false;
      }
    }
  }

  function formatBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  // -------------------------------------------------------------- bootstrap
  const instances = new WeakMap();

  function init(root) {
    if (instances.has(root)) return;
    try {
      instances.set(root, new Analyzer(root));
      root.dataset.anReady = "1";
    } catch (error) {
      console.error("[analyzer-kit] failed to initialise", error);
    }
  }

  function scan() {
    document.querySelectorAll(".an-page[data-analyzer]").forEach(init);
  }

  let scheduled = 0;
  const observer = new MutationObserver(() => {
    if (scheduled) return;
    scheduled = requestAnimationFrame(() => { scheduled = 0; scan(); });
  });
  observer.observe(document.body, { childList: true, subtree: true });
  document.addEventListener("DOMContentLoaded", scan);
  window.KeystoneAnalyzerKit = { scan, instances };
  scan();
})();
