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
  const STATUS_LABEL = { analyzed: "Analyzed", covered: "Covered", ignored: "Ignored", "not parsed": "Not parsed", error: "Rejected", missing: "Missing" };
  const MAX_CHIPS = 6;
  const MAX_FACET_VALUES = 12;   // a filter column with more distinct values than this is not a category

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
    if (/^(up(\/up)?|ok|good|yes|used|in use|established|full|registered|permit|strong|analyzed|active)$/.test(t)) return "ok";
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

    // A "shared" facet (the VDOM / vsys filter of the Firewall Analyzer) keeps one selection for the whole page:
    // pick a VDOM in one table and every other table that has the column follows. Other facets stay per table.
    const shared = state.tables.__shared || (state.tables.__shared = {});          // survives tab switches with the other table state
    const painters = state.painters || (state.painters = {});                       // the tables of this render, repainted together
    const present = new Map(facetDefs.map(def => [def.key, new Set(rows.map(row => cellText(row, def.key)).filter(Boolean))]));
    // The value that is actually applied here: a shared choice that this table has no row for is ignored, not applied.
    const activeOf = def => {
      const chosen = (def.shared ? shared[def.key] : local.facet[def.key]) || "";
      return chosen && present.get(def.key).size > 1 && present.get(def.key).has(chosen) ? chosen : "";
    };
    const choose = (def, value) => {
      if (!def.shared) { local.facet[def.key] = value; local.page = 0; paint(); return; }
      shared[def.key] = value;
      repaintScope(state);
    };

    const statusColumns = new Set(columns.filter(col => col.kind === "status").map(col => col.key));
    function facetTone(value) {
      const text = plain(value).toLowerCase();
      if (["pass", "enabled", "enable", "good", "available", "up"].includes(text)) return "ok";
      if (["fail", "forced down", "weak", "offline"].includes(text)) return "bad";
      const tone = statusTone(value);
      return tone === "mute" ? "" : tone;
    }

    function facetValues(def) {
      const found = new Map();
      rows.forEach(row => {
        const value = cellText(row, def.key);
        if (!value) return;
        // Chip colour: the row's own tone, else (for a status column) the same colour its pill gets: pass green, fail red
        const entry = found.get(value) || { count: 0, tone: (row._tones && row._tones[def.key]) || (statusColumns.has(def.key) ? facetTone(value) : "") };
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
        // One value gives nothing to filter by; a dozen-plus (peer names, counters) would be a wall of buttons, so the search box does that job
        if (values.length < 2 || (values.length > MAX_FACET_VALUES && !def.shared)) { if (!def.shared) delete local.facet[def.key]; return null; }
        const active = activeOf(def);
        const pick = value => () => choose(def, value === active ? "" : value);
        return h("div", { class: `an-sev-chips an-facet${def.shared ? " an-scope" : ""}`, role: "group", "aria-label": `Filter by ${def.label || def.key}` },
          def.shared ? h("span", { class: "an-facet-label", text: def.label || def.key }) : null,
          h("button", { type: "button", class: `an-chip link${active ? "" : " active"}`, "aria-pressed": active ? "false" : "true", onclick: pick(active), text: `All ${rows.length.toLocaleString()}` }),
          values.map(([value, info]) => h("button", { type: "button", class: `an-chip link${info.tone ? ` tone-${info.tone}` : ""}${active === value ? " active" : ""}`, "aria-pressed": active === value ? "true" : "false", onclick: pick(value),
            text: `${def.prefix || ""}${value} ${info.count.toLocaleString()}` })));
      }).filter(Boolean));
    }

    function filtered() {
      let list = rows;
      facetDefs.forEach(def => { const chosen = activeOf(def); if (chosen) list = list.filter(row => cellText(row, def.key) === chosen); });
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

    painters[section.id] = { local, paint };
    search.value = local.q;
    let timer = 0;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { local.q = search.value; local.page = 0; paint(); }, 120); });
    paint();
    return wrap;
  }


  // ----------------------------------------------------------------- map view
  // A clickable parent -> child tree (the Load Balancer "Network map": virtual server -> pool -> member -> monitor).
  // Data is the flat node list of a "map" section (features/analyzer_core/result.py: map_section).
  const mapHaystacks = new WeakMap();

  function buildMap(section, state) {
    const nodes = section.nodes || [];
    if (!nodes.length) return h("p", { class: "an-empty", text: section.empty });
    const statuses = section.statuses || [], types = section.types || [];
    const statusDef = new Map(statuses.map(def => [def.key, def]));
    const typeLabel = new Map(types.map(def => [def.key, def.label]));
    const byId = new Map(nodes.map(node => [node.id, node]));
    const kids = new Map();
    nodes.forEach(node => { const key = node.parent || ""; if (!kids.has(key)) kids.set(key, []); kids.get(key).push(node); });
    const byRef = new Map();
    nodes.forEach(node => { if (node.ref) { if (!byRef.has(node.ref)) byRef.set(node.ref, []); byRef.get(node.ref).push(node); } });
    const parents = nodes.filter(node => (kids.get(node.id) || []).length).map(node => node.id);

    const stateKey = `map:${section.id}`;
    const local = state.tables[stateKey] || (state.tables[stateKey] = { status: "", type: "", q: "", monitors: true, open: new Set(nodes.length <= 1500 ? parents : []), collapsed: new Set(), selected: "", focus: "" });

    const uniqueCount = pick => { const seen = new Set(); nodes.forEach(node => { if (pick(node)) seen.add(node.ref || node.id); }); return seen.size; };
    const dot = (status, extra) => {
      const def = statusDef.get(status);
      return h("span", { class: `an-map-dot ${def ? `shape-${def.shape} tone-${def.tone}` : "shape-none"}${extra ? ` ${extra}` : ""}`, title: def ? `${def.label}: ${def.description}` : "No status", "aria-hidden": "true" });
    };
    const statusLabel = status => (statusDef.get(status) || {}).label || status || "";
    const typeName = type => typeLabel.get(type) || type;
    const SOURCE = { live: "live 'show' output", config: "configuration", derived: "derived from its children / configuration" };

    function hay(node) {
      let value = mapHaystacks.get(node);
      if (value === undefined) {
        const parts = [node.name, node.badge, node.status, typeName(node.type)];
        (node.detail || []).forEach(pair => { if (["Address", "Port", "Destination", "Node", "Description"].includes(pair.label)) parts.push(plain(pair.value)); });
        value = parts.join(" ").toLowerCase();
        mapHaystacks.set(node, value);
      }
      return value;
    }

    const wrap = h("div", { class: "an-map" });
    const notes = (section.notes || []).length ? [h("div", { class: "an-banner info an-map-note", role: "note" }, (section.notes || []).map(text => h("span", { text })))] : [];
    const search = h("input", { type: "search", class: "an-search", placeholder: "Search name, address or port", "aria-label": "Search the network map", value: local.q });
    const counter = h("span", { class: "an-map-count", role: "status", "aria-live": "polite" });
    const statusBox = h("div", { class: "an-sev-chips an-facet", role: "group", "aria-label": "Filter by status" });
    const typeBox = h("div", { class: "an-sev-chips an-facet", role: "group", "aria-label": "Filter by type" });
    const monitorToggle = h("input", { type: "checkbox", id: null });
    monitorToggle.checked = local.monitors;
    const tree = h("div", { class: "an-map-tree", role: "tree", "aria-label": section.title });
    const detail = h("aside", { class: "an-map-detail an-box", "aria-label": "Selected object" });
    const summaryBox = h("details", { class: "an-map-summary" });
    const rowEls = new Map();

    // ---- what is shown
    let visible = new Map(), subtree = new Map(), filtering = false, shown = 0;
    const terms = () => local.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    function matches(node, words) {
      if (!local.monitors && node.type === "monitor") return false;
      if (local.status && node.status !== local.status) return false;
      if (local.type && node.type !== local.type) return false;
      return words.every(word => hay(node).includes(word));
    }
    function compute() {
      const words = terms();
      filtering = Boolean(local.status || local.type || words.length);
      visible = new Map(); subtree = new Map(); shown = 0;
      const mark = node => {
        const self = matches(node, words);
        let below = false;
        (kids.get(node.id) || []).forEach(child => { if (mark(child)) below = true; });
        const show = filtering ? (self || below) : (local.monitors || node.type !== "monitor");
        visible.set(node.id, { show, self, below });
        if (show && (self || !filtering)) shown += 1;
        return filtering ? (self || below) : show;
      };
      (kids.get("") || []).forEach(mark);
    }
    const isOpen = node => {
      const children = (kids.get(node.id) || []).filter(child => visible.get(child.id) && visible.get(child.id).show);
      if (!children.length) return false;
      if (local.collapsed.has(node.id)) return false;
      return local.open.has(node.id) || (filtering && visible.get(node.id).below);
    };
    function toggle(id) {
      const node = byId.get(id);
      if (isOpen(node)) { local.open.delete(id); local.collapsed.add(id); }
      else { local.collapsed.delete(id); local.open.add(id); }
      local.focus = id;
      paintTree();
    }
    function reveal(id) {
      for (let node = byId.get(id); node && node.parent; node = byId.get(node.parent)) { local.collapsed.delete(node.parent); local.open.add(node.parent); }
    }
    function select(id, focusRow) {
      local.selected = id;
      local.focus = id;
      rowEls.forEach((el, key) => {
        el.classList.toggle("selected", key === id);
        el.setAttribute("aria-selected", String(key === id));
        el.tabIndex = key === id ? 0 : -1;
      });
      const node = byId.get(id);
      rowEls.forEach((el, key) => el.classList.toggle("same", Boolean(node && node.ref && key !== id && byId.get(key).ref === node.ref)));
      paintDetail();
      if (focusRow && rowEls.get(id)) rowEls.get(id).focus();
    }

    // ---- tree
    function item(node, level) {
      const info = visible.get(node.id);
      const children = (kids.get(node.id) || []).filter(child => visible.get(child.id) && visible.get(child.id).show);
      const open = isOpen(node);
      const caret = children.length
        ? h("button", { type: "button", class: "an-map-caret", tabindex: "-1", "aria-label": `${open ? "Collapse" : "Expand"} ${node.name}`, onclick: event => { event.stopPropagation(); toggle(node.id); } }, h("span", { class: `an-map-chevron${open ? " open" : ""}`, "aria-hidden": "true" }))
        : h("span", { class: "an-map-caret spacer", "aria-hidden": "true" });
      const row = h("div", {
        class: `an-map-row type-${node.type}${filtering ? (info.self ? " hit" : " dim") : ""}${node.tone ? ` row-${node.tone}` : ""}`, role: "treeitem", "aria-level": String(level), "aria-selected": String(local.selected === node.id),
        "aria-expanded": children.length ? String(open) : null, tabindex: (local.selected || local.focus || (kids.get("") || [])[0].id) === node.id ? "0" : "-1", "data-id": node.id,
        onclick: () => select(node.id), ondblclick: () => { if (children.length) toggle(node.id); },
      }, caret, dot(node.status), h("span", { class: "an-map-name", text: node.name }), h("span", { class: "an-map-type", text: typeName(node.type) }), node.badge ? h("span", { class: "an-map-badge", text: node.badge }) : null,
        children.length && !open ? h("span", { class: "an-map-kids", text: `${children.length}` }) : null,
        node.status ? h("span", { class: `an-pill an-map-status tone-${(statusDef.get(node.status) || {}).tone || "mute"}`, text: statusLabel(node.status) }) : null);
      row.classList.toggle("selected", local.selected === node.id);
      rowEls.set(node.id, row);
      const li = h("li", { role: "none", class: "an-map-item" }, row);
      if (open && children.length) li.append(h("ul", { role: "group", class: "an-map-level" }, children.map(child => item(child, level + 1))));
      return li;
    }
    function paintTree() {
      compute();
      rowEls.clear();
      const roots = (kids.get("") || []).filter(node => visible.get(node.id) && visible.get(node.id).show);
      if (!roots.length) tree.replaceChildren(h("p", { class: "an-empty", text: "No object matches the current filters." }));
      else tree.replaceChildren(h("ul", { class: "an-map-level root", role: "none" }, roots.map(node => item(node, 1))));
      counter.textContent = filtering ? `${shown.toLocaleString()} matching of ${nodes.length.toLocaleString()} objects` : `${nodes.length.toLocaleString()} objects`;
      paintFilters();
      if (local.selected && rowEls.get(local.selected)) { rowEls.get(local.selected).classList.add("selected"); select(local.selected, false); }
      else paintDetail();
      if (![...rowEls.values()].some(el => el.tabIndex === 0) && rowEls.size) rowEls.values().next().value.tabIndex = 0;   // keep the tree reachable with Tab
      if (local.restoreFocus && rowEls.get(local.focus)) { rowEls.get(local.focus).focus(); }
      local.restoreFocus = false;
    }

    // ---- filters (Status / Type, as in the BIG-IP GUI) and the summary
    function chip(label, count, active, tone, onclick, status) {
      return h("button", { type: "button", class: `an-chip link${tone ? ` tone-${tone}` : ""}${active ? " active" : ""}`, "aria-pressed": String(active), onclick }, status !== undefined ? dot(status) : null, `${label} ${count.toLocaleString()}`);
    }
    function paintFilters() {
      const total = uniqueCount(() => true);
      const statusChips = statuses.map(def => { const count = uniqueCount(node => node.status === def.key); return count ? chip(def.label, count, local.status === def.key, def.tone === "dark" ? "" : def.tone, () => { local.status = local.status === def.key ? "" : def.key; paintTree(); }, def.key) : null; }).filter(Boolean);
      const typeChips = types.map(def => { const count = uniqueCount(node => node.type === def.key); return count ? chip(def.label, count, local.type === def.key, "", () => { local.type = local.type === def.key ? "" : def.key; paintTree(); }) : null; }).filter(Boolean);
      statusBox.replaceChildren(h("span", { class: "an-facet-label", text: "Status" }), chip("All", total, !local.status, "", () => { local.status = ""; paintTree(); }), ...statusChips);
      typeBox.replaceChildren(h("span", { class: "an-facet-label", text: "Type" }), chip("All", total, !local.type, "", () => { local.type = ""; paintTree(); }), ...typeChips);
      paintSummary();
    }
    function paintSummary() {
      const wanted = types.filter(def => uniqueCount(node => node.type === def.key && node.status));
      const cols = statuses.filter(def => uniqueCount(node => node.status === def.key));
      const wasOpen = summaryBox.open;
      const head = h("tr", null, h("th", { scope: "col", text: "Object" }), cols.map(def => h("th", { scope: "col" }, dot(def.key), ` ${def.label}`)), h("th", { scope: "col", text: "Total" }));
      const body = wanted.map(def => h("tr", null, h("th", { scope: "row", text: def.label }),
        cols.map(col => { const count = uniqueCount(node => node.type === def.key && node.status === col.key); return h("td", { class: "an-num" }, count ? h("button", { type: "button", class: "an-link", onclick: () => { local.type = def.key; local.status = col.key; paintTree(); }, text: count.toLocaleString() }) : "–"); }),
        h("td", { class: "an-num" }, h("button", { type: "button", class: "an-link", onclick: () => { local.type = def.key; local.status = ""; paintTree(); }, text: uniqueCount(node => node.type === def.key).toLocaleString() }))));
      summaryBox.replaceChildren(h("summary", { text: "Summary by type and status" }), h("div", { class: "an-map-summary-body" }, h("table", { class: "an-table an-map-summary-table" }, h("thead", null, head), h("tbody", null, body)),
        h("p", { class: "an-map-fine", text: "A pool used by several virtual servers is counted once." })));
      summaryBox.open = wasOpen;
    }

    // ---- detail panel
    function chain(node) { const out = []; for (let up = node; up; up = byId.get(up.parent)) out.unshift(up); return out; }
    function paintDetail() {
      const node = byId.get(local.selected);
      if (!node) {
        detail.replaceChildren(h("h3", { text: "Details" }), h("p", { class: "an-empty", text: "Click a virtual server, pool, member or monitor to see its status, the reason, the health monitors that apply and where else it is used." }),
          h("p", { class: "an-map-fine", text: "Arrow keys move through the tree; Right / Left expand or collapse; Enter selects." }));
        return;
      }
      const def = statusDef.get(node.status);
      const skip = new Set(["Status", "Source", "Reason"]);
      const pairs = (node.detail || []).filter(pair => !skip.has(pair.label));
      const list = h("dl", { class: "an-kv" });
      pairs.forEach(pair => {
        const dd = h("dd");
        if (Array.isArray(pair.value)) pair.value.forEach(entry => dd.append(h("span", { class: "an-chip", text: plain(entry) })));
        else dd.textContent = plain(pair.value) || "—";
        list.append(h("dt", { text: pair.label }), dd);
      });
      const others = (node.ref && byRef.get(node.ref) || []).filter(other => other.id !== node.id);
      const trail = chain(node);
      detail.replaceChildren(...[                      // replaceChildren(null) would write the text "null": drop the empty parts
        h("div", { class: "an-map-detail-head" }, dot(node.status, "big"), h("div", null, h("h3", { text: node.name }), h("small", { text: typeName(node.type) + (node.badge ? ` · ${node.badge}` : "") }))),
        node.status ? h("p", { class: "an-map-detail-status" }, h("span", { class: `an-pill tone-${(def || {}).tone || "mute"}`, text: statusLabel(node.status) }), node.source ? h("span", { class: "an-chip", text: `from ${SOURCE[node.source] || node.source}` }) : null) : null,
        def ? h("p", { class: "an-map-fine", text: def.description }) : null,
        node.reason ? h("p", { class: "an-map-reason", text: node.reason }) : null,
        trail.length > 1 ? h("nav", { class: "an-map-trail", "aria-label": "Path" }, trail.map((step, index) => [index ? h("span", { "aria-hidden": "true", text: " › " }) : null, index === trail.length - 1 ? h("strong", { text: step.name }) : h("button", { type: "button", class: "an-link", onclick: () => { reveal(step.id); select(step.id, false); paintTree(); }, text: step.name })])) : null,
        pairs.length ? list : null,
        others.length ? h("div", { class: "an-map-also" }, h("h4", { text: `Also appears ${others.length} more time${others.length === 1 ? "" : "s"}` }),
          h("ul", null, others.slice(0, 12).map(other => { const parent = byId.get(other.parent); return h("li", null, h("button", { type: "button", class: "an-link", onclick: () => { reveal(other.id); local.selected = other.id; paintTree(); rowEls.get(other.id)?.scrollIntoView({ block: "nearest" }); }, text: parent ? `under ${parent.name}` : "at the top" })); })),
          others.length > 12 ? h("small", { text: `+${others.length - 12} more` }) : null) : null,
        node.section && state.goto ? h("button", { type: "button", class: "an-btn small", onclick: () => state.goto(node.section) }, "Open in the table") : null].filter(Boolean));
    }

    // ---- keyboard (tree pattern)
    tree.addEventListener("keydown", event => {
      const row = event.target.closest && event.target.closest(".an-map-row");
      if (!row) return;
      const rows = [...tree.querySelectorAll(".an-map-row")];
      const index = rows.indexOf(row);
      const node = byId.get(row.dataset.id);
      const move = target => { if (target) { event.preventDefault(); local.focus = target.dataset.id; rows.forEach(r => { r.tabIndex = -1; }); target.tabIndex = 0; target.focus(); } };
      if (event.key === "ArrowDown") move(rows[index + 1]);
      else if (event.key === "ArrowUp") move(rows[index - 1]);
      else if (event.key === "Home") move(rows[0]);
      else if (event.key === "End") move(rows[rows.length - 1]);
      else if (event.key === "ArrowRight") {
        if (row.getAttribute("aria-expanded") === "false") { event.preventDefault(); local.restoreFocus = true; toggle(node.id); }
        else if (row.getAttribute("aria-expanded") === "true") move(rows[index + 1]);
      } else if (event.key === "ArrowLeft") {
        if (row.getAttribute("aria-expanded") === "true") { event.preventDefault(); local.restoreFocus = true; toggle(node.id); }
        else if (node.parent && rowEls.get(node.parent)) move(rowEls.get(node.parent));
      } else if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(node.id, true); }
    });

    // ---- controls
    let timer = 0;
    search.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => { local.q = search.value; paintTree(); }, 120); });
    monitorToggle.addEventListener("change", () => { local.monitors = monitorToggle.checked; paintTree(); });
    const expandAll = () => { local.collapsed.clear(); parents.forEach(id => local.open.add(id)); paintTree(); };
    const collapseAll = () => { local.open.clear(); parents.forEach(id => local.collapsed.add(id)); paintTree(); };
    const reset = () => { local.status = ""; local.type = ""; local.q = ""; search.value = ""; paintTree(); };
    const controls = h("div", { class: "an-map-controls" },
      h("div", { class: "an-table-tools" }, search, h("button", { type: "button", class: "an-btn small", onclick: expandAll, text: "Expand all" }), h("button", { type: "button", class: "an-btn small", onclick: collapseAll, text: "Collapse all" }),
        h("label", { class: "an-map-check" }, monitorToggle, " Health monitors"), h("button", { type: "button", class: "an-btn small", onclick: reset, text: "Reset" }), counter),
      statusBox, typeBox);

    const legend = h("div", { class: "an-map-legend", "aria-label": "Legend" }, statuses.map(def => h("span", { class: "an-map-key", title: def.description }, dot(def.key), def.label)));
    const refs = (section.references || []).length ? h("details", { class: "an-map-refs" }, h("summary", { text: "What the icons mean, and where this comes from" }),
      h("ul", null, statuses.map(def => h("li", null, dot(def.key), h("strong", { text: ` ${def.label}: ` }), def.description))),
      h("p", { class: "an-map-fine", text: "Documentation:" }),
      h("ul", null, section.references.map(ref => h("li", null, h("a", { href: ref.url, target: "_blank", rel: "noopener noreferrer", text: ref.label }))))) : null;

    wrap.append(...[...notes, controls, legend, summaryBox, h("div", { class: "an-map-body" }, tree, detail), refs].filter(Boolean));
    paintTree();
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

  // Shared (scope) filters: one selection for every table of the tab, e.g. the FortiGate VDOM or the Palo Alto vsys.
  function repaintScope(state) {
    Object.values(state.painters || {}).forEach(entry => { entry.local.page = 0; entry.paint(); });
    if (state.onScope) state.onScope();
  }

  // The bar above the tables of a tab: one button per scope value found in any of its tables. Returns null when the
  // tab has no scope column or only one value (a single-VDOM device).
  function scopeBar(sections, state) {
    const found = new Map();
    sections.forEach(section => (section.facets || []).filter(def => def.shared && (section.columns || []).some(col => col.key === def.key)).forEach(def => {
      const entry = found.get(def.key) || { def, counts: new Map() };
      (section.rows || []).forEach(row => { const value = plain(row[def.key]); if (value) entry.counts.set(value, (entry.counts.get(value) || 0) + 1); });
      found.set(def.key, entry);
    }));
    const entries = [...found.values()].filter(entry => entry.counts.size > 1);
    if (!entries.length) return null;
    const shared = state.tables.__shared || (state.tables.__shared = {});
    const box = h("div", { class: "an-scope-bar", role: "group", "aria-label": "Scope filter" });
    const paintBar = () => box.replaceChildren(...entries.map(({ def, counts }) => {
      const active = counts.has(shared[def.key]) ? shared[def.key] : "";
      const pick = value => () => { shared[def.key] = value === active ? "" : value; repaintScope(state); };
      const names = [...counts.keys()].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
      return h("div", { class: "an-sev-chips an-facet an-scope" },
        h("span", { class: "an-facet-label", text: `${def.label || def.key} filter` }),
        h("button", { type: "button", class: `an-chip link${active ? "" : " active"}`, "aria-pressed": active ? "false" : "true", onclick: pick(active), text: "All" }),
        names.map(name => h("button", { type: "button", class: `an-chip link${active === name ? " active" : ""}`, "aria-pressed": active === name ? "true" : "false", onclick: pick(name), text: name })));
    }));
    state.onScope = paintBar;
    paintBar();
    return box;
  }

  function buildSection(section, state) {
    const header = h("header", { class: "an-section-head" }, h("h3", { text: section.title }), section.hint ? h("p", { text: section.hint }) : null);
    const body = section.kind === "table" ? buildTable(section, state) : (section.kind === "map" ? buildMap(section, state) : buildKv(section));
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
        h("div", { class: "an-toolbar-title" }, h("strong", { text: result.hostname || result.source_name }), h("span", { text: [result.platform, result.source_name].filter(Boolean).join(" · ") })), this.compareBar(), exportButton));
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

    // Compare two analyzed devices (an older backup against a newer one, or the two units of an HA pair).
    // The answer is a result of its own, added as one more device tab, so every table, filter and the Excel export work on it.
    compareBar() {
      const real = this.state.results.map((item, index) => ({ item, index })).filter(entry => !entry.item.comparison);
      if (real.length < 2) return null;
      const pick = this.state.compare = this.state.compare && real.some(e => e.index === this.state.compare.a) && real.some(e => e.index === this.state.compare.b) ? this.state.compare : { a: real[0].index, b: real[1].index };
      const label = entry => entry.item.hostname || entry.item.source_name;
      const select = (key, aria) => {
        const node = h("select", { class: "an-select", "aria-label": aria }, real.map(entry => h("option", { value: String(entry.index), selected: entry.index === pick[key] ? true : null, text: label(entry) })));
        node.addEventListener("change", () => { pick[key] = Number(node.value); });
        return node;
      };
      const button = h("button", { type: "button", class: "an-btn", onclick: () => this.compare(button) }, "Compare");
      return h("div", { class: "an-compare", role: "group", "aria-label": "Compare two devices" }, h("span", { class: "an-facet-label", text: "Compare" }), select("a", "First capture"), h("span", { text: "→" }), select("b", "Second capture"), button);
    }

    async compare(button) {
      const { a, b } = this.state.compare;
      if (a === b) { toast("Pick two different devices to compare.", "error"); return; }
      button.disabled = true;
      try {
        const response = await fetch(`${this.api}/api/compare`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ before: this.state.results[a], after: this.state.results[b] }) });
        let payload = null;
        try { payload = await response.json(); } catch (error) { /* non-JSON error body */ }
        if (!response.ok || !payload || !payload.ok) throw new Error((payload && payload.error) || `HTTP ${response.status}`);
        const old = this.state.results.findIndex(item => item.comparison);
        if (old !== -1) { this.state.results.splice(old, 1); this.state.tables.splice(old, 1); }
        this.state.results.push(payload.result);
        this.state.tables.push({});
        this.state.index = this.state.results.length - 1;
        this.state.tab = "overview";
        this.render();
      } catch (error) {
        toast(`Comparison failed: ${error.message}`, "error");
        button.disabled = false;
      }
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
        const state = { tables: this.state.tables[this.state.index], painters: {}, goto: id => this.focusSection(id) };
        const bar = scopeBar(sections, state);
        this.panel.replaceChildren(h("div", { class: "an-sections" }, bar, sections.length > 3 ? this.sectionNav(sections) : null, sections.map(section => buildSection(section, state))));
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
        facets: [{ key: "status", label: "status", order: ["analyzed", "covered", "not parsed", "error", "missing", "ignored"].map(key => STATUS_LABEL[key]) }],
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
