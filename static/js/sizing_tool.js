// Sizing Tool: upload captures (or combine demo sets), read them with the analyzers' own engines on the server, show the inventory grouped by device type.
// Scoped to .sz-page (the SPA router keeps every visited page mounted).  Every value that came from a capture is escaped before it is written into the page.
(() => {
  const root = document.querySelector(".sz-page");
  if (!root || root.dataset.ready) return;
  root.dataset.ready = "1";
  const $ = (role) => root.querySelector(`[data-role="${role}"]`);
  const api = root.dataset.api;
  const form = $("form"), input = $("file-input"), list = $("file-list"), status = $("status"), drop = $("drop");
  function loadLibrary() { try { const list = JSON.parse(localStorage.getItem("keystone-sizing-candidates") || "[]"); return Array.isArray(list) ? list : []; } catch (error) { return []; } }
  function saveLibrary() { try { localStorage.setItem("keystone-sizing-candidates", JSON.stringify(state.library)); } catch (error) { /* private window or blocked storage: the library lives in this page until it is exported */ } }
  const state = { files: [], demo: new Set(), runId: "", data: null, overrides: {}, tab: "types", sets: [], profiles: {}, peaks: {}, runs: [], compare: null, library: loadLibrary(), pick: {}, cmp: {}, open: new Set() };

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const num = (value) => (typeof value === "number" ? value.toLocaleString("en-US", { maximumFractionDigits: 1 }) : esc(value));
  const plural = (n, word) => `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : "s"}`;
  const setStatus = (text, bad) => { status.textContent = text || ""; status.classList.toggle("error", !!bad); };
  const growth = () => Math.max(0, Math.min(500, parseFloat($("growth").value) || 0));
  const options = () => ({ growth: growth(), spare_pct: Math.max(0, Math.min(90, parseFloat($("spare").value) || 0)), redundancy: $("redundancy").value, ports_basis: $("basis").value,
    expiry_months: Math.max(1, Math.min(60, parseInt($("months").value, 10) || 12)), profiles: state.profiles, manual_peaks: state.peaks, overrides: state.overrides });
  const post = async (path, body) => {
    const response = await fetch(`${api}${path}`, body instanceof FormData ? { method: "POST", body } : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `The server answered ${response.status}.`);
    return payload;
  };
  const download = async (path, body, fallback, label) => {
    setStatus(`Building ${label}...`);
    const response = await fetch(`${api}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error((await response.json().catch(() => ({}))).error || `${label} could not be built.`);
    const blob = await response.blob();
    const name = (response.headers.get("Content-Disposition") || "").match(/filename="?([^";]+)"?/);
    const url = URL.createObjectURL(blob), a = document.createElement("a");
    a.href = url; a.download = name ? name[1] : fallback; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    setStatus(`${label} downloaded.`);
  };

  // ---- intake -----------------------------------------------------------------------------------------------------------------------------------
  function renderFiles() {
    list.classList.toggle("hidden", !state.files.length);
    list.innerHTML = state.files.map((f, i) => `<li><span class="an-file-name">${esc(f.name)}</span><button type="button" class="an-btn small" data-remove="${i}" aria-label="Remove ${esc(f.name)}">Remove</button></li>`).join("");
  }
  function addFiles(files) {
    const known = new Set(state.files.map((f) => `${f.name}:${f.size}`));
    for (const file of files) if (!known.has(`${file.name}:${file.size}`)) state.files.push(file);
    renderFiles();
  }
  input.addEventListener("change", () => { addFiles([...input.files]); input.value = ""; });
  ["dragenter", "dragover"].forEach((name) => drop.addEventListener(name, (e) => { e.preventDefault(); drop.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((name) => drop.addEventListener(name, (e) => { e.preventDefault(); drop.classList.remove("dragging"); }));
  drop.addEventListener("drop", (e) => addFiles([...(e.dataTransfer?.files || [])]));
  list.addEventListener("click", (e) => {
    const button = e.target.closest("[data-remove]");
    if (!button) return;
    state.files.splice(Number(button.dataset.remove), 1);
    renderFiles();
  });
  $("clear").addEventListener("click", () => {
    state.files = []; state.demo.clear(); renderFiles(); renderDemo(); setStatus("");
  });

  function renderDemo() {
    const buttons = $("demo-buttons");
    buttons.innerHTML = state.sets.map((s) => `<button type="button" class="an-btn small sz-chip" data-demo="${esc(s.id)}" aria-pressed="${state.demo.has(s.id)}" title="${esc(s.description)}">${esc(s.label)} <span class="sz-chip-count">${s.files.length}</span></button>`).join("");
  }
  $("demo-buttons").addEventListener("click", (e) => {
    const button = e.target.closest("[data-demo]");
    if (!button) return;
    const id = button.dataset.demo;
    if (state.demo.has(id)) state.demo.delete(id); else state.demo.add(id);
    renderDemo();
    const total = state.sets.filter((s) => state.demo.has(s.id)).reduce((n, s) => n + s.files.length, 0);
    setStatus(total ? `${plural(total, "invented capture")} selected. Press Build the sizing inventory. Sets that share hostnames (before and after, HQ and HQ-DC) are counted twice, so combine them with care.` : "");
  });
  fetch(`${api}/api/demo`, { cache: "no-store" }).then((r) => r.json()).then((payload) => {
    state.sets = ((payload && payload.sets) || []).filter((s) => s.files && s.files.length);
    if (!state.sets.length) return;
    renderDemo();
    $("demo").hidden = false;
  }).catch(() => { /* no demo row */ });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!state.files.length && !state.demo.size) { setStatus("Add device captures or choose a demo set first.", true); return; }
    const body = new FormData();
    state.files.forEach((f) => body.append("files", f, f.name));
    body.append("demo", [...state.demo].join(","));
    body.append("name", $("name").value);
    body.append("growth", String(growth()));
    const submit = $("analyze");
    submit.disabled = true;
    setStatus("Reading the captures with the analyzers...");
    try {
      const payload = await post("/api/analyze", body);
      state.runId = payload.run_id; state.overrides = {}; state.profiles = {}; state.peaks = {}; state.compare = null;
      show(payload);
      setStatus(`Read ${plural(payload.assets.length, "device")}${payload.skipped.length ? `; ${plural(payload.skipped.length, "file")} skipped (see Gaps and inputs)` : ""}.`);
    } catch (error) {
      setStatus(error.message || "The captures could not be read.", true);
    } finally {
      submit.disabled = false;
    }
  });

  // ---- capture pack (before any run) -----------------------------------------------------------------------------------------------------------
  fetch(`${api}/api/capture-packs`, { cache: "no-store" }).then((r) => r.json()).then((payload) => {
    $("packs").innerHTML = (payload.packs || []).map((p) => `<details class="sz-pack"><summary><strong>${esc(p.title)}</strong> <span class="sz-pill">${p.commands.length} commands</span></summary>
      <table class="sz-table"><tbody>${p.commands.map((c) => `<tr><td><code>${esc(c.command)}</code></td><td>${esc(c.why)}</td></tr>`).join("")}</tbody></table>
      <ul class="sz-list">${p.docs.map((d) => `<li><a href="${esc(d.url)}" target="_blank" rel="noopener noreferrer">${esc(d.title)}</a></li>`).join("")}</ul></details>`).join("");
  }).catch(() => { /* the download link still works */ });

  // ---- result -----------------------------------------------------------------------------------------------------------------------------------
  const allAssets = () => state.data.all_assets || state.data.assets;
  function show(payload) {
    state.data = payload;
    const o = payload.options || {};
    if (o.spare_pct !== undefined) $("spare").value = o.spare_pct;
    if (o.redundancy) $("redundancy").value = o.redundancy;
    if (o.ports_basis) $("basis").value = o.ports_basis;
    if (o.expiry_months) $("months").value = o.expiry_months;
    $("empty").hidden = true; $("empty-what").hidden = true;
    $("result").hidden = false;
    $("recalc").hidden = !Object.keys(state.overrides).length;
    const s = payload.rollup.summary;
    const apRecords = s.by_type["Access point"] || 0;
    const boxes = s.devices - apRecords;                       // an access-point record is a model with a quantity, not a box
    const cards = [[boxes, boxes === 1 ? "device" : "devices"]];
    if (s.access_points) cards.push([s.access_points, s.access_points === 1 ? "access point" : "access points"], [apRecords, apRecords === 1 ? "access point model" : "access point models"]);
    Object.entries(s.by_type).filter(([k]) => k !== "Access point").forEach(([k, v]) => cards.push([v, v === 1 ? k.toLowerCase() : (/(ch|s|x)$/i.test(k) ? k.toLowerCase() + "es" : k.toLowerCase() + "s")]));
    const brands = Object.keys(s.by_vendor).length;
    cards.push([brands, brands === 1 ? "brand" : "brands"], [s.sites, s.sites === 1 ? "site" : "sites"], [`${s.with_licence}/${boxes}`, "with licence output"]);
    const ex = payload.rollup.expiry;
    if (ex && ex.expired) cards.push([ex.expired, "licences expired"]);
    if (ex && ex.soon) cards.push([ex.soon, `ending within ${ex.months} months`]);
    if (s.duplicates) cards.push([s.duplicates, "duplicate captures left out"]);
    $("cards").innerHTML = cards.map(([v, l]) => `<div class="sz-card"><strong>${num(v)}</strong><span>${esc(l)}</span></div>`).join("");
    const conf = payload.rollup.confidence || {};
    $("result-note").innerHTML = `${esc(payload.name || "Sizing run")} &middot; growth margin ${esc(payload.rollup.growth)} % &middot; ${plural(payload.assets.length, "device")} counted &middot; ${plural(payload.rollup.units.count, "logical unit")}. Quantities that add up are shown as <em>today</em> and <em>target</em>; the rest is shown as read. Figures: ${num(conf.high || 0)} high confidence, ${num(conf.medium || 0)} medium, ${num(conf.low || 0)} low, ${num(conf.entered || 0)} entered by you (see Evidence).`;
    renderTab();
  }

  // ---- tables: filter and sort, in every table --------------------------------------------------------------------------------------------------
  const table = (headers, rows, opts = {}) => `<div class="sz-tablewrap">${rows.length > 6 || opts.filter ? `<input class="sz-text sz-filter" type="search" placeholder="Filter rows" aria-label="Filter the rows of this table">` : ""}<div class="sz-scroll"><table class="sz-table" data-sortable><thead><tr>${headers.map((h, i) => `<th aria-sort="none">${h ? `<button type="button" class="sz-sort" data-col="${i}">${esc(h)}</button>` : ""}</th>`).join("")}</tr></thead><tbody>${rows.length ? rows.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`).join("") : `<tr><td colspan="${headers.length}" class="sz-none">${esc(opts.empty || "Nothing in the captures.")}</td></tr>`}</tbody></table></div></div>`;
  const cellValue = (cell) => { const field = cell.querySelector("input, select"); return (field ? field.value : cell.textContent).trim(); };
  root.addEventListener("input", (e) => {
    const box = e.target.closest(".sz-filter");
    if (!box) return;
    const needle = box.value.trim().toLowerCase();
    box.closest(".sz-tablewrap").querySelectorAll("tbody tr").forEach((tr) => { tr.hidden = !!needle && !tr.textContent.toLowerCase().includes(needle) && ![...tr.querySelectorAll("input,select")].some((f) => String(f.value).toLowerCase().includes(needle)); });
  });
  root.addEventListener("click", (e) => {
    const button = e.target.closest(".sz-sort");
    if (!button) return;
    const tbl = button.closest("table"), col = Number(button.dataset.col), th = button.closest("th");
    const dir = th.getAttribute("aria-sort") === "ascending" ? "descending" : "ascending";
    tbl.querySelectorAll("th").forEach((x) => x.setAttribute("aria-sort", "none"));
    th.setAttribute("aria-sort", dir);
    const body = tbl.tBodies[0], rows = [...body.rows].filter((r) => r.cells.length > 1);
    const key = (r) => { const v = cellValue(r.cells[col]); const n = parseFloat(v.replace(/,/g, "")); return Number.isFinite(n) && /^[-\d.,\s%]+/.test(v) ? n : v.toLowerCase(); };
    rows.sort((a, b) => { const x = key(a), y = key(b); const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true }); return dir === "ascending" ? c : -c; });
    rows.forEach((r) => body.appendChild(r));
  });

  const chips = (obj) => Object.entries(obj || {}).map(([k, v]) => `<span class="sz-pill">${esc(k)} <b>${num(v)}</b></span>`).join(" ");
  const list2 = (items) => `<ul class="sz-list">${items.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>`;
  const links = (items) => items.length ? `<ul class="sz-list">${items.map((l) => `<li><span class="sz-pill">${esc(l.vendor)} &middot; ${esc(l.topic)}</span> <a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.title)}</a></li>`).join("")}</ul>` : "";
  const typeName = (t) => (state.data.type_labels || {})[t] || t;
  const tag = (text, kind) => `<span class="sz-tag sz-tag-${esc(kind)}">${esc(text)}</span>`;
  const sourceTag = (src) => (src === "csv" ? tag("imported", "entered") : src === "manual" ? tag("entered", "entered") : "");

  function typesTab(r) {
    return r.groups.map((g, i) => {
      const sizing = g.sizing.map((x) => [esc(x.label), num(x.today), x.scales ? `<b>${num(x.target)}</b>` : `<span class="sz-faint">as today</span>`, num(x.largest_single_device)]);
      const models = g.models.map((m) => [esc(m.vendor), esc(m.model), num(m.qty), esc(Object.entries(m.tiers).map(([k, v]) => `${k} ${v}`).join(", ")), esc(Object.entries(m.ha).map(([k, v]) => `${k} ${v}`).join(", ")), esc(m.os.join(", ") || "")]);
      const feats = g.features.map((f) => `<span class="sz-feat" title="${esc(f.group)}">${esc(f.name)} <b>${num(f.devices)}</b>${f.objects ? `<small>${num(f.objects)} ${f.objects === 1 ? "object" : "objects"}</small>` : ""}</span>`).join("");
      const lic = g.licences.map((l) => [esc(l.vendor), esc(l.name), esc(l.state), num(l.count), esc(l.expires.join(", "))]);
      const gaps = g.gaps.map((x) => `${x.note} (${x.count})`);
      return `<details class="sz-type" ${i === 0 ? "open" : ""}><summary><strong>${esc(g.label)}</strong> <span class="sz-pill">${num(g.units)}${g.units !== g.count ? ` units on ${plural(g.count, "record")}` : ""}</span> ${chips(g.vendors)}</summary>
        <div class="sz-body">
          <h4>Models</h4>${table(["Brand", "Model", "Qty", "Tier", "Redundancy", "Software"], models)}
          <h4>What a replacement must carry <small>today and target (+${esc(r.growth)} %)</small></h4>${table(["Quantity", "Today", "Target", "Largest single device"], sizing)}
          <h4>Features in use <small>number of devices</small></h4><div class="sz-feats">${feats || '<span class="sz-faint">No feature objects were found.</span>'}</div>
          <h4>Licences and entitlements</h4>${table(["Brand", "Licence", "State", "Devices", "Ends"], lic, { empty: "No licence output in these captures. See the checklist below." })}
          ${gaps.length ? `<h4>Missing in the captures</h4>${list2(gaps)}` : ""}
          <h4>Collect before the design is final</h4>${list2(g.inputs)}
          <h4>Vendor documentation</h4>${links(g.links)}
        </div></details>`;
    }).join("");
  }

  function candidateBlock(p) {
    const lib = state.library.filter((c) => !c.device_type || c.device_type === p.device_type);
    const pick = state.pick[p.key] || {};
    const opts = (sel) => `<option value="">Choose...</option>` + lib.map((c, i) => `<option value="${i}" ${String(sel) === String(i) ? "selected" : ""}>${esc(c.name)}${c.vendor ? " (" + esc(c.vendor) + ")" : ""}</option>`).join("");
    const cmp = state.cmp[p.key];
    const cmpHtml = cmp ? `<p class="sz-result-line">${cmp.a.units ?? "n/a"} unit(s) of <b>${esc(cmp.names[0])}</b> (limited by ${esc(cmp.a.limited_by || "n/a")}) against ${cmp.b.units ?? "n/a"} unit(s) of <b>${esc(cmp.names[1])}</b> (limited by ${esc(cmp.b.limited_by || "n/a")}).${cmp.fewer_units ? ` <b>${esc(cmp.fewer_units)}</b> needs fewer units.` : cmp.same_units ? " The same number of units." : ""}</p>` + table(["Quantity", "Target", `${cmp.names[0]}: per unit`, "Units", "Full at target", `${cmp.names[1]}: per unit`, "Units", "Full at target"], cmp.rows.map((x) => [esc(x.label), num(x.target), x.a.per_unit ?? "", x.a.units_needed ?? "", x.a.used_pct !== null && x.a.used_pct !== undefined ? x.a.used_pct + " %" : "", x.b.per_unit ?? "", x.b.units_needed ?? "", x.b.used_pct !== null && x.b.used_pct !== undefined ? x.b.used_pct + " %" : ""]), { empty: "" }) : "";
    return `<details class="sz-cand" data-keep="cand:${esc(p.key)}" ${state.open.has("cand:" + p.key) ? "open" : ""}><summary>Candidate models: save the per-unit values above, or compare two</summary>
      <div class="sz-buttons"><input class="sz-text" type="text" maxlength="60" placeholder="Name of this candidate (for example a model name)" data-cand-name="${esc(p.key)}" aria-label="Name of the candidate to save">
      <button type="button" class="an-btn" data-act="cand-save" data-group="${esc(p.key)}">Save the values above as a candidate</button></div>
      <div class="sz-buttons"><label>A <select class="sz-text" data-cand-pick="a" data-group="${esc(p.key)}">${opts(pick.a)}</select></label> <label>B <select class="sz-text" data-cand-pick="b" data-group="${esc(p.key)}">${opts(pick.b)}</select></label>
      <button type="button" class="an-btn" data-act="cand-compare" data-group="${esc(p.key)}">Compare side by side</button>
      <button type="button" class="an-btn" data-act="cand-apply" data-group="${esc(p.key)}" title="Copy the capacity of candidate A into the per-unit column">Use A in the plan</button></div>${cmpHtml}</details>`;
  }
  function libraryBlock() {
    const list = state.library.map((c, i) => `<li><b>${esc(c.name)}</b>${c.vendor ? " &middot; " + esc(c.vendor) : ""}${c.device_type ? " &middot; " + esc(c.device_type) : ""}: ${Object.entries(c.capacity).map(([k, v]) => `${esc(k)} ${num(v)}`).join(", ")} <button type="button" class="an-btn sz-mini" data-act="cand-remove" data-index="${i}" aria-label="Remove ${esc(c.name)} from the library">Remove</button></li>`).join("");
    return `<details class="sz-cand" data-keep="library" ${state.open.has("library") ? "open" : ""}><summary>Candidate library (${num(state.library.length)})</summary><p class="an-hint">The tool ships no product list. Candidates are the models you type from a datasheet; they are kept in this browser and can be exported to a file and imported into another project.</p>
      <div class="sz-buttons"><button type="button" class="an-btn" data-act="lib-export">Export the library</button><label class="an-btn">Import a library file<input type="file" accept=".json" data-lib-import hidden></label></div>${list ? `<ul class="sz-list">${list}</ul>` : ""}</details>`;
  }
  function planTab(r) {
    const o = state.data.options || {};
    const blocks = r.plan.map((p) => {
      if (p.device_type === "access_point") return `<div class="sz-plan"><h4>${esc(p.label)}</h4><p class="an-hint">${num(p.units_today)} access points are bought by model: see the Bill of materials. Wi-Fi standard, radios and count come from a survey.</p></div>`;
      const rows = p.rows.filter((x) => x.scales || x.kind === "peak").map((x) => {
        const value = (state.profiles[p.key] || {})[x.label] ?? x.per_unit ?? "";
        return [esc(x.label) + (x.kind === "peak" ? " " + tag("peak", "peak") : ""), num(x.today), `<b>${num(x.target)}</b>`,
          `<input class="sz-text sz-small" type="number" min="0" step="any" data-profile="${esc(p.key)}" data-label="${esc(x.label)}" value="${esc(value)}" aria-label="Capacity of one unit for ${esc(x.label)} in ${esc(p.label)}">`,
          x.usable_per_unit !== null && x.usable_per_unit !== undefined ? num(x.usable_per_unit) : "", x.units_needed !== null && x.units_needed !== undefined ? `<b>${num(x.units_needed)}</b>` : ""];
      });
      const result = p.final_units !== null && p.final_units !== undefined
        ? `<p class="sz-result-line"><strong>${num(p.final_units)}</strong> replacement ${p.final_units === 1 ? "unit" : "units"} (today ${num(p.units_today)}). ${esc(p.formula)}</p>`
        : !rows.length ? `<p class="an-hint">These captures hold no quantity that adds up (for example a show-only capture without the port table). See Evidence for what each device lacks, and the Capture pack for the commands.</p>`
        : `<p class="an-hint">Type the capacity of one unit of the model you consider (from its datasheet) in the Per-unit column; the highest quantity decides how many units are needed.</p>`;
      const sb = p.sizing_basis;
      const basis = sb ? `<div class="sz-basis"><p><strong>Size on: ${esc(sb.title)}</strong>${sb.datasheet ? ` &mdash; datasheet column <em>${esc(sb.datasheet)}</em>` : ""}. ${(sb.why || []).map(esc).join(" ")}</p>${sb.level ? `<p class="an-hint">Peak figure to enter: <code>${esc(sb.label)}</code>${sb.has_figure ? " (present)" : " (not entered yet)"}${sb.unknown_devices ? `; ${num(sb.unknown_devices)} firewall(s) of this group did not show their profiles in the capture` : ""}.</p>` : ""}</div>` : "";
      return `<div class="sz-plan"><h4>${esc(p.label)} <small>${num(p.units_today)} today</small></h4>${result}${basis}${candidateBlock(p)}${table(["Quantity", "Today", "Target", "Capacity of one unit", "Usable (after spare)", "Units needed"], rows, { empty: "No quantity to size." })}</div>`;
    }).join("");
    const libraryHtml = libraryBlock();
    const lm = r.licence_models.map((m) => `<li><span class="sz-pill">${esc(m.vendor)}</span> ${esc(m.note)} ${m.url ? `<a href="${esc(m.url)}" target="_blank" rel="noopener noreferrer">${esc(m.title)}</a>` : ""}</li>`).join("");
    return `<p class="an-hint">Replacement units = target &divide; (capacity of one unit &times; (1 &minus; spare %)), the highest quantity decides; ${o.redundancy === "n+1" ? "one unit is added for N+1" : o.redundancy === "2n" ? "every unit is doubled (2N)" : "no redundancy is added"}. The tool keeps no product list: you type the per-unit capacity from the datasheet (links in Gaps and inputs), so the plan never goes stale. Change a value, then press Enter or leave the field.</p>${blocks}
      ${libraryHtml}
      <h4>How the licences move to the new devices</h4><ul class="sz-list">${lm}</ul>`;
  }

  function bomTab(r) {
    return `<p class="an-hint">Every component the captures list, added up across devices. A part number is what the device reports; a blank one means the device did not print it (a third-party optic). The CSV download adds a column for the replacement part number.</p>` + table(["Category", "Brand", "Part number", "Description", "Qty", "On devices", "Types"], r.bom.map((b) => [esc(b.category), esc(b.vendor), `<code>${esc(b.part)}</code>`, esc(b.description), num(b.qty), num(b.devices), esc(b.types.map(typeName).join(", "))]));
  }
  function licencesTab(r) {
    return licencesBase(r) + tiersBlock(r);
  }
  function licencesBase(r) {
    const lm = r.lifecycle.length ? `<h4>Lifecycle (from your imported list)</h4>${table(["Device", "Model", "End of sale", "End of support", "Replacement"], r.lifecycle.map((l) => [esc(l.hostname), esc(l.device_model), esc(l.end_of_sale), esc(l.end_of_support), esc(l.replacement)]))}` : `<p class="an-hint">The tool keeps no end-of-sale dates (they change). Import the vendor's lifecycle table in the Imports tab, or open the lifecycle pages in Gaps and inputs.</p>`;
    return `<p class="an-hint">What the captures and your imports hold. A device without licence output is listed under Gaps and inputs: its entitlement must come from the vendor portal (Cisco Smart Account, Palo Alto Customer Support Portal, FortiCare, MyF5, Aruba Central, Huawei ESDP); import that export in the Imports tab.</p>` + table(["Brand", "Licence / entitlement", "State", "Devices", "Ends", "Types"], r.licences.map((l) => [esc(l.vendor), esc(l.name), esc(l.state), `<span title="${esc(l.devices.join(", "))}">${num(l.count)}</span>`, esc(l.expires.join(", ")), esc(l.types.map(typeName).join(", "))]), { empty: "No licence output in these captures." }) + lm;
  }
  function tiersBlock(r) {
    const tiers = r.tiers || [], windows = r.coterm || [];
    const certainty = (c) => (c === "stated" ? tag("stated by the vendor page", "ok") : tag("confirm for the chosen model", "warn"));
    const t = tiers.length ? `<h4>Licence tier the replacement needs</h4><p class="an-hint">From the features each device uses today. "Stated" means the vendor's own page says so; "confirm" means the vendor gates the feature by platform or release, so check it for the model you choose.</p>` + table(["Brand", "Feature in use", "Evidence", "The replacement needs", "Certainty", "Devices", "Vendor page"], tiers.map((x) => [esc(x.vendor), esc(x.feature), esc((x.evidence_samples || []).join("; ")), `${esc(x.needs)}${x.why ? `<div class="an-hint">${esc(x.why)}</div>` : ""}`, certainty(x.certainty), num(x.count), x.url ? `<a href="${esc(x.url)}" target="_blank" rel="noopener noreferrer">open</a>` : ""])) : "";
    const w = windows.length ? `<h4>Renewal windows (co-term)</h4><p class="an-hint">Licences whose end dates are within four months of each other are one window. Ask the vendor for one co-term date per window (the latest date) instead of one renewal per device.</p>` + table(["From", "To", "Co-term date", "Licences", "Devices", "Brands", "Examples"], windows.map((x) => [esc(x.from), esc(x.to), `<b>${esc(x.coterm)}</b>${x.expired ? " " + tag("already expired", "bad") : ""}`, num(x.licences), num(x.devices), esc(x.vendors.join(", ")), esc(x.samples.join("; "))])) : "";
    return t + w;
  }
  function expiryTab(r) {
    const ex = r.expiry, top = Math.max(1, ...ex.timeline.map((t) => t.count));
    const bar = (n) => "█".repeat(Math.round((n / top) * 24));
    const statusTag = (i) => (i.state === "expired" ? tag("expired", "bad") : i.state === "soon" ? tag(`within ${ex.months} months`, "warn") : tag("later", "ok"));
    return `<div class="sz-cards sz-cards-small"><div class="sz-card"><strong>${num(ex.expired)}</strong><span>expired</span></div><div class="sz-card"><strong>${num(ex.soon)}</strong><span>ending within ${num(ex.months)} months</span></div><div class="sz-card"><strong>${num(ex.dated)}</strong><span>with an end date</span></div><div class="sz-card"><strong>${num(ex.undated)}</strong><span>without an end date</span></div></div>
      <p class="an-hint">As of ${esc(ex.as_of)}. Dates are shown as YYYY-MM-DD whatever format the vendor printed. A licence with no end date (perpetual, or the capture does not print it) is not in this list; import the portal export to add them.</p>
      <h4>Licences ending, month by month</h4>${table(["Month", "", "Licences"], ex.timeline.map((t) => [esc(t.month), `<span class="sz-bar" aria-hidden="true">${bar(t.count)}</span>`, num(t.count)]), { empty: "" })}
      ${ex.beyond_timeline ? `<p class="an-hint">${num(ex.beyond_timeline)} more end after the last month shown.</p>` : ""}
      <h4>Every licence with an end date</h4>${table(["Device", "Brand", "Licence", "Ends", "Days left", "Status", "From"], ex.items.map((i) => [esc(i.hostname), esc(i.vendor), esc(i.licence), esc(i.expires), num(i.days_left), statusTag(i), i.source === "csv" ? tag("import", "entered") : "capture"]), { empty: "No licence in the data has an end date." })}`;
  }
  function peaksTab(r) {
    const pk = r.peaks, fields = state.data.peak_fields || {};
    const summary = table(["Type", "Figure", "Unit", "Devices", "Sum", "Largest single device", "From"], pk.rows.map((x) => [esc(typeName(x.device_type)), esc(x.label), esc(x.unit), num(x.devices), x.adds_up ? num(x.sum) : `<span class="sz-faint">does not add up</span>`, num(x.max), esc(x.sources.join(", "))]), { empty: "No peak figures yet. Type them below, import a CSV, or capture tmsh show sys performance all-stats on F5." });
    const blocks = Object.entries(fields).map(([dtype, labels]) => {
      const mine = allAssets().filter((a) => a.device_type === dtype && !a.duplicate_of);
      if (!mine.length) return "";
      const rows = mine.map((a) => [`<b>${esc(a.hostname || a.source)}</b>`, ...labels.map((label) => {
        const manual = (state.peaks[a.id] || {})[label], held = (a.peaks || {})[label];
        const value = manual !== undefined ? manual : held ? held.value : "";
        return `<input class="sz-text sz-small" type="number" min="0" step="any" data-peak="${esc(a.id)}" data-label="${esc(label)}" value="${esc(value)}" aria-label="${esc(label)} of ${esc(a.hostname)}">${held && manual === undefined ? " " + (sourceTag(held.source) || tag("capture", "ok")) : ""}`;
      })]);
      return `<h4>${esc(typeName(dtype))}: peak figures per device <small>from monitoring over a full business cycle; a typed value replaces a captured one</small></h4>${table(["Device", ...labels], rows)}`;
    }).join("");
    return `<p class="an-hint">A configuration never holds throughput or sessions. Peak figures come from the unit's statistics (F5: tmsh show sys performance all-stats, read here), from monitoring, or from your CSV. They enter the replacement plan when they add up (throughput, sessions).</p>${summary}${pk.missing_total ? `<p class="an-hint"><b>${num(pk.missing_total)}</b> firewall, load balancer or router ${pk.missing_total === 1 ? "has" : "have"} no peak figure yet.</p>` : ""}${blocks}<div class="sz-buttons"><button type="button" class="an-btn primary" data-act="apply-peaks">Recalculate with these peaks</button></div>`;
  }
  function featuresTab(r) {
    const types = Object.keys(state.data.type_labels || {});
    const used = types.filter((t) => r.features.some((f) => f.by_type[t]));
    return table(["Group", "Feature", "Devices", "Objects", ...used.map(typeName)], r.features.map((f) => [esc(f.group), esc(f.name), num(f.devices), f.objects ? num(f.objects) : "", ...used.map((t) => (f.by_type[t] ? num(f.by_type[t]) : ""))]), { empty: "No feature was found." });
  }
  function devicesTab() {
    const rows = allAssets().map((a) => {
      const o = state.overrides[a.id] || {};
      const typeOptions = Object.entries(state.data.type_labels).map(([k, v]) => `<option value="${esc(k)}" ${k === (o.device_type || a.device_type) ? "selected" : ""}>${esc(v)}</option>`).join("");
      const dup = a.duplicate_of ? `<div>${tag("same serial as " + a.duplicate_of, "warn")}</div><label class="sz-x"><input type="checkbox" data-edit="keep_duplicate" data-id="${esc(a.id)}" ${o.keep_duplicate ? "checked" : ""}><span>Count it anyway</span></label>` : "";
      return [`<b>${esc(a.hostname || a.source)}</b>${dup}`, `<select class="sz-text sz-small" data-edit="device_type" data-id="${esc(a.id)}" aria-label="Device type of ${esc(a.hostname)}">${typeOptions}</select>`, esc(a.tier), esc(a.vendor), esc(a.model), `<code>${esc(a.serial)}</code>`, esc(a.os),
        `<input class="sz-text sz-small" data-edit="site" data-id="${esc(a.id)}" value="${esc(o.site ?? a.site)}" maxlength="40" aria-label="Site of ${esc(a.hostname)}">`, esc(a.ha), a.notes.length ? `<span title="${esc(a.notes.join(" | "))}">${a.notes.length}</span>` : "",
        `<label class="sz-x"><input type="checkbox" data-edit="exclude" data-id="${esc(a.id)}" ${o.exclude ? "checked" : ""} aria-label="Leave ${esc(a.hostname)} out"><span>Leave out</span></label>`];
    });
    return `<p class="an-hint">Change a device type or site, or leave a device out (a duplicate, a lab box), then press Recalculate. Nothing is read again. A capture with the serial number of another one is counted once; tick Count it anyway if it is a different device.</p>` + `<div class="sz-devices">${table(["Hostname", "Type", "Tier", "Brand", "Model", "Serial", "Software", "Site", "Redundancy", "Notes", ""], rows, { filter: true })}</div>`;
  }
  function evidenceTab(r) {
    const conf = r.confidence, assets = state.data.assets, id = state.evidenceId && assets.some((a) => a.id === state.evidenceId) ? state.evidenceId : (assets[0] || {}).id;
    state.evidenceId = id;
    const rows = ((state.data.evidence || {})[id] || []).map((e) => [esc(e.label), e.kind === "peak" ? tag("peak", "peak") : "", num(e.value), esc(e.from), tag(e.confidence, e.confidence === "high" ? "ok" : e.confidence === "low" ? "bad" : e.confidence === "entered" ? "entered" : "warn")]);
    const a = assets.find((x) => x.id === id) || { notes: [] };
    return `<p class="an-hint">Where every number comes from and how far to trust it. <b>High</b>: printed by the device or counted in its configuration. <b>Medium</b>: right but a moment in time or from a partial table. <b>Low</b>: the capture lacks the command that would answer it. <b>Entered</b>: typed or imported by you.</p>
      <div class="sz-cards sz-cards-small"><div class="sz-card"><strong>${num(conf.high || 0)}</strong><span>high</span></div><div class="sz-card"><strong>${num(conf.medium || 0)}</strong><span>medium</span></div><div class="sz-card"><strong>${num(conf.low || 0)}</strong><span>low</span></div><div class="sz-card"><strong>${num(conf.entered || 0)}</strong><span>entered</span></div></div>
      <label class="an-field sz-pick"><span class="an-label">Device</span><select class="sz-text" data-pick="evidence">${assets.map((x) => `<option value="${esc(x.id)}" ${x.id === id ? "selected" : ""}>${esc(x.hostname || x.source)} (${esc(typeName(x.device_type))})</option>`).join("")}</select></label>
      ${table(["Quantity", "", "Value", "Where it comes from", "Confidence"], rows, { empty: "Nothing recorded for this device." })}
      ${a.notes.length ? `<h4>What the capture did not hold</h4>${list2(a.notes)}` : ""}`;
  }
  function sitesTab(r) {
    const used = Object.keys(state.data.type_labels).filter((t) => r.sites.some((s) => s.by_type[t]));
    return `<p class="an-hint">The site is the leading word(s) of the hostname (JKT-SW1 is JKT), unless you imported a site map (Imports tab) or changed it in the Devices tab. Building and floor come from the site map.</p>` + table(["Site", "Devices", ...used.map(typeName), "Buildings", "Floors", "Physical ports", "Ports in use", "PoE (W)", "Access points"], r.sites.map((s) => [esc(s.site), num(s.total), ...used.map((t) => (s.by_type[t] ? num(s.by_type[t]) : "")), esc(s.buildings.join(", ")), esc(s.floors.join(", ")), num(s.capacity["Physical ports"] || ""), num(s.capacity["Ports in use (link up)"] || ""), num(s.capacity["PoE power (W)"] || ""), num(s.capacity["Access points"] || "")]));
  }

  const IMPORTS = {
    site_map: { title: "Site map", help: "Hostname (or serial) to site, building and floor. Replaces the site guessed from the hostname.", columns: "Hostname, Site, Building, Floor" },
    peaks: { title: "Peak figures", help: "One row per device (hostname or serial); every other numeric column is a peak figure, and the unit is read from the header (Gbps, Mbps, %, sessions).", columns: "Hostname, Peak throughput (Gbps), Concurrent sessions, CPU %" },
    entitlements: { title: "Licence entitlements", help: "A portal export: Cisco Smart Account or SNTC, FortiCare, Aruba Central / HPE GreenLake, Palo Alto Customer Support Portal. Columns are found by their names; dates are normalised.", columns: "Serial Number, Subscription / Licence / Contract, Start Date, End Date, Quantity, Status" },
    lifecycle: { title: "Lifecycle table", help: "The vendor's end-of-sale and end-of-support dates for the models in use, copied from the vendor's page (links in Gaps and inputs). The tool keeps no such dates itself.", columns: "Model (or Product ID), End of sale, End of support, Replacement" },
  };
  function importsTab() {
    const reports = state.data.imports_report || {};
    return `<p class="an-hint">Bring what the captures cannot hold. Column order does not matter: each column is matched by its name, and the answer says which column was used for which field and how many rows matched a device (by serial, then hostname).</p>` + Object.entries(IMPORTS).map(([kind, d]) => {
      const rep = reports[kind];
      const detail = rep ? `<div class="sz-report"><b>${num(rep.matched)}</b> of ${num(rep.rows)} rows matched a device${rep.unmatched ? `; ${num(rep.unmatched)} did not (for example ${esc(rep.unmatched_examples.join(", "))})` : ""}. Columns used: ${esc(Object.entries(rep.columns).map(([f, h]) => `${h} → ${f}`).join("; "))}.${rep.ignored_columns.length ? ` Ignored: ${esc(rep.ignored_columns.join(", "))}.` : ""}${rep.ambiguous_dates ? ` ${num(rep.ambiguous_dates)} dates like 06/12/2026 were read day first.` : ""}</div>` : "";
      return `<div class="sz-import"><h4>${esc(d.title)}</h4><p class="an-hint">${esc(d.help)}</p><p class="an-hint">Typical columns: <code>${esc(d.columns)}</code></p>
        <div class="sz-buttons"><label class="an-btn">Choose a CSV file<input type="file" accept=".csv,.tsv,.txt" data-import="${esc(kind)}" hidden></label>${kind === "site_map" ? `<button type="button" class="an-btn" data-act="site-template">Download a template with these hostnames</button>` : ""}${rep ? `<button type="button" class="an-btn" data-act="clear-import" data-kind="${esc(kind)}">Remove this import</button>` : ""}</div>${detail}</div>`;
    }).join("");
  }
  function compareTab() {
    const cmp = state.compare;
    const runs = state.runs.filter((x) => x.run_id !== state.runId).map((x) => `<option value="${esc(x.run_id)}">${esc(x.name)} (${num(x.devices)} devices, ${esc(x.saved)})</option>`).join("");
    const out = cmp ? `<h4>${esc(cmp.before_name)} &rarr; ${esc(cmp.after_name)}</h4><div class="sz-cards sz-cards-small"><div class="sz-card"><strong>${num(cmp.before)}</strong><span>devices before</span></div><div class="sz-card"><strong>${num(cmp.after)}</strong><span>devices now</span></div><div class="sz-card"><strong>${num(cmp.added.length)}</strong><span>added</span></div><div class="sz-card"><strong>${num(cmp.removed.length)}</strong><span>removed</span></div><div class="sz-card"><strong>${num(cmp.changed.length)}</strong><span>changed</span></div><div class="sz-card"><strong>${num(cmp.unchanged)}</strong><span>unchanged</span></div></div>
      <h4>Added</h4>${table(["Device", "Type", "Brand", "Model", "Site"], cmp.added.map((d) => [esc(d.hostname), esc(typeName(d.type)), esc(d.vendor), esc(d.model), esc(d.site)]), { empty: "No device was added." })}
      <h4>Removed</h4>${table(["Device", "Type", "Brand", "Model", "Site"], cmp.removed.map((d) => [esc(d.hostname), esc(typeName(d.type)), esc(d.vendor), esc(d.model), esc(d.site)]), { empty: "No device was removed." })}
      <h4>Changed</h4>${table(["Device", "What", "Before", "Now"], cmp.changed.flatMap((c) => c.diffs.map((d) => [esc(c.hostname), esc(d.field), esc(d.before), esc(d.after)])), { empty: "No device changed." })}
      <h4>Quantities that moved</h4>${table(["Quantity", "Before", "Now", "Change"], cmp.totals.map((t) => [esc(t.label), num(t.before), num(t.after), `${t.delta > 0 ? "+" : ""}${num(t.delta)}`]), { empty: "No quantity moved." })}` : "";
    return `<p class="an-hint">Compare this run with an earlier one (before and after a refresh, or last quarter and now). Devices are matched by serial number, else by hostname.</p>
      <div class="sz-compare"><label class="an-field"><span class="an-label">An earlier run still kept on this computer</span><select class="sz-text" data-role-compare="run"><option value="">Choose a run...</option>${runs}</select></label>
      <div class="sz-buttons"><button type="button" class="an-btn primary" data-act="compare-run">Compare with this run</button><label class="an-btn">Compare with a saved project file<input type="file" accept=".json" data-compare-file hidden></label></div></div>${out}`;
  }
  function gapsTab(r) {
    const skipped = (state.data.skipped || []).map((s) => [esc(s.file), esc(s.reason)]);
    const blocks = r.groups.map((g) => `<h4>${esc(g.label)}: collect before sizing</h4>${list2(g.inputs)}`).join("");
    return `<h4>Missing in the captures</h4>${table(["What is missing", "Devices", "Hostnames"], r.gaps.map((g) => [esc(g.note), num(g.count), esc(g.devices.slice(0, 12).join(", ") + (g.devices.length > 12 ? ", ..." : ""))]), { empty: "Nothing is missing." })}
      ${skipped.length ? `<h4>Files skipped</h4>${table(["File", "Reason"], skipped)}` : ""}${blocks}<h4>Vendor documentation</h4>${links(r.links)}
      <h4>Capture pack</h4><p class="an-hint">The short list of commands per platform that fills these gaps. <a href="${esc(api)}/api/capture-pack.txt" download>Download the capture pack (.txt)</a>.</p>`;
  }

  const TABS = { types: typesTab, plan: planTab, bom: bomTab, licences: licencesTab, expiry: expiryTab, peaks: peaksTab, features: featuresTab, devices: devicesTab, evidence: evidenceTab, sites: sitesTab, imports: importsTab, compare: compareTab, gaps: gapsTab };
  function renderTab() {
    const r = state.data.rollup;
    $("panel").innerHTML = TABS[state.tab](r);
    root.querySelectorAll('[data-role="tabs"] [role="tab"]').forEach((b) => { const on = b.dataset.tab === state.tab; b.setAttribute("aria-selected", String(on)); b.tabIndex = on ? 0 : -1; });
  }
  $("tabs").addEventListener("click", async (e) => {
    const button = e.target.closest("[data-tab]");
    if (!button || !state.data) return;
    state.tab = button.dataset.tab;
    if (state.tab === "compare") { try { state.runs = (await (await fetch(`${api}/api/runs`, { cache: "no-store" })).json()).runs || []; } catch (error) { state.runs = []; } }
    renderTab();
  });
  $("tabs").addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight"].includes(e.key)) return;
    const tabs = [...root.querySelectorAll('[data-role="tabs"] [role="tab"]')];
    const next = tabs[(tabs.findIndex((b) => b.dataset.tab === state.tab) + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    next.focus(); next.click();
  });

  // ---- edits in the panels ----------------------------------------------------------------------------------------------------------------------
  $("panel").addEventListener("toggle", (e) => { const keep = e.target.dataset && e.target.dataset.keep; if (keep) { if (e.target.open) state.open.add(keep); else state.open.delete(keep); } }, true);
  $("panel").addEventListener("change", async (e) => {
    const t = e.target;
    const edit = t.closest("[data-edit]");
    if (edit) {
      const id = edit.dataset.id, o = (state.overrides[id] = state.overrides[id] || {});
      if (edit.dataset.edit === "exclude" || edit.dataset.edit === "keep_duplicate") o[edit.dataset.edit] = edit.checked; else o[edit.dataset.edit] = edit.value;
      const asset = allAssets().find((a) => a.id === id);
      if (asset && o.device_type === asset.device_type) delete o.device_type;
      if (asset && o.site === asset.site) delete o.site;
      if (o.exclude === false) delete o.exclude;
      if (o.keep_duplicate === false) delete o.keep_duplicate;
      if (!Object.keys(o).length) delete state.overrides[id];
      $("recalc").hidden = !Object.keys(state.overrides).length;
      return;
    }
    if (t.dataset.profile !== undefined) {
      const key = t.dataset.profile, label = t.dataset.label, v = parseFloat(t.value);
      state.profiles[key] = state.profiles[key] || {};
      if (Number.isFinite(v) && v > 0) state.profiles[key][label] = v; else delete state.profiles[key][label];
      recalc();
      return;
    }
    if (t.dataset.peak !== undefined) {
      const id = t.dataset.peak, label = t.dataset.label, v = parseFloat(t.value);
      state.peaks[id] = state.peaks[id] || {};
      if (Number.isFinite(v) && v >= 0) state.peaks[id][label] = v; else delete state.peaks[id][label];
      if (!Object.keys(state.peaks[id]).length) delete state.peaks[id];
      return;
    }
    if (t.dataset.candPick) { const g = t.dataset.group; state.pick[g] = { ...(state.pick[g] || {}), [t.dataset.candPick]: t.value }; return; }
    if (t.matches("[data-lib-import]") && t.files[0]) {
      const body = new FormData(); body.append("file", t.files[0], t.files[0].name); t.value = "";
      try {
        const payload = await post("/api/candidates/import", body);
        const have = new Set(state.library.map((c) => `${c.name.toLowerCase()}|${c.device_type}`));
        const added = payload.library.filter((c) => !have.has(`${c.name.toLowerCase()}|${c.device_type}`));
        state.library = state.library.concat(added); saveLibrary(); renderTab();
        setStatus(`Imported ${plural(added.length, "candidate")} (${plural(payload.library.length - added.length, "candidate")} already in the library).`);
      } catch (error) { setStatus(error.message, true); }
      return;
    }
    if (t.dataset.pick === "evidence") { state.evidenceId = t.value; renderTab(); return; }
    if (t.dataset.import) { await importCsv(t.dataset.import, t.files[0]); t.value = ""; return; }
    if (t.matches("[data-compare-file]") && t.files[0]) { await runCompare({ project: t.files[0] }); t.value = ""; }
  });
  $("panel").addEventListener("click", async (e) => {
    const act = e.target.closest("[data-act]");
    if (!act) return;
    const kind = act.dataset.act;
    try {
      if (kind === "cand-save") {
        const g = act.dataset.group, input = root.querySelector(`[data-cand-name="${CSS.escape(g)}"]`), name = (input ? input.value : "").trim();
        const capacity = state.profiles[g] || {};
        if (!name) { setStatus("Give the candidate a name first.", true); return; }
        if (!Object.keys(capacity).length) { setStatus("Type the capacity of one unit in the per-unit column first.", true); return; }
        const vendor = ((state.data.rollup.plan.find((p) => p.key === g) || {}).vendors || [])[0] || "";
        state.library = state.library.filter((c) => !(c.name.toLowerCase() === name.toLowerCase() && c.device_type === g.split("|")[0]));
        state.library.push({ name, vendor: "", device_type: g.split("|")[0], capacity: { ...capacity }, note: "", source: "" }); saveLibrary(); renderTab();
        setStatus(`Saved ${name} in the candidate library.`);
      } else if (kind === "cand-remove") { state.library.splice(parseInt(act.dataset.index, 10), 1); saveLibrary(); renderTab(); }
      else if (kind === "lib-export") await download("/api/candidates/export", { library: state.library }, "keystone-candidates.json", "The candidate library");
      else if (kind === "cand-apply") {
        const g = act.dataset.group, list = state.library.filter((c) => !c.device_type || c.device_type === g.split("|")[0]), c = list[parseInt((state.pick[g] || {}).a, 10)];
        if (!c) { setStatus("Choose candidate A first.", true); return; }
        state.profiles[g] = { ...c.capacity }; await recalc();
      } else if (kind === "cand-compare") {
        const g = act.dataset.group, list = state.library.filter((c) => !c.device_type || c.device_type === g.split("|")[0]), pick = state.pick[g] || {};
        const a = list[parseInt(pick.a, 10)], b = list[parseInt(pick.b, 10)];
        if (!a || !b) { setStatus("Choose two candidates to compare.", true); return; }
        const payload = await post("/api/candidates/compare", { run_id: state.runId, options: options(), group: g, candidates: [a, b] });
        state.cmp[g] = payload.comparison; renderTab(); setStatus("Compared the two candidates.");
      }
      else if (kind === "apply-peaks") await recalc();
      else if (kind === "clear-import") { state.data = { ...(await post("/api/import/clear", { run_id: state.runId, kind: act.dataset.kind, options: options() })) }; show(state.data); }
      else if (kind === "compare-run") { const id = root.querySelector("[data-role-compare]").value; if (!id) { setStatus("Choose an earlier run first.", true); return; } await runCompare({ other_run_id: id }); }
      else if (kind === "site-template") {
        const csv = "Hostname,Site,Building,Floor\r\n" + allAssets().map((a) => `"${String(a.hostname || a.source).replace(/"/g, '""')}","${String(a.site || "").replace(/"/g, '""')}","",""`).join("\r\n") + "\r\n";
        const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" })), link = document.createElement("a");
        link.href = url; link.download = "site-map-template.csv"; document.body.appendChild(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
      }
    } catch (error) { setStatus(error.message, true); }
  });

  async function importCsv(kind, file) {
    if (!file || !state.runId) return;
    const body = new FormData();
    body.append("run_id", state.runId); body.append("kind", kind); body.append("file", file, file.name); body.append("options", JSON.stringify(options()));
    setStatus(`Reading ${file.name}...`);
    try {
      const payload = await post("/api/import", body);
      show(payload);
      setStatus(`${IMPORTS[kind].title}: ${payload.report.matched} of ${payload.report.rows} rows matched a device.`);
    } catch (error) { setStatus(error.message, true); }
  }
  async function runCompare(extra) {
    const body = new FormData();
    body.append("run_id", state.runId); body.append("options", JSON.stringify(options()));
    Object.entries(extra).forEach(([k, v]) => body.append(k, v));
    setStatus("Comparing...");
    try { state.compare = await post("/api/compare", body); setStatus("Compared."); renderTab(); } catch (error) { setStatus(error.message, true); }
  }

  async function recalc() {
    if (!state.runId) return;
    setStatus("Recalculating...");
    try {
      const payload = await post("/api/rollup", { run_id: state.runId, options: options() });
      show(payload);
      setStatus(`Recalculated for ${plural(payload.assets.length, "device")}.`);
    } catch (error) {
      setStatus(error.message, true);
    }
  }
  $("recalc").addEventListener("click", recalc);
  let timer = 0;
  const later = () => { if (!state.runId) return; clearTimeout(timer); timer = setTimeout(recalc, 450); };
  ["growth", "spare", "months"].forEach((r) => $(r).addEventListener("input", later));
  ["redundancy", "basis"].forEach((r) => $(r).addEventListener("change", later));

  $("export").addEventListener("click", async () => { if (state.runId) try { await download("/api/export", { run_id: state.runId, options: options() }, "keystone-sizing.xlsx", "The workbook"); } catch (error) { setStatus(error.message, true); } });
  $("summary").addEventListener("click", async () => { if (state.runId) try { await download("/api/summary", { run_id: state.runId, options: options() }, "keystone-sizing-summary.html", "The one-page summary"); } catch (error) { setStatus(error.message, true); } });
  $("export-bom").addEventListener("click", async () => { if (state.runId) try { await download("/api/export-bom", { run_id: state.runId, options: options() }, "keystone-sizing-bom.csv", "The bill of materials"); } catch (error) { setStatus(error.message, true); } });
  $("save-project").addEventListener("click", async () => { if (state.runId) try { await download("/api/project/save", { run_id: state.runId, options: options() }, "keystone.sizing.json", "The project file"); } catch (error) { setStatus(error.message, true); } });

  // more captures into the open run; a saved project reopened
  $("add-more").addEventListener("click", () => $("add-input").click());
  $("add-input").addEventListener("change", async () => {
    const files = [...$("add-input").files]; $("add-input").value = "";
    if (!files.length || !state.runId) return;
    const body = new FormData();
    body.append("run_id", state.runId); body.append("options", JSON.stringify(options()));
    files.forEach((f) => body.append("files", f, f.name));
    setStatus("Adding the captures...");
    try {
      const payload = await post("/api/add", body);
      show(payload);
      setStatus(`Added ${plural(payload.added, "device")}; the run now holds ${plural(payload.all_assets.length, "device")}.`);
    } catch (error) { setStatus(error.message, true); }
  });
  $("open-project").addEventListener("click", () => $("project-input").click());
  $("project-input").addEventListener("change", async () => {
    const file = $("project-input").files[0]; $("project-input").value = "";
    if (!file) return;
    const body = new FormData(); body.append("file", file, file.name);
    setStatus("Opening the project...");
    try {
      const payload = await post("/api/project/open", body);
      const o = payload.options || {};
      state.runId = payload.run_id; state.overrides = o.overrides || {}; state.profiles = o.profiles || {}; state.peaks = o.manual_peaks || {}; state.compare = null;
      $("name").value = payload.name || ""; $("growth").value = o.growth ?? $("growth").value;
      show(payload);
      setStatus(`Opened ${plural(payload.all_assets.length, "device")} from the project file.`);
    } catch (error) { setStatus(error.message, true); }
  });
})();
