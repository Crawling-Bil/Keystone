(() => {
  const root = document.querySelector(".tp-page");
  if (!root || root.dataset.ready) return;
  root.dataset.ready = "1";
  const $ = (role) => root.querySelector(`[data-role="${role}"]`);
  const api = root.dataset.api;
  const maxFiles = Number(root.dataset.maxFiles || 100);
  const form = $("form"), input = $("file-input"), list = $("file-list"), drop = $("drop");
  const button = $("build"), status = $("status"), result = $("result"), empty = $("empty");
  let files = [], data = null, activePage = 0, activeView = "physical";

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const setStatus = (text, error) => { status.textContent = text || ""; status.classList.toggle("error", !!error); };
  const canBuild = () => files.length > 0 || !!$("previous-state").files[0];

  function renderFiles() {
    list.innerHTML = files.map((f, i) => `<li><span>${esc(f.name)}</span><small>${Math.max(1, Math.round(f.size / 1024))} KB</small><button type="button" class="an-btn small" data-remove="${i}" aria-label="Remove ${esc(f.name)}">Remove</button></li>`).join("");
    list.classList.toggle("hidden", !files.length);
    button.disabled = !canBuild();
  }
  function addFiles(incoming) {
    const known = new Set(files.map((f) => f.name + f.size));
    for (const f of incoming) if (!known.has(f.name + f.size)) files.push(f);
    if (files.length > maxFiles) { files = files.slice(0, maxFiles); setStatus(`Only the first ${maxFiles} files are used.`, true); }
    renderFiles();
  }
  input.addEventListener("change", () => { addFiles([...input.files]); input.value = ""; });
  $("previous-state").addEventListener("change", renderFiles);
  // a file chosen in the styled pickers shows its name; options that make no sense with "exclude end points" step aside
  ["previous-state", "previous"].forEach((role) => {
    const picker = $(role), label = $(role + "-name");
    const show = () => { const f = picker.files[0]; label.textContent = f ? f.name : "No file chosen"; picker.closest(".tp-file").classList.toggle("has-file", !!f); };
    picker.addEventListener("change", show); picker.showName = show;
  });
  const syncDeps = () => root.querySelectorAll("[data-dep]").forEach((row) => {
    const needs = row.dataset.dep.split(" ");
    row.hidden = (needs.includes("no-exclude") && $("exclude-endpoints").checked) || (needs.includes("no-collapse") && $("collapse").checked);
  });
  $("exclude-endpoints").addEventListener("change", syncDeps); $("collapse").addEventListener("change", syncDeps); syncDeps();
  list.addEventListener("click", (e) => { const i = e.target.closest("[data-remove]"); if (i) { files.splice(Number(i.dataset.remove), 1); renderFiles(); } });
  ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.remove("dragover"); }));
  drop.addEventListener("drop", (e) => addFiles([...e.dataTransfer.files]));
  $("clear").addEventListener("click", () => { files = []; data = null; $("previous-state").value = ""; $("previous").value = ""; $("previous-state").showName(); $("previous").showName(); renderFiles(); result.classList.add("hidden"); empty.classList.remove("hidden"); setStatus(""); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!canBuild()) return;
    const body = new FormData();
    files.forEach((f) => body.append("files", f, f.name));
    body.append("name", $("name").value.trim());
    body.append("group", $("group").value);
    body.append("collapse_endpoints", $("collapse").checked ? "1" : "0");
    body.append("collapse_aps", $("collapse-ap").checked ? "1" : "0");
    body.append("exclude_endpoints", $("exclude-endpoints").checked ? "1" : "0");
    body.append("group_endpoints", $("group-endpoints").checked ? "1" : "0");
    body.append("show_ports", $("ports").checked ? "1" : "0");
    body.append("include_routed", $("routed").checked ? "1" : "0");
    body.append("show_link_ips", $("link-ips").checked ? "1" : "0");
    body.append("infer_neighbors", $("infer").checked ? "1" : "0");
    body.append("include_hosts", $("hosts").checked ? "1" : "0");
    body.append("hide_mgmt", $("mgmt").checked ? "1" : "0");
    body.append("view", $("view").value);
    body.append("provider_hints", $("provider-hints").value);
    body.append("overlay_sites", $("overlay-sites").value);
    body.append("focus_sites", $("focus-sites").value);
    body.append("group_l3", $("group-l3").checked ? "1" : "0");
    body.append("line_style", $("line-style").value);
    body.append("line_shape", $("line-shape").value);
    const previous = $("previous").files[0];
    if (previous) body.append("previous", previous, previous.name);
    const saved = $("previous-state").files[0];
    if (saved) body.append("previous_state", saved, saved.name);
    button.disabled = true;
    setStatus(files.length ? `Reading ${files.length} capture(s)... this takes about one second per device.` : "Rebuilding from the previous run...");
    let response;
    try {
      response = await fetch(`${api}/api/build`, { method: "POST", body });
    } catch (err) {
      setStatus("Keystone did not answer. Check that its terminal window is still open, then try again.", true);
      button.disabled = !canBuild();
      return;
    }
    try {
      let payload;
      try { payload = await response.json(); } catch (err) { payload = null; }
      if (!payload) { setStatus(`Keystone answered with an error (HTTP ${response.status}). See the Keystone terminal window for details.`, true); return; }
      if (!response.ok || !payload.ok) { setStatus(payload.error || "The topology could not be built.", true); return; }
      data = payload; activePage = 0; activeView = startView($("view").value); render(); setStatus("");
    } catch (err) {
      setStatus(`The result could not be shown (${err && err.message ? err.message : err}). Please report this message.`, true);
    } finally { button.disabled = !canBuild(); }
  });

  function render() {
    const s = data.summary;
    const cards = [["captured", "Devices captured"], ["seen_only", "Seen by neighbors only"], ["links", "Links"], ["confirmed", "Confirmed both ends"],
      ["single_sided", "One end only"], ["conflicts", "Conflicts"], ["vpc_pairs", "vPC pairs"], ["routed", "Routed links inferred"], ["hosts", "Hosts in MAC tables"],
      ["behind_macs", "Of which behind uncaptured devices"], ["findings", "Findings"]];
    if (s.layout_kept) cards.push(["layout_kept", "Devices kept in place"]);
    if (s.carried) cards.push(["carried", "Devices from the previous run"]);
    if (s.replaced) cards.push(["replaced", "Replaced by new captures"]);
    $("cards").innerHTML = cards.map(([k, label]) => `<div class="tp-card"><strong>${esc(s[k])}</strong><span>${label}</span></div>`).join("");
    $("downloads").innerHTML = data.downloads.map((d, i) => `<a class="an-btn small${i === 0 ? " primary" : ""}" href="${esc(d.url)}" download="${esc(d.filename || d.name)}">${esc(d.filename || d.name)}</a>`).join("");
    $("findings-count").textContent = data.findings.length;
    renderPages(); renderFindings();
    renderTable("l3links", data.l3_links); renderTable("l3routes", data.l3_routes); renderTable("l3overlay", data.l3_overlay); renderSites();
    [["l3links", "l3_links"], ["l3routes", "l3_routes"], ["l3overlay", "l3_overlay"]].forEach(([t, k]) => $("tab-" + t).classList.toggle("hidden", !(data[k] || []).length));
    $("howto").innerHTML = data.howto || "";
    $("trace-source").innerHTML = ((data.trace && data.trace.devices) || []).map((d) => `<option value="${esc(d.key)}">${esc(d.name)}</option>`).join("");
    clearTrace();
    $("l3-detail").classList.add("hidden");
    renderTable("links", data.links); renderTable("bundles", data.bundles); renderTable("hosts-table", data.hosts); renderTable("behind", data.behind); renderTable("devices", data.devices);
    result.classList.remove("hidden"); empty.classList.add("hidden");
    switchTab("diagram");
    if (data.skipped.length) setStatus(`${data.skipped.length} file(s) skipped: ` + data.skipped.map((x) => `${x.file} (${x.reason})`).join("; "), true);
  }
  // the view shown first: the one chosen in the form; "all views" opens the first of L3 over L2, L3 route, then the L2 pictures
  function startView(choice) {
    const has = (v) => data.pages.some((p) => p.view === v);
    if (choice === "all") return has("l3over2") ? "l3over2" : has("l3route") ? "l3route" : has("physical") ? "physical" : data.pages[0].view;
    if (["ip", "l3route", "l3over2", "f5map"].includes(choice) && has(choice)) return choice;
    return has("logical") && choice !== "physical" ? "logical" : "physical";
  }
  function visiblePages() { return data.pages.map((p, i) => ({ ...p, index: i })).filter((p) => p.view === activeView); }
  function renderPages() {
    const views = [["l3over2", "L3 over L2"], ["l3route", "L3 route view"], ["ip", "IP view"], ["physical", "Physical view"], ["logical", "vPC view"], ["f5map", "F5 map"]].filter(([v]) => data.pages.some((p) => p.view === v));
    $("viewbar").innerHTML = views.length > 1 ? views.map(([v, label]) =>
      `<button type="button" class="an-btn small${v === activeView ? " primary" : ""}" data-view="${v}" aria-pressed="${v === activeView}">${label}</button>`).join("") : "";
    let shown = visiblePages();
    if (!shown.length) { activeView = data.pages[0].view; shown = visiblePages(); }
    if (!shown.some((p) => p.index === activePage)) activePage = shown[0].index;
    $("pagebar").innerHTML = shown.length > 1 ? shown.map((p) => `<button type="button" class="an-btn small${p.index === activePage ? " primary" : ""}" data-page="${p.index}">${esc(p.name)}</button>`).join("") : "";
    $("canvas").innerHTML = data.pages[activePage].svg;
    $("trace").classList.toggle("hidden", !(activeView === "l3route" || activeView === "l3over2") || !((data.trace && data.trace.devices) || []).length);
    clearTrace();
    applyZoom();
    const rows = (data.legend && data.legend[activeView]) || [];
    $("legend").innerHTML = rows.map(([colour, text]) => `<li><i style="background:${esc(colour)}"></i>${esc(text)}</li>`).join("");
  }
  // Zoom, pan and a full-window copy of the diagram: a 60-device network is unreadable inside a 900 px frame.
  let zoom = 100;
  const canvas = $("canvas");
  canvas.insertAdjacentHTML("beforebegin", `<div class="tp-zoom" role="group" aria-label="Diagram zoom"><button type="button" class="an-btn small" data-zoom="out" aria-label="Zoom out">-</button><span data-role="zoom-level" aria-live="polite">100%</span><button type="button" class="an-btn small" data-zoom="in" aria-label="Zoom in">+</button><button type="button" class="an-btn small" data-zoom="fit">Fit width</button><button type="button" class="an-btn small" data-zoom="open">Open in new tab</button><span class="an-hint">Ctrl + wheel zooms, drag to move.</span></div>`);
  function applyZoom() {
    const svg = canvas.querySelector("svg");
    if (svg) { svg.style.width = zoom + "%"; svg.style.minWidth = zoom > 100 ? "0" : ""; }
    const label = root.querySelector("[data-role=zoom-level]");
    if (label) label.textContent = zoom + "%";
  }
  function setZoom(value) { zoom = Math.max(25, Math.min(800, Math.round(value))); applyZoom(); }
  function openCopy() {
    const svg = data.pages[activePage].svg;
    const page = `<!doctype html><meta charset="utf-8"><title>${esc(data.pages[activePage].name)}</title><body style="margin:0;background:#fff">${svg}</body>`;
    const url = URL.createObjectURL(new Blob([page], { type: "text/html" }));
    window.open(url, "_blank", "noopener");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  }
  root.addEventListener("click", (e) => {
    const b = e.target.closest("[data-zoom]"); if (!b) return;
    if (b.dataset.zoom === "in") setZoom(zoom * 1.25);
    else if (b.dataset.zoom === "out") setZoom(zoom / 1.25);
    else if (b.dataset.zoom === "fit") setZoom(100);
    else openCopy();
  });
  canvas.addEventListener("wheel", (e) => { if (e.ctrlKey) { e.preventDefault(); setZoom(zoom * (e.deltaY < 0 ? 1.1 : 1 / 1.1)); } }, { passive: false });
  let drag = null;
  canvas.addEventListener("pointerdown", (e) => { if (e.button === 0) { drag = { x: e.clientX, y: e.clientY, left: canvas.scrollLeft, top: canvas.scrollTop }; canvas.classList.add("dragging"); } });
  window.addEventListener("pointermove", (e) => { if (drag) { canvas.scrollLeft = drag.left - (e.clientX - drag.x); canvas.scrollTop = drag.top - (e.clientY - drag.y); } });
  window.addEventListener("pointerup", () => { drag = null; canvas.classList.remove("dragging"); });
  $("pagebar").addEventListener("click", (e) => { const b = e.target.closest("[data-page]"); if (b) { activePage = Number(b.dataset.page); renderPages(); } });
  $("viewbar").addEventListener("click", (e) => { const b = e.target.closest("[data-view]"); if (b) { activeView = b.dataset.view; renderPages(); } });
  function renderFindings() {
    const tone = { medium: "var(--orange, #ED7D31)", low: "var(--blue)", info: "var(--muted)" };
    const byDevice = data.findings_by_device || [];
    const rollup = byDevice.length ? `<h4>Findings by device</h4><div class="tp-scroll"><table class="tp-table"><thead><tr><th>Device</th><th>Captured</th><th>Medium</th><th>Low</th><th>Info</th><th>Findings</th></tr></thead><tbody>${byDevice.map((r) => `<tr><td>${esc(r.device)}</td><td>${esc(r.captured)}</td><td>${esc(r.medium)}</td><td>${esc(r.low)}</td><td>${esc(r.info)}</td><td>${esc(r.findings)}</td></tr>`).join("")}</tbody></table></div><h4>All findings</h4>` : "";
    $("findings").innerHTML = rollup + (data.findings.length ? data.findings.map((f) => `<div class="tp-finding"><h4><span class="an-pill" style="--tone:${tone[f.severity] || "var(--muted)"}">${esc(f.severity)}</span> ${esc(f.id)} · ${esc(f.title)}</h4><p>${esc(f.detail)}</p><p><strong>Next step:</strong> ${esc(f.recommendation)}${f.reference ? ` <a href="${esc(f.reference)}" target="_blank" rel="noopener noreferrer">Reference</a>` : ""}</p></div>`).join("") : "<p class='an-hint'>No findings.</p>");
  }
  function renderTable(role, rows) {
    if (!rows || !rows.length) { $(role).innerHTML = "<p class='an-hint'>Nothing to show.</p>"; return; }
    const cols = [...new Set(rows.flatMap((r) => Object.keys(r)))];
    $(role).innerHTML = `<div class="tp-scroll"><table class="tp-table"><thead><tr>${cols.map((c) => `<th>${esc(c.replace(/_/g, " "))}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${cols.map((c) => `<td>${esc(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }
  function switchTab(name) {
    root.querySelectorAll("[data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
    root.querySelectorAll("[data-panel]").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== name));
  }
  // SD-WAN site picker: every remote site of the BFD tables with a tick box; ticked sites are typed into the list and the page is built again.
  const ticked = new Set();
  function renderSites() {
    const box = $("l3sites"), rows = data.l3_sites || [];
    if (!rows.length) { box.innerHTML = ""; return; }
    const drawn = rows.filter((r) => r.on_the_picture === "yes").length;
    box.innerHTML = `<h3>Remote sites in the BFD tables <span class="an-badge">${rows.length}</span></h3>
      <p class="an-hint">${drawn} of ${rows.length} sites are drawn now. Tick the sites you want to see and press <em>Draw the ticked sites</em>; the page is built again from the same captures. Sites you captured are listed first.</p>
      <div class="tp-sites-bar"><input class="tp-text" type="search" data-role="site-filter" placeholder="Filter by site ID, system IP, host or colour" aria-label="Filter sites" autocomplete="off">
      <button type="button" class="an-btn small primary" data-site-action="draw">Draw the ticked sites</button>
      <button type="button" class="an-btn small" data-site-action="captured">Captured sites only</button>
      <button type="button" class="an-btn small" data-site-action="all">Every site</button>
      <button type="button" class="an-btn small" data-site-action="clear">Clear ticks</button> <span class="an-hint" data-role="site-count"></span></div>
      <div class="tp-scroll tp-sites-list" data-role="site-table"></div>`;
    paintSites();
  }
  function paintSites() {
    const filter = (($("l3sites").querySelector("[data-role=site-filter]") || {}).value || "").toLowerCase();
    const rows = (data.l3_sites || []).filter((r) => !filter || Object.values(r).join(" ").toLowerCase().includes(filter));
    const shown = rows.slice(0, 300);
    const table = $("l3sites").querySelector("[data-role=site-table]");
    if (!table) return;
    table.innerHTML = `<table class="tp-table"><thead><tr><th>Draw</th><th>Site ID</th><th>System IP</th><th>Captured as</th><th>Seen by</th><th>Sessions up</th><th>Sessions</th><th>Colours</th><th>On the picture</th></tr></thead><tbody>${shown.map((r) =>
      `<tr><td><input type="checkbox" data-site="${esc(r.system_ip)}" ${ticked.has(r.system_ip) ? "checked" : ""} aria-label="Draw site ${esc(r.site_id)} ${esc(r.system_ip)}"></td><td>${esc(r.site_id)}</td><td>${esc(r.system_ip)}</td><td>${esc(r.captured_as)}</td><td>${esc(r.seen_by)}</td><td>${esc(r.sessions_up)}</td><td>${esc(r.sessions)}</td><td>${esc(r.colours)}</td><td>${esc(r.on_the_picture)}</td></tr>`).join("")}</tbody></table>`;
    countSites(rows.length, shown.length);
  }
  let lastCount = [0, 0];
  function countSites(total, shown) {
    if (total !== undefined) lastCount = [total, shown];
    const [t, n] = lastCount, count = $("l3sites").querySelector("[data-role=site-count]");
    if (count) count.textContent = `${t} match${t === 1 ? "" : "es"}${t > n ? `, first ${n} shown (use the filter)` : ""}; ${ticked.size} ticked`;
  }
  $("l3sites").addEventListener("input", (e) => { if (e.target.matches("[data-role=site-filter]")) paintSites(); });
  $("l3sites").addEventListener("change", (e) => { const c = e.target.closest("[data-site]"); if (c) { c.checked ? ticked.add(c.dataset.site) : ticked.delete(c.dataset.site); countSites(); } });
  $("l3sites").addEventListener("click", (e) => {
    const b = e.target.closest("[data-site-action]"); if (!b) return;
    const act = b.dataset.siteAction;
    if (act === "clear") { ticked.clear(); paintSites(); return; }
    if (act === "draw") { if (!ticked.size) { setStatus("Tick at least one site first.", true); return; } $("focus-sites").value = [...ticked].join("\n"); }
    if (act === "captured") { $("overlay-sites").value = "captured"; $("focus-sites").value = ""; ticked.clear(); }
    if (act === "all") { $("overlay-sites").value = "all"; $("focus-sites").value = ""; ticked.clear(); }
    if (typeof form.requestSubmit === "function") form.requestSubmit(); else form.dispatchEvent(new Event("submit", { cancelable: true }));
  });
  // Path trace: the server walks the routing tables of the build; the lines of the path are highlighted.
  function clearTrace() {
    $("trace-result").classList.add("hidden"); $("trace-result").innerHTML = "";
    canvas.querySelectorAll(".traced").forEach((n) => n.classList.remove("traced"));
  }
  function showTrace(result) {
    const box = $("trace-result");
    canvas.querySelectorAll(".traced").forEach((n) => n.classList.remove("traced"));
    if (!result.ok) { box.innerHTML = `<p>${esc(result.error || "The trace failed.")}</p>`; box.classList.remove("hidden"); return; }
    const wanted = new Set(result.edge_ids || []);
    canvas.querySelectorAll("[data-l3]").forEach((g) => { if ((g.dataset.l3All || g.dataset.l3).split(" ").some((i) => wanted.has(i))) g.classList.add("traced"); });
    box.innerHTML = `<h3>${result.arrived ? "Path found" : "Path stops"}: ${esc(result.message)}</h3><ol>${result.hops.map((h) => `<li><strong>${esc(h.device)}</strong> (VRF ${esc(h.vrf)}): ${esc(h.action)}${h.edges.length ? ` <span class="an-badge">${esc(h.edges.join(", "))}</span>` : ""}</li>`).join("")}</ol><p class="an-hint">Routing intent from the captured routing tables; not measured traffic. Policy routing, ACLs, NAT and SD-WAN data policy are not evaluated.</p>`;
    box.classList.remove("hidden");
  }
  $("trace").addEventListener("submit", async (e) => {
    e.preventDefault();
    const response = await fetch("/topology/api/trace", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ export_id: data.trace.export_id, source: $("trace-source").value, destination: $("trace-dest").value, vrf: $("trace-vrf").value }) });
    let result; try { result = await response.json(); } catch (err) { result = { ok: false, error: "Keystone answered with an error." }; }
    showTrace(result);
  });
  $("trace-clear").addEventListener("click", clearTrace);
  // L3 views: a click (or Enter) on a line explains it: the sentence, the evidence and the routes that use it.
  function showL3(id) {
    const row = (data.l3_links || []).find((r) => r.id === id);
    if (!row) return;
    const routes = (data.l3_routes || []).filter((r) => r.link === id);
    const evidence = row.evidence ? row.evidence.split(" | ").map((t) => `<li>${esc(t)}</li>`).join("") : "";
    const table = routes.length ? `<div class="tp-scroll"><table class="tp-table"><thead><tr><th>Device</th><th>VRF</th><th>Protocol</th><th>Next hop</th><th>Prefixes</th><th>Default</th><th>Prefix list</th></tr></thead><tbody>${routes.map((r) =>
      `<tr><td>${esc(r.device)}</td><td>${esc(r.vrf)}</td><td>${esc(r.protocol)}</td><td>${esc(r.next_hop)}</td><td>${esc(r.prefixes)}</td><td>${esc(r.default_route)}</td><td>${esc(r.prefix_list)}</td></tr>`).join("")}</tbody></table></div>` : "";
    const box = $("l3-detail");
    box.innerHTML = `<h3>${esc(row.id)} · ${esc(row.kind)} · ${esc(row.device_a)} - ${esc(row.device_b)} <span class="an-badge">${esc(row.state)}</span></h3><p>${esc(row.meaning)}</p>${evidence ? `<strong>Evidence in the captures</strong><ul>${evidence}</ul>` : ""}${table}<p class="an-hint">Routing intent from interface state, routing tables and neighbors; not measured traffic.</p>`;
    box.classList.remove("hidden");
  }
  canvas.addEventListener("click", (e) => { const g = e.target.closest("[data-l3]"); if (g) showL3(g.dataset.l3); });
  canvas.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { const g = e.target.closest("[data-l3]"); if (g) { e.preventDefault(); showL3(g.dataset.l3); } } });
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) switchTab(b.dataset.tab); });
})();
