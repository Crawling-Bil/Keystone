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
  const syncDeps = () => root.querySelectorAll('[data-dep="no-exclude"]').forEach((row) => { row.hidden = $("exclude-endpoints").checked; });
  $("exclude-endpoints").addEventListener("change", syncDeps); syncDeps();
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
    body.append("show_ports", $("ports").checked ? "1" : "0");
    body.append("include_routed", $("routed").checked ? "1" : "0");
    body.append("infer_neighbors", $("infer").checked ? "1" : "0");
    body.append("include_hosts", $("hosts").checked ? "1" : "0");
    body.append("hide_mgmt", $("mgmt").checked ? "1" : "0");
    body.append("view", $("view").value);
    body.append("line_style", $("line-style").value);
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
      data = payload; activePage = 0; activeView = $("view").value === "ip" && data.pages.some((p) => p.view === "ip") ? "ip" : data.pages.some((p) => p.view === "logical") ? "logical" : "physical"; render(); setStatus("");
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
    renderTable("links", data.links); renderTable("bundles", data.bundles); renderTable("hosts-table", data.hosts); renderTable("behind", data.behind); renderTable("devices", data.devices);
    result.classList.remove("hidden"); empty.classList.add("hidden");
    switchTab("diagram");
    if (data.skipped.length) setStatus(`${data.skipped.length} file(s) skipped: ` + data.skipped.map((x) => `${x.file} (${x.reason})`).join("; "), true);
  }
  function visiblePages() { return data.pages.map((p, i) => ({ ...p, index: i })).filter((p) => p.view === activeView); }
  function renderPages() {
    const views = [["logical", "vPC view"], ["physical", "Physical view"], ["ip", "IP view"]].filter(([v]) => data.pages.some((p) => p.view === v));
    $("viewbar").innerHTML = views.length > 1 ? views.map(([v, label]) =>
      `<button type="button" class="an-btn small${v === activeView ? " primary" : ""}" data-view="${v}" aria-pressed="${v === activeView}">${label}</button>`).join("") : "";
    let shown = visiblePages();
    if (!shown.length) { activeView = data.pages[0].view; shown = visiblePages(); }
    if (!shown.some((p) => p.index === activePage)) activePage = shown[0].index;
    $("pagebar").innerHTML = shown.length > 1 ? shown.map((p) => `<button type="button" class="an-btn small${p.index === activePage ? " primary" : ""}" data-page="${p.index}">${esc(p.name)}</button>`).join("") : "";
    $("canvas").innerHTML = data.pages[activePage].svg;
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
    $("findings").innerHTML = data.findings.length ? data.findings.map((f) => `<div class="tp-finding"><h4><span class="an-pill" style="--tone:${tone[f.severity] || "var(--muted)"}">${esc(f.severity)}</span> ${esc(f.id)} · ${esc(f.title)}</h4><p>${esc(f.detail)}</p><p><strong>Next step:</strong> ${esc(f.recommendation)}${f.reference ? ` <a href="${esc(f.reference)}" target="_blank" rel="noopener noreferrer">Reference</a>` : ""}</p></div>`).join("") : "<p class='an-hint'>No findings.</p>";
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
  $("tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-tab]"); if (b) switchTab(b.dataset.tab); });
})();
