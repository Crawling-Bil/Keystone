// Topology Builder: "Topology history". Every build kept on this computer: details, download, rename, note, pin, compare, runbook, delete; search, filter and sort.
// Talks to /topology/api/history (list, details, pin, rename, note, delete, clear). Comparing and the runbook are handed to the two panels below
// through the events "tp:compare", "tp:runbook" and "tp:open" (Open again); "tp:built" (sent by topology.js after a build) refreshes the count on the button.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root || root.dataset.historyReady) return;
  root.dataset.historyReady = "1";
  const $ = (role) => root.querySelector(`[data-role="${role}"]`);
  const api = root.dataset.api;
  const dialog = $("history-dialog"), openButton = $("history-open"), badge = $("history-count");
  if (!dialog || !openButton) return;
  const list = $("history-list"), statusLine = $("history-status"), search = $("history-search"), compareButton = $("history-compare");
  const sortBox = $("history-sort"), filterBox = $("history-filter");
  const clearBox = $("history-clear-box"), foot = $("history-foot"), rule = $("history-rule");

  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;
  const size = (bytes) => {
    const n = Number(bytes) || 0;
    if (n >= 1048576) return `${(n / 1048576).toFixed(1)} MB`;
    if (n >= 1024) return `${Math.round(n / 1024)} KB`;
    return `${n} B`;
  };
  const ago = (seconds) => {                       // "2 hours ago": easier to find the run you just built than a date
    const s = Math.max(0, Date.now() / 1000 - Number(seconds));
    if (!Number(seconds) || s >= 14 * 86400) return "";
    if (s < 90) return "just now";
    if (s < 3600) return plural(Math.round(s / 60), "minute") + " ago";
    if (s < 86400) return plural(Math.round(s / 3600), "hour") + " ago";
    return plural(Math.round(s / 86400), "day") + " ago";
  };
  const say = (text, error) => { statusLine.textContent = text || ""; statusLine.classList.toggle("error", !!error); };

  let runs = [], info = { keep: 20, max_age_days: 30, max_pinned: 30, pinned: 0, total_size: 0 };
  let selected = [];                 // run ids ticked for the comparison (at most two)
  let opened = new Set();            // run ids whose details are open
  let details = new Map();           // id -> details payload
  let editing = null;                // id being renamed
  let noting = null;                 // id whose note is being edited
  let asking = null;                 // id waiting for the delete confirmation
  let askingClear = false;

  async function call(path, options) {
    let response, payload = null;
    try {
      response = await fetch(`${api}${path}`, { cache: "no-store", ...(options || {}) });
      try { payload = await response.json(); } catch (err) { payload = null; }
    } catch (err) {
      return { ok: false, error: "The connection to Keystone was lost. Is it still running?" };
    }
    if (!payload) return { ok: false, error: `Keystone answered with an error (HTTP ${response.status}).` };
    return payload;
  }
  const post = (path, body) => call(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });

  async function load() {
    const payload = await call("/api/history");
    if (!payload.ok) { say(payload.error || "The history could not be read.", true); return false; }
    runs = payload.runs || [];
    info = { keep: payload.keep, max_age_days: payload.max_age_days, max_pinned: payload.max_pinned, pinned: payload.pinned, total_size: payload.total_size };
    selected = selected.filter((id) => runs.some((r) => r.id === id));
    opened = new Set([...opened].filter((id) => runs.some((r) => r.id === id)));
    paintBadge();
    return true;
  }

  function paintBadge() {
    badge.textContent = String(runs.length);
    badge.hidden = runs.length === 0;
    openButton.setAttribute("aria-label", `Topology history, ${plural(runs.length, "run")} kept`);
  }

  // Search looks at the name, the note, the date and the view; the filter narrows the list; the sort never moves the baseline mark (it stays on the run that has it).
  const FILTERS = {
    all: () => true,
    pinned: (r) => r.pinned,
    unpinned: (r) => !r.pinned,
    medium: (r) => r.findings_medium > 0,
    noted: (r) => !!r.note,
  };
  const SORTS = {
    newest: (a, b) => (b.built_seconds || 0) - (a.built_seconds || 0),
    oldest: (a, b) => (a.built_seconds || 0) - (b.built_seconds || 0),
    name: (a, b) => (a.name || "~").toLowerCase().localeCompare((b.name || "~").toLowerCase()) || (b.built_seconds || 0) - (a.built_seconds || 0),
    findings: (a, b) => (b.findings_medium - a.findings_medium) || (b.findings - a.findings) || (b.built_seconds || 0) - (a.built_seconds || 0),
    devices: (a, b) => (b.devices - a.devices) || (b.built_seconds || 0) - (a.built_seconds || 0),
  };

  function visibleRuns() {
    const needle = search.value.trim().toLowerCase();
    const keep = FILTERS[filterBox.value] || FILTERS.all;
    const order = SORTS[sortBox.value] || SORTS.newest;
    return runs.filter((r) => keep(r) && (!needle || `${r.name} ${r.note || ""} ${r.built} ${r.view}`.toLowerCase().includes(needle))).sort(order);
  }

  // Every action rebuilds the list; remember which control had the keyboard focus and give it back afterwards.
  function focusMark() {
    const el = document.activeElement;
    if (!el || !list.contains(el)) return null;
    const li = el.closest("li[data-id]");
    const back = { "delete-no": "delete", "rename-cancel": "rename" };   // a cancelled question returns to the button that asked it
    return li && el.dataset.act ? { id: li.dataset.id, act: back[el.dataset.act] || el.dataset.act } : null;
  }

  function restoreFocus(mark) {
    if (!mark) return;
    const li = Array.from(list.querySelectorAll("li[data-id]")).find((item) => item.dataset.id === mark.id);
    const control = li && Array.from(li.querySelectorAll("[data-act]")).find((item) => item.dataset.act === mark.act && !item.disabled);
    if (control) control.focus();
  }

  function render() {
    const mark = focusMark();
    rule.textContent = `Keystone keeps the newest ${info.keep} topologies for ${info.max_age_days} days. Pin one to keep it until you delete it (up to ${info.max_pinned}); the newest pinned one is your baseline, and every new build says what changed since. Everything stays on this computer.`;
    const shown = visibleRuns();
    if (!runs.length) {
      list.innerHTML = `<li class="tp-history-empty">No topology kept yet. Build one and it appears here.</li>`;
    } else if (!shown.length) {
      list.innerHTML = `<li class="tp-history-empty">Nothing matches the search and the filter.</li>`;
    } else {
      list.innerHTML = shown.map(card).join("");
    }
    compareButton.textContent = `Compare selected (${selected.length} of 2)`;
    compareButton.disabled = selected.length !== 2;
    const unpinned = runs.filter((r) => !r.pinned).length;
    clearBox.innerHTML = askingClear
      ? `<span class="tp-confirm" role="alert">Delete ${plural(unpinned, "unpinned run")}?</span> <button type="button" class="an-btn small danger" data-act="clear-yes">Delete</button> <button type="button" class="an-btn small" data-act="clear-no">Keep</button>`
      : `<button type="button" class="an-btn small" data-act="clear" ${unpinned ? "" : "disabled"}>Delete all unpinned</button>`;
    foot.textContent = `${plural(runs.length, "run")} kept (${info.pinned} pinned), ${size(info.total_size)} on disk.` + (shown.length !== runs.length ? ` Showing ${shown.length}.` : "");
    restoreFocus(mark);
  }

  function card(run) {
    const open = opened.has(run.id);
    const title = run.name || "Unnamed topology";
    const meta = [run.built + (ago(run.built_seconds) ? ` (${ago(run.built_seconds)})` : ""), plural(run.devices, "device"), plural(run.links, "link"), plural(run.findings, "finding"), size(run.size)].join(" · ");
    const keep = run.baseline ? "Baseline: kept until you delete it; every new build is compared with it" : run.pinned ? "Pinned: kept until you delete it" : (run.expires ? `Kept until ${run.expires} at the latest` : "");
    const tick = selected.includes(run.id);
    const full = selected.length >= 2 && !tick;
    const titleHtml = editing === run.id
      ? `<form class="tp-run-rename" data-act="rename-form"><input class="tp-text" type="text" maxlength="60" value="${esc(run.name)}" aria-label="New name" data-role="rename-input" autocomplete="off"><button type="submit" class="an-btn small primary">Save</button><button type="button" class="an-btn small" data-act="rename-cancel">Cancel</button></form>`
      : `<strong class="tp-run-name">${esc(title)}</strong>${run.baseline ? `<span class="an-badge tp-pin-badge" title="Every new build is compared with this run">Baseline</span>` : (run.pinned ? `<span class="an-badge tp-pin-badge">Pinned</span>` : "")}${run.anonymized ? `<span class="an-badge">Anonymized copy</span>` : ""}`;
    const noteHtml = noting === run.id
      ? `<form class="tp-run-note-form" data-act="note-form"><label class="an-hint" for="tp-note-${esc(run.id)}">Note (up to 300 characters, kept only on this computer)</label><textarea class="tp-text" id="tp-note-${esc(run.id)}" rows="2" maxlength="300" data-role="note-input" placeholder="Why was this built? For example: before the change window">${esc(run.note)}</textarea><div class="an-actions"><button type="submit" class="an-btn small primary">Save note</button><button type="button" class="an-btn small" data-act="note-cancel">Cancel</button></div></form>`
      : (run.note ? `<p class="tp-run-note">${esc(run.note)}</p>` : "");
    const actions = asking === run.id
      ? `<span class="tp-confirm" role="alert">Delete this run?</span><button type="button" class="an-btn small danger" data-act="delete-yes">Delete</button><button type="button" class="an-btn small" data-act="delete-no">Keep</button>`
      : (run.has_result ? `<button type="button" class="an-btn small primary" data-act="open" title="Show this topology again, with its diagrams and tables, without building it again">Open again</button>` : "")
        + (run.has_pack ? `<a class="an-btn small${run.has_result ? "" : " primary"}" href="${esc(api)}/api/export/${esc(run.id)}/keystone-topology-pack.zip" download title="The documentation pack: draw.io, workbook, tables and report in one ZIP">Download pack</a>` : "")
        + `<button type="button" class="an-btn small" data-act="details" aria-expanded="${open}">${open ? "Hide details" : "Details"}</button>`
        + `<button type="button" class="an-btn small" data-act="pin" aria-pressed="${run.pinned}">${run.pinned ? "Unpin" : "Pin"}</button>`
        + `<button type="button" class="an-btn small" data-act="rename">Rename</button>`
        + `<button type="button" class="an-btn small" data-act="note">${run.note ? "Edit note" : "Add note"}</button>`
        + `<button type="button" class="an-btn small" data-act="delete">Delete</button>`;
    return `<li class="tp-run${run.pinned ? " pinned" : ""}" data-id="${esc(run.id)}">
      <div class="tp-run-main">
        <label class="tp-run-pick" title="${full ? "Two runs are already selected" : "Select for comparison"}"><input type="checkbox" data-act="pick" ${tick ? "checked" : ""} ${full ? "disabled" : ""} aria-label="Select ${esc(title)} for comparison"></label>
        <div class="tp-run-text"><div class="tp-run-title">${titleHtml}</div><div class="tp-run-meta">${esc(meta)}</div>${keep ? `<div class="tp-run-keep">${esc(keep)}</div>` : ""}</div>
      </div>
      ${noteHtml}
      <div class="tp-run-actions">${actions}</div>
      ${open ? `<div class="tp-run-detail" data-role="detail">${detailHtml(details.get(run.id))}</div>` : ""}
    </li>`;
  }

  function detailHtml(d) {
    if (!d) return `<p class="an-hint">Reading the details ...</p>`;
    if (d.error) return `<p class="an-hint error">${esc(d.error)}</p>`;
    const cards = [[d.captured, "captured devices"], [d.devices, "devices drawn"], [d.links, "links"], [d.hosts, "hosts"], [d.findings_by_severity.medium, "medium findings"], [d.findings_by_severity.low, "low findings"], [d.findings_by_severity.info, "notes"]];
    const kinds = (obj) => Object.entries(obj || {}).map(([k, n]) => `${esc(k)} ${esc(n)}`).join(" · ") || "-";
    const options = Object.entries(d.options || {}).map(([k, v]) => `${esc(k.replace(/_/g, " "))}: ${esc(typeof v === "boolean" ? (v ? "yes" : "no") : v)}`).join(" · ");
    const top = (d.top_findings || []).map((f) => `<li><span class="an-badge">${esc(f.severity || "info")}</span> ${esc(f.title)}</li>`).join("");
    const files = (d.files || []).map((f) => `<li><a href="${esc(f.url)}" download="${esc(f.filename)}">${esc(f.label)}</a> <span class="muted-copy">${esc(size(f.size))}</span></li>`).join("");
    const index = runs.findIndex((r) => r.id === d.id);
    const older = index >= 0 ? runs[index + 1] : null;
    const baseline = runs.find((r) => r.baseline && r.id !== d.id);
    return `<div class="tp-cards">${cards.map(([n, label]) => `<div class="tp-card"><strong>${esc(n)}</strong><span>${esc(label)}</span></div>`).join("")}</div>
      <p class="tp-run-line"><strong>Vendors</strong> ${kinds(d.vendors)}</p>
      <p class="tp-run-line"><strong>Roles</strong> ${kinds(d.roles)}</p>
      ${d.pack_sha256 ? `<p class="tp-run-line"><strong>Pack SHA-256</strong> <code class="tp-hash" title="Write this in your change record: it proves the pack was not changed afterwards">${esc(d.pack_sha256)}</code></p>` : ""}
      ${options ? `<p class="tp-run-line"><strong>Build options</strong> ${options}</p>` : ""}
      ${top ? `<div class="tp-run-block"><strong>Findings</strong><ul class="tp-run-list">${top}</ul>${d.findings > (d.top_findings || []).length ? `<p class="an-hint">The first ${(d.top_findings || []).length} of ${esc(d.findings)}; the full list is in the report and findings.csv.</p>` : ""}</div>` : ""}
      <div class="tp-run-block"><strong>Download</strong><ul class="tp-run-list files">${files || "<li class=\"an-hint\">The files of this run were removed.</li>"}</ul></div>
      <div class="an-actions">
        <button type="button" class="an-btn small" data-act="runbook">Cutover runbook from this run</button>
        ${baseline ? `<button type="button" class="an-btn small" data-act="compare-baseline" data-baseline="${esc(baseline.id)}" title="${esc(baseline.name || "Unnamed topology")}, built ${esc(baseline.built)}">Compare with the baseline</button>` : ""}
        ${older ? `<button type="button" class="an-btn small" data-act="compare-previous" data-older="${esc(older.id)}">Compare with the run before (${esc(older.built)})</button>` : ""}
      </div>`;
  }

  async function refresh(keepStatus) {
    const ok = await load();
    if (ok) { if (!keepStatus) say(""); render(); }
  }

  async function showDetails(id) {
    if (details.has(id) && !details.get(id).error) { render(); return; }
    const payload = await call(`/api/history/${id}`);
    details.set(id, payload.ok ? payload.run : { error: payload.error || "The details could not be read." });
    if (!payload.ok && payload.error && payload.error.includes("no longer")) {          // deleted behind the page's back: show what is really there
      details.delete(id); say(payload.error, true); await refresh(true); return;
    }
    render();
  }

  list.addEventListener("click", async (event) => {
    const target = event.target.closest("[data-act]");
    if (!target) return;
    const li = target.closest("li[data-id]");
    const id = li ? li.dataset.id : null;
    const act = target.dataset.act;
    if (act === "pick") {
      selected = target.checked ? [...selected, id].slice(0, 2) : selected.filter((x) => x !== id);
      render(); return;
    }
    if (act === "details") {
      if (opened.has(id)) { opened.delete(id); render(); } else { opened.add(id); render(); await showDetails(id); }
      return;
    }
    if (act === "pin") {
      const run = runs.find((r) => r.id === id);
      const result = await post(`/api/history/${id}/pin`, { pinned: !run.pinned });
      if (!result.ok) { say(result.error || "The run could not be changed.", true); if (result.error && result.error.includes("no longer")) await refresh(true); return; }
      details.delete(id);
      await refresh(); say(result.pinned ? "Pinned: this run stays until you delete it." : "Unpinned: the normal clean-up applies again.");
      if (opened.has(id)) await showDetails(id);
      return;
    }
    if (act === "note") { noting = id; editing = null; asking = null; render(); const area = list.querySelector('[data-role="note-input"]'); if (area) { area.focus(); area.setSelectionRange(area.value.length, area.value.length); } return; }
    if (act === "note-cancel") { noting = null; render(); return; }
    if (act === "rename") { editing = id; noting = null; asking = null; render(); const input = list.querySelector('[data-role="rename-input"]'); if (input) { input.focus(); input.select(); } return; }
    if (act === "rename-cancel") { editing = null; render(); return; }
    if (act === "delete") { asking = id; editing = null; noting = null; render(); const yes = list.querySelector('[data-act="delete-yes"]'); if (yes) yes.focus(); return; }
    if (act === "delete-no") { asking = null; render(); return; }
    if (act === "delete-yes") {
      const result = await call(`/api/history/${id}`, { method: "DELETE" });
      asking = null; details.delete(id); selected = selected.filter((x) => x !== id);
      if (!result.ok && !(result.error || "").includes("no longer")) { say(result.error || "The run could not be deleted.", true); render(); return; }
      await refresh(); say("The run was deleted.");
      return;
    }
    if (act === "open") {
      close();
      root.dispatchEvent(new CustomEvent("tp:open", { detail: { id } }));
      return;
    }
    if (act === "runbook") {
      close();
      root.dispatchEvent(new CustomEvent("tp:runbook", { detail: { id } }));
      return;
    }
    if (act === "compare-baseline") {
      close();
      root.dispatchEvent(new CustomEvent("tp:compare", { detail: { before: target.dataset.baseline, after: id } }));
      return;
    }
    if (act === "compare-previous") {
      close();
      root.dispatchEvent(new CustomEvent("tp:compare", { detail: { before: target.dataset.older, after: id } }));
    }
  });

  list.addEventListener("submit", async (event) => {
    const noteForm = event.target.closest('[data-act="note-form"]');
    if (noteForm) {
      event.preventDefault();
      const noteId = noteForm.closest("li[data-id]").dataset.id;
      const saved = await post(`/api/history/${noteId}/note`, { note: noteForm.querySelector("textarea").value });
      if (!saved.ok) { say(saved.error || "The note could not be saved.", true); return; }
      noting = null;
      await refresh(); say(saved.note ? "Note saved." : "The note was removed.");
      return;
    }
    const formEl = event.target.closest('[data-act="rename-form"]');
    if (!formEl) return;
    event.preventDefault();
    const id = formEl.closest("li[data-id]").dataset.id;
    const result = await post(`/api/history/${id}/rename`, { name: formEl.querySelector("input").value });
    if (!result.ok) { say(result.error || "The run could not be renamed.", true); return; }
    editing = null; details.delete(id);
    await refresh(); say(result.name ? `Renamed to ${result.name}.` : "The name was removed.");
    if (opened.has(id)) await showDetails(id);
  });

  clearBox.addEventListener("click", async (event) => {
    const act = event.target.closest("[data-act]")?.dataset.act;
    if (!act) return;
    if (act === "clear") { askingClear = true; render(); const yes = clearBox.querySelector('[data-act="clear-yes"]'); if (yes) yes.focus(); return; }
    if (act === "clear-no") { askingClear = false; render(); return; }
    if (act === "clear-yes") {
      askingClear = false;
      const result = await post("/api/history/clear", {});
      details = new Map();
      await refresh(); say(result.ok ? `${plural(result.removed, "run")} deleted. Pinned runs were kept.` : (result.error || "The history could not be cleared."), !result.ok);
    }
  });

  compareButton.addEventListener("click", () => {
    if (selected.length !== 2) return;
    const [a, b] = selected.map((id) => runs.find((r) => r.id === id));
    const [before, after] = (a.built_seconds || 0) <= (b.built_seconds || 0) ? [a, b] : [b, a];     // the older run is "before"
    close();
    root.dispatchEvent(new CustomEvent("tp:compare", { detail: { before: before.id, after: after.id } }));
  });

  search.addEventListener("input", render);
  sortBox.addEventListener("change", () => { try { localStorage.setItem("tp-history-sort", sortBox.value); } catch (err) { /* a private window: the choice is not kept */ } render(); });
  filterBox.addEventListener("change", render);
  try { const saved = localStorage.getItem("tp-history-sort"); if (saved && SORTS[saved]) sortBox.value = saved; } catch (err) { /* no storage: the default order */ }
  dialog.addEventListener("cancel", (event) => {            // Esc closes the panel, except while a name or note is being typed or a question is open
    if (editing || noting || asking || askingClear) { event.preventDefault(); editing = null; noting = null; asking = null; askingClear = false; render(); }
  });
  dialog.addEventListener("click", (event) => { if (event.target === dialog) close(); });          // a click on the dark area closes it
  $("history-close").addEventListener("click", close);

  function close() { if (dialog.open) dialog.close(); }
  async function open() {
    say("Reading the history ...");
    if (typeof dialog.showModal === "function") { if (!dialog.open) dialog.showModal(); } else dialog.setAttribute("open", "");
    editing = null; noting = null; asking = null; askingClear = false; details = new Map();
    if (await load()) { say(""); render(); for (const id of opened) showDetails(id); }
  }
  openButton.addEventListener("click", open);
  root.addEventListener("tp:built", () => { refresh(true); });
  refresh(true).then(() => { /* the count on the button */ });
})();
