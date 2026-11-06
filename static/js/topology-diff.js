// Topology Builder: "Compare two runs". Talks to /topology/api/runs and /topology/api/diff.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root) return;
  const box = root.querySelector('[data-role="diff"]');
  if (!box || box.dataset.ready) return;
  box.dataset.ready = "1";
  const $ = (role) => box.querySelector(`[data-role="${role}"]`);
  const api = root.dataset.api;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const form = $("diff-form"), status = $("diff-status"), go = $("diff-go"), csvButton = $("diff-csv");
  const selects = { before: $("diff-before-run"), after: $("diff-after-run") };
  const files = { before: $("diff-before-file"), after: $("diff-after-file") };
  const AREAS = ["Devices", "Links", "Findings", "Hosts", "Behind devices"];
  let last = null, loadedAt = 0;

  const setStatus = (text, error) => { status.textContent = text || ""; status.classList.toggle("error", !!error); };

  // The runs kept in exports/topology, newest first. The two lists keep what the person picked while they are refilled.
  async function loadRuns(force) {
    if (!force && Date.now() - loadedAt < 3000) return;
    loadedAt = Date.now();
    let runs = [];
    try {
      const response = await fetch(`${api}/api/runs`, { cache: "no-store" });
      runs = (await response.json()).runs || [];
    } catch (err) { /* the file inputs still work */ }
    const first = !selects.before.options.length;
    for (const [side, select] of Object.entries(selects)) {
      const keep = select.value;
      select.innerHTML = `<option value="">${runs.length ? "Choose a kept run" : "No kept run - upload a file"}</option>` + runs.map((r) =>
        `<option value="${esc(r.id)}">${esc(r.built)} · ${esc(r.name || "unnamed")} · ${esc(r.devices)} devices, ${esc(r.links)} links</option>`).join("");
      if (keep && runs.some((r) => r.id === keep)) select.value = keep;
      else if (first && runs.length) select.value = side === "after" ? runs[0].id : (runs[1] || runs[0]).id;       // newest against the one before it
    }
  }
  root.addEventListener("tp:viewshown", (event) => { if (event.detail.view === "compare") loadRuns(true); });
  // "Compare selected" in the Topology history: open this panel with the two runs chosen and compare them at once
  root.addEventListener("tp:compare", async (event) => {
    const { before, after } = event.detail || {};
    if (!before || !after) return;
    root.dispatchEvent(new CustomEvent("tp:showview", { detail: { view: "compare" } }));
    await loadRuns(true);
    const known = (id) => Array.from(selects.before.options).some((o) => o.value === id);
    if (!known(before) || !known(after)) { setStatus("One of the runs is no longer kept.", true); return; }
    selects.before.value = before; selects.after.value = after;
    for (const input of Object.values(files)) input.value = "";
    box.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    form.requestSubmit();
  });
  for (const select of Object.values(selects)) select.addEventListener("focus", () => loadRuns(false));
  $("diff-swap").addEventListener("click", () => {
    [selects.before.value, selects.after.value] = [selects.after.value, selects.before.value];
    const a = files.before.value, b = files.after.value;       // a chosen file cannot be moved between inputs; say so instead of silently keeping it on one side
    if (a || b) setStatus("The chosen files stay where they are; choose them again on the other side if you want them swapped.", false);
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = new FormData();
    for (const side of ["before", "after"]) {
      const file = files[side].files && files[side].files[0];
      if (file) body.append(side, file);
      else if (selects[side].value) body.append(`${side}_id`, selects[side].value);
      else { setStatus(`Choose the ${side} run: a kept run or a file.`, true); return; }
    }
    go.disabled = true; setStatus("Comparing ...", false);
    try {
      const response = await fetch(`${api}/api/diff`, { method: "POST", body });
      let data; try { data = await response.json(); } catch (err) { data = { ok: false, error: "Keystone answered with an error." }; }
      if (!data.ok) { setStatus(data.error || "The runs could not be compared.", true); return; }
      last = data; render(); setStatus("", false);
    } catch (err) {
      setStatus("The connection to Keystone was lost. Is it still running?", true);
    } finally { go.disabled = false; }
  });

  function render() {
    const { summary, rows } = last;
    $("diff-result").classList.remove("hidden");
    const cards = [[summary.attention, "need attention", summary.attention ? "attention" : ""], [summary.differences, "differences", ""]];
    for (const area of AREAS) {
      const c = summary.areas[area] || {};
      const n = (c.added || 0) + (c.removed || 0) + (c.changed || 0) + (c.moved || 0) + (c.resolved || 0);
      cards.push([n, `${area.toLowerCase()} changed`, ""]);
    }
    $("diff-cards").innerHTML = cards.map(([n, label, tone]) => `<div class="tp-card ${tone}"><strong>${esc(n)}</strong><span>${esc(label)}</span></div>`).join("");
    const verdict = { identical: "The two runs are identical in every table.", changed: "The runs differ, and nothing in the difference is on the attention list.", attention: "The runs differ and some changes need attention (marked in the table)." }[summary.verdict] || "";
    const cut = Object.entries(summary.truncated || {}).map(([area, n]) => `${area}: ${n} more row(s) not shown (use the CSV)`).join("; ");
    $("diff-verdict").textContent = `${verdict} Captured in both runs: ${summary.captured_in_both} device(s). Before ${summary.before.devices} devices / ${summary.before.links} links; after ${summary.after.devices} devices / ${summary.after.links} links.${cut ? " " + cut + "." : ""}`;
    const areaSelect = $("diff-area");
    areaSelect.innerHTML = `<option value="">All areas</option>` + AREAS.filter((a) => rows.some((r) => r.area === a)).map((a) => `<option>${esc(a)}</option>`).join("");
    $("diff-attention").checked = summary.attention > 0;
    csvButton.classList.toggle("hidden", !last.csv);
    renderTable();
  }

  function renderTable() {
    if (!last) return;
    const onlyAttention = $("diff-attention").checked, area = $("diff-area").value;
    const shown = last.rows.filter((r) => (!onlyAttention || r.impact === "attention") && (!area || r.area === area));
    if (!shown.length) { $("diff-table").innerHTML = `<p class="an-hint">${last.rows.length ? "Nothing matches the filter." : "No difference."}</p>`; return; }
    const head = ["Area", "Change", "Item", "Field", "Before", "After", "Why it matters"];
    $("diff-table").innerHTML = `<table class="tp-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${shown.map((r) =>
      `<tr class="${r.impact === "attention" ? "tp-diff-attention" : ""}"><td>${esc(r.area)}</td><td>${esc(r.change)}${r.impact === "attention" ? " <span class=\"an-badge\">read</span>" : ""}</td><td>${esc(r.item)}</td><td>${esc(r.field)}</td><td class="tp-diff-before">${esc(r.before)}</td><td>${esc(r.after)}</td><td class="tp-long">${esc(r.why)}</td></tr>`).join("")}</tbody></table>`;
  }
  $("diff-attention").addEventListener("change", renderTable);
  $("diff-area").addEventListener("change", renderTable);

  csvButton.addEventListener("click", () => {
    if (!last || !last.csv) return;
    const url = URL.createObjectURL(new Blob(["﻿", last.csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url; link.download = "topology-diff.csv";
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
})();
