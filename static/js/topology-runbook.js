// Topology Builder: "Cutover runbook". Talks to /topology/api/runs and /topology/api/runbook.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root) return;
  const box = root.querySelector('[data-role="runbook"]');
  if (!box || box.dataset.ready) return;
  box.dataset.ready = "1";
  const $ = (role) => box.querySelector(`[data-role="${role}"]`);
  const api = root.dataset.api;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const form = $("rb-form"), status = $("rb-status"), go = $("rb-go"), select = $("rb-run"), file = $("rb-file");
  let last = null;

  const setStatus = (text, error) => { status.textContent = text || ""; status.classList.toggle("error", !!error); };

  async function loadRuns() {
    let runs = [];
    try { runs = (await (await fetch(`${api}/api/runs`, { cache: "no-store" })).json()).runs || []; } catch (err) { /* the file input still works */ }
    const keep = select.value;
    select.innerHTML = `<option value="">${runs.length ? "Choose a kept run" : "No kept run - upload a file"}</option>` + runs.map((r) =>
      `<option value="${esc(r.id)}">${esc(r.built)} · ${esc(r.name || "unnamed")} · ${esc(r.devices)} devices, ${esc(r.links)} links</option>`).join("");
    if (keep && runs.some((r) => r.id === keep)) select.value = keep; else if (runs.length) select.value = runs[0].id;
  }
  root.addEventListener("tp:viewshown", (event) => { if (event.detail.view === "runbook") loadRuns(); });
  // "Cutover runbook from this run" in the Topology history: open this panel with that run chosen (the engineer still fills in the title and window)
  root.addEventListener("tp:runbook", async (event) => {
    const id = event.detail && event.detail.id;
    if (!id) return;
    root.dispatchEvent(new CustomEvent("tp:showview", { detail: { view: "runbook" } }));
    await loadRuns();
    if (Array.from(select.options).some((o) => o.value === id)) { select.value = id; if (file.value) file.value = ""; setStatus("Run chosen from the history. Fill in the title and the change window, then build the runbook.", false); }
    else setStatus("This run is no longer kept.", true);
    box.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
    select.focus({ preventScroll: true });
  });

  const save = (name, text, type) => {
    const url = URL.createObjectURL(new Blob([type === "text/csv" ? "﻿" : "", text], { type: `${type};charset=utf-8` }));
    const link = document.createElement("a");
    link.href = url; link.download = name;
    document.body.appendChild(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const body = new FormData();
    const chosen = file.files && file.files[0];
    if (chosen) body.append("source", chosen);
    else if (select.value) body.append("source_id", select.value);
    else { setStatus("Choose a run: a kept run or a file.", true); return; }
    for (const [field, role] of [["change", "rb-change"], ["title", "rb-title"], ["window", "rb-window"], ["reference", "rb-reference"], ["devices", "rb-devices"]]) body.append(field, $(role).value);
    go.disabled = true; setStatus("Writing the runbook ...", false);
    try {
      const response = await fetch(`${api}/api/runbook`, { method: "POST", body });
      let data; try { data = await response.json(); } catch (err) { data = { ok: false, error: "Keystone answered with an error." }; }
      if (!data.ok) { setStatus(data.error || "The runbook could not be written.", true); return; }
      last = data; render(); setStatus("", false);
    } catch (err) {
      setStatus("The connection to Keystone was lost. Is it still running?", true);
    } finally { go.disabled = false; }
  });

  function render() {
    const { summary, devices } = last;
    $("rb-result").classList.remove("hidden");
    for (const role of ["rb-open", "rb-html", "rb-csv"]) $(role).classList.remove("hidden");
    $("rb-verdict").textContent = `${summary.devices} device(s) in the plan: ${summary.outage} with an expected outage, ${summary.rolling} with a redundant path in the captured links. ${summary.steps} steps in the CSV.${summary.not_captured ? ` ${summary.not_captured} device(s) seen by neighbors only are not in the plan.` : ""}`;
    $("rb-table").innerHTML = `<table class="tp-table"><thead><tr><th>#</th><th>Device</th><th>Role</th><th>Platform</th><th>Redundancy</th><th>Impact</th></tr></thead><tbody>${devices.map((d) =>
      `<tr class="${d.outage ? "tp-diff-attention" : ""}"><td>${esc(d.seq)}</td><td>${esc(d.device)}</td><td>${esc(d.role)}</td><td>${esc((d.vendor + " " + d.model).trim())}</td><td>${esc(d.partner ? "vPC with " + d.partner : "")}</td><td class="tp-long">${esc(d.impact_text)}</td></tr>`).join("")}</tbody></table>`;
  }

  $("rb-open").addEventListener("click", () => {
    if (!last) return;
    const url = URL.createObjectURL(new Blob([last.html], { type: "text/html;charset=utf-8" }));
    window.open(url, "_blank", "noopener");
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  });
  $("rb-html").addEventListener("click", () => { if (last) save("cutover-runbook.html", last.html, "text/html"); });
  $("rb-csv").addEventListener("click", () => { if (last && last.csv) save("cutover-plan.csv", last.csv, "text/csv"); });
})();
