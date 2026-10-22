// LLD Index page. Scoped to .li-page (the SPA router keeps pages mounted).
(function () {
  function init(root) {
    if (!root || root.dataset.ready) return;
    root.dataset.ready = "1";
    const esc = value => window.NES.escape(value);
    const $ = role => root.querySelector(`[data-role="${role}"]`);
    const COLS = ["site", "hostname", "model", "role", "mgmt_ip", "serial", "config", "rack", "rack_size", "u", "u_height"];
    const PLACE = ["HO", "HO-CORE-SW01", "S5755-H24T4Y2CZ", "Core Switch", "10.10.10.1/24", "", "ho-core-sw01.txt", "Ruang Server Rack 1", "42", "30", "1"];
    const NARROW = new Set(["rack_size", "u", "u_height"]);
    let configFiles = [];

    // ------------------------------------------------------------ inventory rows
    function addRow(values = {}) {
      const tr = document.createElement("tr");
      const fresh = !Object.values(values).some(v => String(v ?? "").trim());
      tr.innerHTML = COLS.map((c, i) =>
        `<td><input class="li-cell${NARROW.has(c) ? " li-narrow" : ""}" data-col="${c}" value="${esc(values[c] ?? "")}" placeholder="${fresh ? esc(PLACE[i]) : ""}" aria-label="${c}"${NARROW.has(c) ? ' inputmode="numeric"' : ""}></td>`
      ).join("") + `<td><button type="button" class="an-icon-btn" data-role="remove" aria-label="Remove device">×</button></td>`;
      tr.querySelector('[data-role="remove"]').addEventListener("click", () => { tr.remove(); if (!rowsBody().children.length) addRow(); });
      // Paste a block copied from Excel into the first cell: one device per line.
      tr.querySelector('[data-col="site"]').addEventListener("paste", event => {
        const text = (event.clipboardData || window.clipboardData).getData("text");
        if (!text.includes("\t") && !text.includes("\n")) return;
        event.preventDefault();
        const lines = text.replace(/\r/g, "").split("\n").filter(l => l.trim());
        lines.forEach((line, index) => {
          const cells = line.split("\t");
          const record = Object.fromEntries(COLS.map((c, i) => [c, (cells[i] || "").trim()]));
          if (/^site$/i.test(record.site) && /hostname/i.test(record.hostname)) return;
          if (index === 0) fillRow(tr, record); else addRow(record);
        });
      });
      rowsBody().appendChild(tr);
      return tr;
    }
    function fillRow(tr, record) {
      COLS.forEach(c => { const input = tr.querySelector(`[data-col="${c}"]`); if (input) input.value = record[c] || ""; });
    }
    function rowsBody() { return $("rows"); }
    function readRows() {
      return [...rowsBody().querySelectorAll("tr")].map(tr =>
        Object.fromEntries(COLS.map(c => [c, tr.querySelector(`[data-col="${c}"]`).value.trim()]))
      ).filter(r => r.hostname);
    }
    $("add-row").addEventListener("click", () => addRow().querySelector("input").focus());
    $("clear-rows").addEventListener("click", () => { rowsBody().innerHTML = ""; addRow(); });
    $("inventory-file").addEventListener("change", async event => {
      const file = event.target.files[0];
      if (!file) return;
      const data = new FormData();
      data.set("inventory", file);
      $("inventory-status").textContent = "Reading…";
      try {
        const response = await fetch("/lld-index/api/inventory", { method: "POST", body: data });
        const payload = await response.json();
        if (!payload.ok) throw new Error(payload.error);
        rowsBody().innerHTML = "";
        payload.rows.forEach(r => addRow(r));
        if (!payload.rows.length) addRow();
        $("inventory-status").textContent = `${payload.rows.length} devices imported from ${file.name}.`;
      } catch (error) {
        $("inventory-status").textContent = "";
        window.NES.toast(error.message, "error");
      }
      event.target.value = "";
    });
    addRow();

    // ------------------------------------------------------------ config files
    function renderFiles() {
      const list = $("file-list");
      list.classList.toggle("hidden", !configFiles.length);
      list.innerHTML = configFiles.map((f, i) =>
        `<li><span class="an-file-name">${esc(f.name)}</span><small>${Math.max(1, Math.round(f.size / 1024))} KB</small>
         <button type="button" class="an-icon-btn" data-index="${i}" aria-label="Remove ${esc(f.name)}">×</button></li>`).join("");
      list.querySelectorAll("button[data-index]").forEach(b => b.addEventListener("click", () => {
        configFiles.splice(Number(b.dataset.index), 1); renderFiles();
      }));
    }
    function addFiles(files) {
      const names = new Set(configFiles.map(f => f.name));
      [...files].forEach(f => { if (!names.has(f.name)) configFiles.push(f); });
      renderFiles();
    }
    $("config-files").addEventListener("change", event => { addFiles(event.target.files); event.target.value = ""; });
    const drop = $("drop");
    ["dragover", "dragenter"].forEach(e => drop.addEventListener(e, ev => { ev.preventDefault(); drop.classList.add("is-over"); }));
    ["dragleave", "drop"].forEach(e => drop.addEventListener(e, () => drop.classList.remove("is-over")));
    drop.addEventListener("drop", ev => { ev.preventDefault(); addFiles(ev.dataTransfer.files); });

    // ------------------------------------------------------------ build
    $("form").addEventListener("submit", async event => {
      event.preventDefault();
      const project = Object.fromEntries([...root.querySelectorAll("[data-field]")].map(i => [i.dataset.field, i.value.trim()]));
      const technologies = [...root.querySelectorAll("[data-tech]:checked")].map(i => i.dataset.tech);
      const inventory = readRows();
      if (!technologies.length) { window.NES.toast("Pick at least one technology.", "error"); return; }
      if (!inventory.length) { window.NES.toast("Add at least one device with a hostname.", "error"); return; }
      const data = new FormData();
      data.set("payload", JSON.stringify({ project, technologies, inventory }));
      configFiles.forEach(f => data.append("configs", f));
      const button = $("build");
      window.NES.setLoading(button, true, "Building…");
      $("status").textContent = configFiles.length ? `Reading ${configFiles.length} config file(s)…` : "";
      try {
        const response = await fetch("/lld-index/api/build", { method: "POST", body: data });
        const payload = await response.json();
        if (!payload.ok) throw new Error(payload.error);
        renderResult(payload.result);
        $("status").textContent = "";
      } catch (error) {
        $("status").textContent = "";
        window.NES.toast(error.message, "error");
      } finally {
        window.NES.setLoading(button, false);
      }
    });

    function renderRacks(racks) {
      const panel = $("racks-panel");
      panel.classList.toggle("hidden", !racks.length);
      $("racks").innerHTML = racks.map(rack => {
        const cells = [];
        let u = rack.size;
        const byTop = new Map(rack.units.map(d => [d.u + d.height - 1, d]));
        while (u >= 1) {
          const d = byTop.get(u);
          if (d) {
            const span = d.height > 1 ? `${d.u}–${u}` : `${u}`;
            cells.push(`<div class="li-u is-dev" style="--h:${d.height}" title="${esc(d.hostname)} U${d.u}${d.height > 1 ? "-U" + (d.u + d.height - 1) : ""}">
              <span class="li-un">${span}</span><span class="li-dev"><strong>${esc(d.hostname)}</strong><small>${esc(d.model || "")} · ${d.height}U</small></span><span class="li-un">${span}</span></div>`);
            u = d.u - 1;
          } else {
            cells.push(`<div class="li-u" style="--h:1"><span class="li-un">${u}</span><span class="li-dev"></span><span class="li-un">${u}</span></div>`);
            u -= 1;
          }
        }
        return `<figure class="li-rack"><figcaption><strong>${esc(rack.rack)}</strong><small>${esc(rack.site)} · ${rack.size}U · ${rack.units.length} device(s)</small></figcaption>
          <div class="li-rack-body">${cells.join("")}</div>
          ${rack.problems.length ? `<ul class="li-rack-warn">${rack.problems.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}</figure>`;
      }).join("");
    }

    function card(label, value, hint, tone) {
      return `<article class="an-card"${tone ? ` style="--tone: var(--${tone})"` : ""}><span class="an-card-label">${esc(label)}</span>
        <strong class="an-card-value">${esc(value)}</strong><small class="an-hint">${esc(hint || "")}</small></article>`;
    }

    function renderResult(result) {
      const s = result.stats;
      $("result").classList.remove("hidden");
      $("summary").textContent = `${result.project.project_name || "Project"} · ${result.project.customer || "customer not set"} · ${result.project.technologies.length} technolog${result.project.technologies.length === 1 ? "y" : "ies"}`;
      const link = $("download");
      link.href = result.download_url;
      link.setAttribute("download", result.download_name);
      $("cards").innerHTML = [
        card("Chapters", s.chapters, `${s.headings} headings in total`),
        card("Tables", s.tables, `${s.from_config} filled from configs`),
        card("Devices", s.devices, `${s.configs_read} configs read`),
        card("To fill by hand", s.to_fill, "images and TBD rows", s.to_fill ? "amber" : "green"),
      ].join("");
      $("devices").innerHTML = result.devices.map(d => `<tr class="${d.in_scope ? "" : "is-muted"}">
        <td>${esc(d.site)}</td><td><strong>${esc(d.hostname)}</strong></td><td>${esc(d.model || "-")}</td>
        <td>${esc(d.technology_label || "?")}<small>${esc(d.technology_source ? "from " + d.technology_source : "")}</small></td>
        <td>${d.config_name ? `${esc(d.config_name)}<small>${d.analyzed ? "read" : "not read"}</small>` : `<span class="li-muted">none</span>`}</td>
        <td>${(d.notes || []).map(n => `<span class="li-note">${esc(n)}</span>`).join("") || "-"}</td></tr>`).join("") +
        (s.unused_files.length ? `<tr><td colspan="6" class="li-warn">Uploaded but not matched to any device: ${esc(s.unused_files.join(", "))}. Put the file name in the Config column.</td></tr>` : "");
      const chips = b => {
        const badge = b.kind === "table" ? `Table · ${b.rows} rows` : b.kind === "paragraph" ? "Paragraph" : b.kind === "image" ? "Image" : "";
        return (badge ? `<span class="li-kind">${esc(badge)}</span>` : "") +
          (b.source && b.kind !== "group" ? `<span class="li-src">${esc(b.source)}</span>` : "") +
          (b.placeholder ? `<span class="li-todo">${b.kind === "image" ? "add image" : "TBD"}</span>` : "");
      };
      $("tree").innerHTML = result.tree.map(n => `<li class="li-node lvl-${Math.min(n.level, 4)}${n.placeholder ? " is-todo" : ""}">
          <span class="li-no">${esc(n.no)}</span><span class="li-title">${esc(n.title)}</span>${chips(n)}
          ${(n.more || []).map(m => `<span class="li-plus">+</span>${chips(m)}`).join("")}</li>`).join("");
      renderRacks(result.racks || []);
      $("result").scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  function boot() { document.querySelectorAll(".li-page").forEach(init); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot); else boot();
  // The SPA router injects pages later; watch for this one being mounted.
  new MutationObserver(boot).observe(document.body, { childList: true, subtree: true });
})();
