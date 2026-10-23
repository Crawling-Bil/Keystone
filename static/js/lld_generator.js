// LLD Generator page: the Document Generator UI, ported into Keystone.
// Scoped to .lg-page: the SPA router keeps every visited page mounted, so the
// page holds no global ids (data-ld instead) and runs once per page element.
(function () {
  function init(page) {
    if (!page || page.dataset.ready) return;
    page.dataset.ready = "1";
    // ===================== helpers =====================
    const host = () => document.querySelector(".lg-dialog-host");
    const $ = (sel, root) => root ? root.querySelector(sel) : (page.querySelector(sel) || (host() && host().querySelector(sel)));
    const $$ = (sel, root) => root ? Array.from(root.querySelectorAll(sel))
      : [...page.querySelectorAll(sel), ...(host() ? host().querySelectorAll(sel) : [])];

    async function api(path, opts = {}) {
      const res = await fetch(`/lld-generator/api${path}`, {
        headers: opts.body && !(opts.body instanceof FormData) ? { "Content-Type": "application/json" } : undefined,
        ...opts,
      });
      if (!res.ok) {
        let msg = res.statusText;
        try {
          const j = await res.json();
          if (Array.isArray(j.detail)) {
            msg = j.detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
          } else {
            msg = j.detail || msg;
          }
        } catch (e) {}
        throw new Error(msg);
      }
      const ct = res.headers.get("content-type") || "";
      return ct.includes("application/json") ? res.json() : res;
    }
    const apiGet = (p) => api(p);
    const apiPost = (p, body) => api(p, { method: "POST", body: body instanceof FormData ? body : JSON.stringify(body) });
    const apiPut = (p, body) => api(p, { method: "PUT", body: JSON.stringify(body) });
    const apiDel = (p) => api(p, { method: "DELETE" });

    function toast(msg, isError = false) {
      if (window.NES && window.NES.toast) window.NES.toast(msg, isError ? "error" : "success");
      else console.log(msg);
    }

    function escapeHtml(s) {
      return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    }

    // generic modal dialog. fieldsHtml = inner HTML, onSubmit(formEl) => Promise
    function openDialog({ title, bodyHtml, submitLabel = "Simpan", onSubmit, wide = false }) {
      // Dialogs live in a host on <body>: a page container (SPA outlet) can be a
      // containing block for position:fixed, which pushed the dialog off screen.
      let root = document.querySelector(".lg-dialog-host");
      if (!root) { root = document.createElement("div"); root.className = "lg-page lg-dialog-host"; document.body.appendChild(root); }
      root.innerHTML = `
        <div class="dialog-scrim" data-ld="dlg-scrim">
          <div class="dialog-box" style="${wide ? "width:640px" : ""}">
            <h2>${escapeHtml(title)}</h2>
            <form data-ld="dlg-form">${bodyHtml}
            <div class="dialog-actions">
              <button type="button" class="btn btn-text" data-ld="dlg-cancel">Batal</button>
              <button type="submit" class="btn btn-filled" data-ld="dlg-submit">${escapeHtml(submitLabel)}</button>
            </div></form>
          </div>
        </div>`;
      const close = () => { root.innerHTML = ""; };
      root.querySelector('[data-ld="dlg-scrim"]').addEventListener("click", (e) => { if (e.target.dataset.ld === "dlg-scrim") close(); });
      $('[data-ld=\"dlg-cancel\"]').addEventListener("click", close);
      $('[data-ld=\"dlg-form\"]').addEventListener("submit", async (e) => {
        e.preventDefault();
        const btn = $('[data-ld=\"dlg-submit\"]');
        btn.disabled = true;
        try {
          await onSubmit(e.target);
          close();
        } catch (err) {
          toast(err.message, true);
          btn.disabled = false;
        }
      });
      return close;
    }

    function confirmDialog(message) {
      return new Promise((resolve) => {
        openDialog({
          title: "Konfirmasi",
          bodyHtml: `<p style="margin:0 0 4px;color:var(--md-on-surface-variant)">${escapeHtml(message)}</p>`,
          submitLabel: "Ya, lanjutkan",
          onSubmit: async () => resolve(true),
        });
        $('[data-ld="dlg-scrim"]').addEventListener("click", (e) => { if (e.target.dataset.ld === "dlg-scrim") resolve(false); });
        $('[data-ld=\"dlg-cancel\"]').addEventListener("click", () => resolve(false));
      });
    }

    // ===================== app state =====================
    const state = {
      view: "projects",       // 'projects' | 'templates' | 'project'
      projects: [],
      templates: [],
      currentProjectId: null,
      currentProject: null,
      chapters: [],
      selectedChapterId: null,
      blocks: [],
    };

    // ===================== nav =====================
    $$(".lg-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const view = btn.dataset.view;
        state.currentProjectId = null;
        switchView(view);
      });
    });

    function switchView(view) {
      state.view = view;
      $$(".lg-tab").forEach((b) => b.classList.toggle("active", b.dataset.view === view || (view === "project" && b.dataset.view === "projects")));
      render();
    }

    async function render() {
      const main = $('[data-ld=\"main\"]');
      await loadTemplates(); // dipakai di banyak dialog (pilih template project), murah untuk selalu di-refresh
      if (state.view === "projects") {
        await loadProjects();
        renderProjectsView(main);
      } else if (state.view === "templates") {
        renderTemplatesView(main);
      } else if (state.view === "project") {
        await renderProjectWorkspace(main);
      }
    }

    async function loadProjects() { state.projects = await apiGet("/projects"); }
    async function loadTemplates() { state.templates = await apiGet("/templates"); }

    // ===================== PROJECTS view =====================
    function renderProjectsView(main) {
      main.innerHTML = `
        <div class="topbar">
          <div>
            <h1>Projects</h1>
            <div class="subtitle">Semua dokumen LLD yang lagi kamu kerjain</div>
          </div>
          <button class="btn btn-filled" data-ld="btn-new-project">
            <span class="lg-ic" aria-hidden="true">+</span> Project Baru
          </button>
        </div>
        <div class="content-area">
          ${state.projects.length === 0 ? emptyStateHtml("folder_off", "Belum ada project", "Bikin project baru untuk mulai nyusun LLD.") : `
          <div class="grid-cards">
            ${state.projects.map(projectCardHtml).join("")}
          </div>`}
        </div>`;

      $('[data-ld=\"btn-new-project\"]').addEventListener("click", openNewProjectDialog);
      $$(".js-open-project", main).forEach((el) => {
        el.addEventListener("click", () => {
          state.currentProjectId = Number(el.dataset.id);
          switchView("project");
        });
      });
      $$(".js-delete-project", main).forEach((el) => {
        el.addEventListener("click", async (e) => {
          e.stopPropagation();
          const ok = await confirmDialog("Hapus project ini beserta seluruh struktur bab & isinya? Tidak bisa dibatalkan.");
          if (!ok) return;
          await apiDel(`/projects/${el.dataset.id}`);
          toast("Project dihapus");
          await loadProjects();
          renderProjectsView($('[data-ld=\"main\"]'));
        });
      });
    }

    function projectCardHtml(p) {
      return `
        <div class="card card-clickable js-open-project" data-id="${p.id}">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div>
              <div style="font-weight:500;font-size:15px;margin-bottom:4px">${escapeHtml(p.name)}</div>
              <div class="muted" style="font-size:12.5px">${escapeHtml(p.client || "-")}</div>
            </div>
            <button class="btn-icon btn-danger js-delete-project" data-id="${p.id}" title="Hapus">
              <span class="lg-ic" aria-hidden="true">✕</span>
            </button>
          </div>
          <div style="margin-top:14px;display:flex;gap:6px;flex-wrap:wrap">
            <span class="chip">v${escapeHtml(p.version)}</span>
            <span class="chip">${escapeHtml(p.template_name || "template?")}</span>
          </div>
        </div>`;
    }

    function emptyStateHtml(icon, title, sub) {
      return `<div class="empty-state">
        <span class="lg-ic" aria-hidden="true"></span>
        <div style="font-size:16px;font-weight:500;color:var(--md-on-surface)">${escapeHtml(title)}</div>
        <div>${escapeHtml(sub)}</div>
      </div>`;
    }

    function openNewProjectDialog() {
      if (state.templates.length === 0) {
        toast("Upload template dulu di menu Templates sebelum bikin project", true);
        return;
      }
      openDialog({
        title: "Project Baru",
        submitLabel: "Buat",
        bodyHtml: `
          <div class="field"><label>Nama Project</label><input name="name" required placeholder="mis. Wireless Network Improvement" /></div>
          <div class="field-row">
            <div class="field"><label>Client</label><input name="client" placeholder="mis. Toyota Astra Motor" /></div>
            <div class="field"><label>Versi</label><input name="version" value="0.1" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Kode Project</label><input name="project_code" placeholder="mis. 7TAMO26009001" /></div>
            <div class="field"><label>Disusun oleh</label><input name="prepared_by" placeholder="Nama penulis dokumen" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Perusahaan</label><input name="company" value="Multipolar Technology" /></div>
            <div class="field"><label>Tanggal Dokumen</label><input name="doc_date" placeholder="kosong = tanggal generate" /></div>
          </div>
          <div class="field">
            <label>Master Template</label>
            <select name="template_id">
              ${state.templates.map((t) => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("")}
            </select>
          </div>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const p = await apiPost("/projects", {
            name: fd.get("name"), client: fd.get("client") || "", version: fd.get("version") || "0.1",
            template_id: Number(fd.get("template_id")),
            project_code: fd.get("project_code") || "", prepared_by: fd.get("prepared_by") || "",
            company: fd.get("company") || "Multipolar Technology", doc_date: fd.get("doc_date") || "",
          });
          toast("Project dibuat");
          state.currentProjectId = p.id;
          switchView("project");
        },
      });
    }

    // ===================== TEMPLATES view =====================
    function renderTemplatesView(main) {
      main.innerHTML = `
        <div class="topbar">
          <div>
            <h1>Templates</h1>
            <div class="subtitle">Master .docx (cover, branding, heading style) yang dipakai project-project kamu</div>
          </div>
          <button class="btn btn-filled" data-ld="btn-new-template">
            <span class="lg-ic" aria-hidden="true">⤒</span> Upload Template
          </button>
        </div>
        <div class="content-area">
          ${state.templates.length === 0 ? emptyStateHtml("layers_clear", "Belum ada template", "Upload file .docx master (yang formatnya mau dipakai berulang) dulu.") : `
          <div class="grid-cards">
            ${state.templates.map(templateCardHtml).join("")}
          </div>`}
        </div>`;

      $('[data-ld=\"btn-new-template\"]').addEventListener("click", openNewTemplateDialog);
      $$(".js-delete-template", main).forEach((el) => {
        el.addEventListener("click", async (e) => {
          e.stopPropagation();
          const ok = await confirmDialog("Hapus template ini? Project yang masih pakai template ini nggak akan bisa di-generate lagi.");
          if (!ok) return;
          await apiDel(`/templates/${el.dataset.id}`);
          toast("Template dihapus");
          await loadTemplates();
          renderTemplatesView($('[data-ld=\"main\"]'));
        });
      });
      $$(".js-edit-template", main).forEach((el) => {
        el.addEventListener("click", () => openEditTemplateDialog(Number(el.dataset.id)));
      });
    }

    function templateCardHtml(t) {
      const levels = JSON.parse(t.auto_numbered_levels);
      return `
        <div class="card">
          <div style="display:flex;justify-content:space-between;align-items:flex-start">
            <div style="font-weight:500;font-size:15px">${escapeHtml(t.name)}</div>
            <div style="display:flex">
              <button class="btn-icon js-edit-template" data-id="${t.id}" title="Edit pengaturan"><span class="lg-ic" aria-hidden="true">⚙</span></button>
              <button class="btn-icon btn-danger js-delete-template" data-id="${t.id}" title="Hapus"><span class="lg-ic" aria-hidden="true">✕</span></button>
            </div>
          </div>
          <div class="muted" style="font-size:12.5px;margin-top:10px;line-height:1.6">
            Heading auto-number: <b>${levels.map((l) => "H" + l).join(", ") || "-"}</b><br/>
            Heading penutup: <b>${t.closing_heading ? escapeHtml(t.closing_heading) : "(tidak ada)"}</b>
          </div>
        </div>`;
    }

    function openNewTemplateDialog() {
      openDialog({
        title: "Upload Master Template",
        submitLabel: "Upload & Analisis",
        bodyHtml: `
          <div class="field"><label>Nama Template</label><input name="name" required placeholder="mis. Multipolar LLD Master" /></div>
          <div class="field"><label>File .docx</label><input name="file" type="file" accept=".docx" required /></div>
          <p class="hint">Setelah upload, file bakal dianalisis otomatis (heading style apa aja yang ada). Pengaturan detail (heading penutup, level auto-number) bisa diedit sesudahnya.</p>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const upload = new FormData();
          upload.append("name", fd.get("name"));
          upload.append("closing_heading", "");
          upload.append("auto_numbered_levels", "[1,2]");
          upload.append("file", fd.get("file"));
          const t = await apiPost("/templates", upload);
          toast("Template diupload");
          await loadTemplates();
          renderTemplatesView($('[data-ld=\"main\"]'));
          openEditTemplateDialog(t.id);
        },
      });
    }

    async function openEditTemplateDialog(templateId) {
      const t = await apiGet(`/templates/${templateId}`);
      const outline = t.analysis ? t.analysis.outline : [];
      const availableLevels = t.analysis ? t.analysis.available_heading_levels : [1, 2, 3, 4];
      const currentAuto = new Set(t.auto_numbered_levels);

      openDialog({
        title: `Pengaturan: ${t.name}`,
        submitLabel: "Simpan",
        wide: true,
        bodyHtml: `
          <div class="field"><label>Nama Template</label><input name="name" value="${escapeHtml(t.name)}" required /></div>

          <div class="field">
            <label>Heading penutup (opsional)</label>
            <input name="closing_heading" list="closing-options" value="${escapeHtml(t.closing_heading || "")}"
              placeholder="mis. Document Acceptance — kosongkan kalau tidak ada" />
            <datalist data-ld="closing-options">
              ${[...new Set(outline.filter((o) => o.style === "Heading1").map((o) => o.text))]
                .map((x) => `<option value="${escapeHtml(x)}">`).join("")}
            </datalist>
            <span class="hint">Semua konten SETELAH heading ini (kalau ada) akan dipertahankan apa adanya — cocok buat halaman tanda tangan/approval di akhir dokumen.</span>
          </div>

          <div class="field">
            <label>Level heading yang auto-numbering (dari style Word template ini)</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap;padding:8px 0">
              ${availableLevels.map((lvl) => `
                <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:400">
                  <input type="checkbox" name="auto_level" value="${lvl}" ${currentAuto.has(lvl) ? "checked" : ""} /> Heading ${lvl}
                </label>`).join("")}
            </div>
            <span class="hint">Centang level yang nomornya SUDAH otomatis dari Word (biasanya H1/H2 di template korporat). Level yang tidak dicentang akan diberi nomor manual oleh app (format 1.2.3) di depan judulnya.</span>
          </div>

          <div class="field-row">
            <div class="field"><label>Nama field caption Gambar</label><input name="figure_seq_name" value="${escapeHtml(t.figure_seq_name || "Gambar")}" /></div>
            <div class="field"><label>Nama field caption Tabel</label><input name="table_seq_name" value="${escapeHtml(t.table_seq_name || "Tabel")}" /></div>
          </div>
          <p class="hint" style="margin-top:-10px">Harus sama persis dengan identifier yang dipakai field "List of Pictures"/"List of Table" di template (default Word: "Figure"/"Table"; kalau template ini pakai istilah Indonesia biasanya "Gambar"/"Tabel").</p>

          <div class="field">
            <label>Outline template (referensi, tidak bisa diedit di sini)</label>
            <div style="max-height:160px;overflow-y:auto;border:1px solid var(--md-outline-variant);border-radius:8px;padding:8px 12px;font-size:12.5px;line-height:1.8">
              ${outline.length === 0 ? '<span class="muted">Tidak ada heading terdeteksi setelah Heading 1 pertama.</span>' :
                outline.map((o) => `<div><span class="level-badge">${o.style.replace("Heading", "H")}</span> ${escapeHtml(o.text)}</div>`).join("")}
            </div>
          </div>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const autoLevels = $$('input[name="auto_level"]:checked', form).map((el) => Number(el.value));
          await apiPut(`/templates/${templateId}`, {
            name: fd.get("name"),
            closing_heading: fd.get("closing_heading") || "",
            auto_numbered_levels: autoLevels,
            figure_seq_name: fd.get("figure_seq_name") || "Gambar",
            table_seq_name: fd.get("table_seq_name") || "Tabel",
          });
          toast("Pengaturan template disimpan");
          await loadTemplates();
          if (state.view === "templates") renderTemplatesView($('[data-ld=\"main\"]'));
        },
      });
    }

    // ===================== PROJECT workspace =====================
    async function renderProjectWorkspace(main) {
      const pid = state.currentProjectId;
      state.currentProject = await apiGet(`/projects/${pid}`);
      state.chapters = await apiGet(`/projects/${pid}/chapters`);
      if (state.selectedChapterId && !state.chapters.find((c) => c.id === state.selectedChapterId)) {
        state.selectedChapterId = null;
      }

      const p = state.currentProject;
      try {
        const rv = await apiGet(`/projects/${pid}/review`);
        state.reviewMap = Object.fromEntries(rv.chapters.map((c) => [c.id, c]));
      } catch (e) { state.reviewMap = {}; }
      main.innerHTML = `
        <div class="topbar">
          <div>
            <button class="btn-text" data-ld="btn-back" style="padding:4px 8px 4px 0"><span class="lg-ic" aria-hidden="true">←</span></button>
            <span style="font-size:22px;font-weight:500">${escapeHtml(p.name)}</span>
            <div class="subtitle">${escapeHtml(p.client || "-")} &middot; v${escapeHtml(p.version)}</div>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-tonal" data-ld="btn-review"><span class="lg-ic" aria-hidden="true">✓</span> Review</button>
            <button class="btn btn-outlined" data-ld="btn-project-settings"><span class="lg-ic" aria-hidden="true">⚙</span> Pengaturan</button>
            <button class="btn btn-filled" data-ld="btn-generate"><span class="lg-ic" aria-hidden="true">⤓</span> Generate &amp; Download</button>
          </div>
        </div>
        <div class="workspace">
          <div class="pane-tree" data-ld="pane-tree"></div>
          <div class="pane-content" data-ld="pane-content"></div>
        </div>`;

      $('[data-ld=\"btn-back\"]').addEventListener("click", () => { state.currentProjectId = null; switchView("projects"); });
      $('[data-ld=\"btn-generate\"]').addEventListener("click", handleGenerate);
      $('[data-ld=\"btn-project-settings\"]').addEventListener("click", openProjectSettingsDialog);
      $('[data-ld=\"btn-review\"]').addEventListener("click", openReviewDialog);

      renderTree();
      renderContentPane();
    }

    function chapterChildren(parentId) {
      return state.chapters.filter((c) => c.parent_id === parentId).sort((a, b) => a.order_index - b.order_index);
    }

    // Bab numbering ("1.2.3") harus konsisten antara tree kiri dan dialog Review
    // — sebelumnya dua tempat itu masing-masing punya salinan logic counter
    // sendiri (gampang drift kalau salah satu diubah tapi yang lain lupa).
    // Sekarang cuma satu implementasi, dipanggil depth-first sesuai urutan
    // `chapters` (yang memang sudah depth-first dari backend).
    function computeChapterNumbers(chapters) {
      const counters = {};
      const numberById = {};
      for (const chapter of chapters) {
        counters[chapter.level] = (counters[chapter.level] || 0) + 1;
        for (const k of Object.keys(counters)) if (Number(k) > chapter.level) counters[k] = 0;
        const parts = [];
        for (let l = 1; l <= chapter.level; l++) parts.push(counters[l] || 0);
        numberById[chapter.id] = parts.join(".");
      }
      return numberById;
    }

    function renderTree() {
      const pane = $('[data-ld=\"pane-tree\"]');
      const roots = chapterChildren(null);
      pane.innerHTML = `
        <div class="tree-toolbar">
          <h3>Struktur Bab</h3>
          <button class="btn-icon" data-ld="btn-add-root" title="Tambah bab utama"><span class="lg-ic" aria-hidden="true">+</span></button>
        </div>
        <button class="btn btn-outlined" data-ld="btn-import-excel" style="width:100%;justify-content:center;margin-bottom:14px">
          <span class="lg-ic" aria-hidden="true">⤒</span> Import dari Excel Index
        </button>
        <div data-ld="tree-root"></div>
        ${roots.length === 0 ? `<div class="muted" style="font-size:12.5px;padding:8px 4px">Belum ada bab. Klik "Import dari Excel Index" kalau udah punya file Excel-nya, atau + di atas buat mulai manual.</div>` : ""}
      `;
      $('[data-ld=\"btn-add-root\"]').addEventListener("click", () => openChapterDialog({ parent_id: null }));
      $('[data-ld=\"btn-import-excel\"]').addEventListener("click", openImportExcelDialog);

      const chapterNumbers = computeChapterNumbers(state.chapters);

      function renderNode(chapter, depth) {
        const num = chapterNumbers[chapter.id];
        const wrap = document.createElement("div");
        wrap.className = "tree-node";
        const row = document.createElement("div");
        row.className = "tree-row" + (chapter.id === state.selectedChapterId ? " selected" : "");
        row.style.setProperty("--depth", depth);
        const rv = (state.reviewMap || {})[chapter.id];
        const emptyDot = rv && !rv.is_group && rv.block_types.length === 0
          ? `<span title="Belum diisi" style="width:8px;height:8px;border-radius:50%;background:var(--md-error);flex-shrink:0"></span>` : "";
        row.innerHTML = `
          <span class="num">${num}</span>
          <span class="title">${escapeHtml(chapter.title)}</span>
          ${emptyDot}
          <span class="row-actions">
            <button class="btn-icon js-add-child" title="Tambah sub-bab"><span class="lg-ic" aria-hidden="true">+</span></button>
            <button class="btn-icon js-edit-ch" title="Rename"><span class="lg-ic" aria-hidden="true">✎</span></button>
            <button class="btn-icon js-up" title="Naik"><span class="lg-ic" aria-hidden="true">↑</span></button>
            <button class="btn-icon js-down" title="Turun"><span class="lg-ic" aria-hidden="true">↓</span></button>
            <button class="btn-icon btn-danger js-del-ch" title="Hapus"><span class="lg-ic" aria-hidden="true">✕</span></button>
          </span>`;
        row.addEventListener("click", (e) => {
          if (e.target.closest(".row-actions")) return;
          state.selectedChapterId = chapter.id;
          renderTree();
          renderContentPane();
        });
        row.querySelector(".js-add-child").addEventListener("click", (e) => { e.stopPropagation(); openChapterDialog({ parent_id: chapter.id }); });
        row.querySelector(".js-edit-ch").addEventListener("click", (e) => { e.stopPropagation(); openChapterDialog({ chapter }); });
        row.querySelector(".js-del-ch").addEventListener("click", async (e) => {
          e.stopPropagation();
          const ok = await confirmDialog(`Hapus bab "${chapter.title}" beserta semua sub-bab & isinya?`);
          if (!ok) return;
          await apiDel(`/chapters/${chapter.id}`);
          if (state.selectedChapterId === chapter.id) state.selectedChapterId = null;
          await refreshChapters();
        });
        row.querySelector(".js-up").addEventListener("click", (e) => { e.stopPropagation(); moveChapter(chapter, -1); });
        row.querySelector(".js-down").addEventListener("click", (e) => { e.stopPropagation(); moveChapter(chapter, 1); });
        wrap.appendChild(row);

        const kids = chapterChildren(chapter.id);
        kids.forEach((k) => wrap.appendChild(renderNode(k, depth + 1)));
        return wrap;
      }

      const rootEl = $('[data-ld=\"tree-root\"]');
      roots.forEach((r) => rootEl.appendChild(renderNode(r, 0)));
    }

    function openImportExcelDialog() {
      openDialog({
        title: "Import dari Excel Index",
        submitLabel: "Import",
        bodyHtml: `
          <div class="field"><label>File Excel Index (.xlsx)</label><input name="file" type="file" accept=".xlsx,.xlsm" required /></div>
          <div class="field">
            <label>Mode</label>
            <div style="display:flex;flex-direction:column;gap:8px;padding:4px 0">
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="update" ${state.chapters && state.chapters.length ? "checked" : ""} /> Perbarui dari Index baru (gambar & isi manual tetap)
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="append" ${state.chapters && state.chapters.length ? "" : "checked"} /> Tambahkan ke struktur yang sudah ada
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="replace" /> Ganti semua (hapus struktur & isi lama dulu)
              </label>
            </div>
          </div>
          <p class="hint">Format yang dibaca: sheet "Index" (kolom No, Judul Heading, Level, Tipe Konten, Isi/Nama Sheet Rujukan). Isi tabel & paragraf dari sheet rujukan ikut ke-import; block gambar dibuat kosong (upload file gambarnya di sini setelah import). Baris contoh "(contoh)" otomatis dilewati. Mode Perbarui nyocokin bab lewat judulnya: tabel & paragraf diganti data baru, gambar yang udah diupload dan isi yang kamu isi manual (Index cuma TBD) tetap. Kalau gagal di tengah, nggak ada yang berubah.</p>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const upload = new FormData();
          upload.append("mode", fd.get("mode"));
          upload.append("file", fd.get("file"));
          const res = await apiPost(`/projects/${state.currentProjectId}/import-excel`, upload);
          const filled = (res.project_fields || []).length ? ` · data project diisi dari Excel` : "";
          const upd = res.updated ? ` · ${res.updated} bab diperbarui, ${res.kept_blocks} isi lama dipertahankan` : "";
          const extra = (res.not_in_index || []).length
            ? ` · ${res.not_in_index.length} bab nggak ada di Index baru, dibiarkan: ${res.not_in_index.slice(0, 5).join(", ")}${res.not_in_index.length > 5 ? ", ..." : ""}` : "";
          toast(`Import berhasil: ${res.chapters} bab baru, ${res.blocks} block konten${upd}${filled}${extra}`);
          if (filled) { await renderProjectWorkspace($('[data-ld=\"main\"]')); } else { await refreshChapters(); }
        },
      });
    }

    async function moveChapter(chapter, dir) {
      const siblings = chapterChildren(chapter.parent_id);
      const idx = siblings.findIndex((s) => s.id === chapter.id);
      const swapIdx = idx + dir;
      if (swapIdx < 0 || swapIdx >= siblings.length) return;
      const other = siblings[swapIdx];
      await apiPost(`/chapters/${chapter.id}/move`, { parent_id: chapter.parent_id, order_index: other.order_index });
      await apiPost(`/chapters/${other.id}/move`, { parent_id: other.parent_id, order_index: chapter.order_index });
      await refreshChapters();
    }

    async function refreshChapters() {
      state.chapters = await apiGet(`/projects/${state.currentProjectId}/chapters`);
      try {
        const rv = await apiGet(`/projects/${state.currentProjectId}/review`);
        state.reviewMap = Object.fromEntries(rv.chapters.map((c) => [c.id, c]));
      } catch (e) { state.reviewMap = {}; }
      renderTree();
      renderContentPane();
    }

    function openChapterDialog({ parent_id, chapter }) {
      const isEdit = !!chapter;
      openDialog({
        title: isEdit ? "Edit Judul Bab" : "Bab / Sub-bab Baru",
        submitLabel: isEdit ? "Simpan" : "Tambah",
        bodyHtml: `<div class="field"><label>Judul</label><input name="title" required value="${isEdit ? escapeHtml(chapter.title) : ""}" placeholder="mis. Deskripsi Project" /></div>`,
        onSubmit: async (form) => {
          const title = new FormData(form).get("title");
          if (isEdit) {
            await apiPut(`/chapters/${chapter.id}`, { title });
          } else {
            const c = await apiPost(`/projects/${state.currentProjectId}/chapters`, { parent_id, title });
            state.selectedChapterId = c.id;
          }
          toast("Tersimpan");
          await refreshChapters();
        },
      });
    }

    // ---------- content pane (blocks editor) ----------
    async function renderContentPane() {
      const pane = $('[data-ld=\"pane-content\"]');
      if (!state.selectedChapterId) {
        pane.innerHTML = emptyStateHtml("touch_app", "Pilih bab di kiri", "Atau tambah bab baru dulu buat mulai isi konten.");
        return;
      }
      const chapter = state.chapters.find((c) => c.id === state.selectedChapterId);
      state.blocks = await apiGet(`/chapters/${chapter.id}/blocks`);

      pane.innerHTML = `
        <h2 class="section-title">${escapeHtml(chapter.title)}</h2>
        <div class="muted" style="font-size:12.5px;margin-bottom:20px">Level H${chapter.level} &middot; isi konten di bawah ini akan muncul persis di bawah heading-nya di dokumen</div>
        <div data-ld="blocks-list"></div>
        <div class="add-block-row">
          <button class="btn btn-tonal js-add-block" data-type="paragraph"><span class="lg-ic" aria-hidden="true">¶</span> Paragraf</button>
          <button class="btn btn-tonal js-add-block" data-type="table"><span class="lg-ic" aria-hidden="true">▦</span> Tabel</button>
          <button class="btn btn-tonal js-add-block" data-type="image"><span class="lg-ic" aria-hidden="true">▣</span> Gambar</button>
        </div>`;

      $$(".js-add-block", pane).forEach((btn) => {
        btn.addEventListener("click", async () => {
          const type = btn.dataset.type;
          const defaults = {
            paragraph: { paragraphs: [""] },
            table: { headers: ["Kolom 1", "Kolom 2"], rows: [["", ""]] },
            image: { filename: "", caption: "" },
          };
          await apiPost(`/chapters/${chapter.id}/blocks`, { block_type: type, content: defaults[type] });
          await refreshChapters();
        });
      });

      const list = $('[data-ld=\"blocks-list\"]');
      state.blocks.forEach((block) => list.appendChild(renderBlock(block)));
    }

    function renderBlock(block) {
      const card = document.createElement("div");
      card.className = "card block-card";
      const labelMap = { paragraph: "Paragraf", table: "Tabel", image: "Gambar" };
      card.innerHTML = `
        <div class="block-head">
          <span class="block-type-label">${labelMap[block.block_type]}</span>
          <button class="btn-icon btn-danger js-del-block" title="Hapus block"><span class="lg-ic" aria-hidden="true">✕</span></button>
        </div>
        <div class="block-body"></div>`;
      card.querySelector(".js-del-block").addEventListener("click", async () => {
        await apiDel(`/blocks/${block.id}`);
        await refreshChapters();
      });
      const body = card.querySelector(".block-body");
      if (block.block_type === "paragraph") body.appendChild(renderParagraphBlock(block));
      else if (block.block_type === "table") body.appendChild(renderTableBlock(block));
      else body.appendChild(renderImageBlock(block));
      return card;
    }

    function renderParagraphBlock(block) {
      const wrap = document.createElement("div");
      const paragraphs = block.content.paragraphs || [""];
      const save = debounce(async () => {
        await apiPut(`/blocks/${block.id}`, { content: { paragraphs } });
      }, 500);

      function draw() {
        wrap.innerHTML = "";
        paragraphs.forEach((text, i) => {
          const line = document.createElement("div");
          line.className = "paragraph-line";
          line.innerHTML = `<textarea rows="2" placeholder="Tulis paragraf atau satu poin bullet...">${escapeHtml(text)}</textarea>
            <button class="btn-icon btn-danger js-rm" title="Hapus baris"><span class="lg-ic" aria-hidden="true">×</span></button>`;
          line.querySelector("textarea").addEventListener("input", (e) => { paragraphs[i] = e.target.value; save(); });
          line.querySelector(".js-rm").addEventListener("click", () => { paragraphs.splice(i, 1); if (paragraphs.length === 0) paragraphs.push(""); draw(); save(); });
          wrap.appendChild(line);
        });
        const addBtn = document.createElement("button");
        addBtn.className = "btn btn-text";
        addBtn.innerHTML = `<span class="lg-ic" aria-hidden="true">+</span> Tambah baris`;
        addBtn.addEventListener("click", () => { paragraphs.push(""); draw(); save(); });
        wrap.appendChild(addBtn);
      }
      draw();
      return wrap;
    }

    function renderTableBlock(block) {
      const wrap = document.createElement("div");
      const headers = block.content.headers || ["Kolom 1"];
      const rows = block.content.rows || [[""]];
      let caption = block.content.caption || "";
      const save = debounce(async () => {
        await apiPut(`/blocks/${block.id}`, { content: { headers, rows, caption, merges: block.content.merges } });
      }, 500);

      const capField = document.createElement("div");
      capField.className = "field";
      capField.innerHTML = `<label>Caption Tabel (opsional — kalau diisi, otomatis masuk List of Table + penomoran "Tabel N")</label>
        <input class="js-caption" value="${escapeHtml(caption)}" placeholder="mis. BoQ Project" />`;
      capField.querySelector("input").addEventListener("input", (e) => { caption = e.target.value; save(); });
      wrap.appendChild(capField);

      const tableHost = document.createElement("div");
      wrap.appendChild(tableHost);

      function draw() {
        tableHost.innerHTML = "";
        const table = document.createElement("table");
        table.className = "editable-table";
        const thead = document.createElement("thead");
        const htr = document.createElement("tr");
        headers.forEach((h, ci) => {
          const th = document.createElement("th");
          th.innerHTML = `<input value="${escapeHtml(h)}" placeholder="Judul kolom" />`;
          th.querySelector("input").addEventListener("input", (e) => { headers[ci] = e.target.value; save(); });
          htr.appendChild(th);
        });
        const thAction = document.createElement("th");
        thAction.style.width = "36px";
        htr.appendChild(thAction);
        thead.appendChild(htr);
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        rows.forEach((row, ri) => {
          const tr = document.createElement("tr");
          headers.forEach((_, ci) => {
            const td = document.createElement("td");
            td.innerHTML = `<input value="${escapeHtml(row[ci] ?? "")}" />`;
            td.querySelector("input").addEventListener("input", (e) => { row[ci] = e.target.value; save(); });
            tr.appendChild(td);
          });
          const tdAction = document.createElement("td");
          tdAction.innerHTML = `<button class="btn-icon btn-danger js-rm-row" title="Hapus baris"><span class="lg-ic" aria-hidden="true">×</span></button>`;
          tdAction.querySelector("button").addEventListener("click", () => { rows.splice(ri, 1); if (rows.length === 0) rows.push(headers.map(() => "")); draw(); save(); });
          tr.appendChild(tdAction);
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        tableHost.appendChild(table);

        const toolbar = document.createElement("div");
        toolbar.style.cssText = "display:flex;gap:8px;margin-top:10px";
        toolbar.innerHTML = `
          <button class="btn btn-text js-add-row"><span class="lg-ic" aria-hidden="true">+</span> Baris</button>
          <button class="btn btn-text js-add-col"><span class="lg-ic" aria-hidden="true">+</span> Kolom</button>
          ${headers.length > 1 ? `<button class="btn btn-text js-rm-col"><span class="lg-ic" aria-hidden="true">−</span> Kolom</button>` : ""}
        `;
        toolbar.querySelector(".js-add-row").addEventListener("click", () => { rows.push(headers.map(() => "")); draw(); save(); });
        toolbar.querySelector(".js-add-col").addEventListener("click", () => { headers.push(`Kolom ${headers.length + 1}`); rows.forEach((r) => r.push("")); draw(); save(); });
        const rmColBtn = toolbar.querySelector(".js-rm-col");
        if (rmColBtn) rmColBtn.addEventListener("click", () => { headers.pop(); rows.forEach((r) => r.pop()); draw(); save(); });
        tableHost.appendChild(toolbar);
      }
      draw();
      return wrap;
    }

    function renderImageBlock(block) {
      const wrap = document.createElement("div");
      const content = { filename: block.content.filename || "", caption: block.content.caption || "", original_name: block.content.original_name || "" };
      const save = async () => { await apiPut(`/blocks/${block.id}`, { content }); };

      wrap.innerHTML = `
        <div class="js-preview" style="margin-bottom:10px">${content.filename
          ? `<img src="/lld-generator/api/projects/${state.currentProjectId}/images/${encodeURIComponent(content.filename)}" style="max-width:100%;max-height:260px;border:1px solid var(--md-outline-variant);border-radius:8px" />`
          : ""}</div>
        <div class="field">
          <label>File Gambar</label>
          <input type="file" accept="image/*" class="js-file" />
          <span class="hint js-current">${content.filename ? "Saat ini: " + escapeHtml(content.original_name || content.filename) : "Belum ada file dipilih"}</span>
        </div>
        <div class="field"><label>Caption (opsional)</label><input class="js-caption" value="${escapeHtml(content.caption)}" placeholder="mis. Topology Before" /></div>`;

      wrap.querySelector(".js-file").addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const fd = new FormData();
        fd.append("file", file);
        const res = await apiPost(`/projects/${state.currentProjectId}/upload-image`, fd);
        content.filename = res.filename;
        content.original_name = res.original_name;
        wrap.querySelector(".js-current").textContent = "Saat ini: " + res.original_name;
        wrap.querySelector(".js-preview").innerHTML =
          `<img src="/lld-generator/api/projects/${state.currentProjectId}/images/${encodeURIComponent(res.filename)}" style="max-width:100%;max-height:260px;border:1px solid var(--md-outline-variant);border-radius:8px" />`;
        await save();
        toast("Gambar diupload & tersimpan");
      });
      wrap.querySelector(".js-caption").addEventListener("input", debounce((e) => { content.caption = e.target.value; save(); }, 500));
      return wrap;
    }

    async function openReviewDialog() {
      const data = await apiGet(`/projects/${state.currentProjectId}/review`);
      const chapterNumbers = computeChapterNumbers(data.chapters);
      const rows = data.chapters.map((c) => {
        const num = chapterNumbers[c.id];
        let status;
        if (c.is_group) {
          status = `<span class="chip" style="background:var(--md-surface-container-highest);color:var(--md-on-surface-variant)">grup</span>`;
        } else if (c.block_types.length) {
          const t = {};
          c.block_types.forEach((x) => (t[x] = (t[x] || 0) + 1));
          const label = Object.entries(t).map(([k, v]) => `${v} ${k === "paragraph" ? "paragraf" : k === "table" ? "tabel" : "gambar"}`).join(", ");
          status = `<span class="chip" style="background:#C8E6C9;color:#1B5E20">✓ ${label}</span>`;
        } else {
          status = `<span class="chip" style="background:var(--md-error-container);color:var(--md-on-error-container)">belum diisi</span>`;
        }
        return `<div style="display:flex;align-items:center;gap:10px;padding:6px 4px 6px ${(c.level - 1) * 18 + 4}px;border-bottom:1px solid var(--md-outline-variant)">
          <span class="num muted" style="min-width:52px;font-variant-numeric:tabular-nums">${num}</span>
          <span style="flex:1">${escapeHtml(c.title)}</span>
          ${status}
        </div>`;
      }).join("");

      openDialog({
        title: "Review Dokumen",
        submitLabel: "Tutup",
        wide: true,
        bodyHtml: `
          <div style="display:flex;gap:12px;margin-bottom:16px">
            <div class="card" style="flex:1;text-align:center;padding:12px">
              <div style="font-size:24px;font-weight:700;color:#1B5E20">${data.leaf_filled}</div>
              <div class="hint">bab terisi</div>
            </div>
            <div class="card" style="flex:1;text-align:center;padding:12px">
              <div style="font-size:24px;font-weight:700;color:var(--md-error)">${data.leaf_empty}</div>
              <div class="hint">bab belum diisi</div>
            </div>
          </div>
          <div style="max-height:50vh;overflow-y:auto;border:1px solid var(--md-outline-variant);border-radius:8px;padding:4px 8px;font-size:13px">
            ${rows || '<div class="muted" style="padding:12px">Belum ada bab.</div>'}
          </div>
          <p class="hint" style="margin-top:10px">Baris "grup" = heading pengelompokan yang isinya ada di sub-bab, tidak perlu diisi langsung.</p>`,
        onSubmit: async () => {},
      });
    }

    function debounce(fn, ms) {
      let t;
      return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    // ---------- project settings + generate ----------
    function openProjectSettingsDialog() {
      const p = state.currentProject;
      openDialog({
        title: "Pengaturan Project",
        submitLabel: "Simpan",
        bodyHtml: `
          <div class="field"><label>Nama Project</label><input name="name" required value="${escapeHtml(p.name)}" /></div>
          <div class="field-row">
            <div class="field"><label>Client</label><input name="client" value="${escapeHtml(p.client || "")}" /></div>
            <div class="field"><label>Versi</label><input name="version" value="${escapeHtml(p.version)}" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Kode Project</label><input name="project_code" value="${escapeHtml(p.project_code || "")}" /></div>
            <div class="field"><label>Disusun oleh</label><input name="prepared_by" value="${escapeHtml(p.prepared_by || "")}" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Perusahaan</label><input name="company" value="${escapeHtml(p.company || "Multipolar Technology")}" /></div>
            <div class="field"><label>Tanggal Dokumen</label><input name="doc_date" value="${escapeHtml(p.doc_date || "")}" placeholder="kosong = tanggal generate" /></div>
          </div>
          <div class="field"><label>Logo Customer (cover) ${p.logo ? "· sudah ada, upload lagi buat ganti" : "· belum ada"}</label>
            <input type="file" name="logo_file" accept="image/png,image/jpeg" /></div>
          <p class="muted" style="font-size:12px;margin:-4px 0 10px">Dipakai buat placeholder master template: {{project_name}}, {{customer}}, {{project_code}}, {{version}}, {{date}}, {{company}}, {{prepared_by}}.</p>
          <div class="field">
            <label>Master Template</label>
            <select name="template_id">
              ${state.templates.map((t) => `<option value="${t.id}" ${t.id === p.template_id ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}
            </select>
          </div>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          let logo;
          const logoFile = fd.get("logo_file");
          if (logoFile && logoFile.size) {
            const up = new FormData();
            up.append("file", logoFile);
            logo = (await apiPost(`/projects/${p.id}/upload-image`, up)).filename;
          }
          await apiPut(`/projects/${p.id}`, {
            ...(logo ? { logo } : {}),
            name: fd.get("name"), client: fd.get("client") || "", version: fd.get("version") || "0.1",
            template_id: Number(fd.get("template_id")),
            project_code: fd.get("project_code") || "", prepared_by: fd.get("prepared_by") || "",
            company: fd.get("company") || "Multipolar Technology", doc_date: fd.get("doc_date") || "",
          });
          toast("Pengaturan disimpan");
          await renderProjectWorkspace($('[data-ld=\"main\"]'));
        },
      });
    }

    async function handleGenerate() {
      const btn = $('[data-ld=\"btn-generate\"]');
      btn.disabled = true;
      btn.innerHTML = `<span class="lg-ic" aria-hidden="true">…</span> Generating...`;
      try {
        const res = await apiPost(`/projects/${state.currentProjectId}/generate`, {});
        const a = document.createElement("a");
        a.href = res.download_url;
        a.download = res.filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        if (res.warnings && res.warnings.length) {
          toast(`Dokumen tergenerate, tapi: ${res.warnings.join(" ")}`, true);
        } else {
          toast("Dokumen berhasil digenerate!");
        }
      } catch (e) {
        toast(e.message, true);
      } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="lg-ic" aria-hidden="true">⤓</span> Generate &amp; Download`;
      }
    }

    // ===================== boot =====================
    const wanted = Number(new URLSearchParams(location.search).get("project"));
    if (wanted) { state.currentProjectId = wanted; state.view = "project"; }
    render();
    page.lgOpenProject = (id) => { state.currentProjectId = id; switchView("project"); };

    // ---------- import from the old Document Generator (one time) ----------
    $('[data-ld="legacy"]').addEventListener("click", async () => {
      let found = "";
      try { found = (await apiGet("/legacy")).folder || ""; } catch (e) { /* none found */ }
      openDialog({
        title: "Import from the old Document Generator",
        submitLabel: "Import",
        bodyHtml: `
          <div class="field"><label>Document Generator folder (with backend/storage/app.db)</label>
            <input name="folder" value="${escapeHtml(found)}" placeholder="/Volumes/Work/Tools/Document_Generator/lld_generator_v1.0.5" /></div>
          <p class="hint">Templates, projects, chapters, content and images are copied. The old app is only read, never changed. Running it again only adds what is new.</p>`,
        onSubmit: async (form) => {
          const res = await apiPost("/legacy-import", { folder: new FormData(form).get("folder") || null });
          const missing = (res.missing_files || []).length ? ` · ${res.missing_files.length} file(s) missing` : "";
          toast(`Imported ${res.projects} project(s), ${res.templates} template(s), ${res.chapters} chapters, ${res.images} images${res.skipped_projects ? ` · ${res.skipped_projects} already here` : ""}${missing}`);
          state.currentProjectId = null;
          switchView("projects");
        },
      });
    });
  }

  function boot() { document.querySelectorAll(".lg-page:not(.lg-dialog-host)").forEach(init); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  new MutationObserver(boot).observe(document.body, { childList: true, subtree: true });
})();
