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
    function openDialog({ title, bodyHtml, submitLabel = "Save", onSubmit, wide = false }) {
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
              <button type="button" class="btn btn-text" data-ld="dlg-cancel">Cancel</button>
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
          title: "Confirm",
          bodyHtml: `<p style="margin:0 0 4px;color:var(--md-on-surface-variant)">${escapeHtml(message)}</p>`,
          submitLabel: "Yes, continue",
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
            <div class="subtitle">Your LLD documents</div>
          </div>
          <button class="btn btn-filled" data-ld="btn-new-project">
            <span class="lg-ic" aria-hidden="true">+</span> Project Baru
          </button>
        </div>
        <div class="content-area">
          ${state.projects.length === 0 ? emptyStateHtml("folder_off", "No projects yet", "Open an index from LLD Index, or create a project here.") : `
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
          const ok = await confirmDialog("Delete this project with all its chapters and content? This cannot be undone.");
          if (!ok) return;
          await apiDel(`/projects/${el.dataset.id}`);
          toast("Project deleted.");
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
            <button class="btn-icon btn-danger js-delete-project" data-id="${p.id}" title="Delete">
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
        toast("Upload a master template in Templates first.", true);
        return;
      }
      openDialog({
        title: "New project",
        submitLabel: "Create",
        bodyHtml: `
          <div class="field"><label>Project name</label><input name="name" required placeholder="Switch Replacement" /></div>
          <div class="field-row">
            <div class="field"><label>Client</label><input name="client" placeholder="PT Toyota Astra Motor" /></div>
            <div class="field"><label>Version</label><input name="version" value="0.1" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Project code</label><input name="project_code" placeholder="7TAMO26009001" /></div>
            <div class="field"><label>Prepared by</label><input name="prepared_by" placeholder="Document writer" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Company</label><input name="company" value="Multipolar Technology" /></div>
            <div class="field"><label>Document date</label><input name="doc_date" placeholder="blank = day of generating" /></div>
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
          toast("Project created.");
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
            <div class="subtitle">Master .docx files (cover, branding, heading styles) for your projects</div>
          </div>
          <button class="btn btn-filled" data-ld="btn-new-template">
            <span class="lg-ic" aria-hidden="true">⤒</span> Upload Template
          </button>
        </div>
        <div class="content-area">
          ${state.templates.length === 0 ? emptyStateHtml("layers_clear", "No templates yet", "Upload the master .docx you want to reuse.") : `
          <div class="grid-cards">
            ${state.templates.map(templateCardHtml).join("")}
          </div>`}
        </div>`;

      $('[data-ld=\"btn-new-template\"]').addEventListener("click", openNewTemplateDialog);
      $$(".js-delete-template", main).forEach((el) => {
        el.addEventListener("click", async (e) => {
          e.stopPropagation();
          const ok = await confirmDialog("Delete this template?");
          if (!ok) return;
          await apiDel(`/templates/${el.dataset.id}`);
          toast("Template deleted.");
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
              <button class="btn-icon js-edit-template" data-id="${t.id}" title="Settings"><span class="lg-ic" aria-hidden="true">⚙</span></button>
              <button class="btn-icon btn-danger js-delete-template" data-id="${t.id}" title="Delete"><span class="lg-ic" aria-hidden="true">✕</span></button>
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
        title: "Upload a master template",
        submitLabel: "Upload",
        bodyHtml: `
          <div class="field"><label>Template name</label><input name="name" required placeholder="LLD Master Template" /></div>
          <div class="field"><label>.docx file</label><input name="file" type="file" accept=".docx" required /></div>
          <p class="hint">The file is checked for heading styles after upload. The closing heading and numbering can be changed afterwards.</p>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const upload = new FormData();
          upload.append("name", fd.get("name"));
          upload.append("closing_heading", "");
          upload.append("auto_numbered_levels", "[1,2]");
          upload.append("file", fd.get("file"));
          const t = await apiPost("/templates", upload);
          toast("Template uploaded.");
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
        title: `Template: ${t.name}`,
        submitLabel: "Save",
        wide: true,
        bodyHtml: `
          <div class="field"><label>Template name</label><input name="name" value="${escapeHtml(t.name)}" required /></div>

          <div class="field">
            <label>Closing heading (optional)</label>
            <input name="closing_heading" list="closing-options" value="${escapeHtml(t.closing_heading || "")}"
              placeholder="Document Acceptance (blank = none)" />
            <datalist data-ld="closing-options">
              ${[...new Set(outline.filter((o) => o.style === "Heading1").map((o) => o.text))]
                .map((x) => `<option value="${escapeHtml(x)}">`).join("")}
            </datalist>
            <span class="hint">Everything from this heading on is kept from the template, such as the Document Acceptance page.</span>
          </div>

          <div class="field">
            <label>Heading levels numbered by Word</label>
            <div style="display:flex;gap:14px;flex-wrap:wrap;padding:8px 0">
              ${availableLevels.map((lvl) => `
                <label style="display:flex;align-items:center;gap:6px;font-size:13px;font-weight:400">
                  <input type="checkbox" name="auto_level" value="${lvl}" ${currentAuto.has(lvl) ? "checked" : ""} /> Heading ${lvl}
                </label>`).join("")}
            </div>
            <span class="hint">Tick the levels Word already numbers (usually H1 and H2). Unticked levels get a 1.2.3 number written in front of the title.</span>
          </div>

          <div class="field-row">
            <div class="field"><label>Picture caption label</label><input name="figure_seq_name" value="${escapeHtml(t.figure_seq_name || "Picture")}" /></div>
            <div class="field"><label>Table caption label</label><input name="table_seq_name" value="${escapeHtml(t.table_seq_name || "Table")}" /></div>
          </div>
          <p class="hint" style="margin-top:-10px">Must match the caption label the template's List of Pictures / List of Tables uses (Word default: Figure / Table).</p>

          <div class="field">
            <label>Template outline (for reference)</label>
            <div style="max-height:160px;overflow-y:auto;border:1px solid var(--md-outline-variant);border-radius:8px;padding:8px 12px;font-size:12.5px;line-height:1.8">
              ${outline.length === 0 ? '<span class="muted">No headings after the first Heading 1.</span>' :
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
            figure_seq_name: fd.get("figure_seq_name") || "Picture",
            table_seq_name: fd.get("table_seq_name") || "Table",
          });
          toast("Template saved.");
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
            <button class="btn btn-text lg-back" data-ld="btn-back"><span class="lg-ic" aria-hidden="true">←</span> Projects</button>
            <div style="font-size:21px;font-weight:600">${escapeHtml(p.name)}</div>
            <div class="subtitle">${escapeHtml(p.client || "-")} &middot; v${escapeHtml(p.version)}</div>
          </div>
          <div style="display:flex;gap:8px">
            <label class="btn btn-outlined" title="Upload several pictures; each goes to the empty picture whose chapter matches its file name">
              <span class="lg-ic" aria-hidden="true">⤒</span> Pictures
              <input type="file" data-ld="bulk-pictures" accept="image/*,.svg" multiple hidden></label>
            <button class="btn btn-tonal" data-ld="btn-review"><span class="lg-ic" aria-hidden="true">✓</span> Review</button>
            <button class="btn btn-outlined" data-ld="btn-project-settings"><span class="lg-ic" aria-hidden="true">⚙</span> Settings</button>
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
      $('[data-ld="bulk-pictures"]').addEventListener("change", async (e) => {
        const files = [...e.target.files];
        e.target.value = "";
        if (!files.length) return;
        const fd = new FormData();
        for (const f of files) fd.append("files", await asPicture(f));
        try {
          const res = await apiPost(`/projects/${pid}/pictures`, fd);
          const miss = res.unmatched.length ? ` · not matched: ${res.unmatched.join(", ")} (name the file after its chapter, or drop it in the chapter)` : "";
          toast(`${res.placed.length} picture(s) placed${miss}`, !!res.unmatched.length && !res.placed.length);
          await renderProjectWorkspace($('[data-ld="main"]'));
        } catch (err) { toast(err.message, true); }
      });

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
          <h3>Chapters</h3>
          <button class="btn-icon" data-ld="btn-add-root" title="Add a chapter"><span class="lg-ic" aria-hidden="true">+</span></button>
        </div>
        <button class="btn btn-outlined" data-ld="btn-import-excel" style="width:100%;justify-content:center;margin-bottom:14px">
          <span class="lg-ic" aria-hidden="true">⤒</span> Import dari Excel Index
        </button>
        <div data-ld="tree-root"></div>
        ${roots.length === 0 ? `<div class="muted" style="font-size:12.5px;padding:8px 4px">No chapters yet. Open an index from LLD Index, import an Excel index, or add a chapter with +.</div>` : ""}
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
          ? `<span class="lg-dot bad" title="Empty"></span>`
          : rv && !rv.is_group && (rv.todo || []).length ? `<span class="lg-dot warn" title="${escapeHtml([...new Set(rv.todo)].join(", "))}"></span>` : "";
        row.innerHTML = `
          <span class="num">${num}</span>
          <span class="title">${escapeHtml(chapter.title)}</span>
          ${emptyDot}
          <span class="row-actions">
            <button class="btn-icon js-add-child" title="Add a sub-chapter"><span class="lg-ic" aria-hidden="true">+</span></button>
            <button class="btn-icon js-edit-ch" title="Rename"><span class="lg-ic" aria-hidden="true">✎</span></button>
            <button class="btn-icon js-up" title="Move up"><span class="lg-ic" aria-hidden="true">↑</span></button>
            <button class="btn-icon js-down" title="Move down"><span class="lg-ic" aria-hidden="true">↓</span></button>
            <button class="btn-icon btn-danger js-del-ch" title="Delete"><span class="lg-ic" aria-hidden="true">✕</span></button>
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
          const ok = await confirmDialog(`Delete "${chapter.title}" with its sub-chapters and content?`);
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
        title: "Import an Excel index",
        submitLabel: "Import",
        bodyHtml: `
          <div class="field"><label>Excel index (.xlsx)</label><input name="file" type="file" accept=".xlsx,.xlsm" required /></div>
          <div class="field">
            <label>Mode</label>
            <div style="display:flex;flex-direction:column;gap:8px;padding:4px 0">
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="update" ${state.chapters && state.chapters.length ? "checked" : ""} /> Update from the new index (pictures and manual edits stay)
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="append" ${state.chapters && state.chapters.length ? "" : "checked"} /> Add to the existing chapters
              </label>
              <label style="display:flex;align-items:center;gap:8px;font-weight:400;font-size:13.5px">
                <input type="radio" name="mode" value="replace" /> Replace everything
              </label>
            </div>
          </div>
          <p class="hint">An LLD Content Index workbook (sheet "Index"). Update matches chapters by title: tables and text take the new data, uploaded pictures and text you typed (where the index only says TBD) stay. A failed import changes nothing.</p>`,
        onSubmit: async (form) => {
          const fd = new FormData(form);
          const upload = new FormData();
          upload.append("mode", fd.get("mode"));
          upload.append("file", fd.get("file"));
          const res = await apiPost(`/projects/${state.currentProjectId}/import-excel`, upload);
          const filled = (res.project_fields || []).length ? ` · project details filled from the Excel` : "";
          const upd = res.updated ? ` · ${res.updated} chapters updated, ${res.kept_blocks} pictures/edits kept` : "";
          const extra = (res.not_in_index || []).length
            ? ` · ${res.not_in_index.length} chapters not in the index kept: ${res.not_in_index.slice(0, 5).join(", ")}${res.not_in_index.length > 5 ? ", ..." : ""}` : "";
          toast(`Imported: ${res.chapters} new chapters, ${res.blocks} blocks${upd}${filled}${extra}`);
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
        title: isEdit ? "Rename chapter" : "New chapter",
        submitLabel: isEdit ? "Save" : "Add",
        bodyHtml: `<div class="field"><label>Title</label><input name="title" required value="${isEdit ? escapeHtml(chapter.title) : ""}" placeholder="Project Description" /></div>`,
        onSubmit: async (form) => {
          const title = new FormData(form).get("title");
          if (isEdit) {
            await apiPut(`/chapters/${chapter.id}`, { title });
          } else {
            const c = await apiPost(`/projects/${state.currentProjectId}/chapters`, { parent_id, title });
            state.selectedChapterId = c.id;
          }
          toast("Saved.");
          await refreshChapters();
        },
      });
    }

    // ---------- content pane (blocks editor) ----------
    async function renderContentPane() {
      const pane = $('[data-ld=\"pane-content\"]');
      if (!state.selectedChapterId) {
        pane.innerHTML = emptyStateHtml("touch_app", "Pick a chapter on the left", "Or add a chapter to start writing.");
        return;
      }
      const chapter = state.chapters.find((c) => c.id === state.selectedChapterId);
      state.blocks = await apiGet(`/chapters/${chapter.id}/blocks`);

      pane.innerHTML = `
        <h2 class="section-title">${escapeHtml(chapter.title)}</h2>
        <div class="muted" style="font-size:12.5px;margin-bottom:20px">Level H${chapter.level} &middot; content below appears under this heading in the document</div>
        <div data-ld="blocks-list"></div>
        <div class="add-block-row">
          <button class="btn btn-tonal js-add-block" data-type="paragraph"><span class="lg-ic" aria-hidden="true">¶</span> Text</button>
          <button class="btn btn-tonal js-add-block" data-type="table"><span class="lg-ic" aria-hidden="true">▦</span> Table</button>
          <button class="btn btn-tonal js-add-block" data-type="image"><span class="lg-ic" aria-hidden="true">▣</span> Picture</button>
        </div>`;

      $$(".js-add-block", pane).forEach((btn) => {
        btn.addEventListener("click", async () => {
          const type = btn.dataset.type;
          const defaults = {
            paragraph: { paragraphs: [""] },
            table: { headers: ["Column 1", "Column 2"], rows: [["", ""]] },
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
      const labelMap = { paragraph: "Text", table: "Table", image: "Picture" };
      card.innerHTML = `
        <div class="block-head">
          <span class="block-type-label">${labelMap[block.block_type]}</span>
          <button class="btn-icon btn-danger js-del-block" title="Remove block"><span class="lg-ic" aria-hidden="true">✕</span></button>
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
          line.innerHTML = `<textarea rows="2" placeholder="A paragraph or one bullet point">${escapeHtml(text)}</textarea>
            <button class="btn-icon btn-danger js-rm" title="Remove row"><span class="lg-ic" aria-hidden="true">×</span></button>`;
          line.querySelector("textarea").addEventListener("input", (e) => { paragraphs[i] = e.target.value; save(); });
          line.querySelector(".js-rm").addEventListener("click", () => { paragraphs.splice(i, 1); if (paragraphs.length === 0) paragraphs.push(""); draw(); save(); });
          wrap.appendChild(line);
        });
        const addBtn = document.createElement("button");
        addBtn.className = "btn btn-text";
        addBtn.innerHTML = `<span class="lg-ic" aria-hidden="true">+</span> Add row`;
        addBtn.addEventListener("click", () => { paragraphs.push(""); draw(); save(); });
        wrap.appendChild(addBtn);
      }
      draw();
      return wrap;
    }

    function renderTableBlock(block) {
      const wrap = document.createElement("div");
      const headers = block.content.headers || ["Column 1"];
      const rows = block.content.rows || [[""]];
      let caption = block.content.caption || "";
      const save = debounce(async () => {
        await apiPut(`/blocks/${block.id}`, { content: { headers, rows, caption, merges: block.content.merges } });
      }, 500);

      const capField = document.createElement("div");
      capField.className = "field";
      capField.innerHTML = `<label>Table caption (optional, numbered and listed in the List of Tables)</label>
        <input class="js-caption" value="${escapeHtml(caption)}" placeholder="Bill of Quantity" />`;
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
          th.innerHTML = `<input value="${escapeHtml(h)}" placeholder="Column title" />`;
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
          tdAction.innerHTML = `<button class="btn-icon btn-danger js-rm-row" title="Remove row"><span class="lg-ic" aria-hidden="true">×</span></button>`;
          tdAction.querySelector("button").addEventListener("click", () => { rows.splice(ri, 1); if (rows.length === 0) rows.push(headers.map(() => "")); draw(); save(); });
          tr.appendChild(tdAction);
          tbody.appendChild(tr);
        });
        table.appendChild(tbody);
        tableHost.appendChild(table);

        const toolbar = document.createElement("div");
        toolbar.style.cssText = "display:flex;gap:8px;margin-top:10px";
        toolbar.innerHTML = `
          <button class="btn btn-text js-add-row"><span class="lg-ic" aria-hidden="true">+</span> Row</button>
          <button class="btn btn-text js-add-col"><span class="lg-ic" aria-hidden="true">+</span> Column</button>
          ${headers.length > 1 ? `<button class="btn btn-text js-rm-col"><span class="lg-ic" aria-hidden="true">−</span> Column</button>` : ""}
        `;
        toolbar.querySelector(".js-add-row").addEventListener("click", () => { rows.push(headers.map(() => "")); draw(); save(); });
        toolbar.querySelector(".js-add-col").addEventListener("click", () => { headers.push(`Column ${headers.length + 1}`); rows.forEach((r) => r.push("")); draw(); save(); });
        const rmColBtn = toolbar.querySelector(".js-rm-col");
        if (rmColBtn) rmColBtn.addEventListener("click", () => { headers.pop(); rows.forEach((r) => r.pop()); draw(); save(); });
        tableHost.appendChild(toolbar);
      }
      draw();
      return wrap;
    }

    // SVG (e.g. a Topology Builder diagram) is drawn to a PNG in the browser:
    // Word does not take SVG pictures, and this needs no extra tool.
    async function asPicture(file) {
      if (!/\.svg$/i.test(file.name) && file.type !== "image/svg+xml") return file;
      const url = URL.createObjectURL(file);
      try {
        const img = await new Promise((ok, bad) => { const i = new Image(); i.onload = () => ok(i); i.onerror = bad; i.src = url; });
        const scale = 2, w = img.naturalWidth || 1600, h = img.naturalHeight || 900;
        const canvas = document.createElement("canvas");
        canvas.width = w * scale; canvas.height = h * scale;
        const ctx = canvas.getContext("2d");
        ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        const blob = await new Promise(ok => canvas.toBlob(ok, "image/png"));
        return new File([blob], file.name.replace(/\.svg$/i, ".png"), { type: "image/png" });
      } finally { URL.revokeObjectURL(url); }
    }

    function renderImageBlock(block) {
      const wrap = document.createElement("div");
      const content = { filename: block.content.filename || "", caption: block.content.caption || "", original_name: block.content.original_name || "" };
      const save = async () => { await apiPut(`/blocks/${block.id}`, { content }); };
      const preview = () => content.filename
        ? `<img src="/lld-generator/api/projects/${state.currentProjectId}/images/${encodeURIComponent(content.filename)}" alt="" />`
        : `<span><strong>Drop a picture here, paste it (Ctrl/Cmd+V) or click to choose</strong><small>PNG, JPG or SVG (a Topology Builder diagram works)</small></span>`;

      wrap.innerHTML = `
        <label class="lg-drop${content.filename ? " has-image" : ""}" tabindex="0">
          <input type="file" accept="image/*,.svg" class="js-file" hidden />
          <span class="js-preview">${preview()}</span>
        </label>
        <div class="hint js-current" style="margin:6px 0 12px">${content.filename ? "Current: " + escapeHtml(content.original_name || content.filename) + " · drop or paste another to replace it" : ""}</div>
        <div class="field"><label>Caption (optional)</label><input class="js-caption" value="${escapeHtml(content.caption)}" placeholder="Topology Before" /></div>`;

      const zone = wrap.querySelector(".lg-drop");
      const upload = async (file) => {
        if (!file) return;
        try {
          const picture = await asPicture(file);
          const fd = new FormData();
          fd.append("file", picture);
          const res = await apiPost(`/projects/${state.currentProjectId}/upload-image`, fd);
          content.filename = res.filename;
          content.original_name = res.original_name;
          zone.classList.add("has-image");
          wrap.querySelector(".js-preview").innerHTML = preview();
          wrap.querySelector(".js-current").textContent = "Current: " + res.original_name + " · drop or paste another to replace it";
          await save();
          toast("Picture saved.");
        } catch (err) { toast(err.message, true); }
      };
      wrap.querySelector(".js-file").addEventListener("change", (e) => upload(e.target.files[0]));
      ["dragenter", "dragover"].forEach(ev => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add("is-over"); }));
      ["dragleave", "drop"].forEach(ev => zone.addEventListener(ev, () => zone.classList.remove("is-over")));
      zone.addEventListener("drop", (e) => { e.preventDefault(); upload(e.dataTransfer.files[0]); });
      zone.addEventListener("paste", (e) => {
        const item = [...((e.clipboardData && e.clipboardData.items) || [])].find(i => i.type.startsWith("image/"));
        if (!item) return;
        e.preventDefault();
        const blob = item.getAsFile();
        upload(new File([blob], `pasted-${Date.now()}.png`, { type: blob.type || "image/png" }));
      });
      zone.addEventListener("mouseenter", () => zone.focus({ preventScroll: true }));
      wrap.querySelector(".js-caption").addEventListener("input", debounce((e) => { content.caption = e.target.value; save(); }, 500));
      return wrap;
    }

    async function openReviewDialog() {
      const data = await apiGet(`/projects/${state.currentProjectId}/review`);
      const numbers = computeChapterNumbers(data.chapters);
      const work = data.chapters.filter((c) => !c.is_group && (!c.block_types.length || c.todo.length));
      const rows = work.map((c) => {
        const what = c.block_types.length ? [...new Set(c.todo)].join(", ") : "no content";
        return `<button type="button" class="lg-todo" data-chapter="${c.id}">
          <span class="num">${numbers[c.id]}</span><span class="title">${escapeHtml(c.title)}</span>
          <span class="chip ${c.block_types.length ? "chip-warn" : "chip-bad"}">${escapeHtml(what)}</span></button>`;
      }).join("");
      const close = openDialog({
        title: "Review",
        submitLabel: "Close",
        wide: true,
        bodyHtml: `
          <div class="lg-stats">
            <div class="card"><b class="ok">${data.leaf_filled}</b><span class="hint">done</span></div>
            <div class="card"><b class="warn">${data.leaf_todo}</b><span class="hint">to finish (TBD or picture)</span></div>
            <div class="card"><b class="bad">${data.leaf_empty}</b><span class="hint">empty</span></div>
          </div>
          ${work.length ? `<p class="hint" style="margin:0 0 8px">Click a chapter to open it.</p>
            <div class="lg-todo-list">${rows}</div>` : `<p class="muted">Nothing left to do. Generate the document.</p>`}`,
        onSubmit: async () => {},
      });
      document.querySelectorAll(".lg-dialog-host .lg-todo").forEach((el) => el.addEventListener("click", () => {
        state.selectedChapterId = Number(el.dataset.chapter);
        close();
        renderTree();
        renderContentPane();
      }));
    }

    function debounce(fn, ms) {
      let t;
      return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
    }

    // ---------- project settings + generate ----------
    function approverRow(side, a = {}) {
      const ph = side === "customer" ? "Company (blank = Client)" : "PT. Multipolar Technology Tbk.";
      return `<div class="lg-appr-row" data-side="${side}">
        <input data-k="name" value="${escapeHtml(a.name || "")}" placeholder="Name" aria-label="Name" />
        <input data-k="title" value="${escapeHtml(a.title || "")}" placeholder="Title / position" aria-label="Title" />
        <input data-k="company" value="${escapeHtml(a.company || "")}" placeholder="${ph}" aria-label="Company" />
        <button type="button" class="btn-icon btn-danger js-appr-rm" title="Remove"><span class="lg-ic" aria-hidden="true">×</span></button></div>`;
    }

    function wireApprovers() {
      const host = document.querySelector(".lg-dialog-host");
      const bind = (scope) => scope.querySelectorAll(".js-appr-rm").forEach((b) => { b.onclick = () => b.closest(".lg-appr-row").remove(); });
      bind(host);
      host.querySelectorAll(".js-appr-add").forEach((btn) => btn.addEventListener("click", () => {
        const list = host.querySelector(`.lg-appr-list[data-side="${btn.dataset.side}"]`);
        list.insertAdjacentHTML("beforeend", approverRow(btn.dataset.side));
        bind(list);
        list.lastElementChild.querySelector("input").focus();
      }));
    }

    function readApprovers() {
      const host = document.querySelector(".lg-dialog-host");
      return [...host.querySelectorAll(".lg-appr-row")].map((row) => ({
        side: row.dataset.side,
        ...Object.fromEntries([...row.querySelectorAll("input[data-k]")].map((i) => [i.dataset.k, i.value.trim()])),
      }));
    }

    async function openProjectSettingsDialog() {
      const p = state.currentProject;
      let appr = { approvers: [], from: "project" };
      try { appr = await apiGet(`/projects/${p.id}/approvers`); } catch (e) { /* section starts empty */ }
      const people = (side) => appr.approvers.filter((a) => a.side === side).map((a) => approverRow(side, a)).join("");
      openDialog({
        title: "Project settings",
        submitLabel: "Save",
        wide: true,
        bodyHtml: `
          <div class="field"><label>Project name</label><input name="name" required value="${escapeHtml(p.name)}" /></div>
          <div class="field-row">
            <div class="field"><label>Client</label><input name="client" value="${escapeHtml(p.client || "")}" /></div>
            <div class="field"><label>Version</label><input name="version" value="${escapeHtml(p.version)}" /></div>
          </div>
          <div class="field"><label>Change note <small class="hint">for the Release History when the version changes</small></label><input name="change_note" placeholder="Update after site survey" /></div>
          <div class="field-row">
            <div class="field"><label>Project code</label><input name="project_code" value="${escapeHtml(p.project_code || "")}" /></div>
            <div class="field"><label>Prepared by</label><input name="prepared_by" value="${escapeHtml(p.prepared_by || "")}" /></div>
          </div>
          <div class="field-row">
            <div class="field"><label>Company</label><input name="company" value="${escapeHtml(p.company || "Multipolar Technology")}" /></div>
            <div class="field"><label>Document date</label><input name="doc_date" value="${escapeHtml(p.doc_date || "")}" placeholder="blank = day of generating" /></div>
          </div>
          <div class="field"><label>Customer logo (cover) ${p.logo ? "· uploaded, pick another to replace it" : "· not uploaded"}</label>
            <input type="file" name="logo_file" accept="image/png,image/jpeg" /></div>
          <p class="muted" style="font-size:12px;margin:-4px 0 10px">Used for the master template placeholders: {{project_name}}, {{customer}}, {{project_code}}, {{version}}, {{date}}, {{company}}, {{prepared_by}}.</p>
          <div class="field">
            <label>Master Template</label>
            <select name="template_id">
              ${state.templates.map((t) => `<option value="${t.id}" ${t.id === p.template_id ? "selected" : ""}>${escapeHtml(t.name)}</option>`).join("")}
            </select>
          </div>
          <div class="lg-appr">
            <h3>Approvers <small class="hint">Document Approval page${appr.from === "remembered" ? " · filled from earlier projects, check and save" : ""}</small></h3>
            <div class="lg-appr-head"><span>Customer</span><button type="button" class="btn btn-text js-appr-add" data-side="customer">+ Add</button></div>
            <div class="lg-appr-list" data-side="customer">${people("customer")}</div>
            <div class="lg-appr-head"><span>Multipolar</span><button type="button" class="btn btn-text js-appr-add" data-side="multipolar">+ Add</button></div>
            <div class="lg-appr-list" data-side="multipolar">${people("multipolar")}</div>
            <label class="lg-appr-default"><input type="checkbox" name="multipolar_default" /> Use these Multipolar approvers for new projects</label>
            <p class="hint">Customer approvers are remembered per customer, so the next project for the same customer starts with them. Date and signature stay empty for signing.</p>
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
            change_note: fd.get("change_note") || "",
            company: fd.get("company") || "Multipolar Technology", doc_date: fd.get("doc_date") || "",
          });
          await apiPut(`/projects/${p.id}/approvers`, { approvers: readApprovers(), multipolar_default: fd.get("multipolar_default") === "on" });
          toast("Settings saved.");
          await renderProjectWorkspace($('[data-ld=\"main\"]'));
        },
      });
      wireApprovers();
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
          toast(`Document generated. Check: ${res.warnings.join(" ")}`, true);
        } else {
          toast("Document generated.");
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
