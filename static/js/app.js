window.NES = {
  escape(value) {
    return String(value ?? "").replace(/[&<>'"]/g, character => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
    })[character]);
  },
  toast(message, type = "success") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.setAttribute("role", type === "error" ? "alert" : "status");
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4500);
  },
  setLoading(button, loading, text = "Processing...") {
    if (!button) return;
    if (loading) {
      button.dataset.originalText = button.innerHTML;
      button.disabled = true;
      button.innerHTML = text;
    } else {
      button.disabled = false;
      button.innerHTML = button.dataset.originalText || button.innerHTML;
    }
  },
  async copyText(text) {
    await navigator.clipboard.writeText(text);
    this.toast("Copied to clipboard.");
  }
};

document.addEventListener("click", event => {
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  const target = document.getElementById(button.dataset.copy);
  if (target) window.NES.copyText(target.textContent || "");
});

(() => {
  const toggle = document.getElementById("theme-toggle");
  if (!toggle) return;
  toggle.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    toggle.setAttribute("aria-label", `Switch to ${current} theme`);
    toggle.setAttribute("aria-pressed", String(next === "light"));
    try { localStorage.setItem("nes-theme", next); } catch (e) {}
  });
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  toggle.setAttribute("aria-label", `Switch to ${current === "dark" ? "light" : "dark"} theme`);
  toggle.setAttribute("aria-pressed", String(current === "light"));
})();

(() => {
  const menu = document.getElementById("mobile-menu");
  const close = document.getElementById("sidebar-close");
  const scrim = document.getElementById("sidebar-scrim");
  const sidebar = document.getElementById("suite-sidebar");
  if (!menu || !sidebar) return;
  const setOpen = open => {
    document.body.classList.toggle("sidebar-open", open);
    menu.setAttribute("aria-expanded", String(open));
    if (open) close?.focus();
    else menu.focus();
  };
  menu.addEventListener("click", () => setOpen(true));
  close?.addEventListener("click", () => setOpen(false));
  scrim?.addEventListener("click", () => setOpen(false));
  sidebar.querySelectorAll("a").forEach(link => link.addEventListener("click", () => {
    if (window.innerWidth <= 900) setOpen(false);
  }));
  document.addEventListener("keydown", event => {
    if (event.key === "Escape" && document.body.classList.contains("sidebar-open")) setOpen(false);
  });
})();

// Dashboard-only wiring (module search + health check). Pulled into a
// named, idempotent function — rather than an immediately-invoked block —
// because the SPA router (spa-router.js) may mount the Dashboard's markup
// well after this file has already run once (e.g. the user's first page
// this session was Wireless Analyzer, and they navigate to Dashboard
// later). The router calls this again once the Dashboard DOM exists; the
// data-nes-init guards make repeat calls a safe no-op.
window.NES.initDashboardExtras = function initDashboardExtras() {
  const search = document.getElementById("module-search");
  if (search && !search.dataset.nesInit) {
    search.dataset.nesInit = "1";
    const cards = [...document.querySelectorAll("[data-module-name]")];
    const empty = document.getElementById("module-empty");
    const filter = () => {
      const query = search.value.trim().toLowerCase();
      let visible = 0;
      cards.forEach(card => {
        const match = !query || card.dataset.moduleName.includes(query);
        card.classList.toggle("hidden", !match);
        if (match) visible += 1;
      });
      empty?.classList.toggle("hidden", visible !== 0);
    };
    search.addEventListener("input", filter);
    document.addEventListener("keydown", event => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
      if (event.key === "/" && !typing) {
        event.preventDefault();
        search.focus();
      }
    });
  }

  const button = document.getElementById("health-check");
  if (button && !button.dataset.nesInit) {
    button.dataset.nesInit = "1";
    button.addEventListener("click", async () => {
      window.NES.setLoading(button, true, "Checking local service…");
      try {
        const response = await fetch("/api/health", { headers: { Accept: "application/json" } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        document.getElementById("health-service").textContent = `${data.application} · ${data.status}`;
        window.NES.toast(`Health check passed · ${Object.keys(data.modules || {}).length} modules ready.`);
      } catch (error) {
        window.NES.toast(`Health check failed. Confirm the local server is running.`, "error");
      } finally {
        window.NES.setLoading(button, false);
      }
    });
  }
};

window.NES.initDashboardExtras();
