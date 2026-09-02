/*
 * Lightweight in-app router.
 *
 * Problem: every module (Dashboard, Configuration Studio, Wireless
 * Analyzer, Switch Analyzer, Lifecycle Manager, About) is a separate
 * Flask route. Clicking between them used to be a normal full page
 * navigation, which throws away every bit of client-side state — a file
 * picked in an upload drop-zone, a rendered AP Role Diff / Config Delta
 * result, an in-progress form. This file intercepts navigation between
 * those pages, fetches the target page's HTML once, and keeps its DOM
 * mounted (just hidden) instead of ever discarding it. Switching back
 * later is instant and picks up exactly where the user left off.
 *
 * Anything that ISN'T one of the known module routes (file exports,
 * template downloads, API calls, external links) is left completely
 * alone and behaves like a normal link/request.
 */
(() => {
  const ROUTES = ["/", "/configuration", "/wireless", "/switch-analyzer", "/lifecycle/", "/ztp/", "/lifecycle/config-push", "/about"];

  const outlet = document.getElementById("spa-outlet");
  if (!outlet) return; // base.html not on this page (shouldn't happen) — fail safe to normal navigation

  const headingEl = document.getElementById("page-heading");
  const subtitleEl = document.getElementById("page-subtitle");
  const actionsSlot = document.getElementById("topbar-actions-slot");

  const pages = new Map(); // normalized path -> {container, title, heading, subtitle, actionsHtml}
  const loadedScripts = new Set(
    [...document.querySelectorAll("script[src]")].map(node => node.getAttribute("src"))
  );
  const loadedStyles = new Set(
    [...document.querySelectorAll('link[rel="stylesheet"]')].map(node => node.getAttribute("href"))
  );

  function normalize(pathname) {
    if (pathname === "/lifecycle") return "/lifecycle/";
    return pathname;
  }

  function matchRoute(pathname) {
    const path = normalize(pathname);
    return ROUTES.includes(path) ? path : null;
  }

  function setActiveNav(path) {
    document.querySelectorAll(".suite-nav-item").forEach(link => {
      const linkPath = normalize(new URL(link.getAttribute("href"), location.href).pathname);
      const active = linkPath === path;
      link.classList.toggle("active", active);
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    });
  }

  function closeMobileSidebar() {
    document.body.classList.remove("sidebar-open");
  }

  function showPage(path) {
    const entry = pages.get(path);
    if (!entry) return;
    outlet.querySelectorAll(":scope > [data-spa-page]").forEach(node => {
      node.hidden = node !== entry.container;
    });
    if (actionsSlot) {
      actionsSlot.querySelectorAll(":scope > [data-spa-page-actions]").forEach(node => {
        node.hidden = node !== entry.actionsContainer;
      });
    }
    document.title = entry.title;
    if (headingEl) headingEl.textContent = entry.heading;
    if (subtitleEl) subtitleEl.textContent = entry.subtitle;
    setActiveNav(path);
    closeMobileSidebar();
    window.scrollTo(0, 0);
  }

  function loadScript(src) {
    return new Promise(resolve => {
      const el = document.createElement("script");
      el.src = src;
      el.async = false; // preserve document order relative to other injected scripts
      el.onload = () => resolve();
      el.onerror = () => {
        console.error(`[spa-router] failed to load ${src}`);
        resolve(); // don't block the rest of the page on one bad script
      };
      document.body.appendChild(el);
    });
  }

  async function mount(path, doc) {
    const sourceOutlet = doc.getElementById("spa-outlet");
    const container = document.createElement("div");
    container.setAttribute("data-spa-page", path);
    container.hidden = true;
    container.innerHTML = sourceOutlet ? sourceOutlet.innerHTML : "";
    outlet.appendChild(container);

    // Topbar actions (e.g. Lifecycle Manager's Refresh button) must be
    // attached to the live document — hidden, same as the content above —
    // BEFORE this page's scripts run below. Those scripts do
    // document.getElementById("refresh-button") etc. immediately; if the
    // markup only existed as an off-DOM string until showPage() ran later,
    // that lookup would return null and the script would throw.
    let actionsContainer = null;
    if (actionsSlot) {
      const actionsSource = doc.getElementById("topbar-actions-slot");
      actionsContainer = document.createElement("div");
      actionsContainer.setAttribute("data-spa-page-actions", path);
      actionsContainer.hidden = true;
      actionsContainer.innerHTML = actionsSource ? actionsSource.innerHTML : "";
      actionsSlot.appendChild(actionsContainer);
    }

    // Pull in any stylesheet this page's <head> declares that we don't
    // already have (e.g. Lifecycle Manager ships its own stylesheet).
    doc.querySelectorAll('head link[rel="stylesheet"]').forEach(link => {
      const href = link.getAttribute("href");
      if (href && !loadedStyles.has(href)) {
        loadedStyles.add(href);
        const el = document.createElement("link");
        el.rel = "stylesheet";
        el.href = href;
        document.head.appendChild(el);
      }
    });

    // Run this page's own scripts exactly once, in document order.
    const scripts = [...doc.querySelectorAll("body script")];
    const toLoad = [];
    const inlineBlocks = [];
    scripts.forEach(script => {
      const src = script.getAttribute("src");
      if (src) {
        if (!loadedScripts.has(src)) {
          loadedScripts.add(src);
          toLoad.push(src);
        }
      } else if (script.textContent.trim()) {
        inlineBlocks.push(script.textContent);
      }
    });

    let injectedAny = toLoad.length > 0;
    for (const src of toLoad) {
      await loadScript(src);
    }
    inlineBlocks.forEach(code => {
      injectedAny = true;
      const el = document.createElement("script");
      el.textContent = code;
      document.body.appendChild(el);
    });

    // Some page controllers (Lifecycle Manager's) run their setup inside
    // a `DOMContentLoaded` listener, which only ever fires once per real
    // page load. Since we're injecting the script long after that event
    // already happened, replay it so those listeners still run.
    if (injectedAny) {
      document.dispatchEvent(new Event("DOMContentLoaded", { bubbles: true, cancelable: true }));
    }

    if (path === "/") window.NES.initDashboardExtras?.();

    pages.set(path, {
      container,
      actionsContainer,
      title: doc.title || document.title,
      heading: doc.getElementById("page-heading")?.textContent || "",
      subtitle: doc.getElementById("page-subtitle")?.textContent || "",
    });
  }

  function currentPath() {
    return (history.state && history.state.path) || matchRoute(location.pathname);
  }

  async function navigate(rawPath, { push = true } = {}) {
    const path = matchRoute(rawPath);
    if (!path) {
      location.href = rawPath;
      return;
    }
    if (path === currentPath() && pages.has(path)) {
      closeMobileSidebar();
      return;
    }
    if (!pages.has(path)) {
      let html;
      try {
        const response = await fetch(path, { headers: { "X-Requested-With": "fetch" } });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        html = await response.text();
      } catch (error) {
        // Fetch failed for any reason — fall back to a real navigation
        // rather than leaving the user stuck.
        location.href = path;
        return;
      }
      const doc = new DOMParser().parseFromString(html, "text/html");
      await mount(path, doc);
    }
    showPage(path);
    if (push) history.pushState({ path }, "", path);
  }

  function registerInitialPage() {
    const path = matchRoute(location.pathname) || normalize(location.pathname);
    const container = document.createElement("div");
    container.setAttribute("data-spa-page", path);
    // Relocate (not clone) the server-rendered content into the wrapper —
    // this preserves every already-bound listener and any live form state.
    while (outlet.firstChild) container.appendChild(outlet.firstChild);
    outlet.appendChild(container);

    let actionsContainer = null;
    if (actionsSlot) {
      actionsContainer = document.createElement("div");
      actionsContainer.setAttribute("data-spa-page-actions", path);
      while (actionsSlot.firstChild) actionsContainer.appendChild(actionsSlot.firstChild);
      actionsSlot.appendChild(actionsContainer);
    }

    pages.set(path, {
      container,
      actionsContainer,
      title: document.title,
      heading: headingEl ? headingEl.textContent : "",
      subtitle: subtitleEl ? subtitleEl.textContent : "",
    });
    setActiveNav(path);
    history.replaceState({ path }, "", location.pathname + location.search);
  }

  document.addEventListener("click", event => {
    if (event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const link = event.target.closest("a[href]");
    if (!link) return;
    if (link.target && link.target !== "_self") return;
    if (link.hasAttribute("download")) return;
    let url;
    try {
      url = new URL(link.href, location.href);
    } catch (error) {
      return;
    }
    if (url.origin !== location.origin) return;
    const path = matchRoute(url.pathname);
    if (!path) return; // not a module route — exports/downloads/API calls pass through untouched
    event.preventDefault();
    navigate(path);
  });

  window.addEventListener("popstate", event => {
    const path = (event.state && event.state.path) || matchRoute(location.pathname);
    if (!path) {
      location.reload();
      return;
    }
    if (pages.has(path)) showPage(path);
    else navigate(path, { push: false });
  });

  registerInitialPage();
})();
