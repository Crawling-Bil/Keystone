// Topology Builder: the three sections of the page (Create topology, Compare two runs, Cutover runbook) as tabs, so building a
// topology has the whole page. Other scripts ask for a section with the event "tp:showview" ({ view }) and hear "tp:viewshown"
// ({ view, changed }) when it is on screen. Hidden sections stay mounted: a build keeps running while another tab is open.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root || root.dataset.viewsReady) return;
  root.dataset.viewsReady = "1";
  const bar = root.querySelector('[data-role="views"]');
  if (!bar) return;
  const tabs = Array.from(bar.querySelectorAll("[data-view]"));
  const panels = Array.from(root.querySelectorAll("[data-view-panel]"));
  let current = "create";

  function show(name, focus) {
    const tab = tabs.find((t) => t.dataset.view === name);
    if (!tab) return false;
    const changed = name !== current;
    current = name;
    for (const t of tabs) { const on = t === tab; t.setAttribute("aria-selected", String(on)); t.tabIndex = on ? 0 : -1; }
    for (const p of panels) p.hidden = p.dataset.viewPanel !== name;
    if (focus) tab.focus();
    root.dispatchEvent(new CustomEvent("tp:viewshown", { detail: { view: name, changed } }));
    return true;
  }

  bar.addEventListener("click", (event) => { const tab = event.target.closest("[data-view]"); if (tab) show(tab.dataset.view, false); });
  // Arrow keys move between the tabs, Home and End jump to the first and last (WAI-ARIA tabs pattern)
  bar.addEventListener("keydown", (event) => {
    const at = tabs.findIndex((t) => t === document.activeElement);
    if (at < 0) return;
    let next = -1;
    if (event.key === "ArrowRight") next = (at + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (at - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    if (next < 0) return;
    event.preventDefault();
    show(tabs[next].dataset.view, true);
  });
  root.addEventListener("tp:showview", (event) => { show(event.detail && event.detail.view, true); });
})();
