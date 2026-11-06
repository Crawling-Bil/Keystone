// Topology Builder: "Load demo data". Sets of invented captures (see features/topology/demo.py) are fetched and handed to the upload list
// with the event "tp:addfiles", so the normal build runs on them.  The row stays hidden when the server has no demo files.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root || root.dataset.demoReady) return;
  root.dataset.demoReady = "1";
  const box = root.querySelector('[data-role="demo"]'), buttons = root.querySelector('[data-role="demo-buttons"]');
  if (!box || !buttons) return;
  const api = root.dataset.api;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  let sets = [];

  async function load(set, button) {
    button.disabled = true;
    try {
      const files = await Promise.all(set.files.map(async (item) => {          // a set of 40 captures loads in parallel, in the listed order
        const response = await fetch(`${api}/api/demo/${encodeURIComponent(set.id)}/${encodeURIComponent(item.name)}`, { cache: "no-store" });
        if (!response.ok) throw new Error(item.name);
        return new File([await response.blob()], item.name, { type: "text/plain" });
      }));
      let layout = null;                                                          // a set may bring the layout of its diagram (the file "Keep my layout" reads)
      if (set.layout) {
        const response = await fetch(`${api}/api/demo/${encodeURIComponent(set.id)}/${encodeURIComponent(set.layout)}`, { cache: "no-store" });
        if (response.ok) layout = new File([await response.blob()], set.layout, { type: "application/xml" });
      }
      root.dispatchEvent(new CustomEvent("tp:addfiles", { detail: { files, replace: true, layout, name: `Demo ${set.label}`, group: set.group || "", showBuild: true, status: `Loaded ${files.length} invented captures: ${set.label}${layout ? " and its diagram layout" : ""}. Press Build topology.` } }));
    } catch (error) {
      const status = root.querySelector('[data-role="status"]');
      if (status) { status.textContent = "The demo files could not be loaded. Is Keystone still running?"; status.classList.add("error"); }
    } finally {
      button.disabled = false;
    }
  }

  buttons.addEventListener("click", (event) => {
    const button = event.target.closest("[data-demo]");
    const set = button && sets.find((s) => s.id === button.dataset.demo);
    if (set) load(set, button);
  });

  fetch(`${api}/api/demo`, { cache: "no-store" }).then((r) => r.json()).then((payload) => {
    sets = ((payload && payload.sets) || []).filter((s) => s.files && s.files.length);
    if (!sets.length) return;
    buttons.innerHTML = sets.map((s) => `<button type="button" class="an-btn small" data-demo="${esc(s.id)}" title="${esc(s.description)}">${esc(s.label)}</button>`).join("");
    box.hidden = false;
  }).catch(() => { /* no demo row */ });
})();
