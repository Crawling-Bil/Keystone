// Hardware catalogue (Configuration Studio): expand/collapse all, and the router page's model picker.
// Delegated listeners on the document, bound once, so they also work for a page the single-page router inserts later.
(() => {
  if (window.__nesHardwareCatalogBound) return;
  window.__nesHardwareCatalogBound = true;

  document.addEventListener("click", event => {
    const button = event.target.closest("[data-hw-action]");
    const root = button && button.closest("#hardware-catalog");
    if (!root) return;
    const open = button.dataset.hwAction === "expand";
    root.querySelectorAll("details.hw-node").forEach(node => { node.open = open; });
  });

  // Router page: pick one model, every other model and every branch without it is hidden, the branches above it open.
  document.addEventListener("change", event => {
    const picker = event.target.closest("#hw-model-picker");
    const root = picker && picker.closest("#hardware-catalog");
    if (!root) return;
    const wanted = picker.value;
    root.querySelectorAll("details.hw-model").forEach(card => {
      card.classList.toggle("is-hidden", !!wanted && card.dataset.model !== wanted);
    });
    root.querySelectorAll("details.hw-node:not(.hw-model)").forEach(branch => {
      const has = !wanted || branch.querySelector("details.hw-model:not(.is-hidden)");
      branch.classList.toggle("is-hidden", !has);
      if (wanted && has) branch.open = true;
    });
    const shown = root.querySelector("details.hw-model:not(.is-hidden)");
    if (wanted && shown) shown.open = true;
  });
})();
