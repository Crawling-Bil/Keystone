// Topology Builder: the baseline banner. The newest pinned run in the Topology history is the baseline; after every build the page asks
// /topology/api/baseline/<id> what changed and says so under the build. "Show changes" opens the Compare two runs panel on the two runs.
(() => {
  const root = document.querySelector(".tp-page");
  if (!root || root.dataset.baselineReady) return;
  root.dataset.baselineReady = "1";
  const banner = root.querySelector('[data-role="baseline"]');
  if (!banner) return;
  const api = root.dataset.api;
  const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + "s")}`;
  let latest = 0;                                    // a slow answer for an earlier build must not replace the banner of a newer one

  function hide() { banner.classList.add("hidden"); banner.classList.remove("same", "changed", "attention"); banner.innerHTML = ""; }

  function show(id, built, answer) {
    const base = answer.baseline;
    const name = `<strong>${esc(base.name)}</strong> <span class="muted-copy">(pinned, built ${esc(base.built)})</span>`;
    banner.classList.remove("hidden", "same", "changed", "attention");
    if (!answer.differences) {
      banner.classList.add("same");
      banner.innerHTML = `<div class="tp-baseline-text"><strong>Same as the baseline.</strong> No difference from ${name}.</div>
        <button type="button" class="an-btn small" data-act="baseline-close">Dismiss</button>`;
    } else {
      banner.classList.add(answer.attention ? "attention" : "changed");
      const read = answer.attention ? `, ${answer.attention} to read` : "";
      banner.innerHTML = `<div class="tp-baseline-text"><strong>${plural(answer.differences, "difference")} from the baseline${read}.</strong> Compared with ${name}.</div>
        <div class="tp-baseline-actions"><button type="button" class="an-btn small primary" data-act="baseline-show" data-before="${esc(base.id)}" data-after="${esc(id)}">Show changes</button>
        <button type="button" class="an-btn small" data-act="baseline-close">Dismiss</button></div>`;
    }
  }

  root.addEventListener("tp:built", async (event) => {
    const id = event.detail && event.detail.id;
    const ticket = ++latest;
    hide();
    if (!id) return;
    try {
      const response = await fetch(`${api}/api/baseline/${encodeURIComponent(id)}`, { cache: "no-store" });
      const answer = await response.json();
      if (ticket !== latest || !answer || !answer.ok || !answer.baseline) return;
      show(id, "", answer);
    } catch (error) { /* no banner: the build itself already succeeded */ }
  });

  banner.addEventListener("click", (event) => {
    const button = event.target.closest("[data-act]");
    if (!button) return;
    if (button.dataset.act === "baseline-close") { hide(); return; }
    if (button.dataset.act === "baseline-show") root.dispatchEvent(new CustomEvent("tp:compare", { detail: { before: button.dataset.before, after: button.dataset.after } }));
  });

  // a new build, or Clear, makes the banner stale at once
  root.addEventListener("tp:buildstart", () => { latest += 1; hide(); });
})();
