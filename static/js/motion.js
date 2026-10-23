// Motion helpers for the suite (paired with css/motion.css):
// - stagger the cards of a group when it appears
// - count numbers up in stat cards when they change
// - reveal panels as they scroll into view on long pages
// Everything is skipped when the OS asks for reduced motion.
(() => {
  const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) return;

  const STAGGER = ".an-cards, .li-techs, .li-racks, .grid-cards, .lg-stats, .module-list, .tool-list, .an-file-list";

  function stagger(group) {
    group.classList.remove("m-stagger");
    [...group.children].forEach((child, i) => child.style.setProperty("--m-i", Math.min(i, 10)));
    void group.offsetWidth;                       // restart the animation
    group.classList.add("m-stagger");
  }

  function countUp(el) {
    const target = Number(String(el.textContent).replace(/[^\d.-]/g, ""));
    if (!Number.isFinite(target) || target === 0 || el.dataset.mCounted === String(target)) return;
    el.dataset.mCounted = String(target);
    const start = performance.now(), dur = 600, whole = Number.isInteger(target);
    const tick = now => {
      const t = Math.min(1, (now - start) / dur), eased = 1 - Math.pow(1 - t, 3);
      el.textContent = whole ? Math.round(target * eased).toLocaleString() : (target * eased).toFixed(1);
      if (t < 1) requestAnimationFrame(tick); else el.textContent = whole ? target.toLocaleString() : String(target);
    };
    requestAnimationFrame(tick);
  }

  const seen = new WeakSet();
  const reveal = "IntersectionObserver" in window ? new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      e.target.animate([{ opacity: 0, transform: "translateY(14px)" }, { opacity: 1, transform: "none" }],
        { duration: 380, easing: "cubic-bezier(.2,.8,.2,1)", fill: "both" });
      reveal.unobserve(e.target);
    });
  }, { rootMargin: "0px 0px -40px 0px" }) : null;

  function scan(root) {
    if (!(root instanceof Element)) return;
    const groups = root.matches(STAGGER) ? [root] : [...root.querySelectorAll(STAGGER)];
    groups.forEach(g => { if (g.children.length) stagger(g); });
    root.querySelectorAll(".an-card-value, .lg-stats b").forEach(countUp);
    if (reveal) {
      root.querySelectorAll(".li-result > .panel, .lg-page .block-card").forEach(p => {
        if (seen.has(p)) return;
        seen.add(p);
        const r = p.getBoundingClientRect();
        if (r.top > window.innerHeight) reveal.observe(p);
      });
    }
  }

  let queued = new Set(), scheduled = false;
  new MutationObserver(records => {
    records.forEach(r => r.addedNodes.forEach(n => { if (n instanceof Element) queued.add(n.closest(STAGGER) || n); }));
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => { scheduled = false; const list = queued; queued = new Set(); list.forEach(scan); });
  }).observe(document.body, { childList: true, subtree: true });

  document.addEventListener("DOMContentLoaded", () => scan(document.body));
  window.NESMotion = { stagger, countUp, scan };
})();
