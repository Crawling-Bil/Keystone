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

  // Only plain numbers ("12", "1,234", "99.5") count up. Anything with a unit,
  // a slash or a prefix ("45%", "3/4", "v17.9", "1.2 GB") stays as written:
  // stripping it to digits would show a different value.
  const PLAIN_NUMBER = /^\s*(\d{1,3}(,\d{3})+|\d+)(\.\d+)?\s*$/;
  function countUp(el) {
    const text = String(el.textContent);
    if (!PLAIN_NUMBER.test(text)) return;
    const target = Number(text.replace(/,/g, ""));
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

  // Click feedback: a ripple from the pointer on buttons, tabs and nav
  // items, and a short flash on a table row whose checkbox gets ticked.
  const RIPPLE = "button, .btn, .an-btn, a.button, .suite-nav-item, .nav-item, .lg-tab, .li-rtab";
  document.addEventListener("pointerdown", event => {
    if (event.button !== 0) return;
    const host = event.target.closest(RIPPLE);
    if (!host || host.disabled || host.matches(".modal-close")) return;
    const rect = host.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height) * 2.2;
    const dot = document.createElement("span");
    dot.className = "m-ripple";
    dot.style.width = dot.style.height = `${size}px`;
    dot.style.left = `${event.clientX - rect.left - size / 2}px`;
    dot.style.top = `${event.clientY - rect.top - size / 2}px`;
    host.classList.add("m-ripple-host");
    host.appendChild(dot);
    dot.addEventListener("animationend", () => dot.remove(), { once: true });
  }, { passive: true });

  document.addEventListener("change", event => {
    const box = event.target;
    if (!box.matches || !box.matches('input[type="checkbox"]') || !box.checked) return;
    const row = box.closest("tr");
    if (!row) return;
    row.classList.remove("m-picked");
    void row.offsetWidth;   // restart the animation on a quick re-tick
    row.classList.add("m-picked");
  });
  window.NESMotion = { stagger, countUp, scan };
})();
