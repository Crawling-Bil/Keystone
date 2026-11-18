"""The one-page summary for the customer: what was found, what it means for the refresh, what is still needed.

A self-contained HTML page (no script, no external file) that prints on one A4 page.  It holds counts and decisions, not a device list: the workbook is the detail.  Every value that came
from a capture is escaped.
"""

from __future__ import annotations

from html import escape
from typing import Any

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root{{--ink:#17202a;--mut:#5b6672;--line:#d5dbe1;--acc:#1f5fbf;--warn:#a15c00;--bad:#b3261e;--ok:#1b7a3d;--bg:#fff}}
@media (prefers-color-scheme:dark){{:root:not([data-theme="light"]){{--ink:#e8edf2;--mut:#a3adb8;--line:#38424d;--acc:#7aa7ff;--warn:#e0a84c;--bad:#ff8a80;--ok:#6fd08c;--bg:#14181d}}}}
html,body{{background:var(--bg);color:var(--ink);margin:0;font:13px/1.45 system-ui,Segoe UI,Arial,sans-serif}}
main{{max-width:820px;margin:0 auto;padding:24px 16px}}
h1{{font-size:22px;margin:0 0 2px}} h2{{font-size:13px;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin:18px 0 6px;border-bottom:1px solid var(--line);padding-bottom:3px}}
.sub{{color:var(--mut);margin:0 0 12px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}}
.card{{border:1px solid var(--line);border-radius:8px;padding:8px 10px}} .card b{{display:block;font-size:20px}} .card span{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%}} td,th{{text-align:left;padding:3px 6px;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:var(--mut);font-weight:600}}
.warn{{color:var(--warn)}} .bad{{color:var(--bad)}} .ok{{color:var(--ok)}}
ul{{margin:4px 0 0 18px;padding:0}} li{{margin:2px 0}}
footer{{color:var(--mut);margin-top:16px;font-size:11px}}
@media print{{main{{padding:0}} html,body{{background:#fff;color:#000;font-size:11px}} h2{{margin-top:12px}} @page{{size:A4;margin:14mm}}}}
</style></head><body><main>
<h1>{title}</h1><p class="sub">Infrastructure refresh sizing summary &middot; as of {as_of} &middot; growth allowance {growth:g} %</p>
<h2>What was found</h2>
<div class="cards">{cards}</div>
<table><tr><th>Device type</th><th>Devices</th><th>Brands</th></tr>{types}</table>
<h2>What it means for the refresh</h2><ul>{means}</ul>
<h2>What needs a decision</h2><ul>{decisions}</ul>
<h2>What is still needed</h2><ul>{needs}</ul>
<footer>Figures come from the captured configurations and command output; a quantity that is a moment in time (ports with a link, clients on an access point) is not a peak. {confidence}</footer>
</main></body></html>"""


def _li(items: list[str]) -> str:
    return "".join(f"<li>{item}</li>" for item in items) or "<li>Nothing outstanding.</li>"


def render(name: str, assets: list[dict[str, Any]], rollup: dict[str, Any]) -> str:
    s = rollup["summary"]
    expiry = rollup.get("expiry") or {}
    units = rollup.get("units") or {}
    conf = rollup.get("confidence") or {}
    total_conf = max(1, sum(conf.values()))
    brands: dict[str, set[str]] = {}
    for asset in assets:
        brands.setdefault(asset["device_type"], set()).add(asset["vendor"])
    cards = "".join(f'<div class="card"><b>{escape(str(value))}</b><span>{escape(label)}</span></div>' for label, value in (
        ("devices", s["devices"]), ("sites", s["sites"]), ("access points", s["access_points"]), ("logical units", units.get("count", s["devices"])),
        ("licences ending in the window", expiry.get("soon", 0)), ("already expired", expiry.get("expired", 0))))
    types = "".join(f"<tr><td>{escape(label)}</td><td>{count}</td><td>{escape(', '.join(sorted(brands.get(dtype, set()))))}</td></tr>"
                    for dtype, (label, count) in _types(rollup))
    means: list[str] = []
    for plan in rollup.get("plan", []):
        if plan.get("final_units") is not None:
            means.append(f"<b>{escape(plan['label'])}</b>: {plan['final_units']} replacement unit(s) for {plan['units_today']} today, limited by {escape(plan['limited_by'])}.")
        basis = plan.get("sizing_basis")
        if basis and basis.get("level"):
            means.append(f"The <b>{escape(plan['label'].lower())}</b> group is sized on {escape(basis['title'].lower())}, because of what its rules do to the traffic.")
    if units.get("pairs"):
        means.append(f"{units['pairs']} redundant pair(s) were found in the configurations and are counted as one unit each.")
    decisions: list[str] = []
    if expiry.get("expired"):
        decisions.append(f'<span class="bad">{expiry["expired"]} licence(s) have expired</span>: renew or retire before the refresh.')
    if expiry.get("soon"):
        decisions.append(f'<span class="warn">{expiry["soon"]} licence(s) end within {expiry.get("months", 12)} months</span>: a refresh can co-term them ({len(rollup.get("coterm") or [])} renewal window(s)).')
    missing_pairs = [a for a in assets if a.get("pair_missing")]
    if missing_pairs:
        decisions.append(f'<span class="warn">{len(missing_pairs)} device(s) are one half of a pair whose other half was not captured</span>: the replacement needs two units.')
    if rollup.get("tiers"):
        confirm = sum(1 for t in rollup["tiers"] if t["certainty"] == "confirm")
        decisions.append(f"{len(rollup['tiers'])} licence tier hint(s) from the features in use" + (f", {confirm} to confirm for the chosen model." if confirm else "."))
    needs = [f"{escape(g['note'])} ({g['count']} device(s))" for g in (rollup.get("gaps") or [])[:6]]
    peaks_missing = (rollup.get("peaks") or {}).get("missing_total", 0)
    if peaks_missing:
        needs.append(f"Peak throughput, sessions and connections from monitoring for {peaks_missing} firewall / load balancer / router(s).")
    return PAGE.format(title=escape(name or "Sizing summary"), as_of=escape(str(expiry.get("as_of", ""))), growth=float(rollup.get("growth", 0)), cards=cards, types=types, means=_li(means), decisions=_li(decisions),
                       needs=_li(needs), confidence=escape(f"{100 * conf.get('high', 0) // total_conf} % of the figures are printed by the device or counted in its configuration."))


def _types(rollup: dict[str, Any]):
    from .classify import DEVICE_TYPES
    by_label = rollup["summary"]["by_type"]
    from .classify import TYPE_LABELS
    for dtype in DEVICE_TYPES:
        label = TYPE_LABELS[dtype]
        if label in by_label:
            yield dtype, (label, by_label[label])
