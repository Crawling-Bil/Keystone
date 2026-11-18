"""The change-window page: one page for a change advisory board (CAB) that says what a change window did to the network.

A change record asks what changed, what needs a second look, which new findings the change introduced (and which requirement each is evidence for), which ones it resolved, and who
approved it.  When a run is built with "Mark the changes since an earlier run", the pack therefore holds ``change-window/change-window.html`` (this page) and ``change-window/changes.csv``
(every difference, for a spreadsheet).  The differences are those of ``diff.compare_runs`` (devices, links, findings, hosts, devices behind switches; a renamed device is one row), so the page
agrees with the Compare tool and with the marks on the diagrams.

What the page does not know: that the second capture was taken after the window and the first before it (the labels are the ones the person typed), and whether a device that is gone from
the second run left the network or was not captured again.  Both are written on the page.  The sign-off block is left empty.

ITIL change enablement (change records, approval, review) is described in AXELOS / PeopleCert ITIL 4: https://www.axelos.com/certifications/itil-service-management ; a financial institution
in Indonesia keeps the change record under OJK Regulation 11/POJK.03/2022 (see ``evidence.py``).
"""

from __future__ import annotations

from html import escape
from typing import Any

from . import evidence

SIGN_OFF = ("Prepared by", "Reviewed by", "Approved by (CAB)", "Change record number", "Date and time of the window", "Rollback plan reference", "Post-change verification (who, when, how)")
MAX_ROWS = 200


def _table(rows: list[dict[str, str]], controls: bool = False) -> str:
    head = ["Area", "Change", "Item", "Field", "Before", "After", "Why"] + (["Evidence for"] if controls else [])
    parts = ["<table><tr>" + "".join(f"<th>{h}</th>" for h in head) + "</tr>"]
    for row in rows[:MAX_ROWS]:
        cells = [row["area"], row["change"], row["item"], row["field"], row["before"], row["after"], row["why"]]
        if controls:
            code = row["item"].split(" ", 1)[0]
            cells.append(evidence.controls_text(code))
        parts.append("<tr class=\"imp-" + escape(row["impact"]) + "\">" + "".join(f"<td>{escape(str(c))}</td>" for c in cells) + "</tr>")
    parts.append("</table>")
    if len(rows) > MAX_ROWS:
        parts.append(f"<p class=\"muted\">{len(rows) - MAX_ROWS} more row(s) are in changes.csv.</p>")
    return "".join(parts)


def page(diff: dict[str, Any], label: str, title: str = "Network topology", created: str = "") -> str:
    """The page as one self-contained HTML text (no script, no outside file)."""
    summary, rows = diff["summary"], diff["rows"]
    areas = summary["areas"]
    verdict = {"identical": "No difference between the two runs.", "changed": "The runs differ; nothing is marked as needing attention.",
               "attention": f"The runs differ and {summary['attention']} difference(s) need attention."}[summary["verdict"]]
    attention = [r for r in rows if r["impact"] == "attention"]
    renamed = [r for r in rows if r["change"] == "renamed"]
    added = [r for r in rows if r["area"] == "Findings" and r["change"] == "added"]
    resolved = [r for r in rows if r["area"] == "Findings" and r["change"] == "resolved"]
    other = [r for r in rows if r["impact"] != "attention" and r["change"] != "renamed" and not (r["area"] == "Findings" and r["change"] in ("added", "resolved"))]
    devices, links, findings = areas["Devices"], areas["Links"], areas["Findings"]
    counts = [("Devices added", devices.get("added", 0)), ("Devices removed", devices.get("removed", 0)), ("Devices renamed", devices.get("renamed", 0)), ("Devices changed", devices.get("changed", 0)),
              ("Links added", links.get("added", 0)), ("Links removed", links.get("removed", 0)), ("Links moved", links.get("moved", 0)), ("Links changed", links.get("changed", 0)),
              ("Findings new", findings.get("added", 0)), ("Findings resolved", findings.get("resolved", 0))]
    out = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{escape(title)} - change window</title><style>"
           "body{font:14px/1.45 Helvetica,Arial,sans-serif;margin:32px auto;max-width:1150px;color:#1d2b36}h1{font-size:22px}h2{font-size:17px;margin:26px 0 6px;border-bottom:2px solid #005073;color:#005073}"
           "table{border-collapse:collapse;width:100%;margin:6px 0 14px;font-size:13px}th,td{border:1px solid #c5ced6;padding:4px 7px;text-align:left;vertical-align:top}th{background:#eef3f7}"
           ".imp-attention td{background:#fff3e0}.banner{padding:10px 14px;border:1px solid #c5ced6;background:#f7fafc;margin:10px 0}.banner.attention{border-color:#e08a00;background:#fff3e0}"
           ".cards{display:flex;flex-wrap:wrap;gap:8px}.card{border:1px solid #c5ced6;padding:6px 12px;min-width:120px}.card b{display:block;font-size:20px}.muted{color:#5b6b78}"
           ".sign td{height:34px}.sign td:first-child{width:260px;background:#eef3f7;font-weight:600}.note{background:#fff7e0;border:1px solid #e0b84a;padding:8px 12px;margin:12px 0}"
           "@media print{body{margin:12mm}}</style></head><body>",
           f"<h1>{escape(title)}: change window</h1>",
           f"<p class=\"muted\">{escape(created)}{' · ' if created else ''}compared with {escape(label)} · {summary['before']['devices']} device(s) before, {summary['after']['devices']} after · "
           f"{summary['captured_in_both']} captured in both runs</p>",
           f"<div class=\"banner {'attention' if summary['verdict'] == 'attention' else ''}\"><b>{escape(verdict)}</b></div>",
           "<div class=\"cards\">" + "".join(f"<div class=\"card\"><b>{n}</b>{escape(name)}</div>" for name, n in counts) + "</div>"]
    out.append(f"<h2>Needs attention ({len(attention)})</h2>" + (_table(attention, controls=True) if attention else "<p>Nothing.</p>"))
    out.append(f"<h2>Renamed devices ({len(renamed)})</h2>" + (_table(renamed) if renamed else "<p>None.</p>"))
    out.append(f"<h2>New findings ({len(added)})</h2>" + (_table(added, controls=True) if added else "<p>None.</p>"))
    out.append(f"<h2>Resolved findings ({len(resolved)})</h2>" + (_table(resolved) if resolved else "<p>None.</p>"))
    out.append(f"<h2>Other differences ({len(other)})</h2>" + (_table(other) if other else "<p>None.</p>"))
    out.append("<div class=\"note\">The two runs are the captures the person gave as the earlier and the later state; Keystone cannot tell that they were taken before and after the window. "
               "A device that is missing from the later run may have left the network or may simply not have been captured again. " + escape(evidence.DISCLAIMER) + "</div>")
    out.append("<h2>Sign-off</h2><table class=\"sign\">" + "".join(f"<tr><td>{escape(name)}</td><td></td></tr>" for name in SIGN_OFF) + "</table></body></html>")
    return "".join(out)
