"""Audit evidence in the documentation pack: a SHA-256 manifest of every file, the hashes of the captures the run was built from, and the findings
tagged with the control they are evidence for.

A change record or an audit asks three things of a network diagram: *is this the file you produced* (manifest and pack hash), *what was it built from*
(the capture hashes) and *which requirement does it support* (the control table).  The tagging is guidance for filing, not an assessment: whether a control
is met is the auditor's decision, and the tool says so in the file.

Controls named (check the edition your auditor uses; the identifiers below are those of the editions named):

* CIS Critical Security Controls v8: 1.1 Establish and Maintain Detailed Enterprise Asset Inventory, 4.1 Establish and Maintain a Secure Configuration Process,
  12.4 Establish and Maintain Architecture Diagram(s) - https://www.cisecurity.org/controls/v8
* NIST SP 800-53 Rev. 5: CM-2 Baseline Configuration, CM-6 Configuration Settings, CM-8 System Component Inventory, CP-8(2) Single Points of Failure
  - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
* PCI DSS v4.0: 1.2.3 accurate network diagram, 2.2.1 configuration standards, 12.5.1 inventory of system components - https://www.pcisecuritystandards.org/document_library/
* ISO/IEC 27001:2022 Annex A: A.5.9 Inventory of information and other associated assets, A.5.30 ICT readiness for business continuity, A.8.9 Configuration management,
  A.8.14 Redundancy of information processing facilities, A.8.20 Networks security - https://www.iso.org/standard/27001
* IEC 62443-3-3:2013 (industrial automation and control systems, system security requirements): SR 5.1 Network segmentation and SR 5.2 Zone boundary protection (foundational requirement 5,
  restricted data flow); the zones and conduits method itself is IEC 62443-3-2.  The standards are sold by IEC and ISA; the two requirement titles are listed, for example, on
  https://teeptrak.com/en/iec-62443-3-3-system-requirements-2026/ (a secondary source: read the standard for the wording).
* For the findings about a main site and its recovery site (TOPO-047 to 056): NIST SP 800-53 Rev. 5 CP-2 Contingency Plan and CP-7 Alternate Processing Site
  (an alternate site that can resume the essential functions within the time set; the base text also expects it to be far enough from the primary site) - https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final ;
  and, for a bank in Indonesia, OJK Regulation 11/POJK.03/2022 on the use of information technology by commercial banks (Penyelenggaraan Teknologi Informasi oleh Bank Umum):
  Pasal 18 (a disaster recovery plan, Rencana Pemulihan Bencana, that can be carried out; the OJK summary names a test and review at least once a year in chapter IV; the paragraph
  numbers of Pasal 18 are not cited here, read them in the regulation) and Pasal 37 (the data center and the disaster recovery center, Pusat Pemulihan Bencana, must
  guarantee the continuity of the bank's business) - https://ojk.go.id/id/regulasi/Pages/Penyelenggaraan-Teknologi-Informasi-Oleh-Bank-Umum.aspx ;
  the regulation text https://ojk.go.id/id/regulasi/Documents/Pages/Penyelenggaraan-Teknologi-Informasi-Oleh-Bank-Umum/POJK%2011%20-%2003%20-%202022.pdf
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

CIS = "CIS Controls v8"
NIST = "NIST SP 800-53 Rev. 5"
PCI = "PCI DSS v4.0"
ISO = "ISO/IEC 27001:2022"
OJK = "POJK 11/POJK.03/2022"
IEC = "IEC 62443-3-3:2013"

DISCLAIMER = ("Keystone tags what a finding is evidence for. It does not assess compliance: whether a control is met, and which edition applies, is decided by "
              "the person who owns the control or by the auditor.")

# a control: (framework, identifier, title)
DIAGRAM = [(PCI, "1.2.3", "An accurate network diagram is maintained that shows all connections"),
           (CIS, "12.4", "Establish and Maintain Architecture Diagram(s)"),
           (ISO, "A.8.20", "Networks security"),
           (NIST, "CM-2", "Baseline Configuration")]
INVENTORY = [(CIS, "1.1", "Establish and Maintain Detailed Enterprise Asset Inventory"),
             (NIST, "CM-8", "System Component Inventory"),
             (ISO, "A.5.9", "Inventory of information and other associated assets"),
             (PCI, "12.5.1", "An inventory of system components in scope is maintained")]
CONFIGURATION = [(NIST, "CM-6", "Configuration Settings"),
                 (CIS, "4.1", "Establish and Maintain a Secure Configuration Process"),
                 (ISO, "A.8.9", "Configuration management"),
                 (PCI, "2.2.1", "Configuration standards are developed, implemented and maintained")]
RESILIENCE = [(NIST, "CP-8(2)", "Telecommunications Services: Single Points of Failure"),
              (ISO, "A.8.14", "Redundancy of information processing facilities")]
# the recovery site: the data center and the disaster recovery center guarantee business continuity; the plan can be carried out (OJK: Pasal 37 and Pasal 18, Bank Umum)
DR_SITE = [(OJK, "Pasal 37", "Pusat Data dan Pusat Pemulihan Bencana menjamin kelangsungan usaha (continuity of the business)"),
           (NIST, "CP-7", "Alternate Processing Site"),
           (ISO, "A.5.30", "ICT readiness for business continuity"),
           (ISO, "A.8.14", "Redundancy of information processing facilities")]
# the zones of a firewall are separated by the firewall, and a cable or a router that goes round it defeats that (TOPO-059, 060, 063, 064)
SEGMENTATION = [(PCI, "1.4.1", "Network security controls (NSCs) are implemented between trusted and untrusted networks"),
                (PCI, "11.4.5", "If segmentation is used to isolate the cardholder data environment, penetration tests are performed on the segmentation controls"),
                (NIST, "SC-7", "Boundary Protection"),
                (ISO, "A.8.22", "Segregation of networks"),
                (CIS, "12.2", "Establish and Maintain a Secure Network Architecture"),
                (IEC, "SR 5.1", "Network segmentation"),
                (IEC, "SR 5.2", "Zone boundary protection")]
DR_PLAN = [(OJK, "Pasal 18", "Rencana Pemulihan Bencana (RPB) yang dapat dijalankan, diuji dan dikaji ulang"),
           (NIST, "CP-2", "Contingency Plan")]

# finding id -> the controls it is evidence for (by what the check looks at)
THEMES: dict[str, list[tuple[str, str, str]]] = {}


def _merged(*sets: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for controls in sets:
        out += [c for c in controls if c not in out]
    return out


for _ids, _controls in (
    (("TOPO-001", "TOPO-003", "TOPO-004", "TOPO-007", "TOPO-008", "TOPO-013", "TOPO-014", "TOPO-021", "TOPO-022", "TOPO-024", "TOPO-027", "TOPO-028", "TOPO-029", "TOPO-030", "TOPO-043", "TOPO-044", "TOPO-045", "TOPO-046", "TOPO-058"), INVENTORY),
    (("TOPO-002", "TOPO-009", "TOPO-010", "TOPO-011", "TOPO-012", "TOPO-016", "TOPO-017", "TOPO-018", "TOPO-025", "TOPO-026", "TOPO-031", "TOPO-032", "TOPO-033",
      "TOPO-036", "TOPO-037", "TOPO-038", "TOPO-039", "TOPO-040", "TOPO-042"), CONFIGURATION),
    (("TOPO-015", "TOPO-019", "TOPO-020", "TOPO-023", "TOPO-034", "TOPO-035", "TOPO-041", "TOPO-057"), RESILIENCE),
    # a recovery site that is set up like the main one: gateways, routing, equipment, layer 2, MTU, firewall pairs
    (("TOPO-047", "TOPO-048", "TOPO-052", "TOPO-053", "TOPO-054", "TOPO-055"), _merged(CONFIGURATION, DR_SITE, DR_PLAN)),
    (("TOPO-049", "TOPO-056"), _merged(RESILIENCE, DR_SITE, DR_PLAN)),
    # the path between the sites and out to the WAN
    (("TOPO-050", "TOPO-051"), _merged(RESILIENCE, DR_SITE)),
    # a cable path between two zones of one firewall; an SD-WAN site whose transport is down or single
    (("TOPO-059", "TOPO-060", "TOPO-063", "TOPO-064"), SEGMENTATION),
    (("TOPO-061", "TOPO-062", "TOPO-066", "TOPO-067", "TOPO-069"), RESILIENCE),
    # a load balancer whose member cannot answer through it, an OMP session that installs nothing, a system IP that two edges share: configuration that does not do what it is meant to
    (("TOPO-065", "TOPO-068", "TOPO-070"), CONFIGURATION),
):
    for _id in _ids:
        THEMES[_id] = list(_controls)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def controls_for(finding_id: str) -> list[tuple[str, str, str]]:
    return THEMES.get(str(finding_id), [])


def controls_text(finding_id: str) -> str:
    """The controls a finding is evidence for as one line ("POJK 11/POJK.03/2022 Pasal 37; NIST SP 800-53 Rev. 5 CP-7; ..."), for a table that shows a finding beside what it concerns."""
    return "; ".join(f"{framework} {control}" for framework, control, _ in controls_for(finding_id))


TRACKING = ("owner", "due_date", "status", "decision_note")        # filled in by the people who own the control; Keystone leaves them empty (status "open" for a finding)


def control_rows(findings: Iterable[dict[str, Any]], diagram_title: str = "Topology diagram and inventory") -> list[dict[str, str]]:
    """One row per (finding, control), after one row per control that the drawing itself supports.  ``finding`` is empty for the drawing."""
    rows: list[dict[str, str]] = []
    for framework, control, title in DIAGRAM + INVENTORY:
        rows.append({"finding": "", "severity": "", "evidence": diagram_title, "framework": framework, "control": control, "control_title": title, "devices": "",
                     "owner": "", "due_date": "", "status": "", "decision_note": ""})
    for item in findings:
        devices = item.get("devices") or ""
        if isinstance(devices, list):
            devices = ", ".join(str(d) for d in devices)
        for framework, control, title in controls_for(str(item.get("id", ""))):
            rows.append({"finding": str(item.get("id", "")), "severity": str(item.get("severity", "")), "evidence": str(item.get("title", "")),
                         "framework": framework, "control": control, "control_title": title, "devices": str(devices),
                         "owner": "", "due_date": "", "status": "open", "decision_note": ""})
    return rows


def control_page(rows: list[dict[str, str]], title: str = "Topology", created: str = "", capture_count: int = 0) -> str:
    """The control evidence of ``audit/controls.csv`` as one page to read or print: per framework, per control, what the drawing and which findings support it.  No script, no outside file."""
    from html import escape as esc
    order = [CIS, NIST, PCI, ISO, IEC, OJK]
    frameworks = sorted({r["framework"] for r in rows}, key=lambda f: (order.index(f) if f in order else len(order), f))
    parts = [f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{esc(title)} - control evidence</title><style>"
             "body{font:14px/1.45 Helvetica,Arial,sans-serif;margin:32px auto;max-width:1100px;color:#1d2b36}h1{font-size:22px}h2{font-size:17px;margin:28px 0 6px;border-bottom:2px solid #005073;color:#005073}"
             "table{border-collapse:collapse;width:100%;margin:6px 0 14px}th,td{border:1px solid #c5ced6;padding:5px 8px;text-align:left;vertical-align:top}th{background:#eef3f7}"
             ".fill{min-width:90px;background:#fbfdff}.note{background:#fff7e0;border:1px solid #e0b84a;padding:8px 12px;margin:12px 0}.sev-high,.sev-medium{font-weight:700}@media print{body{margin:12mm}}</style></head><body>",
             f"<h1>{esc(title)}: control evidence</h1>",
             f"<p>{esc(created)}{' · ' if created else ''}{capture_count} capture(s) · {len({r['finding'] for r in rows if r['finding']})} finding(s) tagged · "
             "the SHA-256 of every file of the pack is in <code>MANIFEST.sha256</code>.</p>",
             f"<div class=\"note\">{esc(DISCLAIMER)}</div>"]
    for framework in frameworks:
        parts.append(f"<h2>{esc(framework)}</h2><table><tr><th>Control</th><th>Title</th><th>Evidence</th><th>Severity</th><th>Devices</th><th>Owner</th><th>Due</th><th>Status</th><th>Decision (fix / accepted risk, why)</th></tr>")
        for row in sorted((r for r in rows if r["framework"] == framework), key=lambda r: (r["control"], r["finding"])):
            evidence = f"{esc(row['finding'])} {esc(row['evidence'])}".strip()
            parts.append(f"<tr><td>{esc(row['control'])}</td><td>{esc(row['control_title'])}</td><td>{evidence}</td>"
                         f"<td class=\"sev-{esc(row['severity'])}\">{esc(row['severity'])}</td><td>{esc(row['devices'])}</td>"
                         f"<td class=\"fill\">{esc(row.get('owner', ''))}</td><td class=\"fill\">{esc(row.get('due_date', ''))}</td><td>{esc(row.get('status', ''))}</td><td class=\"fill\">{esc(row.get('decision_note', ''))}</td></tr>")
        parts.append("</table>")
    parts.append("</body></html>")
    return "".join(parts)


def manifest_text(entries: dict[str, bytes | str]) -> str:
    """``sha256sum`` format: ``<hash>  <path>``, one line per file, sorted. ``sha256sum -c MANIFEST.sha256`` checks it on Linux and macOS (``shasum -a 256 -c``)."""
    return "".join(f"{sha256_hex(content)}  {name}\n" for name, content in sorted(entries.items()) if name != "MANIFEST.sha256")


def inputs_text(inputs: Iterable[tuple[str, bytes | str]]) -> str:
    """The captures a run was built from, ``sha256sum`` format: the SHA-256 of the text of each capture (UTF-8, after a ZIP is unpacked). A name is reduced to safe characters."""
    lines = []
    for name, content in inputs:
        safe = _SAFE_NAME.sub("_", str(name))[:160] or "capture"
        lines.append(f"{sha256_hex(content)}  {safe}\n")
    return "".join(sorted(lines, key=lambda line: line.split("  ", 1)[1]))


def audit_readme(inputs: bool) -> str:
    text = ("Audit evidence\r\n\r\n"
            "MANIFEST.sha256 (in the folder above)  SHA-256 of every file of this pack. Check it with: sha256sum -c MANIFEST.sha256 (Linux), shasum -a 256 -c MANIFEST.sha256 (macOS),\r\n"
            "                                       or certutil -hashfile <file> SHA256 on Windows and compare with the line of that file.\r\n"
            "                                       The SHA-256 of the whole ZIP is shown in the Topology history (details of the run); write it in your change record.\r\n"
            "audit/controls.csv                     The drawing and every finding, with the control it is evidence for (CIS Controls v8, NIST SP 800-53 Rev. 5, PCI DSS v4.0, ISO/IEC 27001:2022, IEC 62443-3-3:2013;\r\n"
            "                                       for the recovery-site findings also OJK POJK 11/POJK.03/2022 Pasal 18 and 37, which apply to the institutions that regulation covers in Indonesia).\r\n"
            "                                       The columns owner, due_date, status and decision_note are left for the people who own the control (a finding starts as open).\r\n"
            "audit/control-evidence.html            The same table as one page to read or print, grouped by framework and control, with room to write owner, due date and decision.\r\n"
            "change-window/change-window.html       (when the run was built with 'Mark the changes since an earlier run') one page for the change record: what changed, what needs attention,\r\n"
            "                                       renamed devices, new and resolved findings with the control each is evidence for, and an empty sign-off block. changes.csv has every difference.\r\n"
            "tables/dr-parity.csv                   (when the captures hold a main site and its recovery site) the two sites side by side, the control each line is evidence for,\r\n"
            "                                       and the evidence no capture can hold (the plan test, recovery objectives, distance between the sites) left to be filled in.\r\n")
    if inputs:
        text += "audit/inputs.sha256                    SHA-256 of the text of each capture this run was built from (UTF-8, after unzipping), so the same captures can be shown to give the same pack.\r\n"
    return text + "\r\n" + DISCLAIMER + "\r\n"
