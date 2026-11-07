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
* ISO/IEC 27001:2022 Annex A: A.5.9 Inventory of information and other associated assets, A.8.9 Configuration management, A.8.14 Redundancy of information
  processing facilities, A.8.20 Networks security - https://www.iso.org/standard/27001
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

CIS = "CIS Controls v8"
NIST = "NIST SP 800-53 Rev. 5"
PCI = "PCI DSS v4.0"
ISO = "ISO/IEC 27001:2022"

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

# finding id -> the controls it is evidence for (by what the check looks at)
THEMES: dict[str, list[tuple[str, str, str]]] = {}
for _ids, _controls in (
    (("TOPO-001", "TOPO-003", "TOPO-004", "TOPO-007", "TOPO-008", "TOPO-013", "TOPO-014", "TOPO-021", "TOPO-022", "TOPO-024", "TOPO-027", "TOPO-028", "TOPO-029", "TOPO-030", "TOPO-043", "TOPO-044", "TOPO-045", "TOPO-046"), INVENTORY),
    (("TOPO-002", "TOPO-009", "TOPO-010", "TOPO-011", "TOPO-012", "TOPO-016", "TOPO-017", "TOPO-018", "TOPO-025", "TOPO-026", "TOPO-031", "TOPO-032", "TOPO-033",
      "TOPO-036", "TOPO-037", "TOPO-038", "TOPO-039", "TOPO-040", "TOPO-042"), CONFIGURATION),
    (("TOPO-015", "TOPO-019", "TOPO-020", "TOPO-023", "TOPO-034", "TOPO-035", "TOPO-041"), RESILIENCE),
):
    for _id in _ids:
        THEMES[_id] = list(_controls)

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._ -]+")


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def controls_for(finding_id: str) -> list[tuple[str, str, str]]:
    return THEMES.get(str(finding_id), [])


def control_rows(findings: Iterable[dict[str, Any]], diagram_title: str = "Topology diagram and inventory") -> list[dict[str, str]]:
    """One row per (finding, control), after one row per control that the drawing itself supports.  ``finding`` is empty for the drawing."""
    rows: list[dict[str, str]] = []
    for framework, control, title in DIAGRAM + INVENTORY:
        rows.append({"finding": "", "severity": "", "evidence": diagram_title, "framework": framework, "control": control, "control_title": title, "devices": ""})
    for item in findings:
        devices = item.get("devices") or ""
        if isinstance(devices, list):
            devices = ", ".join(str(d) for d in devices)
        for framework, control, title in controls_for(str(item.get("id", ""))):
            rows.append({"finding": str(item.get("id", "")), "severity": str(item.get("severity", "")), "evidence": str(item.get("title", "")),
                         "framework": framework, "control": control, "control_title": title, "devices": str(devices)})
    return rows


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
            "audit/controls.csv                     The drawing and every finding, with the control it is evidence for (CIS Controls v8, NIST SP 800-53 Rev. 5, PCI DSS v4.0, ISO/IEC 27001:2022).\r\n")
    if inputs:
        text += "audit/inputs.sha256                    SHA-256 of the text of each capture this run was built from (UTF-8, after unzipping), so the same captures can be shown to give the same pack.\r\n"
    return text + "\r\n" + DISCLAIMER + "\r\n"
