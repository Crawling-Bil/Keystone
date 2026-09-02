"""Bulk pre-registration of ZTP devices from an uploaded .xlsx workbook.

Column layout mirrors the Pre-Register Devices form field-for-field
(see templates/index.html and core.store.upsert_device()), so the
downloadable template and the manual form always agree on what a
device record needs -- there is exactly one place (store.py) that
defines what a valid device looks like; this module only gets data
into that same shape from spreadsheet rows instead of form fields.

Uses openpyxl, already a project dependency (see requirements.txt --
the Firmware Repository and Wireless Analyzer features already build
.xlsx exports the same way), so this adds no new pip dependency.
"""

from __future__ import annotations

import io
import tempfile
from pathlib import Path

from openpyxl import Workbook, load_workbook

# Column header -> core.store.upsert_device() field name. Matching
# is case/whitespace-insensitive (see _normalize_header()) so a
# harmlessly retyped header ("Mgmt IP" instead of "Management IP")
# still lands in the right field instead of silently being dropped.
_HEADER_TO_FIELD = {
    "esn (serial number)": "esn",
    "esn": "esn",
    "serial number": "esn",
    "mac address": "mac",
    "mac": "mac",
    "hostname": "hostname",
    "site": "site",
    "management ip": "mgmt_ip",
    "mgmt ip": "mgmt_ip",
    "subnet mask": "mgmt_mask",
    "mgmt mask": "mgmt_mask",
    "gateway": "gateway",
    "ssh username": "vrp_username",
    "vrp username": "vrp_username",
    "ssh password": "vrp_password",
    "vrp password": "vrp_password",
    "firmware filename": "firmware_filename",
    "firmware filename (optional)": "firmware_filename",
    "current vrp version": "vrp_version",
    "current vrp version (optional)": "vrp_version",
    "vrp version": "vrp_version",
    "vendor": "vendor",
    "model": "model",
}

# Column order in the generated template -- also doubles as "every
# field a device record can carry" for building the example row.
_TEMPLATE_COLUMNS = [
    ("ESN (Serial Number)", "esn", "2102311LDL0000000806"),
    ("MAC Address", "mac", "AA:BB:CC:DD:EE:01"),
    ("Hostname", "hostname", "TTC-SWAC-NEW-01"),
    ("Site", "site", "TTC"),
    ("Management IP", "mgmt_ip", "10.50.1.11"),
    ("Subnet Mask", "mgmt_mask", "255.255.255.0"),
    ("Gateway", "gateway", "10.50.1.1"),
    ("SSH Username", "vrp_username", "ztp-admin"),
    ("SSH Password", "vrp_password", "Str0ngP@ssw0rd!"),
    ("Firmware Filename (optional)", "firmware_filename", "S5735-V2_V600R025C00SPC500.cc"),
    ("Current VRP Version (optional)", "vrp_version", "V600R025C00SPC500"),
]


class DeviceImportError(ValueError):
    """Raised when the uploaded workbook itself can't be read at all
    (wrong file, no header row, no data) -- distinct from a single bad
    row, which is reported per-row instead of aborting the whole
    import (see routes.py's ztp_devices_import())."""


def build_template_workbook():
    """Write a blank .xlsx template (headers + one filled example row)
    to a temp file and return its path."""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "ZTP Devices"

    headers = [label for label, _field, _example in _TEMPLATE_COLUMNS]
    sheet.append(headers)
    sheet.append([example for _label, _field, example in _TEMPLATE_COLUMNS])

    for column_cells in sheet.columns:
        longest = max(len(str(cell.value)) for cell in column_cells if cell.value is not None)
        sheet.column_dimensions[column_cells[0].column_letter].width = min(40, longest + 2)

    fd, tmp_path = tempfile.mkstemp(prefix="ztp_device_template_", suffix=".xlsx")
    import os
    os.close(fd)
    workbook.save(tmp_path)
    return Path(tmp_path)


def _normalize_header(value):
    return " ".join(str(value or "").strip().lower().split())


def parse_workbook(file_stream):
    """Read an uploaded .xlsx and return [(row_number, record_dict), ...]
    -- row_number is the spreadsheet row (2-based, since row 1 is the
    header), for error messages that match what the user sees in Excel.

    record_dict has whatever fields the workbook's header row mapped
    to core.store fields -- validation of the record itself
    (required fields, ESN/MAC format) is left entirely to
    store.upsert_device(), so this module and the manual form never
    validate a device two different ways."""
    # openpyxl (via zipfile) needs a real seekable file-like object.
    # A path/BytesIO already qualifies, but Flask's FileStorage.stream
    # (what routes.py hands in for a real upload) doesn't reliably
    # expose .seekable() -- confirmed failing with "'SpooledTemporaryFile'
    # object has no attribute 'seekable'" even though the underlying
    # data is perfectly readable. Reading it fully into BytesIO first
    # sidesteps that regardless of which stream type openpyxl was
    # handed; ZTP device lists are small enough that buffering the
    # whole upload in memory here is not a concern.
    if not isinstance(file_stream, (str, Path)):
        file_stream = io.BytesIO(file_stream.read())

    try:
        workbook = load_workbook(file_stream, read_only=True, data_only=True)
    except Exception as exc:
        raise DeviceImportError(f"Could not read this file as an .xlsx workbook: {exc}") from exc

    sheet = workbook.active
    rows_iter = sheet.iter_rows(values_only=True)
    try:
        header_row = next(rows_iter)
    except StopIteration:
        raise DeviceImportError("The workbook is empty -- no header row found.")

    field_by_column = {}
    for index, header in enumerate(header_row):
        field = _HEADER_TO_FIELD.get(_normalize_header(header))
        if field:
            field_by_column[index] = field

    if "esn" not in field_by_column.values():
        raise DeviceImportError(
            "No \"ESN (Serial Number)\" column found -- download the template "
            "from this tab to get the expected column headers."
        )

    results = []
    for offset, row in enumerate(rows_iter, start=2):
        if row is None or all(cell is None or str(cell).strip() == "" for cell in row):
            continue  # blank spacer row -- not an error, just skip it

        record = {}
        for index, field in field_by_column.items():
            if index < len(row) and row[index] is not None:
                record[field] = str(row[index]).strip()

        if not record.get("esn"):
            continue  # a row with other data but no ESN isn't a device this store can key on

        results.append((offset, record))

    return results
