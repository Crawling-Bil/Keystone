import io
import os
import unittest

from openpyxl import Workbook

from features.ztp.core import device_import as imp


def _workbook_bytes(rows):
    workbook = Workbook()
    sheet = workbook.active
    for row in rows:
        sheet.append(row)
    buffer = io.BytesIO()
    workbook.save(buffer)
    buffer.seek(0)
    return buffer


class BuildTemplateWorkbookTests(unittest.TestCase):
    def test_creates_a_readable_xlsx_with_expected_headers(self):
        path = imp.build_template_workbook()
        try:
            self.assertTrue(path.exists())
            rows = imp.parse_workbook(str(path))
            self.assertEqual(len(rows), 1)
            row_number, record = rows[0]
            self.assertEqual(row_number, 2)
            self.assertEqual(record["esn"], "2102311LDL0000000806")
            self.assertEqual(record["hostname"], "TTC-SWAC-NEW-01")
            self.assertEqual(record["mgmt_ip"], "10.50.1.11")
        finally:
            os.unlink(path)


class ParseWorkbookTests(unittest.TestCase):
    def test_maps_headers_to_store_fields(self):
        buf = _workbook_bytes([
            ["ESN (Serial Number)", "Hostname", "Management IP", "SSH Password"],
            ["2102311LDL0000000806", "sw-01", "10.50.1.11", "Str0ngP@ss!"],
        ])
        rows = imp.parse_workbook(buf)
        self.assertEqual(len(rows), 1)
        row_number, record = rows[0]
        self.assertEqual(row_number, 2)
        self.assertEqual(record, {
            "esn": "2102311LDL0000000806",
            "hostname": "sw-01",
            "mgmt_ip": "10.50.1.11",
            "vrp_password": "Str0ngP@ss!",
        })

    def test_header_matching_is_case_and_whitespace_insensitive(self):
        buf = _workbook_bytes([
            ["  esn  ", "MGMT IP"],
            ["2102311LDL0000000806", "10.50.1.11"],
        ])
        rows = imp.parse_workbook(buf)
        self.assertEqual(rows[0][1]["esn"], "2102311LDL0000000806")
        self.assertEqual(rows[0][1]["mgmt_ip"], "10.50.1.11")

    def test_skips_fully_blank_rows(self):
        buf = _workbook_bytes([
            ["ESN", "Hostname"],
            ["2102311LDL0000000806", "sw-01"],
            [None, None],
            ["", ""],
            ["2102311LDL0000000807", "sw-02"],
        ])
        rows = imp.parse_workbook(buf)
        self.assertEqual([r[1]["esn"] for r in rows], [
            "2102311LDL0000000806", "2102311LDL0000000807",
        ])

    def test_skips_rows_with_no_esn_even_if_other_columns_have_data(self):
        buf = _workbook_bytes([
            ["ESN", "Hostname"],
            ["", "sw-with-no-esn"],
            ["2102311LDL0000000806", "sw-01"],
        ])
        rows = imp.parse_workbook(buf)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1]["esn"], "2102311LDL0000000806")

    def test_rejects_workbook_with_no_esn_column(self):
        buf = _workbook_bytes([
            ["Hostname", "Management IP"],
            ["sw-01", "10.50.1.11"],
        ])
        with self.assertRaises(imp.DeviceImportError):
            imp.parse_workbook(buf)

    def test_rejects_empty_workbook(self):
        buf = _workbook_bytes([])
        with self.assertRaises(imp.DeviceImportError):
            imp.parse_workbook(buf)

    def test_ignores_unrecognized_columns(self):
        buf = _workbook_bytes([
            ["ESN", "Some Random Column"],
            ["2102311LDL0000000806", "whatever"],
        ])
        rows = imp.parse_workbook(buf)
        self.assertEqual(rows[0][1], {"esn": "2102311LDL0000000806"})

    def test_handles_a_stream_without_seekable_like_flasks_filestorage(self):
        # Regression: Flask's FileStorage.stream (what a real upload
        # hands routes.py) doesn't reliably expose .seekable(), which
        # openpyxl's zipfile reader requires -- confirmed failing with
        # "'SpooledTemporaryFile' object has no attribute 'seekable'"
        # via the Flask test client, which uses the same FileStorage
        # machinery as a real browser upload. A minimal stand-in with
        # only .read() (no .seekable()) reproduces it here without
        # needing the full Flask/Werkzeug upload machinery.
        class _ReadOnlyStream:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

        raw_bytes = _workbook_bytes([
            ["ESN", "Hostname"],
            ["2102311LDL0000000806", "sw-01"],
        ]).getvalue()

        rows = imp.parse_workbook(_ReadOnlyStream(raw_bytes))
        self.assertEqual(rows[0][1]["esn"], "2102311LDL0000000806")


if __name__ == "__main__":
    unittest.main()
