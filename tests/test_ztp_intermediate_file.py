import unittest

from features.ztp.core import intermediate_file as intf


def _device(**overrides):
    device = {
        "esn": "2102311LDL0000000806",
        "mac": "aa:bb:cc:dd:ee:01",
        "hostname": "TTC-SWAC-TEST-01",
        "vrp_version": "",
        "firmware_filename": "",
    }
    device.update(overrides)
    return device


class IntermediateFileTests(unittest.TestCase):
    FILESERVER = "sftp://ztp_user:ztp_pass@10.50.1.5:2222/"

    def test_rejects_non_sftp_fileserver_url(self):
        # Confirmed against the vendor doc: ZTP on this VRP family only
        # accepts SFTP for the intermediate/deployment file server.
        for bad_url in ["ftp://u:p@h/", "tftp://h/", "http://h/", "not-a-url"]:
            with self.assertRaises(intf.IntermediateFileError):
                intf.build_intermediate_file([_device()], bad_url)

    def test_rejects_empty_device_list(self):
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file([], self.FILESERVER)

    def test_has_mandatory_markers_and_global_fields(self):
        text, _ = intf.build_intermediate_file([_device()], self.FILESERVER, time_sn="20260829120000")
        self.assertTrue(text.startswith(";BEGIN ZTP CONFIG\n"))
        self.assertTrue(text.rstrip().endswith(";END ZTP CONFIG"))
        self.assertIn("[GLOBAL CONFIG]", text)
        self.assertIn(f"*FILESERVER={self.FILESERVER}", text)
        self.assertIn("*TIME_SN=20260829120000", text)
        self.assertIn("*DEVICE_TYPE_NUM=1", text)

    def test_esn_is_the_per_device_match_key(self):
        d1 = _device(esn="2102311LDL0000000806", hostname="DEVICE-A")
        d2 = _device(esn="2102311LDL0000000918", hostname="DEVICE-B")
        text, config_filenames = intf.build_intermediate_file([d1, d2], self.FILESERVER)
        self.assertIn("*DEVICE_TYPE_NUM=2", text)
        self.assertIn("ESN=2102311LDL0000000806", text)
        self.assertIn("ESN=2102311LDL0000000918", text)
        self.assertEqual(set(config_filenames), {"2102311LDL0000000806", "2102311LDL0000000918"})
        self.assertNotEqual(config_filenames["2102311LDL0000000806"], config_filenames["2102311LDL0000000918"])

    def test_config_file_always_included_software_only_when_requested(self):
        # No firmware_filename -> only the CFG deployment file.
        text, _ = intf.build_intermediate_file([_device()], self.FILESERVER)
        self.assertIn("*FILETYPENUM=1", text)
        self.assertIn("*TYPE_1=CFG", text)
        self.assertNotIn("TYPE_1=SOFTWARE", text)

        # firmware_filename set -> both SOFTWARE and CFG files, in that order.
        text, _ = intf.build_intermediate_file(
            [_device(firmware_filename="S5735-V2_V600R025C00SPC500.cc")], self.FILESERVER
        )
        self.assertIn("*FILETYPENUM=2", text)
        self.assertIn("*FILENAME_1=S5735-V2_V600R025C00SPC500.cc", text)
        self.assertIn("*TYPE_1=SOFTWARE", text)
        self.assertIn("*TYPE_2=CFG", text)

    def test_effective_mode_is_on_restart_for_generated_files(self):
        text, _ = intf.build_intermediate_file(
            [_device(firmware_filename="fw.cc")], self.FILESERVER
        )
        self.assertIn("*EFFECTIVE_MODE_1=0", text)
        self.assertIn("*EFFECTIVE_MODE_2=0", text)

    def test_device_missing_esn_is_rejected(self):
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file([_device(esn="")], self.FILESERVER)

    def test_sha256_included_when_file_exists_on_disk(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cfg_name = intf._sanitize_config_filename("TTC-SWAC-TEST-01")
            (root / cfg_name).write_text("dummy config content", encoding="utf-8")
            text, _ = intf.build_intermediate_file([_device()], self.FILESERVER, ztp_root=root)
            self.assertIn("SHA256_1=", text)

    def test_sha256_omitted_when_file_not_yet_present(self):
        text, _ = intf.build_intermediate_file([_device()], self.FILESERVER, ztp_root="/nonexistent/path")
        self.assertNotIn("SHA256_1=", text)

    # ------------------------------------------------------------------
    # Regression (production-debugger pass): this INI is strictly
    # line-oriented and parsed by the switch's own ZTP engine field by
    # field. fileserver_url/vrp_version/syslog_target/firmware_filename
    # all reached the file RAW with no rejection of embedded control
    # characters -- and the FILESERVER regex specifically does NOT
    # reliably reject an embedded newline (character classes like
    # [^@]+ don't exclude '\n', and a lone trailing '\n' satisfies `$`
    # without re.MULTILINE), so a pasted value with a stray newline
    # could inject an extra, malformed line into the generated .ini.
    # ------------------------------------------------------------------

    def test_rejects_newline_in_fileserver_url(self):
        bad_url = "sftp://u:p@10.50.1.5:2222/\nEXTRA_LINE=injected"
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file([_device()], bad_url)

    def test_rejects_lone_trailing_newline_in_fileserver_url(self):
        # Confirmed the SFTP-URL regex alone does NOT catch this case:
        # Python's `$` (without re.MULTILINE) matches just before a
        # single trailing newline, so this would otherwise slip through
        # the existing _SFTP_URL_RE.match() check untouched.
        bad_url = self.FILESERVER + "\n"
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file([_device()], bad_url)

    def test_rejects_newline_in_vrp_version(self):
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file(
                [_device(vrp_version="V600R025C00SPC500\nEXTRA=injected")], self.FILESERVER
            )

    def test_rejects_newline_in_firmware_filename(self):
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file(
                [_device(firmware_filename="fw.cc\nEXTRA=injected")], self.FILESERVER
            )

    def test_rejects_newline_in_syslog_target(self):
        with self.assertRaises(intf.IntermediateFileError):
            intf.build_intermediate_file(
                [_device()], self.FILESERVER, syslog_target="10.50.1.5:514\nEXTRA=injected"
            )

    def test_valid_values_with_no_control_characters_still_work(self):
        text, _ = intf.build_intermediate_file(
            [_device(vrp_version="V600R025C00SPC500", firmware_filename="fw.cc")],
            self.FILESERVER,
            syslog_target="10.50.1.5:514",
        )
        self.assertIn("VRPVER=V600R025C00SPC500", text)
        self.assertIn("SYSLOG_INFO=10.50.1.5:514", text)


if __name__ == "__main__":
    unittest.main()
