"""Regression tests for F5 UCS ingestion and the security-module layer of the Load Balancer Analyzer."""

from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from datetime import date
from pathlib import Path

from features.lb_analyzer import bigip_rules, bigip_ucs, service, ucs_reader

TODAY = date(2026, 10, 14)

BIGIP_CONF = """#TMSH-VERSION: 15.1.8
asm policy /Common/pol_web {
    active
    encoding utf-8
    policy-template POLICY_TEMPLATE_FUNDAMENTAL
}
asm policy /Common/pol_old {
    active
}
asm policy /Common/pol_inactive {
    encoding utf-8
}
ltm policy /Common/asm_web {
    controls { asm }
    requires { http }
    rules {
        r1 {
            actions {
                1 {
                    asm
                    enable
                    policy /Common/pol_web
                }
            }
            ordinal 1
        }
    }
    strategy /Common/first-match
}
ltm pool /Common/p1 {
    members {
        /Common/10.0.0.1:80 {
            address 10.0.0.1
            session user-disabled
        }
    }
    monitor /Common/http
}
ltm virtual /Common/vs_web {
    destination /Common/10.0.0.10:80
    ip-protocol tcp
    pool /Common/p1
    policies { asm_web { } }
    profiles { /Common/http { } /Common/tcp { } }
}
security dos profile /Common/dos_unused {
    app-service none
}
security log profile /Common/log_unused {
    app-service none
}
"""
BASE_CONF = """sys global-settings {
    hostname lab-ltm1.example.com
}
sys provision asm {
    level nominal
}
sys file ssl-cert /Common/web.crt {
    cache-path /config/filestore/files_d/Common_d/certificate_d/:Common:web.crt_1_1
    certificate-key-size 2048
}
ltm profile client-ssl /Common/cs_web {
    cert /Common/web.crt
    key /Common/web.key
}
"""
VERSION = "Product: BIG-IP\nVersion: 15.1.8\nBuild: 0.0.7\nEdition: Final\nDate: Wed Jan 1 00:00:00 PST 2025\n"
LICENSE = (
    "Usage : Production\nVendor : F5 Networks, Inc.\nRegistration key : AAAAA-BBBBB-CCCCC-DDDDD-EEEEEEE\nDossier : deadbeefdeadbeef\n"
    "active module : Local Traffic Manager, VE|ABCDEF\ntimelimited module : IP Intelligence|ABC|20240101|20260901|Subscription\n"
)
BIGDB = "[Log.Tmm.Level]\nvalue=Debug\ndefault=Notice\n\n[Systemauth.Password]\nvalue=hunter2\ndefault=x\n\n[Same.Key]\nvalue=1\ndefault=1\n"
PATCH_DISABLED = """--- /config/bigip.conf\t2026-06-01 17:00:00.000000000 +0700
+++ /config/.diffVersions//config/bigip.conf/bigip.conf\t2026-05-30 10:00:00.000000000 +0700
@@ -3,6 +3,8 @@ ltm pool /Common/p1 {
     members {
         /Common/10.0.0.1:80 {
             address 10.0.0.1
-            session user-disabled
         }
@@ -40,3 +41,4 @@ auth user /Common/bob {
-    encrypted-password $6$salt$hashvalue
-    description changed
"""
PATCH_NOISE = """--- /config/bigip.conf\t2026-06-02 17:00:00.000000000 +0700
+++ /config/.diffVersions//config/bigip.conf/bigip.conf\t2026-06-02 16:00:00.000000000 +0700
@@ -9,3 +9,3 @@ asm device-sync /Common/x/y {
-    timestamp 200
+    timestamp 100
"""
PRIVATE_KEY = b"-----BEGIN RSA PRIVATE KEY-----\nSENTINEL-PRIVATE-KEY-BODY\n-----END RSA PRIVATE KEY-----\n"


def _make_cert() -> bytes | None:
    """A SHA-1 self-signed leaf, made with the openssl CLI (None when it is not installed or refuses SHA-1)."""
    if not shutil.which("openssl"):
        return None
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "c.der"
        proc = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(Path(tmp) / "k.pem"), "-sha1", "-days", "20", "-subj", "/CN=web.example.com",
                               "-addext", "subjectAltName=DNS:web.example.com,DNS:www.example.com", "-addext", "basicConstraints=CA:FALSE", "-outform", "DER", "-out", str(out)], capture_output=True)
        return out.read_bytes() if proc.returncode == 0 and out.exists() else None


PATCH_TIME = 1780300800            # 2026-06-01 08:00:00 UTC


def _tar(members: dict[str, bytes], gz: bool = True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = PATCH_TIME
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _ucs(cert: bytes | None = None) -> bytes:
    members = {
        "config/bigip.conf": BIGIP_CONF.encode(), "config/bigip_base.conf": BASE_CONF.encode(), "config/ucs_version": VERSION.encode(), "config/bigip.license": LICENSE.encode(),
        "config/BigDB.dat": BIGDB.encode(), "config/startup": b"#!/bin/sh\necho custom\n", "config/ssl/ssl.key/web.key": PRIVATE_KEY, "etc/shadow": b"root:$6$hash::0:99999:7:::\n",
        "var/tmp/unrelated.bin": b"x" * 1000,
        "config/.diffVersions/config/bigip.conf/12.patch": PATCH_DISABLED.encode(), "config/.diffVersions/config/bigip.conf/13.patch": PATCH_NOISE.encode(), "config/.diffVersions/config/BigDB.dat/14.patch": b"@@ -1 +1 @@\n-value=1\n+value=2\n",
        "etc/passwd": b"root:x:0:0:root:/root:/bin/bash\nbob:x:500:500::/home/bob:/bin/bash\nnobody:x:99:99::/:/sbin/nologin\n", "etc/hosts.deny": b"sshd : ALL EXCEPT 127.\nALL : ALL\n",
        "config/bigip/auth/userrolepartitions": b"# generated\nroot 0 [All]\nalice 0 [All]\n", "config/bigip/kstore/master": b"MASTERKEY-SENTINEL",
        "var/config/rest/iapps/RPMS.save/f5-iappslx-waf-1.5.0-0.0.1657.noarch.rpm": b"rpm", "config/failover/active": b"#!/bin/sh\n# default\n/usr/bin/logger custom\n",
        "config/httpd/conf.d/auth_pam.conf": b"x", "config/httpd/conf.d/extra.conf": b"SetEnv A B\n",
    }
    if cert:
        members["config/filestore/files_d/Common_d/certificate_d/:Common:web.crt_1_1"] = cert
    return _tar(members)


class UcsReaderTests(unittest.TestCase):
    def test_reads_config_license_db_and_never_keeps_secrets(self):
        bundle = ucs_reader.read_ucs(io.BytesIO(_ucs()))
        self.assertIn("ltm virtual /Common/vs_web", bundle.text)
        self.assertEqual(bundle.version["Version"], "15.1.8")
        self.assertEqual(bundle.license["timelimited"][0]["end"], date(2026, 9, 1))
        self.assertEqual(set(bundle.db), {"Log.Tmm.Level", "Systemauth.Password"})                  # unchanged Same.Key is dropped
        self.assertEqual(bundle.db["Systemauth.Password"]["value"], "<hidden>")                   # secret-looking db values are hidden
        self.assertTrue(bundle.has_startup_additions)
        blob = repr(bundle.__dict__)
        for needle in ("SENTINEL-PRIVATE-KEY-BODY", "AAAAA-BBBBB", "deadbeef", "hunter2", "$6$hash", "MASTERKEY-SENTINEL", "$6$salt"):
            self.assertNotIn(needle, blob)
        self.assertEqual(bundle.omitted.get("private keys / password files"), 3)           # key, shadow, master key store

    def test_not_gzip_and_missing_config_give_readable_errors(self):
        with self.assertRaises(ucs_reader.UcsError) as ctx:
            ucs_reader.read_ucs(io.BytesIO(b"Salted__" + b"\x00" * 64))                           # what an encrypted UCS looks like
        self.assertIn("passphrase", str(ctx.exception))
        with self.assertRaises(ucs_reader.UcsError) as ctx:
            ucs_reader.read_ucs(io.BytesIO(_tar({"config/other.txt": b"x"})))
        self.assertIn("bigip.conf", str(ctx.exception))

    def test_member_limit_stops_a_tar_bomb(self):
        original = ucs_reader.MAX_MEMBERS
        ucs_reader.MAX_MEMBERS = 3
        try:
            with self.assertRaises(ucs_reader.UcsError):
                ucs_reader.read_ucs(io.BytesIO(_tar({f"f{i}": b"x" for i in range(10)})))
        finally:
            ucs_reader.MAX_MEMBERS = original

    def test_expansion_and_time_limits(self):
        original = (ucs_reader.MAX_UNCOMPRESSED_BYTES, ucs_reader.MAX_SECONDS)
        try:
            ucs_reader.MAX_UNCOMPRESSED_BYTES = 500
            with self.assertRaises(ucs_reader.UcsError) as ctx:
                ucs_reader.read_ucs(io.BytesIO(_tar({"config/bigip.conf": b"x" * 2000})))
            self.assertIn("expands", str(ctx.exception))
            ucs_reader.MAX_UNCOMPRESSED_BYTES, ucs_reader.MAX_SECONDS = original[0], -1
            with self.assertRaises(ucs_reader.UcsError) as ctx:
                ucs_reader.read_ucs(io.BytesIO(_ucs()))
            self.assertIn("longer than", str(ctx.exception))
        finally:
            ucs_reader.MAX_UNCOMPRESSED_BYTES, ucs_reader.MAX_SECONDS = original

    def test_upload_hook_ignores_plain_text(self):
        self.assertIsNone(bigip_ucs.read_upload("bigip.conf", io.BytesIO(BIGIP_CONF.encode())))
        text = bigip_ucs.read_upload("x.ucs", io.BytesIO(_ucs()))
        self.assertIsNotNone(bigip_ucs.bundle_of(text))
        self.assertIn("asm policy", text)


class UcsFilesAndHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = ucs_reader.read_ucs(io.BytesIO(_ucs()))

    def test_history_keeps_only_administrator_changes(self):
        self.assertEqual([c["revision"] for c in self.bundle.history], [12])                  # BigDB.dat patch ignored, timestamp-only patch dropped
        change = self.bundle.history[0]
        self.assertEqual(change["events"][0], {"kind": "member-disabled", "object": "/Common/p1", "member": "/Common/10.0.0.1:80"})
        self.assertEqual((change["added"], change["removed"]), (3, 0))                        # '-' lines are the ones the save added
        blob = repr(change["sample"])
        self.assertIn("encrypted-password <hidden>", blob)
        self.assertNotIn("$6$salt", blob)

    def test_accounts_wrappers_packages_and_custom_files(self):
        self.assertEqual([a["name"] for a in self.bundle.os_accounts if a["login"]], ["root", "bob"])
        self.assertNotIn("x:0:0", repr(self.bundle.os_accounts))                                # password field and uid are dropped
        self.assertEqual(self.bundle.role_partitions[1], {"user": "alice", "role_id": "0", "partitions": "All"})
        self.assertEqual(self.bundle.tcp_wrappers["deny"][0], {"daemon": "sshd", "clients": "ALL EXCEPT 127."})
        self.assertEqual(self.bundle.packages, [{"name": "f5-iappslx-waf", "version": "1.5.0", "release": "0.0.1657"}])
        kinds = {c["path"]: c["kind"] for c in self.bundle.custom_files}
        self.assertEqual(kinds["/config/httpd/conf.d/extra.conf"], "custom httpd configuration")
        self.assertTrue(kinds["/config/failover/active"].startswith("failover script"))
        self.assertNotIn("/config/httpd/conf.d/auth_pam.conf", kinds)                          # stock file


class UcsAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert = _make_cert()
        cls.text = bigip_ucs.read_upload("x.ucs", io.BytesIO(_ucs(cls.cert)))
        cls.result = service.analyze(cls.text, "x.ucs", today=TODAY)
        cls.ids = {f["id"] for f in cls.result["findings"]}
        cls.sections = {s["id"]: s for s in cls.result["sections"]}

    def test_asm_attachment_and_findings(self):
        rows = {r["name"]: r for r in self.sections["asm_policies"]["rows"]}
        self.assertEqual(rows["pol_web"]["attached"], ["vs_web"])
        self.assertEqual(rows["pol_old"]["attached"], ["(not attached)"])
        by_obj = {f["object"]: f for f in self.result["findings"] if f["id"] == "LB-ASM-001"}
        self.assertEqual(by_obj["asm policy pol_old"]["severity"], "low")
        self.assertEqual(by_obj["asm policy pol_inactive"]["severity"], "info")
        self.assertNotIn("asm policy pol_web", by_obj)

    def test_unused_dos_and_log_profiles(self):
        self.assertIn("LB-DOS-001", self.ids)
        self.assertIn("LB-LOG-001", self.ids)

    def test_license_and_db_findings(self):
        self.assertIn("LB-LIC-001", self.ids)                                                   # subscription ended 2026-09-01
        self.assertIn("LB-SYS-010", self.ids)                                                   # Log.Tmm.Level = Debug
        self.assertIn("LB-SYS-011", self.ids)                                                   # custom /config/startup
        self.assertIn("ucs_archive", self.sections)
        self.assertEqual({r["key"] for r in self.sections["sys_db"]["rows"]}, {"Log.Tmm.Level", "Systemauth.Password"})

    def test_certificate_details_come_from_the_archive(self):
        if not self.cert:
            self.skipTest("openssl CLI cannot create a SHA-1 certificate here")
        row = self.sections["certificates"]["rows"][0]
        self.assertEqual(row["san"], ["web.example.com", "www.example.com"])
        self.assertTrue(row["signature"].lower().startswith("sha1"))
        self.assertEqual(row["used_by"], ["cs_web"])
        self.assertIn("LB-CRT-005", self.ids)                                                   # SHA-1 leaf
        self.assertIn("LB-CRT-004", self.ids)                                                   # self-signed leaf
        self.assertIn("LB-CRT-002", self.ids)                                                   # 20-day certificate

    def test_stale_disabled_member_is_reported_from_history(self):
        finding_ = next(f for f in self.result["findings"] if f["id"] == "LB-CHG-001")
        self.assertIn("10.0.0.1:80", finding_["object"])
        self.assertIn("2026-06-01", finding_["detail"])
        sections = {s["id"]: s for s in self.result["sections"]}
        self.assertEqual(sections["change_still_disabled"]["rows"][0]["current"], "yes")
        accounts = {r["user"]: r for r in sections["accounts"]["rows"]}
        self.assertEqual(accounts["alice"]["defined"], "no (remote or removed)")              # in the role map, not configured locally
        self.assertEqual(accounts["bob"]["os"], "login shell /bin/bash")

    def test_inventory_counts_every_object_type(self):
        types = {r["type"]: r for r in self.sections["inventory"]["rows"]}
        self.assertEqual(types["asm policy"]["count"], 3)
        self.assertEqual(types["asm policy"]["status"], "listed on the Security tab")
        self.assertEqual(types["ltm virtual"]["status"], "analysed")

    def test_plain_conf_still_works_without_ucs_sections(self):
        result = service.analyze(BIGIP_CONF + BASE_CONF, "bigip.conf", today=TODAY)
        ids = {s["id"] for s in result["sections"]}
        self.assertNotIn("ucs_archive", ids)
        self.assertIn("inventory", ids)
        self.assertNotIn("LB-LIC-001", {f["id"] for f in result["findings"]})


class OverflowTests(unittest.TestCase):
    def test_cap_is_per_rule_so_a_noisy_rule_cannot_hide_another(self):
        from features.analyzer_core.findings import finding
        noisy = [finding("LB-REF-001", "low", "Objects", f"dangling {i}", obj=f"o{i}") for i in range(40)]
        other = [finding("LB-OBJ-009", "high", "Objects", "important", obj="x")]
        out = bigip_rules._overflow(noisy + other)
        self.assertEqual(sum(1 for f in out if f["id"] == "LB-REF-001"), bigip_rules.MAX_PER_RULE + 1)    # 25 + the summary line
        self.assertEqual(sum(1 for f in out if f["id"] == "LB-OBJ-009"), 1)
        self.assertTrue(any("15 more" in f["title"] for f in out))


if __name__ == "__main__":
    unittest.main()
