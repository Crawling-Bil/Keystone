"""Unit tests for core.auth -- the session-based login gate added so
Keystone isn't wide open the moment NES_ALLOW_REMOTE is ever set (it
previously relied solely on binding to 127.0.0.1, with no credential
check at all if that binding were ever loosened).

These tests exercise core.auth directly (password persistence, lockout)
and, separately, the wiring into a minimal Flask app so a change to
app.py's route registration can't silently reopen a route without a
test noticing.
"""

from __future__ import annotations

import shutil
import tempfile
import time
import unittest
from pathlib import Path

from flask import Flask

import core.auth as auth


class TestAuthPasswordPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        self._orig_path = auth.AUTH_PASSWORD_PATH
        auth.AUTH_PASSWORD_PATH = Path(self.tmp_dir) / "data" / ".auth_password"
        self.addCleanup(setattr, auth, "AUTH_PASSWORD_PATH", self._orig_path)

    def test_generates_and_persists_a_password_once(self):
        first = auth._get_or_create_auth_password()
        second = auth._get_or_create_auth_password()
        self.assertEqual(first, second)
        self.assertTrue(auth.AUTH_PASSWORD_PATH.exists())
        self.assertGreaterEqual(len(first), 12)

    def test_env_var_overrides_generated_password(self, monkeypatch=None):
        import os
        os.environ["NES_AUTH_PASSWORD"] = "my-custom-password"
        try:
            self.assertEqual(auth._get_or_create_auth_password(), "my-custom-password")
            self.assertFalse(auth.AUTH_PASSWORD_PATH.exists())
        finally:
            del os.environ["NES_AUTH_PASSWORD"]


class TestLockout(unittest.TestCase):
    def setUp(self):
        auth._failed_attempts.clear()
        self.addCleanup(auth._failed_attempts.clear)

    def test_locks_out_after_max_attempts_then_clears_on_success(self):
        key = "1.2.3.4"
        for _ in range(auth.MAX_ATTEMPTS):
            self.assertFalse(auth._is_locked_out(key))
            auth._record_failed_attempt(key)
        self.assertTrue(auth._is_locked_out(key))
        auth._clear_failed_attempts(key)
        self.assertFalse(auth._is_locked_out(key))

    def test_old_attempts_outside_the_window_do_not_count(self):
        key = "5.6.7.8"
        for _ in range(auth.MAX_ATTEMPTS):
            auth._failed_attempts.setdefault(key, []).append(
                time.time() - auth.LOCKOUT_SECONDS - 1
            )
        self.assertFalse(auth._is_locked_out(key))


def _build_test_app(password: str, tmp_path: Path) -> Flask:
    app = Flask(__name__, template_folder=str(Path(__file__).resolve().parents[1] / "templates"))
    app.config.update(SECRET_KEY="test-secret")

    auth.AUTH_PASSWORD_PATH = tmp_path / ".auth_password"

    import os
    os.environ["NES_AUTH_PASSWORD"] = password

    @app.get("/")
    def dashboard():
        return "dashboard"

    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    auth.register(app)
    return app


class TestLoginGateWiring(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp_dir, ignore_errors=True)
        auth._failed_attempts.clear()
        self.app = _build_test_app("secret123", self.tmp_dir)
        self.client = self.app.test_client()
        self.addCleanup(lambda: __import__("os").environ.pop("NES_AUTH_PASSWORD", None))

    def test_protected_route_redirects_to_login_when_unauthenticated(self):
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_health_endpoint_is_exempt(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)

    def test_wrong_password_is_rejected(self):
        response = self.client.post("/login", data={"password": "wrong"})
        self.assertEqual(response.status_code, 401)

    def test_correct_password_grants_access(self):
        login = self.client.post("/login", data={"password": "secret123"}, follow_redirects=False)
        self.assertEqual(login.status_code, 302)
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_logout_revokes_access(self):
        self.client.post("/login", data={"password": "secret123"})
        self.client.get("/logout")
        response = self.client.get("/", follow_redirects=False)
        self.assertEqual(response.status_code, 302)

    def test_disable_auth_env_var_bypasses_gate_entirely(self):
        import os
        os.environ["NES_DISABLE_AUTH"] = "1"
        try:
            app = _build_test_app("secret123", self.tmp_dir)
            client = app.test_client()
            response = client.get("/", follow_redirects=False)
            self.assertEqual(response.status_code, 200)
        finally:
            del os.environ["NES_DISABLE_AUTH"]


if __name__ == "__main__":
    unittest.main()
