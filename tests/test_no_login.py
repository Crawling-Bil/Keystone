"""Keystone has no login: a fresh download opens straight to the dashboard.

These tests pin that behaviour, and the small guard (core/local_guard.py) that
replaces the login: only this computer's own names are answered, and a request
that another website started is refused.
"""
from __future__ import annotations

import json
import socket

import pytest

import run
from app import create_app
from core import local_guard


@pytest.fixture()
def client(monkeypatch):
    for name in ("NES_ALLOW_REMOTE", "NES_ALLOWED_HOSTS", "NES_AUTH_PASSWORD", "NES_DISABLE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# --- no login ------------------------------------------------------------------------------------------------------

def test_dashboard_opens_without_any_login(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"password" not in response.data.lower()


def test_main_pages_open_without_login(client):
    for path in ("/convert/switch", "/switch-analyzer", "/wireless", "/api/health", "/about"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "Location" not in response.headers, path


def test_there_is_no_login_or_logout_route(client):
    assert client.get("/login").status_code == 404
    assert client.post("/login", data={"password": "x"}).status_code == 404
    assert client.get("/logout").status_code == 404


def test_old_login_settings_change_nothing(monkeypatch):
    monkeypatch.setenv("NES_AUTH_PASSWORD", "left-over-from-an-old-install")
    app = create_app()
    app.config["TESTING"] = True
    assert app.test_client().get("/").status_code == 200


# --- the guard -----------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("base", ["http://localhost:8002", "http://127.0.0.1:8002", "http://[::1]:8002"])
def test_this_computers_own_names_are_answered(client, base):
    assert client.get("/api/health", base_url=base).status_code == 200


def test_a_foreign_host_name_is_refused(client):
    """DNS rebinding: a hostile site pointing its own name at 127.0.0.1 keeps its name in the Host header."""
    response = client.get("/api/health", base_url="http://rebind.attacker.example:8002")
    assert response.status_code == 403
    assert b"127.0.0.1:8002" in response.data


def test_a_lan_address_is_refused_unless_remote_access_is_allowed(client, monkeypatch):
    assert client.get("/", base_url="http://192.168.1.20:8002").status_code == 403
    monkeypatch.setenv("NES_ALLOW_REMOTE", "1")
    assert client.get("/", base_url="http://192.168.1.20:8002").status_code == 200


def test_extra_names_can_be_added(client, monkeypatch):
    assert client.get("/", base_url="http://keystone-lab:8002").status_code == 403
    monkeypatch.setenv("NES_ALLOWED_HOSTS", "keystone-lab, other-name")
    assert client.get("/", base_url="http://keystone-lab:8002").status_code == 200


# A POST to a GET-only route answers 405 when the guard lets it through and 403 when the guard refuses it.

def test_a_post_from_another_website_is_refused(client):
    assert client.post("/api/health", headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/health", headers={"Origin": "null"}).status_code == 403
    assert client.post("/api/health", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert client.post("/api/health", headers={"Sec-Fetch-Site": "same-site"}).status_code == 403


def test_a_post_from_a_keystone_page_goes_through(client):
    assert client.post("/api/health", headers={"Origin": "http://localhost", "Sec-Fetch-Site": "same-origin"}).status_code == 405
    assert client.post("/api/health", base_url="http://127.0.0.1:8002",
                       headers={"Origin": "http://127.0.0.1:8002"}).status_code == 405


def test_a_post_from_a_script_goes_through(client):
    """curl, Python and the test client send neither header, so terminal use is never blocked."""
    assert client.post("/api/health").status_code == 405


def test_a_cross_site_post_is_still_refused_with_remote_access_on(client, monkeypatch):
    monkeypatch.setenv("NES_ALLOW_REMOTE", "1")
    assert client.post("/api/health", base_url="http://192.168.1.20:8002",
                       headers={"Origin": "https://evil.example"}).status_code == 403
    assert client.post("/api/health", base_url="http://192.168.1.20:8002",
                       headers={"Origin": "http://192.168.1.20:8002"}).status_code == 405


def test_get_requests_are_not_judged_by_origin(client):
    assert client.get("/api/health", headers={"Origin": "https://evil.example"}).status_code == 200


def test_host_name_parsing():
    assert local_guard.host_name("localhost:8002") == "localhost"
    assert local_guard.host_name("LOCALHOST") == "localhost"
    assert local_guard.host_name("[::1]:8002") == "::1"
    assert local_guard.host_name("") == ""


# --- run.py ------------------------------------------------------------------------------------------------------

def test_run_refuses_a_network_address_without_the_explicit_switch(monkeypatch):
    monkeypatch.delenv("NES_ALLOW_REMOTE", raising=False)
    with pytest.raises(SystemExit) as stop:
        run.check_bind("0.0.0.0")
    assert "no login" in str(stop.value) and "NES_ALLOW_REMOTE=1" in str(stop.value)
    run.check_bind("127.0.0.1")
    run.check_bind("localhost")


def test_run_allows_a_network_address_with_the_switch(monkeypatch, capsys):
    monkeypatch.setenv("NES_ALLOW_REMOTE", "1")
    run.check_bind("0.0.0.0")
    assert "WARNING" in capsys.readouterr().out


def test_port_in_use_sees_a_listening_socket():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        assert run.port_in_use("127.0.0.1", port) is True
    assert run.port_in_use("127.0.0.1", port) is False


def test_a_second_start_reopens_the_running_keystone(monkeypatch, capsys):
    opened = []
    monkeypatch.setenv("NES_PORT", "8123")
    monkeypatch.setenv("NES_HOST", "127.0.0.1")
    monkeypatch.delenv("NES_OPEN_BROWSER", raising=False)
    monkeypatch.setattr(run, "port_in_use", lambda host, port: True)
    monkeypatch.setattr(run, "is_keystone", lambda url: True)
    monkeypatch.setattr(run, "open_browser", opened.append)
    run.main()
    assert opened == ["http://127.0.0.1:8123"]
    assert "already running" in capsys.readouterr().out


def test_another_program_on_the_port_gives_a_plain_message(monkeypatch):
    monkeypatch.setenv("NES_PORT", "8123")
    monkeypatch.setenv("NES_HOST", "127.0.0.1")
    monkeypatch.setattr(run, "port_in_use", lambda host, port: True)
    monkeypatch.setattr(run, "is_keystone", lambda url: False)
    with pytest.raises(SystemExit) as stop:
        run.main()
    assert "NES_PORT=8010" in str(stop.value)


def test_a_bad_port_gives_a_plain_message(monkeypatch):
    monkeypatch.setenv("NES_PORT", "eighty")
    with pytest.raises(SystemExit) as stop:
        run.main()
    assert "NES_PORT must be a number" in str(stop.value)


def test_health_answers_with_the_name_run_py_looks_for(client):
    assert json.loads(client.get("/api/health").data)["application"] == "Keystone"
