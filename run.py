from __future__ import annotations

import json
import os
import socket
import threading
import urllib.request
import webbrowser

from waitress import serve

from app import app, APP_VERSION

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def open_browser(url: str) -> None:
    webbrowser.open(url, new=2)


def check_bind(host: str) -> None:
    """Keystone has no login, so it must stay on this computer unless the person says otherwise."""
    if host in LOCAL_HOSTS:
        return
    if os.environ.get("NES_ALLOW_REMOTE") != "1":
        raise SystemExit(
            f"Refusing to listen on {host}: Keystone has no login and is meant for this computer only.\n"
            "Remove the NES_HOST setting to use the normal address (127.0.0.1).\n"
            "Only if you understand the risk and want other machines to reach it, also set NES_ALLOW_REMOTE=1."
        )
    print(
        f"WARNING: listening on {host} with NES_ALLOW_REMOTE=1. Keystone has no login, so anyone who can "
        "reach this address can run its tools, including the ones that push firmware and configuration to "
        "devices. Only do this on a trusted, isolated network."
    )


def is_keystone(url: str) -> bool:
    """True when the address already answers like a running Keystone."""
    try:
        with urllib.request.urlopen(f"{url}/api/health", timeout=2) as response:
            return json.load(response).get("application") == "Keystone"
    except Exception:
        return False


def port_in_use(host: str, port: int) -> bool:
    probe = "127.0.0.1" if host in {"0.0.0.0", "::", "localhost"} else host
    family = socket.AF_INET6 if ":" in probe else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((probe, port)) == 0


def main() -> None:
    host = os.environ.get("NES_HOST", "127.0.0.1")
    try:
        port = int(os.environ.get("NES_PORT", "8002"))
    except ValueError:
        raise SystemExit("NES_PORT must be a number, for example 8010.")

    check_bind(host)

    url_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    url = f"http://{url_host}:{port}"
    open_it = os.environ.get("NES_OPEN_BROWSER", "1") != "0"

    if port_in_use(host, port):
        if is_keystone(url):
            print(f"Keystone is already running at {url}.")
            if open_it:
                print("Opening it in your browser. You do not need to start it again.")
                open_browser(url)
            return
        raise SystemExit(
            f"Port {port} is already used by another program.\n"
            "Close that program, or start Keystone on another port:\n"
            "  Windows:      set NES_PORT=8010   then run start_windows.bat\n"
            "  macOS/Linux:  NES_PORT=8010 ./start_mac_linux.sh"
        )

    if open_it:
        threading.Timer(1.0, open_browser, args=(url,)).start()
    print(f"Keystone v{APP_VERSION} is running.")
    print(f"  Open: {url}" + ("   (your browser opens by itself)" if open_it else ""))
    print("  No login needed. Only this computer can reach it.")
    print("  Keep this window open while you work. Press Ctrl+C to stop Keystone.")
    try:
        serve(app, host=host, port=port, threads=8, channel_timeout=600)
    except OSError as exc:
        raise SystemExit(f"Keystone could not start on {host}:{port}: {exc}")


if __name__ == "__main__":
    main()
