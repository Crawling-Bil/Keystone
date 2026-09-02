from __future__ import annotations

import os
import threading
import webbrowser

from waitress import serve

from app import app, APP_VERSION


def open_browser(url: str) -> None:
    webbrowser.open(url, new=2)


def main() -> None:
    host = os.environ.get("NES_HOST", "127.0.0.1")
    port = int(os.environ.get("NES_PORT", "8002"))

    if host not in {"127.0.0.1", "localhost", "::1"}:
        # The app has no login/auth layer — it's designed to be used
        # from localhost only. Lifecycle Manager routes in particular
        # accept device IPs + SSH credentials in plain JSON bodies, so
        # binding to a non-loopback address exposes an unauthenticated
        # "push firmware to any device" endpoint to the network.
        if os.environ.get("NES_ALLOW_REMOTE") != "1":
            raise SystemExit(
                f"Refusing to bind to {host}: this app has no authentication and is "
                "meant for localhost use only. Set NES_ALLOW_REMOTE=1 if you understand "
                "the risk and really want to expose it on your network."
            )
        print(
            f"WARNING: binding to {host} with NES_ALLOW_REMOTE=1 — this app has no "
            "login/CSRF protection. Anyone who can reach this address can push "
            "firmware to your devices. Only do this on a trusted, isolated network."
        )

    url_host = "127.0.0.1" if host in {"0.0.0.0", "::"} else host
    url = f"http://{url_host}:{port}"
    if os.environ.get("NES_OPEN_BROWSER", "1") != "0":
        threading.Timer(1.0, open_browser, args=(url,)).start()
    print(f"Network Engineer Suite v{APP_VERSION} running at {url}")
    print("Press Ctrl+C to stop.")
    serve(app, host=host, port=port, threads=8, channel_timeout=600)


if __name__ == "__main__":
    main()
