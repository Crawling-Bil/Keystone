import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from .ssh_manager import SSHManager
from .device_detector import detect_driver


def check_ssh_port(
    ip,
    port=22,
    timeout=1.5
):
    try:
        with socket.create_connection(
            (
                str(ip),
                port
            ),
            timeout=timeout
        ):
            return True

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):
        return False


def _friendly_ssh_error(raw_error):
    text = str(raw_error)
    lowered = text.lower()

    if "banner" in lowered and ("reset" in lowered or "connection reset" in lowered):
        return (
            f"{text} — the device accepted the TCP connection but reset it "
            "before the SSH handshake started. If manual SSH from this same "
            "machine works fine, this usually means the device's own SSH "
            "attack-defense / IP-blacklist feature has temporarily blocked "
            "this source IP (common on Huawei VRP after a few rapid "
            "connection attempts). Wait a minute or two and try again, or "
            "check the switch with `display ip blacklist all` "
            "(Huawei) before retrying."
        )

    return text


def discover_device(
    ip,
    username,
    password
):

    started_at = time.time()

    result = {
        "ip": str(ip),
        "hostname": "Unknown",
        "vendor": "Unknown",
        "platform": "Unknown",
        "model": "Unknown",
        "version": "Unknown",
        "serial": "Unknown",
        "status": "offline",
        "discovery_log": []
    }


    def add_log(
        stage,
        status,
        message
    ):

        result[
            "discovery_log"
        ].append({
            "stage": stage,
            "status": status,
            "message": message
        })


    # NOTE: this used to do a quick raw-socket "probe" connection to
    # port 22 (open, then immediately close) before opening the real SSH
    # connection below. That put two separate TCP connections on the
    # device within milliseconds of each other on every single discovery
    # attempt. On Huawei VRP switches with SSH attack-defense enabled,
    # two rapid connections from the same source IP is exactly the
    # pattern that gets that IP temporarily blacklisted -- which then
    # also breaks the *next* discovery attempt (and can even affect a
    # manual SSH session for a short window afterwards). We now open
    # exactly one TCP/SSH connection per discovery attempt instead, and
    # classify a transport-level failure (refused/timeout/reset before
    # login was even attempted) as a tcp_probe failure so the UI still
    # tells "device not reachable" apart from "reachable, login failed".
    add_log(
        "tcp_probe",
        "running",
        "Connecting to SSH service (single connection attempt)."
    )


    add_log(
        "ssh_authentication",
        "running",
        "Connecting to SSH service."
    )


    ssh_result = SSHManager.connect(
        ip=str(ip),
        username=username,
        password=password
    )


    if not ssh_result.get(
        "success"
    ):

        raw_error = ssh_result.get(
            "error",
            "Unknown SSH error."
        )

        lowered_error = raw_error.lower()

        transport_level = (
            "authentication failed" not in lowered_error
            and any(
                token in lowered_error
                for token in (
                    "connection refused",
                    "timed out",
                    "timeout",
                    "no route to host",
                    "network is unreachable",
                    "connection reset",
                    "error reading ssh protocol banner",
                )
            )
        )

        result["status"] = (
            "offline" if transport_level else "failed"
        )

        result["error"] = _friendly_ssh_error(
            raw_error
        )

        if transport_level:

            add_log(
                "tcp_probe",
                "failed",
                result["error"]
            )

        else:

            add_log(
                "tcp_probe",
                "passed",
                "TCP port 22 is reachable."
            )

            add_log(
                "ssh_authentication",
                "failed",
                result["error"]
            )

        result[
            "discovery_duration"
        ] = round(
            time.time()
            -
            started_at,
            2
        )

        return result


    add_log(
        "tcp_probe",
        "passed",
        "TCP port 22 is reachable."
    )


    result["status"] = (
        "ssh_detected"
    )


    connection = ssh_result[
        "connection"
    ]


    add_log(
        "ssh_authentication",
        "passed",
        (
            "SSH authentication "
            "successful."
        )
    )


    try:

        add_log(
            "platform_detection",
            "running",
            (
                "Detecting network "
                "operating system."
            )
        )


        driver = detect_driver(
            connection,
            ssh_result[
                "netmiko_device_type"
            ]
        )


        add_log(
            "platform_detection",
            "passed",
            driver.__class__.__name__
        )


        add_log(
            "inventory",
            "running",
            (
                "Collecting read-only "
                "device inventory."
            )
        )


        info = (
            driver.get_device_info()
            or {}
        )


        result.update(
            info
        )


        result["status"] = (
            "online"
        )


        add_log(
            "inventory",
            "passed",
            (
                "Inventory collection "
                "completed."
            )
        )


    except Exception as exc:

        result["status"] = (
            "failed"
        )

        result["error"] = str(
            exc
        )


        add_log(
            "inventory",
            "failed",
            str(exc)
        )


    finally:

        try:

            connection.disconnect()

        except Exception:

            pass


    result[
        "discovery_duration"
    ] = round(
        time.time()
        -
        started_at,
        2
    )


    return result


def scan_range(
    start_ip,
    end_ip,
    username,
    password,
    max_workers=20
):

    start = ipaddress.ip_address(
        start_ip
    )

    end = ipaddress.ip_address(
        end_ip
    )


    if (
        start.version
        !=
        end.version
    ):

        raise ValueError(
            "Start IP and End IP must "
            "use the same IP version."
        )


    if int(end) < int(start):

        raise ValueError(
            "End IP cannot be lower "
            "than Start IP."
        )


    addresses = [

        ipaddress.ip_address(
            address
        )

        for address in range(
            int(start),
            int(end) + 1
        )

    ]


    max_workers = max(
        1,
        min(
            int(max_workers),
            50,
            len(addresses)
        )
    )


    results = []


    with ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:

        futures = {

            executor.submit(
                discover_device,
                ip,
                username,
                password
            ):
            ip

            for ip in addresses

        }


        for future in as_completed(
            futures
        ):

            ip = futures[
                future
            ]


            try:

                result = (
                    future.result()
                )


            except Exception as exc:

                result = {
                    "ip": str(ip),
                    "hostname": "Unknown",
                    "vendor": "Unknown",
                    "platform": "Unknown",
                    "model": "Unknown",
                    "version": "Unknown",
                    "serial": "Unknown",
                    "status": "failed",
                    "error": str(exc),
                    "discovery_log": [
                        {
                            "stage":
                                "discovery",
                            "status":
                                "failed",
                            "message":
                                str(exc)
                        }
                    ]
                }


            results.append(
                result
            )


    results.sort(
        key=lambda item:
            ipaddress.ip_address(
                item["ip"]
            )
    )


    return results
