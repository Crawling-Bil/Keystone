from __future__ import annotations

import compileall
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from unittest.mock import patch

BASE_DIR = Path(__file__).resolve().parent
REQUIRED = (
    "app.py",
    "run.py",
    "core/database.py",
    "features/configuration_studio/routes.py",
    "features/configuration_studio/service.py",
    "features/configuration_studio/converter_engine/engine.py",
    "features/configuration_studio/mappings/migration_inventory.csv",
    "features/wireless_center/routes.py",
    "features/wireless_center/inventory_master.py",
    "features/wireless_center/parsers/config_parser.py",
    "features/wireless_center/parsers/cisco9800_parser.py",
    "features/wireless_center/analyzers/relationship_analyzer.py",
    "features/wireless_center/analyzers/assessment_analyzer.py",
    "features/wireless_center/exporters/excel_exporter.py",
    "features/switch_analyzer/routes.py",
    "features/switch_analyzer/service.py",
    "templates/switch_analyzer.html",
    "static/js/switch_analyzer.js",
    "features/lifecycle_manager/routes.py",
    "features/lifecycle_manager/core/precheck_engine.py",
    "features/lifecycle_manager/core/upgrade_engine.py",
    "features/lifecycle_manager/core/tftp_server.py",
    "features/lifecycle_manager/core/ftp_server.py",
    "features/lifecycle_manager/templates/index.html",
    "features/lifecycle_manager/static/js/app.js",
    "templates/dashboard.html",
    "templates/configuration.html",
    "templates/wireless.html",
    "static/css/app.css",
)
DEPENDENCIES = ("flask", "waitress", "openpyxl", "netmiko", "scp", "paramiko", "pyftpdlib")


def suite_python() -> Path | None:
    for candidate in (BASE_DIR / ".venv/bin/python", BASE_DIR / ".venv/Scripts/python.exe"):
        if candidate.is_file():
            return candidate
    return None


def inside_suite_venv() -> bool:
    try:
        return Path(sys.prefix).resolve() == (BASE_DIR / ".venv").resolve()
    except OSError:
        return False


def rerun_in_venv() -> int | None:
    python = suite_python()
    if python and not inside_suite_venv():
        return subprocess.call([str(python), str(Path(__file__).resolve())], cwd=BASE_DIR)
    return None


def run_smoke_tests() -> list[str]:
    errors: list[str] = []

    # core/auth.py fronts every route with a shared-password login gate.
    # This script is verifying that a fresh install's features work, not
    # exercising that gate, so pin a private password for this run (via
    # NES_AUTH_PASSWORD) unless the environment already disables auth or
    # sets its own -- then log the test client in before touching any
    # protected route, instead of every route failing on a login redirect.
    auth_disabled = os.environ.get("NES_DISABLE_AUTH", "").strip() == "1"
    login_password = os.environ.setdefault("NES_AUTH_PASSWORD", "keystone-verify-install")

    try:
        from app import app

        client = app.test_client()

        if not auth_disabled:
            login_response = client.post("/login", data={"password": login_password})
            if login_response.status_code != 302:
                errors.append(
                    f"Login smoke test failed: /login returned {login_response.status_code}"
                )

        for path in ("/", "/configuration", "/wireless", "/switch-analyzer", "/lifecycle/", "/api/health"):
            response = client.get(path)
            if response.status_code != 200:
                errors.append(f"HTTP smoke test failed: {path} returned {response.status_code}")
    except Exception as exc:
        errors.append(f"Application import/HTTP smoke test failed: {type(exc).__name__}: {exc}")
        return errors

    try:
        from tempfile import TemporaryDirectory
        from features.configuration_studio.service import convert_file

        with TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "sample.cfg"
            source.write_text(
                "hostname NES-TEST\n!\nversion 16.12\n!\nvlan 10\n name USERS\n!\n"
                "interface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 10\n!\n",
                encoding="utf-8",
            )
            result = convert_file(source)
            if "sysname NES-TEST" not in result.get("output_text", ""):
                errors.append("Configuration Studio engine smoke test failed")
    except Exception as exc:
        errors.append(f"Configuration Studio smoke test failed: {type(exc).__name__}: {exc}")

    try:
        from features.wireless_center.service import analyze
        from features.wireless_center.inventory_master import template_csv, read_inventory, compare_inventory
        from tempfile import TemporaryDirectory

        result = analyze(
            "sysname NES-WLC\ninterface Vlanif100\n ip address 10.0.0.1 255.255.255.0\n#\n"
        )
        if result.get("data", {}).get("wlc", {}).get("hostname") != "NES-WLC":
            errors.append("Wireless Center engine smoke test failed")

        with TemporaryDirectory() as temp_dir:
            master_path = Path(temp_dir) / "master.csv"
            master_path.write_bytes(template_csv("Huawei", 2, "AP", "HQ", "F01"))
            master = read_inventory(master_path, "Huawei")
            comparison = compare_inventory(
                master["records"],
                [{"ap_id": "1", "name": "HQ-F01-AP-001", "status": "Normal"}],
                "Huawei",
            )
            if master["summary"]["total_records"] != 2 or comparison["summary"]["matched"] != 1:
                errors.append("Wireless AP master/deployment validation smoke test failed")

        response = client.get("/wireless/template/Cisco?quantity=2&site=HQ&floor=F01&prefix=AP")
        if response.status_code != 200 or b"Site Tag" not in response.data:
            errors.append("Wireless vendor template endpoint smoke test failed")
    except Exception as exc:
        errors.append(f"Wireless Center smoke test failed: {type(exc).__name__}: {exc}")

    try:
        sample_config = (
            "hostname NES-BATCH\n!\nversion 16.12\n!\n"
            "vlan 10\n name USERS\n!\n"
            "interface GigabitEthernet1/0/1\n"
            " switchport mode access\n switchport access vlan 10\n!\n"
        ).encode("utf-8")
        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("site-a/from-zip.cfg", sample_config)
        archive_buffer.seek(0)

        response = client.post(
            "/configuration/api/batch",
            data={
                "source_vendor": "Auto Detect",
                "source_device_type": "Auto Detect",
                "target_vendor": "Huawei",
                "target_device_type": "",
                "config_files": [
                    (io.BytesIO(sample_config), "folder-a/direct.cfg"),
                    (archive_buffer, "configs.zip"),
                ],
            },
            content_type="multipart/form-data",
        )
        payload = response.get_json() or {}
        if response.status_code != 200 or payload.get("result", {}).get("converted_count") != 2:
            errors.append("Configuration Studio folder/ZIP batch smoke test failed")
        else:
            first_item = payload["result"]["converted"][0]
            preview_response = client.get(first_item["preview_url"])
            if preview_response.status_code != 200:
                errors.append("Configuration Studio batch preview smoke test failed")

            batch_id = payload["result"]["download_url"].rstrip("/").split("/")[-1]
            (BASE_DIR / "exports" / "configuration" / f"{batch_id}.zip").unlink(missing_ok=True)
            shutil.rmtree(
                BASE_DIR / "exports" / "configuration" / "batch_previews" / batch_id,
                ignore_errors=True,
            )
    except Exception as exc:
        errors.append(f"Configuration Studio revised batch smoke test failed: {type(exc).__name__}: {exc}")

    try:
        from features.lifecycle_manager import routes as lifecycle_routes

        original_device_data = (
            lifecycle_routes.DEVICES_FILE.read_text(encoding="utf-8")
            if lifecycle_routes.DEVICES_FILE.exists()
            else json.dumps({"devices": []})
        )
        offline_scan = [{
            "ip": "192.0.2.10",
            "hostname": "Unknown",
            "vendor": "Unknown",
            "platform": "Unknown",
            "model": "Unknown",
            "version": "Unknown",
            "serial": "Unknown",
            "status": "offline",
        }]
        try:
            with patch.object(lifecycle_routes, "scan_range", return_value=offline_scan):
                response = client.post(
                    "/lifecycle/api/discovery",
                    json={
                        "demo_mode": False,
                        "start_ip": "192.0.2.10",
                        "end_ip": "192.0.2.10",
                        "username": "test",
                        "password": "test",
                    },
                )
            payload = response.get_json() or {}
            if (
                response.status_code != 200
                or payload.get("devices") != []
                or payload.get("no_devices") is not True
            ):
                errors.append("Lifecycle empty real-discovery handling smoke test failed")
        finally:
            lifecycle_routes.DEVICES_FILE.write_text(original_device_data, encoding="utf-8")
    except Exception as exc:
        errors.append(f"Lifecycle revised discovery smoke test failed: {type(exc).__name__}: {exc}")

    return errors


def main() -> int:
    rerun = rerun_in_venv()
    if rerun is not None:
        return rerun

    print("Network Engineer Suite Web installation verification")
    print("=" * 58)
    errors: list[str] = []

    for relative in REQUIRED:
        path = BASE_DIR / relative
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"Missing or empty: {relative}")

    missing = [module for module in DEPENDENCIES if importlib.util.find_spec(module) is None]
    if missing:
        errors.append("Dependencies not installed: " + ", ".join(missing))

    if not compileall.compile_dir(BASE_DIR, quiet=1, rx=re.compile(r"[\\/]\.venv[\\/]")):
        errors.append("Python syntax compilation failed")

    if not missing:
        errors.extend(run_smoke_tests())

    if errors:
        print("VERIFICATION RESULT: FAIL")
        for error in errors:
            print(f"- {error}")
        return 1

    print("SOURCE & INTEGRITY: OK")
    print("DEPENDENCIES: OK")
    print("PYTHON SYNTAX: OK")
    print("APPLICATION SMOKE TESTS: OK")
    print("VERIFICATION RESULT: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
