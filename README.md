# Keystone

Keystone is a local web tool for network engineers. It reads device captures and builds assessment reports, converts configurations between vendors, and runs firmware and configuration jobs on switches. It runs on your own laptop, so customer configurations never leave your machine.

Current version: 1.11.0. Indonesian guide: [docs/PANDUAN.md](docs/PANDUAN.md).

## What it does

| Group | Tool | What you give it | What you get |
| --- | --- | --- | --- |
| Analyze | Wireless Analyzer | Huawei or Cisco 9800 WLC configuration, optional AP inventory | Assessment, AP master validation, AP role diff, source-to-target delta |
| Analyze | Switch Analyzer | Cisco (Catalyst, Nexus), Huawei, Aruba (ArubaOS-Switch, AOS-CX) configuration and `show` output | Inventory, VLANs, spanning tree, port-channels, vPC/M-LAG, PoE, transceivers, findings, Excel export |
| Analyze | Router Analyzer | Cisco IOS, IOS-XE or SD-WAN capture | Interfaces, routing, BGP/OSPF, VPN, hardening findings |
| Analyze | Firewall Analyzer | FortiGate, FortiSwitch, Palo Alto (configuration or runtime log), MikroTik RouterOS 6/7 | Policies, NAT, VPN, routing, objects, hardening findings |
| Analyze | Load Balancer Analyzer | F5 BIG-IP `.ucs`, `bigip.conf` or `tmsh` output | Virtual server to pool map, monitors, SSL, HA, DNS (GTM), findings |
| Convert | Convert Switch | Cisco, Huawei or Aruba switch configuration | Configuration for another vendor, interface map, pre-flight summary |
| Convert | Convert Firewall | MikroTik configuration | Palo Alto (Panorama-ready) configuration |
| Convert | Wireless, Router, Load Balancer | none yet | These pages say what is needed first and link to the matching analyzer |
| Operate | Lifecycle Manager, Config Push, ZTP Provisioning | Device credentials, firmware, draft configuration | Firmware upgrade, configuration push, zero-touch provisioning (these change real devices) |
| Operate | Config Backup, Live Logs | Device credentials | Read-only backup bundle, live job log |

## Requirements

- Windows, macOS or Linux.
- Python 3.11 or newer. On Windows install it from [python.org](https://www.python.org/downloads/) and keep the "py launcher" option selected, because the setup script starts Python with `py -3`.
- Internet access during setup, once, to download the packages in `requirements-lock.txt`.
- A current browser. Keystone listens on your own machine at `http://127.0.0.1:8002`.
- Optional: `dnsmasq`, only if you use the built-in DHCP server of ZTP Provisioning (`apt install dnsmasq` or `brew install dnsmasq`).

## Install

1. Download the repository (green Code button, then Download ZIP) and unzip it, or clone it:

   ```bash
   git clone https://github.com/Crawling-Bil/Keystone.git
   cd Keystone
   ```

2. Run setup once. It creates a private `.venv` folder, installs the pinned packages and runs `verify_install.py`.

   Windows: double-click `setup_windows.bat`. Wait until the window stops and asks you to press a key; scroll up if you want to read the check result.

   macOS or Linux:

   ```bash
   ./setup_mac_linux.sh
   ```

   If `python3` is older than 3.11, point the script at a newer one: `PYTHON_BIN=python3.12 ./setup_mac_linux.sh`.

3. Start Keystone.

   Windows: double-click `start_windows.bat`.

   macOS or Linux:

   ```bash
   ./start_mac_linux.sh
   ```

   The browser opens at `http://127.0.0.1:8002`. If it does not, open that address yourself (on Windows `open_nes.bat` does it).

4. Log in. The first start generates a password, prints it in the terminal window under the heading "Keystone login password", and saves it to `data/.auth_password`. Use your own password instead by setting `NES_AUTH_PASSWORD` before you start.

5. Stop Keystone with Ctrl+C in its terminal window, or run `stop_windows.bat` / `./stop_mac_linux.sh`.

If your security software blocks the scripts, run the same steps by hand from the Keystone folder. On Windows:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.venv\Scripts\python.exe verify_install.py
.venv\Scripts\python.exe run.py
```

On macOS or Linux replace `.venv\Scripts\python.exe` with `.venv/bin/python` and `py -3` with `python3`.

## Your first analysis (five minutes)

1. Open **Switch Analyzer** in the left menu and choose the **Collect Backup** tab.
2. Download the command list for your platform (Cisco Catalyst, Cisco Nexus, Aruba Switch, Aruba CX, Huawei S/L/E-series or Huawei H-series), or press **Copy commands** and paste it into your SSH or console session.
3. Save the whole terminal output as one `.txt` file.
4. Go to **Single Device**, drop the file in, leave Vendor on Auto Detect and press **Analyze Switch**.
5. Read **Overview**, **Findings** and **Health**, then **Export to Excel (.xlsx)** for the report.

The other analyzers work the same way. Each has a Collect Backup tab or list for its platforms: Cisco IOS-XE and SD-WAN routers, FortiGate, MikroTik, Palo Alto, F5 BIG-IP (LTM and DNS).

A file that belongs to another tool (for example a router capture on the Switch page) is not forced through the wrong parser. The page tells you which analyzer to use.

## Convert a switch configuration

1. Open **Convert**, then **Switch**.
2. Choose the configuration file or paste it. Source Vendor can stay on Auto Detect.
3. Pick the Target Vendor. Pick a Target Model if you know it: Keystone then checks every used port against the real model and tells you if the target has too few ports.
4. For a Huawei stack, set **Stack member** and **Units in the stack**. Convert each old switch as its own file.
5. Optionally pick a Standard Config Profile, then press **Convert Configuration**.
6. Read the three views of the result:
   - **Configuration**: source and converted text side by side. Download it with **Download CFG**.
   - **Interface map**: every source port, the port it becomes, and why. A banner says whether the target model fits.
   - **Pre-flight**: what converted cleanly, what needs a decision, what was not converted, and structural checks such as duplicate ACL rules and empty port-channels.
7. Search the output for `REVIEW-`. Every such line is a decision or a missing equivalent that a person must settle before the configuration goes on a device.

Several files or a ZIP can be converted in one go with **batch conversion**. Details and the rules behind the converter are in [docs/modules/configuration-studio.md](docs/modules/configuration-studio.md).

## Tools that change devices

Lifecycle Manager, Config Push and ZTP Provisioning write to real devices. Real runs support Huawei VRP only; other vendors run in demo mode. Firmware upgrade and Config Push run a pre-check and take a configuration backup around the job. Use Demo Mode to rehearse first. Config Backup and Live Logs are read-only. Read [docs/modules/lifecycle-manager.md](docs/modules/lifecycle-manager.md) before the first real job.

## Settings

Set these as environment variables before you start Keystone.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NES_PORT` | `8002` | Port to listen on |
| `NES_HOST` | `127.0.0.1` | Address to listen on. Anything other than localhost also needs `NES_ALLOW_REMOTE=1` |
| `NES_ALLOW_REMOTE` | unset | Set to `1` to allow another machine to connect. Only on a trusted, isolated network: the login is a single shared password |
| `NES_AUTH_PASSWORD` | generated | Your own login password |
| `NES_DISABLE_AUTH` | unset | Set to `1` to turn the login off, for local development only |
| `NES_OPEN_BROWSER` | `1` | Set to `0` to stop the browser opening at start |
| `NES_SECRET_KEY` | generated | Session signing key |

On Windows, open Command Prompt in the Keystone folder, run for example `set NES_PORT=8010`, then `start_windows.bat`. Variables set that way last only for that window.

## Troubleshooting

| What you see | What to do |
| --- | --- |
| `py` is not recognized (Windows) | Install Python 3.11 or newer from python.org with the py launcher, then run `setup_windows.bat` again |
| "Python 3 was not found" (macOS/Linux) | Install Python 3.11 or newer, or run `PYTHON_BIN=python3.12 ./setup_mac_linux.sh` |
| Setup stops while installing packages | Check internet access and any proxy (pip reads `HTTPS_PROXY`), then run setup again |
| `start_windows.bat` says to run setup first | The `.venv` folder is missing. Run `setup_windows.bat` |
| Port 8002 is already in use | Run `stop_windows.bat` / `./stop_mac_linux.sh`, or start on another port with `NES_PORT=8010` |
| Forgot the password | Open `data/.auth_password`. Or set `NES_AUTH_PASSWORD` and restart |
| "Too many attempts" at login | Five wrong passwords lock the login for 60 seconds. Wait, then try again |
| Browser does not open | Go to `http://127.0.0.1:8002` yourself |
| Refusing to bind to an address | You set `NES_HOST` to a non-local address. Set `NES_ALLOW_REMOTE=1` only if you accept the risk |
| An analyzer says the file is not recognised | Use the matching analyzer, or collect the output again with the command list from the Collect Backup tab |
| Results look incomplete | Collect with the full command list for the platform. The Coverage tab of the Switch Analyzer shows which commands were found |
| ZTP built-in DHCP does not start | Install `dnsmasq` and run Keystone with administrator or root rights; DHCP uses a privileged port |
| Setup finished but something fails later | Run `.venv/bin/python verify_install.py` (Windows: `.venv\Scripts\python.exe verify_install.py`) and read what it reports |

## Your data

- Uploaded files, exports, logs and generated settings stay in `data/`, `uploads/`, `exports/` and `logs/` inside the Keystone folder. They are ignored by git on purpose.
- Never commit real customer captures or credentials. The tests use synthetic files only.
- Keystone does not send configurations to any external service.

## More documentation

- [docs/PRD.md](docs/PRD.md): scope, supported vendors, roadmap (Indonesian)
- [docs/PANDUAN.md](docs/PANDUAN.md): user guide in Bahasa Indonesia
- [docs/modules/configuration-studio.md](docs/modules/configuration-studio.md): how Convert works, Nexus, stacks, hardware catalog
- [docs/modules/lifecycle-manager.md](docs/modules/lifecycle-manager.md): upgrade, push, backup and ZTP
- [CHANGELOG.md](CHANGELOG.md)

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest -q
```

The tool list lives in `core/modules.py`. To add a module, register its blueprint in `app.py` and add an entry there. Adding a converter is described in `docs/modules/configuration-studio.md`.

## License

No license file has been published yet. Ask the repository owner before you reuse or redistribute the code.
