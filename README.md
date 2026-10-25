# Keystone

Keystone is a local web tool for network engineers. It reads device captures and builds assessment reports, converts configurations between vendors, writes the LLD (Low Level Design) Word document of a project, and runs firmware and configuration jobs on switches. It runs on your own computer, so customer configurations never leave your machine.

Current version: 1.11.0. Indonesian guide: [docs/PANDUAN.md](docs/PANDUAN.md).

## Quick start

There is no account and no login. You download it, start it, and the browser opens.

**Windows**

1. Install Python 3.12 or 3.13 from [python.org](https://www.python.org/downloads/windows/) (once).
2. On this page press the green **Code** button, then **Download ZIP** ([GitHub's steps](https://docs.github.com/en/repositories/working-with-files/using-files/downloading-source-code-archives)). Right-click the ZIP, choose **Extract All**, and open the extracted `Keystone` folder.
3. Double-click **`start_windows.bat`**.

**macOS or Linux**

1. Install Python 3.11 or newer if you do not have it (macOS: `brew install python@3.12`, Debian or Ubuntu: `sudo apt install python3 python3-venv python3-pip`).
2. Download and unzip the repository, or run `git clone https://github.com/Crawling-Bil/Keystone.git`.
3. In a terminal, in the Keystone folder, run `bash start_mac_linux.sh`.

The first start installs everything it needs by itself. That takes 2 to 5 minutes and needs internet; keep the window open. After that, Keystone opens in your browser at `http://127.0.0.1:8002` and every later start takes a few seconds. Leave the black window open while you work, and close it (or press Ctrl+C) to stop Keystone.

Windows may show "Windows protected your PC" for a downloaded `.bat` file. Press **More info**, then **Run anyway**. The scripts are plain text; open them in Notepad if you want to read them first.

### Is it safe without a login?

Keystone only listens on your own computer (`127.0.0.1`), so another machine on the network cannot reach it, and it also refuses requests that another website tries to send to it from your browser. Anyone who is signed in to your computer can use it, the same as any other program on it. Do not expose it on a network (see `NES_ALLOW_REMOTE` in Settings) unless that network is trusted and isolated, because the Operate tools can push firmware and configuration to real devices.

## What it does

| Group | Tool | What you give it | What you get |
| --- | --- | --- | --- |
| Analyze | Wireless Analyzer | Huawei or Cisco 9800 WLC configuration, optional AP inventory | Assessment, AP master validation, AP role diff, source-to-target delta |
| Analyze | Switch Analyzer | Cisco (Catalyst, Nexus), Huawei, Aruba (ArubaOS-Switch, AOS-CX) configuration and `show` output | Inventory, VLANs, spanning tree, port-channels, vPC/M-LAG, PoE, transceivers, findings, Excel export |
| Analyze | Router Analyzer | Cisco IOS, IOS-XE or SD-WAN capture | Interfaces, routing, BGP/OSPF, VPN, hardening findings |
| Analyze | Firewall Analyzer | FortiGate, FortiSwitch, Palo Alto (configuration or runtime log), MikroTik RouterOS 6/7 | Policies, NAT, VPN, routing, objects, hardening findings |
| Analyze | Load Balancer Analyzer | F5 BIG-IP `.ucs`, `bigip.conf` or `tmsh` output | Virtual server to pool map, monitors, SSL, HA, DNS (GTM), findings |
| Analyze | Topology Builder | Captures (or a ZIP) with CDP / LLDP neighbors, optionally MAC / ARP tables | draw.io diagram with physical, vPC and logical IP views (keeps your layout between runs), neighbors from ARP / MAC / descriptions where CDP/LLDP is silent, grouping by site, optional topology name for the file names, link speeds, documentation pack (ZIP / HTML report), Excel, link, bundle and host tables, devices behind uncaptured devices, merge with a previous run, gaps in the discovery |
| Convert | Convert Switch | Cisco, Huawei or Aruba switch configuration | Configuration for another vendor, interface map, pre-flight summary |
| Convert | Convert Firewall | MikroTik configuration | Palo Alto (Panorama-ready) configuration, in one click or step by step (Guided Conversion: target model, interface and VLAN mapping, zones, checked at every step) |
| Convert | Wireless, Router, Load Balancer | none yet | These pages say what is needed first and link to the matching analyzer |
| Operate | Device Operations (Devices, Backup, Config Push, Upgrade, Live Logs), ZTP Provisioning | Device credentials, firmware, draft configuration | Firmware upgrade, configuration push, zero-touch provisioning (these change real devices) |
| Operate | Config Backup, Live Logs | Device credentials | Read-only backup bundle, live job log |
| Document | LLD Index | Project details and goals, device inventory (Excel template), optional configs | The LLD chapter structure per technology (switch, wireless, firewall; router and load balancer as drafts), per site and device, tables filled from the configs, rack layout (Before/After for a replacement project), narrative from the goals. Saved per project |
| Document | LLD Generator | An index from LLD Index (one click) or an Excel index | The Word LLD on the master template: cover, footer and Document Control filled from the project, customer logo, chapters, tables and pictures, Document Acceptance with your approvers, release history |

## Requirements

- Windows, macOS or Linux.
- Python 3.11 or newer. Python 3.12 is what the automatic tests use and 3.13 is also tried; take one of those if you have a choice. Download: [python.org](https://www.python.org/downloads/). How the Windows installer and the `py` command work: [Python on Windows](https://docs.python.org/3/using/windows.html).
- Internet access on the first start only, to download the packages listed in `requirements-lock.txt`.
- A current browser.
- Optional: `dnsmasq`, only if you use the built-in DHCP server of ZTP Provisioning (`apt install dnsmasq` or `brew install dnsmasq`).

## Start and stop

| | Windows | macOS or Linux |
| --- | --- | --- |
| Start | double-click `start_windows.bat` | `bash start_mac_linux.sh` |
| Stop | close the window, or double-click `stop_windows.bat` | Ctrl+C, or `bash stop_mac_linux.sh` |
| Open the page again | double-click `open_nes.bat`, or go to `http://127.0.0.1:8002` | go to `http://127.0.0.1:8002` |
| Install again or repair | double-click `setup_windows.bat` | `bash setup_mac_linux.sh` |
| Check the installation | `.venv\Scripts\python.exe verify_install.py` | `.venv/bin/python verify_install.py` |

If you start Keystone while it is already running, it just reopens the browser instead of failing.

If your security software blocks the scripts, do the same by hand from the Keystone folder. On Windows:

```bat
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
.venv\Scripts\python.exe run.py
```

On macOS or Linux replace `.venv\Scripts\python.exe` with `.venv/bin/python` and `py -3` with `python3`.

## Update to a newer version

With git: `git pull`, then run the setup file once (`setup_windows.bat` or `bash setup_mac_linux.sh`) in case the package list changed. With a ZIP: download the new ZIP, extract it to a new folder, and copy the old `data` folder into it if you want to keep your activity history. Then run the setup file once.

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

## Draw a network topology

1. Open **Analyze**, then **Topology Builder**. Select or drop one capture per device (or a ZIP). The more devices you add, the more links are confirmed from both ends.
2. Optional: type a **Topology name**. Every download is then named after it (`Panin-DC-topology.drawio`, `Panin-DC-links.csv`, ...); empty keeps the plain names. The draw.io file shows the name and `Topology Created at Date YYYY:MM:DD - Time HH:MM:SS` above the diagram.
3. Check the options (defaults in brackets):
   - **Exclude IP phones, PCs and servers** (on): draw network devices only. While it is on, the phone/host options are hidden.
   - **Collapse phones and hosts into one node per switch** (on) and **Collapse access points into one node per switch** (on: one box per switch; clear it to draw every access point with its own hostname, model and IP address for a detailed diagram).
   - **Show port names on the lines** (on), **Infer neighbors where CDP/LLDP is silent** (on; order of trust: ARP, then MAC address, then port description), **Add routed /30 and /31 links** (on), **Leave out-of-band management links out of the picture** (on), **Draw end hosts learned from MAC tables** (off).
   - **Grouping**: one diagram, or group by the first one, two or three hostname words (`JKT`, `JKT-A02`, `JKT-GD1-LT1`). The group with the most links to other groups is drawn in the middle, the others around it, each in a black frame.
   - **Diagram file contains**: physical and vPC view, physical only, vPC only, or the **Logical IP view** (devices that share a subnet, the interface and address at each end, and a table of every interface address per device).
   - **Style lines by**: rated speed (default) or link state.
4. Press **Build topology**, look at the preview (zoom, drag, open in a new tab) and read the findings. Download the **pack** (ZIP) for everything, or single files.
5. To continue later, pick the `topology.json` under **Add to a previous run** and the `topology.drawio` you moved things in under **Keep my layout**.

The pack contains `run-settings.txt`: the options you set, the creation time and the topology name. Send it together with a question or a bug report. Everything else, including finding IDs (TOPO-001 ...) and what each option does, is in [docs/modules/topology.md](docs/modules/topology.md).

## Write an LLD document

1. Open **Document**, then **LLD Index**. Fill in the customer, project name, code, your name and the project goals. Turn on **Replacement project** when old devices are replaced.
2. Pick the technologies (Switch, Wireless, Firewall, ...).
3. Add the devices: **Download template**, fill it in Excel (Site, Hostname, Model, Role, Status, Mgmt IP, SN, Config, Rack, Rack Size, U, U Height) and **Import CSV / XLSX**, or type the rows. Status is New, Existing (removed) or Keep.
4. Optional: drop the running configs (one per device, or a ZIP). VLAN, interface, routing and policy tables are filled from them; without configs those tables stay TBD.
5. Press **Build LLD index**. The build is saved: next time pick it under **Continue a project**, change what you need and build again without uploading the configs again.
6. Press **Open in LLD Generator**. The project opens with all chapters. Building again later updates the same project and keeps your pictures and edits.
7. In the LLD Generator: drop, paste or choose the topology and rack pictures (SVG from Topology Builder works; **Pictures** places several at once by file name), fill what **Review** lists as still to do, and set the customer logo, version and **Approvers** in **Settings**.
8. Press **Generate & Download**. Open the file in Word and let it update the fields (table of contents, captions).

The first time, open **LLD Generator** and press **Import from the old Document Generator** to bring over projects made with the separate Document Generator app. Details: [docs/modules/lld-index.md](docs/modules/lld-index.md) and [docs/modules/lld-generator.md](docs/modules/lld-generator.md).

## Tools that change devices

Device Operations and ZTP Provisioning write to real devices. Real runs support Huawei VRP only; other vendors run in demo mode. Firmware upgrade and Config Push run a pre-check and take a configuration backup around the job. Use Demo Mode to rehearse first. The Backup and Live Logs tabs are read-only. Read [docs/modules/lifecycle-manager.md](docs/modules/lifecycle-manager.md) before the first real job.

## Settings (optional)

You do not need any of these. Set them as environment variables before you start Keystone.

| Variable | Default | Meaning |
| --- | --- | --- |
| `NES_PORT` | `8002` | Port to listen on |
| `NES_HOST` | `127.0.0.1` | Address to listen on. Anything other than localhost also needs `NES_ALLOW_REMOTE=1` |
| `NES_ALLOW_REMOTE` | unset | Set to `1` to let another machine connect. There is no login, so only on a trusted, isolated network |
| `NES_ALLOWED_HOSTS` | unset | Extra host names Keystone should answer to, separated by commas |
| `NES_OPEN_BROWSER` | `1` | Set to `0` to stop the browser opening at start |
| `NES_SECRET_KEY` | generated | Signing key for cookies |

On Windows, open Command Prompt in the Keystone folder, run for example `set NES_PORT=8010`, then `start_windows.bat`. Variables set that way last only for that window. On macOS or Linux: `NES_PORT=8010 bash start_mac_linux.sh`.

## Troubleshooting

| What you see | What to do |
| --- | --- |
| "Python 3.11 or newer was not found" | Install Python from [python.org](https://www.python.org/downloads/), then double-click `setup_windows.bat` (macOS or Linux: `bash setup_mac_linux.sh`) again. To pick one Python: `PYTHON_BIN=python3.12 bash setup_mac_linux.sh` |
| "Windows protected your PC" | Press **More info**, then **Run anyway** |
| Setup stops while installing packages | Check internet access and any company proxy (pip reads `HTTPS_PROXY`), then run the setup file again |
| Antivirus deletes or blocks a script | Allow the Keystone folder, or use the manual commands in Start and stop |
| "Could not create the private Python folder" (Debian or Ubuntu) | `sudo apt install python3-venv python3-pip`, then run setup again |
| `bash: ... No such file` or strange `\r` errors on macOS/Linux | The script has Windows line endings. Run `sed -i 's/\r$//' *.sh` (macOS: `sed -i '' 's/\r$//' *.sh`) in the Keystone folder |
| "Port 8002 is already used by another program" | Another program owns the port. Start on a different port with `NES_PORT=8010` (see Settings) |
| "Keystone is already running" | It is. The browser reopens; use that tab |
| Browser does not open | Go to `http://127.0.0.1:8002` yourself |
| "Keystone only answers on this computer's own addresses" | You opened it with a different name or address. Use `http://127.0.0.1:8002` or `http://localhost:8002` |
| "Refusing to listen on ..." | `NES_HOST` is set to a non-local address. Remove it, or also set `NES_ALLOW_REMOTE=1` if you accept the risk |
| "Keystone refused a request that another website started" | A page other than Keystone tried to send a request. Close that tab and use the Keystone tab |
| An analyzer says the file is not recognised | Use the matching analyzer, or collect the output again with the command list from the Collect Backup tab |
| Results look incomplete | Collect with the full command list for the platform. The Coverage tab of the Switch Analyzer shows which commands were found |
| ZTP built-in DHCP does not start | Install `dnsmasq` and run Keystone with administrator or root rights; DHCP uses a privileged port |
| Setup finished but something fails later | Run the check in Start and stop and read what it reports |

## Your data

- Uploaded files, exports, logs and generated settings stay in `data/`, `uploads/`, `exports/` and `logs/` inside the Keystone folder. They are ignored by git on purpose.
- LLD work is kept in `data/nes.db` (saved LLD Index projects, LLD Generator projects, approvers) and `data/lld_generator/` (templates, pictures, generated Word files; generated files older than 7 days are removed). Back up the `data` folder to keep it.
- Never commit real customer captures or credentials. The tests use synthetic files only.
- Keystone does not send configurations to any external service.

## More documentation

- [docs/PRD.md](docs/PRD.md): scope, supported vendors, roadmap (Indonesian)
- [docs/PANDUAN.md](docs/PANDUAN.md): user guide in Bahasa Indonesia
- [docs/modules/configuration-studio.md](docs/modules/configuration-studio.md): how Convert works, Nexus, stacks, hardware catalog
- [docs/modules/lifecycle-manager.md](docs/modules/lifecycle-manager.md): upgrade, push, backup and ZTP
- [docs/modules/lld-index.md](docs/modules/lld-index.md): LLD index templates, inventory columns, rack layout, saved projects
- [docs/modules/lld-generator.md](docs/modules/lld-generator.md): LLD Generator, master template placeholders, approvers, import from the old Document Generator
- [CHANGELOG.md](CHANGELOG.md)

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest -q
```

The tool list lives in `core/modules.py`. To add a module, register its blueprint in `app.py` and add an entry there. Adding a converter is described in `docs/modules/configuration-studio.md`. The Word engine shared by the document tools is `core/docgen/` (docgen, importer, placeholders, and the master template in `core/docgen/master/`); change `docgen.py` only together with a test that compares the generated document. `core/local_guard.py` is the small guard that keeps other websites from calling Keystone; keep new routes behind the same app so they get it.

## License

No license file has been published yet. Ask the repository owner before you reuse or redistribute the code.
