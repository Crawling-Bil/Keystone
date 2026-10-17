# Keystone

A local tool for day-to-day network engineering work: read device captures, build assessment reports, convert configs between vendors, and upgrade switch firmware. It runs on your own laptop, so customer configs stay there.

Current version: 1.11.0.

## What's inside

Analyzers (read uploaded files only):

- Wireless Analyzer: Huawei and Cisco 9800 WLCs
- Switch Analyzer: Cisco, Huawei, Aruba, Nexus
- Router Analyzer: Cisco IOS / IOS-XE / SD-WAN
- Firewall Analyzer: FortiGate, FortiSwitch, Palo Alto (configuration or runtime-only log), MikroTik RouterOS 6/7
- Load Balancer Analyzer: F5 BIG-IP

Converter:

- Convert: one page per device type (wireless, switch, router, firewall, load balancer). Switch and Firewall convert today; the others show what they need first. See `docs/modules/configuration-studio.md`

Device operations:

- Lifecycle Manager: discovery and firmware upgrades
- Config Push: push config over SSH
- ZTP Provisioning: bring up new Huawei switches without a console
- Config Backup: pull a config backup (read-only)
- Live Logs: watch jobs as they run

Lifecycle Manager, Config Push and ZTP change real devices. Real runs only support Huawei VRP for now; other vendors run in demo mode. Pre-check and backup run automatically before every job.

## Install

Windows: run `setup_windows.bat` once, then `start_windows.bat`.

Mac / Linux:

```bash
./setup_mac_linux.sh
./start_mac_linux.sh
```

Open http://127.0.0.1:8002. The login password is printed in the terminal on first start and saved to `data/.auth_password`.

## Notes

- By default it only listens on localhost. Set `NES_ALLOW_REMOTE` if you need to reach it from another device.
- Use your own password with `NES_AUTH_PASSWORD`. For development you can turn login off with `NES_DISABLE_AUTH=1`.
- ZTP needs `dnsmasq` if you want to use the built-in DHCP server (`apt install dnsmasq` / `brew install dnsmasq`).

More detail:

- [docs/PRD.md](docs/PRD.md): scope, supported vendors, roadmap
- [CHANGELOG.md](CHANGELOG.md)
- [docs/modules/lifecycle-manager.md](docs/modules/lifecycle-manager.md): upgrade, push, backup and ZTP details

## Development

```bash
pip install -r requirements.txt pytest
python -m pytest -q
```

The tool list lives in `core/modules.py`. To add a module, register its blueprint in `app.py` and add an entry there.
