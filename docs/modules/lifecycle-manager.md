# Lifecycle Manager and ZTP

Operating notes for the write-to-device tools. Risk classes and required safeguards are defined in [docs/PRD.md](../PRD.md).

## Lifecycle Manager: Discovery, Firmware Upgrade & Jobs

- Subnet SSH discovery (`Start IP`-`End IP` range) logs into every reachable address once, identifies vendor/platform/model/version/serial from read-only inventory commands, and lists only devices that authenticated successfully. Failed/unreachable IPs are reported separately instead of filling the device table.
- One TCP+SSH connection per scanned IP, with no separate port pre-probe. Two rapid connections from the same source is exactly the pattern that trips Huawei VRP's SSH attack-defense IP blacklist, so discovery avoids it.
- A single job system (`pending -> [prechecking ->] ready -> running -> completed/failed`) is shared across every job type below. Upgrade, Config Push, and Config Backup all read/write the same job store and reuse the same live Execution Log / SSE stream.
- Firmware Upgrade: SFTP/TFTP/FTP firmware transfer, pre/post config backup, install, save, reload, and reconnect-wait, with Pre-Check validating SSH reachability, live device info, and firmware/storage compatibility before a job can start. Live-tested end-to-end against real Huawei VRP hardware (S5735-class), including parallel upgrade of multiple devices in one job.
- Demo Mode simulates every stage of any job type without touching real hardware, for safe rehearsal. A real (non-demo) run currently supports Huawei VRP end-to-end; other vendors' drivers implement discovery/device-info only.

## Lifecycle Manager: Config Push

- Pushes an operator-prepared draft config to an already-discovered device line-by-line over SSH. No firmware involved, device stays online throughout.
- Fully self-contained page (`/lifecycle/config-push`): select devices, assign a draft config each (pasted, or picked from a saved draft / Configuration Studio's converter output), create the job, then run Pre-Check and start Config Push. No detour through any other page required.
- Live per-line push results stream in as they happen. A full before/after config backup is captured automatically around the push for audit.

## Lifecycle Manager: Config Backup

- Captures a fixed, read-only ~40-command snapshot from an already-configured device over SSH: full running-config, hardware/elabel, VLAN/interface/port, LLDP/LACP/eth-trunk, STP, PoE, stack, dual-active, routing, licensing, ACLs, and the MAC address table.
- Read-only end to end, so there is no Pre-Check stage. A job goes straight from creation to Start.
- One command failing (unsupported on a given platform/firmware) never aborts the batch. Every command is independent, unlike Config Push's line-by-line push, which stops on the first rejection.
- Result is saved as one downloadable, timestamped backup bundle per device. Each capture is kept as its own snapshot rather than overwriting the previous one, so a device accumulates a history over time.

## Live Logs & Device Reachability

- Live Logs (`/lifecycle/live-logs`) is a suite-wide, top-level page that merges Lifecycle Manager's Upgrade, Config Push, and Config Backup jobs with ZTP's activity feed into one real-time console, regardless of which module created the job.
- Device Reachability check (topbar action on Config Backup) is a fast, credential-free TCP/SSH-port probe an operator can run on demand against already-discovered devices. Discovery's own "online" status is a snapshot from whenever that IP range was last scanned, with no timestamp recorded, so this adds an explicit, timestamped "reachable right now" signal instead.

## Lifecycle Manager: ZTP Provisioning

Lifecycle Manager's "ZTP Provisioning" tab replaces the manual console-and-preconfig step for onboarding a factory-default Huawei VRP switch (CloudEngine S5735/S5755-class, see the vendor's ZTP hardware support table) with DHCP-based Zero Touch Provisioning, following the vendor's "without a controller" flow: DHCP Option 67 points the switch at an SFTP-hosted intermediate file, matched to the device by ESN.

Features:
- Pre-register a device by ESN, hostname, management IP/mask/gateway, MAC, and credentials before it's ever powered on.
- Generates the ZTP intermediate file (`.ini`) and a per-device minimal bootstrap config (identity + SSH reachability only, not full production config) from the pre-registered device list.
- Built-in read-only SFTP server to host the generated files (VRP's ZTP flow requires SFTP; FTP/TFTP are not supported).
- Built-in DHCP server (wraps `dnsmasq`) for staging segments with no existing DHCP service, scoped to one explicitly named interface. It refuses to bind a wildcard/all-interfaces address and requires an explicit "isolated segment" confirmation before starting, so it can't become a rogue DHCP server on a shared network.
- A device is marked "provisioned" automatically the next time it's found by a real `/api/discovery` scan (matched by ESN), so completed devices stop reappearing in future deployment-file generation and DHCP reservations. It can also be marked manually from the device table.

**Optional system dependency:** the built-in DHCP server requires `dnsmasq` on the host (`apt install dnsmasq` / `brew install dnsmasq`). It is not a Python package and is not installed by `setup_mac_linux.sh`/`setup_windows.bat`. It's only needed if you use Keystone's own DHCP server; skip it entirely if your staging segment already has DHCP with an Option 67 reservation pointing at the SFTP server started from this tab.

Not yet validated against real hardware: `rsa local-key-pair create` behavior when applied from a batch-loaded startup-config (rather than typed interactively at a console), and whether the target VRP client reads DHCP Option 67 from the packet's legacy BOOTP `file` field (where every mainstream DHCP server, `dnsmasq` included, places it) versus requiring a separate Option-67 TLV. Test against one spare unit before relying on this for a real rollout, and check the DHCP server's own log if a device gets a lease but never completes ZTP.
