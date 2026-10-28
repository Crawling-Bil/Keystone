# Contributing to Keystone

Thank you for helping. Keystone is a local web tool for network engineers (Cisco, Huawei, Aruba, FortiGate, Palo Alto, F5, MikroTik). Bug reports, captures that Keystone reads wrongly (made safe, see below), documentation fixes and code are all welcome.

Nobody has decided on a license yet (see the README), so please ask the repository owner before you reuse or redistribute the code outside this repository.

## Before you send anything: keep real data out

Keystone reads device captures. Those hold hostnames, addresses, serial numbers, descriptions, sometimes credentials.

- **Never put a real capture, a real hostname, a customer or site name, an IP address that is not documentation space, a MAC address, a serial number, a password, a key or a token in an issue, a pull request, a test, a fixture or a document.** Git history is public and permanent.
- For an issue about the Topology Builder, tick *Also make an anonymized copy* and attach `keystone-topology-pack-anonymized.zip`. Keep `anonymization-map.csv` on your computer. The anonymized copy hides names and numbers, not the shape of the network (how many devices, which vendors and models, VLAN ids), so look at it before you attach it. How it works and what it does not hide: [docs/modules/topology.md](docs/modules/topology.md), section "Version 1.6".
- For the other tools, cut the capture down to the few lines that show the problem and replace names and addresses yourself. Use documentation addresses: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` ([RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)) or `2001:db8::/32` ([RFC 3849](https://www.rfc-editor.org/rfc/rfc3849)), and private ranges in lab-looking names (`Lab-DC`, `Branch-01`).
- Tests use **synthetic** files only. The `data/`, `uploads/`, `exports/` and `logs/` folders are ignored by git on purpose; do not force-add anything from them.

## Report a problem

Use the issue forms (New issue). The most useful report has:

1. The tool and its version (the Dashboard shows the version on each tool's card; `core/modules.py` lists them too).
2. What you gave it (vendor, platform, OS version, the command that produced the file), made safe as above.
3. What you expected and what you got.
4. For the Topology Builder, `run-settings.txt` from the pack: it holds every option you set.

## Set up and run the tests

Python 3.11 or newer; the automatic checks use 3.12 ([.github/workflows/tests.yml](.github/workflows/tests.yml)).

```bash
git clone https://github.com/Crawling-Bil/Keystone.git
cd Keystone
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest        # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest -q
```

To run one tool while you work: `.venv/bin/python run.py`, then open `http://127.0.0.1:8002`. The README explains start, stop and the settings.

## How the code is laid out

| Where | What |
| --- | --- |
| `core/modules.py` | The list of tools and their versions. A change a user can see raises the version of that tool. |
| `features/<tool>/` | One folder per tool: its blueprint (`routes.py`), the parsing and logic, and nothing that belongs to another tool. |
| `templates/`, `static/` | Pages, scripts and styles. Plain JavaScript and CSS, no build step. |
| `tests/` | One file per area (`test_topology_v16.py`, ...). Fixtures that need sample captures live next to the tests and are invented. |
| `docs/modules/` | One document per tool: what it does, how it works, its limits, references. |
| `CHANGELOG.md` | Newest first, in plain words: what a person sees, what was fixed, what is not changed. |

`core/local_guard.py` keeps Keystone answering only on the local computer; do not weaken it, and do not add a route that writes to a device without a clear warning on the page (see the README, "Tools that change devices").

## Making a change

1. Open an issue first for anything bigger than a fix, so the direction is agreed before you spend the time.
2. Branch from `main`. One topic per branch.
3. Write the test first or with the change. A bug fix comes with a test that fails without it. Use synthetic data.
4. Run the whole suite (`python -m pytest -q`) and fix what you broke. A test you must change because the behaviour changed on purpose is changed in the same pull request, with the reason in the description.
5. Update the document of the tool in `docs/modules/` and add a `CHANGELOG.md` entry when a person can see the change.
6. Open a pull request and fill in the template.

### Conventions that the project keeps

- **Say what is certain and what is guessed.** A fact from the capture is shown as a fact; an inference (a link inferred from ARP, a model guessed from a prefix) is labelled as one. Do not invent a value the device did not state.
- **Documentation links must be real.** When code, a finding or a document points to vendor documentation or an RFC, open the link and check it says what you claim. Prefer the vendor's own documentation (Cisco, Huawei, HPE Aruba, Fortinet, Palo Alto Networks, F5) and the RFC or IEEE text.
- **Deterministic output.** The same captures give the same pictures, tables and ids. No timestamps or random values in an output unless the person asked for them.
- **No hidden network access.** Keystone does not send captures anywhere. A feature that must reach the network (a device job, a download) says so on its page.
- **Plain language in the interface.** Write for an engineer in a hurry: what happened, what to do next.
- Keep files in the line endings of the repository (`.gitattributes`: text is stored as LF; `*.sh` stays LF and `*.bat` stays CRLF).

## Pull request review

A reviewer looks at: does the change do what the description says; is there a test that would catch a regression; does it leak or invent data; does it keep the output the same for captures it should not affect (run one of your own captures before and after and compare); are the documents and the changelog updated. Small, focused pull requests are reviewed quickly.

## Security problems

Do not open a public issue for a vulnerability (a way to reach Keystone from another machine, to read a file outside its folders, to run a command). Tell the repository owner privately instead, with the steps to reproduce.
