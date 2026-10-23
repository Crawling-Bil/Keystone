# LLD Index

Builds the "LLD Content Index" workbook that the Document Generator (lld-generator) imports with **Import Excel Index**. Keystone writes the chapter structure and fills every table it can; the Document Generator turns it into the Word LLD with the master template's cover, styles and Document Acceptance.

Page: `/lld-index`. Code: `features/lld_index/`. Templates: `features/lld_index/templates/*.json`.

## Inputs

1. **Project**: customer, project name, code, company, goals, scope, out of scope, related documents. The Introduction chapter is written from these (`narrative.py`), in the wording of the existing Multipolar LLDs.
2. **Technologies**: switch, wireless, firewall, router, load balancer. Pick one or more.
3. **Device inventory**: Site, Hostname, Model, Role, Mgmt IP, SN, Config, Rack, Rack Size, U, U Height, Status. Import a CSV/XLSX (template on the page) or type/paste rows. Config names an uploaded file; blank means "match by hostname", or no config at all for a design written before implementation.
4. **Config files** (optional): running configs or terminal captures, or one ZIP.

A device's technology comes from its config (the same domain detection Convert uses), then keywords in Role (switch/core/access, WLC/AP, firewall/FW, router/WAN, LB/F5), then the model name.

## Rack layout

Rack (name), Rack Size (24/27/32/36/42/45/47/48U, blank = 42), U (lowest unit the device sits in) and U Height (blank = 1) draw one table per rack under **Rack Layout**, per site: `U | <rack> (<size>U) | U`, top unit first, a device taller than 1U as one merged cell. Device cells are light blue, the U columns light grey, text centred. A device that overlaps another one or does not fit the rack is left out of the table and noted on the page; a site where no device has a rack position keeps an image slot instead. The page shows each rack as a drawing before download.

### Replacement project

Tick **Replacement project** and set **Status** per device: `New` (installed by the project, the default when blank), `Existing` (old device that is removed) or `Keep` (stays in place: patch panel, server, a switch that is not replaced). Every rack then gets two tables under its site: **Rack Layout Before - <rack>** (Existing + Keep) and **Rack Layout After - <rack>** (New + Keep). Existing and New devices may share units; overlaps are only checked within the same phase.

Existing devices appear nowhere else in the index (no VLAN, connectivity or configuration chapters, not in the Device Inventory or BoQ). Keep devices without a selected technology (a patch panel) only appear in the racks. The BoQ counts New devices only. The firewall Existing Device List lists the Existing devices with "Replaced by <New device of the same site and technology>" or "Removed"; Scope of Work, Project Description and Implementation Step (Dismantle row) mention them. Without the option the rack shows the finished state (New + Keep).

## How the index is built

`builder.build()` expands `common.json` and, where it says `{"insert": "technology"}`, the chapters of every selected technology.

Template node keys:

| Key | Meaning |
| --- | --- |
| `title` | Heading text; `{site}`, `{hostname}`, `{model}`, `{vendor}`, `{customer}`, `{project}` are filled in |
| `type` | `group` (default with children), `paragraph`, `table`, `image` |
| `repeat` | `site`, `device`, `model` or `rack`: one copy per item in scope |
| `flatten` | with `repeat`: no heading for the item, its children repeat in place (Before/After per site) |
| `inline_single` | with `repeat: device`: one device in scope means no hostname level |
| `devices` | narrow the scope: `tech`, `role` (regex), `exclude_role` (regex), `rack` (true = devices with a rack position; false = only when none has one) |
| `replacement` | `true`: only in a replacement project; `false`: only outside one |
| `phase` | `before` (Existing + Keep) or `after` (New + Keep) for a rack table; without it a node never sees Existing devices |
| `status` | list of statuses the node works with, e.g. `["Existing"]` for the Existing Device List |
| `replacement_rows` | static table: rows added in a replacement project (`{existing}` = the Existing hostnames) |
| `optional` | drop when there is no data; without it an empty table becomes one `TBD` row |
| `table.builder` | `device` (config tables), `inventory`, `rack`, `boq`, `allocation`, `models_spec`, `mgmt_ip`, `software`, `config`, `uat`, `static` |
| `table.tables` | candidate dataset tables, first one with rows wins (PAN-OS `security_rules`, FortiGate `policies`) |
| `table.columns` | `[label, "key1|key2"]`: first key with a value wins |
| `blocks` | more content under the same heading, each with its own `type`, `text`/`narrative`/`table`, `caption`, `optional` (model heading: description paragraph + spec table) |

`datasets.py` runs the existing analyzers (switch, firewall, router, load balancer, wireless) and flattens their results into named tables. An analyzer error never stops the index; the device gets a note.

Rules that come from the existing LLDs:

* Switch: VLAN, physical connectivity and configuration per site, then per hostname; topology Before/After side by side per site.
* Wireless: per site, then per device; access points are listed (AP List, Layout Overview) but get no chapter each.
* Firewall: one chapter per site with the configuration tables the firewall has; sections with no data are left out (a site with DHCP gets DHCP, one without does not).
* A device belongs to its own technology's chapters. Wireless also takes switches, but only when Switch is not selected, so nothing is written twice. When two technologies produce the same chapter title, the title gets the technology name (`Site DC - Firewall`).

## Output format

The workbook follows `lld_generator/backend/importer.py`:

* sheet `Index`, header `No | Judul Heading | Level | Tipe Konten | Isi / Nama Sheet Rujukan | Catatan`, Level `H1`..`H9`;
* `Paragraf`: text in Isi, or a sheet (`No | Isi`, one paragraph per row) for more than one paragraph;
* `Tabel`: a sheet with a header row and at least one data row (the importer drops a table without rows, so empty tables carry `TBD`); Catatan is the caption;
* `Gambar`: an empty image block for manual upload;
* a row with an empty Judul Heading adds one more block to the heading above it. The Document Generator reads these with the multi-block importer (`feat/multi-block-import`); an older importer skips them and keeps the first block;
* sheet names unique, at most 31 characters.

Yellow rows in the Index sheet still need manual content. Document Acceptance is not in the index: the Document Generator keeps it from the master template.

## Known limits

* Router and Load Balancer templates are drafts until an LLD sample exists for them.
* Narrative is English, the language of the switch, wireless and Palo Alto LLD samples.
* Topology and map layout are image placeholders.
