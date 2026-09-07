# mappings/ — what's actually wired in

This folder holds reference/config data for the Cisco/Aruba → Huawei
converter. Not all of these files are read by the code — this note exists
so that editing one of the "not wired in" files doesn't quietly do
nothing, and so future changes here go with intent instead of assumption.

## Wired in (editing these changes converter output)

- **`migration_inventory.csv`** — loaded by `Inventory`
  (`converter_engine/inventory.py`), keyed on `OldHostname`. Drives
  `get_target_hostname`, `get_target_model`, `get_source_model`, and (as of
  this pass) PoE-capability lookups in the Huawei translator
  (`HuaweiSwitchTranslator.is_poe_capable`). This is the one mapping file
  every device in a migration batch needs a correct row in.

- **`unsupported.json`** (`ignore` key only) — loaded once at import time
  by `translators/switch/huawei.py` (`UNSUPPORTED_IGNORE`) and merged into
  both `filter_interface_review` and `filter_global_review`. Entries are
  matched by `str.startswith(...)`, so keep them as literal command
  prefixes, not regex.

  The `unsupported` key in this file is **not currently read anywhere** —
  it exists as a human-readable list of Cisco features with no Huawei
  VRP equivalent, but nothing in the code special-cases it today. Treat it
  as documentation for now, not as configuration.

  Two `ignore` entries (`"logging buffered"`, `"spanning-tree extend
  system-id"`) also don't currently have any effect: those command lines
  are routed by the Cisco parser into `config.logging_commands` and
  `config.spanning_tree_commands` respectively — dedicated lists handled
  by `translate_logging` / `translate_spanning_tree` — never through
  `filter_global_review`/`filter_interface_review`, which is what
  `UNSUPPORTED_IGNORE` actually reaches. They're left in the list as
  intent (harmless either way), but if you need them actually suppressed,
  the ignore check has to be added inside those two translate_* methods
  instead.

## Not wired in (safe to edit for planning, has zero effect on output today)

- **`site_mapping.csv`** — no loader in `converter_engine/` or
  `service.py` reads this file. `migration_inventory.csv` already carries
  `Site`/`Region` per device, so this file is redundant with it rather
  than a fallback for it. Kept consistent with `migration_inventory.csv`'s
  `Region` values as of this pass (was previously drifted: several rows
  said `"Mining Site"` where the inventory file says `"Mining"`).
  `CCY`'s `Region` is `"Site"` in both files — that looks like a likely
  data-entry shorthand in the original inventory rather than a real
  region name, but since both files agree, it wasn't changed here;
  worth confirming with whoever owns the inventory data before a Phase 2
  batch reuses this pattern.

- **`hostname_mapping.csv`**, **`device_mapping.csv`**,
  **`interface_mapping.json`**, **`command_mapping.json`** — no loader
  reads any of these. If you're tempted to "fix" a value in one of them
  expecting it to change converter output, it won't — `migration_inventory.csv`
  and the translator code itself are the only things that do.

  `interface_mapping.json` in particular has an `interface_numbering`
  remap (`GigabitEthernet "1/0/"` → `"0/0/"`) that would be **wrong** to
  wire in as-is: per the official Huawei `V600R025C00 Configuration
  Guide — Virtualization` (Stack chapter, Table 2-3), a standalone device
  defaults to Slot ID 1, and stack member 1 also uses `GE1/0/x` — never
  `GE0/0/x`. This was confirmed against a real migration project's
  decision log, which explicitly flags any draft using `GE0/0/x` as
  incorrect. The current pass-through interface naming in
  `HuaweiSwitchTranslator.map_interface_name` (prefix-only remap, e.g.
  `Port-channel` → `Eth-Trunk`) is closer to correct than this JSON's
  numbering remap and should stay that way.

## If you add a new mapping file

State in this file, in one line, which module loads it and what happens
if a row is missing — that's the difference between a mapping file that
shapes real output and one that just looks like it does.
