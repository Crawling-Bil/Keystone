# Regression snapshots

Each `*.json` file is the frozen output of one synthetic sample (converter, Switch Analyzer, Topology Builder, cutover runbook, run comparison). `tests/test_snapshots.py` rebuilds every output and compares it with its file.

When a snapshot test fails, read the diff it prints. If the new output is the intended improvement, accept it once:

    KEYSTONE_UPDATE_SNAPSHOTS=1 python -m pytest tests/test_snapshots.py

and review the changed files in this folder like any other change. A new sample needs its snapshot created the same way; a missing snapshot fails on purpose.

Inputs are invented (documentation addresses, made-up names). SNMP communities are masked in the converter snapshots.
