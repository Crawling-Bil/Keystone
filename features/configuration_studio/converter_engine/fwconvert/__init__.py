"""FortiGate <-> Palo Alto PAN-OS conversion, in layers (interfaces and zones, objects, policies, NAT, routes, VPN) with a loss report.

Both directions go through one neutral model (``model.FwModel``): a reader turns a configuration into the model, a writer turns the model into the other
vendor's CLI.  Whatever a reader cannot carry, and whatever a writer cannot express, is written to a ``Report`` with the reason and a documentation link,
so nothing is dropped silently.  See ``convert.convert`` for the entry point and ``docs/modules/configuration-studio.md`` for the rules.
"""

from .convert import LAYERS, ConvertResult, convert  # noqa: F401
