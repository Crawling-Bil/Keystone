"""Shared building blocks for the Router / Firewall / Load Balancer analyzers.

Everything here is vendor-neutral: splitting a multi-command terminal
capture into per-command blocks, redacting secrets, building the common
result structure the browser renders, writing the generic Excel export and
discovering collect-script files.  Vendor knowledge lives in each analyzer
package (features/router_analyzer, features/firewall_analyzer,
features/load_balancer_analyzer).
"""
