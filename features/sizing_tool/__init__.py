"""Sizing Tool: one inventory of every network device, grouped by type, with its hardware, modules, optics, licences and the features in use.

It reads the same captures the analyzers read and calls the analyzers' own engines (Switch, Router, Firewall, Load Balancer and Wireless);
it keeps no parser of its own.  The result is the input of a refresh project: what runs today, on what hardware, with which licences.
"""
