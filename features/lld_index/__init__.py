"""LLD Index: build the "LLD Content Index" workbook the Document Generator imports.

A project is a device inventory (site, hostname, model, role, management IP,
serial, optional config file) plus a few lines about the project. Keystone
picks the technology templates (templates/*.json), expands each chapter per
site, per device or per model, fills tables from the inventory and from the
same analyzers the rest of Keystone uses, writes the narrative from the
project goals, and saves an .xlsx in the importer's format.
"""
