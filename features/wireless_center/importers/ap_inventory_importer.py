import csv
from pathlib import Path


class APInventoryImporter:
    """
    Import Huawei AP inventory CSV and enrich AP data parsed
    from the WLC running configuration.

    Matching priority:
        1. MAC Address
        2. Serial Number
        3. AP Name
        4. AP ID
    """

    EMPTY_VALUES = {
        "",
        "--",
        "-",
        "n/a",
        "na",
        "none",
        "null",
    }

    def __init__(self, path):
        self.path = Path(path)
        self.records = []


    # ========================================================
    # NORMALIZATION
    # ========================================================

    @staticmethod
    def clean(value):
        if value is None:
            return ""

        return str(value).replace(
            "\t",
            ""
        ).strip()


    @classmethod
    def clean_value(cls, value):
        value = cls.clean(value)

        if value.lower() in cls.EMPTY_VALUES:
            return ""

        return value


    @staticmethod
    def normalize_mac(value):
        value = str(
            value or ""
        ).lower()

        for char in [
            ":",
            "-",
            ".",
            " ",
            "\t"
        ]:
            value = value.replace(
                char,
                ""
            )

        return value


    @staticmethod
    def normalize_text(value):
        return str(
            value or ""
        ).strip().lower()


    # ========================================================
    # LOAD CSV
    # ========================================================

    def load(self):
        self.records = []

        with open(
            self.path,
            "r",
            encoding="utf-8-sig",
            errors="ignore",
            newline=""
        ) as file:

            reader = csv.DictReader(
                file
            )

            for raw_row in reader:

                row = {
                    self.clean(key):
                    self.clean_value(value)

                    for key, value
                    in raw_row.items()

                    if key is not None
                }

                # Case-insensitive, multi-alias header lookup.
                #
                # This used to do exact-string dict lookups against one
                # hardcoded header spelling per field (e.g. row.get("AP
                # name", "")). Two concrete failures came from that:
                #   1. The real header is "AP Name" (capital N) everywhere
                #      else in this app (inventory_master.py's own ALIASES
                #      and its generated master template both use "AP
                #      Name"), but this importer looked for "AP name"
                #      (lowercase n) and never matched it -- `name` came
                #      back "" even with a populated column.
                #   2. "Longitude, Latitude" as a single literal dict key
                #      can only ever match a header quoted exactly that way
                #      in the source file; an ordinary unquoted CSV header
                #      `Longitude, Latitude` gets split by csv.DictReader
                #      into two separate columns ("Longitude" and "
                #      Latitude"), so `location` was always "".
                # A case-insensitive alias list, checked in priority order,
                # is robust to both a real Huawei AP Info export and this
                # app's own generated AP Master template.
                row_ci = {str(key).strip().lower(): value for key, value in row.items()}

                def pick(*aliases):
                    for alias in aliases:
                        value = row_ci.get(alias)
                        if value:
                            return value
                    return ""

                # A header written as `Longitude, Latitude` (one column,
                # comma inside the label) only matches literally if that
                # exact text is quoted in the source file. An ordinary
                # unquoted CSV header splits it into two real columns,
                # "Longitude" and "Latitude" (with a leading space on the
                # second from the comma) -- which is the common case, so
                # synthesize `location` from those two if a dedicated
                # location/site column isn't present.
                location = pick("location", "site", "longitude, latitude")
                if not location:
                    lon = pick("longitude")
                    lat = pick("latitude")
                    if lon and lat:
                        location = f"{lon}, {lat}"

                record = {
                    "ap_id": pick("ap id", "ap_id", "id"),
                    "name": pick("ap name", "ap_name", "name", "hostname"),
                    "mac": pick("mac address", "mac", "ap mac", "ethernet mac"),
                    "ip": pick("ip address", "management ip", "ip", "ap ip"),
                    "model": pick("ap type", "ap model", "type"),
                    "version": pick("system version", "software version", "version"),
                    "serial": pick("serial number", "serial", "sn"),
                    "location": location,
                    "status": pick("status", "ap status", "deployment status"),
                }

                self.records.append(
                    record
                )

        return self.records


    # ========================================================
    # MERGE
    # ========================================================

    def merge(self, config_aps):
        if not self.records:
            self.load()

        by_mac = {}
        by_serial = {}
        by_name = {}
        by_id = {}

        for record in self.records:

            mac = self.normalize_mac(
                record.get(
                    "mac"
                )
            )

            serial = self.normalize_text(
                record.get(
                    "serial"
                )
            )

            name = self.normalize_text(
                record.get(
                    "name"
                )
            )

            ap_id = self.normalize_text(
                record.get(
                    "ap_id"
                )
            )

            if mac:
                by_mac[mac] = record

            if serial:
                by_serial[
                    serial
                ] = record

            if name:
                by_name[name] = record

            if ap_id:
                by_id[ap_id] = record


        matched = 0
        unmatched = 0

        matched_aps = []
        unmatched_aps = []

        matched_by = {
            "mac": 0,
            "serial": 0,
            "name": 0,
            "ap_id": 0,
        }


        for ap in config_aps:

            inventory = None
            match_method = ""

            mac = self.normalize_mac(
                ap.get(
                    "mac"
                )
            )

            serial = self.normalize_text(
                ap.get(
                    "serial"
                )
            )

            name = self.normalize_text(
                ap.get(
                    "name"
                )
            )

            ap_id = self.normalize_text(
                ap.get(
                    "ap_id"
                )
            )


            # Primary:
            # MAC Address

            if (
                mac
                and mac in by_mac
            ):
                inventory = (
                    by_mac[mac]
                )

                match_method = "MAC"


            # Fallback:
            # Serial Number

            elif (
                serial
                and serial
                in by_serial
            ):
                inventory = (
                    by_serial[
                        serial
                    ]
                )

                match_method = (
                    "Serial"
                )


            # Fallback:
            # AP Name

            elif (
                name
                and name
                in by_name
            ):
                inventory = (
                    by_name[
                        name
                    ]
                )

                match_method = (
                    "Name"
                )


            # Last fallback:
            # AP ID

            elif (
                ap_id
                and ap_id
                in by_id
            ):
                inventory = (
                    by_id[
                        ap_id
                    ]
                )

                match_method = (
                    "AP ID"
                )


            if inventory:

                matched += 1

                if match_method == "MAC":
                    matched_by[
                        "mac"
                    ] += 1

                elif match_method == "Serial":
                    matched_by[
                        "serial"
                    ] += 1

                elif match_method == "Name":
                    matched_by[
                        "name"
                    ] += 1

                elif match_method == "AP ID":
                    matched_by[
                        "ap_id"
                    ] += 1


                # ----------------------------
                # Enrichment fields
                # ----------------------------

                if inventory.get(
                    "ip"
                ):
                    ap["ip"] = (
                        inventory["ip"]
                    )


                if inventory.get(
                    "model"
                ):
                    ap["model"] = (
                        inventory[
                            "model"
                        ]
                    )


                if inventory.get(
                    "version"
                ):
                    ap["version"] = (
                        inventory[
                            "version"
                        ]
                    )


                if inventory.get(
                    "status"
                ):
                    ap["status"] = (
                        inventory[
                            "status"
                        ]
                    )


                if inventory.get(
                    "location"
                ):
                    ap[
                        "inventory_location"
                    ] = inventory[
                        "location"
                    ]


                # Keep source inventory
                # information for auditing.

                ap[
                    "inventory_match"
                ] = True

                ap[
                    "inventory_match_method"
                ] = match_method

                ap[
                    "inventory_ap_id"
                ] = inventory.get(
                    "ap_id",
                    ""
                )

                ap[
                    "inventory_name"
                ] = inventory.get(
                    "name",
                    ""
                )

                matched_aps.append(
                    {
                        "ap_id": ap.get(
                            "ap_id",
                            ""
                        ),
                        "name": ap.get(
                            "name",
                            ""
                        ),
                        "mac": ap.get(
                            "mac",
                            ""
                        ),
                        "serial": ap.get(
                            "serial",
                            ""
                        ),
                        "match_method":
                            match_method,
                    }
                )


            else:

                unmatched += 1

                ap[
                    "inventory_match"
                ] = False

                ap[
                    "inventory_match_method"
                ] = ""

                unmatched_aps.append(
                    {
                        "ap_id": ap.get(
                            "ap_id",
                            ""
                        ),
                        "name": ap.get(
                            "name",
                            ""
                        ),
                        "mac": ap.get(
                            "mac",
                            ""
                        ),
                        "serial": ap.get(
                            "serial",
                            ""
                        ),
                    }
                )


        return {
            "total_inventory":
                len(
                    self.records
                ),

            "total_config":
                len(
                    config_aps
                ),

            "matched":
                matched,

            "unmatched":
                unmatched,

            "matched_aps":
                matched_aps,

            "unmatched_aps":
                unmatched_aps,

            "matched_by":
                matched_by,
        }
