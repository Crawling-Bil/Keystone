import csv
from pathlib import Path


class Inventory:

    def __init__(
        self,
        csv_file="mappings/migration_inventory.csv"
    ):
        self.csv_file = Path(csv_file)
        self.devices = {}

        if self.csv_file.exists():
            self.load()

    def load(self):

        self.devices = {}

        with open(
            self.csv_file,
            "r",
            encoding="utf-8-sig",
            errors="ignore",
        ) as file:

            reader = csv.DictReader(file)

            if not reader.fieldnames:
                return

            for row in reader:

                cleaned = {}

                for key, value in row.items():

                    if key is None:
                        continue

                    clean_key = key.strip()

                    clean_value = (
                        value.strip()
                        if value
                        else ""
                    )

                    cleaned[
                        clean_key
                    ] = clean_value

                old_hostname = cleaned.get(
                    "OldHostname",
                    ""
                )

                if not old_hostname:
                    continue

                key = self.normalize_hostname(
                    old_hostname
                )

                self.devices[key] = cleaned

    def get(self, hostname):

        if not hostname:
            return None

        key = self.normalize_hostname(
            hostname
        )

        return self.devices.get(key)

    def get_new_hostname(
        self,
        old_hostname,
        default=None
    ):

        device = self.get(
            old_hostname
        )

        if not device:

            if default is not None:
                return default

            return old_hostname

        new_hostname = device.get(
            "NewHostname",
            ""
        )

        return (
            new_hostname
            or default
            or old_hostname
        )

    def get_target_model(
        self,
        hostname
    ):

        device = self.get(
            hostname
        )

        if not device:
            return ""

        return (
            device.get(
                "HuaweiModel",
                ""
            )
            or device.get(
                "TargetModel",
                ""
            )
        )

    def get_source_model(
        self,
        hostname
    ):

        device = self.get(
            hostname
        )

        if not device:
            return ""

        return (
            device.get(
                "CiscoModel",
                ""
            )
            or device.get(
                "SourceModel",
                ""
            )
        )

    def get_metadata(
        self,
        hostname
    ):

        device = self.get(
            hostname
        )

        if not device:
            return {}

        return dict(device)

    def exists(
        self,
        hostname
    ):

        return (
            self.get(hostname)
            is not None
        )

    @staticmethod
    def normalize_hostname(
        hostname
    ):

        return (
            str(hostname)
            .strip()
            .lower()
        )

    def __len__(self):

        return len(
            self.devices
        )