import re

from ..base_driver import BaseDriver


class ArubaAOSCXDriver(
    BaseDriver
):

    def get_device_info(
        self
    ):

        output = (
            self.connection
            .send_command(
                "show system"
            )
        )


        hostname = (
            self.connection
            .find_prompt()
            .strip()
            .rstrip("#>")
        )


        model = "Unknown"
        version = "Unknown"
        serial = "Unknown"


        patterns = {
            "model": [
                r"Product Name\s*:\s*(.+)",
                r"Product SKU\s*:\s*(\S+)"
            ],
            "version": [
                r"Software Version\s*:\s*(\S+)",
                r"Version\s*:\s*(\S+)"
            ],
            "serial": [
                r"Serial Number\s*:\s*(\S+)"
            ]
        }


        values = {
            "model": model,
            "version": version,
            "serial": serial
        }


        for field, field_patterns in (
            patterns.items()
        ):

            for pattern in (
                field_patterns
            ):

                match = re.search(
                    pattern,
                    output,
                    re.IGNORECASE
                )

                if match:

                    values[field] = (
                        match.group(1)
                        .strip()
                    )

                    break


        return {
            "vendor": "Aruba",
            "platform": "AOS-CX",
            "hostname": (
                hostname
                or
                "Unknown"
            ),
            "model": (
                values["model"]
            ),
            "version": (
                values["version"]
            ),
            "serial": (
                values["serial"]
            )
        }


    def get_storage_info(
        self
    ):

        return (
            self.connection
            .send_command(
                "show images"
            )
        )
