import re

from ..base_driver import BaseDriver


class ArubaAOSSwitchDriver(
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


        version_output = ""

        try:

            version_output = (
                self.connection
                .send_command(
                    "show version"
                )
            )

        except Exception:

            pass


        combined_output = (
            output
            +
            "\n"
            +
            version_output
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


        model_patterns = [

            r"Product Model\s*:\s*(.+)",

            r"Product Name\s*:\s*(.+)",

            r"Model\s*:\s*(\S+)"

        ]


        version_patterns = [

            r"Software revision\s*:\s*(\S+)",

            r"Software Version\s*:\s*(\S+)",

            r"Version\s*:\s*(\S+)"

        ]


        serial_patterns = [

            r"Serial Number\s*:\s*(\S+)",

            r"Serial number\s*:\s*(\S+)"

        ]


        for pattern in (
            model_patterns
        ):

            match = re.search(
                pattern,
                combined_output,
                re.IGNORECASE
            )

            if match:

                model = (
                    match.group(1)
                    .strip()
                )

                break


        for pattern in (
            version_patterns
        ):

            match = re.search(
                pattern,
                combined_output,
                re.IGNORECASE
            )

            if match:

                version = (
                    match.group(1)
                    .strip()
                )

                break


        for pattern in (
            serial_patterns
        ):

            match = re.search(
                pattern,
                combined_output,
                re.IGNORECASE
            )

            if match:

                serial = (
                    match.group(1)
                    .strip()
                )

                break


        return {
            "vendor": "Aruba",
            "platform": "AOS-S",
            "hostname": (
                hostname
                or
                "Unknown"
            ),
            "model": model,
            "version": version,
            "serial": serial
        }


    def get_storage_info(
        self
    ):

        return (
            self.connection
            .send_command(
                "show flash"
            )
        )
