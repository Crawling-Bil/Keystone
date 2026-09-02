import re

from ..base_driver import BaseDriver


class CiscoIOSXEDriver(BaseDriver):

    def get_device_info(self):

        output = self.connection.send_command(
            "show version"
        )

        hostname = (
            self.connection.find_prompt()
            .strip()
            .rstrip("#>")
        )

        model = "Unknown"
        version = "Unknown"
        serial = "Unknown"

        version_patterns = [

            r"Cisco IOS XE Software,\s*Version\s+([^\s,]+)",

            r"Cisco IOS Software.*?Version\s+([^\s,]+)",

            r"Version\s+([0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*)"

        ]

        for pattern in version_patterns:

            match = re.search(
                pattern,
                output,
                re.IGNORECASE
            )

            if match:

                version = (
                    match.group(1)
                    .strip()
                    .rstrip(",")
                )

                break

        model_patterns = [

            r"Model Number\s*:\s*(\S+)",

            r"Model number\s*:\s*(\S+)",

            r"cisco\s+(\S+)\s+\([^)]+\)\s+processor",

            r"^([A-Z0-9-]+)\s+uptime is"

        ]

        for pattern in model_patterns:

            match = re.search(
                pattern,
                output,
                re.IGNORECASE | re.MULTILINE
            )

            if match:

                model = match.group(1)

                break

        serial_patterns = [

            r"System Serial Number\s*:\s*(\S+)",

            r"Processor board ID\s+(\S+)",

            r"System serial number\s*:\s*(\S+)"

        ]

        for pattern in serial_patterns:

            match = re.search(
                pattern,
                output,
                re.IGNORECASE
            )

            if match:

                serial = match.group(1)

                break

        return {

            "vendor": "Cisco",

            "platform": "IOS-XE",

            "hostname": hostname,

            "model": model,

            "version": version,

            "serial": serial

        }

    def get_storage_info(self):

        return self.connection.send_command(
            "dir flash:"
        )

    def check_free_space(
        self,
        required_size
    ):
        return True

    def firmware_exists(
        self,
        filename
    ):

        output = self.connection.send_command(
            "dir flash:"
        )

        return filename in output

    def copy_firmware(
        self,
        protocol,
        server,
        filename
    ):
        raise NotImplementedError

    def verify_md5(
        self,
        filename,
        checksum
    ):
        raise NotImplementedError

    def save_config(self):

        self.connection.send_command(
            "write memory"
        )

        return True

    def install_firmware(
        self,
        filename
    ):
        raise NotImplementedError

    def reload_device(self):
        raise NotImplementedError

    def wait_until_online(
        self,
        timeout=600
    ):
        raise NotImplementedError

    def post_check(self):

        return self.get_device_info()