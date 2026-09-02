import re

from ..base_driver import BaseDriver


class CiscoIOSDriver(BaseDriver):

    def get_device_info(self):

        output = self.connection.send_command(
            "show version"
        )

        hostname = (
            self.connection.find_prompt()
            .strip("#> ")
        )

        model = "Unknown"
        version = "Unknown"

        match = re.search(
            r"Version\s+([^,\s]+)",
            output,
            re.IGNORECASE
        )

        if match:
            version = match.group(1)

        match = re.search(
            r"cisco\s+(\S+)\s+\(",
            output,
            re.IGNORECASE
        )

        if match:
            model = match.group(1)

        return {
            "vendor": "Cisco",
            "platform": "IOS",
            "hostname": hostname,
            "model": model,
            "version": version,
            "serial": "Unknown"
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
        raise NotImplementedError(
            "Firmware copy not implemented yet."
        )

    def verify_md5(
        self,
        filename,
        checksum
    ):
        raise NotImplementedError(
            "MD5 verification not implemented yet."
        )

    def save_config(self):

        self.connection.send_command(
            "write memory"
        )

        return True

    def install_firmware(
        self,
        filename
    ):
        raise NotImplementedError(
            "Firmware installation not implemented yet."
        )

    def reload_device(self):
        raise NotImplementedError(
            "Device reload not implemented yet."
        )

    def wait_until_online(
        self,
        timeout=600
    ):
        raise NotImplementedError(
            "Reconnect check not implemented yet."
        )

    def post_check(self):
        return self.get_device_info()