from ..base_driver import BaseDriver


class CiscoNXOSDriver(BaseDriver):

    def get_device_info(self):
        return {
            "vendor": "Cisco",
            "platform": "NX-OS",
            "hostname": self.connection.find_prompt().strip("#> "),
            "model": "Unknown",
            "version": "Unknown",
            "serial": "Unknown"
        }
    def get_storage_info(self):
        return self.connection.send_command(
            "dir bootflash:"
        )

    def check_free_space(self, required_size):
        return True

    def firmware_exists(self, filename):

        output = self.connection.send_command(
            "dir bootflash:"
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
            "copy running-config startup-config"
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