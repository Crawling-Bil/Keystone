from ..drivers.cisco.ios import CiscoIOSDriver
from ..drivers.cisco.iosxe import CiscoIOSXEDriver
from ..drivers.cisco.nxos import CiscoNXOSDriver
from ..drivers.huawei.vrp import HuaweiVRPDriver
from ..drivers.aruba.aos_switch import ArubaAOSSwitchDriver
from ..drivers.aruba.aos_cx import ArubaAOSCXDriver


def detect_driver(connection, netmiko_device_type, log_fn=None):

    if netmiko_device_type == "cisco_nxos":
        return CiscoNXOSDriver(connection, log_fn)

    if netmiko_device_type == "huawei":
        return HuaweiVRPDriver(connection, log_fn)

    if netmiko_device_type == "aruba_os":
        return ArubaAOSSwitchDriver(connection, log_fn)

    if netmiko_device_type == "aruba_aoscx":
        return ArubaAOSCXDriver(connection, log_fn)

    if netmiko_device_type == "cisco_ios":
        output = connection.send_command("show version")

        if "IOS XE" in output.upper():
            return CiscoIOSXEDriver(connection, log_fn)

        return CiscoIOSDriver(connection, log_fn)

    raise ValueError(
        f"Unsupported device type: {netmiko_device_type}"
    )
