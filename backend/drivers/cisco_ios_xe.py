"""
cisco_ios_xe.py — Driver for Cisco IOS-XE devices (CSR1000v, Catalyst 9k, ASR1k, etc.)

Netmiko device_type: cisco_ios  (IOS-XE uses the same driver as IOS)
"""

from typing import Optional
from .base import BaseDriver


class CiscoIOSXEDriver(BaseDriver):

    NETMIKO_DEVICE_TYPE = "cisco_ios"

    COMMANDS = {
        "config_backup": [
            "show running-config",
        ],
    }

    def test_command(self) -> str:
        return "show version"

    def save_config_command(self) -> Optional[str]:
        return "write memory"

    def parse_version(self, raw_output: str) -> str:
        for line in raw_output.splitlines():
            if "Cisco IOS" in line or "IOS-XE" in line:
                return line.strip()
        return raw_output.strip().splitlines()[0] if raw_output.strip() else "Connected"

    def interfaces_command(self) -> str:
        return "show ip interface brief"

    def parse_interface_names(self, raw_output: str) -> list[str]:
        """
        Parse 'show ip interface brief' — first token of each data line is the
        canonical interface name (e.g. GigabitEthernet1, Loopback0, Vlan10).
        Skip the header line.
        """
        names = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith("interface"):
                continue
            name = stripped.split()[0]
            if name:
                names.append(name)
        return names
