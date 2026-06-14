"""
fortigate.py — Driver for Fortinet FortiGate firewalls (FortiOS 6.x / 7.x)

Netmiko device_type: fortinet
Legacy SHA1 KEX algorithms are re-enabled globally in device_connector.py
for older FortiGate firmware that doesn't support modern algorithms.
"""

from typing import Optional
from .base import BaseDriver


class FortiGateDriver(BaseDriver):

    NETMIKO_DEVICE_TYPE = "fortinet"

    COMMANDS = {
        "config_backup": [
            "show full-configuration",
        ],
    }

    def get_connection_params(self, host, username, password, port=22, timeout=30) -> dict:
        params = super().get_connection_params(host, username, password, port, timeout)
        # FortiGate requires legacy KEX algorithms on older firmware
        params["disabled_algorithms"] = {"kex": []}
        return params

    def test_command(self) -> str:
        return "get system status"

    def save_config_command(self) -> Optional[str]:
        # FortiGate auto-saves on commit — no explicit save needed
        return None

    def parse_version(self, raw_output: str) -> str:
        for line in raw_output.splitlines():
            if "Version:" in line or "Fortigate" in line.lower() or "FortiOS" in line:
                return line.strip()
        return raw_output.strip().splitlines()[0] if raw_output.strip() else "Connected"

    def interfaces_command(self) -> str:
        return "get system interface"

    def parse_interface_names(self, raw_output: str) -> list[str]:
        """
        Parse 'get system interface' — lines starting with '== [' contain
        the interface name e.g. '== [ port1 ]'
        """
        names = []
        for line in raw_output.splitlines():
            stripped = line.strip()
            if stripped.startswith("== [") and "]" in stripped:
                name = stripped[4:stripped.index("]")].strip()
                if name:
                    names.append(name)
        return names
