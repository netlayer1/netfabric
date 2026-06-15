"""
cisco_ios_xe.py — NED for Cisco IOS / IOS-XE devices

NED ID:   cisco-ios-cli-6.115
Protocol: CLI (SSH via Netmiko)
Covers:   CSR1000v, Catalyst 9k, ASR1k, ISR, IOS-XE

Matches the NED ID used in Cisco NSO for IOS/IOS-XE devices.
"""

from typing import Optional
from .base import BaseDriver


class CiscoIOSXEDriver(BaseDriver):

    # ── NED Identity ─────────────────────────────────────────────────────
    NED_ID = "cisco-ios-cli-1.0"
    NED_VERSION = "1.0"
    PROTOCOL = "cli"

    CAPABILITIES = (
        "rollback",
        "commit-queue",
        "live-status",
        "check-sync",
        "config-backup",
        "interface-list",
    )

    # ── Netmiko ───────────────────────────────────────────────────────────
    NETMIKO_DEVICE_TYPE = "cisco_ios"

    # ── Config commands ───────────────────────────────────────────────────
    COMMANDS = {
        "config_backup": [
            "show running-config",
        ],
    }

    # ── Live-status (operational) commands ────────────────────────────────
    # These are show commands — never stored or diffed as config.
    LIVE_STATUS_COMMANDS = {
        "interfaces":    ["show interfaces"],
        "ip_brief":      ["show ip interface brief"],
        "routes":        ["show ip route"],
        "bgp":           ["show bgp summary"],
        "arp":           ["show arp"],
        "cdp":           ["show cdp neighbors detail"],
        "version":       ["show version"],
        "cpu":           ["show processes cpu sorted"],
        "memory":        ["show processes memory sorted"],
        "spanning_tree": ["show spanning-tree summary"],
        "vlans":         ["show vlan brief"],
        "mac_table":     ["show mac address-table"],
        "ntp":           ["show ntp status", "show ntp associations"],
        "crypto":        ["show crypto isakmp sa", "show crypto ipsec sa"],
    }

    # ── Methods ───────────────────────────────────────────────────────────

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

    def parse_platform(self, raw_version: str) -> str:
        """
        Extract the hardware platform string from 'show version'.
        e.g. "Cisco CSR1000V, Version 17.3.1a, RELEASE SOFTWARE"
        """
        for line in raw_version.splitlines():
            stripped = line.strip()
            if "cisco" in stripped.lower() and (
                "CSR" in stripped or "ASR" in stripped
                or "Catalyst" in stripped or "ISR" in stripped
            ):
                return stripped
        return self.parse_version(raw_version)
