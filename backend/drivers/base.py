"""
base.py — Abstract base class for all network device drivers (NEDs).

Inspired by Cisco NSO's NED (Network Element Driver) architecture.
Each driver is a NED — it owns the protocol conversation with one vendor/platform.

NED concepts implemented here:
  - NED_ID        unique identity e.g. "cisco-ios-cli-6.115"
  - NED_VERSION   semver-style version string
  - PROTOCOL      transport: "cli" | "netconf" | "restconf"
  - CAPABILITIES  feature flags the NED supports
  - live_status_commands()  operational (non-config) data — separate from config
  - rollback_command()      native device rollback if supported

To add a new vendor NED:
  1. Create backend/drivers/<vendor>.py
  2. Subclass BaseDriver, set NED_ID / NED_VERSION / PROTOCOL / CAPABILITIES
  3. Implement all abstract methods
  4. Register it in backend/drivers/__init__.py
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseDriver(ABC):
    """
    Every vendor NED must implement these methods.
    The core orchestrator calls only this interface — never vendor-specific code.
    """

    # ── NED Identity (set in each subclass) ──────────────────────────────
    NED_ID: str = ""          # e.g. "cisco-ios-cli-6.115"
    NED_VERSION: str = ""     # e.g. "6.115"
    PROTOCOL: str = "cli"     # "cli" | "netconf" | "restconf"

    # Feature flags — declare what this NED supports.
    # Common values: "rollback", "commit-queue", "live-status",
    #                "check-sync", "config-backup", "interface-list",
    #                "candidate-config"
    CAPABILITIES: tuple[str, ...] = ()

    # Netmiko device_type (CLI NEDs only)
    NETMIKO_DEVICE_TYPE: str = ""

    # Config commands by analysis type (pulled and stored/diffed)
    COMMANDS: dict[str, list[str]] = {}

    # Live-status (operational) commands — output is NOT configuration.
    # These pull real-time data: BGP sessions, interface counters, ARP tables.
    # Kept separate from COMMANDS so the orchestrator never diffs them like config.
    #
    # Keys are human-readable categories; values are CLI command lists.
    # Example:
    #   "bgp":        ["show bgp summary"],
    #   "interfaces": ["show interfaces"],
    #   "arp":        ["show arp"],
    #   "routes":     ["show ip route"],
    LIVE_STATUS_COMMANDS: dict[str, list[str]] = {}

    # ── Connection helpers ────────────────────────────────────────────────

    def get_connection_params(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        timeout: int = 30,
    ) -> dict:
        """
        Return the kwargs dict passed to Netmiko ConnectHandler.
        Override in subclass to add vendor-specific params (e.g. disabled_algorithms).
        """
        return {
            "device_type": self.NETMIKO_DEVICE_TYPE,
            "host": host,
            "username": username,
            "password": password,
            "port": port,
            "timeout": timeout,
            "session_log": None,
            "global_delay_factor": 1,
            "banner_timeout": 10,
            "auth_timeout": 10,
        }

    def get_commands(self, analysis_type: str) -> list[str]:
        """Return config command list for the given analysis type."""
        return self.COMMANDS.get(analysis_type, self.COMMANDS.get("status", []))

    def get_live_status_commands(self, category: str) -> list[str]:
        """
        Return operational command list for the given category.
        Returns empty list if category not supported by this NED.
        """
        return self.LIVE_STATUS_COMMANDS.get(category, [])

    def get_live_status_categories(self) -> list[str]:
        """Return all operational data categories this NED supports."""
        return list(self.LIVE_STATUS_COMMANDS.keys())

    def supports(self, capability: str) -> bool:
        """Check if this NED supports a given capability."""
        return capability in self.CAPABILITIES

    def ned_info(self) -> dict:
        """Return NED identity as a dict (for API responses)."""
        return {
            "ned_id": self.NED_ID,
            "version": self.NED_VERSION,
            "protocol": self.PROTOCOL,
            "capabilities": list(self.CAPABILITIES),
            "live_status_categories": self.get_live_status_categories(),
        }

    # ── Rollback support ──────────────────────────────────────────────────

    def rollback_command(self) -> Optional[str]:
        """
        Return a CLI command to roll back the last config change natively on
        the device (e.g. 'rollback configuration last 1' on IOS-XR).

        Return None if the device has no native rollback — the orchestrator
        will fall back to snapshot-based restore instead.
        """
        return None

    # ── Abstract interface — must be implemented ──────────────────────────

    @abstractmethod
    def test_command(self) -> str:
        """Single command used to verify connectivity (e.g. 'show version')."""
        ...

    @abstractmethod
    def save_config_command(self) -> Optional[str]:
        """
        Command to persist running config to startup config.
        Return None if the device saves automatically (e.g. FortiGate).
        """
        ...

    @abstractmethod
    def parse_version(self, raw_output: str) -> str:
        """
        Extract a short human-readable version/platform string
        from the output of test_command().
        """
        ...

    @abstractmethod
    def interfaces_command(self) -> str:
        """Command that lists all interfaces with their canonical names."""
        ...

    @abstractmethod
    def parse_interface_names(self, raw_output: str) -> list[str]:
        """
        Parse output of interfaces_command() and return a list of
        canonical interface names as the device knows them.
        e.g. ["GigabitEthernet1", "Loopback0", "Vlan10"]
        """
        ...
