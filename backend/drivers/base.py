"""
base.py — Abstract base class for all network device drivers.

To add a new vendor:
  1. Create backend/drivers/<vendor>.py
  2. Subclass BaseDriver and implement all abstract methods
  3. Register it in backend/drivers/__init__.py
"""

from abc import ABC, abstractmethod
from typing import Optional


class BaseDriver(ABC):
    """
    Every vendor driver must implement these methods.
    The core orchestrator calls only this interface — never vendor-specific code.
    """

    # Subclasses must set this to the Netmiko device_type string
    NETMIKO_DEVICE_TYPE: str = ""

    # Subclasses define commands per analysis type
    COMMANDS: dict[str, list[str]] = {}

    # ──────────────────────────────────────────────
    # Connection helpers
    # ──────────────────────────────────────────────

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
        """Return the command list for the given analysis type."""
        return self.COMMANDS.get(analysis_type, self.COMMANDS.get("status", []))

    # ──────────────────────────────────────────────
    # Abstract interface — must be implemented
    # ──────────────────────────────────────────────

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
