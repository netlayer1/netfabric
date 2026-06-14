"""
drivers/__init__.py — Driver registry

Maps Netmiko device_type strings → driver instances.

To add a new vendor:
  1. Create backend/drivers/<vendor>.py subclassing BaseDriver
  2. Import it here and add an entry to DRIVER_REGISTRY
"""

from .base import BaseDriver
from .cisco_ios_xe import CiscoIOSXEDriver
from .fortigate import FortiGateDriver

# Maps the device_type stored in the DB → driver instance
DRIVER_REGISTRY: dict[str, BaseDriver] = {
    "cisco_ios":    CiscoIOSXEDriver(),
    "cisco_ios_xe": CiscoIOSXEDriver(),
    "fortinet":     FortiGateDriver(),
}

_DEFAULT_DRIVER = CiscoIOSXEDriver()


def get_driver(device_type: str) -> BaseDriver:
    """
    Return the driver for the given device_type.
    Falls back to CiscoIOSXE if the type is unknown.
    """
    return DRIVER_REGISTRY.get(device_type, _DEFAULT_DRIVER)


__all__ = ["BaseDriver", "get_driver", "DRIVER_REGISTRY"]
