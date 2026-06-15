"""
drivers/__init__.py — NED (Network Element Driver) registry

Devices can be looked up two ways:
  1. By ned_id   (preferred) — e.g. "cisco-ios-cli-1.0"
  2. By device_type (legacy) — e.g. "cisco_ios"  (Netmiko string)

To add a new vendor NED:
  1. Create backend/drivers/<vendor>.py subclassing BaseDriver
  2. Set NED_ID, NED_VERSION, PROTOCOL, CAPABILITIES on the class
  3. Import it here and add entries to both registries below
"""

from .base import BaseDriver
from .cisco_ios_xe import CiscoIOSXEDriver
from .fortigate import FortiGateDriver

# ── Driver instances ──────────────────────────────────────────────────────────
_cisco_ios_xe  = CiscoIOSXEDriver()
_fortigate     = FortiGateDriver()

# ── NED ID registry (primary lookup) ─────────────────────────────────────────
NED_DRIVER_REGISTRY: dict[str, BaseDriver] = {
    "cisco-ios-cli-1.0":      _cisco_ios_xe,
    "fortinet-fortios-cli-1.0": _fortigate,
}

# ── Legacy device_type registry (backwards compat with existing DB rows) ──────
DRIVER_REGISTRY: dict[str, BaseDriver] = {
    "cisco_ios":    _cisco_ios_xe,
    "cisco_ios_xe": _cisco_ios_xe,
    "fortinet":     _fortigate,
}

_DEFAULT_DRIVER = _cisco_ios_xe


def get_driver(device_type_or_ned_id: str) -> BaseDriver:
    """
    Return the driver for the given ned_id OR legacy device_type.
    Checks NED ID registry first, then falls back to device_type.
    Falls back to CiscoIOSXE if nothing matches.
    """
    return (
        NED_DRIVER_REGISTRY.get(device_type_or_ned_id)
        or DRIVER_REGISTRY.get(device_type_or_ned_id)
        or _DEFAULT_DRIVER
    )


def get_driver_by_ned_id(ned_id: str) -> BaseDriver:
    """Strict NED ID lookup — raises KeyError if not found."""
    if ned_id not in NED_DRIVER_REGISTRY:
        raise KeyError(f"No NED registered for ned_id='{ned_id}'")
    return NED_DRIVER_REGISTRY[ned_id]


def list_ned_ids() -> list[str]:
    """Return all registered NED IDs."""
    return list(NED_DRIVER_REGISTRY.keys())


__all__ = [
    "BaseDriver",
    "get_driver",
    "get_driver_by_ned_id",
    "list_ned_ids",
    "DRIVER_REGISTRY",
    "NED_DRIVER_REGISTRY",
]
