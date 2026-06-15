"""
ned_registry.py — NED (Network Element Driver) Registry

Inspired by Cisco NSO's NED architecture.

Every driver has a formal NED ID (e.g. "cisco-ios-cli-1.0") that uniquely
identifies the vendor, platform, protocol, and version.  Devices store their
ned_id so the orchestrator always knows exactly which driver handles them.

NED ID format: <vendor>-<platform>-<protocol>-<major>.<minor>
  e.g.  cisco-ios-cli-1.0
        cisco-nxos-cli-1.0
        fortinet-fortios-cli-1.0

Usage:
    from backend.ned_registry import NED_REGISTRY, get_ned_metadata

    meta = get_ned_metadata("cisco-ios-cli-1.0")
    print(meta.vendor)       # "Cisco"
    print(meta.protocol)     # "cli"
    print(meta.capabilities) # ["rollback", "commit-queue", ...]
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class NedMetadata:
    """Immutable descriptor for a registered NED."""

    ned_id: str                      # e.g. "cisco-ios-cli-1.0"
    version: str                     # e.g. "1.0"
    vendor: str                      # e.g. "Cisco"
    platform: str                    # e.g. "IOS/IOS-XE"
    protocol: str                    # "cli" | "netconf" | "restconf" | "snmp"
    netmiko_type: str                # Netmiko device_type (CLI NEDs only)
    description: str
    capabilities: tuple[str, ...]    # e.g. ("rollback", "commit-queue", "live-status")
    supported_families: tuple[str, ...] = ()  # device families this NED covers

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict:
        return {
            "ned_id": self.ned_id,
            "version": self.version,
            "vendor": self.vendor,
            "platform": self.platform,
            "protocol": self.protocol,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "supported_families": list(self.supported_families),
        }


# ─────────────────────────────────────────────
# Registered NEDs  (v1.0 — first release)
# ─────────────────────────────────────────────

_NEDS: list[NedMetadata] = [

    # ── Cisco IOS / IOS-XE (CLI) ──────────────────────────────────────────
    NedMetadata(
        ned_id="cisco-ios-cli-1.0",
        version="1.0",
        vendor="Cisco",
        platform="IOS/IOS-XE",
        protocol="cli",
        netmiko_type="cisco_ios",
        description="Cisco IOS and IOS-XE devices via SSH CLI (CSR1000v, Catalyst 9k, ASR1k)",
        capabilities=(
            "rollback",
            "commit-queue",
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
        ),
        supported_families=("CSR1000v", "Catalyst 9k", "ASR1k", "ISR", "IOS-XE"),
    ),

    # ── Cisco NX-OS (CLI) ─────────────────────────────────────────────────
    NedMetadata(
        ned_id="cisco-nxos-cli-1.0",
        version="1.0",
        vendor="Cisco",
        platform="NX-OS",
        protocol="cli",
        netmiko_type="cisco_nxos",
        description="Cisco Nexus datacenter switches via SSH CLI",
        capabilities=(
            "rollback",
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
        ),
        supported_families=("Nexus 9k", "Nexus 7k", "Nexus 5k", "Nexus 3k"),
    ),

    # ── Cisco IOS-XR (CLI) ────────────────────────────────────────────────
    NedMetadata(
        ned_id="cisco-iosxr-cli-1.0",
        version="1.0",
        vendor="Cisco",
        platform="IOS-XR",
        protocol="cli",
        netmiko_type="cisco_xr",
        description="Cisco IOS-XR service provider routers via SSH CLI",
        capabilities=(
            "rollback",
            "commit-queue",
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
            "candidate-config",
        ),
        supported_families=("ASR 9k", "NCS 5500", "NCS 540", "XRv 9000"),
    ),

    # ── Fortinet FortiGate (CLI) ──────────────────────────────────────────
    NedMetadata(
        ned_id="fortinet-fortios-cli-1.0",
        version="1.0",
        vendor="Fortinet",
        platform="FortiOS",
        protocol="cli",
        netmiko_type="fortinet",
        description="Fortinet FortiGate firewalls via SSH CLI (FortiOS 6.x / 7.x)",
        capabilities=(
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
        ),
        supported_families=("FortiGate 60F", "FortiGate 100F", "FortiGate 200F", "FortiGate VM"),
    ),

    # ── Juniper JunOS (CLI) ───────────────────────────────────────────────
    NedMetadata(
        ned_id="juniper-junos-cli-1.0",
        version="1.0",
        vendor="Juniper",
        platform="JunOS",
        protocol="cli",
        netmiko_type="juniper_junos",
        description="Juniper routers and switches via SSH CLI",
        capabilities=(
            "rollback",
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
            "candidate-config",
        ),
        supported_families=("MX Series", "EX Series", "QFX Series", "SRX Series"),
    ),

    # ── Palo Alto PAN-OS (CLI) ────────────────────────────────────────────
    NedMetadata(
        ned_id="paloalto-panos-cli-1.0",
        version="1.0",
        vendor="Palo Alto",
        platform="PAN-OS",
        protocol="cli",
        netmiko_type="paloalto_panos",
        description="Palo Alto Networks firewalls via SSH CLI",
        capabilities=(
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
            "candidate-config",
        ),
        supported_families=("PA-220", "PA-820", "PA-850", "PA-3200", "PA-5200", "VM-Series"),
    ),

    # ── Arista EOS (CLI) ──────────────────────────────────────────────────
    NedMetadata(
        ned_id="arista-eos-cli-1.0",
        version="1.0",
        vendor="Arista",
        platform="EOS",
        protocol="cli",
        netmiko_type="arista_eos",
        description="Arista Networks switches via SSH CLI",
        capabilities=(
            "rollback",
            "live-status",
            "check-sync",
            "config-backup",
            "interface-list",
        ),
        supported_families=("7050X", "7260X", "7300X", "7500R", "cEOS"),
    ),

]

# ─────────────────────────────────────────────
# Registry lookup
# ─────────────────────────────────────────────

NED_REGISTRY: dict[str, NedMetadata] = {n.ned_id: n for n in _NEDS}

# Also index by netmiko_type so we can reverse-lookup from legacy device_type
_BY_NETMIKO_TYPE: dict[str, NedMetadata] = {}
for _ned in _NEDS:
    if _ned.netmiko_type not in _BY_NETMIKO_TYPE:
        _BY_NETMIKO_TYPE[_ned.netmiko_type] = _ned


def get_ned_metadata(ned_id: str) -> Optional[NedMetadata]:
    """Return NED metadata by ned_id, or None if not registered."""
    return NED_REGISTRY.get(ned_id)


def ned_id_from_netmiko_type(netmiko_type: str) -> Optional[str]:
    """
    Reverse-lookup: given a Netmiko device_type (e.g. 'cisco_ios'),
    return the primary NED ID for that type.
    Used when migrating devices that only have a device_type set.
    """
    ned = _BY_NETMIKO_TYPE.get(netmiko_type)
    return ned.ned_id if ned else None


def list_neds() -> list[dict]:
    """Return all registered NEDs as serialisable dicts."""
    return [n.to_dict() for n in _NEDS]
