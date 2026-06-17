"""
fortigate.py — NED for Fortinet FortiGate firewalls (FortiOS 6.x / 7.x)

NED ID:   fortinet-fortios-cli-2.0
Protocol: CLI (SSH via Netmiko)

Legacy SHA1 KEX algorithms are re-enabled globally in device_connector.py
for older FortiGate firmware that doesn't support modern algorithms.
"""

import re
from typing import Optional
from .base import BaseDriver

# Lines FortiOS regenerates on every export — always volatile, never meaningful diffs
_VOLATILE = re.compile(
    r"^\s*(set \S*password\S* ENC\s"       # any *-password ENC field
    r"|set (private-key|certificate) ENC\s"
    r"|set (private-key|certificate) \"-----BEGIN )"
    r"|^[-A-Za-z0-9+/=]{40,}$"            # bare base64 lines inside key/cert blocks
    r'|^-----(?:BEGIN|END) ',
    re.IGNORECASE,
)


class FortiGateDriver(BaseDriver):

    # ── NED Identity ─────────────────────────────────────────────────────
    NED_ID = "fortinet-fortios-cli-1.0"
    NED_VERSION = "1.0"
    PROTOCOL = "cli"

    CAPABILITIES = (
        "live-status",
        "check-sync",
        "config-backup",
        "interface-list",
    )
    # Note: FortiGate auto-saves on commit so no "rollback" via write memory,
    # but also lacks native config rollback — snapshot restore is the fallback.

    # ── Netmiko ───────────────────────────────────────────────────────────
    NETMIKO_DEVICE_TYPE = "fortinet"

    # ── Config commands ───────────────────────────────────────────────────
    COMMANDS = {
        "config_backup": [
            "show full-configuration",
        ],
    }

    # ── Live-status (operational) commands ────────────────────────────────
    LIVE_STATUS_COMMANDS = {
        "status":       ["get system status"],
        "interfaces":   ["get system interface"],
        "routes":       ["get router info routing-table all"],
        "arp":          ["get system arp"],
        "sessions":     ["get system session list"],
        "performance":  ["get system performance status"],
        "ha":           ["get system ha status"],
        "vpn_ipsec":    ["get vpn ipsec tunnel summary"],
        "firewall":     ["get firewall policy"],
        "users":        ["get user local"],
        "logs":         ["execute log filter category event", "execute log display"],
    }

    # ── Methods ───────────────────────────────────────────────────────────

    def get_connection_params(self, host, username, password, port=22, timeout=30) -> dict:
        params = super().get_connection_params(host, username, password, port, timeout)
        # FortiGate requires legacy KEX algorithms on older firmware
        params["disabled_algorithms"] = {"kex": []}
        return params

    def test_command(self) -> str:
        return "get system status"

    def save_config_command(self) -> Optional[str]:
        # FortiGate auto-saves on commit — no explicit save command needed
        return None

    def parse_version(self, raw_output: str) -> str:
        for line in raw_output.splitlines():
            if "Version:" in line or "Fortigate" in line.lower() or "FortiOS" in line:
                return line.strip()
        return raw_output.strip().splitlines()[0] if raw_output.strip() else "Connected"

    def interfaces_command(self) -> str:
        return "get system interface"

    def normalize_for_diff(self, config: str) -> str:
        """Strip volatile auto-generated lines before diffing.

        FortiOS re-encrypts ENC passwords, SAE passwords, and SSL certificates
        on every config export. These lines are meaningless for sync checks.
        """
        out = []
        skip_block = False  # True while inside a multi-line key/cert value
        for line in config.splitlines():
            stripped = line.strip()
            # Start of a multi-line private-key or certificate block
            if re.match(r'^\s*set (private-key|certificate) "', line, re.IGNORECASE):
                skip_block = True
                continue
            # End of multi-line block (closing quote on its own line)
            if skip_block:
                if stripped == '"':
                    skip_block = False
                continue
            if _VOLATILE.match(line):
                continue
            out.append(line)
        return "\n".join(out)

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
