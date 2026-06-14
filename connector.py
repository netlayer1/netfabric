"""
connector.py - Netmiko-based SSH device connector.

Supported device types (Netmiko driver strings):
  cisco_ios, cisco_nxos, cisco_iosxr, cisco_iosxe,
  juniper_junos, arista_eos, huawei, linux, etc.
"""

from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException


# Commands used to pull the running config per OS family
_CONFIG_COMMANDS = {
    "cisco_ios":     "show running-config",
    "cisco_iosxe":   "show running-config",
    "cisco_iosxr":   "show running-config",
    "cisco_nxos":    "show running-config",
    "arista_eos":    "show running-config",
    "juniper_junos": "show configuration",
    "huawei":        "display current-configuration",
    "linux":         "cat /etc/network/interfaces",
}

_DEFAULT_CMD = "show running-config"


def _config_command(device_type: str) -> str:
    return _CONFIG_COMMANDS.get(device_type, _DEFAULT_CMD)


def fetch_config(device_row) -> str:
    """
    Connect to a device (sqlite3.Row or dict-like) via SSH and return
    the running configuration as a string.

    Raises:
        ConnectionError   - auth or timeout failures
        RuntimeError      - unexpected Netmiko errors
    """
    params = {
        "device_type": device_row["device_type"],
        "host":        device_row["host"],
        "port":        device_row["port"],
        "username":    device_row["username"],
        "password":    device_row["password"],
        "secret":      device_row["secret"] or "",
        "timeout":     30,
        "session_log": None,
    }

    try:
        with ConnectHandler(**params) as net_connect:
            if params["secret"]:
                net_connect.enable()
            cmd = _config_command(params["device_type"])
            output = net_connect.send_command(cmd, read_timeout=60)
        return output

    except NetmikoAuthenticationException as exc:
        raise ConnectionError(f"Authentication failed for {device_row['host']}: {exc}") from exc
    except NetmikoTimeoutException as exc:
        raise ConnectionError(f"Timeout connecting to {device_row['host']}: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Netmiko error on {device_row['host']}: {exc}") from exc


def test_connectivity(device_row) -> tuple[bool, str]:
    """
    Try to connect and send a no-op command. Returns (success, message).
    """
    try:
        params = {
            "device_type": device_row["device_type"],
            "host":        device_row["host"],
            "port":        device_row["port"],
            "username":    device_row["username"],
            "password":    device_row["password"],
            "secret":      device_row["secret"] or "",
            "timeout":     10,
        }
        with ConnectHandler(**params) as net_connect:
            prompt = net_connect.find_prompt()
        return True, f"Reachable — prompt: {prompt}"
    except Exception as exc:
        return False, str(exc)
