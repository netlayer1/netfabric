"""
device_connector.py — SSH device connectivity via Netmiko

Vendor-specific logic lives in backend/drivers/.
This module is vendor-agnostic — it calls the driver interface only.
"""

import logging
from datetime import datetime
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import paramiko

from backend.drivers import get_driver

# Re-enable SHA1 KEX algorithms globally for legacy devices (e.g. older FortiGate firmware)
_kex = list(paramiko.Transport._preferred_kex)
for _algo in ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]:
    if _algo not in _kex:
        _kex.append(_algo)
paramiko.Transport._preferred_kex = tuple(_kex)

logger = logging.getLogger(__name__)


def pull_device_data(
    host: str,
    username: str,
    password: str,
    device_type: str = "cisco_ios",
    port: int = 22,
    analysis_type: str = "status",
    timeout: int = 10,
) -> dict:
    """
    SSH into a device and run read-only show commands.

    Returns:
        {
            "success": bool,
            "host": str,
            "data": str,
            "error": str | None,
            "timestamp": str,
        }
    """
    driver = get_driver(device_type)
    commands = driver.get_commands(analysis_type)
    params = driver.get_connection_params(host, username, password, port, timeout)
    timestamp = datetime.utcnow().isoformat()

    try:
        logger.info(f"Connecting to {host}:{port} ({device_type})")
        with ConnectHandler(**params) as conn:
            output_parts = []
            for cmd in commands:
                try:
                    result = conn.send_command(cmd, read_timeout=30)
                    output_parts.append(f"### {cmd}\n{result}\n")
                    logger.debug(f"[{host}] '{cmd}' — {len(result)} chars")
                except Exception as cmd_err:
                    output_parts.append(f"### {cmd}\nERROR: {cmd_err}\n")

        return {
            "success": True,
            "host": host,
            "data": "\n".join(output_parts),
            "error": None,
            "timestamp": timestamp,
        }

    except NetmikoAuthenticationException:
        msg = f"Authentication failed for {username}@{host}"
        logger.error(msg)
        return {"success": False, "host": host, "data": "", "error": msg, "timestamp": timestamp}

    except NetmikoTimeoutException:
        msg = f"Connection timed out to {host}:{port}"
        logger.error(msg)
        return {"success": False, "host": host, "data": "", "error": msg, "timestamp": timestamp}

    except Exception as e:
        msg = f"Unexpected error connecting to {host}: {e}"
        logger.error(msg)
        return {"success": False, "host": host, "data": "", "error": msg, "timestamp": timestamp}


def apply_config_set(
    host: str,
    username: str,
    password: str,
    config_lines: list,
    device_type: str = "cisco_ios",
    port: int = 22,
    timeout: int = 10,
) -> dict:
    """
    Push a list of config lines to the device.
    Saves running config to startup config if the driver provides a save command.
    """
    driver = get_driver(device_type)
    params = driver.get_connection_params(host, username, password, port, timeout)
    timestamp = datetime.utcnow().isoformat()
    logger.info(f"Applying {len(config_lines)} config lines to {host}:{port}")

    try:
        with ConnectHandler(**params) as conn:
            output = conn.send_config_set(
                config_lines,
                enter_config_mode=True,
                exit_config_mode=True,
                read_timeout=60,
            )
            save_cmd = driver.save_config_command()
            if save_cmd:
                try:
                    save_out = conn.send_command(save_cmd, read_timeout=30)
                    output += f"\n{save_out}"
                except Exception as save_err:
                    logger.warning(f"{save_cmd} failed: {save_err}")

        return {
            "success": True,
            "lines_sent": len(config_lines),
            "output": output,
            "error": None,
            "timestamp": timestamp,
        }

    except NetmikoAuthenticationException:
        msg = f"Authentication failed for {username}@{host}"
        logger.error(msg)
        return {"success": False, "lines_sent": 0, "output": "", "error": msg}

    except NetmikoTimeoutException:
        msg = f"Timeout connecting to {host}:{port}"
        logger.error(msg)
        return {"success": False, "lines_sent": 0, "output": "", "error": msg}

    except Exception as e:
        msg = f"Error applying config to {host}: {e}"
        logger.error(msg)
        return {"success": False, "lines_sent": 0, "output": "", "error": msg}


def test_connectivity(
    host: str,
    username: str,
    password: str,
    device_type: str = "cisco_ios",
    port: int = 22,
) -> dict:
    """
    Quick connectivity test — runs the driver's test command.
    """
    driver = get_driver(device_type)
    params = driver.get_connection_params(host, username, password, port, timeout=15)

    try:
        with ConnectHandler(**params) as conn:
            raw = conn.send_command(driver.test_command(), read_timeout=15)
            return {"success": True, "message": driver.parse_version(raw)}

    except NetmikoAuthenticationException:
        return {"success": False, "message": "Authentication failed — check username/password"}

    except NetmikoTimeoutException:
        return {"success": False, "message": f"Timeout — check host {host}:{port} and firewall"}

    except Exception as e:
        return {"success": False, "message": str(e)}
