"""
sync.py - Sync engine: check-sync and sync operations.

check-sync:
  Fetches the live config from the device, diffs it against the latest
  stored snapshot, and reports 'in-sync' or 'out-of-sync'.

sync:
  Fetches the live config, saves a new snapshot, and marks the device
  as 'synced' in the history log.
"""

import difflib
from datetime import datetime

import db
import connector


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize(config: str) -> list[str]:
    """Strip blank lines and trailing whitespace for a cleaner diff."""
    lines = []
    for line in config.splitlines():
        stripped = line.rstrip()
        if stripped:
            lines.append(stripped + "\n")
    return lines


def _unified_diff(old: str, new: str, device_name: str) -> str:
    old_lines = _normalize(old)
    new_lines = _normalize(new)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"{device_name} (stored)",
        tofile=f"{device_name} (live)",
        lineterm="",
    )
    return "\n".join(diff)


# ── Core operations ───────────────────────────────────────────────────────────

def check_sync(device_name: str) -> dict:
    """
    Compare the stored config snapshot against the live device config.

    Returns a dict with keys:
      status   : 'in-sync' | 'out-of-sync' | 'no-snapshot' | 'error'
      diff     : unified diff string (empty if in-sync or no-snapshot)
      message  : human-readable summary
    """
    device = db.get_device(device_name)
    if not device:
        return {"status": "error", "diff": "", "message": f"Device '{device_name}' not found"}

    snapshot = db.get_latest_snapshot(device_name)
    if not snapshot:
        return {
            "status": "no-snapshot",
            "diff": "",
            "message": "No stored snapshot — run 'config fetch' first",
        }

    try:
        live_config = connector.fetch_config(device)
    except Exception as exc:
        detail = str(exc)
        db.log_sync(device_name, "check-sync", "error", detail)
        return {"status": "error", "diff": "", "message": detail}

    diff = _unified_diff(snapshot["config"], live_config, device_name)

    if diff:
        status = "out-of-sync"
        message = "Configuration differs from stored snapshot"
    else:
        status = "in-sync"
        message = "Device is in sync with stored snapshot"

    db.log_sync(device_name, "check-sync", status, diff[:2000] if diff else "")
    return {"status": status, "diff": diff, "message": message}


def sync_device(device_name: str) -> dict:
    """
    Fetch the live config, save it as a new snapshot, log 'synced'.

    Returns a dict with keys:
      status  : 'synced' | 'error'
      bytes   : config length in bytes
      message : human-readable summary
    """
    device = db.get_device(device_name)
    if not device:
        return {"status": "error", "bytes": 0, "message": f"Device '{device_name}' not found"}

    try:
        live_config = connector.fetch_config(device)
    except Exception as exc:
        detail = str(exc)
        db.log_sync(device_name, "sync", "error", detail)
        return {"status": "error", "bytes": 0, "message": detail}

    db.save_snapshot(device_name, live_config)
    db.log_sync(device_name, "sync", "synced", f"Saved {len(live_config)} bytes")
    return {
        "status": "synced",
        "bytes": len(live_config),
        "message": f"Snapshot saved ({len(live_config):,} bytes)",
    }


def fetch_config(device_name: str) -> dict:
    """
    Download config and store as a new snapshot (alias for sync_device,
    used by the 'config fetch' command with no prior-snapshot dependency).
    """
    return sync_device(device_name)


# ── Bulk helpers ──────────────────────────────────────────────────────────────

def check_sync_all() -> list[dict]:
    devices = db.list_devices()
    results = []
    for d in devices:
        result = check_sync(d["name"])
        result["device"] = d["name"]
        results.append(result)
    return results


def sync_all() -> list[dict]:
    devices = db.list_devices()
    results = []
    for d in devices:
        result = sync_device(d["name"])
        result["device"] = d["name"]
        results.append(result)
    return results
