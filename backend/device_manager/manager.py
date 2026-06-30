"""
device_manager/manager.py — NetFabric Device Manager

The Device Manager owns all operations that touch the device database and
live device state. It is the only layer that talks to device_connector
directly — main.py endpoints delegate here rather than calling
device_connector inline.

Responsibilities:
  - Device CRUD helpers (get, ownership check)
  - Credential resolution (authgroup → plaintext)
  - Config fetch / sync-from
  - Config snapshot storage
  - Interface list fetch
  - Device lock / unlock (exclusive write transactions)
  - Connectivity test

Architecture:
  main.py (thin API)
    └─ DeviceManager        ← this module
         └─ device_connector ← SSH/Netmiko transport
         └─ ND drivers       ← normalize_for_diff, parse_interface_names

Not instantiated per-request — use the module-level singleton `device_manager`.
"""

import logging
import uuid
from datetime import datetime, timedelta
from typing import Optional, TYPE_CHECKING

from fastapi import HTTPException
from sqlalchemy.orm import Session

import backend.device_connector as device_connector

if TYPE_CHECKING:
    from backend.models import Device, User

_log = logging.getLogger(__name__)

LOCK_TIMEOUT_MINUTES = 10


class DeviceManagerError(Exception):
    """Raised when the Device Manager cannot fulfill a request."""


class DeviceManager:
    """
    Single entry point for all device-level operations.

    Usage (from FastAPI endpoints):
        dm = DeviceManager()
        device  = dm.get_owned(device_id, user_id, db)
        config  = dm.fetch_config(device, db)
        txn_id  = dm.acquire_lock(device_id, user_id, db)
        ifaces  = dm.fetch_interfaces(device, db)
    """

    # ── Device lookup ─────────────────────────────────────────────────────

    def get_owned(self, device_id: int, user_id: int, db: Session):
        """Return device owned by user, or raise 404."""
        from backend.models import Device
        device = db.query(Device).filter(
            Device.id == device_id,
            Device.user_id == user_id,
        ).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    # ── Credential resolution ─────────────────────────────────────────────

    def resolve_credentials(self, device, db: Session) -> tuple[str, str]:
        """
        Return (username, plaintext_password) for a device.

        Resolution order (mirrors NSO authgroup behaviour):
          1. device.authgroup_id  → fetch from Authgroup row
          2. device.authgroup     → look up by name for this user
          3. device.username / device.encrypted_password  (direct)
        """
        from backend.models import Authgroup
        from backend.main import decrypt_password  # Fernet helper lives in main for now

        # 1 / 2 — authgroup lookup
        ag = None
        if getattr(device, 'authgroup_id', None):
            ag = db.query(Authgroup).filter(Authgroup.id == device.authgroup_id).first()
        elif getattr(device, 'authgroup', None):
            ag = db.query(Authgroup).filter(
                Authgroup.name == device.authgroup,
                Authgroup.user_id == device.user_id,
            ).first()

        if ag:
            return ag.username, decrypt_password(ag.password)

        # 3 — device-level credentials
        return device.username or '', decrypt_password(device.encrypted_password or '')

    # ── Config fetch ──────────────────────────────────────────────────────

    def fetch_config(self, device, db: Session) -> str:
        """
        SSH to the device and return the running configuration as a string.
        Strips the "### …" header added by device_connector.
        """
        username, password = self.resolve_credentials(device, db)
        _log.info("[DM] fetch_config: device=%r host=%s", device.name, device.host)
        result = device_connector.pull_device_data(
            host=device.host,
            username=username,
            password=password,
            device_type=device.device_type,
            port=device.port,
            analysis_type="config_backup",
        )
        if not result["success"]:
            raise HTTPException(status_code=502, detail=result["error"])
        config = result["data"]
        if config.startswith("### "):
            config = "\n".join(config.split("\n")[1:]).strip()
        return config

    # ── Interface fetch ───────────────────────────────────────────────────

    def fetch_interfaces(self, device, db: Session) -> list[str]:
        """Return list of interface names from the live device."""
        from backend.drivers import get_driver
        username, password = self.resolve_credentials(device, db)
        driver = get_driver(device.ned_id or '')
        _log.info("[DM] fetch_interfaces: device=%r", device.name)
        result = device_connector.pull_device_data(
            host=device.host,
            username=username,
            password=password,
            device_type=device.device_type,
            port=device.port,
            analysis_type="interface_list",
        )
        if not result["success"]:
            return []
        return driver.parse_interface_names(result["data"])

    # ── Connectivity test ─────────────────────────────────────────────────

    def test_connectivity(self, device, db: Session) -> dict:
        """Return {success, version, latency_ms} for a device."""
        username, password = self.resolve_credentials(device, db)
        _log.info("[DM] test_connectivity: device=%r host=%s", device.name, device.host)
        return device_connector.test_connectivity(
            host=device.host,
            username=username,
            password=password,
            device_type=device.device_type,
            port=device.port,
        )

    # ── Live status ───────────────────────────────────────────────────────

    def live_status(self, device, command_key: str, db: Session) -> dict:
        """
        Run a named live-status command on the device and return raw output.

        command_key maps to the ND's LIVE_STATUS_COMMANDS dict, e.g.:
          "routes", "arp", "interfaces", "sessions", "vpn_ipsec", "performance"

        Returns {success, output, command_key, commands_run}.
        The ND driver owns the command list — adding a new live-status view
        only requires updating the driver's LIVE_STATUS_COMMANDS dict.
        """
        from backend.drivers import get_driver
        driver   = get_driver(device.ned_id or '')
        commands = driver.LIVE_STATUS_COMMANDS.get(command_key)
        if not commands:
            raise HTTPException(
                status_code=404,
                detail=f"Live-status command '{command_key}' not supported by ND '{driver.NED_ID}'. "
                       f"Available: {list(driver.LIVE_STATUS_COMMANDS.keys())}",
            )

        username, password = self.resolve_credentials(device, db)
        _log.info("[DM] live_status: device=%r key=%r commands=%s", device.name, command_key, commands)

        results = []
        for cmd in commands:
            result = device_connector.pull_device_data(
                host=device.host,
                username=username,
                password=password,
                device_type=device.device_type,
                port=device.port,
                analysis_type="live_status",
                command=cmd,
            )
            results.append({"command": cmd, "output": result.get("data", ""), "success": result.get("success", False)})

        combined_output = "\n\n".join(
            f"### {r['command']}\n{r['output']}" for r in results
        )
        return {
            "success":      all(r["success"] for r in results),
            "output":       combined_output,
            "command_key":  command_key,
            "commands_run": [r["command"] for r in results],
        }

    # ── Lock management ───────────────────────────────────────────────────

    def acquire_lock(self, device_id: int, user_id: int, db: Session) -> str:
        """
        Acquire an exclusive write lock on a device.
        Returns a new transaction_id on success.
        Raises HTTP 409 if the device is already locked.
        Expired locks are cleaned up automatically.
        """
        from backend.models import DeviceLock, User
        now = datetime.utcnow()

        # Clean up stale locks
        db.query(DeviceLock).filter(DeviceLock.expires_at < now).delete(synchronize_session=False)
        db.commit()

        existing = db.query(DeviceLock).filter(DeviceLock.device_id == device_id).first()
        if existing:
            owner = db.query(User).filter(User.id == existing.user_id).first()
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "Device is locked by another engineer",
                    "locked_by": owner.email if owner else "unknown",
                    "transaction_id": existing.transaction_id,
                    "locked_at": existing.locked_at.isoformat(),
                    "expires_at": existing.expires_at.isoformat(),
                },
            )

        txn_id = str(uuid.uuid4())
        lock = DeviceLock(
            device_id=device_id,
            user_id=user_id,
            transaction_id=txn_id,
            expires_at=now + timedelta(minutes=LOCK_TIMEOUT_MINUTES),
        )
        db.add(lock)
        db.commit()
        _log.info("[DM] lock acquired: device_id=%d txn=%s", device_id, txn_id)
        return txn_id

    def release_lock(self, device_id: int, transaction_id: str, db: Session) -> None:
        """Release a device lock by transaction_id."""
        from backend.models import DeviceLock
        db.query(DeviceLock).filter(
            DeviceLock.device_id == device_id,
            DeviceLock.transaction_id == transaction_id,
        ).delete(synchronize_session=False)
        db.commit()
        _log.info("[DM] lock released: device_id=%d txn=%s", device_id, transaction_id)

    # ── Sync-from ─────────────────────────────────────────────────────────

    def sync_from(self, device, db: Session) -> dict:
        """
        Pull running config from device, store as snapshot, update sync status.
        Returns {config, snapshot_id, lines}.
        """
        from backend.models import ConfigSnapshot, SyncHistory
        config = self.fetch_config(device, db)
        snap = ConfigSnapshot(device_id=device.id, config=config)
        db.add(snap)
        db.add(SyncHistory(
            device_id=device.id,
            user_id=device.user_id,
            action="sync-from",
            detail=f"{len(config)} bytes",
        ))
        device.last_seen = datetime.utcnow()
        db.commit()
        db.refresh(snap)
        _log.info("[DM] sync_from: device=%r snapshot_id=%d lines=%d",
                  device.name, snap.id, len(config.splitlines()))
        return {"config": config, "snapshot_id": snap.id, "lines": len(config.splitlines())}


# Module-level singleton
device_manager = DeviceManager()
