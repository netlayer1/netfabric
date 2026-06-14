"""
db.py - SQLite database layer for NSO-like network config manager.

Tables:
  devices       - device inventory
  config_snapshots - stored configs with timestamp
  sync_history  - per-device sync/check-sync log
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.environ.get(
    "NM_DB_PATH",
    os.path.join(os.path.expanduser("~"), ".network_orchestrator.db"),
)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            host        TEXT NOT NULL,
            port        INTEGER DEFAULT 22,
            device_type TEXT NOT NULL DEFAULT 'cisco_ios',
            username    TEXT NOT NULL,
            password    TEXT NOT NULL,
            secret      TEXT DEFAULT '',
            created_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS config_snapshots (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            config      TEXT NOT NULL,
            fetched_at  TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (device_name) REFERENCES devices(name) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sync_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            device_name TEXT NOT NULL,
            action      TEXT NOT NULL,   -- 'check-sync' | 'sync'
            status      TEXT NOT NULL,   -- 'in-sync' | 'out-of-sync' | 'synced' | 'error'
            detail      TEXT DEFAULT '',
            timestamp   TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (device_name) REFERENCES devices(name) ON DELETE CASCADE
        );
        """)


# ── Device CRUD ─────────────────────────────────────────────────────────────

def add_device(name, host, port, device_type, username, password, secret=""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO devices (name,host,port,device_type,username,password,secret) "
            "VALUES (?,?,?,?,?,?,?)",
            (name, host, port, device_type, username, password, secret),
        )


def remove_device(name):
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM devices WHERE name=?", (name,))
        return cur.rowcount > 0


def get_device(name):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM devices WHERE name=?", (name,)).fetchone()


def list_devices():
    with get_conn() as conn:
        return conn.execute("SELECT * FROM devices ORDER BY name").fetchall()


# ── Config snapshots ─────────────────────────────────────────────────────────

def save_snapshot(device_name, config):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO config_snapshots (device_name, config) VALUES (?,?)",
            (device_name, config),
        )


def get_latest_snapshot(device_name):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM config_snapshots WHERE device_name=? "
            "ORDER BY fetched_at DESC LIMIT 1",
            (device_name,),
        ).fetchone()


def list_snapshots(device_name, limit=10):
    with get_conn() as conn:
        return conn.execute(
            "SELECT id, device_name, fetched_at, length(config) as bytes "
            "FROM config_snapshots WHERE device_name=? ORDER BY fetched_at DESC LIMIT ?",
            (device_name, limit),
        ).fetchall()


# ── Sync history ─────────────────────────────────────────────────────────────

def log_sync(device_name, action, status, detail=""):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sync_history (device_name,action,status,detail) VALUES (?,?,?,?)",
            (device_name, action, status, detail),
        )


def get_sync_history(device_name, limit=20):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM sync_history WHERE device_name=? ORDER BY timestamp DESC LIMIT ?",
            (device_name, limit),
        ).fetchall()


# Bootstrap on import
init_db()
