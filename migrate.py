"""
migrate.py — Run this once to apply pending DB schema changes.
Usage:  python3 migrate.py
"""
import sqlite3, os, pathlib

DB_PATHS = [
    pathlib.Path(__file__).parent / "data" / "network_orchestrator.db",
    pathlib.Path(__file__).parent / "network_orchestrator.db",
]

db_path = next((p for p in DB_PATHS if p.exists()), None)
if db_path is None:
    print("ERROR: database file not found — start the server at least once first.")
    raise SystemExit(1)

print(f"Using database: {db_path}")
conn = sqlite3.connect(db_path)

# ── 1. device_groups table ────────────────────────────────────────────────────
conn.execute("""
    CREATE TABLE IF NOT EXISTS device_groups (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id     INTEGER NOT NULL REFERENCES users(id),
        name        TEXT    NOT NULL,
        description TEXT    DEFAULT '',
        created_at  TEXT    DEFAULT (datetime('now'))
    )
""")
print("✓ device_groups table ready")

# ── 2. devices.group_id column ────────────────────────────────────────────────
existing_cols = [r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
if "group_id" not in existing_cols:
    conn.execute("ALTER TABLE devices ADD COLUMN group_id INTEGER REFERENCES device_groups(id)")
    print("✓ Added devices.group_id column")
else:
    print("✓ devices.group_id already exists")

conn.commit()
conn.close()
print("\nMigration complete.")
