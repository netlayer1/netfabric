"""
migrate.py — Apply pending DB schema changes to PostgreSQL.

Run inside the app container:
    docker exec network-orchestrator-app python3 migrate.py

Or locally (requires DATABASE_URL pointing to an accessible host):
    DATABASE_URL=postgresql://netorch:someStrongPassword@localhost:5432/network_orchestrator python3 migrate.py
"""

import os
import sys
from dotenv import load_dotenv
load_dotenv()

try:
    import psycopg2
except ImportError:
    # Fall back to SQLAlchemy's raw connection if psycopg2 isn't available standalone
    psycopg2 = None

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL not set — check your .env file.")
    sys.exit(1)

# ── Connect ───────────────────────────────────────────────────────────────────

if psycopg2:
    # Strip SQLAlchemy dialect prefix if present (postgresql+psycopg2://...)
    url = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://")
    conn = psycopg2.connect(url)
    conn.autocommit = False
    cur = conn.cursor()

    def execute(sql, label):
        cur.execute(sql)
        print(f"✓ {label}")

    def col_exists(table, column):
        cur.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_name=%s AND column_name=%s",
            (table, column),
        )
        return cur.fetchone() is not None

    def table_exists(table):
        cur.execute(
            "SELECT 1 FROM information_schema.tables WHERE table_name=%s",
            (table,),
        )
        return cur.fetchone() is not None

    def commit():
        conn.commit()

    def close():
        cur.close()
        conn.close()

else:
    from sqlalchemy import create_engine, text
    engine = create_engine(DATABASE_URL)
    _conn = engine.connect()

    def execute(sql, label):
        _conn.execute(text(sql))
        print(f"✓ {label}")

    def col_exists(table, column):
        result = _conn.execute(text(
            f"SELECT 1 FROM information_schema.columns "
            f"WHERE table_name='{table}' AND column_name='{column}'"
        ))
        return result.fetchone() is not None

    def table_exists(table):
        result = _conn.execute(text(
            f"SELECT 1 FROM information_schema.tables WHERE table_name='{table}'"
        ))
        return result.fetchone() is not None

    def commit():
        _conn.commit()

    def close():
        _conn.close()
        engine.dispose()


print(f"Connected to: {DATABASE_URL.split('@')[-1]}\n")  # hide credentials

# ── 1. device_groups table ────────────────────────────────────────────────────
if not table_exists("device_groups"):
    execute("""
        CREATE TABLE device_groups (
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER NOT NULL REFERENCES users(id),
            name        TEXT    NOT NULL,
            description TEXT    DEFAULT '',
            created_at  TIMESTAMP DEFAULT NOW()
        )
    """, "device_groups table created")
else:
    print("✓ device_groups table already exists")

# ── 2. devices.group_id column ────────────────────────────────────────────────
if not col_exists("devices", "group_id"):
    execute("ALTER TABLE devices ADD COLUMN group_id INTEGER REFERENCES device_groups(id)",
            "Added devices.group_id column")
else:
    print("✓ devices.group_id already exists")

# ── 3. device_locks table ─────────────────────────────────────────────────────
if not table_exists("device_locks"):
    execute("""
        CREATE TABLE device_locks (
            id             SERIAL PRIMARY KEY,
            device_id      INTEGER NOT NULL UNIQUE REFERENCES devices(id),
            user_id        INTEGER NOT NULL REFERENCES users(id),
            transaction_id TEXT    NOT NULL,
            locked_at      TIMESTAMP DEFAULT NOW(),
            expires_at     TIMESTAMP NOT NULL
        )
    """, "device_locks table created")
    execute("CREATE INDEX IF NOT EXISTS ix_device_locks_device_id ON device_locks(device_id)",
            "Index on device_locks.device_id")
else:
    print("✓ device_locks table already exists")

# ── 4. sync_history.transaction_id column ────────────────────────────────────
if not col_exists("sync_history", "transaction_id"):
    execute("ALTER TABLE sync_history ADD COLUMN transaction_id TEXT",
            "Added sync_history.transaction_id column")
    execute("CREATE INDEX IF NOT EXISTS ix_sync_history_transaction_id ON sync_history(transaction_id)",
            "Index on sync_history.transaction_id")
else:
    print("✓ sync_history.transaction_id already exists")

commit()
close()
print("\nMigration complete.")
