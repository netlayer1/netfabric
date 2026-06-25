-- migrate_unique_devices.sql
-- Adds unique constraints on (user_id, name) and (user_id, host) for devices.
-- Run once against existing DB.
--
-- Usage:
--   docker compose exec -T db psql -U netfabric -d netfabric < scripts/migrate_unique_devices.sql

BEGIN;

-- Remove duplicates first (keep lowest ID)
DELETE FROM devices WHERE id NOT IN (
    SELECT MIN(id) FROM devices GROUP BY user_id, name
);
DELETE FROM devices WHERE id NOT IN (
    SELECT MIN(id) FROM devices GROUP BY user_id, host
);

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS uq_device_name_per_user,
    ADD CONSTRAINT uq_device_name_per_user UNIQUE (user_id, name);

ALTER TABLE devices
    DROP CONSTRAINT IF EXISTS uq_device_host_per_user,
    ADD CONSTRAINT uq_device_host_per_user UNIQUE (user_id, host);

COMMIT;
