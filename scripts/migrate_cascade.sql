-- migrate_cascade.sql
-- Adds ON DELETE CASCADE / SET NULL to all device_id foreign keys.
-- Run once against the existing database.
--
-- Usage:
--   docker compose exec db psql -U netfabric -d netfabric -f /migrate_cascade.sql
-- (copy this file into the container first, or pipe it via stdin)

BEGIN;

-- config_snapshots → CASCADE
ALTER TABLE config_snapshots
    DROP CONSTRAINT IF EXISTS config_snapshots_device_id_fkey,
    ADD CONSTRAINT config_snapshots_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- sync_history → CASCADE
ALTER TABLE sync_history
    DROP CONSTRAINT IF EXISTS sync_history_device_id_fkey,
    ADD CONSTRAINT sync_history_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- device_locks → CASCADE
ALTER TABLE device_locks
    DROP CONSTRAINT IF EXISTS device_locks_device_id_fkey,
    ADD CONSTRAINT device_locks_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- analysis_results → SET NULL (nullable column)
ALTER TABLE analysis_results
    DROP CONSTRAINT IF EXISTS analysis_results_device_id_fkey,
    ADD CONSTRAINT analysis_results_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL;

-- service_instances → RESTRICT (must delete services before device)
ALTER TABLE service_instances
    DROP CONSTRAINT IF EXISTS service_instances_device_id_fkey,
    ADD CONSTRAINT service_instances_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT;

-- state_declarations → RESTRICT (must delete state declarations before device)
ALTER TABLE state_declarations
    DROP CONSTRAINT IF EXISTS state_declarations_device_id_fkey,
    ADD CONSTRAINT state_declarations_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT;

-- lld_check_history → CASCADE
ALTER TABLE lld_check_history
    DROP CONSTRAINT IF EXISTS lld_check_history_device_id_fkey,
    ADD CONSTRAINT lld_check_history_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE;

-- ipam_addresses → SET NULL (nullable column)
ALTER TABLE ipam_addresses
    DROP CONSTRAINT IF EXISTS ipam_addresses_device_id_fkey,
    ADD CONSTRAINT ipam_addresses_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL;

COMMIT;
