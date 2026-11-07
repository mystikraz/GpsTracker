-- Review and run this manually on the Neon staging database.
-- Replace every placeholder through a secret manager or an interactive psql
-- session. Do not commit real passwords or database URLs.
-- Generate a URL-safe hex password with: openssl rand -hex 24

BEGIN;

CREATE ROLE fleet_api
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    INHERIT
    PASSWORD 'REPLACE_WITH_SECRET_FROM_SECRET_MANAGER';

CREATE ROLE fleet_ingest
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    INHERIT
    PASSWORD 'REPLACE_WITH_SECRET_FROM_SECRET_MANAGER';

CREATE ROLE fleet_worker
    LOGIN
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION
    NOBYPASSRLS
    INHERIT
    PASSWORD 'REPLACE_WITH_SECRET_FROM_SECRET_MANAGER';

-- Run this statement separately with the actual database name.
-- GRANT CONNECT ON DATABASE "REPLACE_WITH_DATABASE_NAME"
--     TO fleet_api, fleet_ingest, fleet_worker;

GRANT USAGE ON SCHEMA public TO fleet_api, fleet_ingest, fleet_worker;

-- The worker must never create or drop objects directly in the schema.
REVOKE CREATE ON SCHEMA public FROM fleet_api, fleet_ingest, fleet_worker;

-- Run the following as the migration/database owner after migration 0004.
-- The owner-only functions create and drop monthly partitions, apply FORCE RLS,
-- and are the only partition DDL path available to fleet_worker.
-- GRANT EXECUTE ON FUNCTION fleet_create_position_partition(date, date)
--     TO fleet_worker;
-- GRANT EXECUTE ON FUNCTION fleet_drop_position_partition(text)
--     TO fleet_worker;

-- Replace the role name with the actual migration owner. These defaults prevent
-- newly created partition tables from receiving runtime table privileges by
-- accident. The migration function still applies RLS explicitly because RLS
-- policies are not default privileges.
-- ALTER DEFAULT PRIVILEGES FOR ROLE "REPLACE_WITH_MIGRATION_OWNER_ROLE"
--     IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC;
-- ALTER DEFAULT PRIVILEGES FOR ROLE "REPLACE_WITH_MIGRATION_OWNER_ROLE"
--     IN SCHEMA public REVOKE ALL ON TABLES FROM fleet_api, fleet_ingest, fleet_worker;

-- The SECURITY DEFINER functions are owned by the role that runs migration
-- 0004. Verify that owner is the migration/owner role, not a runtime role:
-- SELECT p.proname, pg_get_userbyid(p.proowner) AS owner
-- FROM pg_proc AS p
-- JOIN pg_namespace AS n ON n.oid = p.pronamespace
-- WHERE n.nspname = 'public'
--   AND p.proname IN ('fleet_create_position_partition', 'fleet_drop_position_partition');

COMMIT;

-- After migration 0004, grant only the required table/sequence privileges.
-- Runtime roles must never own the tables and must never receive BYPASSRLS.

-- API runtime privileges. RLS supplies tenant filtering; these grants do not
-- permit bypassing RLS or direct partition DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON organizations, vehicles, devices,
    device_vehicle_assignments, organization_memberships,
    organization_invitations, user_groups, vehicle_group_memberships,
    membership_group_scopes, sessions, password_tokens, reauthentications
    TO fleet_api;
GRANT SELECT, INSERT, UPDATE ON users TO fleet_api;
GRANT SELECT ON positions TO fleet_api;
GRANT INSERT, SELECT ON audit_events TO fleet_api;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO fleet_api;
GRANT EXECUTE ON FUNCTION fleet_delete_organization_data(uuid) TO fleet_api;

-- Ingestion discovers devices/assignments and inserts telemetry only.
GRANT SELECT ON devices, device_vehicle_assignments TO fleet_ingest;
GRANT INSERT ON raw_messages, positions, outbox_events TO fleet_ingest;
-- INSERT ... RETURNING needs column-level SELECT only for generated IDs.
GRANT SELECT (id) ON raw_messages, positions TO fleet_ingest;
GRANT USAGE, SELECT ON SEQUENCE raw_messages_id_seq, positions_id_seq,
    outbox_events_id_seq TO fleet_ingest;
GRANT EXECUTE ON FUNCTION fleet_create_position_partition(date, date)
    TO fleet_worker;
GRANT EXECUTE ON FUNCTION fleet_drop_position_partition(text)
    TO fleet_worker;

-- Worker reads retention settings and deletes expired rows across tenants.
GRANT SELECT ON organizations, raw_messages, positions, outbox_events
    TO fleet_worker;
GRANT DELETE ON raw_messages, positions, outbox_events TO fleet_worker;
GRANT SELECT ON positions_default TO fleet_worker;

SELECT
    rolname,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolbypassrls
FROM pg_roles
WHERE rolname IN ('fleet_api', 'fleet_ingest', 'fleet_worker');
