-- Reset the identity database to a clean state, then restart the identity
-- service: ent auto-migrate recreates all tables (branches, roles,
-- role_permissions, the new tenant_users columns, ...) and SeedSystemRoles
-- reseeds the system roles.
--
-- Safe ONLY when there is no data worth keeping (test/empty DB). It drops every
-- per-tenant schema plus the shared identity tables.
--
-- Run against the identity database, e.g.:
--   psql "$DATABASE_URL" -f scripts/reset-db.sql
--
-- After this completes, (re)start the identity service so it re-migrates + seeds.

-- 1. Drop every per-tenant schema (tenant_<slug>) created by the registration saga.
DO $$
DECLARE
    s text;
BEGIN
    FOR s IN
        SELECT schema_name
        FROM information_schema.schemata
        WHERE schema_name LIKE 'tenant\_%'
    LOOP
        EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', s);
    END LOOP;
END $$;

-- 2. Drop the shared (public-schema) identity tables. Order is handled by CASCADE.
DROP TABLE IF EXISTS
    role_permissions,
    roles,
    refresh_tokens,
    tenant_users,
    branches,
    plugin_installs,
    plugin_migration_histories,
    user_profiles,
    users,
    tenants
CASCADE;
