# ApiCoreX Identity Plugin

The authentication and tenant-management plugin for [ApiCoreX](../apicorex). It
is a normal ApiCoreX plugin (no SDK — pure Gin) that owns its PostgreSQL
database and issues the JWTs that Core verifies.

Responsibilities:
- **Tenant registration** — a compensating saga creates the tenant, its dedicated
  Postgres schema, the owner account, and runs installed plugins' migrations.
- **Authentication** — one global credential per email; a user can belong to
  many tenants and picks one at login (`409` chooser when ambiguous).
- **Tokens** — HS256 access tokens (15 min) + rotating refresh tokens (7 days);
  optional Redis-backed logout (immediate revocation).
- **Plugin management** — install/uninstall plugins per tenant, running their
  migrations in the tenant schema. Uninstall can keep or drop tenant data.

> Core only *verifies* tokens. Issuing, users, and tenant state live here so Core
> stays stateless. To swap in a third-party identity provider (Auth0, Google,
> etc.), replace this plugin — Core is unaffected.

---

## Database model (schema-per-tenant, auth-decoupled)

Credentials are **global** (one account can own/join many tenants); personally
identifiable info (PII) is **tenant-scoped** and isolated per schema.

```
PostgreSQL
├── public                         (shared)
│   ├── users                      global credentials (email, password hash)
│   ├── tenant_users               user ↔ tenant membership + role (M2M)
│   ├── tenants                    tenant registry (slug, schema_name, status)
│   ├── refresh_tokens
│   ├── plugin_installs
│   └── plugin_migration_histories
└── tenant_{slug}                  (per tenant — created on registration)
    ├── user_profiles              tenant-scoped PII (full name, phone, …)
    └── [plugin tables, via migrations — e.g. sync_records]
```

Per-tenant schema isolation uses EntGo with a `search_path` connector trick — no
Atlas CLI needed. A user logging into a tenant they don't belong to is rejected;
a user in multiple tenants gets a `409` chooser until they pass a `slug`.

**Slug rules:** a tenant slug becomes part of the schema name (`tenant_<slug>`),
so it must be a safe identifier — 3–32 chars, lowercase, starting with a letter,
containing only letters, digits, and underscores. Invalid slugs are rejected at
registration with `400`.

---

## Quickstart

Requires Go 1.25+, PostgreSQL, and a running [Core](../apicorex).

```bash
DATABASE_URL=postgres://user:pass@host:5432/apicorex?sslmode=disable \
JWT_SECRET=dev-secret \
PLUGIN_API_KEY=dev-key \
CORE_URL=http://localhost:8080 \
PLUGIN_ADDR=:50051 \
PLUGIN_BASE_URL=http://localhost:50051 \
go run ./cmd/identity
```

On boot it migrates the shared (public) tables, registers with Core, and starts
serving. See the root [README](../apicorex/README.md) for the end-to-end flow.

### With Docker

This repo ships a `Dockerfile` and a standalone `docker-compose.yml` (plugin +
its Postgres). It still needs a running Core to register with — point `CORE_URL`
at it (the compose file defaults to `http://host.docker.internal:8080`).

```bash
docker compose up --build
```

For an all-in-one stack (Core + Postgres + Redis + every plugin) use the
compose file in the [Core repo](../apicorex) instead.

---

## Configuration

| Var | Required | Purpose |
|-----|----------|---------|
| `DATABASE_URL` | yes | PostgreSQL DSN (never hardcoded) |
| `JWT_SECRET` | yes | HS256 secret to sign access tokens (shared with Core) |
| `PLUGIN_API_KEY` | yes | Key presented to Core on register |
| `CORE_URL` | yes | Core's HTTP base URL |
| `PLUGIN_ADDR` | `:50051` | Local bind address |
| `PLUGIN_BASE_URL` | derived | URL Core dials back (set in docker/k8s) |
| `REDIS_URL` | no | Enables immediate logout (token denylist) |

---

## Routes

| Method | Path | Public | Description |
|--------|------|--------|-------------|
| POST | `/auth/register` | yes | Provision a tenant + owner |
| POST | `/auth/login` | yes | Returns access + refresh token |
| POST | `/auth/refresh` | yes | Rotate tokens |
| POST | `/auth/logout` | no | Revoke refresh (+ access token if Redis) |
| GET | `/me` | no | Current user from injected headers |
| POST | `/plugins/install` | no | Install a plugin for **your own** tenant |
| POST | `/plugins/uninstall` | no | Uninstall (`drop_data` keeps or drops tables) |

> Install/uninstall require the body's `tenant_id` to match the caller's JWT
> tenant — you cannot manage another tenant's plugins (`403` otherwise). New
> tenants automatically get every currently-installed plugin's tables during
> registration.

---

## Project structure

```
cmd/identity/      entrypoint + route handlers
ent/               EntGo schema + generated code (run `go generate ./ent/...`)
internal/
  auth/            login, JWT issuer, refresh, logout denylist
  plugin/          self-contained ApiCoreX plugin runtime (manifest, register, headers)
  pluginmgr/       per-tenant plugin install/uninstall + migration orchestration
  migrator/        runs plugin migrations in tenant schemas
  tenant/          registration saga + per-tenant schema migration
  tenantclient/    EntGo client scoped to a tenant schema
```
