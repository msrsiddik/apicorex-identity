# ApiCoreX Identity Plugin

The authentication and tenant-management plugin for [ApiCoreX](../apicorex). It
is a normal ApiCoreX plugin (no SDK — pure Gin) that owns its PostgreSQL
database and issues the opaque device tokens that Core resolves via
introspection.

Responsibilities:
- **Tenant registration** — a compensating saga creates the tenant, its dedicated
  Postgres schema, the owner account, and runs installed plugins' migrations.
- **Authentication** — one global credential per email; a user can belong to
  many tenants and picks one at login (`409` chooser when ambiguous).
- **Tokens** — opaque device tokens (`zdt_...`, sha256-hashed at rest, no
  expiry, no refresh token). A token stays valid until revoked (logout, or the
  owner is removed/suspended). Core never sees or parses tokens — it hashes
  the bearer and calls this plugin's `POST /internal/introspect` (cached ~30s
  in Core, so this isn't a network hop on every request), which resolves fresh
  tenant/branch/user/role/permissions, so revocation and role changes take
  effect within that window.

  **Why device tokens instead of user-bound JWTs?** The target use case is a
  shared device (e.g. one POS terminal, several drivers/staff clocking in and
  out on it). A plain JWT is bound to whoever logged in and stays locally valid
  until expiry — so a shift change on the same device risks a stale token
  still being usable as the previous user. A device token is bound to the
  *device*, and `X-Acting-User` (PIN-unlock) picks who's currently operating
  it; Identity re-validates the acting user's membership on every introspect
  call, so a removed/suspended user is locked out immediately regardless of
  what the device token itself still shows.
- **Plugin management** — install/uninstall plugins per tenant, running their
  migrations in the tenant schema. Uninstall can keep or drop tenant data.

> Core only *introspects* tokens (it never issues, signs, or parses them).
> Issuing, users, and tenant state live here so Core stays stateless. To swap in
> a third-party identity provider (Auth0, Google, etc.), replace this plugin —
> Core is unaffected.

---

## Database model (schema-per-tenant, auth-decoupled)

Credentials are **global** (one account can own/join many tenants); personally
identifiable info (PII) is **tenant-scoped** and isolated per schema.

```
PostgreSQL
├── public                         (shared)
│   ├── users                      global credentials (email, password hash)
│   ├── tenants                    tenant registry (slug, schema_name, status)
│   ├── branches                   sub-orgs within a tenant (one tenant → many)
│   ├── tenant_users               membership per (user, tenant): role_id + current branch_id
│   ├── roles                      system roles (tenant_id="") + tenant custom roles
│   ├── role_permissions           role → permission ("resource:action", wildcards)
│   ├── device_tokens              opaque token hashes; carry tenant_id + branch_id
│   ├── plugin_installs
│   └── plugin_migration_histories
└── tenant_{slug}                  (per tenant — created on registration)
    ├── user_profiles              tenant-scoped PII (full name, phone, …)
    └── [plugin tables, via migrations — branch-scoped via a branch_id column]
```

Per-tenant schema isolation uses EntGo with a `search_path` connector trick — no
Atlas CLI needed. A user logging into a tenant they don't belong to is rejected;
a user in multiple tenants gets a `409` chooser until they pass a `slug`.

**Branches.** A tenant has one or more branches (a default `main` is created at
registration). A user has exactly **one** membership per tenant — they are
active in exactly one branch at a time, with one role for the whole tenant
(role doesn't change with the branch). Login lands them on their current
branch; `/branches/switch` moves that same membership to a different branch
they're being granted access to and issues a fresh token for it (see
[docs/branch-isolation.md](docs/branch-isolation.md)). Branch-scoped data lives
in the tenant schema with a `branch_id` column; downstream plugins filter on it
via the `plugin.RequireBranch` / `BranchScope` helpers.

**RBAC.** A membership's `role_id` resolves to a role and its flattened
permission set, embedded in the access token (`permissions` claim) on top of a
neutral baseline floor (`user:read`, `branch:read`). System roles
(`owner`/`admin`/`manager`/`member`) are seeded on boot; tenants can manage
custom roles via `/roles`. Permissions are enforced **twice**: Core's gateway
rejects a request whose route declares a permission the caller lacks
(wildcard-aware), and handlers re-check via `plugin.HasPermission` for
defense-in-depth. See [docs/rbac-design.md](docs/rbac-design.md).

**Slug rules:** a tenant slug becomes part of the schema name (`tenant_<slug>`),
so it must be a safe identifier — 3–32 chars, lowercase, starting with a letter,
containing only letters, digits, and underscores. Invalid slugs are rejected at
registration with `400`. The slug is **immutable** once set — it names the schema
and is the login key — so `PATCH /tenant` changes only the display name / plan.

---

## Quickstart

Requires Go 1.25+, PostgreSQL, and a running [Core](../apicorex).

```bash
DATABASE_URL=postgres://user:pass@host:5432/apicorex?sslmode=disable \
PLUGIN_API_KEY=dev-key \
CORE_URL=http://localhost:8080 \
PLUGIN_ADDR=:50051 \
PLUGIN_BASE_URL=http://localhost:50051 \
go run ./cmd/identity
```

On boot it migrates the shared (public) tables, seeds the built-in system roles,
registers with Core, and starts serving. See the root
[README](../apicorex/README.md) for the end-to-end flow.

> **Schema change note:** branches/RBAC added new `NOT NULL` columns to
> `tenant_users` (`branch_id`, `role_id`). On an existing database with data,
> auto-migrate cannot add them in place — start from a clean DB
> (`scripts/reset-db.sql` drops the identity tables + per-tenant schemas) or
> backfill manually.

### With Docker

This repo ships a `Dockerfile` and a standalone `docker-compose.yml` that
connects to the **shared** Postgres started from Core's compose file (host
port `15432`) — start that first:

```bash
cd ../apicorex && docker compose up -d postgres
cd ../apicorex-identity && docker compose up --build
```

It still needs a running Core to register with — point `CORE_URL` at it (the
compose file defaults to `http://host.docker.internal:9999`, matching Core's
compose-stack port). Core and this plugin run as separate compose projects
(separate Docker networks), so container-name URLs don't resolve across them —
`CORE_URL` and `PLUGIN_BASE_URL` both go through the host
(`host.docker.internal`) instead.

Core's own compose file only brings up Core + Postgres (no plugins) — each
plugin repo, including this one, runs its own compose stack against that
shared Postgres.

---

## Configuration

| Var | Required | Purpose |
|-----|----------|---------|
| `DATABASE_URL` | yes | PostgreSQL DSN (never hardcoded) |
| `PLUGIN_API_KEY` | yes | Key presented to Core on register; also required on Core's calls to `/internal/introspect` (shared with Core) |
| `CORE_URL` | yes | Core's HTTP base URL |
| `PLUGIN_ADDR` | `:50051` | Local bind address |
| `PLUGIN_BASE_URL` | derived | URL Core dials back (set in docker/k8s) |
| `PLATFORM_ADMIN_EMAILS` | no | Comma-separated emails to bootstrap as platform admins on boot (only grants; only affects users who have already registered). `is_platform_admin` (a DB column) is the actual source of truth, so it's consistent across every instance — manage it after boot via `/platform-admins`. |
| `GOOGLE_CLIENT_IDS` | no | Comma-separated OAuth client IDs accepted at `POST /auth/google` (password-free login). Unset disables Google login. |

---

## Routes

| Method | Path | Public | Permission | Description |
|--------|------|--------|------------|-------------|
| POST | `/auth/register` | yes | — | Provision a tenant + owner (+ default `main` branch); `slug` optional (auto-generated from `name`), final slug returned |
| GET | `/auth/slug-available` | yes | — | `?slug=` → `{valid, available, reason}` for live slug checks |
| GET | `/auth/slug-suggest` | yes | — | `?name=` (required) → a valid, available slug derived from the name |
| POST | `/auth/login` | yes | — | Returns a device token (lands on the user's current branch) |
| GET | `/auth/config` | yes | — | Public auth config the client needs before login (Google client ID, whether Google login is enabled) |
| POST | `/auth/google` | yes | — | Password-free login with a Google ID token; the matching account must already exist (never self-registers). Same tenant-chooser behavior as `/auth/login` |
| POST | `/auth/logout` | no | — | Revoke the caller's device token |
| GET | `/me` | no | — | Current user: roles, permissions, branch, profile |
| GET | `/branches` | no | `branch:read` | List the tenant's branches |
| POST | `/branches` | no | `branch:write` | Create a branch |
| PATCH | `/branches/:id` | no | `branch:manage` | Rename / archive a branch |
| POST | `/branches/:id/members` | no | `user:invite` | Add a user to a branch (creates the user if new) |
| POST | `/branches/switch` | no | — | Move to a different branch in your tenant and issue a fresh token for it |
| GET | `/roles` | no | `tenant:manage` | List system + custom roles |
| POST | `/roles` | no | `tenant:manage` | Create a custom role |
| PATCH | `/roles/:id` | no | `tenant:manage` | Update a custom role |
| DELETE | `/roles/:id` | no | `tenant:manage` | Delete a custom role |
| PATCH | `/tenant` | no | `tenant:manage` | Update the tenant's display name / plan (slug is immutable) |
| POST | `/plugins/install` | no | `plugin:install` | Install a plugin for **your own** tenant |
| POST | `/plugins/uninstall` | no | `plugin:uninstall` | Uninstall (`drop_data` keeps or drops tables) |
| POST | `/plugins/install-all` | no | *platform admin* | Install a plugin for every active tenant that doesn't already have it |
| POST | `/plugins/reconcile` | no | *platform admin* | Roll a plugin's newly-added migrations out to every tenant that has it installed |
| GET | `/tenants` | no | *platform admin* | List every tenant (id, slug, name, plan, status) |
| GET | `/tenants/:id/plugins` | no | *platform admin* | List a tenant's installed plugins (any tenant, not just your own) |
| PATCH | `/tenants/:id/status` | no | *platform admin* | Suspend or reactivate a tenant (`{"status":"suspended"\|"active"}`) — blocks/restores login for every user of the tenant without touching data |
| GET | `/platform-admins` | no | *platform admin* | List platform admins |
| POST | `/platform-admins` | no | *platform admin* | Grant an existing user platform admin |
| DELETE | `/platform-admins/:email` | no | *platform admin* | Revoke a user's platform admin |
| GET | `/console/*` | yes | — | Platform-admin web UI (see below) |

> The **Permission** column is what Core's gateway requires before proxying
> (handlers re-check it too). `—` means any authenticated user — `/branches/switch`
> acts only on the caller's own membership.
>
> Install/uninstall additionally require the body's `tenant_id` to match the
> caller's device-token tenant — you cannot manage another tenant's plugins
> (`403` otherwise). New tenants automatically get every currently-installed
> plugin's tables during registration.
>
> `/plugins/reconcile` is different from install/uninstall: it's cross-tenant by
> design (gated on `X-ApiCoreX-User-Type: platform_admin`, not a tenant
> permission), for rolling out a plugin's new migration version to every tenant
> that already installed it — each tenant's applied versions are tracked
> (`plugin_migration_histories`), so it's safe to call repeatedly.
>
> **Platform admin is a DB column (`users.is_platform_admin`), not a tenant
> role** — a tenant's `owner` role (even with `*:*`) does not make you a
> platform admin, and vice versa. `PLATFORM_ADMIN_EMAILS` only bootstraps it
> once at boot for users who've already registered; `/platform-admins`
> grants/revokes it after that, taking effect immediately on every instance
> (no restart, no drift between replicas — unlike an env-only flag would have).
>
> **`POST /platform-admins` never creates an account** — it only flags an
> *existing* global user (matched by email); there's no password field. If the
> email has no account yet, register a tenant with it or add it as a branch
> member first (both admin-create a global user), then grant platform admin.
> This is intentional: account creation and privilege escalation stay separate
> steps, so granting platform admin can never be used to spray new credentials.
>
> **`/console` is a Next.js app** (login form + tenant list + plugin admins),
> statically exported and embedded into the binary (`//go:embed all:admin/out`),
> served by this plugin but with no session or auth logic of its own — it
> authenticates via the ordinary `/auth/login` and stores the access token in
> `localStorage`, then calls the JSON API through Core's gateway exactly like
> any other client. (It's served at `/console`, not `/admin`: Core's gateway
> firewall reserves and blocks the `/admin/` prefix, which would 403 the app's
> assets.) The source lives in `cmd/identity/admin/`; rebuild it with
> `cd cmd/identity/admin && npm ci && npm run build` (this regenerates
> `admin/out`, which the Go build embeds — the Docker image does both stages
> automatically). Open it through Core (e.g. `http://localhost:8080/console`)
> so the browser's requests go through the same device-token introspection as
> everything else. Like every plugin route, this only works because the plugin trusts
> Core's `X-ApiCoreX-*` headers unconditionally — the plugin's own port should
> not be reachable from outside the deployment; Core is the only intended
> entry point.

---

## Project structure

```
cmd/identity/      entrypoint + route handlers (auth, branches, roles, plugins)
docs/              design + contract docs (branches, RBAC, branch-isolation)
scripts/           reset-db.sql and other ops helpers
ent/               EntGo schema + generated code (run `go generate ./ent/...`)
internal/
  auth/            login, device-token issue/introspect/revoke, branch + role services
  rbac/            permission vocabulary, system-role seeding, baseline floor
  plugin/          self-contained ApiCoreX plugin runtime (manifest, register, headers,
                   permission + branch-scope helpers)
  pluginmgr/       per-tenant plugin install/uninstall + migration orchestration
  migrator/        runs plugin migrations in tenant schemas
  tenant/          registration saga + per-tenant schema migration
  tenantclient/    EntGo client scoped to a tenant schema
```
