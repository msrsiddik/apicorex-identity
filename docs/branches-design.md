# Branches — Design Doc

Status: **implemented** (identity-side). Core-side branch header injection baki.
Date: 2026-06-29

> **Superseded (2026-07-03):** membership model changed to **one row per
> (user, tenant)** — a user is active in exactly one branch at a time, with one
> role for the whole tenant. `is_default` and `/branches/default` removed;
> `/branches/switch` now moves the existing membership instead of creating a
> second one. The rest of this doc reflects the original (per-branch-row)
> decision and is kept for history.

## Implemented decisions (superseded, see note above)

- Membership granularity: **per (user, tenant, branch)** — branch-prati alada row + role.
- Login: **default branch** (`is_default`), chooser na. Tenant chooser unchanged.
- Branch CRUD + switch + set-default + add-member endpoints — full set.
- Isolation: logical (`branch_id`), branches table public schema.

## Core-side TODO (apicorex repo, alada)

Core `auth.Claims`-e `BranchID`/`BranchSlug` add kore `X-ApiCoreX-Branch-ID` /
`X-ApiCoreX-Branch-Slug` header inject korte hobe (identity token-e field already
ache; identity-side header helper `plugin.BranchID/BranchSlug` ready).

## Goal

Ek tenant (= company) er bhitore **onek branch** (sub-org / sakha) support kora.
Ekjon user ek tenant-er ekadhik branch-e thakte parbe, branch-prati alada role
niye. Token branch-aware hobe jate Core branch-level header inject korte pare.

Ekhon `User → Tenant` (M2M via `tenant_users`) ache. Branch hocche `Tenant`-er
bhitore aro ekta level:

```
User ──< TenantUser >── Tenant ──< Branch
                │                    │
                └── branch_id ───────┘   (membership ekta nirdishto branch-e)
```

## Decisions (confirmed)

1. **Isolation: logical** — protita branch-er alada schema na. Ek tenant schema
   (`tenant_<slug>`), tar table-gulo te `branch_id` column. Query-te always
   `WHERE branch_id = <ctx>` filter. Branch-table nije `shared` (public) schema-e.
2. **Login: default branch** — protita membership-er ekta default branch thakbe;
   login korle sei branch-e dhuke. Branch switch korar alada endpoint.
3. Age ei doc, tarpor code.

## Schema changes (`ent/schema`)

### Notun: `Branch` (public schema)

```go
type Branch struct{ ent.Schema }

Fields:
  id          string  "br_<uuid8>"  immutable, unique
  tenant_id   string                 // FK -> shared.tenants.id
  slug        string                 // unique per tenant (not global)
  name        string
  status      string  default "active"   // active | archived
  created_at  time.Time default now immutable

Edges:
  tenant  <- From(Tenant) Ref("branches") Field("tenant_id") Unique Required

Indexes:
  Fields("tenant_id", "slug").Unique()   // slug unique within a tenant
  Fields("tenant_id")
```

### `Tenant` — edge add

```go
Edges:
  edge.To("branches", Branch.Type)   // notun
  // (existing) tenant_users, plugin_installs
```

### `TenantUser` — branch_id field add

Membership ekhon (user, tenant) jora. Branch dhukle membership (user, branch)
hote pare — kintu eta boro change. Simplest: membership tenant-level-i thakuk,
ekta `branch_id` add kore "ei user ei tenant-e kon branch-e default-e thake"
bojhabo. Multi-branch-per-user dorkar hole ekadhik TenantUser row.

```go
Fields (add):
  branch_id   string  Optional   // user-er default/active branch ei tenant-e

Indexes (change):
  Fields("user_id", "tenant_id").Unique()  // -> agile rakho jodi ek user ek
       tenant-e ek-i row; multi-branch chaile (user_id, tenant_id, branch_id) Unique
```

> Decision point review-e: membership **per (user,tenant)** (branch_id = default)
> naki **per (user,tenant,branch)** (protita branch alada row, alada role)?
> Recommendation: **per (user,tenant,branch)** — taholе branch-prati alada role
> dewa jay, ar default branch alada flag/field (`is_default bool`) diye chinha.
> Niche ei version dhore likha holo.

Final TenantUser (recommended):

```go
Fields:
  id          string immutable unique  "tu_<uuid8>"
  user_id     string
  tenant_id   string
  branch_id   string                    // kon branch-e ei membership
  role        string default "member"
  is_default  bool   default false       // login default branch
  created_at  time.Time

Indexes:
  Fields("user_id", "tenant_id", "branch_id").Unique()
  Fields("tenant_id")
  Fields("user_id", "tenant_id")          // chooser/lookup
```

### Per-tenant data tables — `branch_id`

`user_profiles` (ar future plugin tables) te `branch_id` column add. PII
branch-scoped: ek user ek tenant-er 2 branch-e thakle 2 ta profile row?
- Simpler: profile tenant-level-i (PK = user_id), branch_id NULL allowed,
  branch-specific PII na. **Recommendation: ekhon profile tenant-level rakhi**,
  branch_id sudhu business/plugin table-e (orders, etc.) add hobe. Identity
  plugin-er user_profiles unchanged.

## Token / Claims changes

`internal/auth/jwt_issuer.go` `Claims`:

```go
type Claims struct {
  TenantID   string
  TenantSlug string
  SchemaName string
  BranchID   string   // NOTUN
  BranchSlug string   // NOTUN (optional, convenience)
  UserType   string
  Roles      []string
  jwt.RegisteredClaims
}
```

Core-er `auth.Claims` ar header injection-eo `branch_id` add korte hobe
(apicorex repo-te) — naile Core token-er branch field ignore korbe. Ei doc
identity-side; Core-side ekta alada change lagbe (note kora holo).

## Login flow change (`internal/auth/login.go`)

Ekhon: credential -> memberships (per tenant) -> slug diye tenant pick -> token.

Notun:
1. Credential verify (unchanged).
2. memberships = TenantUser by user_id (ekhon protita row = (tenant,branch)).
3. Tenant pick:
   - slug dile: sei tenant-er membership-gulo neo.
   - slug na + sob membership ek tenant-e: sei tenant.
   - slug na + multiple tenant: `MultiTenantError` (unchanged chooser).
4. Branch pick (notun):
   - select kora tenant-er membership-gulo theke `is_default=true` ta neo.
   - default na thakle prothom ta (deterministic: created_at asc).
   - (multi-branch chooser **na** — decision: default branch.)
5. `issueTokens` branch_id/slug bosabe.

`Refresh` — refresh_token-e `branch_id` store korte hobe (RefreshToken schema-e
field add) jate refresh-eo same branch e thake. Naile refresh branch reset kore.

```go
// RefreshToken schema add:
field.String("branch_id").Optional()
```

## Branch switch endpoint

```
POST /branches/switch   { "branch_id": "br_..." }
-> verify caller-er ei branch-e membership ache (TenantUser row)
-> notun token pair issue (same tenant, notun branch)
-> response: LoginResponse (access + refresh)
```

## Branch CRUD endpoints (owner/admin only)

```
POST   /branches            { name, slug }      -> create branch in caller's tenant
GET    /branches                                 -> list branches of caller's tenant
PATCH  /branches/:id        { name?, status? }   -> rename/archive
POST   /branches/:id/members { email, role }     -> add existing user to branch (invite)
```

`POST /branches` — caller-er tenant_id (JWT theke trusted) niye `shared.branches`
row banabe. Slug per-tenant unique. Plugin install-er moto: caller sudhu nijer
tenant-e branch banate parbe (tenant_id mismatch -> 403).

## Registration (saga) change

`saga.go` Register — notun tenant banale ekhon ekta **default branch** o banate
hobe (warna tenant-er kono branch thakbe na, login bhangbe):

- Step 1.5 (tenant create-er por): `shared.branches` e ekta default branch
  (`slug: "main"`, `name: "Main"`, `is_default`) insert. Compensation: delete.
- Step 2b membership-e oi default branch-er `branch_id` + `is_default=true` set.

## Migration

- `shared`: notun `branches` table + `tenant_users.branch_id`, `is_default`
  columns + `refresh_tokens.branch_id`. `migrateSharedSchema` (main.go) auto
  ent-migrate kore — branches table public-schema, tai user_profiles-er moto
  exclude korar dorkar nai.
- Existing tenants (jodi prod data thake): backfill — protita tenant-er ekta
  "main" branch banao, sob tenant_users.branch_id = oi main, is_default=true.
  Ekta one-off migration script (`cmd/migrate-branches`) lagbe. (Ekhon initial
  commit-i, prod data nai dhore — skip korte pari, kintu doc-e thaklo.)

## Out of scope (ekhon na)

- Schema-per-branch isolation (logical-i confirmed).
- Branch-scoped PII (user_profiles tenant-level thakbe).
- Branch chooser at login (default branch confirmed).
- resolveUser password-verify gap (alada kaj, pore).

## Open questions for review

1. TenantUser **per (user,tenant)** naki **per (user,tenant,branch)**?
   (doc recommendation: per branch — branch-prati role.)
2. Core repo-te branch_id claim/header injection ke korbe — ei task-e include
   korbo naki alada PR?
3. Branch CRUD-er full set ekhon-i, naki age sudhu schema + saga default branch +
   login + switch (CRUD pore)?
