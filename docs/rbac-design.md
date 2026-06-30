# RBAC — Design Doc

Status: **implemented** (identity + core). All recommendations taken.
Date: 2026-06-30

## Implemented (as built)

- Schema: `roles` (system + tenant custom), `role_permissions`; `tenant_users.role` → `role_id`.
- System roles seeded idempotently on startup (`rbac.Store.SeedSystemRoles`); owner=`*:*`, admin, manager, member.
- Login/refresh resolve role_id → role slug + flattened permissions, embedded in token (`Claims.Permissions`).
- Identity endpoints: `/roles` CRUD (perm `tenant:manage`); `AddMember` accepts a role slug; branch routes declare permissions via `plugin.RequirePermission`.
- Plugin defense-in-depth: `plugin.HasPermission` reads `X-ApiCoreX-Permissions`; `requirePerm` guards handlers.
- Core gateway: `auth.Claims` gained `Permissions` (+ branch fields); `InjectTenantHeaders` sets `X-ApiCoreX-Permissions` (+ branch headers); manifest `Route.Permission` → dispatcher `routeEntry.permission` → authz check in `Dispatch` (403 on miss, wildcard-aware).
- Tests: rbac matcher unit tests (both repos), permission-in-token integration tests, custom-role lifecycle, dispatcher route-permission, system-role immutability.

## Goal

Role → permission based access control, custom role soho. Enforce **dui jaiga-te**:
Core gateway (route-er required permission) + plugin (defense-in-depth)। Token-e
user-er resolved permission set jabe jate gateway DB hit chara check korte pare।

## Decisions (confirmed)

1. Model: **RBAC** — role-er sathe permission set; custom role banano jay.
2. Enforcement: **gateway + plugin** duto.
3. Age ei doc, tarpor code.

## Ekhon ja ache

- `tenant_users.role` = ekta string (`owner`/`admin`/`member`)। Login token-e
  `Roles []string` jay (always 1 element ekhon)।
- Plugin handler-e hardcoded: `canManageBranches` → `owner || admin`।
- Core gateway: token verify kore `X-ApiCoreX-Roles` header inject kore, kintu
  route-level authorization **kore na** — sob authenticated user sob route-e jete pare.

## Notun concept

### Permissions (string, `resource:action`)

Convention: `<resource>:<action>`। Wildcard `*` allowed (`*:*` = superuser,
`branch:*` = sob branch action)। Initial set:

```
user:read   user:write   user:invite
branch:read branch:write branch:manage
plugin:install plugin:uninstall
billing:view billing:manage
tenant:manage
```

Permission gulo **code-defined constant** (DB-te string hisebe store), na ekta
DB-managed catalog — taholе typo/drift kom. Ekta `internal/rbac/permissions.go`-e
canonical list।

### Roles (per-tenant, default + custom)

Role ekhon string, RBAC-e eta ekta **row** hobe jate permission map kora jay.

```
shared.roles
  id          "role_<uuid8>"
  tenant_id   string        // NULL/"" => system role (sob tenant)
  slug        string        // owner | admin | manager | member | <custom>
  name        string
  is_system   bool          // system role: edit/delete na
  Indexes: (tenant_id, slug) unique
```

System roles (tenant_id empty) — sob tenant-er jonno default, register-e seed kora:

| slug    | permissions |
|---------|-------------|
| owner   | `*:*` |
| admin   | user:*, branch:*, plugin:*, billing:view |
| manager | user:read, user:invite, branch:read, branch:write |
| member  | user:read, branch:read |

Tenant nijer **custom role** banate parbe (tenant_id set, is_system=false)।

### Role → permission mapping

```
shared.role_permissions
  id         "rp_<uuid8>"
  role_id    string   // -> roles.id
  permission string   // "user:write"
  Indexes: (role_id, permission) unique
```

### Membership → role

`tenant_users.role` (string) → bodle `role_id` (FK to roles.id)। Migration:
existing `role` string-er sathe-mil system role-er id boshbe।

> Alternative (kom invasive): `role` string rakhi, ar role slug → permissions
> resolve kori roles table theke। Kintu custom role-er jonno role_id-i clean.
> **Recommendation: role_id।**

## Token / Claims change

Login-e role resolve kore tar permission set ber kore token-e dei:

```go
type Claims struct {
  ...
  Roles       []string `json:"roles"`        // role slug(s) — informational
  Permissions []string `json:"permissions"`  // NOTUN — resolved, flattened, deduped
  ...
}
```

Permissions token-e thakle gateway **prufficient** — DB hit chara check। Trade-off:
role/permission change korle existing token (15 min) purono permission carry korbe।
15-min TTL chhoto bole gromonjogyo; instant revoke laglе denylist-er moto branch
nite hobe (out of scope ekhon)।

## Gateway enforcement (apicorex repo)

### Manifest Route-e permission declare

`internal/manifest/manifest.go` Route-e:

```go
type Route struct {
  Method     string
  Path       string
  Public     bool
  Permission string   `json:"permission,omitempty"` // NOTUN: required permission, "" = any authenticated
  ...
}
```

Plugin route declare korar somoy permission dey (niche identity-side dekho)।

### Dispatcher + middleware

- `routeEntry`-e `permission string` add (dispatcher.go AddRoutes)।
- Notun middleware `internal/middleware/authz.go`: matched route-er `permission`
  thakle, claims-er `Permissions`-e seta (ba matching wildcard) ache kina check।
  Na thakle `403 forbidden`। Public/permission-empty route → skip।
- Wildcard match: `branch:manage` allowed by `branch:*` ba `*:*`।
- Core `auth.Claims`-e `Permissions` add + `X-ApiCoreX-Permissions` header inject
  (tenant.go), jate downstream plugin-o porte pare.

## Plugin-side (identity) change

### Route permission declare

`option`-e ekta helper, ba manifest Route build-er somoy permission set kora।
`internal/plugin/plugin.go`-e `Permission(perm string)` option / `route` field।
Identity routes:

```
POST /branches          -> branch:write
PATCH /branches/:id      -> branch:manage
POST /branches/:id/members -> user:invite
POST /plugins/install    -> plugin:install
GET  /branches           -> branch:read
... (login/register/refresh = public)
```

### Defense-in-depth helper

`canManageBranches` (hardcoded role) → bodle `plugin.HasPermission(c, "branch:manage")`
jeta `X-ApiCoreX-Permissions` header parse kore। Gateway already check korbe,
kintu plugin-o korbe (direct-call safety)।

### Role management endpoints (identity)

```
GET    /roles                       -> list system + tenant roles      [tenant:manage]
POST   /roles      {slug,name,permissions[]}  -> create custom role    [tenant:manage]
PATCH  /roles/:id  {name?,permissions[]?}     -> edit custom role       [tenant:manage]
DELETE /roles/:id                              -> delete custom role     [tenant:manage]
```
System role edit/delete forbidden (is_system)।

### Membership role assign

`AddMember` / notun `PATCH /branches/:id/members/:userId` — role ekhon role_id
(ba role slug → resolve)। Validate: role oi tenant-er (ba system) hote hobe.

## Registration (saga) change

Register-er somoy oi tenant-er jonno system role gulo **seed** kora lagbe na jodi
system role tenant_id-less global hoy — ekbar bootstrap-e seed kora jay
(`cmd/seed-roles` ba migrate hook)। Owner membership `role_id = owner-system-role`.

## Migration

- `shared`: `roles`, `role_permissions` notun table; `tenant_users.role` → `role_id`.
- Bootstrap: system role + role_permissions seed (idempotent, app start-e ek-bar)।
- Existing `tenant_users` backfill: `role` string → system role_id. (Initial commit,
  data nai dhore — fresh seed-i hobe।)

## Resolve flow (login)

```
membership.role_id
  -> roles row (slug)
  -> role_permissions rows -> []permission
  -> dedupe + wildcard expand kora hoy na (raw rakhi, gateway match-e wildcard handle)
  -> Claims.Roles = [slug], Claims.Permissions = [perm...]
```

## Out of scope (ekhon na)

- Instant permission revoke (token TTL-e nirbhor)।
- ABAC / conditional policy (resource-owner, branch-scoped condition)।
- Per-branch alada role beyond ja ache (membership already branch-scoped)।
- UI।

## Open questions for review

1. Membership-e `role_id` (FK) naki `role` slug string + resolve? (rec: role_id)
2. Permission token-e embed (prufficient, 15-min stale) — thik ache, naki gateway
   per-request DB/cache theke resolve korbe? (rec: token embed)
3. System role permission set ta upor-er table-moto thik ache?
4. Core-side change ei kaj-ei, naki identity age + Core alada PR?
