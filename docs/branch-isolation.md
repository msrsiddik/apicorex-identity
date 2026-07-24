# Branch isolation — contract for plugins

Status: **implemented** (helper + contract). Identity has no branch-scoped data
of its own; this is the rule every *branch-scoped* plugin (billing, inventory,
…) follows.

## The model

Branch isolation is **logical**, not physical:

- A tenant's data lives in one Postgres schema (`tenant_<slug>`).
- Branch-scoped tables carry a `branch_id` column.
- Every read/write must be filtered by the caller's **active branch**.

The active branch comes from the caller's device token, resolved by Core via
Identity's `/internal/introspect`. Core injects it into the proxied request as
`X-ApiCoreX-Branch-ID` (and `-Branch-Slug`). A device token only ever scopes to
a branch its owner is a member of (login lands on their current branch;
`/branches/switch` moves the membership and issues a fresh token for the new
branch). So "trust the header" is safe — Core resolved the token via Identity
and stripped any client-supplied `X-ApiCoreX-*` headers first.

## The rule

**A branch-scoped query must never run without a branch filter.** A missing
`branch_id` filter silently spans every branch in the tenant — a data leak.

Use the helpers in `internal/plugin` instead of reading the header by hand:

```go
// read path — reject requests with no branch context, then filter
func listOrders(c *gin.Context) {
    bid, ok := plugin.RequireBranch(c) // writes 400 + returns false if absent
    if !ok {
        return
    }
    orders, _ := db.Order.Query().Where(order.BranchID(bid)).All(ctx)
    c.JSON(200, orders)
}

// write path — stamp the branch from the token, never from the request body
func createOrder(c *gin.Context) {
    bid, ok := plugin.RequireBranch(c)
    if !ok {
        return
    }
    db.Order.Create().SetBranchID(bid).Set... .Save(ctx) // body cannot override branch
}
```

In non-handler/service code that must not run a branch-spanning query, use
`plugin.BranchScope(c)` which returns `ErrNoBranchContext` rather than a silent
unfiltered result.

## What is NOT branch-scoped

- **Shared/public tables** (users, tenants, branches, tenant_users, roles) —
  these are tenant- or global-level by design.
- **Identity's `user_profiles`** — deliberately tenant-level (one PII row per
  user per tenant), not branch-scoped. A user in two branches has one profile.
- Any table where the data legitimately belongs to the whole tenant.

For these, use the tenant context (`X-ApiCoreX-Schema` / `X-ApiCoreX-Tenant-ID`)
and do **not** apply a branch filter.

## Why switch needs no permission

`/branches/switch` only issues a token for a branch the caller is already a
member of (membership is checked against `shared.tenant_users`). It grants no new
access — it changes which branch's data the same user sees, with the role they
already hold in that branch. So it is a self-service action, like switching
Slack workspaces. The isolation guarantee lives at the data layer (this
contract), not at the switch endpoint.

## Enforcement summary

| Layer | Responsibility |
|-------|----------------|
| Identity | Issues branch-scoped device tokens; membership-checked switch; resolves branch on every introspect call. |
| Core gateway | Resolves the device token via Identity, injects `X-ApiCoreX-Branch-ID`, strips spoofed headers. |
| Branch-scoped plugin | `RequireBranch` / `BranchScope` + `WHERE branch_id = ?` on every query. |
