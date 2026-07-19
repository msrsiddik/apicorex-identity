// Package rbac defines the permission vocabulary, the built-in system roles, and
// helpers to seed and match permissions. Permissions are "resource:action"
// strings; "*" is a wildcard in either segment ("branch:*", "*:*").
package rbac

import "strings"

// Permission constants. The canonical vocabulary lives here so typos surface at
// compile time rather than as silent authorization drift.
const (
	PermUserRead   = "user:read"
	PermUserWrite  = "user:write"
	PermUserInvite = "user:invite"

	PermBranchRead   = "branch:read"
	PermBranchWrite  = "branch:write"
	PermBranchManage = "branch:manage"

	PermPluginInstall   = "plugin:install"
	PermPluginUninstall = "plugin:uninstall"

	PermBillingView   = "billing:view"
	PermBillingManage = "billing:manage"

	PermTenantManage = "tenant:manage"

	// PermSaleVoid lets a user cancel (void) a recorded POS sale, which reverses
	// its stock and credit side effects. Given to managers and up, not plain
	// members — an ordinary staffer shouldn't be able to unwind settled bills.
	PermSaleVoid = "sale:void"

	// PermSaleRefund lets a user record a (partial or full) return against a
	// recorded POS sale — returning stock and refunding money (cash back or a
	// due adjustment). Like void, it unwinds settled money, so it's manager-and-up
	// only, not plain members.
	PermSaleRefund = "sale:refund"

	// PermAll grants everything (owner).
	PermAll = "*:*"
)

// Catalog is the full set of concrete, grantable permissions — the vocabulary a
// custom role can be built from. Wildcards (branch:*, *:*) are intentionally
// excluded: they're for the seeded system roles, not something a tenant assigns
// by hand. Ordered for display, grouped by resource.
var Catalog = []string{
	PermUserRead, PermUserWrite, PermUserInvite,
	PermBranchRead, PermBranchWrite, PermBranchManage,
	PermPluginInstall, PermPluginUninstall,
	PermBillingView, PermBillingManage,
	PermTenantManage,
	PermSaleVoid, PermSaleRefund,
}

// BaselinePermissions is the floor granted to every authenticated user
// regardless of role: a neutral read-only set so even a role with no (or empty)
// permissions can see its own profile and current branch. Merged into the token
// at login/refresh on top of the role's own permissions.
var BaselinePermissions = []string{PermUserRead, PermBranchRead}

// WithBaseline returns perms merged with BaselinePermissions, deduped, baseline
// first. Use when building the permission set embedded in a token.
func WithBaseline(perms []string) []string {
	seen := make(map[string]bool, len(perms)+len(BaselinePermissions))
	out := make([]string, 0, len(perms)+len(BaselinePermissions))
	for _, p := range BaselinePermissions {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, p := range perms {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// SystemRole describes a built-in role seeded for every tenant.
type SystemRole struct {
	Slug        string
	Name        string
	Permissions []string
}

// SystemRoles are the built-in roles. Order matters only for display.
var SystemRoles = []SystemRole{
	{Slug: "owner", Name: "Owner", Permissions: []string{PermAll}},
	{Slug: "admin", Name: "Admin", Permissions: []string{
		"user:*", "branch:*", "plugin:*", PermBillingView, PermSaleVoid, PermSaleRefund,
	}},
	{Slug: "manager", Name: "Manager", Permissions: []string{
		PermUserRead, PermUserInvite, PermBranchRead, PermBranchWrite, PermSaleVoid, PermSaleRefund,
	}},
	{Slug: "member", Name: "Member", Permissions: []string{
		PermUserRead, PermBranchRead,
	}},
}

// Allows reports whether the granted permission set satisfies the required
// permission, honoring "*" wildcards in either the resource or action segment.
// An empty required permission is always allowed (route declares no permission).
func Allows(granted []string, required string) bool {
	if required == "" {
		return true
	}
	for _, g := range granted {
		if match(g, required) {
			return true
		}
	}
	return false
}

// match reports whether a granted permission pattern covers a required one.
func match(granted, required string) bool {
	if granted == required || granted == PermAll {
		return true
	}
	gRes, gAct, ok := splitPerm(granted)
	if !ok {
		return false
	}
	rRes, rAct, ok := splitPerm(required)
	if !ok {
		return false
	}
	resOK := gRes == "*" || gRes == rRes
	actOK := gAct == "*" || gAct == rAct
	return resOK && actOK
}

func splitPerm(p string) (resource, action string, ok bool) {
	res, act, found := strings.Cut(p, ":")
	if !found || res == "" || act == "" {
		return "", "", false
	}
	return res, act, true
}
