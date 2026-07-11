package auth

import (
	"context"
	"errors"
	"time"

	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/devicetoken"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
)

// ErrInvalidToken: the device token doesn't exist, is revoked, or its tenant is
// unavailable. The device must log in again.
var ErrInvalidToken = errors.New("invalid token")

// ErrMembershipRevoked: the token is fine, but the acting user (or the token's
// owner) is no longer an active member of the tenant. The app matches this
// message to boot the removed/suspended user.
var ErrMembershipRevoked = errors.New("membership revoked")

// lastUsedThrottle bounds how often a token's last_used_at is rewritten — one
// write per token per interval, not one per request.
const lastUsedThrottle = 5 * time.Minute

// IntrospectResult is everything Core needs to inject the trusted X-ApiCoreX-*
// headers for one request: tenant/branch scope from the device token, identity
// and fresh role/permissions from the ACTING user.
type IntrospectResult struct {
	TenantID    string   `json:"tenant_id"`
	TenantSlug  string   `json:"tenant_slug"`
	SchemaName  string   `json:"schema_name"`
	BranchID    string   `json:"branch_id,omitempty"`
	BranchSlug  string   `json:"branch_slug,omitempty"`
	UserID      string   `json:"user_id"` // the acting user
	UserType    string   `json:"user_type"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

// Introspect resolves an opaque device token (by hash) plus an optional acting
// user into the request identity. Authorization data is never cached in the
// token: the acting user's membership, status, role, and permissions are read
// fresh here on every call, so role changes and suspensions take effect
// immediately (modulo Core's short response cache).
//
// Rules:
//   - unknown/revoked token, or inactive tenant → ErrInvalidToken
//   - the token OWNER must still be an active member — removing or suspending
//     the owner kills every device they signed in on → ErrMembershipRevoked
//   - actingUserID (empty = the owner) must be an active member of the token's
//     tenant → ErrMembershipRevoked. A removed staff only unauthorizes that
//     staff; the shop's device token itself survives.
func (s *Service) Introspect(ctx context.Context, tokenHash, actingUserID string) (*IntrospectResult, error) {
	dt, err := s.entClient.DeviceToken.Query().
		Where(devicetoken.TokenHash(tokenHash), devicetoken.RevokedAtIsNil()).
		Only(ctx)
	if err != nil {
		return nil, ErrInvalidToken
	}
	t, err := s.entClient.Tenant.Get(ctx, dt.TenantID)
	if err != nil || t.Status != "active" {
		return nil, ErrInvalidToken
	}

	// The token OWNER must still be an active member — UNLESS they're a platform
	// admin, who acts across tenants and may hold no tenant membership at all.
	// Removing/suspending the owner (a regular user) kills every device they
	// signed in on; a platform admin's device only dies when the token is revoked.
	owner, oerr := s.entClient.User.Get(ctx, dt.UserID)
	ownerIsAdmin := oerr == nil && owner.IsPlatformAdmin

	// Load the owner's membership. For a regular user its absence is a hard
	// revocation; for a platform admin it's optional — but when present we still
	// use it, so an admin who is ALSO a tenant member (e.g. that tenant's owner)
	// keeps their full tenant role/permissions, not an empty set.
	ownerM, err := s.activeMembership(ctx, dt.TenantID, dt.UserID)
	if err != nil {
		if !ownerIsAdmin {
			return nil, ErrMembershipRevoked
		}
		ownerM = nil
	}

	// Resolve the acting user. Default is the token owner. A different acting
	// user (PIN unlock) must be an active member — a platform admin can't be
	// "acted as" without a membership, so this only applies to real staff.
	acting, m := dt.UserID, ownerM
	actingIsAdmin := ownerIsAdmin
	if actingUserID != "" && actingUserID != dt.UserID {
		if m, err = s.activeMembership(ctx, dt.TenantID, actingUserID); err != nil {
			return nil, ErrMembershipRevoked
		}
		acting = actingUserID
		if au, aerr := s.entClient.User.Get(ctx, acting); aerr == nil {
			actingIsAdmin = au.IsPlatformAdmin
		}
	}

	// Resolve the membership's role → roles/permissions. A platform admin with no
	// membership at all gets empty tenant permissions (Core's authorizer bypasses
	// permission checks for platform_admin anyway). Always non-nil slices so they
	// marshal as [] (not null) — clients decode them as non-optional arrays.
	roles, permissions := []string{}, []string{}
	if m != nil {
		if roles, permissions, err = s.resolveRole(ctx, m.RoleID); err != nil {
			return nil, err
		}
	}

	userType := "tenant_user"
	if actingIsAdmin {
		userType = "platform_admin"
	}

	res := &IntrospectResult{
		TenantID:    t.ID,
		TenantSlug:  t.Slug,
		SchemaName:  t.SchemaName,
		UserID:      acting,
		UserType:    userType,
		Roles:       roles,
		Permissions: permissions,
	}
	// branch scope comes from the device token, not the acting user's membership:
	// the till stays on its branch no matter who unlocks it.
	if dt.BranchID != "" {
		if b, berr := s.entClient.Branch.Get(ctx, dt.BranchID); berr == nil {
			res.BranchID = b.ID
			res.BranchSlug = b.Slug
		}
	}

	// throttled last-used stamp (best-effort)
	if dt.LastUsedAt == nil || time.Since(*dt.LastUsedAt) > lastUsedThrottle {
		s.entClient.DeviceToken.UpdateOneID(dt.ID).SetLastUsedAt(time.Now()).Exec(ctx) //nolint:errcheck
	}
	return res, nil
}

// activeMembership returns the user's non-suspended membership row in a tenant,
// or an error when there is none (removed or suspended).
func (s *Service) activeMembership(ctx context.Context, tenantID, userID string) (*ent.TenantUser, error) {
	return s.entClient.TenantUser.Query().
		Where(
			tenantuser.UserID(userID),
			tenantuser.TenantID(tenantID),
			tenantuser.StatusNEQ("suspended"),
		).
		Only(ctx)
}
