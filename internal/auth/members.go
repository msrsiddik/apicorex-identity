package auth

import (
	"context"
	"fmt"

	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	"github.com/msrsiddik/apicorex-identity/ent/userprofile"
	"github.com/msrsiddik/apicorex-identity/internal/tenantclient"
)

// MemberInfo is one member of a tenant as returned to clients: who they are
// (email + name from their profile), their role, and which branch they're
// currently active in. Never carries the password hash or another tenant's data.
type MemberInfo struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	FullName string `json:"full_name"`
	Phone    string `json:"phone"`
	RoleID   string `json:"role_id"`
	RoleSlug string `json:"role_slug"`
	RoleName string `json:"role_name"`
	BranchID string `json:"branch_id"`
}

// ListMembers returns every member of the given tenant.
//
// Tenant isolation is the whole point of this query, so it is enforced in two
// layers: the membership rows are read with an explicit tenant_id filter (the
// TenantUser table is shared/public, so nothing but this WHERE keeps tenants
// apart), and the PII (names/phones) is read from that tenant's own schema.
// tenantID must come from the caller's verified context, never a request body.
func (s *Service) ListMembers(ctx context.Context, tenantID string) ([]MemberInfo, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant required")
	}

	// membership rows for THIS tenant only, with the global user (email) joined
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.TenantID(tenantID)).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(memberships) == 0 {
		return []MemberInfo{}, nil
	}

	// names/phones live in the tenant's own schema (user_profiles) — read them
	// there, keyed by user id, so PII never crosses a tenant boundary.
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant: %w", err)
	}
	tc := tenantclient.New(s.db, t.SchemaName)
	defer tc.Close()

	userIDs := make([]string, 0, len(memberships))
	for _, m := range memberships {
		userIDs = append(userIDs, m.UserID)
	}
	// PII lookup is best-effort: a member list must not break just because the
	// tenant schema is mid-migration (e.g. a newly added column not yet applied
	// to an old tenant). On failure we return the memberships with blank names
	// rather than failing the whole request.
	profileByID := make(map[string]struct{ name, phone string })
	if profiles, perr := tc.UserProfile.Query().Where(userprofile.IDIn(userIDs...)).All(ctx); perr == nil {
		for _, p := range profiles {
			profileByID[p.ID] = struct{ name, phone string }{p.FullName, p.Phone}
		}
	}

	// resolve role slug/name once per distinct role (usually a handful)
	roleCache := make(map[string]struct{ slug, name string })
	resolveRole := func(roleID string) (string, string) {
		if r, ok := roleCache[roleID]; ok {
			return r.slug, r.name
		}
		slug, name := "", ""
		if r, rerr := s.entClient.Role.Get(ctx, roleID); rerr == nil {
			slug, name = r.Slug, r.Name
		}
		roleCache[roleID] = struct{ slug, name string }{slug, name}
		return slug, name
	}

	out := make([]MemberInfo, 0, len(memberships))
	for _, m := range memberships {
		email := ""
		if m.Edges.User != nil {
			email = m.Edges.User.Email
		}
		prof := profileByID[m.UserID]
		slug, name := resolveRole(m.RoleID)
		out = append(out, MemberInfo{
			UserID:   m.UserID,
			Email:    email,
			FullName: prof.name,
			Phone:    prof.phone,
			RoleID:   m.RoleID,
			RoleSlug: slug,
			RoleName: name,
			BranchID: m.BranchID,
		})
	}
	return out, nil
}
