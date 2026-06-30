package rbac

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/role"
	"github.com/msrsiddik/apicorex-identity/ent/rolepermission"
)

// Store reads and writes roles/permissions in the shared schema.
type Store struct {
	client *ent.Client
}

func NewStore(client *ent.Client) *Store { return &Store{client: client} }

// SeedSystemRoles creates the built-in system roles (tenant_id = "") and their
// permissions if missing. Idempotent: safe to call on every startup. Returns the
// slug -> role_id map for the system roles.
func (s *Store) SeedSystemRoles(ctx context.Context) (map[string]string, error) {
	ids := make(map[string]string, len(SystemRoles))
	for _, sr := range SystemRoles {
		r, err := s.client.Role.Query().
			Where(role.TenantID(""), role.Slug(sr.Slug)).Only(ctx)
		switch {
		case ent.IsNotFound(err):
			r, err = s.client.Role.Create().
				SetID("role_" + uuid.New().String()[:8]).
				SetTenantID("").
				SetSlug(sr.Slug).
				SetName(sr.Name).
				SetIsSystem(true).
				Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("seed role %s: %w", sr.Slug, err)
			}
		case err != nil:
			return nil, fmt.Errorf("query role %s: %w", sr.Slug, err)
		}
		ids[sr.Slug] = r.ID
		if err := s.syncPermissions(ctx, r.ID, sr.Permissions); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// SystemRoleID returns the id of a system role by slug.
func (s *Store) SystemRoleID(ctx context.Context, slug string) (string, error) {
	r, err := s.client.Role.Query().Where(role.TenantID(""), role.Slug(slug)).Only(ctx)
	if err != nil {
		return "", fmt.Errorf("system role %q: %w", slug, err)
	}
	return r.ID, nil
}

// ResolveRoleID maps a role slug to a role_id usable by a tenant: a tenant's own
// custom role takes precedence, else the system role with that slug. Errors if
// neither exists.
func (s *Store) ResolveRoleID(ctx context.Context, tenantID, slug string) (string, error) {
	if r, err := s.client.Role.Query().
		Where(role.TenantID(tenantID), role.Slug(slug)).Only(ctx); err == nil {
		return r.ID, nil
	}
	r, err := s.client.Role.Query().Where(role.TenantID(""), role.Slug(slug)).Only(ctx)
	if err != nil {
		return "", fmt.Errorf("role %q not found for tenant", slug)
	}
	return r.ID, nil
}

// RoleUsableBy reports whether a role_id is assignable within a tenant — it must
// be either a system role or one owned by that tenant.
func (s *Store) RoleUsableBy(ctx context.Context, tenantID, roleID string) (bool, error) {
	r, err := s.client.Role.Get(ctx, roleID)
	if err != nil {
		return false, nil //nolint:nilerr // missing role => not usable
	}
	return r.TenantID == "" || r.TenantID == tenantID, nil
}

// Permissions returns the flat, deduped permission list for a role.
func (s *Store) Permissions(ctx context.Context, roleID string) ([]string, error) {
	rps, err := s.client.RolePermission.Query().
		Where(rolepermission.RoleID(roleID)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rps))
	for _, rp := range rps {
		out = append(out, rp.Permission)
	}
	return out, nil
}

// syncPermissions makes the role's permission rows exactly match want (adds
// missing, removes extra). Used by seeding and role updates.
func (s *Store) syncPermissions(ctx context.Context, roleID string, want []string) error {
	existing, err := s.client.RolePermission.Query().
		Where(rolepermission.RoleID(roleID)).All(ctx)
	if err != nil {
		return err
	}
	have := make(map[string]string, len(existing)) // permission -> rp.id
	for _, rp := range existing {
		have[rp.Permission] = rp.ID
	}
	wantSet := make(map[string]bool, len(want))
	for _, p := range want {
		wantSet[p] = true
		if _, ok := have[p]; ok {
			continue
		}
		if _, err := s.client.RolePermission.Create().
			SetID("rp_" + uuid.New().String()[:8]).
			SetRoleID(roleID).
			SetPermission(p).
			Save(ctx); err != nil {
			return fmt.Errorf("add permission %s: %w", p, err)
		}
	}
	for perm, id := range have {
		if !wantSet[perm] {
			if err := s.client.RolePermission.DeleteOneID(id).Exec(ctx); err != nil {
				return fmt.Errorf("remove permission %s: %w", perm, err)
			}
		}
	}
	return nil
}
