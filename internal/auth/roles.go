package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/role"
	"github.com/msrsiddik/apicorex-identity/ent/rolepermission"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
)

var roleSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

// RoleInfo is a role as returned to clients, with its permission list.
type RoleInfo struct {
	ID          string   `json:"id"`
	Slug        string   `json:"slug"`
	Name        string   `json:"name"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
}

// ListRoles returns the system roles plus the tenant's custom roles, each with
// their permission set.
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]RoleInfo, error) {
	roles, err := s.entClient.Role.Query().
		Where(role.Or(role.TenantID(""), role.TenantID(tenantID))).
		Order(ent.Asc(role.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]RoleInfo, 0, len(roles))
	for _, r := range roles {
		perms, err := s.rbac.Permissions(ctx, r.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, RoleInfo{ID: r.ID, Slug: r.Slug, Name: r.Name, IsSystem: r.IsSystem, Permissions: perms})
	}
	return out, nil
}

// CreateRole creates a tenant custom role with the given permissions. The slug
// must be unique within the tenant and not collide with a system role slug.
func (s *Service) CreateRole(ctx context.Context, tenantID, slug, name string, permissions []string) (*RoleInfo, error) {
	if !roleSlugPattern.MatchString(slug) {
		return nil, errors.New("invalid role slug: 2–32 chars, lowercase letters/digits/-/_, starting with a letter")
	}
	if err := validatePermissions(permissions); err != nil {
		return nil, err
	}
	// reject collisions with a system role or an existing tenant role.
	clash, err := s.entClient.Role.Query().
		Where(role.Slug(slug), role.Or(role.TenantID(""), role.TenantID(tenantID))).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if clash {
		return nil, errors.New("a role with that slug already exists")
	}
	r, err := s.entClient.Role.Create().
		SetID("role_" + uuid.New().String()[:8]).
		SetTenantID(tenantID).
		SetSlug(slug).
		SetName(name).
		SetIsSystem(false).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	if err := s.replacePermissions(ctx, r.ID, permissions); err != nil {
		return nil, err
	}
	return &RoleInfo{ID: r.ID, Slug: r.Slug, Name: r.Name, IsSystem: false, Permissions: permissions}, nil
}

// UpdateRole changes a tenant custom role's name and/or permissions. System
// roles cannot be modified. Empty name leaves it unchanged; nil permissions
// leaves them unchanged (pass an empty non-nil slice to clear).
func (s *Service) UpdateRole(ctx context.Context, tenantID, roleID, name string, permissions []string) (*RoleInfo, error) {
	r, err := s.entClient.Role.Get(ctx, roleID)
	if err != nil || (r.TenantID != tenantID) {
		return nil, errors.New("role not found")
	}
	if r.IsSystem {
		return nil, errors.New("system roles cannot be modified")
	}
	if name != "" {
		if r, err = s.entClient.Role.UpdateOneID(r.ID).SetName(name).Save(ctx); err != nil {
			return nil, fmt.Errorf("update role: %w", err)
		}
	}
	if permissions != nil {
		if err := validatePermissions(permissions); err != nil {
			return nil, err
		}
		if err := s.replacePermissions(ctx, r.ID, permissions); err != nil {
			return nil, err
		}
	}
	perms, err := s.rbac.Permissions(ctx, r.ID)
	if err != nil {
		return nil, err
	}
	return &RoleInfo{ID: r.ID, Slug: r.Slug, Name: r.Name, IsSystem: false, Permissions: perms}, nil
}

// DeleteRole removes a tenant custom role. System roles and roles still in use
// by a membership cannot be deleted.
func (s *Service) DeleteRole(ctx context.Context, tenantID, roleID string) error {
	r, err := s.entClient.Role.Get(ctx, roleID)
	if err != nil || r.TenantID != tenantID {
		return errors.New("role not found")
	}
	if r.IsSystem {
		return errors.New("system roles cannot be deleted")
	}
	inUse, err := s.entClient.TenantUser.Query().Where(tenantuser.RoleID(roleID)).Exist(ctx)
	if err != nil {
		return err
	}
	if inUse {
		return errors.New("role is assigned to members; reassign them first")
	}
	if _, err := s.entClient.RolePermission.Delete().
		Where(rolepermission.RoleID(roleID)).Exec(ctx); err != nil {
		return fmt.Errorf("delete role permissions: %w", err)
	}
	return s.entClient.Role.DeleteOneID(roleID).Exec(ctx)
}

// replacePermissions sets a role's permission rows to exactly the given list.
func (s *Service) replacePermissions(ctx context.Context, roleID string, permissions []string) error {
	if _, err := s.entClient.RolePermission.Delete().
		Where(rolepermission.RoleID(roleID)).Exec(ctx); err != nil {
		return fmt.Errorf("clear permissions: %w", err)
	}
	seen := make(map[string]bool, len(permissions))
	for _, p := range permissions {
		if seen[p] {
			continue
		}
		seen[p] = true
		if _, err := s.entClient.RolePermission.Create().
			SetID("rp_" + uuid.New().String()[:8]).
			SetRoleID(roleID).
			SetPermission(p).
			Save(ctx); err != nil {
			return fmt.Errorf("add permission %s: %w", p, err)
		}
	}
	return nil
}

var permPattern = regexp.MustCompile(`^(\*|[a-z][a-z0-9_-]*):(\*|[a-z][a-z0-9_-]*)$`)

func validatePermissions(permissions []string) error {
	for _, p := range permissions {
		if !permPattern.MatchString(p) {
			return fmt.Errorf("invalid permission %q: must be resource:action (or with * wildcards)", p)
		}
	}
	return nil
}
