package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/branch"
	"github.com/msrsiddik/apicorex-identity/ent/tenant"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/internal/tenantclient"
	"golang.org/x/crypto/bcrypt"
)

// branchSlugPattern restricts a branch slug to a safe, readable identifier. It
// is scoped per-tenant (not a SQL schema name), so the rules are looser than a
// tenant slug but still URL/identifier friendly.
var branchSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

// ErrInvalidBranchSlug is returned when a branch slug is malformed.
var ErrInvalidBranchSlug = errors.New("invalid branch slug: 2–32 chars, lowercase letters/digits/-/_, starting with a letter")

// BranchInfo is a branch as returned to clients.
type BranchInfo struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

func toBranchInfo(b *ent.Branch) BranchInfo {
	return BranchInfo{ID: b.ID, Slug: b.Slug, Name: b.Name, Status: b.Status}
}

// ListBranches returns all branches of a tenant.
func (s *Service) ListBranches(ctx context.Context, tenantID string) ([]BranchInfo, error) {
	bs, err := s.entClient.Branch.Query().
		Where(branch.TenantID(tenantID)).
		Order(ent.Asc(branch.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BranchInfo, 0, len(bs))
	for _, b := range bs {
		out = append(out, toBranchInfo(b))
	}
	return out, nil
}

// CreateBranch creates a new branch in a tenant. The slug must be unique within
// the tenant. The creator is not auto-added — use AddMember to grant access.
func (s *Service) CreateBranch(ctx context.Context, tenantID, slug, name string) (*BranchInfo, error) {
	if !branchSlugPattern.MatchString(slug) {
		return nil, ErrInvalidBranchSlug
	}
	exists, err := s.entClient.Branch.Query().
		Where(branch.TenantID(tenantID), branch.Slug(slug)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("a branch with that slug already exists")
	}
	b, err := s.entClient.Branch.Create().
		SetID("br_" + uuid.New().String()[:8]).
		SetTenantID(tenantID).
		SetSlug(slug).
		SetName(name).
		SetStatus("active").
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create branch: %w", err)
	}
	info := toBranchInfo(b)
	return &info, nil
}

// UpdateBranch renames and/or changes the status of a branch within a tenant.
// Empty name/status fields are left unchanged.
func (s *Service) UpdateBranch(ctx context.Context, tenantID, branchID, name, status string) (*BranchInfo, error) {
	b, err := s.entClient.Branch.Query().
		Where(branch.ID(branchID), branch.TenantID(tenantID)).Only(ctx)
	if err != nil {
		return nil, errors.New("branch not found")
	}
	upd := s.entClient.Branch.UpdateOneID(b.ID)
	if name != "" {
		upd = upd.SetName(name)
	}
	if status != "" {
		if status != "active" && status != "archived" {
			return nil, errors.New("status must be active or archived")
		}
		upd = upd.SetStatus(status)
	}
	b, err = upd.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("update branch: %w", err)
	}
	info := toBranchInfo(b)
	return &info, nil
}

// AddMemberInput describes a user to add to a branch. Email + Role identify the
// membership. If no global user exists for Email, one is created (admin-create):
// Password is then required and a PII profile is written in the tenant schema
// from FullName/Phone/JobTitle. If the user already exists, Password and the
// profile fields are ignored (their existing credential and profile stand).
type AddMemberInput struct {
	Email    string
	Role     string
	Password string // required only when creating a new user
	FullName string
	Phone    string
	JobTitle string
}

// AddMember grants a user access to a branch of a tenant with the given role,
// creating the global user (and tenant PII profile) when the email is new. If
// the user has no membership in this tenant yet, the new one becomes their
// default landing branch.
func (s *Service) AddMember(ctx context.Context, tenantID, branchID string, in AddMemberInput) error {
	roleSlug := in.Role
	if roleSlug == "" {
		roleSlug = "member"
	}
	roleID, err := s.rbac.ResolveRoleID(ctx, tenantID, roleSlug)
	if err != nil {
		return err
	}
	b, err := s.entClient.Branch.Query().
		Where(branch.ID(branchID), branch.TenantID(tenantID)).Only(ctx)
	if err != nil {
		return errors.New("branch not found")
	}

	// resolve (or admin-create) the global user.
	u, err := s.entClient.User.Query().Where(entuser.Email(in.Email)).Only(ctx)
	createdProfile := false
	if ent.IsNotFound(err) {
		if in.Password == "" {
			return errors.New("password required to create a new user")
		}
		hash, herr := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if herr != nil {
			return fmt.Errorf("hash password: %w", herr)
		}
		u, err = s.entClient.User.Create().
			SetID("u_" + uuid.New().String()[:8]).
			SetEmail(in.Email).
			SetPasswordHash(string(hash)).
			Save(ctx)
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		createdProfile = true
	} else if err != nil {
		return err
	}

	// already a member of this branch?
	exists, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(u.ID), tenantuser.TenantID(tenantID), tenantuser.BranchID(b.ID)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return errors.New("user is already a member of this branch")
	}

	// is this their first membership in the tenant? then it's their default.
	hasAny, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(u.ID), tenantuser.TenantID(tenantID)).Exist(ctx)
	if err != nil {
		return err
	}

	if _, err := s.entClient.TenantUser.Create().
		SetID("tu_" + uuid.New().String()[:8]).
		SetUserID(u.ID).
		SetTenantID(tenantID).
		SetBranchID(b.ID).
		SetRoleID(roleID).
		SetIsDefault(!hasAny).
		Save(ctx); err != nil {
		return fmt.Errorf("add member: %w", err)
	}

	// for a freshly created user, write their PII profile in the tenant schema.
	if createdProfile {
		t, terr := s.entClient.Tenant.Get(ctx, tenantID)
		if terr != nil {
			return fmt.Errorf("load tenant schema: %w", terr)
		}
		tc := tenantclient.New(s.db, t.SchemaName)
		defer tc.Close()
		if _, perr := tc.UserProfile.Create().
			SetID(u.ID).
			SetFullName(in.FullName).
			SetPhone(in.Phone).
			SetJobTitle(in.JobTitle).
			SetSystemRole(roleSlug).
			Save(ctx); perr != nil {
			return fmt.Errorf("create profile: %w", perr)
		}
	}
	return nil
}

// SwitchBranch issues a fresh token pair scoped to a different branch the user
// is a member of within their current tenant. tenantID/userID come from the
// caller's verified context.
func (s *Service) SwitchBranch(ctx context.Context, userID, tenantID, branchID string) (*LoginResult, error) {
	m, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID), tenantuser.BranchID(branchID)).
		Only(ctx)
	if err != nil {
		return nil, errors.New("no access to that branch")
	}
	t, err := s.entClient.Tenant.Query().Where(tenant.ID(tenantID), tenant.Status("active")).Only(ctx)
	if err != nil {
		return nil, errors.New("tenant not available")
	}
	b, err := s.entClient.Branch.Get(ctx, branchID)
	if err != nil || b.Status != "active" {
		return nil, errors.New("branch not available")
	}
	u, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return nil, errors.New("user not found")
	}
	return s.issueTokens(ctx, u, t, b, m.RoleID)
}

// SetDefaultBranch marks one branch membership as the user's default landing
// branch in a tenant, clearing the flag on their other memberships there.
func (s *Service) SetDefaultBranch(ctx context.Context, userID, tenantID, branchID string) error {
	target, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID), tenantuser.BranchID(branchID)).
		Only(ctx)
	if err != nil {
		return errors.New("no access to that branch")
	}
	// clear existing defaults in this tenant, then set the target.
	if _, err := s.entClient.TenantUser.Update().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID), tenantuser.IsDefault(true)).
		SetIsDefault(false).Save(ctx); err != nil {
		return fmt.Errorf("clear defaults: %w", err)
	}
	if _, err := s.entClient.TenantUser.UpdateOneID(target.ID).SetIsDefault(true).Save(ctx); err != nil {
		return fmt.Errorf("set default: %w", err)
	}
	return nil
}
