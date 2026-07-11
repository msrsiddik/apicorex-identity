package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	"github.com/msrsiddik/apicorex-identity/ent/userprofile"
	"github.com/msrsiddik/apicorex-identity/internal/rbac"
	"github.com/msrsiddik/apicorex-identity/internal/tenantclient"
	"golang.org/x/crypto/bcrypt"
)

// pinPattern restricts a device-unlock PIN to exactly 4 digits.
var pinPattern = regexp.MustCompile(`^\d{4}$`)

// ErrInvalidPin: the PIN isn't 4 digits.
var ErrInvalidPin = errors.New("pin must be 4 digits")

// ErrMemberNotFound: no such member in this tenant. Also returned when a userID
// belongs to another tenant — the tenant-scoped lookup simply doesn't match, so
// a caller can never act on a user outside their own tenant.
var ErrMemberNotFound = errors.New("member not found in this tenant")

// ErrLastManager: refusing to demote or remove the tenant's last member who can
// manage it — that would leave the tenant with no one able to administer it.
var ErrLastManager = errors.New("cannot remove the tenant's last manager")

// UpdateMemberRole changes a member's role within the caller's tenant. The
// membership is looked up scoped to tenantID, so a userID from another tenant
// resolves to nothing (ErrMemberNotFound). Demoting the last manager is refused.
func (s *Service) UpdateMemberRole(ctx context.Context, tenantID, userID, roleSlug string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	m, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID)).
		Only(ctx)
	if err != nil {
		return ErrMemberNotFound
	}
	newRoleID, err := s.rbac.ResolveRoleID(ctx, tenantID, roleSlug)
	if err != nil {
		return fmt.Errorf("unknown role %q", roleSlug)
	}

	// If this member is currently a manager and the new role isn't, make sure
	// they aren't the last one — otherwise no one could administer the tenant.
	wasManager, merr := s.roleHasPerm(ctx, m.RoleID, rbac.PermTenantManage)
	if merr != nil {
		return merr
	}
	if wasManager {
		willManage, werr := s.roleHasPerm(ctx, newRoleID, rbac.PermTenantManage)
		if werr != nil {
			return werr
		}
		if !willManage {
			n, cerr := s.countManagers(ctx, tenantID)
			if cerr != nil {
				return cerr
			}
			if n <= 1 {
				return ErrLastManager
			}
		}
	}

	_, err = s.entClient.TenantUser.UpdateOneID(m.ID).SetRoleID(newRoleID).Save(ctx)
	return err
}

// RemoveMember revokes a user's access to the caller's tenant: it deletes the
// membership (scoped to tenantID) and the user's PII profile in the tenant
// schema. The global User row is left intact — they may still belong to other
// tenants. Removing the last manager is refused.
func (s *Service) RemoveMember(ctx context.Context, tenantID, userID string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	m, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID)).
		Only(ctx)
	if err != nil {
		return ErrMemberNotFound
	}

	isManager, merr := s.roleHasPerm(ctx, m.RoleID, rbac.PermTenantManage)
	if merr != nil {
		return merr
	}
	if isManager {
		n, cerr := s.countManagers(ctx, tenantID)
		if cerr != nil {
			return cerr
		}
		if n <= 1 {
			return ErrLastManager
		}
	}

	if err := s.entClient.TenantUser.DeleteOneID(m.ID).Exec(ctx); err != nil {
		return err
	}
	// best-effort PII cleanup in the tenant schema; membership is already gone,
	// which is what actually revokes access.
	if t, terr := s.entClient.Tenant.Get(ctx, tenantID); terr == nil {
		tc := tenantclient.New(s.db, t.SchemaName)
		defer tc.Close()
		_, _ = tc.UserProfile.Delete().Where(userprofile.ID(userID)).Exec(ctx)
	}
	return nil
}

// roleHasPerm reports whether the role grants perm (honoring "*" wildcards).
func (s *Service) roleHasPerm(ctx context.Context, roleID, perm string) (bool, error) {
	perms, err := s.rbac.Permissions(ctx, roleID)
	if err != nil {
		return false, err
	}
	return rbac.Allows(perms, perm), nil
}

// countManagers counts the tenant's members whose role grants tenant:manage.
func (s *Service) countManagers(ctx context.Context, tenantID string) (int, error) {
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.TenantID(tenantID)).
		All(ctx)
	if err != nil {
		return 0, err
	}
	// distinct role ids, each checked once
	managerRole := make(map[string]bool)
	count := 0
	for _, m := range memberships {
		ok, has := managerRole[m.RoleID]
		if !has {
			var perr error
			ok, perr = s.roleHasPerm(ctx, m.RoleID, rbac.PermTenantManage)
			if perr != nil {
				return 0, perr
			}
			managerRole[m.RoleID] = ok
		}
		if ok {
			count++
		}
	}
	return count, nil
}

// SetMemberPin sets (or clears) a member's device-unlock PIN, hashed with
// bcrypt, in the tenant's user_profiles. tenantID scopes it, and the member
// must belong to the tenant — so an owner can only set PINs for their own
// staff. An empty pin clears it. The PIN is validated as 4 digits.
func (s *Service) SetMemberPin(ctx context.Context, tenantID, userID, pin string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	// membership check keeps this tenant-scoped: a userID from another tenant
	// doesn't resolve, so no one can set a PIN outside their own shop.
	exists, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID)).
		Exist(ctx)
	if err != nil || !exists {
		return ErrMemberNotFound
	}
	return s.writePinHash(ctx, tenantID, userID, pin)
}

// SetOwnPin sets the caller's own device-unlock PIN. tenantID/userID come from
// the verified context.
func (s *Service) SetOwnPin(ctx context.Context, tenantID, userID, pin string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	return s.writePinHash(ctx, tenantID, userID, pin)
}

// VerifyOwnPin checks a plaintext pin against the caller's stored bcrypt hash.
// Used when a user activates their PIN on a new device (or one an owner set) —
// after an online verify the device caches a local hash for offline unlock.
// Returns false (no error) on a mismatch or when no PIN is set.
func (s *Service) VerifyOwnPin(ctx context.Context, tenantID, userID, pin string) (bool, error) {
	if tenantID == "" || userID == "" {
		return false, ErrMemberNotFound
	}
	p, err := s.LoadProfileForTenant(ctx, tenantID, userID)
	if err != nil {
		return false, err
	}
	if p.PinHash == "" {
		return false, nil
	}
	return bcrypt.CompareHashAndPassword([]byte(p.PinHash), []byte(pin)) == nil, nil
}

// LoadProfileForTenant loads a profile by tenant id (resolving its schema).
func (s *Service) LoadProfileForTenant(ctx context.Context, tenantID, userID string) (*Profile, error) {
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant: %w", err)
	}
	return s.LoadProfile(ctx, t.SchemaName, userID)
}

// writePinHash hashes pin (or clears it when empty) into the tenant profile.
func (s *Service) writePinHash(ctx context.Context, tenantID, userID, pin string) error {
	hash := ""
	if pin != "" {
		if !pinPattern.MatchString(pin) {
			return ErrInvalidPin
		}
		h, err := bcrypt.GenerateFromPassword([]byte(pin), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash pin: %w", err)
		}
		hash = string(h)
	}
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("load tenant: %w", err)
	}
	tc := tenantclient.New(s.db, t.SchemaName)
	defer tc.Close()
	_, err = tc.UserProfile.UpdateOneID(userID).SetPinHash(hash).Save(ctx)
	return err
}
