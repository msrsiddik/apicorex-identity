package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/devicetoken"
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

// ErrPinTaken: another active member of the same tenant already uses this PIN.
// PINs must be unique per tenant so unlock-by-PIN resolves to exactly one staff.
var ErrPinTaken = errors.New("pin already used by another member")

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
	// Revoke every device token this user OWNS in THIS tenant — i.e. devices
	// they personally logged in on. Introspect already rejects a removed user
	// (as owner or acting user), but a live row would silently become valid
	// again if they were ever re-added — revoking now closes that. Devices owned
	// by OTHERS (e.g. the shop till the manager logged in on) are untouched: the
	// removed user simply stops being an authorized acting user there.
	// Best-effort: membership deletion above is what actually revokes access.
	_, _ = s.entClient.DeviceToken.Update().
		Where(devicetoken.UserID(userID), devicetoken.TenantID(tenantID), devicetoken.RevokedAtIsNil()).
		SetRevokedAt(time.Now()).
		Save(ctx)
	// best-effort PII cleanup in the tenant schema; membership is already gone,
	// which is what actually revokes access.
	if t, terr := s.entClient.Tenant.Get(ctx, tenantID); terr == nil {
		tc := tenantclient.New(s.db, t.SchemaName)
		defer tc.Close()
		_, _ = tc.UserProfile.Delete().Where(userprofile.ID(userID)).Exec(ctx)
	}
	return nil
}

// SetMemberStatus suspends or reactivates a member within the caller's tenant.
// A suspended member can't sign in, refresh, or unlock (login/refresh/me all
// reject) until reactivated — a reversible alternative to RemoveMember that
// keeps their row (and past-sale attribution) intact. Suspending is refused for
// the tenant's last active manager (same guard as remove/demote). status must be
// "active" or "suspended".
func (s *Service) SetMemberStatus(ctx context.Context, tenantID, userID, status string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	if status != "active" && status != "suspended" {
		return errors.New(`status must be "active" or "suspended"`)
	}
	m, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID)).
		Only(ctx)
	if err != nil {
		return ErrMemberNotFound
	}
	if m.Status == status {
		return nil // idempotent — already in the requested state
	}

	// Suspending a manager: don't strand the tenant without an administrator.
	if status == "suspended" {
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
	}

	if _, err := s.entClient.TenantUser.UpdateOneID(m.ID).SetStatus(status).Save(ctx); err != nil {
		return err
	}
	// On suspend, revoke the device tokens this user OWNS so a device they
	// signed in on stops working (introspect already rejects them, this is
	// defense-in-depth and mirrors RemoveMember). Devices owned by others are
	// untouched. Reactivation doesn't restore tokens — the member logs in again.
	if status == "suspended" {
		_, _ = s.entClient.DeviceToken.Update().
			Where(devicetoken.UserID(userID), devicetoken.TenantID(tenantID), devicetoken.RevokedAtIsNil()).
			SetRevokedAt(time.Now()).
			Save(ctx)
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

// countManagers counts the tenant's ACTIVE members whose role grants
// tenant:manage. Suspended members are excluded: a suspended manager can't
// administer anything, so they don't count toward "is there still a manager"
// when removing/suspending/demoting the last one.
func (s *Service) countManagers(ctx context.Context, tenantID string) (int, error) {
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.TenantID(tenantID), tenantuser.StatusNEQ("suspended")).
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

// ResolvedMember is the member a PIN resolved to (see ResolvePin).
type ResolvedMember struct {
	UserID   string
	FullName string
	Email    string
}

// ResolvePin finds which ACTIVE member of a tenant a plaintext PIN belongs to,
// by bcrypt-comparing it against every member's stored pin_hash. It's what lets
// a shared till unlock ANY staff by PIN alone — even ones who never enrolled on
// this device — using only the device token to authorize (tenantID comes from
// the verified context). Returns the matched member, or ErrInvalidPin when no
// active member's PIN matches. Suspended/removed members are excluded, so their
// PIN stops unlocking the moment they're blocked.
//
// PINs are unique per tenant by enrollment convention, so at most one matches;
// if two ever collided, the first (by membership creation order) wins.
func (s *Service) ResolvePin(ctx context.Context, tenantID, pin string) (*ResolvedMember, error) {
	if tenantID == "" {
		return nil, ErrMemberNotFound
	}
	if !pinPattern.MatchString(pin) {
		return nil, ErrInvalidPin
	}
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant: %w", err)
	}
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.TenantID(tenantID), tenantuser.StatusNEQ("suspended")).
		Order(ent.Asc(tenantuser.FieldCreatedAt)).
		WithUser().
		All(ctx)
	if err != nil {
		return nil, err
	}
	tc := tenantclient.New(s.db, t.SchemaName)
	defer tc.Close()
	for _, m := range memberships {
		p, perr := tc.UserProfile.Get(ctx, m.UserID)
		if perr != nil || p.PinHash == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(p.PinHash), []byte(pin)) == nil {
			email := ""
			if m.Edges.User != nil {
				email = m.Edges.User.Email
			}
			return &ResolvedMember{UserID: m.UserID, FullName: p.FullName, Email: email}, nil
		}
	}
	return nil, ErrInvalidPin
}

// PinAvailable reports whether a PIN is free to use in a tenant — i.e. no OTHER
// active member already has it (bcrypt-compared against every member's hash).
// exceptUserID lets a member keep their own PIN when re-saving. A malformed PIN
// is treated as unavailable (never a valid choice). This backs both the hard
// write-guard and the realtime UI check.
func (s *Service) PinAvailable(ctx context.Context, tenantID, pin, exceptUserID string) (bool, error) {
	if tenantID == "" {
		return false, ErrMemberNotFound
	}
	if !pinPattern.MatchString(pin) {
		return false, nil
	}
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return false, fmt.Errorf("load tenant: %w", err)
	}
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.TenantID(tenantID), tenantuser.StatusNEQ("suspended")).
		All(ctx)
	if err != nil {
		return false, err
	}
	tc := tenantclient.New(s.db, t.SchemaName)
	defer tc.Close()
	for _, m := range memberships {
		if m.UserID == exceptUserID {
			continue
		}
		p, perr := tc.UserProfile.Get(ctx, m.UserID)
		if perr != nil || p.PinHash == "" {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(p.PinHash), []byte(pin)) == nil {
			return false, nil // some other member already uses it
		}
	}
	return true, nil
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

// IsMember reports whether userID is an ACTIVE member of tenantID. Used by /me to
// re-check membership on every call: a JWT stays valid until it expires, but an
// owner may since have removed (row deleted) or suspended (status="suspended")
// this user — either way IsMember returns false, so /me 401s and the device boots
// them the next time it comes online. A suspended member reactivated later reads
// as a member again, no re-login needed. Returns false (no error) when there's no
// active membership row.
func (s *Service) IsMember(ctx context.Context, tenantID, userID string) (bool, error) {
	if tenantID == "" || userID == "" {
		return false, nil
	}
	return s.entClient.TenantUser.Query().
		Where(
			tenantuser.UserID(userID),
			tenantuser.TenantID(tenantID),
			tenantuser.StatusNEQ("suspended"),
		).
		Exist(ctx)
}

// LoadProfileForTenant loads a profile by tenant id (resolving its schema).
func (s *Service) LoadProfileForTenant(ctx context.Context, tenantID, userID string) (*Profile, error) {
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant: %w", err)
	}
	return s.LoadProfile(ctx, t.SchemaName, userID)
}

// UpdateOwnProfile updates the caller's own PII (name/phone/job title) in the
// tenant schema's user_profiles. Empty fields are left unchanged, so a client
// can patch just one. tenantID/userID come from the verified context — a user
// can only ever edit their own profile.
func (s *Service) UpdateOwnProfile(ctx context.Context, tenantID, userID, fullName, phone, jobTitle string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("load tenant: %w", err)
	}
	tc := tenantclient.New(s.db, t.SchemaName)
	defer tc.Close()
	// Upsert: most members already have a profile row (created at AddMember), but
	// an owner provisioned before profiles existed may not — create one then.
	if exists, _ := tc.UserProfile.Query().Where(userprofile.ID(userID)).Exist(ctx); !exists {
		if _, cerr := tc.UserProfile.Create().
			SetID(userID).
			SetFullName(fullName).
			SetPhone(phone).
			SetJobTitle(jobTitle).
			Save(ctx); cerr != nil {
			return fmt.Errorf("create profile: %w", cerr)
		}
		return nil
	}
	upd := tc.UserProfile.UpdateOneID(userID)
	if fullName != "" {
		upd = upd.SetFullName(fullName)
	}
	if phone != "" {
		upd = upd.SetPhone(phone)
	}
	if jobTitle != "" {
		upd = upd.SetJobTitle(jobTitle)
	}
	_, err = upd.Save(ctx)
	return err
}

// writePinHash hashes pin (or clears it when empty) into the tenant profile.
// Hard-guards uniqueness: a non-empty PIN already used by another active member
// is refused (ErrPinTaken) so unlock-by-PIN always resolves to one staff.
func (s *Service) writePinHash(ctx context.Context, tenantID, userID, pin string) error {
	hash := ""
	if pin != "" {
		if !pinPattern.MatchString(pin) {
			return ErrInvalidPin
		}
		free, err := s.PinAvailable(ctx, tenantID, pin, userID)
		if err != nil {
			return err
		}
		if !free {
			return ErrPinTaken
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
