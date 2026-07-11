package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/plugininstall"
	"github.com/msrsiddik/apicorex-identity/ent/refreshtoken"
	"github.com/msrsiddik/apicorex-identity/ent/tenant"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/internal/rbac"
	"github.com/msrsiddik/apicorex-identity/internal/tenantclient"
	"golang.org/x/crypto/bcrypt"
)

const refreshTokenTTL = 7 * 24 * time.Hour

// ErrMultipleTenants is returned by Login when the credentials are valid but the
// user belongs to more than one tenant and no slug was supplied. The handler
// surfaces a tenant chooser. The available tenants are carried in TenantOptions.
var ErrMultipleTenants = errors.New("multiple tenants: slug required")

// TenantOption is one entry in a tenant chooser.
type TenantOption struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// MultiTenantError carries the chooser list alongside ErrMultipleTenants.
type MultiTenantError struct {
	Tenants []TenantOption
}

func (e *MultiTenantError) Error() string { return ErrMultipleTenants.Error() }
func (e *MultiTenantError) Unwrap() error { return ErrMultipleTenants }

// LoginInput is the credentials for a login attempt. Slug is optional; if empty
// and the user belongs to multiple tenants, Login returns ErrMultipleTenants.
type LoginInput struct {
	Slug     string
	Email    string
	Password string
}

// LoginResult is a freshly issued token pair.
type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

// Service implements the authentication flows: login, token refresh (with
// rotation), and logout.
type Service struct {
	entClient *ent.Client
	db        *sql.DB
	issuer    *Issuer
	denylist  *Denylist // optional (nil if REDIS_URL unset)
	rbac      *rbac.Store
}

// NewService builds the auth Service. denylist may be nil to disable access-token
// revocation on logout.
func NewService(entClient *ent.Client, db *sql.DB, issuer *Issuer, denylist *Denylist, rbacStore *rbac.Store) *Service {
	return &Service{entClient: entClient, db: db, issuer: issuer, denylist: denylist, rbac: rbacStore}
}

// Login verifies the global credential (shared.users), resolves which tenant the
// user is acting as (via shared.tenant_users + the optional slug), and issues a
// token scoped to that tenant with the membership role. Returns ErrMultipleTenants
// (a *MultiTenantError) when the user has several tenants and no slug was given.
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	// 1. global credential
	u, err := s.entClient.User.Query().Where(entuser.Email(in.Email)).Only(ctx)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(in.Password)); err != nil {
		return nil, errors.New("invalid credentials")
	}

	// 2. memberships (exactly one row per tenant — the user's single active branch there)
	memberships, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(u.ID)).
		Order(ent.Asc(tenantuser.FieldCreatedAt)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("load memberships: %w", err)
	}
	if len(memberships) == 0 {
		return nil, errors.New("no tenant access")
	}

	// 3. pick the tenant.
	var t *ent.Tenant
	tenantIDs := distinctTenantIDs(memberships)
	switch {
	case in.Slug != "":
		t, err = s.entClient.Tenant.Query().
			Where(tenant.Slug(in.Slug), tenant.Status("active")).Only(ctx)
		if err != nil {
			return nil, errors.New("tenant not found")
		}
		if !contains(tenantIDs, t.ID) {
			return nil, errors.New("no access to tenant")
		}
	case len(tenantIDs) == 1:
		t, err = s.entClient.Tenant.Get(ctx, tenantIDs[0])
		if err != nil || t.Status != "active" {
			return nil, errors.New("tenant not available")
		}
	default:
		return nil, s.multiTenantError(ctx, tenantIDs)
	}

	// 4. the membership for this tenant carries the user's current branch.
	m := membershipForTenant(memberships, t.ID)
	if m == nil {
		return nil, errors.New("no access to tenant")
	}
	var b *ent.Branch
	if m.BranchID != "" {
		if b, err = s.entClient.Branch.Get(ctx, m.BranchID); err != nil {
			return nil, errors.New("branch not available")
		}
	}

	return s.issueTokens(ctx, u, t, b, m.RoleID)
}

// Refresh exchanges a valid refresh token for a new token pair, rotating the
// refresh token (the old one is revoked). The membership role is re-loaded so
// the new access token reflects current access.
func (s *Service) Refresh(ctx context.Context, tokenID string) (*LoginResult, error) {
	rt, err := s.entClient.RefreshToken.Query().
		Where(refreshtoken.ID(tokenID), refreshtoken.Revoked(false)).
		Only(ctx)
	if err != nil || rt.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("invalid or expired refresh token")
	}

	t, err := s.entClient.Tenant.Get(ctx, rt.TenantID)
	if err != nil {
		return nil, errors.New("tenant not found")
	}
	u, err := s.entClient.User.Get(ctx, rt.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// re-load the membership: role and current branch are re-read fresh (not
	// trusted from the old token), since the user may have switched branches or
	// had their role changed since this refresh token was issued.
	m, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(u.ID), tenantuser.TenantID(t.ID)).Only(ctx)
	if err != nil {
		return nil, errors.New("no access to tenant")
	}

	var b *ent.Branch
	if m.BranchID != "" {
		if b, err = s.entClient.Branch.Get(ctx, m.BranchID); err != nil {
			return nil, errors.New("branch not available")
		}
	}

	res, err := s.issueTokens(ctx, u, t, b, m.RoleID)
	if err != nil {
		return nil, err
	}
	// rotate: revoke the old refresh token
	s.entClient.RefreshToken.UpdateOneID(rt.ID).SetRevoked(true).Exec(ctx) //nolint:errcheck
	return res, nil
}

// issueTokens mints an access token (scoped to tenant t / branch b with the
// membership's role) plus a refresh token carrying the same branch. b may be nil
// for a tenant-only token. roleID resolves to the role slug (Roles claim) and
// its flattened permission set (Permissions claim).
func (s *Service) issueTokens(ctx context.Context, u *ent.User, t *ent.Tenant, b *ent.Branch, roleID string) (*LoginResult, error) {
	userType := "tenant_user"
	if u.IsPlatformAdmin {
		userType = "platform_admin"
	}

	roles, permissions, err := s.resolveRole(ctx, roleID)
	if err != nil {
		return nil, err
	}

	claims := Claims{
		RegisteredClaims: jwtRegisteredClaims(u.ID),
		TenantID:         t.ID,
		TenantSlug:       t.Slug,
		SchemaName:       t.SchemaName,
		UserType:         userType,
		Roles:            roles,
		Permissions:      permissions,
	}
	branchID := ""
	if b != nil {
		claims.BranchID = b.ID
		claims.BranchSlug = b.Slug
		branchID = b.ID
	}

	accessToken, err := s.issuer.Issue(claims)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	rt, err := s.entClient.RefreshToken.Create().
		SetID(uuid.New().String()).
		SetUserID(u.ID).
		SetTenantID(t.ID).
		SetBranchID(branchID).
		SetExpiresAt(time.Now().Add(refreshTokenTTL)).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}
	return &LoginResult{AccessToken: accessToken, RefreshToken: rt.ID}, nil
}

// resolveRole turns a role_id into the role slug (Roles claim) and its flattened
// permission set (Permissions claim). The baseline floor is always merged in, so
// every authenticated user — even one whose role has no permissions, or no role
// at all — holds at least the neutral read-only baseline.
func (s *Service) resolveRole(ctx context.Context, roleID string) (roles, permissions []string, err error) {
	if roleID == "" {
		return []string{}, rbac.WithBaseline(nil), nil
	}
	r, err := s.entClient.Role.Get(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("load role: %w", err)
	}
	perms, err := s.rbac.Permissions(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("load permissions: %w", err)
	}
	return []string{r.Slug}, rbac.WithBaseline(perms), nil
}

func (s *Service) multiTenantError(ctx context.Context, tenantIDs []string) error {
	opts := make([]TenantOption, 0, len(tenantIDs))
	for _, id := range tenantIDs {
		if t, err := s.entClient.Tenant.Get(ctx, id); err == nil {
			opts = append(opts, TenantOption{Slug: t.Slug, Name: t.Name})
		}
	}
	return &MultiTenantError{Tenants: opts}
}

// distinctTenantIDs returns the unique tenant IDs across memberships, preserving
// first-seen order (memberships may hold several branch rows per tenant).
func distinctTenantIDs(ms []*ent.TenantUser) []string {
	seen := make(map[string]bool, len(ms))
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		if !seen[m.TenantID] {
			seen[m.TenantID] = true
			ids = append(ids, m.TenantID)
		}
	}
	return ids
}

func contains(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// membershipForTenant returns the user's (single) membership row for a tenant.
func membershipForTenant(ms []*ent.TenantUser, tenantID string) *ent.TenantUser {
	for _, m := range ms {
		if m.TenantID == tenantID {
			return m
		}
	}
	return nil
}

// Profile holds the tenant-scoped PII returned by /me.
type Profile struct {
	FullName   string
	Phone      string
	JobTitle   string
	SystemRole string
	// PinHash is the bcrypt hash of the device-unlock PIN (empty = none set).
	// Only ever returned to the user themselves (via /me) so their device can
	// cache it for offline unlock — never to other members.
	PinHash string
}

// LoadProfile reads a user's PII profile from the tenant schema's user_profiles.
func (s *Service) LoadProfile(ctx context.Context, schemaName, userID string) (*Profile, error) {
	tc := tenantclient.New(s.db, schemaName)
	defer tc.Close()
	p, err := tc.UserProfile.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &Profile{
		FullName:   p.FullName,
		Phone:      p.Phone,
		JobTitle:   p.JobTitle,
		SystemRole: p.SystemRole,
		PinHash:    p.PinHash,
	}, nil
}

// InstalledPlugins returns the live list of installed plugins for a tenant (used by /me).
func (s *Service) InstalledPlugins(ctx context.Context, tenantID string) []string {
	installs, _ := s.entClient.PluginInstall.Query().
		Where(plugininstall.TenantID(tenantID)).All(ctx)
	plugins := make([]string, 0, len(installs)+1)
	plugins = append(plugins, "identity")
	for _, pi := range installs {
		if pi.PluginName != "identity" {
			plugins = append(plugins, pi.PluginName)
		}
	}
	return plugins
}

// Logout revokes the refresh token and, if a denylist is configured, revokes the
// access token by its jti until it would have expired.
func (s *Service) Logout(ctx context.Context, refreshTokenID, accessJTI string, accessExp time.Time) error {
	if refreshTokenID != "" {
		s.entClient.RefreshToken.UpdateOneID(refreshTokenID).SetRevoked(true).Exec(ctx) //nolint:errcheck
	}
	if s.denylist != nil && accessJTI != "" {
		ttl := time.Until(accessExp)
		if err := s.denylist.Revoke(ctx, accessJTI, ttl); err != nil {
			return fmt.Errorf("denylist revoke: %w", err)
		}
	}
	return nil
}
