package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// The owner's token carries the owner system role's permissions (*:*).
func TestLogin_OwnerHasAllPermissions(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, err := svc.Login(context.Background(), auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	claims := decodeClaims(t, res.AccessToken)
	if !contains(claims.Permissions, "*:*") {
		t.Errorf("owner permissions = %v, want to include *:*", claims.Permissions)
	}
}

// contains reports whether s holds v.
func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// A member added with the "member" role gets only that role's permissions.
func TestLogin_MemberPermissions(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "staff@acme.com", Role: "member", Password: "welcome123", FullName: "Staff",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	login, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "staff@acme.com", Password: "welcome123"})
	claims := decodeClaims(t, login.AccessToken)

	want := map[string]bool{"user:read": true, "branch:read": true}
	if len(claims.Permissions) != len(want) {
		t.Fatalf("member permissions = %v, want %v", claims.Permissions, want)
	}
	for _, p := range claims.Permissions {
		if !want[p] {
			t.Errorf("unexpected member permission %q", p)
		}
	}
}

// Refresh re-resolves the membership's current permissions: changing the role's
// permission set is reflected after a refresh (token is short-lived; refresh
// picks up the new grants).
func TestRefresh_ReresolvesPermissions(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	// custom role without branch:write, assigned to a new member
	role, err := svc.CreateRole(ctx, tenantID, "limited", "Limited", []string{"billing:view"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "lim@acme.com", Role: "limited", Password: "welcome123", FullName: "Lim",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	login, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "lim@acme.com", Password: "welcome123"})
	if contains(decodeClaims(t, login.AccessToken).Permissions, "branch:write") {
		t.Fatal("member should not have branch:write before the role grants it")
	}

	// grant branch:write to the role, then refresh — new token reflects it
	if _, err := svc.UpdateRole(ctx, tenantID, role.ID, "", []string{"billing:view", "branch:write"}); err != nil {
		t.Fatalf("update role: %v", err)
	}
	refreshed, err := svc.Refresh(ctx, login.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !contains(decodeClaims(t, refreshed.AccessToken).Permissions, "branch:write") {
		t.Error("refreshed token should reflect the newly granted branch:write")
	}
}

// Platform admin is DB-authoritative: bootstrap grants it to a registered
// user, login reflects it in user_type, and a tenant owner with *:*
// permissions is NOT automatically a platform admin — those are unrelated.
// Revoking clears it immediately for the next login.
func TestPlatformAdmin_BootstrapGrantRevoke(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)

	// owner is a tenant owner (full *:* permission) but NOT a platform admin yet
	res, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := decodeClaims(t, res.AccessToken).UserType; got != "tenant_user" {
		t.Errorf("user_type before bootstrap = %q, want tenant_user", got)
	}

	// bootstrap from env-configured emails only grants existing users
	emails := auth.ParsePlatformAdminEmails("owner@acme.com, nobody-yet@x.com")
	granted, err := auth.SyncPlatformAdminsFromEnv(ctx, pg.EntClient, emails)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if granted != 1 {
		t.Errorf("granted = %d, want 1 (only the registered email)", granted)
	}
	res2, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if got := decodeClaims(t, res2.AccessToken).UserType; got != "platform_admin" {
		t.Errorf("user_type after bootstrap = %q, want platform_admin", got)
	}

	// re-running bootstrap doesn't double-count (only WHERE is_platform_admin=false matches)
	if granted2, _ := auth.SyncPlatformAdminsFromEnv(ctx, pg.EntClient, emails); granted2 != 0 {
		t.Errorf("second bootstrap granted = %d, want 0 (already set)", granted2)
	}

	// GrantPlatformAdmin promotes another existing user immediately
	if err := svc.AddMember(ctx, decodeClaims(t, res.AccessToken).TenantID, mainBranchID(t, ctx, svc, decodeClaims(t, res.AccessToken).TenantID), auth.AddMemberInput{
		Email: "staff@acme.com", Role: "member", Password: "welcome123", FullName: "Staff",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if _, err := svc.GrantPlatformAdmin(ctx, "staff@acme.com"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	staffLogin, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "staff@acme.com", Password: "welcome123"})
	if got := decodeClaims(t, staffLogin.AccessToken).UserType; got != "platform_admin" {
		t.Errorf("staff user_type after grant = %q, want platform_admin", got)
	}

	// ListPlatformAdmins reflects both
	admins, err := svc.ListPlatformAdmins(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(admins) != 2 {
		t.Errorf("admins = %v, want 2", admins)
	}

	// RevokePlatformAdmin takes effect on the next login, immediately
	if err := svc.RevokePlatformAdmin(ctx, "owner@acme.com"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	res3, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if got := decodeClaims(t, res3.AccessToken).UserType; got != "tenant_user" {
		t.Errorf("user_type after revoke = %q, want tenant_user", got)
	}

	// granting an email with no account fails (no user to flag)
	if _, err := svc.GrantPlatformAdmin(ctx, "ghost@x.com"); err == nil {
		t.Error("granting a nonexistent user should fail")
	}
}

func mainBranchID(t *testing.T, ctx context.Context, svc *auth.Service, tenantID string) string {
	t.Helper()
	branches, err := svc.ListBranches(ctx, tenantID)
	if err != nil || len(branches) == 0 {
		t.Fatalf("list branches: %v", err)
	}
	return branches[0].ID
}

// Baseline floor: a member whose role has no permissions still gets the neutral
// read-only baseline (user:read, branch:read) in their token.
func TestLogin_BaselineFloor(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	// a custom role with NO permissions
	if _, err := svc.CreateRole(ctx, tenantID, "nobody", "Nobody", []string{}); err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "nobody@acme.com", Role: "nobody", Password: "welcome123", FullName: "Nob",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	login, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "nobody@acme.com", Password: "welcome123"})
	perms := decodeClaims(t, login.AccessToken).Permissions
	if !contains(perms, "user:read") || !contains(perms, "branch:read") {
		t.Errorf("permissionless role should still carry the baseline, got %v", perms)
	}
}

// Cross-tenant isolation: an owner of tenant A cannot add members to, or assign
// roles within, tenant B; and tenant B's custom role is invisible to tenant A.
func TestRBAC_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "alpha", "owner@alpha.com")
	registerTenant(t, pg, "beta", "owner@beta.com")

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)

	alpha := decodeClaims(t, mustLogin(t, svc, "alpha", "owner@alpha.com").AccessToken).TenantID
	beta := decodeClaims(t, mustLogin(t, svc, "beta", "owner@beta.com").AccessToken).TenantID

	alphaBranches, _ := svc.ListBranches(ctx, alpha)
	betaBranches, _ := svc.ListBranches(ctx, beta)

	// beta makes a custom role
	betaRole, err := svc.CreateRole(ctx, beta, "betacustom", "Beta Custom", []string{"user:read"})
	if err != nil {
		t.Fatalf("beta create role: %v", err)
	}

	// alpha cannot list beta's custom role
	alphaRoles, _ := svc.ListRoles(ctx, alpha)
	for _, r := range alphaRoles {
		if r.ID == betaRole.ID {
			t.Fatal("alpha can see beta's custom role — tenant isolation broken")
		}
	}

	// alpha cannot use beta's branch id (branch lookup is tenant-scoped)
	if err := svc.AddMember(ctx, alpha, betaBranches[0].ID, auth.AddMemberInput{
		Email: "x@x.com", Role: "member", Password: "p", FullName: "X",
	}); err == nil {
		t.Error("alpha adding a member to beta's branch should fail")
	}

	// alpha cannot assign beta's custom role slug (it resolves only within a tenant)
	if err := svc.AddMember(ctx, alpha, alphaBranches[0].ID, auth.AddMemberInput{
		Email: "y@x.com", Role: "betacustom", Password: "p", FullName: "Y",
	}); err == nil {
		t.Error("alpha assigning beta's custom role should fail")
	}

	// alpha cannot update or delete beta's custom role
	if _, err := svc.UpdateRole(ctx, alpha, betaRole.ID, "Hijacked", nil); err == nil {
		t.Error("alpha updating beta's role should fail")
	}
	if err := svc.DeleteRole(ctx, alpha, betaRole.ID); err == nil {
		t.Error("alpha deleting beta's role should fail")
	}
}

// AddMember rejects an unknown role slug rather than silently defaulting.
func TestAddMember_UnknownRoleRejected(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "z@acme.com", Role: "nonexistent-role", Password: "p", FullName: "Z",
	}); err == nil {
		t.Error("adding a member with an unknown role should fail")
	}
}

func mustLogin(t *testing.T, svc *auth.Service, slug, email string) *auth.LoginResult {
	t.Helper()
	res, err := svc.Login(context.Background(), auth.LoginInput{Slug: slug, Email: email, Password: "secret123"})
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return res
}

// A tenant custom role can be created, assigned, and its permissions flow into
// the member's token. System roles cannot be modified or deleted.
func TestRoles_CustomRoleLifecycle(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	// create a custom "auditor" role
	role, err := svc.CreateRole(ctx, tenantID, "auditor", "Auditor", []string{"user:read", "billing:view"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	// duplicate slug (and system-role slug) rejected
	if _, err := svc.CreateRole(ctx, tenantID, "auditor", "Dup", []string{"user:read"}); err == nil {
		t.Error("duplicate role slug should be rejected")
	}
	if _, err := svc.CreateRole(ctx, tenantID, "owner", "Fake", []string{"user:read"}); err == nil {
		t.Error("clashing with a system role slug should be rejected")
	}

	// assign it to a new member; their token carries the custom permissions
	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "auditor@acme.com", Role: "auditor", Password: "welcome123", FullName: "Aud",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	login, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "auditor@acme.com", Password: "welcome123"})
	claims := decodeClaims(t, login.AccessToken)
	if claims.Roles[0] != "auditor" {
		t.Errorf("role = %v, want auditor", claims.Roles)
	}

	// cannot delete a role still in use
	if err := svc.DeleteRole(ctx, tenantID, role.ID); err == nil {
		t.Error("deleting an in-use role should fail")
	}

	// system roles are immutable
	systemRoles, _ := svc.ListRoles(ctx, tenantID)
	var ownerID string
	for _, r := range systemRoles {
		if r.Slug == "owner" {
			ownerID = r.ID
		}
	}
	if _, err := svc.UpdateRole(ctx, tenantID, ownerID, "Hacked", nil); err == nil {
		t.Error("updating a system role should fail")
	}
}
