package auth_test

import (
	"context"
	"testing"

	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// introspect resolves a raw device token as Core would (acting user = the
// token's owner) and returns the request identity.
func introspect(t *testing.T, svc *auth.Service, raw string) *auth.IntrospectResult {
	t.Helper()
	res, err := svc.Introspect(context.Background(), auth.HashToken(raw), "")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	return res
}

// newService builds the auth service under test.
func newService(pg *testutil.PG) *auth.Service {
	return auth.NewService(pg.EntClient, pg.DB, pg.RBAC, nil)
}

// Registration creates a default "main" branch; login lands the owner on it and
// introspection reflects the branch scope.
func TestLogin_LandsOnDefaultBranch(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	res, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	id := introspect(t, svc, res.Token)
	if id.BranchSlug != "main" {
		t.Errorf("expected branch_slug=main, got %q", id.BranchSlug)
	}
	if id.BranchID == "" {
		t.Error("expected a branch_id")
	}
}

// Listing branches returns the default branch; creating a second branch, adding
// the owner to it, and switching re-scopes the SAME device token to that branch.
func TestBranch_CreateSwitch(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	// owner's user id + tenant id via an initial login
	res, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	main := introspect(t, svc, res.Token)
	tenantID, userID := main.TenantID, main.UserID
	tokenHash := auth.HashToken(res.Token)

	// only the default branch so far
	branches, err := svc.ListBranches(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(branches) != 1 || branches[0].Slug != "main" {
		t.Fatalf("expected only main branch, got %+v", branches)
	}

	// create a second branch
	b, err := svc.CreateBranch(ctx, tenantID, "dhaka", "Dhaka Office")
	if err != nil {
		t.Fatalf("create branch: %v", err)
	}

	// owner is not a member of the new branch yet → switch must fail
	if _, err := svc.SwitchBranch(ctx, userID, tenantID, b.ID, tokenHash); err == nil {
		t.Fatal("switch to a branch without membership should fail")
	}

	// add the owner to it, then switch succeeds and the SAME token now
	// introspects to the new branch
	if err := svc.AddMember(ctx, tenantID, b.ID, auth.AddMemberInput{Email: "owner@acme.com", Role: "admin"}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	sw, err := svc.SwitchBranch(ctx, userID, tenantID, b.ID, tokenHash)
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	if sw.Slug != "dhaka" {
		t.Errorf("switch should return the new branch, got %+v", sw)
	}
	got := introspect(t, svc, res.Token)
	if got.BranchSlug != "dhaka" {
		t.Errorf("expected branch_slug=dhaka after switch, got %q", got.BranchSlug)
	}
	if got.Roles == nil || got.Roles[0] != "admin" {
		t.Errorf("expected admin role on dhaka branch, got %v", got.Roles)
	}
}

// Admin-create: adding a brand-new email with a password creates the global
// user, who can then log in and lands on the branch they were added to.
func TestBranch_AddMemberCreatesUser(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := introspect(t, svc, res.Token).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)
	mainID := branches[0].ID

	// new email without a password is rejected
	if err := svc.AddMember(ctx, tenantID, mainID, auth.AddMemberInput{Email: "new@acme.com"}); err == nil {
		t.Fatal("creating a new user without a password should fail")
	}

	// with a password the user is created and can log in
	if err := svc.AddMember(ctx, tenantID, mainID, auth.AddMemberInput{
		Email: "new@acme.com", Role: "member", Password: "welcome123", FullName: "New Member",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	login, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "new@acme.com", Password: "welcome123"})
	if err != nil {
		t.Fatalf("new member login: %v", err)
	}
	id := introspect(t, svc, login.Token)
	if id.BranchSlug != "main" || id.Roles[0] != "member" {
		t.Errorf("expected main/member, got %s/%v", id.BranchSlug, id.Roles)
	}
}

// A user cannot switch to a branch in a tenant they don't belong to, even with a
// valid branch id from another tenant.
func TestBranch_SwitchCrossTenantRejected(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "alpha", "owner@alpha.com")
	registerTenant(t, pg, "beta", "owner@beta.com")

	svc := newService(pg)

	alphaLogin := mustLogin(t, svc, "alpha", "owner@alpha.com")
	a := introspect(t, svc, alphaLogin.Token)
	betaTenant := introspect(t, svc, mustLogin(t, svc, "beta", "owner@beta.com").Token).TenantID
	betaBranches, _ := svc.ListBranches(ctx, betaTenant)

	// alpha's owner tries to switch into beta's branch, scoped to alpha's tenant
	if _, err := svc.SwitchBranch(ctx, a.UserID, a.TenantID, betaBranches[0].ID, auth.HashToken(alphaLogin.Token)); err == nil {
		t.Error("switching to another tenant's branch should fail")
	}
}

// Branch slug must be unique within a tenant.
func TestBranch_DuplicateSlugRejected(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := introspect(t, svc, res.Token).TenantID

	if _, err := svc.CreateBranch(ctx, tenantID, "main", "Another Main"); err == nil {
		t.Fatal("creating a branch with an existing slug should fail")
	}
}
