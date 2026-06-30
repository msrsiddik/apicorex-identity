package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// decodeClaims parses an access token with the test secret and returns its claims.
func decodeClaims(t *testing.T, token string) *auth.Claims {
	t.Helper()
	var claims auth.Claims
	_, err := jwt.ParseWithClaims(token, &claims, func(*jwt.Token) (any, error) {
		return []byte("test-secret"), nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return &claims
}

// Registration creates a default "main" branch; login lands the owner on it and
// the access token carries the branch claim.
func TestLogin_LandsOnDefaultBranch(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil, pg.RBAC)

	res, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	claims := decodeClaims(t, res.AccessToken)
	if claims.BranchSlug != "main" {
		t.Errorf("expected branch_slug=main, got %q", claims.BranchSlug)
	}
	if claims.BranchID == "" {
		t.Error("expected a branch_id claim")
	}
}

// Listing branches returns the default branch; creating a second branch, adding
// the owner to it, and switching scopes a new token to that branch.
func TestBranch_CreateSwitch(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil, pg.RBAC)

	// owner's user id + tenant id via an initial login
	res, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	main := decodeClaims(t, res.AccessToken)
	tenantID, userID := main.TenantID, main.Subject

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
	if _, err := svc.SwitchBranch(ctx, userID, tenantID, b.ID); err == nil {
		t.Fatal("switch to a branch without membership should fail")
	}

	// add the owner to it, then switch succeeds and the token reflects the branch
	if err := svc.AddMember(ctx, tenantID, b.ID, auth.AddMemberInput{Email: "owner@acme.com", Role: "admin"}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	sw, err := svc.SwitchBranch(ctx, userID, tenantID, b.ID)
	if err != nil {
		t.Fatalf("switch: %v", err)
	}
	got := decodeClaims(t, sw.AccessToken)
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

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil, pg.RBAC)

	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID
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
	claims := decodeClaims(t, login.AccessToken)
	if claims.BranchSlug != "main" || claims.Roles[0] != "member" {
		t.Errorf("expected main/member, got %s/%v", claims.BranchSlug, claims.Roles)
	}
}

// A user cannot switch to a branch in a tenant they don't belong to, even with a
// valid branch id from another tenant.
func TestBranch_SwitchCrossTenantRejected(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "alpha", "owner@alpha.com")
	registerTenant(t, pg, "beta", "owner@beta.com")

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)

	a := decodeClaims(t, mustLogin(t, svc, "alpha", "owner@alpha.com").AccessToken)
	betaTenant := decodeClaims(t, mustLogin(t, svc, "beta", "owner@beta.com").AccessToken).TenantID
	betaBranches, _ := svc.ListBranches(ctx, betaTenant)

	// alpha's owner tries to switch into beta's branch, scoped to alpha's tenant
	if _, err := svc.SwitchBranch(ctx, a.Subject, a.TenantID, betaBranches[0].ID); err == nil {
		t.Error("switching to another tenant's branch should fail")
	}
}

// Branch slug must be unique within a tenant.
func TestBranch_DuplicateSlugRejected(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil, pg.RBAC)

	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID

	if _, err := svc.CreateBranch(ctx, tenantID, "main", "Another Main"); err == nil {
		t.Fatal("creating a branch with an existing slug should fail")
	}
}
