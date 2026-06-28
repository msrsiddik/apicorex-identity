package auth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

type noopInstaller struct{}

func (noopInstaller) InstallForNewTenant(context.Context, string, string) error { return nil }

// registerTenant provisions a tenant + owner with the given slug/email.
func registerTenant(t *testing.T, pg *testutil.PG, slug, email string) {
	t.Helper()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{})
	err := saga.Register(context.Background(), tenant.RegisterInput{
		Slug: slug, Name: slug, Plan: "starter",
		OwnerEmail: email, OwnerPassword: "secret123",
		OwnerFullName: "Ada", OwnerPhone: "+100", OwnerJobTitle: "CEO",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
}

// register provisions the default acme/owner tenant.
func register(t *testing.T, pg *testutil.PG) {
	registerTenant(t, pg, "acme", "owner@acme.com")
}

func TestLogin_Success(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil)

	res, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.AccessToken == "" || res.RefreshToken == "" {
		t.Fatal("login should return both tokens")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil)

	if _, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "wrong",
	}); err == nil {
		t.Fatal("wrong password should fail")
	}
}

func TestLogin_RefreshRotates(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil)

	res, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// refresh with the valid token succeeds
	if _, err := svc.Refresh(context.Background(), res.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	// the old refresh token is now revoked (rotation)
	if _, err := svc.Refresh(context.Background(), res.RefreshToken); err == nil {
		t.Fatal("the rotated (old) refresh token should be rejected")
	}
}

// A user in multiple tenants must supply a slug; without it, login returns the
// tenant chooser. With a slug, it succeeds and scopes the token to that tenant.
func TestLogin_MultiTenantRequiresSlug(t *testing.T) {
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "alpha", "multi@x.com")
	registerTenant(t, pg, "beta", "multi@x.com")

	issuer := auth.NewIssuer("test-secret", 15*time.Minute)
	svc := auth.NewService(pg.EntClient, pg.DB, issuer, nil)

	// no slug → chooser error with both tenants
	_, err := svc.Login(context.Background(), auth.LoginInput{
		Email: "multi@x.com", Password: "secret123",
	})
	var mt *auth.MultiTenantError
	if !errors.As(err, &mt) {
		t.Fatalf("expected MultiTenantError, got %v", err)
	}
	if len(mt.Tenants) != 2 {
		t.Errorf("chooser should list 2 tenants, got %d", len(mt.Tenants))
	}

	// with slug → success
	if _, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "beta", Email: "multi@x.com", Password: "secret123",
	}); err != nil {
		t.Fatalf("login with slug should succeed: %v", err)
	}
}

func TestLoadProfile(t *testing.T) {
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "acme", "owner@acme.com")

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", time.Minute), nil)

	// the owner's user_id comes from the global users table
	u, err := pg.EntClient.User.Query().Where(entuser.Email("owner@acme.com")).Only(context.Background())
	if err != nil {
		t.Fatalf("user lookup: %v", err)
	}

	p, err := svc.LoadProfile(context.Background(), "tenant_acme", u.ID)
	if err != nil {
		t.Fatalf("LoadProfile: %v", err)
	}
	if p.FullName != "Ada" || p.Phone != "+100" || p.JobTitle != "CEO" {
		t.Errorf("profile mismatch: %+v", p)
	}
	if p.SystemRole != "owner" {
		t.Errorf("system_role = %q, want owner", p.SystemRole)
	}
}

func TestInstalledPlugins(t *testing.T) {
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "acme", "owner@acme.com")

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", time.Minute), nil)

	tn, _ := pg.EntClient.Tenant.Query().Only(context.Background())
	plugins := svc.InstalledPlugins(context.Background(), tn.ID)

	// identity is always present
	if len(plugins) == 0 || plugins[0] != "identity" {
		t.Errorf("expected identity first, got %v", plugins)
	}
}
