package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

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
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)
	_, err := saga.Register(context.Background(), tenant.RegisterInput{
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

	svc := newService(pg)

	res, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Token == "" || !strings.HasPrefix(res.Token, "zdt_") {
		t.Fatalf("login should return an opaque zdt_ device token, got %q", res.Token)
	}
	// the token resolves to the owner with a full identity
	id := introspect(t, svc, res.Token)
	if id.TenantSlug != "acme" || id.UserID == "" {
		t.Errorf("introspect after login = %+v", id)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	if _, err := svc.Login(context.Background(), auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "wrong",
	}); err == nil {
		t.Fatal("wrong password should fail")
	}
}

// Logout revokes the device token; introspection rejects it afterwards, and an
// unknown/garbage hash never resolves.
func TestLogout_RevokesDeviceToken(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)

	res, err := svc.Login(ctx, auth.LoginInput{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	// valid before logout
	introspect(t, svc, res.Token)

	// garbage token never resolves
	if _, err := svc.Introspect(ctx, auth.HashToken("zdt_garbage"), ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("garbage token introspect err = %v, want ErrInvalidToken", err)
	}

	if err := svc.Logout(ctx, auth.HashToken(res.Token)); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Introspect(ctx, auth.HashToken(res.Token), ""); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("introspect after logout err = %v, want ErrInvalidToken", err)
	}
}

// A user in multiple tenants must supply a slug; without it, login returns the
// tenant chooser. With a slug, it succeeds and scopes the token to that tenant.
func TestLogin_MultiTenantRequiresSlug(t *testing.T) {
	pg := testutil.NewPostgres(t)
	registerTenant(t, pg, "alpha", "multi@x.com")
	registerTenant(t, pg, "beta", "multi@x.com")

	svc := newService(pg)

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

	svc := newService(pg)

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

	svc := newService(pg)

	tn, _ := pg.EntClient.Tenant.Query().Only(context.Background())
	plugins := svc.InstalledPlugins(context.Background(), tn.ID)

	// identity is always present
	if len(plugins) == 0 || plugins[0] != "identity" {
		t.Errorf("expected identity first, got %v", plugins)
	}
}
