package tenant_test

import (
	"context"
	"errors"
	"testing"

	enttenant "github.com/msrsiddik/apicorex-identity/ent/tenant"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// noopInstaller satisfies tenant.PluginInstaller for tests (no plugins installed).
type noopInstaller struct{}

func (noopInstaller) InstallForNewTenant(context.Context, string, string) error { return nil }

// failingInstaller forces step 6 (plugin install) to fail, triggering compensation.
type failingInstaller struct{}

func (failingInstaller) InstallForNewTenant(context.Context, string, string) error {
	return errors.New("boom")
}

func ownerInput(slug, email string) tenant.RegisterInput {
	return tenant.RegisterInput{
		Slug: slug, Name: slug + " Corp", Plan: "starter",
		OwnerEmail: email, OwnerPassword: "secret123",
		OwnerFullName: "Ada Owner", OwnerPhone: "+10000000000", OwnerJobTitle: "CEO",
	}
}

func TestSaga_Register(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)
	if _, err := saga.Register(ctx, ownerInput("acme", "owner@acme.com")); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// tenant row exists and is active
	tn, err := pg.EntClient.Tenant.Query().Where(enttenant.Slug("acme")).Only(ctx)
	if err != nil {
		t.Fatalf("tenant not found: %v", err)
	}
	if tn.Status != "active" {
		t.Errorf("tenant status = %q, want active", tn.Status)
	}
	if tn.SchemaName != "tenant_acme" {
		t.Errorf("schema_name = %q, want tenant_acme", tn.SchemaName)
	}

	// global credential created once (shared.users)
	u, err := pg.EntClient.User.Query().Where(entuser.Email("owner@acme.com")).Only(ctx)
	if err != nil {
		t.Fatalf("global user not found: %v", err)
	}

	// membership row scoped to the owner system role (shared.tenant_users)
	m, err := pg.EntClient.TenantUser.Query().
		Where(tenantuser.UserID(u.ID), tenantuser.TenantID(tn.ID)).Only(ctx)
	if err != nil {
		t.Fatalf("membership not found: %v", err)
	}
	r, err := pg.EntClient.Role.Get(ctx, m.RoleID)
	if err != nil {
		t.Fatalf("membership role not found: %v", err)
	}
	if r.Slug != "owner" {
		t.Errorf("membership role = %q, want owner", r.Slug)
	}

	// PII profile created in the tenant schema, keyed by user_id (no password here)
	var profiles int
	if err := pg.DB.QueryRow(
		`SELECT count(*) FROM tenant_acme.user_profiles WHERE user_id=$1`, u.ID,
	).Scan(&profiles); err != nil {
		t.Fatalf("query user_profiles: %v", err)
	}
	if profiles != 1 {
		t.Errorf("profile count = %d, want 1", profiles)
	}
}

func TestSaga_DuplicateSlugFails(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	in := ownerInput("dup", "o@dup.com")
	if _, err := saga.Register(ctx, in); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if _, err := saga.Register(ctx, in); err == nil {
		t.Fatal("registering a duplicate slug should fail")
	}
}

// A user with the same email registering a second, different tenant reuses the
// global account (one shared.users row, two memberships).
func TestSaga_SameEmailDifferentTenant(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	if _, err := saga.Register(ctx, ownerInput("first", "multi@x.com")); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if _, err := saga.Register(ctx, ownerInput("second", "multi@x.com")); err != nil {
		t.Fatalf("second register (same email): %v", err)
	}

	// exactly one global user
	if n, _ := pg.EntClient.User.Query().Where(entuser.Email("multi@x.com")).Count(ctx); n != 1 {
		t.Errorf("global user count = %d, want 1 (reused)", n)
	}
	// two memberships
	u, _ := pg.EntClient.User.Query().Where(entuser.Email("multi@x.com")).Only(ctx)
	if n, _ := pg.EntClient.TenantUser.Query().Where(tenantuser.UserID(u.ID)).Count(ctx); n != 2 {
		t.Errorf("membership count = %d, want 2", n)
	}
}

// When a later step fails, the saga must roll back everything: no tenant row, no
// global user, no membership, and the tenant schema dropped.
func TestSaga_RollbackOnFailure(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	// failingInstaller makes step 6 fail after tenant, user, membership, schema,
	// and profile have been created — exercising full compensation.
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, failingInstaller{}, pg.RBAC)
	_, err := saga.Register(ctx, ownerInput("rollme", "rollback@x.com"))
	if err == nil {
		t.Fatal("expected Register to fail (installer boom)")
	}

	// tenant row gone
	if n, _ := pg.EntClient.Tenant.Query().Where(enttenant.Slug("rollme")).Count(ctx); n != 0 {
		t.Errorf("tenant row not rolled back, count=%d", n)
	}
	// global user gone (it was created in this saga)
	if n, _ := pg.EntClient.User.Query().Where(entuser.Email("rollback@x.com")).Count(ctx); n != 0 {
		t.Errorf("user not rolled back, count=%d", n)
	}
	// membership gone
	if n, _ := pg.EntClient.TenantUser.Query().All(ctx); len(n) != 0 {
		t.Errorf("memberships not rolled back, count=%d", len(n))
	}
	// tenant schema dropped
	var schemas int
	pg.DB.QueryRow(
		`SELECT count(*) FROM information_schema.schemata WHERE schema_name=$1`, "tenant_rollme",
	).Scan(&schemas)
	if schemas != 0 {
		t.Errorf("tenant schema not dropped, count=%d", schemas)
	}
}

// A pre-existing global account that fails a later step must NOT be deleted by
// compensation (we only delete the user if this saga created it).
func TestSaga_RollbackKeepsExistingUser(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	// first registration succeeds, creating the global user
	ok := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)
	if _, err := ok.Register(ctx, ownerInput("first", "shared@x.com")); err != nil {
		t.Fatalf("first register: %v", err)
	}

	// second registration (same email) fails at step 6
	bad := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, failingInstaller{}, pg.RBAC)
	if _, err := bad.Register(ctx, ownerInput("second", "shared@x.com")); err == nil {
		t.Fatal("expected second register to fail")
	}

	// the global user must still exist (reused, not created by the failed saga)
	if n, _ := pg.EntClient.User.Query().Where(entuser.Email("shared@x.com")).Count(ctx); n != 1 {
		t.Errorf("existing user should survive failed saga, count=%d", n)
	}
	// only the first tenant's membership remains
	u, _ := pg.EntClient.User.Query().Where(entuser.Email("shared@x.com")).Only(ctx)
	if n, _ := pg.EntClient.TenantUser.Query().Where(tenantuser.UserID(u.ID)).Count(ctx); n != 1 {
		t.Errorf("only first membership should remain, count=%d", n)
	}
}

// Registering without a slug generates one from the name.
func TestSaga_AutoSlugFromName(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	in := tenant.RegisterInput{
		Slug: "", Name: "Globex Industries", Plan: "starter",
		OwnerEmail: "owner@globex.com", OwnerPassword: "secret123", OwnerFullName: "G",
	}
	slug, err := saga.Register(ctx, in)
	if err != nil {
		t.Fatalf("register without slug: %v", err)
	}
	if slug != "globex_industries" {
		t.Errorf("generated slug = %q, want globex_industries", slug)
	}
	if exists, _ := pg.EntClient.Tenant.Query().Where(enttenant.Slug(slug)).Exist(ctx); !exists {
		t.Errorf("tenant with generated slug %q not found", slug)
	}
}

// A generated slug that collides gets a numeric suffix.
func TestSaga_AutoSlugCollision(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	// first registration takes "globex_industries"
	if _, err := saga.Register(ctx, tenant.RegisterInput{
		Name: "Globex Industries", Plan: "starter",
		OwnerEmail: "a@globex.com", OwnerPassword: "secret123", OwnerFullName: "A",
	}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// second, same name, different owner → suffixed slug
	slug, err := saga.Register(ctx, tenant.RegisterInput{
		Name: "Globex Industries", Plan: "starter",
		OwnerEmail: "b@globex.com", OwnerPassword: "secret123", OwnerFullName: "B",
	})
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if slug != "globex_industries_2" {
		t.Errorf("collided slug = %q, want globex_industries_2", slug)
	}
}

// SlugAvailable reflects validity and existing tenants.
func TestSaga_SlugAvailable(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	// free + valid
	if ok, _ := saga.SlugAvailable(ctx, "acme"); !ok {
		t.Error("acme should be available before registration")
	}
	// malformed → not available
	if ok, _ := saga.SlugAvailable(ctx, "Ab"); ok {
		t.Error("malformed slug should not be available")
	}
	// taken → not available
	if _, err := saga.Register(ctx, ownerInput("acme", "owner@acme.com")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if ok, _ := saga.SlugAvailable(ctx, "acme"); ok {
		t.Error("acme should be taken after registration")
	}
}

// SuggestSlug derives a unique, valid slug from a name without registering.
func TestSaga_SuggestSlug(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()
	saga := tenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)

	slug, err := saga.SuggestSlug(ctx, "Wayne Enterprises")
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	if slug != "wayne_enterprises" || tenant.ValidateSlug(slug) != nil {
		t.Errorf("suggested slug = %q, want valid wayne_enterprises", slug)
	}
	// suggesting again returns the same (nothing registered yet)
	if again, _ := saga.SuggestSlug(ctx, "Wayne Enterprises"); again != slug {
		t.Errorf("suggest should be stable until taken: %q vs %q", again, slug)
	}
	// after registering it, suggestion moves to a suffix
	if _, err := saga.Register(ctx, ownerInput("wayne_enterprises", "owner@wayne.com")); err != nil {
		t.Fatalf("register: %v", err)
	}
	next, _ := saga.SuggestSlug(ctx, "Wayne Enterprises")
	if next != "wayne_enterprises_2" {
		t.Errorf("post-register suggestion = %q, want wayne_enterprises_2", next)
	}
	// a name with no usable characters errors
	if _, err := saga.SuggestSlug(ctx, "!!!"); err == nil {
		t.Error("suggest from an unusable name should error")
	}
}
