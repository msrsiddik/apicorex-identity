package auth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// Suspending a member blocks login, kills their owned device token, and fails
// the /me membership re-check (IsMember), all reversibly: reactivating restores
// full access. Suspending the last manager is refused.
func TestSetMemberStatus_SuspendBlocksThenReactivateRestores(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := introspect(t, svc, res.Token).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "staff@acme.com", Role: "member", Password: "welcome123", FullName: "Staff",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	staffLogin, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "staff@acme.com", Password: "welcome123"})
	if err != nil {
		t.Fatalf("staff login before suspend: %v", err)
	}
	staffID := introspect(t, svc, staffLogin.Token).UserID

	// While active, /me's membership re-check passes.
	if ok, _ := svc.IsMember(ctx, tenantID, staffID); !ok {
		t.Fatal("active member should pass IsMember")
	}

	// Suspend.
	if err := svc.SetMemberStatus(ctx, tenantID, staffID, "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	// Login now refused.
	if _, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "staff@acme.com", Password: "welcome123"}); err == nil {
		t.Error("suspended member should not be able to log in")
	}
	// The device token they owned (from before suspend) is dead.
	if _, err := svc.Introspect(ctx, auth.HashToken(staffLogin.Token), ""); err == nil {
		t.Error("suspended member's device token should be rejected")
	}
	// And they can't act on someone else's device either.
	if _, err := svc.Introspect(ctx, auth.HashToken(res.Token), staffID); !errors.Is(err, auth.ErrMembershipRevoked) {
		t.Errorf("suspended acting user err = %v, want ErrMembershipRevoked", err)
	}
	// /me re-check fails → device boots.
	if ok, _ := svc.IsMember(ctx, tenantID, staffID); ok {
		t.Error("suspended member should fail IsMember (so /me 401s)")
	}

	// Reactivate → full access restored, no re-registration needed.
	if err := svc.SetMemberStatus(ctx, tenantID, staffID, "active"); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "staff@acme.com", Password: "welcome123"}); err != nil {
		t.Errorf("reactivated member should log in: %v", err)
	}
	if ok, _ := svc.IsMember(ctx, tenantID, staffID); !ok {
		t.Error("reactivated member should pass IsMember")
	}
}

func TestSetMemberStatus_RefusesLastManager(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	owner := introspect(t, svc, res.Token)
	tenantID, ownerID := owner.TenantID, owner.UserID

	// Owner is the only manager — suspending them must be refused.
	if err := svc.SetMemberStatus(ctx, tenantID, ownerID, "suspended"); err == nil {
		t.Error("suspending the last manager should be refused")
	}
}

// The shared-till flow: a manager provisions a staff with a PIN; the device
// (holding the manager's token) introspects with the staff as ACTING user and
// gets the staff's identity + permissions. A removed acting user or one from
// another tenant is rejected; the staff's PIN verifies against the stored hash.
func TestIntrospect_ActingUser(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	owner := introspect(t, svc, res.Token)
	tenantID := owner.TenantID
	tokenHash := auth.HashToken(res.Token)
	branches, _ := svc.ListBranches(ctx, tenantID)

	if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
		Email: "staff@acme.com", Role: "member", Password: "welcome123", FullName: "Staff",
	}); err != nil {
		t.Fatalf("add member: %v", err)
	}
	staffID := ""
	members, _ := svc.ListMembers(ctx, tenantID)
	for _, m := range members {
		if m.Email == "staff@acme.com" {
			staffID = m.UserID
		}
	}
	if staffID == "" {
		t.Fatal("could not resolve staff id")
	}
	if err := svc.SetMemberPin(ctx, tenantID, staffID, "2468"); err != nil {
		t.Fatalf("set member pin: %v", err)
	}
	// PIN verify (used by the device before caching the hash offline)
	if ok, _ := svc.VerifyOwnPin(ctx, tenantID, staffID, "2468"); !ok {
		t.Error("correct pin should verify")
	}
	if ok, _ := svc.VerifyOwnPin(ctx, tenantID, staffID, "0000"); ok {
		t.Error("wrong pin should not verify")
	}

	// Acting as the staff on the owner's device token → staff identity, member role.
	acting, err := svc.Introspect(ctx, tokenHash, staffID)
	if err != nil {
		t.Fatalf("introspect acting staff: %v", err)
	}
	if acting.UserID != staffID {
		t.Errorf("acting user = %q, want %q", acting.UserID, staffID)
	}
	if len(acting.Roles) == 0 || acting.Roles[0] != "member" {
		t.Errorf("acting roles = %v, want [member]", acting.Roles)
	}
	for _, p := range acting.Permissions {
		if p == "*:*" {
			t.Error("acting staff must not inherit the owner's *:*")
		}
	}

	// A user id from nowhere → membership revoked.
	if _, err := svc.Introspect(ctx, tokenHash, "u_ghost"); !errors.Is(err, auth.ErrMembershipRevoked) {
		t.Errorf("ghost acting user err = %v, want ErrMembershipRevoked", err)
	}

	// Suspend the staff → acting introspection rejected; owner unaffected.
	if err := svc.SetMemberStatus(ctx, tenantID, staffID, "suspended"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := svc.Introspect(ctx, tokenHash, staffID); !errors.Is(err, auth.ErrMembershipRevoked) {
		t.Errorf("suspended acting user err = %v, want ErrMembershipRevoked", err)
	}
	if _, err := svc.Introspect(ctx, tokenHash, ""); err != nil {
		t.Errorf("owner introspect after staff suspend: %v", err)
	}
}

// A shared till unlocks ANY active member by PIN alone: ResolvePin bcrypt-checks
// the PIN against every active member's stored hash and returns whoever matches
// — even a staff who never enrolled on this device. Wrong PIN and a suspended
// member's PIN resolve to nobody.
func TestResolvePin(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	owner := introspect(t, svc, res.Token)
	tenantID := owner.TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	// two staff, each with their own PIN
	for _, s := range []struct{ email, name, pin string }{
		{"ali@acme.com", "Ali", "1234"},
		{"bob@acme.com", "Bob", "5678"},
	} {
		if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
			Email: s.email, Role: "member", Password: "welcome123", FullName: s.name,
		}); err != nil {
			t.Fatalf("add %s: %v", s.name, err)
		}
		id := ""
		members, _ := svc.ListMembers(ctx, tenantID)
		for _, m := range members {
			if m.Email == s.email {
				id = m.UserID
			}
		}
		if err := svc.SetMemberPin(ctx, tenantID, id, s.pin); err != nil {
			t.Fatalf("set pin %s: %v", s.name, err)
		}
	}

	// Ali's PIN resolves to Ali (even without any device enrollment).
	m, err := svc.ResolvePin(ctx, tenantID, "1234")
	if err != nil || m.FullName != "Ali" {
		t.Fatalf("resolve 1234 = %+v, %v; want Ali", m, err)
	}
	// Bob's PIN resolves to Bob.
	m, err = svc.ResolvePin(ctx, tenantID, "5678")
	if err != nil || m.FullName != "Bob" {
		t.Fatalf("resolve 5678 = %+v, %v; want Bob", m, err)
	}
	// An unknown PIN resolves to nobody.
	if _, err := svc.ResolvePin(ctx, tenantID, "0000"); err != auth.ErrInvalidPin {
		t.Errorf("resolve unknown pin err = %v, want ErrInvalidPin", err)
	}

	// Suspend Bob → his PIN no longer resolves.
	bobID := ""
	members, _ := svc.ListMembers(ctx, tenantID)
	for _, mm := range members {
		if mm.Email == "bob@acme.com" {
			bobID = mm.UserID
		}
	}
	if err := svc.SetMemberStatus(ctx, tenantID, bobID, "suspended"); err != nil {
		t.Fatalf("suspend Bob: %v", err)
	}
	if _, err := svc.ResolvePin(ctx, tenantID, "5678"); err != auth.ErrInvalidPin {
		t.Errorf("suspended member's pin should not resolve, got %v", err)
	}
}

// PINs are unique per tenant: a PIN already used by another active member is
// refused (ErrPinTaken), PinAvailable reflects it, and a member keeps their own
// PIN available when re-saving (exceptUserID).
func TestPinUniqueness(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := introspect(t, svc, res.Token).TenantID
	branches, _ := svc.ListBranches(ctx, tenantID)

	ids := map[string]string{}
	for _, s := range []struct{ email, name string }{{"ali@acme.com", "Ali"}, {"bob@acme.com", "Bob"}} {
		if err := svc.AddMember(ctx, tenantID, branches[0].ID, auth.AddMemberInput{
			Email: s.email, Role: "member", Password: "welcome123", FullName: s.name,
		}); err != nil {
			t.Fatalf("add %s: %v", s.name, err)
		}
	}
	members, _ := svc.ListMembers(ctx, tenantID)
	for _, m := range members {
		ids[m.Email] = m.UserID
	}

	// Ali takes 1234.
	if err := svc.SetMemberPin(ctx, tenantID, ids["ali@acme.com"], "1234"); err != nil {
		t.Fatalf("set Ali pin: %v", err)
	}
	// 1234 is now unavailable to Bob, and setting it for Bob is refused.
	if ok, _ := svc.PinAvailable(ctx, tenantID, "1234", ""); ok {
		t.Error("1234 should be unavailable once Ali holds it")
	}
	if err := svc.SetMemberPin(ctx, tenantID, ids["bob@acme.com"], "1234"); err != auth.ErrPinTaken {
		t.Errorf("setting Ali's PIN for Bob = %v, want ErrPinTaken", err)
	}
	// A free PIN is available and settable.
	if ok, _ := svc.PinAvailable(ctx, tenantID, "5678", ""); !ok {
		t.Error("5678 should be available")
	}
	if err := svc.SetMemberPin(ctx, tenantID, ids["bob@acme.com"], "5678"); err != nil {
		t.Errorf("setting a free PIN for Bob: %v", err)
	}
	// Ali re-saving their OWN 1234 is fine (exceptUserID keeps it available).
	if ok, _ := svc.PinAvailable(ctx, tenantID, "1234", ids["ali@acme.com"]); !ok {
		t.Error("Ali's own PIN must stay available to Ali")
	}
	if err := svc.SetMemberPin(ctx, tenantID, ids["ali@acme.com"], "1234"); err != nil {
		t.Errorf("Ali re-saving own PIN: %v", err)
	}
}

// A user can update their own name/phone/job title; empty fields are left as-is.
func TestUpdateOwnProfile(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg) // owner: Ada / +100 / CEO

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	id := introspect(t, svc, res.Token)

	// change name + phone, leave job title (empty → unchanged)
	if err := svc.UpdateOwnProfile(ctx, id.TenantID, id.UserID, "Ada Lovelace", "+999", ""); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	p, err := svc.LoadProfileForTenant(ctx, id.TenantID, id.UserID)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	if p.FullName != "Ada Lovelace" || p.Phone != "+999" {
		t.Errorf("profile = %+v, want updated name/phone", p)
	}
	if p.JobTitle != "CEO" {
		t.Errorf("job title = %q, want unchanged CEO", p.JobTitle)
	}
}

func TestSetMemberStatus_RejectsBadStatus(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := newService(pg)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	owner := introspect(t, svc, res.Token)

	if err := svc.SetMemberStatus(ctx, owner.TenantID, owner.UserID, "banned"); err == nil {
		t.Error(`status other than "active"/"suspended" should be rejected`)
	}
}
