package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	iauth "github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/migrator"
	"github.com/msrsiddik/apicorex-identity/internal/plugin"
	"github.com/msrsiddik/apicorex-identity/internal/pluginmgr"
	itenant "github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// testPluginKey guards /internal/introspect in these tests.
const testPluginKey = "test-plugin-key"

type noopInstaller struct{}

func (noopInstaller) InstallForNewTenant(context.Context, string, string) error { return nil }

// emptyRegistry has no plugin manifests registered — install/uninstall calls
// against it fail predictably ("plugin ... not registered") rather than
// panicking on a nil installer, which is enough to prove a request reached
// the installer (i.e. passed the tenant/platform-admin authz check).
type emptyRegistry struct{}

func (emptyRegistry) GetManifest(string) (pluginmgr.PluginManifest, bool) {
	return pluginmgr.PluginManifest{}, false
}

// newTestRouter builds a Gin engine with the real identity handlers backed by a
// throwaway Postgres container, plus the routes /me reads from.
func newTestRouter(t *testing.T) (*gin.Engine, *handlers) {
	t.Helper()
	pg := testutil.NewPostgres(t)

	authSvc := iauth.NewService(pg.EntClient, pg.DB, pg.RBAC, nil)
	saga := itenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{}, pg.RBAC)
	installer := pluginmgr.NewInstaller(pg.EntClient, migrator.New(pg.EntClient, pg.DB), emptyRegistry{})
	h := &handlers{authSvc: authSvc, saga: saga, installer: installer, pluginKey: testPluginKey}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/auth/register", h.register)
	r.GET("/auth/slug-available", h.slugAvailable)
	r.GET("/auth/slug-suggest", h.slugSuggest)
	r.POST("/auth/login", h.login)
	r.POST("/auth/logout", h.logout)
	r.POST("/internal/introspect", h.introspect)
	r.GET("/me", h.me)
	r.POST("/plugins/install", h.install)
	r.POST("/plugins/uninstall", h.uninstall)
	r.POST("/plugins/reconcile", h.reconcilePlugin)
	r.GET("/branches", h.listBranches)
	r.POST("/branches", h.createBranch)
	r.PATCH("/branches/:id", h.updateBranch)
	r.POST("/branches/:id/members", h.addMember)
	r.GET("/roles", h.listRoles)
	r.POST("/roles", h.createRole)
	r.PATCH("/tenant", h.updateTenant)
	r.GET("/platform-admins", h.listPlatformAdmins)
	r.POST("/platform-admins", h.grantPlatformAdmin)
	r.DELETE("/platform-admins/:email", h.revokePlatformAdmin)
	return r, h
}

func do(t *testing.T, r *gin.Engine, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestHandler_Register(t *testing.T) {
	r, _ := newTestRouter(t)

	// valid → 201
	w := do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123",
		FullName: "Ada", Phone: "+100", JobTitle: "CEO",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 (%s)", w.Code, w.Body)
	}

	// malformed body → 400
	req := httptest.NewRequest("POST", "/auth/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("bad body status = %d, want 400", w2.Code)
	}

	// empty/invalid slug → 400 (must not create a tenant_ schema collision)
	for _, bad := range []string{"", "Acme", "ab", "acme-corp"} {
		w := do(t, r, "POST", "/auth/register", RegisterRequest{
			Slug: bad, Name: "X", Plan: "starter",
			Email: "x@x.com", Password: "secret123", FullName: "X",
		}, nil)
		if w.Code != http.StatusBadRequest {
			t.Errorf("register slug=%q status = %d, want 400", bad, w.Code)
		}
	}
}

// TestHandler_InstallCrossTenant verifies a caller cannot install/uninstall a
// plugin for a tenant other than their own (tenant_id from JWT must match body).
func TestHandler_InstallCrossTenant(t *testing.T) {
	r, _ := newTestRouter(t)

	// caller's JWT says tenant t_self; body asks for t_other → 403
	hdr := map[string]string{plugin.HeaderTenantID: "t_self"}
	w := do(t, r, "POST", "/plugins/install",
		InstallPluginRequest{TenantID: "t_other", PluginName: "sync"}, hdr)
	if w.Code != http.StatusForbidden {
		t.Errorf("cross-tenant install status = %d, want 403 (%s)", w.Code, w.Body)
	}

	w2 := do(t, r, "POST", "/plugins/uninstall",
		UninstallPluginRequest{TenantID: "t_other", PluginName: "sync"}, hdr)
	if w2.Code != http.StatusForbidden {
		t.Errorf("cross-tenant uninstall status = %d, want 403 (%s)", w2.Code, w2.Body)
	}

	// missing tenant context (no header) → 403 as well
	w3 := do(t, r, "POST", "/plugins/install",
		InstallPluginRequest{TenantID: "t_self", PluginName: "sync"}, nil)
	if w3.Code != http.StatusForbidden {
		t.Errorf("no-context install status = %d, want 403 (%s)", w3.Code, w3.Body)
	}
}

// A platform admin bypasses the same-tenant restriction on install/uninstall —
// they can act on behalf of any tenant, unlike a regular tenant user.
func TestHandler_InstallPlatformAdminBypass(t *testing.T) {
	r, _ := newTestRouter(t)

	adminHdr := map[string]string{
		plugin.HeaderTenantID: "t_self", // even with an unrelated/no tenant context
		plugin.HeaderUserType: "platform_admin",
	}
	w := do(t, r, "POST", "/plugins/install",
		InstallPluginRequest{TenantID: "t_other", PluginName: "sync"}, adminHdr)
	// not 403: the tenant-mismatch guard is bypassed, so it fails later (no such
	// tenant in this test DB) — proving the request reached the installer.
	if w.Code == http.StatusForbidden {
		t.Errorf("platform admin install status = %d, should not be 403 (%s)", w.Code, w.Body)
	}

	w2 := do(t, r, "POST", "/plugins/uninstall",
		UninstallPluginRequest{TenantID: "t_other", PluginName: "sync"}, adminHdr)
	if w2.Code == http.StatusForbidden {
		t.Errorf("platform admin uninstall status = %d, should not be 403 (%s)", w2.Code, w2.Body)
	}
}

func TestHandler_Login(t *testing.T) {
	r, _ := newTestRouter(t)
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123", FullName: "Ada",
	}, nil)

	// success → 200 with tokens
	w := do(t, r, "POST", "/auth/login", LoginRequest{
		Slug: "acme", Email: "owner@acme.com", Password: "secret123",
	}, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login status = %d, want 200 (%s)", w.Code, w.Body)
	}
	var lr LoginResponse
	json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Token == "" || !strings.HasPrefix(lr.Token, "zdt_") {
		t.Errorf("login should return an opaque zdt_ device token, got %q", lr.Token)
	}

	// wrong password → 401
	w2 := do(t, r, "POST", "/auth/login", LoginRequest{
		Slug: "acme", Email: "owner@acme.com", Password: "wrong",
	}, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("wrong password status = %d, want 401", w2.Code)
	}
}

func TestHandler_LoginMultiTenantChooser(t *testing.T) {
	r, _ := newTestRouter(t)
	// same email in two tenants
	do(t, r, "POST", "/auth/register", RegisterRequest{Slug: "alpha", Name: "A", Plan: "starter", Email: "m@x.com", Password: "secret123", FullName: "M"}, nil)
	do(t, r, "POST", "/auth/register", RegisterRequest{Slug: "beta", Name: "B", Plan: "starter", Email: "m@x.com", Password: "secret123", FullName: "M"}, nil)

	// no slug → 409 chooser
	w := do(t, r, "POST", "/auth/login", LoginRequest{Email: "m@x.com", Password: "secret123"}, nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("chooser status = %d, want 409 (%s)", w.Code, w.Body)
	}
	var ch TenantChooserResponse
	json.Unmarshal(w.Body.Bytes(), &ch)
	if len(ch.Tenants) != 2 {
		t.Errorf("chooser should list 2 tenants, got %d", len(ch.Tenants))
	}

	// with slug → 200
	w2 := do(t, r, "POST", "/auth/login", LoginRequest{Slug: "beta", Email: "m@x.com", Password: "secret123"}, nil)
	if w2.Code != http.StatusOK {
		t.Errorf("login with slug status = %d, want 200", w2.Code)
	}
}

func TestHandler_Me(t *testing.T) {
	r, h := newTestRouter(t)
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123",
		FullName: "Ada", Phone: "+100", JobTitle: "CEO",
	}, nil)

	// find the user_id + real tenant_id to simulate Core's injected headers. The
	// real tenant id matters now: /me re-checks membership, so a fake id would
	// (correctly) read as "not a member" and 401.
	u, tok := newUserID(t, r, h)
	tid := introspectTok(t, h, tok).TenantID

	// /me with Core-injected headers → profile + role + permissions
	w := do(t, r, "GET", "/me", nil, map[string]string{
		"X-ApiCoreX-User-ID":     u,
		"X-ApiCoreX-Tenant-ID":   tid,
		"X-ApiCoreX-Schema":      "tenant_acme",
		"X-ApiCoreX-Roles":       "owner",
		"X-ApiCoreX-Permissions": "*:*",
		"X-ApiCoreX-User-Type":   "tenant_user",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("/me status = %d, want 200 (%s)", w.Code, w.Body)
	}
	var me MeResponse
	json.Unmarshal(w.Body.Bytes(), &me)
	if me.FullName != "Ada" || me.JobTitle != "CEO" {
		t.Errorf("/me profile mismatch: %+v", me)
	}
	if len(me.Roles) != 1 || me.Roles[0] != "owner" {
		t.Errorf("/me roles = %v, want [owner]", me.Roles)
	}
	if len(me.Permissions) != 1 || me.Permissions[0] != "*:*" {
		t.Errorf("/me permissions = %v, want [*:*]", me.Permissions)
	}

	// /me without auth header → 401
	w2 := do(t, r, "GET", "/me", nil, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("/me no-auth status = %d, want 401", w2.Code)
	}
}

// A removed member's JWT stays valid until it expires, but /me must re-check
// membership and reject once the owner has removed them — this is what lets the
// device boot a removed staff the next time it comes online.
func TestHandler_MeRejectsRemovedMember(t *testing.T) {
	r, h := newTestRouter(t)
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123",
		FullName: "Ada", Phone: "+100", JobTitle: "CEO",
	}, nil)

	// Owner's identity + real tenant id, to act as Core would.
	ownerID, ownerTok := newUserID(t, r, h)
	tenant := introspectTok(t, h, ownerTok).TenantID
	ownerHeaders := map[string]string{
		"X-ApiCoreX-User-ID":     ownerID,
		"X-ApiCoreX-Tenant-ID":   tenant,
		"X-ApiCoreX-Schema":      "tenant_acme",
		"X-ApiCoreX-Roles":       "owner",
		"X-ApiCoreX-Permissions": "*:*",
		"X-ApiCoreX-User-Type":   "tenant_user",
	}

	// The owner's default branch (AddMember is branch-scoped).
	bw := do(t, r, "GET", "/branches", nil, ownerHeaders)
	if bw.Code != http.StatusOK {
		t.Fatalf("/branches = %d (%s)", bw.Code, bw.Body)
	}
	var branches ListBranchesResponse
	json.Unmarshal(bw.Body.Bytes(), &branches)
	if len(branches.Branches) == 0 {
		t.Fatal("no default branch")
	}
	branchID := branches.Branches[0].ID

	// Add a plain member (not a manager, so removal isn't blocked as last-manager).
	aw := do(t, r, "POST", "/branches/"+branchID+"/members", AddMemberRequest{
		Email: "bob@acme.com", Password: "secret123", Role: "member",
		FullName: "Bob", Phone: "+200", JobTitle: "Clerk",
	}, ownerHeaders)
	if aw.Code != http.StatusOK {
		t.Fatalf("addMember = %d (%s)", aw.Code, aw.Body)
	}

	bobLogin := do(t, r, "POST", "/auth/login", LoginRequest{Slug: "acme", Email: "bob@acme.com", Password: "secret123"}, nil)
	var blr LoginResponse
	json.Unmarshal(bobLogin.Body.Bytes(), &blr)
	bobID := introspectTok(t, h, blr.Token).UserID

	bobHeaders := map[string]string{
		"X-ApiCoreX-User-ID":     bobID,
		"X-ApiCoreX-Tenant-ID":   tenant,
		"X-ApiCoreX-Schema":      "tenant_acme",
		"X-ApiCoreX-Roles":       "member",
		"X-ApiCoreX-Permissions": "branch:read",
		"X-ApiCoreX-User-Type":   "tenant_user",
	}

	// While a member, /me is OK.
	if w := do(t, r, "GET", "/me", nil, bobHeaders); w.Code != http.StatusOK {
		t.Fatalf("/me before removal = %d, want 200 (%s)", w.Code, w.Body)
	}

	// Owner removes Bob (service call — the DELETE route isn't wired in this test router).
	if err := h.authSvc.RemoveMember(context.Background(), tenant, bobID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	// Bob's still-valid token now → 401, membership revoked.
	w := do(t, r, "GET", "/me", nil, bobHeaders)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("/me after removal = %d, want 401 (%s)", w.Code, w.Body)
	}

	// His device token must be dead too — introspection rejects it.
	if _, err := h.authSvc.Introspect(context.Background(), iauth.HashToken(blr.Token), ""); err == nil {
		t.Error("introspect after removal should fail")
	}

	// Even if Bob is re-added later, the OLD device token must stay dead —
	// RemoveMember revoked it, so re-adding doesn't resurrect old grants.
	aw2 := do(t, r, "POST", "/branches/"+branchID+"/members", AddMemberRequest{
		Email: "bob@acme.com", Role: "member",
	}, ownerHeaders)
	if aw2.Code != http.StatusOK {
		t.Fatalf("re-addMember = %d (%s)", aw2.Code, aw2.Body)
	}
	if _, err := h.authSvc.Introspect(context.Background(), iauth.HashToken(blr.Token), ""); err == nil {
		t.Error("old device token must stay revoked after re-adding the member")
	}
}

// The /internal/introspect endpoint: plugin-key gated, resolves the token owner
// by default and an acting user when supplied, and 401s for a removed acting user.
func TestHandler_Introspect(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)

	ownerID, ownerTok := newUserID(t, r, h)
	tenant := introspectTok(t, h, ownerTok).TenantID
	ownerHeaders := map[string]string{
		"X-ApiCoreX-User-ID":     ownerID,
		"X-ApiCoreX-Tenant-ID":   tenant,
		"X-ApiCoreX-Schema":      "tenant_acme",
		"X-ApiCoreX-Roles":       "owner",
		"X-ApiCoreX-Permissions": "*:*",
		"X-ApiCoreX-User-Type":   "tenant_user",
	}

	// wrong plugin key → 401
	w := do(t, r, "POST", "/internal/introspect",
		IntrospectRequest{TokenHash: iauth.HashToken(ownerTok)},
		map[string]string{"X-Plugin-Key": "wrong"})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("introspect with wrong key = %d, want 401 (%s)", w.Code, w.Body)
	}

	keyHdr := map[string]string{"X-Plugin-Key": testPluginKey}

	// owner default (no acting user) → owner identity with owner perms
	w = do(t, r, "POST", "/internal/introspect", IntrospectRequest{TokenHash: iauth.HashToken(ownerTok)}, keyHdr)
	if w.Code != http.StatusOK {
		t.Fatalf("introspect = %d, want 200 (%s)", w.Code, w.Body)
	}
	var res iauth.IntrospectResult
	json.Unmarshal(w.Body.Bytes(), &res)
	if res.UserID != ownerID || len(res.Permissions) == 0 {
		t.Errorf("introspect owner = %+v", res)
	}

	// add a staff member; introspect with acting user → staff identity + member perms
	bw := do(t, r, "GET", "/branches", nil, ownerHeaders)
	var branches ListBranchesResponse
	json.Unmarshal(bw.Body.Bytes(), &branches)
	do(t, r, "POST", "/branches/"+branches.Branches[0].ID+"/members", AddMemberRequest{
		Email: "staff@acme.com", Password: "secret123", Role: "member", FullName: "Staff",
	}, ownerHeaders)
	staffID := ""
	members, _ := h.authSvc.ListMembers(context.Background(), tenant)
	for _, m := range members {
		if m.Email == "staff@acme.com" {
			staffID = m.UserID
		}
	}
	w = do(t, r, "POST", "/internal/introspect",
		IntrospectRequest{TokenHash: iauth.HashToken(ownerTok), ActingUserID: staffID}, keyHdr)
	if w.Code != http.StatusOK {
		t.Fatalf("introspect acting staff = %d, want 200 (%s)", w.Code, w.Body)
	}
	var actingRes iauth.IntrospectResult
	json.Unmarshal(w.Body.Bytes(), &actingRes)
	if actingRes.UserID != staffID {
		t.Errorf("acting user_id = %q, want %q", actingRes.UserID, staffID)
	}
	for _, p := range actingRes.Permissions {
		if p == "*:*" {
			t.Error("acting staff must NOT inherit the owner's permissions")
		}
	}

	// removed acting user → 401 membership revoked (device token itself survives)
	if err := h.authSvc.RemoveMember(context.Background(), tenant, staffID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	w = do(t, r, "POST", "/internal/introspect",
		IntrospectRequest{TokenHash: iauth.HashToken(ownerTok), ActingUserID: staffID}, keyHdr)
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "membership revoked") {
		t.Errorf("introspect removed acting = %d (%s), want 401 membership revoked", w.Code, w.Body)
	}
	// ...but the owner still introspects fine on the same device token.
	w = do(t, r, "POST", "/internal/introspect", IntrospectRequest{TokenHash: iauth.HashToken(ownerTok)}, keyHdr)
	if w.Code != http.StatusOK {
		t.Errorf("owner introspect after staff removal = %d, want 200 (%s)", w.Code, w.Body)
	}
}

// Logout revokes exactly the calling device token (identified by the trusted
// token-hash header Core injects).
func TestHandler_Logout(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	_, tok := newUserID(t, r, h)

	w := do(t, r, "POST", "/auth/logout", nil, map[string]string{
		plugin.HeaderTokenHash: iauth.HashToken(tok),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("logout = %d, want 200 (%s)", w.Code, w.Body)
	}
	if _, err := h.authSvc.Introspect(context.Background(), iauth.HashToken(tok), ""); err == nil {
		t.Error("device token should be dead after logout")
	}
}

// introspectTok resolves a raw device token as Core would (no acting user) and
// returns the request identity.
func introspectTok(t *testing.T, h *handlers, raw string) *iauth.IntrospectResult {
	t.Helper()
	res, err := h.authSvc.Introspect(context.Background(), iauth.HashToken(raw), "")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	return res
}

// newUserID logs in as the acme owner and returns their user id + raw device token.
func newUserID(t *testing.T, r *gin.Engine, h *handlers) (string, string) {
	t.Helper()
	w := do(t, r, "POST", "/auth/login", LoginRequest{Slug: "acme", Email: "owner@acme.com", Password: "secret123"}, nil)
	var lr LoginResponse
	json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Token == "" {
		t.Fatal("login returned no token")
	}
	return introspectTok(t, h, lr.Token).UserID, lr.Token
}

// Registration without a slug succeeds and returns a generated slug.
func TestHandler_RegisterAutoSlug(t *testing.T) {
	r, _ := newTestRouter(t)

	w := do(t, r, "POST", "/auth/register", RegisterRequest{
		Name: "Initech LLC", Plan: "starter",
		Email: "owner@initech.com", Password: "secret123", FullName: "Bill",
	}, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("register without slug = %d, want 201 (%s)", w.Code, w.Body)
	}
	var rr RegisterResponse
	json.Unmarshal(w.Body.Bytes(), &rr)
	if rr.Slug != "initech_llc" {
		t.Errorf("generated slug = %q, want initech_llc", rr.Slug)
	}

	// no slug AND no name → 400
	w2 := do(t, r, "POST", "/auth/register", RegisterRequest{
		Email: "x@x.com", Password: "secret123",
	}, nil)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("register with neither slug nor name = %d, want 400", w2.Code)
	}
}

// The slug-available endpoint reports validity and whether a slug is taken.
func TestHandler_SlugAvailable(t *testing.T) {
	r, _ := newTestRouter(t)

	check := func(slug string) SlugAvailableResponse {
		w := do(t, r, "GET", "/auth/slug-available?slug="+slug, nil, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("slug-available(%q) = %d, want 200 (%s)", slug, w.Code, w.Body)
		}
		var resp SlugAvailableResponse
		json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}

	if got := check("acme"); !got.Available || !got.Valid {
		t.Errorf("acme before register = %+v, want available+valid", got)
	}
	if got := check("Ab"); got.Valid || got.Available {
		t.Errorf("malformed slug = %+v, want invalid+unavailable", got)
	}

	registerAcme(t, r)
	if got := check("acme"); got.Available {
		t.Errorf("acme after register = %+v, want unavailable", got)
	}

	// missing query param → 400
	w := do(t, r, "GET", "/auth/slug-available", nil, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("slug-available without param = %d, want 400", w.Code)
	}
}

// The slug-suggest endpoint derives a valid slug from a name (name required).
func TestHandler_SlugSuggest(t *testing.T) {
	r, _ := newTestRouter(t)

	// valid name → slug
	w := do(t, r, "GET", "/auth/slug-suggest?name=Acme%20Corp", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("slug-suggest = %d, want 200 (%s)", w.Code, w.Body)
	}
	var resp SlugSuggestResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Slug != "acme_corp" {
		t.Errorf("suggested slug = %q, want acme_corp", resp.Slug)
	}

	// after acme_corp is taken, suggestion is suffixed
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme_corp", Name: "Acme Corp", Email: "x@acme.com", Password: "secret123", FullName: "X",
	}, nil)
	w2 := do(t, r, "GET", "/auth/slug-suggest?name=Acme%20Corp", nil, nil)
	var resp2 SlugSuggestResponse
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	if resp2.Slug != "acme_corp_2" {
		t.Errorf("suggestion after taken = %q, want acme_corp_2", resp2.Slug)
	}

	// missing name → 400
	if w := do(t, r, "GET", "/auth/slug-suggest", nil, nil); w.Code != http.StatusBadRequest {
		t.Errorf("slug-suggest without name = %d, want 400", w.Code)
	}

	// unusable name → 422
	if w := do(t, r, "GET", "/auth/slug-suggest?name=%21%21%21", nil, nil); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("slug-suggest with unusable name = %d, want 422", w.Code)
	}
}

// registerAcme provisions the acme tenant and returns the owner's tenant_id by
// reading it back through a login token.
func registerAcme(t *testing.T, r *gin.Engine) {
	t.Helper()
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123", FullName: "Ada",
	}, nil)
}

// ctxHeaders builds the X-ApiCoreX-* context Core injects after verifying a token.
func ctxHeaders(tenantID, userID, perms string) map[string]string {
	return map[string]string{
		plugin.HeaderTenantID:    tenantID,
		plugin.HeaderUserID:      userID,
		plugin.HeaderSchema:      "tenant_acme",
		plugin.HeaderPermissions: perms,
	}
}

// Defense-in-depth: even if a request reaches the plugin (e.g. a direct call
// bypassing the gateway), the handler rejects it without the right permission.
func TestHandler_BranchAuthz(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	tid := loginTenantID(t, r, h)

	// no permissions header → 403
	w := do(t, r, "POST", "/branches", CreateBranchRequest{Slug: "dhaka", Name: "Dhaka"},
		ctxHeaders(tid, "u_x", ""))
	if w.Code != http.StatusForbidden {
		t.Errorf("create branch without permission = %d, want 403 (%s)", w.Code, w.Body)
	}

	// insufficient permission (only branch:read) → 403
	w = do(t, r, "POST", "/branches", CreateBranchRequest{Slug: "dhaka", Name: "Dhaka"},
		ctxHeaders(tid, "u_x", "branch:read"))
	if w.Code != http.StatusForbidden {
		t.Errorf("create branch with branch:read = %d, want 403 (%s)", w.Code, w.Body)
	}

	// exact permission → 201
	w = do(t, r, "POST", "/branches", CreateBranchRequest{Slug: "dhaka", Name: "Dhaka"},
		ctxHeaders(tid, "u_x", "branch:write"))
	if w.Code != http.StatusCreated {
		t.Errorf("create branch with branch:write = %d, want 201 (%s)", w.Code, w.Body)
	}

	// wildcard permission (branch:*) also allows write → 201
	w = do(t, r, "POST", "/branches", CreateBranchRequest{Slug: "ctg", Name: "Chattogram"},
		ctxHeaders(tid, "u_x", "branch:*"))
	if w.Code != http.StatusCreated {
		t.Errorf("create branch with branch:* = %d, want 201 (%s)", w.Code, w.Body)
	}

	// superuser wildcard (*:*) allows everything → 201
	w = do(t, r, "POST", "/branches", CreateBranchRequest{Slug: "syl", Name: "Sylhet"},
		ctxHeaders(tid, "u_x", "*:*"))
	if w.Code != http.StatusCreated {
		t.Errorf("create branch with *:* = %d, want 201 (%s)", w.Code, w.Body)
	}

	// reading branches needs branch:read; with it → 200
	w = do(t, r, "GET", "/branches", nil, ctxHeaders(tid, "u_x", "branch:read"))
	if w.Code != http.StatusOK {
		t.Errorf("list branches with branch:read = %d, want 200 (%s)", w.Code, w.Body)
	}
}

// Role management requires tenant:manage; lesser permissions are rejected.
func TestHandler_RoleAuthz(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	tid := loginTenantID(t, r, h)

	body := CreateRoleRequest{Slug: "auditor", Name: "Auditor", Permissions: []string{"user:read"}}

	// user:write is not enough → 403
	w := do(t, r, "POST", "/roles", body, ctxHeaders(tid, "u_x", "user:write"))
	if w.Code != http.StatusForbidden {
		t.Errorf("create role with user:write = %d, want 403 (%s)", w.Code, w.Body)
	}

	// tenant:manage → 201
	w = do(t, r, "POST", "/roles", body, ctxHeaders(tid, "u_x", "tenant:manage"))
	if w.Code != http.StatusCreated {
		t.Errorf("create role with tenant:manage = %d, want 201 (%s)", w.Code, w.Body)
	}
}

// Tenant update requires tenant:manage; slug is never changed (the request type
// has no slug field, and the response keeps the original slug).
func TestHandler_UpdateTenant(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	tid := loginTenantID(t, r, h)

	// without tenant:manage → 403
	w := do(t, r, "PATCH", "/tenant", UpdateTenantRequest{Name: "Acme Corporation"},
		ctxHeaders(tid, "u_x", "user:read"))
	if w.Code != http.StatusForbidden {
		t.Errorf("update tenant without permission = %d, want 403 (%s)", w.Code, w.Body)
	}

	// with tenant:manage → 200, name changed, slug unchanged
	w = do(t, r, "PATCH", "/tenant", UpdateTenantRequest{Name: "Acme Corporation", Plan: "pro"},
		ctxHeaders(tid, "u_x", "tenant:manage"))
	if w.Code != http.StatusOK {
		t.Fatalf("update tenant = %d, want 200 (%s)", w.Code, w.Body)
	}
	var resp TenantResponse
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Tenant.Name != "Acme Corporation" || resp.Tenant.Plan != "pro" {
		t.Errorf("update result = %+v, want name/plan changed", resp.Tenant)
	}
	if resp.Tenant.Slug != "acme" {
		t.Errorf("slug = %q, want unchanged acme", resp.Tenant.Slug)
	}
}

// Platform-admin management endpoints are gated on platform_admin user_type,
// not any tenant permission — even *:* on the caller's own tenant.
func TestHandler_PlatformAdminsManage(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	tid := loginTenantID(t, r, h)

	tenantOwnerHeaders := ctxHeaders(tid, "u_x", "*:*")
	adminHeaders := map[string]string{plugin.HeaderUserType: "platform_admin"}

	// a tenant owner, even with *:*, cannot list/grant/revoke platform admins
	if w := do(t, r, "GET", "/platform-admins", nil, tenantOwnerHeaders); w.Code != http.StatusForbidden {
		t.Errorf("list as tenant owner = %d, want 403", w.Code)
	}
	if w := do(t, r, "POST", "/platform-admins", GrantPlatformAdminRequest{Email: "owner@acme.com"}, tenantOwnerHeaders); w.Code != http.StatusForbidden {
		t.Errorf("grant as tenant owner = %d, want 403", w.Code)
	}

	// platform admin can grant an existing user
	w := do(t, r, "POST", "/platform-admins", GrantPlatformAdminRequest{Email: "owner@acme.com"}, adminHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("grant = %d, want 200 (%s)", w.Code, w.Body)
	}
	var granted PlatformAdminResponse
	json.Unmarshal(w.Body.Bytes(), &granted)
	if granted.Admin.Email != "owner@acme.com" {
		t.Errorf("granted = %+v, want owner@acme.com", granted.Admin)
	}

	// granting a nonexistent email fails
	if w := do(t, r, "POST", "/platform-admins", GrantPlatformAdminRequest{Email: "ghost@x.com"}, adminHeaders); w.Code != http.StatusBadRequest {
		t.Errorf("grant nonexistent = %d, want 400", w.Code)
	}

	// list reflects the grant
	w = do(t, r, "GET", "/platform-admins", nil, adminHeaders)
	var list ListPlatformAdminsResponse
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Admins) != 1 || list.Admins[0].Email != "owner@acme.com" {
		t.Errorf("list = %+v, want [owner@acme.com]", list.Admins)
	}

	// revoke
	w = do(t, r, "DELETE", "/platform-admins/owner@acme.com", nil, adminHeaders)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200 (%s)", w.Code, w.Body)
	}
	w = do(t, r, "GET", "/platform-admins", nil, adminHeaders)
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Admins) != 0 {
		t.Errorf("admins after revoke = %+v, want none", list.Admins)
	}
}

// /plugins/reconcile is platform-admin only, regardless of tenant permissions —
// it's a cross-tenant operation, not scoped to the caller's own tenant.
func TestHandler_ReconcilePlatformAdminOnly(t *testing.T) {
	r, h := newTestRouter(t)
	registerAcme(t, r)
	tid := loginTenantID(t, r, h)

	// a regular user, even an owner with *:* permissions, is not a platform admin
	w := do(t, r, "POST", "/plugins/reconcile", ReconcilePluginRequest{PluginName: "billing"}, map[string]string{
		plugin.HeaderTenantID:    tid,
		plugin.HeaderUserID:      "u_x",
		plugin.HeaderUserType:    "tenant_user",
		plugin.HeaderPermissions: "*:*",
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("reconcile as tenant_user = %d, want 403 (%s)", w.Code, w.Body)
	}

	// missing plugin_name → 400, but only after the admin check passes
	w2 := do(t, r, "POST", "/plugins/reconcile", ReconcilePluginRequest{}, map[string]string{
		plugin.HeaderUserType: "platform_admin",
	})
	if w2.Code != http.StatusBadRequest {
		t.Errorf("reconcile without plugin_name (as admin) = %d, want 400 (%s)", w2.Code, w2.Body)
	}
}

// loginTenantID logs in as the acme owner and returns the tenant_id via introspection.
func loginTenantID(t *testing.T, r *gin.Engine, h *handlers) string {
	t.Helper()
	w := do(t, r, "POST", "/auth/login", LoginRequest{Slug: "acme", Email: "owner@acme.com", Password: "secret123"}, nil)
	var lr LoginResponse
	json.Unmarshal(w.Body.Bytes(), &lr)
	if lr.Token == "" {
		t.Fatal("login returned no token")
	}
	return introspectTok(t, h, lr.Token).TenantID
}
