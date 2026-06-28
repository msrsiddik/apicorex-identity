package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	iauth "github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/plugin"
	itenant "github.com/msrsiddik/apicorex-identity/internal/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

type noopInstaller struct{}

func (noopInstaller) InstallForNewTenant(context.Context, string, string) error { return nil }

// newTestRouter builds a Gin engine with the real identity handlers backed by a
// throwaway Postgres container, plus the routes /me reads from.
func newTestRouter(t *testing.T) (*gin.Engine, *handlers) {
	t.Helper()
	pg := testutil.NewPostgres(t)

	issuer := iauth.NewIssuer("test-secret", 15*time.Minute)
	authSvc := iauth.NewService(pg.EntClient, pg.DB, issuer, nil)
	saga := itenant.NewSaga(pg.EntClient, pg.DB, pg.DSN, noopInstaller{})
	h := &handlers{authSvc: authSvc, saga: saga}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/auth/register", h.register)
	r.POST("/auth/login", h.login)
	r.GET("/me", h.me)
	r.POST("/plugins/install", h.install)
	r.POST("/plugins/uninstall", h.uninstall)
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
	if lr.AccessToken == "" || lr.RefreshToken == "" {
		t.Error("login should return both tokens")
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
	r, _ := newTestRouter(t)
	do(t, r, "POST", "/auth/register", RegisterRequest{
		Slug: "acme", Name: "Acme", Plan: "starter",
		Email: "owner@acme.com", Password: "secret123",
		FullName: "Ada", Phone: "+100", JobTitle: "CEO",
	}, nil)

	// find the user_id to simulate Core's injected headers
	u, _ := newUserID(t, r)

	// /me with Core-injected headers → profile + role
	w := do(t, r, "GET", "/me", nil, map[string]string{
		"X-ApiCoreX-User-ID":   u,
		"X-ApiCoreX-Tenant-ID": "t_unused", // installed_plugins query tolerates missing
		"X-ApiCoreX-Schema":    "tenant_acme",
		"X-ApiCoreX-Roles":     "owner",
		"X-ApiCoreX-User-Type": "tenant_user",
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

	// /me without auth header → 401
	w2 := do(t, r, "GET", "/me", nil, nil)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("/me no-auth status = %d, want 401", w2.Code)
	}
}

// newUserID logs in to discover the owner's user_id from the JWT subject — but
// simpler: query via a fresh login and decode the token sub. We just re-login.
func newUserID(t *testing.T, r *gin.Engine) (string, string) {
	t.Helper()
	w := do(t, r, "POST", "/auth/login", LoginRequest{Slug: "acme", Email: "owner@acme.com", Password: "secret123"}, nil)
	var lr LoginResponse
	json.Unmarshal(w.Body.Bytes(), &lr)
	sub := jwtSubject(t, lr.AccessToken)
	return sub, lr.AccessToken
}

func jwtSubject(t *testing.T, token string) string {
	t.Helper()
	sub, _ := decodeSub(token)
	if sub == "" {
		t.Fatal("could not decode jwt subject")
	}
	return sub
}

// decodeSub extracts the "sub" claim from a JWT without verifying the signature.
func decodeSub(token string) (string, error) {
	parts := splitDots(token)
	if len(parts) != 3 {
		return "", errBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	return claims.Sub, nil
}

func splitDots(s string) []string { return strings.Split(s, ".") }

var errBadToken = errorString("bad token")

type errorString string

func (e errorString) Error() string { return string(e) }

// keep the plugin import used (header helpers are exercised by the real /me handler)
var _ = plugin.UserID
