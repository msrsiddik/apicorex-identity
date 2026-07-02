package auth_test

import (
	"context"
	"testing"
	"time"

	enttenant "github.com/msrsiddik/apicorex-identity/ent/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// UpdateTenant changes name/plan but never the slug.
func TestUpdateTenant(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)
	register(t, pg)

	svc := auth.NewService(pg.EntClient, pg.DB, auth.NewIssuer("test-secret", 15*time.Minute), nil, pg.RBAC)
	res, _ := svc.Login(ctx, auth.LoginInput{Slug: "acme", Email: "owner@acme.com", Password: "secret123"})
	tenantID := decodeClaims(t, res.AccessToken).TenantID

	info, err := svc.UpdateTenant(ctx, tenantID, "Acme Corporation", "pro")
	if err != nil {
		t.Fatalf("update tenant: %v", err)
	}
	if info.Name != "Acme Corporation" || info.Plan != "pro" {
		t.Errorf("update result = %+v, want name/plan changed", info)
	}
	if info.Slug != "acme" {
		t.Errorf("slug changed to %q; it must stay acme", info.Slug)
	}

	// the slug (and its schema name) are unchanged in the DB
	tn, _ := pg.EntClient.Tenant.Query().Where(enttenant.ID(tenantID)).Only(ctx)
	if tn.Slug != "acme" || tn.SchemaName != "tenant_acme" {
		t.Errorf("persisted slug/schema = %q/%q, want acme/tenant_acme", tn.Slug, tn.SchemaName)
	}

	// empty fields leave values unchanged
	info2, _ := svc.UpdateTenant(ctx, tenantID, "", "")
	if info2.Name != "Acme Corporation" || info2.Plan != "pro" {
		t.Errorf("no-op update changed values: %+v", info2)
	}
}
