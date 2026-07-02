package pluginmgr_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/internal/migrator"
	"github.com/msrsiddik/apicorex-identity/internal/pluginmgr"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

// fakeRegistry serves a fixed manifest for one plugin, mimicking Core's manifest fetch.
type fakeRegistry struct {
	migrations []migrator.Migration
}

func (r fakeRegistry) GetManifest(name string) (pluginmgr.PluginManifest, bool) {
	if name != "billing" {
		return pluginmgr.PluginManifest{}, false
	}
	return pluginmgr.PluginManifest{Migrations: r.migrations}, true
}

// seedTenant creates a minimal tenant row + its schema, directly via SQL/ent so
// the test doesn't need the full registration saga.
func seedTenant(t *testing.T, pg *testutil.PG, id, slug string) {
	t.Helper()
	ctx := context.Background()
	schema := "tenant_" + slug
	if _, err := pg.DB.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %q", schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := pg.EntClient.Tenant.Create().
		SetID(id).SetSlug(slug).SetName(slug).SetPlan("starter").
		SetStatus("active").SetSchemaName(schema).Save(ctx); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
}

func markInstalled(t *testing.T, pg *testutil.PG, tenantID, pluginName string) {
	t.Helper()
	if _, err := pg.EntClient.PluginInstall.Create().
		SetID(uuid.New().String()).SetTenantID(tenantID).SetPluginName(pluginName).
		Save(context.Background()); err != nil {
		t.Fatalf("mark installed: %v", err)
	}
}

// ReconcileAll rolls a plugin's newly-added migration out to every tenant that
// already has it installed, skipping tenants without it, and is idempotent.
func TestReconcileAll(t *testing.T) {
	ctx := context.Background()
	pg := testutil.NewPostgres(t)

	seedTenant(t, pg, "t_a", "alpha")
	seedTenant(t, pg, "t_b", "beta")
	seedTenant(t, pg, "t_c", "gamma") // never installed billing

	markInstalled(t, pg, "t_a", "billing")
	markInstalled(t, pg, "t_b", "billing")

	mig := migrator.New(pg.EntClient, pg.DB)
	reg := fakeRegistry{migrations: []migrator.Migration{{
		Version: "20260101_001",
		Name:    "create invoices",
		UpSQL:   "CREATE TABLE invoices (id SERIAL PRIMARY KEY)",
		DownSQL: "DROP TABLE invoices",
	}}}
	installer := pluginmgr.NewInstaller(pg.EntClient, mig, reg)

	results, err := installer.ReconcileAll(ctx, "billing")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %v, want 2 (only installed tenants)", results)
	}
	for _, r := range results {
		if r.Error != "" {
			t.Errorf("tenant %s reconcile error: %s", r.TenantID, r.Error)
		}
	}
	if !tableExistsIn(t, pg, "tenant_alpha", "invoices") {
		t.Error("alpha should have the invoices table after reconcile")
	}
	if !tableExistsIn(t, pg, "tenant_beta", "invoices") {
		t.Error("beta should have the invoices table after reconcile")
	}
	if tableExistsIn(t, pg, "tenant_gamma", "invoices") {
		t.Error("gamma never installed billing — it should be untouched")
	}

	// re-running is a no-op (already-applied version is tracked and skipped)
	if _, err := installer.ReconcileAll(ctx, "billing"); err != nil {
		t.Fatalf("second reconcile should be idempotent: %v", err)
	}
}

// Reconciling a plugin nobody has installed returns no results and no error.
func TestReconcileAll_NoInstalls(t *testing.T) {
	pg := testutil.NewPostgres(t)
	mig := migrator.New(pg.EntClient, pg.DB)
	reg := fakeRegistry{migrations: []migrator.Migration{{
		Version: "20260101_001", Name: "x", UpSQL: "SELECT 1", DownSQL: "SELECT 1",
	}}}
	installer := pluginmgr.NewInstaller(pg.EntClient, mig, reg)

	results, err := installer.ReconcileAll(context.Background(), "billing")
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v, want none", results)
	}
}

func tableExistsIn(t *testing.T, pg *testutil.PG, schema, table string) bool {
	t.Helper()
	var n int
	err := pg.DB.QueryRow(
		`SELECT count(*) FROM information_schema.tables WHERE table_schema=$1 AND table_name=$2`,
		schema, table,
	).Scan(&n)
	if err != nil {
		t.Fatalf("query table existence: %v", err)
	}
	return n > 0
}
