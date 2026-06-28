package migrator_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/msrsiddik/apicorex-identity/internal/migrator"
	"github.com/msrsiddik/apicorex-identity/internal/testutil"
)

func TestMigrator_ApplyAndRollback(t *testing.T) {
	pg := testutil.NewPostgres(t)
	ctx := context.Background()

	const (
		tenantID = "t_test"
		schema   = "tenant_test"
		plugin   = "billing"
	)
	// create the tenant schema the migrations target
	if _, err := pg.DB.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %q", schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}

	m := migrator.New(pg.EntClient, pg.DB)
	migs := []migrator.Migration{{
		Version: "20260101_001",
		Name:    "create invoices",
		UpSQL:   "CREATE TABLE invoices (id SERIAL PRIMARY KEY, amount INT)",
		DownSQL: "DROP TABLE invoices",
	}}

	// apply
	if err := m.RunForTenant(ctx, tenantID, schema, plugin, migs); err != nil {
		t.Fatalf("RunForTenant: %v", err)
	}
	if !tableExists(t, pg, schema, "invoices") {
		t.Fatal("invoices table should exist after apply")
	}

	// idempotent: second apply does not error (already applied → skipped)
	if err := m.RunForTenant(ctx, tenantID, schema, plugin, migs); err != nil {
		t.Fatalf("second RunForTenant should be a no-op: %v", err)
	}

	// rollback
	if err := m.RollbackForTenant(ctx, tenantID, schema, plugin, migs); err != nil {
		t.Fatalf("RollbackForTenant: %v", err)
	}
	if tableExists(t, pg, schema, "invoices") {
		t.Fatal("invoices table should be gone after rollback")
	}
}

func tableExists(t *testing.T, pg *testutil.PG, schema, table string) bool {
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
