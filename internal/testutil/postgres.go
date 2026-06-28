// Package testutil provides a Postgres test container shared by integration
// tests. It requires a running container engine (Docker or Podman); see
// TESTING.md. Tests that use it should skip when no engine is available.
package testutil

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/migrate"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// PG holds a running Postgres container and connections to it.
type PG struct {
	DSN       string
	DB        *sql.DB
	EntClient *ent.Client
	container testcontainers.Container
}

// NewPostgres starts a Postgres container, migrates the shared (public) tables,
// and returns connections. It registers cleanup with t.Cleanup. If no container
// engine is reachable, the test is skipped.
func NewPostgres(t *testing.T) *PG {
	t.Helper()
	ctx := context.Background()

	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("apicorex_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Skipf("skipping integration test: no container engine (%v)", err)
	}

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("connection string: %v", err)
	}
	// When the container engine is remote (e.g. Podman over SSH), the mapped port
	// lives on the engine host, not localhost. TEST_DB_HOST overrides the host.
	if h := os.Getenv("TEST_DB_HOST"); h != "" {
		dsn = strings.Replace(dsn, "@localhost:", "@"+h+":", 1)
		dsn = strings.Replace(dsn, "@127.0.0.1:", "@"+h+":", 1)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	entClient := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, db)))

	if err := migrateShared(ctx, db); err != nil {
		t.Fatalf("migrate shared schema: %v", err)
	}

	pg := &PG{DSN: dsn, DB: db, EntClient: entClient, container: container}
	t.Cleanup(func() {
		entClient.Close()
		db.Close()
		_ = pg.container.Terminate(context.Background())
	})
	return pg
}

// migrateShared creates the public tables (excluding user_profiles, which is
// per-tenant). Mirrors cmd/identity migrateSharedSchema.
func migrateShared(ctx context.Context, db *sql.DB) error {
	tables := make([]*schema.Table, 0, len(migrate.Tables))
	for _, tbl := range migrate.Tables {
		if tbl.Name == "user_profiles" {
			continue
		}
		tables = append(tables, tbl)
	}
	m, err := schema.NewMigrate(entsql.OpenDB(dialect.Postgres, db))
	if err != nil {
		return err
	}
	return m.Create(ctx, tables...)
}
