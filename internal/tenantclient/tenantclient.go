// Package tenantclient builds ent clients scoped to a tenant's Postgres schema.
// It uses ent's AlternateSchema so UserProfile queries target
// {schema}.user_profiles, and wraps the driver so closing a tenant client does
// not close the shared connection pool.
package tenantclient

import (
	"database/sql"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/msrsiddik/apicorex-identity/ent"
)

// New returns an ent client scoped to the given tenant schema.
// UserProfile queries go to {schemaName}.user_profiles.
// Closing the returned client does NOT close the underlying *sql.DB.
//
// Future-proofing seam: this is the single place a per-tenant *sql.DB would be
// substituted for a dedicated-database tenant tier. A tenant→DSN router could
// hand a dedicated pool here instead of the shared db; nothing else changes.
func New(db *sql.DB, schemaName string) *ent.Client {
	drv := &NonClosingDriver{Driver: entsql.OpenDB(dialect.Postgres, db)}
	return ent.NewClient(
		ent.Driver(drv),
		ent.AlternateSchema(ent.SchemaConfig{
			UserProfile: schemaName,
		}),
	)
}

// NonClosingDriver wraps entsql.Driver so that Close() is a no-op.
// This prevents the shared *sql.DB from being closed when a tenant client is discarded.
type NonClosingDriver struct {
	*entsql.Driver
}

func (d *NonClosingDriver) Close() error { return nil }
