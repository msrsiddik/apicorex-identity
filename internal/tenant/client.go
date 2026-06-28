package tenant

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	sqlschema "entgo.io/ent/dialect/sql/schema"
	"github.com/msrsiddik/apicorex-identity/ent/migrate"
)

// MigrateTenantSchema creates the user_profiles table inside the given tenant schema.
// Uses a connector that sets search_path on every connection so Atlas'
// CURRENT_SCHEMA() returns the correct tenant schema, not "public".
func MigrateTenantSchema(ctx context.Context, db *sql.DB, dsn, schemaName string) error {
	connector := &searchPathConnector{
		inner:  db.Driver(),
		dsn:    dsn,
		schema: schemaName,
	}
	tenantDB := sql.OpenDB(connector)
	defer tenantDB.Close()

	drv := entsql.OpenDB(dialect.Postgres, tenantDB)
	m, err := sqlschema.NewMigrate(drv)
	if err != nil {
		return err
	}
	return m.Create(ctx, migrate.UserProfilesTable)
}

// searchPathConnector opens new connections via the original driver and immediately
// sets search_path so all DDL runs in the target schema.
type searchPathConnector struct {
	inner  driver.Driver
	dsn    string
	schema string
}

func (c *searchPathConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	stmt := fmt.Sprintf(`SET search_path TO "%s"`, c.schema)
	// pgx's database/sql driver implements ExecerContext; the else branch guards
	// against any driver that doesn't.
	if e, ok := conn.(driver.ExecerContext); ok {
		if _, err := e.ExecContext(ctx, stmt, nil); err != nil {
			conn.Close()
			return nil, fmt.Errorf("set search_path: %w", err)
		}
	} else {
		conn.Close()
		return nil, fmt.Errorf("driver does not support ExecerContext")
	}
	return conn, nil
}

func (c *searchPathConnector) Driver() driver.Driver { return c.inner }
