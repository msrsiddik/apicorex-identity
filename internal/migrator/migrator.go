// Package migrator runs plugin-declared SQL migrations inside a tenant's schema
// and tracks which versions have been applied. Each statement runs in a
// transaction with SET LOCAL search_path so it targets the right tenant schema
// without leaking into the connection pool.
package migrator

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/pluginmigrationhistory"
)

// Migration is one versioned schema change declared by a plugin.
type Migration struct {
	Version string // sortable, e.g. "20260101_001"
	Name    string
	UpSQL   string
	DownSQL string
}

// Migrator applies and rolls back plugin migrations per tenant schema.
type Migrator struct {
	entClient *ent.Client
	db        *sql.DB
}

// New returns a Migrator.
func New(entClient *ent.Client, db *sql.DB) *Migrator {
	return &Migrator{entClient: entClient, db: db}
}

// RunForTenant applies all pending plugin migrations for a single tenant.
func (m *Migrator) RunForTenant(ctx context.Context, tenantID, schemaName, pluginName string, migrations []Migration) error {
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	applied := m.appliedVersions(ctx, tenantID, pluginName)

	for _, mig := range migrations {
		if applied[mig.Version] {
			continue
		}
		if err := m.runSQL(ctx, schemaName, mig.UpSQL); err != nil {
			return fmt.Errorf("run migration %s for tenant %s: %w", mig.Version, tenantID, err)
		}
		m.entClient.PluginMigrationHistory.Create().
			SetID(uuid.New().String()).
			SetTenantID(tenantID).
			SetPluginName(pluginName).
			SetVersion(mig.Version).
			SetName(mig.Name).
			SetStatus("applied").
			SaveX(ctx)
		log.Printf("[migrator] applied %s/%s to tenant %s", pluginName, mig.Version, tenantID)
	}
	return nil
}

// RollbackForTenant runs down_sql for all applied migrations of a plugin (uninstall).
func (m *Migrator) RollbackForTenant(ctx context.Context, tenantID, schemaName, pluginName string, migrations []Migration) error {
	applied := m.appliedVersions(ctx, tenantID, pluginName)

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version > migrations[j].Version
	})

	for _, mig := range migrations {
		if !applied[mig.Version] {
			continue
		}
		if err := m.runSQL(ctx, schemaName, mig.DownSQL); err != nil {
			log.Printf("[migrator] rollback %s/%s failed: %v", pluginName, mig.Version, err)
			continue
		}
		m.entClient.PluginMigrationHistory.Update().
			Where(
				pluginmigrationhistory.TenantID(tenantID),
				pluginmigrationhistory.PluginName(pluginName),
				pluginmigrationhistory.Version(mig.Version),
			).
			SetStatus("rolled_back").
			SaveX(ctx)
	}
	return nil
}

// runSQL executes a SQL statement within a specific tenant schema using SET LOCAL.
func (m *Migrator) runSQL(ctx context.Context, schemaName, query string, args ...any) error {
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, fmt.Sprintf("SET LOCAL search_path TO %q", schemaName)); err != nil {
		tx.Rollback()
		return fmt.Errorf("set search_path: %w", err)
	}
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		tx.Rollback()
		return fmt.Errorf("run sql: %w", err)
	}
	return tx.Commit()
}

func (m *Migrator) appliedVersions(ctx context.Context, tenantID, pluginName string) map[string]bool {
	rows, _ := m.entClient.PluginMigrationHistory.Query().
		Where(
			pluginmigrationhistory.TenantID(tenantID),
			pluginmigrationhistory.PluginName(pluginName),
			pluginmigrationhistory.Status("applied"),
		).
		All(ctx)
	result := make(map[string]bool, len(rows))
	for _, r := range rows {
		result[r.Version] = true
	}
	return result
}
