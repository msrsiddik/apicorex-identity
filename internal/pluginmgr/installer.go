// Package pluginmgr orchestrates per-tenant plugin installation. It pulls a
// plugin's migrations from Core's control plane and runs them in the tenant's
// schema, and records installs in plugin_installs. Uninstall can optionally drop
// the plugin's tenant data.
package pluginmgr

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/plugininstall"
	entTenant "github.com/msrsiddik/apicorex-identity/ent/tenant"
	"github.com/msrsiddik/apicorex-identity/internal/migrator"
)

// PluginManifest is the subset of a plugin manifest the installer needs.
type PluginManifest struct {
	Migrations []migrator.Migration
}

// PluginRegistry lets the installer fetch a plugin's manifest from Core over HTTP.
type PluginRegistry interface {
	GetManifest(pluginName string) (PluginManifest, bool)
}

// Installer handles plugin install/uninstall across tenants.
type Installer struct {
	entClient *ent.Client
	migrator  *migrator.Migrator
	registry  PluginRegistry
}

// NewInstaller returns an Installer. registry fetches plugin manifests (and thus
// migrations) from Core.
func NewInstaller(entClient *ent.Client, m *migrator.Migrator, registry PluginRegistry) *Installer {
	return &Installer{entClient: entClient, migrator: m, registry: registry}
}

// InstallInput names the tenant and plugin to install.
type InstallInput struct {
	TenantID   string
	PluginName string
}

// Install installs a plugin for a single tenant:
//  1. Fetches plugin manifest (migrations) via gRPC
//  2. Runs pending migrations in tenant schema
//  3. Records install in plugin_installs
func (ins *Installer) Install(ctx context.Context, in InstallInput) error {
	exists, err := ins.entClient.PluginInstall.Query().
		Where(plugininstall.TenantID(in.TenantID), plugininstall.PluginName(in.PluginName)).
		Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("plugin %q already installed for tenant %s", in.PluginName, in.TenantID)
	}

	t, err := ins.entClient.Tenant.Query().
		Where(entTenant.ID(in.TenantID)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	migrations, err := ins.fetchMigrations(ctx, in.PluginName)
	if err != nil {
		return fmt.Errorf("fetch migrations for %q: %w", in.PluginName, err)
	}

	if len(migrations) > 0 {
		if err := ins.migrator.RunForTenant(ctx, t.ID, t.SchemaName, in.PluginName, migrations); err != nil {
			return fmt.Errorf("run migrations: %w", err)
		}
	}

	_, err = ins.entClient.PluginInstall.Create().
		SetID(uuid.New().String()).
		SetTenantID(in.TenantID).
		SetPluginName(in.PluginName).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("record install: %w", err)
	}

	log.Printf("[pluginmgr] installed %q for tenant %s", in.PluginName, in.TenantID)
	return nil
}

// InstallForNewTenant runs migrations for all globally installed plugins on a newly registered tenant.
// Called from the registration saga after schema creation.
func (ins *Installer) InstallForNewTenant(ctx context.Context, tenantID, schemaName string) error {
	// Collect unique plugin names that are installed on any existing tenant
	installs, err := ins.entClient.PluginInstall.Query().All(ctx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, pi := range installs {
		if pi.PluginName != "identity" {
			seen[pi.PluginName] = true
		}
	}

	for pluginName := range seen {
		migrations, err := ins.fetchMigrations(ctx, pluginName)
		if err != nil {
			log.Printf("[pluginmgr] fetch migrations for %q: %v (skipping)", pluginName, err)
			continue
		}
		if len(migrations) == 0 {
			continue
		}
		if err := ins.migrator.RunForTenant(ctx, tenantID, schemaName, pluginName, migrations); err != nil {
			return fmt.Errorf("migrate %q for new tenant: %w", pluginName, err)
		}
		_, _ = ins.entClient.PluginInstall.Create().
			SetID(uuid.New().String()).
			SetTenantID(tenantID).
			SetPluginName(pluginName).
			Save(ctx)
	}
	return nil
}

// ReconcileResult reports what happened to one tenant during a reconcile.
type ReconcileResult struct {
	TenantID string `json:"tenant_id"`
	Slug     string `json:"slug"`
	Error    string `json:"error,omitempty"` // empty on success
}

// ReconcileAll applies a plugin's currently-pending migrations to every tenant
// that already has it installed. Each plugin migration is versioned and tracked
// per tenant (plugin_migration_histories), so this is idempotent — a tenant
// already on the latest version does nothing. Use this after a plugin ships a
// new migration, to roll it out to existing installs without touching tenants
// that never installed the plugin (new tenants get it automatically at
// registration via InstallForNewTenant).
func (ins *Installer) ReconcileAll(ctx context.Context, pluginName string) ([]ReconcileResult, error) {
	migrations, err := ins.fetchMigrations(ctx, pluginName)
	if err != nil {
		return nil, fmt.Errorf("fetch migrations for %q: %w", pluginName, err)
	}
	if len(migrations) == 0 {
		return nil, nil
	}

	installs, err := ins.entClient.PluginInstall.Query().
		Where(plugininstall.PluginName(pluginName)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list installs: %w", err)
	}

	results := make([]ReconcileResult, 0, len(installs))
	for _, pi := range installs {
		t, err := ins.entClient.Tenant.Get(ctx, pi.TenantID)
		if err != nil {
			results = append(results, ReconcileResult{TenantID: pi.TenantID, Error: fmt.Sprintf("tenant not found: %v", err)})
			continue
		}
		res := ReconcileResult{TenantID: t.ID, Slug: t.Slug}
		if err := ins.migrator.RunForTenant(ctx, t.ID, t.SchemaName, pluginName, migrations); err != nil {
			res.Error = err.Error()
			log.Printf("[pluginmgr] reconcile %q failed for tenant %s: %v", pluginName, t.ID, err)
		}
		results = append(results, res)
	}
	return results, nil
}

// UninstallInput controls an uninstall.
type UninstallInput struct {
	TenantID   string
	PluginName string
	// DropData: if true, runs the plugin's down migrations (DROP TABLE etc.) —
	// permanent. If false, only the install record is removed; tenant data is
	// preserved so a later re-install restores access to it.
	DropData bool
}

// Uninstall removes a plugin for a tenant. With DropData=false it's a soft
// uninstall (data kept); with DropData=true it rolls back migrations (data dropped).
func (ins *Installer) Uninstall(ctx context.Context, in UninstallInput) error {
	pi, err := ins.entClient.PluginInstall.Query().
		Where(plugininstall.TenantID(in.TenantID), plugininstall.PluginName(in.PluginName)).
		Only(ctx)
	if err != nil {
		return fmt.Errorf("plugin %q not installed for tenant %s", in.PluginName, in.TenantID)
	}

	t, err := ins.entClient.Tenant.Query().Where(entTenant.ID(in.TenantID)).Only(ctx)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}

	if in.DropData {
		migrations, err := ins.fetchMigrations(ctx, in.PluginName)
		if err != nil {
			return fmt.Errorf("fetch migrations for %q: %w", in.PluginName, err)
		}
		// runs down_sql in reverse order, marks history rolled_back
		if err := ins.migrator.RollbackForTenant(ctx, t.ID, t.SchemaName, in.PluginName, migrations); err != nil {
			return fmt.Errorf("rollback migrations: %w", err)
		}
	}

	if err := ins.entClient.PluginInstall.DeleteOneID(pi.ID).Exec(ctx); err != nil {
		return fmt.Errorf("remove install record: %w", err)
	}

	log.Printf("[pluginmgr] uninstalled %q for tenant %s (drop_data=%v)", in.PluginName, in.TenantID, in.DropData)
	return nil
}

// fetchMigrations pulls the plugin's manifest from Core (over HTTP) and returns its migrations.
func (ins *Installer) fetchMigrations(_ context.Context, pluginName string) ([]migrator.Migration, error) {
	m, ok := ins.registry.GetManifest(pluginName)
	if !ok {
		return nil, fmt.Errorf("plugin %q not registered in Core", pluginName)
	}
	return m.Migrations, nil
}
