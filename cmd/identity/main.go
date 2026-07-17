package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/msrsiddik/apicorex-identity/ent"
	"github.com/msrsiddik/apicorex-identity/ent/migrate"
	iauth "github.com/msrsiddik/apicorex-identity/internal/auth"
	"github.com/msrsiddik/apicorex-identity/internal/migrator"
	"github.com/msrsiddik/apicorex-identity/internal/plugin"
	"github.com/msrsiddik/apicorex-identity/internal/pluginmgr"
	"github.com/msrsiddik/apicorex-identity/internal/rbac"
	itenant "github.com/msrsiddik/apicorex-identity/internal/tenant"
)

func main() {
	godotenv.Load()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	drv := entsql.OpenDB(dialect.Postgres, db)
	entClient := ent.NewClient(ent.Driver(drv))
	defer entClient.Close()

	ctx := context.Background()
	if err := migrateSharedSchema(ctx, db); err != nil {
		log.Fatalf("ent schema create: %v", err)
	}
	// Bring every existing tenant's per-tenant schema up to date (idempotent) —
	// new registrations migrate at creation, but existing tenants need their
	// user_profiles ALTERed for newly added columns (e.g. pin_hash).
	if tenants, err := entClient.Tenant.Query().All(ctx); err == nil {
		for _, t := range tenants {
			if t.SchemaName == "" {
				continue
			}
			if err := itenant.MigrateTenantSchema(ctx, db, dsn, t.SchemaName); err != nil {
				log.Printf("[identity] migrate tenant schema %s: %v", t.SchemaName, err)
			}
		}
		log.Printf("[identity] migrated %d tenant schemas", len(tenants))
	}

	// seed built-in system roles (idempotent)
	rbacStore := rbac.NewStore(entClient)
	if _, err := rbacStore.SeedSystemRoles(ctx); err != nil {
		log.Fatalf("seed system roles: %v", err)
	}
	log.Println("[identity] system roles seeded")

	coreURL := envOr("CORE_URL", "http://localhost:8080")
	coreRegistry := pluginmgr.NewCoreRegistry(coreURL)
	mig := migrator.New(entClient, db)
	installer := pluginmgr.NewInstaller(entClient, mig, coreRegistry)

	// bootstrap: grant is_platform_admin to any already-registered user in
	// PLATFORM_ADMIN_EMAILS. This only adds the flag (never revokes) and only
	// affects users who exist yet — it's a one-time seed, not the source of
	// truth. Manage admins after boot via POST/DELETE /platform-admins.
	if csv := os.Getenv("PLATFORM_ADMIN_EMAILS"); csv != "" {
		emails := iauth.ParsePlatformAdminEmails(csv)
		granted, err := iauth.SyncPlatformAdminsFromEnv(ctx, entClient, emails)
		if err != nil {
			log.Fatalf("bootstrap platform admins: %v", err)
		}
		log.Printf("[identity] platform admin bootstrap: %d user(s) granted from %d configured email(s)", granted, len(emails))
	}

	// Google login (password-free): verify ID tokens whose "aud" is one of the
	// configured OAuth client IDs (Android/Web/Desktop). Empty = feature off.
	// The first id is the app-facing one (the Web client ID) served by
	// GET /auth/config so the app doesn't hardcode it.
	var googleVerifier *iauth.GoogleVerifier
	var googleClientID string
	if ids := iauth.ParseGoogleClientIDs(os.Getenv("GOOGLE_CLIENT_IDS")); len(ids) > 0 {
		googleVerifier = iauth.NewGoogleVerifier(ids)
		googleClientID = ids[0]
		log.Printf("[identity] google login enabled for %d client id(s)", len(ids))
	}

	saga := itenant.NewSaga(entClient, db, dsn, installer, rbacStore)
	authSvc := iauth.NewService(entClient, db, rbacStore, googleVerifier)

	p := plugin.New(plugin.Config{
		Name:          "identity",
		Version:       "1.0.0",
		CoreURL:       coreURL,
		PluginAddr:    envOr("PLUGIN_ADDR", ":50051"),
		PluginBaseURL: envOr("PLUGIN_BASE_URL", ""),
		APIKey:        os.Getenv("PLUGIN_API_KEY"),
	})
	registerRoutes(p, &handlers{
		authSvc: authSvc, saga: saga, installer: installer,
		pluginKey:      os.Getenv("PLUGIN_API_KEY"),
		googleClientID: googleClientID,
	})

	sigCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := p.Run(sigCtx); err != nil {
		log.Fatalf("plugin stopped: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// migrateSharedSchema creates/updates only the public-schema tables.
// UserProfile is excluded — it lives in per-tenant schemas, created at registration time.
func migrateSharedSchema(ctx context.Context, db *sql.DB) error {
	tables := make([]*schema.Table, 0, len(migrate.Tables))
	for _, t := range migrate.Tables {
		if t.Name == "user_profiles" {
			continue
		}
		tables = append(tables, t)
	}
	m, err := schema.NewMigrate(entsql.OpenDB(dialect.Postgres, db))
	if err != nil {
		return err
	}
	return m.Create(ctx, tables...)
}
