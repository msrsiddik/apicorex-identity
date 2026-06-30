package main

import (
	"context"
	"database/sql"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// seed built-in system roles (idempotent)
	rbacStore := rbac.NewStore(entClient)
	if _, err := rbacStore.SeedSystemRoles(ctx); err != nil {
		log.Fatalf("seed system roles: %v", err)
	}
	log.Println("[identity] system roles seeded")

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	issuer := iauth.NewIssuer(jwtSecret, 15*time.Minute)

	// optional logout denylist (shared with Core via Redis)
	var denylist *iauth.Denylist
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		denylist, err = iauth.NewDenylist(redisURL)
		if err != nil {
			log.Fatalf("redis denylist: %v", err)
		}
		log.Println("[identity] logout denylist enabled (redis)")
	}

	coreURL := envOr("CORE_URL", "http://localhost:8080")
	coreRegistry := pluginmgr.NewCoreRegistry(coreURL)
	mig := migrator.New(entClient, db)
	installer := pluginmgr.NewInstaller(entClient, mig, coreRegistry)

	saga := itenant.NewSaga(entClient, db, dsn, installer, rbacStore)
	authSvc := iauth.NewService(entClient, db, issuer, denylist, rbacStore)

	p := plugin.New(plugin.Config{
		Name:          "identity",
		Version:       "1.0.0",
		CoreURL:       coreURL,
		PluginAddr:    envOr("PLUGIN_ADDR", ":50051"),
		PluginBaseURL: envOr("PLUGIN_BASE_URL", ""),
		APIKey:        os.Getenv("PLUGIN_API_KEY"),
	})
	registerRoutes(p, &handlers{authSvc: authSvc, saga: saga, installer: installer})

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
