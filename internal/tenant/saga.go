// Package tenant implements tenant registration as a compensating saga: it
// creates the tenant record and its dedicated Postgres schema, the global owner
// credential (shared.users) plus the tenant membership (shared.tenant_users),
// the owner's PII profile (tenant_<slug>.user_profiles), and runs any installed
// plugins' migrations. A failure at any step rolls back the prior steps.
package tenant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"regexp"

	"github.com/google/uuid"
	"github.com/msrsiddik/apicorex-identity/ent"
	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/internal/rbac"
	"github.com/msrsiddik/apicorex-identity/internal/tenantclient"
	"golang.org/x/crypto/bcrypt"
)

// slugPattern restricts a tenant slug to a safe SQL identifier: it becomes part
// of the schema name (tenant_<slug>), so it must start with a lowercase letter
// and contain only lowercase letters, digits, and underscores (3–32 chars).
var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{2,31}$`)

// ErrInvalidSlug is returned when a tenant slug is empty or malformed.
var ErrInvalidSlug = errors.New("invalid tenant slug: must be 3–32 chars, lowercase letters/digits/underscore, starting with a letter")

// ValidateSlug reports whether slug is a safe, non-empty tenant slug.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return ErrInvalidSlug
	}
	return nil
}

// PluginInstaller runs installed plugins' migrations for a new tenant. It is
// satisfied by pluginmgr.Installer.
type PluginInstaller interface {
	InstallForNewTenant(ctx context.Context, tenantID, schemaName string) error
}

// RegisterInput is the data needed to provision a new tenant and its owner.
// Credentials (email/password) are global; profile fields are tenant-scoped PII.
type RegisterInput struct {
	Slug          string
	Name          string
	Plan          string
	OwnerEmail    string
	OwnerPassword string
	OwnerFullName string
	OwnerPhone    string
	OwnerJobTitle string
}

// Saga runs the multi-step tenant registration with compensation on failure.
type Saga struct {
	entClient *ent.Client
	db        *sql.DB
	dsn       string
	installer PluginInstaller
	rbac      *rbac.Store
}

// NewSaga returns a registration Saga. dsn is the database URL, used to open the
// per-tenant schema connection for migrations.
func NewSaga(entClient *ent.Client, db *sql.DB, dsn string, installer PluginInstaller, rbacStore *rbac.Store) *Saga {
	return &Saga{entClient: entClient, db: db, dsn: dsn, installer: installer, rbac: rbacStore}
}

// Register provisions a new tenant and owner and returns the final slug. On any
// step failure it compensates the already-completed steps and returns the error.
// An existing global account (matched by email) is reused so a user can
// own/join multiple tenants. If in.Slug is empty, a slug is generated from
// in.Name and made unique.
func (s *Saga) Register(ctx context.Context, in RegisterInput) (string, error) {
	slug, err := s.resolveSlug(ctx, in.Slug, in.Name)
	if err != nil {
		return "", err
	}
	if err := ValidateSlug(slug); err != nil {
		return "", err
	}
	schemaName := "tenant_" + slug
	tenantID := "t_" + uuid.New().String()[:8]

	var steps []func(context.Context) error

	// Step 1: INSERT tenant record (public.tenants, provisioning)
	t, err := s.entClient.Tenant.Create().
		SetID(tenantID).
		SetSlug(slug).
		SetName(in.Name).
		SetPlan(in.Plan).
		SetStatus("provisioning").
		SetSchemaName(schemaName).
		Save(ctx)
	if err != nil {
		return "", fmt.Errorf("step1 create tenant: %w", err)
	}
	steps = append(steps, func(ctx context.Context) error {
		return s.entClient.Tenant.DeleteOneID(t.ID).Exec(ctx)
	})

	// Step 1b: default branch (shared.branches). Every tenant has at least one
	// branch ("main"); membership and login are branch-scoped.
	branchID := "br_" + uuid.New().String()[:8]
	if _, err := s.entClient.Branch.Create().
		SetID(branchID).
		SetTenantID(t.ID).
		SetSlug("main").
		SetName("Main").
		SetStatus("active").
		Save(ctx); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step1b create default branch: %w", err)
	}
	steps = append(steps, func(ctx context.Context) error {
		return s.entClient.Branch.DeleteOneID(branchID).Exec(ctx)
	})

	// Step 2: resolve the global user (shared.users). Reuse if the email already
	// exists (multi-tenant join); otherwise hash the password once and create it.
	userID, createdUser, err := s.resolveUser(ctx, in.OwnerEmail, in.OwnerPassword)
	if err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step2 resolve user: %w", err)
	}
	if createdUser {
		steps = append(steps, func(ctx context.Context) error {
			return s.entClient.User.DeleteOneID(userID).Exec(ctx)
		})
	}

	// Step 2b: membership mapping (shared.tenant_users), owner role, scoped to
	// the default branch and flagged as the user's default landing branch.
	ownerRoleID, err := s.rbac.SystemRoleID(ctx, "owner")
	if err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step2b resolve owner role: %w", err)
	}
	tuID := "tu_" + uuid.New().String()[:8]
	if _, err := s.entClient.TenantUser.Create().
		SetID(tuID).
		SetUserID(userID).
		SetTenantID(t.ID).
		SetBranchID(branchID).
		SetIsDefault(true).
		SetRoleID(ownerRoleID).
		Save(ctx); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step2b create membership: %w", err)
	}
	steps = append(steps, func(ctx context.Context) error {
		return s.entClient.TenantUser.DeleteOneID(tuID).Exec(ctx)
	})

	// Step 3: CREATE SCHEMA tenant_{slug}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA IF NOT EXISTS %q", schemaName)); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step3 create schema: %w", err)
	}
	steps = append(steps, func(ctx context.Context) error {
		_, err := s.db.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %q CASCADE", schemaName))
		return err
	})

	// Step 4: migrate tenant schema (user_profiles via ent)
	if err := MigrateTenantSchema(ctx, s.db, s.dsn, schemaName); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step4 migrate tenant schema: %w", err)
	}

	// Step 5: owner PII profile in tenant schema (no credentials here)
	tc := tenantclient.New(s.db, schemaName)
	defer tc.Close()
	if _, err := tc.UserProfile.Create().
		SetID(userID). // user_id is the PK
		SetFullName(in.OwnerFullName).
		SetPhone(in.OwnerPhone).
		SetJobTitle(in.OwnerJobTitle).
		SetSystemRole("owner").
		Save(ctx); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step5 create owner profile: %w", err)
	}

	// Step 6: run installed plugin migrations for this new tenant
	if err := s.installer.InstallForNewTenant(ctx, tenantID, schemaName); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step6 install plugins for new tenant: %w", err)
	}

	// Step 7: activate tenant
	if _, err := s.entClient.Tenant.UpdateOneID(t.ID).SetStatus("active").Save(ctx); err != nil {
		s.compensate(ctx, steps)
		return "", fmt.Errorf("step7 activate tenant: %w", err)
	}

	log.Printf("[saga] tenant registered: %s (%s), owner %s", slug, tenantID, userID)
	return slug, nil
}

// resolveUser returns the global user_id for an email, creating the shared.users
// row (with a freshly hashed password) if it does not exist. The bool reports
// whether a new user was created (so compensation only deletes ours).
func (s *Saga) resolveUser(ctx context.Context, email, password string) (string, bool, error) {
	existing, err := s.entClient.User.Query().Where(entuser.Email(email)).Only(ctx)
	if err == nil {
		return existing.ID, false, nil
	}
	if !ent.IsNotFound(err) {
		return "", false, err
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", false, fmt.Errorf("hash password: %w", err)
	}
	userID := "u_" + uuid.New().String()[:8]
	if _, err := s.entClient.User.Create().
		SetID(userID).
		SetEmail(email).
		SetPasswordHash(string(hash)).
		Save(ctx); err != nil {
		return "", false, err
	}
	return userID, true, nil
}

func (s *Saga) compensate(ctx context.Context, steps []func(context.Context) error) {
	for i := len(steps) - 1; i >= 0; i-- {
		if err := steps[i](ctx); err != nil {
			log.Printf("[saga] compensation step %d failed: %v", i, err)
		}
	}
}
