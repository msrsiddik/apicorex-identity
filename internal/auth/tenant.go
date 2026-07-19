package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/msrsiddik/apicorex-identity/ent"
)

// TenantInfo is a tenant's editable settings as returned to clients. The slug
// and schema are immutable and intentionally omitted from update paths.
type TenantInfo struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Plan string `json:"plan"`
}

// TenantSummary is a tenant row as returned by the platform-admin tenant list.
type TenantSummary struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Plan   string `json:"plan"`
	Status string `json:"status"`
}

// ListTenants returns every tenant, newest first. Platform-admin only — callers
// enforce that at the handler.
func (s *Service) ListTenants(ctx context.Context) ([]TenantSummary, error) {
	ts, err := s.entClient.Tenant.Query().Order(ent.Desc("id")).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	out := make([]TenantSummary, 0, len(ts))
	for _, t := range ts {
		out = append(out, TenantSummary{ID: t.ID, Slug: t.Slug, Name: t.Name, Plan: t.Plan, Status: t.Status})
	}
	return out, nil
}

// tenantStatuses are the values SetTenantStatus accepts. "provisioning" is
// set only by the registration saga and isn't a valid target here.
var tenantStatuses = map[string]bool{"active": true, "suspended": true}

// SetTenantStatus transitions a tenant between active and suspended.
// Suspended blocks login (Login and SwitchBranch both require status
// "active") without touching membership, roles, or data — reactivating
// restores access exactly as it was.
func (s *Service) SetTenantStatus(ctx context.Context, tenantID, status string) (*TenantSummary, error) {
	if !tenantStatuses[status] {
		return nil, errors.New("status must be active or suspended")
	}
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, errors.New("tenant not found")
	}
	if t.Status == "provisioning" {
		return nil, errors.New("tenant is still provisioning")
	}
	t, err = s.entClient.Tenant.UpdateOneID(t.ID).SetStatus(status).Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("set tenant status: %w", err)
	}
	return &TenantSummary{ID: t.ID, Slug: t.Slug, Name: t.Name, Plan: t.Plan, Status: t.Status}, nil
}

// UpdateTenant changes a tenant's display name and/or plan. The slug (which
// names the tenant's schema and is the login key) is immutable and cannot be
// changed here. Empty fields are left unchanged.
func (s *Service) UpdateTenant(ctx context.Context, tenantID, name, plan string) (*TenantInfo, error) {
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, errors.New("tenant not found")
	}
	upd := s.entClient.Tenant.UpdateOneID(t.ID)
	changed := false
	if name != "" {
		upd = upd.SetName(name)
		changed = true
	}
	if plan != "" {
		upd = upd.SetPlan(plan)
		changed = true
	}
	if changed {
		if t, err = upd.Save(ctx); err != nil {
			return nil, fmt.Errorf("update tenant: %w", err)
		}
	}
	return &TenantInfo{ID: t.ID, Slug: t.Slug, Name: t.Name, Plan: t.Plan}, nil
}

// GetTenant returns a single tenant as a summary (incl. status). Used by the
// platform-admin console to refresh a row after an edit.
func (s *Service) GetTenant(ctx context.Context, tenantID string) (*TenantSummary, error) {
	t, err := s.entClient.Tenant.Get(ctx, tenantID)
	if err != nil {
		return nil, errors.New("tenant not found")
	}
	return &TenantSummary{ID: t.ID, Slug: t.Slug, Name: t.Name, Plan: t.Plan, Status: t.Status}, nil
}
