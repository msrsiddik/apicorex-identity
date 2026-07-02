package auth

import (
	"context"
	"errors"
	"fmt"
)

// TenantInfo is a tenant's editable settings as returned to clients. The slug
// and schema are immutable and intentionally omitted from update paths.
type TenantInfo struct {
	ID   string `json:"id"`
	Slug string `json:"slug"`
	Name string `json:"name"`
	Plan string `json:"plan"`
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
