package auth

import (
	"context"
	"errors"
	"fmt"

	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
)

// PlatformAdminInfo is a platform admin as returned to clients.
type PlatformAdminInfo struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// ListPlatformAdmins returns every user currently flagged is_platform_admin.
func (s *Service) ListPlatformAdmins(ctx context.Context) ([]PlatformAdminInfo, error) {
	users, err := s.entClient.User.Query().Where(entuser.IsPlatformAdmin(true)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PlatformAdminInfo, 0, len(users))
	for _, u := range users {
		out = append(out, PlatformAdminInfo{UserID: u.ID, Email: u.Email})
	}
	return out, nil
}

// GrantPlatformAdmin flags an existing user (by email) as a platform admin.
// This is a DB write, so it takes effect immediately on every identity
// instance — unlike PLATFORM_ADMIN_EMAILS, which only bootstraps at boot.
func (s *Service) GrantPlatformAdmin(ctx context.Context, email string) (*PlatformAdminInfo, error) {
	u, err := s.entClient.User.Query().Where(entuser.Email(email)).Only(ctx)
	if err != nil {
		return nil, errors.New("no user with that email")
	}
	if _, err := s.entClient.User.UpdateOneID(u.ID).SetIsPlatformAdmin(true).Save(ctx); err != nil {
		return nil, fmt.Errorf("grant platform admin: %w", err)
	}
	return &PlatformAdminInfo{UserID: u.ID, Email: u.Email}, nil
}

// RevokePlatformAdmin clears the platform admin flag for a user (by email).
func (s *Service) RevokePlatformAdmin(ctx context.Context, email string) error {
	u, err := s.entClient.User.Query().Where(entuser.Email(email)).Only(ctx)
	if err != nil {
		return errors.New("no user with that email")
	}
	if _, err := s.entClient.User.UpdateOneID(u.ID).SetIsPlatformAdmin(false).Save(ctx); err != nil {
		return fmt.Errorf("revoke platform admin: %w", err)
	}
	return nil
}
