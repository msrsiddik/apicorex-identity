package auth

import (
	"context"
	"errors"

	entuser "github.com/msrsiddik/apicorex-identity/ent/user"
	"github.com/msrsiddik/apicorex-identity/ent/tenantuser"
	"golang.org/x/crypto/bcrypt"
)

// ErrWeakPassword: the new password is too short.
var ErrWeakPassword = errors.New("password too short")

// ErrWrongPassword: the supplied current password didn't match.
var ErrWrongPassword = errors.New("current password is wrong")

const minPasswordLen = 4

// ChangeOwnPassword lets a user set a new password after proving the current
// one. userID comes from the verified context.
func (s *Service) ChangeOwnPassword(ctx context.Context, userID, current, next string) error {
	if len(next) < minPasswordLen {
		return ErrWeakPassword
	}
	u, err := s.entClient.User.Get(ctx, userID)
	if err != nil {
		return ErrMemberNotFound
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil {
		return ErrWrongPassword
	}
	return s.writePasswordHash(ctx, userID, next)
}

// SetMemberPassword lets an owner reset a staff member's password without the
// old one. Scoped to the tenant: the target must be a member of tenantID, so an
// owner can only reset passwords for their own staff — never a user in another
// tenant (the global users table is shared, so this membership check is what
// keeps tenants apart).
func (s *Service) SetMemberPassword(ctx context.Context, tenantID, userID, next string) error {
	if tenantID == "" || userID == "" {
		return ErrMemberNotFound
	}
	if len(next) < minPasswordLen {
		return ErrWeakPassword
	}
	exists, err := s.entClient.TenantUser.Query().
		Where(tenantuser.UserID(userID), tenantuser.TenantID(tenantID)).
		Exist(ctx)
	if err != nil || !exists {
		return ErrMemberNotFound
	}
	return s.writePasswordHash(ctx, userID, next)
}

func (s *Service) writePasswordHash(ctx context.Context, userID, password string) error {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = s.entClient.User.Update().
		Where(entuser.ID(userID)).
		SetPasswordHash(string(h)).
		Save(ctx)
	return err
}
