// Package auth handles authentication for the Identity plugin: password login
// across platform and tenant (business) users, HS256 access-token issuing with
// rotation-capable refresh tokens, and an optional Redis logout denylist. Core
// verifies the tokens this package issues using the same shared secret.
package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims are the tenant/user fields embedded in an access token. They must match
// what Core reads (see core auth.Claims) so the gateway can inject tenant headers.
type Claims struct {
	TenantID   string   `json:"tenant_id"`
	TenantSlug string   `json:"tenant_slug"`
	SchemaName string   `json:"schema_name"`
	UserType   string   `json:"user_type"`
	Roles      []string `json:"roles"`
	jwt.RegisteredClaims
}

// Issuer signs HS256 access tokens with a fixed TTL.
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer returns an Issuer signing tokens with secret and the given lifetime.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	return &Issuer{secret: []byte(secret), ttl: ttl}
}

// Issue signs an access token. A unique jti is set so logout can revoke it.
func (is *Issuer) Issue(claims Claims) (string, error) {
	now := time.Now()
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(is.ttl))
	if claims.ID == "" {
		claims.ID = uuid.New().String()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(is.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}
